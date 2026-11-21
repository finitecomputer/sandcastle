//! sandcastle's own guest (`sandcastle-guest` as the sandbox's PID 1, from
//! the initrd) driven from the parent (docs/nitro-spike.md, acceptance 6
//! on). Two vsock ports, as on krun:
//!
//! - **The lifecycle** (`PORT_LIFECYCLE`): the guest dials the parent;
//!   Firecracker hands that to `<uds_path>_1025`. Hello, the start, ready,
//!   then the entrypoint's output and its exit, each answered `Recorded`.
//! - **The agent** (`PORT_AGENT`): the parent dials the guest. Firecracker
//!   takes `CONNECT 1024` on `<uds_path>` itself; a relay here turns that
//!   into the plain unix socket sandcastle-vm's client already dials, so
//!   exec and ports run through the krun engine's own client, unchanged.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command as Process, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sandcastle_vm::client::Vm;
use sandcastle_wire::{decode_message, write_message, Event, FrameReader, Kind, Recorded, Start, PORT_AGENT, PORT_LIFECYCLE};

use crate::config::{Parent, Sandbox};
use crate::run::{accept, log_tail, Failure, Reaped, BOOT_MS_MAX, FIRECRACKER};

/// From the guest's hello to its ready: the image's mounts and the
/// entrypoint's start.
pub const READY_MS_MAX: u64 = 60_000;
/// A connection through the agent relay: Firecracker answers its
/// `CONNECT` at once or the guest is not listening yet.
pub const RELAY_HANDSHAKE_MS_MAX: u64 = 5_000;
/// Agent connections relayed at once.
pub const RELAYS_MAX: usize = 64;

fn fail(what: &str, e: impl std::fmt::Display) -> Failure {
    Failure(format!("{what}: {e}"))
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// What the guest's lifecycle says after ready, timed from the spawn.
#[derive(Debug, Clone)]
pub enum Said {
    Line { ms: f64, stderr: bool, text: String },
    Exited { ms: f64, code: Option<i32>, signal: Option<i32> },
    Failed { ms: f64, message: String },
    Closed { ms: f64 },
}

pub struct Guest {
    child: Child,
    spawned: Instant,
    pub dir: PathBuf,
    pub pid: u32,
    pub vm: Vm,
    /// Spawn to the guest's hello, and to its ready, in ms; the guest's
    /// boot clock at ready.
    pub hello_ms: f64,
    pub ready_ms: f64,
    pub guest_ready_uptime_ms: u64,
    pub said: mpsc::Receiver<Said>,
}

/// One relayed agent connection: `CONNECT <port>` on Firecracker's socket,
/// its `OK`, then bytes both ways until either side closes.
fn relay_one(client: UnixStream, uds: &Path, port: u32) -> std::io::Result<()> {
    let mut fc = UnixStream::connect(uds)?;
    fc.set_read_timeout(Some(Duration::from_millis(RELAY_HANDSHAKE_MS_MAX)))?;
    fc.write_all(format!("CONNECT {port}\n").as_bytes())?;
    // The answer is one short line, "OK <host port>"; read it a byte at a
    // time so nothing after it is taken from the stream.
    let mut line = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    // Bounded: an OK line is under 32 bytes.
    while line.len() < 32 && !line.ends_with(b"\n") {
        if fc.read(&mut byte)? == 0 {
            return Err(std::io::Error::other("Firecracker closed before OK"));
        }
        line.push(byte[0]);
    }
    if !line.starts_with(b"OK ") {
        return Err(std::io::Error::other(format!("Firecracker answered {:?}", String::from_utf8_lossy(&line))));
    }
    fc.set_read_timeout(None)?;
    let (mut c_read, mut f_write) = (client.try_clone()?, fc.try_clone()?);
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c_read, &mut f_write);
        let _ = f_write.shutdown(std::net::Shutdown::Write);
    });
    let (mut f_read, mut c_write) = (fc, client);
    let _ = std::io::copy(&mut f_read, &mut c_write);
    let _ = c_write.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
    Ok(())
}

fn relay(listener: UnixListener, uds: PathBuf) {
    let live = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // Unbounded by design: it relays for the sandbox's life; each
    // connection takes one of RELAYS_MAX slots.
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        if live.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= RELAYS_MAX {
            live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            continue;
        }
        let (uds, live) = (uds.clone(), live.clone());
        std::thread::spawn(move || {
            let _ = relay_one(conn, &uds, PORT_AGENT);
            live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }
}

/// Reads the lifecycle after ready: output lines and the end, each sent
/// on, timed; `Recorded` written for the exit or a failure.
fn drain(mut reader: FrameReader<UnixStream>, mut writer: UnixStream, spawned: Instant, tx: mpsc::Sender<Said>) {
    let mut partial: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
    // Bounded by the guest: it says exited and powers off, or closes.
    loop {
        let frame = match reader.read_frame() {
            Ok(f) => f,
            Err(_) => {
                let _ = tx.send(Said::Closed { ms: ms(spawned.elapsed()) });
                return;
            }
        };
        let at = ms(spawned.elapsed());
        match frame.kind {
            Kind::Stdout | Kind::Stderr => {
                let i = usize::from(frame.kind == Kind::Stderr);
                partial[i].extend_from_slice(&frame.payload);
                // Bounded: each pass removes one line from the buffer.
                while let Some(nl) = partial[i].iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = partial[i].drain(..=nl).collect();
                    let _ = tx.send(Said::Line { ms: at, stderr: i == 1, text: String::from_utf8_lossy(&line[..line.len() - 1]).into_owned() });
                }
            }
            Kind::Control => match decode_message::<Event>(&frame) {
                Ok(Event::Exited { code, signal }) => {
                    let _ = write_message(&mut writer, &Recorded {});
                    let _ = tx.send(Said::Exited { ms: at, code, signal });
                }
                Ok(Event::Failed { message }) => {
                    let _ = write_message(&mut writer, &Recorded {});
                    let _ = tx.send(Said::Failed { ms: at, message });
                }
                _ => {}
            },
            Kind::Stdin => {}
        }
    }
}

/// Starts `sandbox` with sandcastle-guest as its init, hands it `start`,
/// and waits for it to be ready.
pub fn launch(sandbox: &Sandbox, parent: &Parent, dir: &Path, start: &Start) -> Result<Guest, Failure> {
    start.validate().map_err(|e| fail("the start", e))?;
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|e| fail("clearing the run directory", e))?;
    }
    std::fs::create_dir_all(dir).map_err(|e| fail("the run directory", e))?;
    let config = sandbox.render(parent).map_err(|e| fail("the configuration", e))?;
    let config_path = dir.join("config.json");
    std::fs::write(&config_path, &config).map_err(|e| fail("writing the configuration", e))?;
    let uds = sandbox.vsock.uds_path.clone();
    let lifecycle = UnixListener::bind(format!("{}_{PORT_LIFECYCLE}", uds.display())).map_err(|e| fail("binding the lifecycle socket", e))?;
    let agent = UnixListener::bind(dir.join(sandcastle_vm::paths::AGENT_SOCK)).map_err(|e| fail("binding the agent relay", e))?;
    {
        let uds = uds.clone();
        std::thread::spawn(move || relay(agent, uds));
    }
    let log = std::fs::File::create(dir.join("firecracker.log")).map_err(|e| fail("the log", e))?;
    let log2 = log.try_clone().map_err(|e| fail("the log", e))?;
    let spawned = Instant::now();
    let child = Process::new(FIRECRACKER)
        .args(["--no-api", "--config-file"])
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(log2)
        .spawn()
        .map_err(|e| fail("spawning Firecracker", e))?;
    let pid = child.id();
    // From here every failure must take the sandbox down with it: a
    // Firecracker left running holds its slot, its cores and its memory.
    let mut child = Reaped(Some(child));
    let stream = accept(&lifecycle, child.0.as_mut().expect("held"), spawned + Duration::from_millis(BOOT_MS_MAX), dir)?;
    stream.set_read_timeout(Some(Duration::from_millis(READY_MS_MAX))).map_err(|e| fail("the lifecycle", e))?;
    let mut writer = stream.try_clone().map_err(|e| fail("the lifecycle", e))?;
    let mut reader = FrameReader::new(stream);
    let hello: Event = reader.read_message().map_err(|e| fail("the guest's hello", e))?;
    let hello_ms = ms(spawned.elapsed());
    match hello {
        Event::Hello { version, .. } if version == sandcastle_wire::VERSION => {}
        other => return Err(Failure(format!("the guest's first message: {other:?}"))),
    }
    write_message(&mut writer, start).map_err(|e| fail("the start", e))?;
    let guest_ready_uptime_ms = match reader.read_message::<Event>().map_err(|e| fail("the guest's ready", e))? {
        Event::Ready { uptime_ms } => uptime_ms,
        Event::Failed { message } => {
            let _ = write_message(&mut writer, &Recorded {});
            return Err(Failure(format!("the guest failed before ready: {message}\n{}", log_tail(dir))));
        }
        other => return Err(Failure(format!("the guest's second message: {other:?}"))),
    };
    let ready_ms = ms(spawned.elapsed());
    assert!(hello_ms <= ready_ms);
    // The same reader drains on, so output the guest sent right behind its
    // ready (already buffered) is kept; its socket now waits for as long
    // as the entrypoint runs.
    writer.set_read_timeout(None).map_err(|e| fail("the lifecycle", e))?;
    let (tx, said) = mpsc::channel();
    std::thread::spawn(move || drain(reader, writer, spawned, tx));
    let child = child.0.take().expect("held");
    Ok(Guest { child, spawned, dir: dir.to_path_buf(), pid, vm: Vm::new(dir), hello_ms, ready_ms, guest_ready_uptime_ms, said })
}

impl Guest {
    pub fn since_spawn_ms(&self) -> f64 {
        ms(self.spawned.elapsed())
    }

    /// Waits for an output line containing `needle`, at most `wait`; the
    /// ms from the spawn it arrived at, and every line seen until then.
    pub fn wait_line(&self, needle: &str, wait: Duration) -> Result<(f64, Vec<String>), Failure> {
        let deadline = Instant::now() + wait;
        let mut seen = Vec::new();
        // Bounded by the deadline.
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.said.recv_timeout(left) {
                Ok(Said::Line { ms, text, .. }) => {
                    let hit = text.contains(needle);
                    seen.push(text);
                    if hit {
                        return Ok((ms, seen));
                    }
                }
                Ok(Said::Exited { code, signal, .. }) => return Err(Failure(format!("the entrypoint exited ({code:?}, {signal:?}) before {needle:?}: {seen:?}"))),
                Ok(Said::Failed { message, .. }) => return Err(Failure(format!("the guest failed before {needle:?}: {message}; {seen:?}"))),
                Ok(Said::Closed { .. }) => return Err(Failure(format!("the lifecycle closed before {needle:?}: {seen:?}"))),
                Err(_) => return Err(Failure(format!("no {needle:?} within {wait:?}: {seen:?}"))),
            }
        }
    }

    /// Ends the sandbox: Firecracker is stopped (SIGTERM, then SIGKILL past
    /// a bound). A sandbox has no pause and no flush of its own; a caller
    /// that needs the guest's data saved does that first (FPAC's sleep).
    pub fn stop(mut self) -> Result<f64, Failure> {
        let asked = Instant::now();
        // SAFETY: kill(2) on the child we spawned.
        unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGTERM) };
        let deadline = asked + Duration::from_millis(crate::run::STOP_MS_MAX);
        // Bounded by the deadline.
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return Ok(ms(asked.elapsed())),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
                Ok(None) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return Ok(ms(asked.elapsed()));
                }
                Err(e) => return Err(fail("waiting for Firecracker", e)),
            }
        }
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Reads a file the guest wrote to stdout line by line, for a quick look.
pub fn lines(text: &[u8]) -> Vec<String> {
    BufReader::new(text).lines().map_while(Result::ok).collect()
}
