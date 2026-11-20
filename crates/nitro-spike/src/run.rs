//! One sandbox's life, driven from the parent: its configuration written,
//! the probe's socket bound, Firecracker started, the probe's hello
//! awaited, commands asked, and the sandbox stopped. Every wait is bounded
//! and every step timed from the moment Firecracker is spawned.

use std::io::BufReader;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command as Process, Stdio};
use std::time::{Duration, Instant};

use sandcastle_nitro_probe::protocol::{read_line, write_line, Answer, Command, PORT};

use crate::config::{Parent, Sandbox};

/// From spawning Firecracker to the probe's dial: a boot past this is a
/// failure, not a sample.
pub const BOOT_MS_MAX: u64 = 30_000;
/// One command's answer (an RSA key and the NSM, or a 1 GiB canary).
pub const ANSWER_MS_MAX: u64 = 60_000;
/// From `PowerOff` to Firecracker's exit, before it is killed.
pub const STOP_MS_MAX: u64 = 20_000;
pub const FIRECRACKER: &str = "/usr/local/bin/firecracker";

#[derive(Debug)]
pub struct Failure(pub String);

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn fail(what: &str, e: impl std::fmt::Display) -> Failure {
    Failure(format!("{what}: {e}"))
}

pub struct Session {
    child: Child,
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    spawned: Instant,
    pub dir: PathBuf,
    pub pid: u32,
    /// Spawn to the probe's dial, and to its hello, in ms.
    pub connect_ms: f64,
    pub hello_ms: f64,
    pub hello: Answer,
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// The last lines of Firecracker's log, for a failure's message.
pub fn log_tail(dir: &Path) -> String {
    let log = std::fs::read_to_string(dir.join("firecracker.log")).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(12)..].join("\n")
}

/// Waits for `listener` to have a connection, at most until `deadline`,
/// while `child` lives.
fn accept(listener: &UnixListener, child: &mut Child, deadline: Instant, dir: &Path) -> Result<UnixStream, Failure> {
    // Bounded by the deadline.
    loop {
        let mut pfd = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: one pollfd, a short timeout.
        let ready = unsafe { libc::poll(&mut pfd, 1, 5) };
        if ready > 0 {
            return listener.accept().map(|(s, _)| s).map_err(|e| fail("accepting the probe", e));
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(Failure(format!("Firecracker exited ({status}) before the probe dialed:\n{}", log_tail(dir))));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Failure(format!("no dial within {BOOT_MS_MAX} ms:\n{}", log_tail(dir))));
        }
    }
}

/// Starts `sandbox` in `dir` (made fresh) and waits for its hello.
pub fn launch(sandbox: &Sandbox, parent: &Parent, dir: &Path) -> Result<Session, Failure> {
    assert!(!sandbox.vsock.uds_path.as_os_str().is_empty());
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|e| fail("clearing the run directory", e))?;
    }
    std::fs::create_dir_all(dir).map_err(|e| fail("the run directory", e))?;
    let config = sandbox.render(parent).map_err(|e| fail("the configuration", e))?;
    let config_path = dir.join("config.json");
    std::fs::write(&config_path, &config).map_err(|e| fail("writing the configuration", e))?;
    let probe_socket = format!("{}_{PORT}", sandbox.vsock.uds_path.display());
    let listener = UnixListener::bind(&probe_socket).map_err(|e| fail("binding the probe's socket", e))?;
    let log = std::fs::File::create(dir.join("firecracker.log")).map_err(|e| fail("the log", e))?;
    let log2 = log.try_clone().map_err(|e| fail("the log", e))?;
    let spawned = Instant::now();
    let mut child = Process::new(FIRECRACKER)
        .args(["--no-api", "--config-file"])
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(log2)
        .spawn()
        .map_err(|e| fail("spawning Firecracker", e))?;
    let pid = child.id();
    let stream = accept(&listener, &mut child, spawned + Duration::from_millis(BOOT_MS_MAX), dir)?;
    let connect_ms = ms(spawned.elapsed());
    stream.set_read_timeout(Some(Duration::from_millis(ANSWER_MS_MAX))).map_err(|e| fail("the probe's socket", e))?;
    let writer = stream.try_clone().map_err(|e| fail("the probe's socket", e))?;
    let mut reader = BufReader::new(stream);
    let hello: Answer = read_line(&mut reader).map_err(|e| fail("the probe's hello", e))?;
    let hello_ms = ms(spawned.elapsed());
    if !matches!(hello, Answer::Hello { .. }) {
        return Err(Failure(format!("the probe's first message was not a hello: {hello:?}")));
    }
    assert!(connect_ms <= hello_ms);
    Ok(Session { child, reader, writer, spawned, dir: dir.to_path_buf(), pid, connect_ms, hello_ms, hello })
}

impl Session {
    pub fn ask(&mut self, command: &Command) -> Result<Answer, Failure> {
        command.validate().map_err(|e| fail("a command we made", e))?;
        write_line(&mut self.writer, command).map_err(|e| fail("asking the probe", e))?;
        read_line(&mut self.reader).map_err(|e| fail("the probe's answer", e))
    }

    /// Ms since Firecracker was spawned.
    pub fn since_spawn_ms(&self) -> f64 {
        ms(self.spawned.elapsed())
    }

    /// Powers the guest off and waits for Firecracker to exit, killing it
    /// past [`STOP_MS_MAX`]. The time from asking to its exit, in ms, and
    /// whether it exited by itself.
    pub fn stop(mut self) -> Result<(f64, bool), Failure> {
        let asked = Instant::now();
        let _ = write_line(&mut self.writer, &Command::PowerOff);
        let deadline = asked + Duration::from_millis(STOP_MS_MAX);
        // Bounded by the deadline.
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return Ok((ms(asked.elapsed()), true)),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
                Ok(None) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return Ok((ms(asked.elapsed()), false));
                }
                Err(e) => return Err(fail("waiting for Firecracker", e)),
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // A session dropped on an error path must not leave a sandbox
        // holding a slot.
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
