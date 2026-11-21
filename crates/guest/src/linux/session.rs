//! The guest's attested session (docs/nitro.md, "The attested session"):
//! a listener on vsock `PORT_SESSION`, each connection's handshake on a
//! thread of its own (it blocks on the home and on the NSM), its plain end
//! then handed to the agent, which serves it as any connection, with all
//! of its work. On a guest whose kernel line says `SESSION_ARG`, the
//! agent's own port takes only what the parent keeps: ping, signal, the
//! memory trim (`agent::host_may`).

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use sandcastle_session::{Guest, SessionError};

use super::sys;

/// Handshakes under way at once; a connection past them is closed.
const HANDSHAKES_MAX: usize = 16;

/// Listens for sessions for the VM's life, each open session's plain end
/// sent to the agent on `to_agent`.
pub fn listen(guest: Arc<Guest>, to_agent: tokio::sync::mpsc::Sender<OwnedFd>) -> std::io::Result<()> {
    let listener = sys::vsock_listen(sandcastle_wire::PORT_SESSION, false)?;
    std::thread::Builder::new().name("session".into()).spawn(move || {
        let live = Arc::new(AtomicUsize::new(0));
        // Unbounded by design: the port serves for the VM's life, each
        // connection bounded by HANDSHAKES_MAX and then by the agent's.
        loop {
            let fd = match sys::accept(listener.as_raw_fd(), false) {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("session: accept: {e}");
                    continue;
                }
            };
            if live.fetch_add(1, Ordering::SeqCst) >= HANDSHAKES_MAX {
                live.fetch_sub(1, Ordering::SeqCst);
                eprintln!("session: {HANDSHAKES_MAX} handshakes at once; one closed");
                continue;
            }
            let (guest, to_agent, held) = (guest.clone(), to_agent.clone(), live.clone());
            let spawned = std::thread::Builder::new().name("session-accept".into()).spawn(move || {
                let opened = open(&guest, fd);
                held.fetch_sub(1, Ordering::SeqCst);
                match opened {
                    Ok(plain) => {
                        let _ = to_agent.blocking_send(plain);
                    }
                    Err(e) => eprintln!("session: {e}"),
                }
            });
            if let Err(e) = spawned {
                live.fetch_sub(1, Ordering::SeqCst);
                eprintln!("session: a handshake's thread: {e}");
            }
        }
    })?;
    Ok(())
}

/// One connection's handshake, attest or resume, to the plain end the agent
/// serves (non-blocking, as the agent's own accepted connections are).
fn open(guest: &Guest, fd: OwnedFd) -> Result<OwnedFd, SessionError> {
    let key = guest.public_key();
    let session = guest.accept(UnixStream::from(fd), |nonce| sys::nsm_document_for(nonce, Some(&key)))?;
    let plain = session.into_plain()?;
    plain.set_nonblocking(true)?;
    Ok(OwnedFd::from(plain))
}
