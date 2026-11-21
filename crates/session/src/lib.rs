//! The attested session (docs/nitro.md, "The attested session"): how a
//! home reaches a computer's guest so that the parent between them, which
//! carries every byte, can neither read nor drive what passes.
//!
//! Per connection, on the guest's vsock port `PORT_SESSION`:
//!
//! 1. **Hello**, home to guest, in the clear: a version, the connection's
//!    kind, and a nonce. Both sides hash it into the handshake (Noise's
//!    prologue), so a changed hello fails it.
//! 2. **Attest**, once per guest life, before anything else: the guest
//!    answers its NSM's document for the hello's nonce with the guest's
//!    Noise key as the document's public key. The home verifies it (the
//!    chain to AWS's root, the nonce, the image's PCR0: the caller's
//!    `verify`), then runs Noise NK to that key, which only the attested
//!    guest holds. The home's first message in the session is a secret of
//!    32 random bytes; the guest keeps it, and the session is claimed: a
//!    second attest is refused. A parent that claims first gains nothing:
//!    the home's attempt then fails, and the home never puts its data into
//!    that VM.
//! 3. **Resume**, every later connection: Noise NKpsk0 to the same key with
//!    that secret, which only the home that claimed the guest has.
//!
//! Then each direction is Noise transport messages, each framed by a
//! two-byte length. An empty message ends a direction (a half-close); a
//! connection that ends without one is a truncation, an error, never a
//! short read taken for the whole.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const VERSION: u8 = 1;
pub const NONCE_BYTES: usize = 32;
/// A Curve25519 key, and the session's secret.
pub const KEY_BYTES: usize = 32;
pub const HELLO_BYTES: usize = 2 + NONCE_BYTES;
/// Noise's ceiling on a message, and so a frame's.
pub const MESSAGE_BYTES_MAX: usize = 65535;
const TAG_BYTES: usize = 16;
/// Plain bytes in one transport message.
pub const CHUNK_BYTES_MAX: usize = MESSAGE_BYTES_MAX - TAG_BYTES;
/// How long either side waits for the other through a handshake.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);

const ATTEST: &str = "Noise_NK_25519_ChaChaPoly_SHA256";
const RESUME: &str = "Noise_NKpsk0_25519_ChaChaPoly_SHA256";

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("the session's stream: {0}")]
    Io(#[from] io::Error),
    #[error("the handshake: {0}")]
    Noise(String),
    #[error("a hello of another version or kind")]
    Hello,
    #[error("a frame of no bytes or past {MESSAGE_BYTES_MAX}")]
    Frame,
    #[error("this guest's session is claimed already")]
    Claimed,
    #[error("this guest has no session to resume")]
    Unclaimed,
    #[error("the guest's attestation: {0}")]
    Attestation(String),
    #[error("the guest's key: {0}")]
    Key(&'static str),
}

fn noise(e: snow::Error) -> SessionError {
    SessionError::Noise(e.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Attest = 1,
    Resume = 2,
}

/// The connection's opening, in the clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello {
    pub kind: Kind,
    pub nonce: [u8; NONCE_BYTES],
}

impl Hello {
    pub fn encode(&self) -> [u8; HELLO_BYTES] {
        let mut b = [0u8; HELLO_BYTES];
        b[0] = VERSION;
        b[1] = self.kind as u8;
        b[2..].copy_from_slice(&self.nonce);
        b
    }

    pub fn decode(b: &[u8; HELLO_BYTES]) -> Result<Hello, SessionError> {
        let kind = match (b[0], b[1]) {
            (VERSION, 1) => Kind::Attest,
            (VERSION, 2) => Kind::Resume,
            _ => return Err(SessionError::Hello),
        };
        Ok(Hello { kind, nonce: b[2..].try_into().expect("32 bytes") })
    }
}

/// What a home keeps for a guest it claimed: the guest's attested key and
/// the session's secret. Whoever holds it is that guest's home.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    #[serde(with = "hex_key")]
    pub guest_key: [u8; KEY_BYTES],
    #[serde(with = "hex_key")]
    pub secret: [u8; KEY_BYTES],
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential").field("guest_key", &hex::encode(self.guest_key)).field("secret", &"<secret>").finish()
    }
}

mod hex_key {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(k: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(k))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        let bytes = hex::decode(text).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| serde::de::Error::custom("a key is 32 bytes"))
    }
}

/// A guest's side for its life: its key, and the secret of the home that
/// claimed it once one has.
pub struct Guest {
    private: Vec<u8>,
    public: [u8; KEY_BYTES],
    state: Mutex<Claim>,
}

#[derive(Clone, Copy)]
enum Claim {
    Open,
    /// An attest is under way; another waits for its end.
    Claiming,
    Claimed([u8; KEY_BYTES]),
}

impl Guest {
    /// A fresh key for this life, from the system's randomness.
    pub fn new() -> Result<Guest, SessionError> {
        let keys = snow::Builder::new(ATTEST.parse().map_err(noise)?).generate_keypair().map_err(noise)?;
        let public: [u8; KEY_BYTES] = keys.public.as_slice().try_into().map_err(|_| SessionError::Key("not 32 bytes"))?;
        Ok(Guest { private: keys.private, public, state: Mutex::new(Claim::Open) })
    }

    /// The key a document binds (its `public_key`).
    pub fn public_key(&self) -> [u8; KEY_BYTES] {
        self.public
    }

    pub fn claimed(&self) -> bool {
        matches!(*self.state.lock().expect("never poisoned"), Claim::Claimed(_))
    }

    /// One connection, from the hello to an open session. `document`
    /// answers the NSM's document for a nonce, its public key this guest's.
    pub fn accept(&self, mut s: UnixStream, document: impl FnOnce(&[u8; NONCE_BYTES]) -> io::Result<Vec<u8>>) -> Result<Session, SessionError> {
        s.set_read_timeout(Some(HANDSHAKE_WAIT))?;
        let mut hello = [0u8; HELLO_BYTES];
        s.read_exact(&mut hello)?;
        let h = Hello::decode(&hello)?;
        let session = match h.kind {
            Kind::Attest => self.attest(&mut s, &hello, &h, document)?,
            Kind::Resume => {
                let resumed = {
                let Claim::Claimed(secret) = *self.state.lock().expect("never poisoned") else {
                    return Err(SessionError::Unclaimed);
                };
                let hs = snow::Builder::new(RESUME.parse().map_err(noise)?)
                    .local_private_key(&self.private)
                    .map_err(noise)?
                    .psk(0, &secret)
                    .map_err(noise)?
                    .prologue(&hello)
                    .map_err(noise)?
                    .build_responder()
                    .map_err(noise)?;
                    respond(&mut s, hs)?
                };
                Session::new(s.try_clone()?, resumed)
            }
        };
        s.set_read_timeout(None)?;
        Ok(session)
    }

    fn attest(&self, s: &mut UnixStream, hello: &[u8], h: &Hello, document: impl FnOnce(&[u8; NONCE_BYTES]) -> io::Result<Vec<u8>>) -> Result<Session, SessionError> {
        {
            let mut state = self.state.lock().expect("never poisoned");
            match *state {
                Claim::Open => *state = Claim::Claiming,
                Claim::Claiming | Claim::Claimed(_) => return Err(SessionError::Claimed),
            }
        }
        let attempt = (|| {
            let doc = document(&h.nonce)?;
            write_frame(s, &doc)?;
            let hs = snow::Builder::new(ATTEST.parse().map_err(noise)?)
                .local_private_key(&self.private)
                .map_err(noise)?
                .prologue(hello)
                .map_err(noise)?
                .build_responder()
                .map_err(noise)?;
            let mut session = Session::new(s.try_clone()?, respond(s, hs)?);
            // The home's first message: the session's secret.
            let secret: [u8; KEY_BYTES] = session.recv_message()?.try_into().map_err(|_| SessionError::Key("a secret of another length"))?;
            Ok::<_, SessionError>((session, secret))
        })();
        let mut state = self.state.lock().expect("never poisoned");
        match attempt {
            Ok((session, secret)) => {
                *state = Claim::Claimed(secret);
                Ok(session)
            }
            Err(e) => {
                *state = Claim::Open;
                Err(e)
            }
        }
    }
}

/// The home's first connection to a guest: attest, verify, claim. `verify`
/// checks the document for `nonce` (chain, nonce, PCR0) and answers the
/// key it binds. `secret` is 32 random bytes of the caller's.
pub fn attest(
    mut s: UnixStream,
    nonce: [u8; NONCE_BYTES],
    secret: [u8; KEY_BYTES],
    verify: impl FnOnce(&[u8]) -> Result<[u8; KEY_BYTES], String>,
) -> Result<(Session, Credential), SessionError> {
    s.set_read_timeout(Some(HANDSHAKE_WAIT))?;
    let hello = Hello { kind: Kind::Attest, nonce }.encode();
    s.write_all(&hello)?;
    let doc = read_frame(&mut s)?.ok_or(SessionError::Frame)?;
    let guest_key = verify(&doc).map_err(SessionError::Attestation)?;
    let hs = snow::Builder::new(ATTEST.parse().map_err(noise)?)
        .remote_public_key(&guest_key)
        .map_err(noise)?
        .prologue(&hello)
        .map_err(noise)?
        .build_initiator()
        .map_err(noise)?;
    let transport = initiate(&mut s, hs)?;
    s.set_read_timeout(None)?;
    let mut session = Session::new(s, transport);
    session.send_message(&secret)?;
    Ok((session, Credential { guest_key, secret }))
}

/// A later connection of the home that claimed the guest.
pub fn resume(mut s: UnixStream, nonce: [u8; NONCE_BYTES], credential: &Credential) -> Result<Session, SessionError> {
    s.set_read_timeout(Some(HANDSHAKE_WAIT))?;
    let hello = Hello { kind: Kind::Resume, nonce }.encode();
    s.write_all(&hello)?;
    let hs = snow::Builder::new(RESUME.parse().map_err(noise)?)
        .remote_public_key(&credential.guest_key)
        .map_err(noise)?
        .psk(0, &credential.secret)
        .map_err(noise)?
        .prologue(&hello)
        .map_err(noise)?
        .build_initiator()
        .map_err(noise)?;
    let transport = initiate(&mut s, hs)?;
    s.set_read_timeout(None)?;
    Ok(Session::new(s, transport))
}

/// Noise's two handshake messages, initiator first (NK and NKpsk0 alike).
fn initiate(s: &mut UnixStream, mut hs: snow::HandshakeState) -> Result<snow::StatelessTransportState, SessionError> {
    let mut buf = vec![0u8; MESSAGE_BYTES_MAX];
    let n = hs.write_message(&[], &mut buf).map_err(noise)?;
    write_frame(s, &buf[..n])?;
    let m = read_frame(s)?.ok_or(SessionError::Frame)?;
    hs.read_message(&m, &mut buf).map_err(noise)?;
    hs.into_stateless_transport_mode().map_err(noise)
}

fn respond(s: &mut UnixStream, mut hs: snow::HandshakeState) -> Result<snow::StatelessTransportState, SessionError> {
    let mut buf = vec![0u8; MESSAGE_BYTES_MAX];
    let m = read_frame(s)?.ok_or(SessionError::Frame)?;
    hs.read_message(&m, &mut buf).map_err(noise)?;
    let n = hs.write_message(&[], &mut buf).map_err(noise)?;
    write_frame(s, &buf[..n])?;
    hs.into_stateless_transport_mode().map_err(noise)
}

fn write_frame(s: &mut impl Write, data: &[u8]) -> io::Result<()> {
    assert!(data.len() <= MESSAGE_BYTES_MAX);
    let mut frame = Vec::with_capacity(2 + data.len());
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    s.write_all(&frame)
}

/// One frame; `None` at a clean end of the stream before any byte of it.
fn read_frame(s: &mut impl Read) -> Result<Option<Vec<u8>>, SessionError> {
    let mut len = [0u8; 2];
    match s.read(&mut len[..1])? {
        0 => return Ok(None),
        _ => s.read_exact(&mut len[1..])?,
    }
    let n = u16::from_be_bytes(len) as usize;
    if n == 0 {
        return Err(SessionError::Frame);
    }
    let mut data = vec![0u8; n];
    s.read_exact(&mut data)?;
    Ok(Some(data))
}

/// An open session over its carrier: the transport's ciphers, and each
/// direction's message count (Noise's nonce for it).
pub struct Session {
    s: UnixStream,
    ciphers: Arc<snow::StatelessTransportState>,
    sent: u64,
    received: u64,
}

impl Session {
    fn new(s: UnixStream, transport: snow::StatelessTransportState) -> Session {
        Session { s, ciphers: Arc::new(transport), sent: 0, received: 0 }
    }

    /// One transport message out.
    fn send_message(&mut self, plain: &[u8]) -> Result<(), SessionError> {
        assert!(plain.len() <= CHUNK_BYTES_MAX);
        let mut msg = vec![0u8; plain.len() + TAG_BYTES];
        let n = self.ciphers.write_message(self.sent, plain, &mut msg).map_err(noise)?;
        self.sent += 1;
        write_frame(&mut self.s, &msg[..n])?;
        Ok(())
    }

    /// One transport message in.
    fn recv_message(&mut self) -> Result<Vec<u8>, SessionError> {
        let frame = read_frame(&mut self.s)?.ok_or(SessionError::Frame)?;
        let mut plain = vec![0u8; frame.len()];
        let n = self.ciphers.read_message(self.received, &frame, &mut plain).map_err(noise)?;
        self.received += 1;
        plain.truncate(n);
        Ok(plain)
    }

    /// The session's two directions.
    pub fn split(self) -> io::Result<(Reader, Writer)> {
        let r = Reader { s: self.s.try_clone()?, cipher: self.ciphers.clone(), nonce: self.received, buf: Vec::new(), pos: 0, ended: false };
        let w = Writer { s: self.s, cipher: self.ciphers, nonce: self.sent };
        Ok((r, w))
    }

    /// The session as a plain local socket: the other end of a socketpair
    /// whose bytes this session carries both ways, by a thread for each,
    /// until both directions end. What uses it sees an ordinary stream.
    pub fn into_plain(self) -> io::Result<UnixStream> {
        let (mine, theirs) = UnixStream::pair()?;
        let (mut reader, mut writer) = self.split()?;
        let (mut plain_in, plain_out) = (mine.try_clone()?, mine);
        std::thread::Builder::new().name("session-out".into()).spawn(move || {
            // Plain bytes out, sealed; the plain side's end ends this way.
            let _ = io::copy(&mut plain_in, &mut writer).and_then(|_| writer.end());
        })?;
        std::thread::Builder::new().name("session-in".into()).spawn(move || {
            let mut out = plain_out;
            match io::copy(&mut reader, &mut out) {
                Ok(_) => {
                    let _ = out.shutdown(std::net::Shutdown::Write);
                }
                // A truncation or a forged message: the stream is dead.
                Err(_) => {
                    let _ = out.shutdown(std::net::Shutdown::Both);
                    let _ = reader.s.shutdown(std::net::Shutdown::Both);
                }
            }
        })?;
        Ok(theirs)
    }
}

/// The receiving half.
pub struct Reader {
    s: UnixStream,
    cipher: Arc<snow::StatelessTransportState>,
    nonce: u64,
    buf: Vec<u8>,
    pos: usize,
    ended: bool,
}

impl Read for Reader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.buf.len() {
            if self.ended {
                return Ok(0);
            }
            let Some(frame) = read_frame(&mut self.s).map_err(io::Error::other)? else {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the session ended without its end"));
            };
            let mut plain = vec![0u8; frame.len()];
            let n = self.cipher.read_message(self.nonce, &frame, &mut plain).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            self.nonce += 1;
            if n == 0 {
                self.ended = true;
            }
            plain.truncate(n);
            self.buf = plain;
            self.pos = 0;
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// The sending half.
pub struct Writer {
    s: UnixStream,
    cipher: Arc<snow::StatelessTransportState>,
    nonce: u64,
}

impl Writer {
    fn seal(&mut self, plain: &[u8]) -> io::Result<()> {
        let mut msg = vec![0u8; plain.len() + TAG_BYTES];
        let n = self.cipher.write_message(self.nonce, plain, &mut msg).map_err(|e| io::Error::other(e.to_string()))?;
        self.nonce += 1;
        write_frame(&mut self.s, &msg[..n])
    }

    /// Ends this direction: an empty message, then a half-close.
    pub fn end(&mut self) -> io::Result<()> {
        self.seal(&[])?;
        self.s.shutdown(std::net::Shutdown::Write)
    }
}

impl Write for Writer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let chunk = &data[..data.len().min(CHUNK_BYTES_MAX)];
        self.seal(chunk)?;
        Ok(chunk.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.s.flush()
    }
}

#[cfg(test)]
mod tests;
