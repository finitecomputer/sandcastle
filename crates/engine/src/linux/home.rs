//! A home's side of its computers' attested sessions (docs/nitro.md, "The
//! attested session"), in the home half of `sandcastle-bridge`. On a node
//! whose computers require sessions, the home half serves celld's
//! `engine.sock` itself rather than relaying its bytes:
//!
//! - a **start** goes to the parent's engine; once the computer runs, the
//!   home attests it (AWS's root, a fresh nonce, a PCR0 of its pins) and
//!   claims its session before celld hears the start answered. A computer
//!   that cannot attest is destroyed and the start fails. A start whose
//!   image's PCR0 on this node (the engine's measure) is no pin waits for
//!   its pin instead, booting nothing, and fails only if none comes in
//!   time (`wait_pinned`);
//! - an **exec** runs over a session resumed with the claim's credential,
//!   the guest's agent at the far end, and so does each `ports.sock`
//!   connection;
//! - **everything else** (stop, kill, list, images, intercepts, logs) goes
//!   to the parent's engine as before: the parent keeps start, stop, kill.
//!
//! The credentials are kept in the home's own state directory, so a
//! computer kept running through a home restart is still the home's.
//!
//! **Egress inside the boundary** (docs/nitro.md): the claim tells each
//! computer to send its workload's connections and lookups to its home, and
//! hands it the home's CA. Each comes as an egress session (bridge port
//! 5003), and the home's own egress proxy (`sandcastle_egress`, the same
//! the engine runs) decides it by that computer's start: intercepts to
//! celld's socket in the home, the internet from the home, refusals. The
//! CA's key never leaves the home; the parent never sees where a
//! connection goes, or what it carries.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use sandcastle_session::Credential;
use sandcastle_vm::client::{ClientError, Vm as AgentClient};

use crate::api::{self, ApiError, ExecRequest};
use crate::ports::{self, send_with_fd};

/// A fresh stream to the parent's engine API (the bridge's port 5000).
pub type Up = Arc<dyn Fn() -> io::Result<UnixStream> + Send + Sync>;

/// PCR0s a home accepts, at most.
pub const PINS_MAX: usize = 64;
/// The pins file, at most: `PINS_MAX` lines and their comments.
const PINS_BYTES_MAX: u64 = 64 * 1024;
/// Computers a home keeps credentials for, at most.
pub const CREDENTIALS_MAX: usize = 1024;
const STATE_FILE: &str = "sessions.json";
/// Each kept computer's egress: its policy and its intercepts' handler.
const EGRESS_FILE: &str = "egress.json";
const CA_CERT: &str = "ca.pem";
const CA_KEY: &str = "ca.key";
const CA_NAME: &str = "sandcastle home CA";
const STATE_BYTES_MAX: u64 = 1 << 20;
/// An upgrade's answer head, at most.
const HEAD_BYTES_MAX: usize = 8192;
/// How long a start waits for its computer to run before it attests.
const RUNNING_WAIT: Duration = Duration::from_secs(60);
/// How long an exec waits for the guest's first word.
const EXEC_START_WAIT: Duration = Duration::from_secs(30);
/// How long a start whose image this home does not pin waits for its pin:
/// within the cell's wait for its computer's first exec (120 s), with room
/// for the boot after it.
const UNPINNED_WAIT: Duration = Duration::from_secs(90);
/// How often a waiting start reads the pins again.
const PINS_LOOK: Duration = Duration::from_secs(2);

type Body = BoxBody<Bytes, hyper::Error>;

fn full(r: Response<Full<Bytes>>) -> Response<Body> {
    r.map(|b| b.map_err(|never| match never {}).boxed())
}

fn fail(e: ApiError) -> Response<Body> {
    full(super::server::error(e))
}

/// The home's sessions: its pins, its credentials, its way to the parent,
/// and its computers' egress.
pub struct Sessions {
    trust: sandcastle_nitro_attest::Trust,
    pins: Mutex<Pins>,
    /// The computers whose starts wait for their image's pin; a destroy
    /// takes its name out, and its start gives up.
    held: Mutex<BTreeSet<String>>,
    state: PathBuf,
    credentials: Mutex<BTreeMap<String, Credential>>,
    up: Up,
    ca: Arc<sandcastle_egress::ca::Ca>,
    egress: Mutex<BTreeMap<String, Kept>>,
    node_addrs: Vec<std::net::IpAddr>,
    rt: Arc<tokio::runtime::Runtime>,
}

/// The pins file and the last pins read from it whole. It is read again
/// at each claim and each look of a waiting start, so a pin added while
/// the home runs counts at once; a file that stops reading as pins keeps
/// the last good ones, said once in the log.
struct Pins {
    at: PathBuf,
    good: BTreeSet<[u8; 48]>,
    said: Option<String>,
}

/// One computer's egress: what its start asked for, and the proxy for it.
struct Kept {
    policy: sandcastle_egress::Policy,
    handler: PathBuf,
    proxy: Arc<sandcastle_egress::Egress>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KeptEgress {
    policy: sandcastle_egress::Policy,
    handler: PathBuf,
}

impl Sessions {
    /// The pins from `pins` (one PCR0 in hex a line, `#` comments), the
    /// credentials kept in `state` before.
    pub fn open(state: &Path, pins: &Path, up: Up) -> io::Result<Sessions> {
        let pins = Pins { at: pins.to_path_buf(), good: read_pins(&std::fs::read_to_string(pins)?)?, said: None };
        std::fs::create_dir_all(state)?;
        let file = state.join(STATE_FILE);
        let credentials = match std::fs::File::open(&file) {
            Ok(f) => {
                let mut body = Vec::new();
                f.take(STATE_BYTES_MAX + 1).read_to_end(&mut body)?;
                if body.len() as u64 > STATE_BYTES_MAX {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{} is past its ceiling", file.display())));
                }
                serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", file.display())))?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e),
        };
        let ca = Arc::new(home_ca(state)?);
        let rt = Arc::new(tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?);
        let s = Sessions {
            trust: sandcastle_nitro_attest::Trust::aws_nitro_enclaves_root_g1(),
            pins: Mutex::new(pins),
            held: Mutex::new(BTreeSet::new()),
            state: state.to_path_buf(),
            credentials: Mutex::new(credentials),
            up,
            ca,
            egress: Mutex::new(BTreeMap::new()),
            node_addrs: super::node_addrs(),
            rt,
        };
        // The kept computers' egress, as their starts asked.
        let file = state.join(EGRESS_FILE);
        if let Ok(body) = std::fs::read(&file) {
            let kept: BTreeMap<String, KeptEgress> = serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", file.display())))?;
            for (name, k) in kept {
                s.register(&name, k.policy, k.handler)?;
            }
        }
        Ok(s)
    }

    /// The pins as the file says now (`Pins`).
    fn pins(&self) -> BTreeSet<[u8; 48]> {
        let mut p = self.pins.lock().expect("never poisoned");
        let read = std::fs::File::open(&p.at).and_then(|f| {
            let mut text = String::new();
            f.take(PINS_BYTES_MAX + 1).read_to_string(&mut text)?;
            if text.len() as u64 > PINS_BYTES_MAX {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("past {PINS_BYTES_MAX} bytes")));
            }
            read_pins(&text)
        });
        match read {
            Ok(pins) => {
                p.good = pins;
                p.said = None;
            }
            Err(e) => {
                let why = e.to_string();
                if p.said.as_deref() != Some(why.as_str()) {
                    eprintln!("sandcastle-bridge: {}: {why}; the last good pins stand", p.at.display());
                    p.said = Some(why);
                }
            }
        }
        p.good.clone()
    }

    /// The egress a computer's start asks for, run in the home.
    fn register(&self, name: &str, policy: sandcastle_egress::Policy, handler: PathBuf) -> io::Result<()> {
        let rules = policy.compile(&self.node_addrs).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let proxy = Arc::new(sandcastle_egress::Egress::new(rules, self.ca.clone(), handler.clone(), name.to_string()));
        self.egress.lock().expect("never poisoned").insert(name.to_string(), Kept { policy, handler, proxy });
        self.save_egress()
    }

    /// A running computer's intercepts, replaced whole.
    fn set_intercepts(&self, name: &str, intercepts: Vec<sandcastle_egress::Intercept>) -> io::Result<()> {
        {
            let mut all = self.egress.lock().expect("never poisoned");
            let Some(k) = all.get_mut(name) else { return Ok(()) };
            let mut policy = k.policy.clone();
            policy.intercept = intercepts;
            let rules = policy.compile(&self.node_addrs).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            k.proxy.set_rules(rules);
            k.policy = policy;
        }
        self.save_egress()
    }

    fn save_egress(&self) -> io::Result<()> {
        let all = self.egress.lock().expect("never poisoned");
        let kept: BTreeMap<&String, KeptEgress> = all.iter().map(|(n, k)| (n, KeptEgress { policy: k.policy.clone(), handler: k.handler.clone() })).collect();
        write_private(&self.state.join(EGRESS_FILE), &serde_json::to_vec(&kept).expect("serializes"))
    }

    /// One of a guest's egress sessions (bridge port 5003): the guest found
    /// by its key, then its connection or lookup to its proxy.
    pub fn egress_connection(self: &Arc<Self>, s: UnixStream) -> io::Result<()> {
        let mut named = None;
        let (session, _) = sandcastle_session::accept_egress(s, |key| {
            let all = self.credentials.lock().expect("never poisoned");
            let (name, c) = all.iter().find(|(_, c)| c.guest_key == *key)?;
            named = Some(name.clone());
            Some(c.secret)
        })
        .map_err(io::Error::other)?;
        let name = named.expect("found with its secret");
        let proxy = self.egress.lock().expect("never poisoned").get(&name).map(|k| k.proxy.clone());
        let Some(proxy) = proxy else {
            return Err(io::Error::other(format!("{name} has no egress in this home")));
        };
        let plain = session.into_plain()?;
        plain.set_nonblocking(true)?;
        self.rt.spawn(async move {
            if let Ok(s) = tokio::net::UnixStream::from_std(plain) {
                let _ = proxy.connection(s).await;
            }
        });
        Ok(())
    }

    /// Attests the computer `name` and claims its session.
    pub fn claim(&self, name: &str) -> Result<(), String> {
        let stream = self.upgrade(name).map_err(|e| format!("reaching its session: {e}"))?;
        let (nonce, secret) = (random32().map_err(|e| e.to_string())?, random32().map_err(|e| e.to_string())?);
        let now = now_ms();
        // What the guest waits for before its workload starts: the home's CA,
        // and its egress to the home.
        let config = serde_json::to_vec(&serde_json::json!({ "ca_pem": self.ca.cert_pem(), "egress": true })).expect("serializes");
        let pins = self.pins();
        let (session, credential) = sandcastle_session::attest(stream, nonce, secret, &config, |doc| verify(&self.trust, &pins, doc, &nonce, now)).map_err(|e| e.to_string())?;
        // The claim's own session carries nothing more.
        drop(session);
        self.keep(name, Some(credential)).map_err(|e| format!("keeping its credential: {e}"))
    }

    /// A plain connection to the computer's agent, over a resumed session.
    pub fn dial(&self, name: &str) -> io::Result<UnixStream> {
        let credential = self.credentials.lock().expect("never poisoned").get(name).cloned();
        let Some(credential) = credential else {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("this home holds no session for {name}")));
        };
        let stream = self.upgrade(name)?;
        let session = sandcastle_session::resume(stream, random32()?, &credential).map_err(io::Error::other)?;
        session.into_plain()
    }

    /// A client of the computer's agent whose every connection is `dial`'s.
    fn agent(self: &Arc<Self>, name: &str) -> AgentClient {
        let (sessions, name) = (self.clone(), name.to_string());
        AgentClient::over(Arc::new(move || sessions.dial(&name)))
    }

    pub fn forget(&self, name: &str) -> io::Result<()> {
        let had = self.egress.lock().expect("never poisoned").remove(name).is_some();
        if had {
            self.save_egress()?;
        }
        self.keep(name, None)
    }

    fn keep(&self, name: &str, credential: Option<Credential>) -> io::Result<()> {
        let mut all = self.credentials.lock().expect("never poisoned");
        match credential {
            Some(c) => {
                if !all.contains_key(name) && all.len() >= CREDENTIALS_MAX {
                    return Err(io::Error::other(format!("{CREDENTIALS_MAX} computers' credentials held")));
                }
                all.insert(name.to_string(), c);
            }
            None => {
                all.remove(name);
            }
        }
        write_private(&self.state.join(STATE_FILE), &serde_json::to_vec(&*all).expect("serializes"))
    }

    /// A stream to the computer's session port, through the parent's engine.
    fn upgrade(&self, name: &str) -> io::Result<UnixStream> {
        api::validate_name(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut s = (self.up)()?;
        s.set_read_timeout(Some(sandcastle_session::HANDSHAKE_WAIT))?;
        write!(s, "POST /v1/containers/{name}/session HTTP/1.1\r\nHost: engine\r\nConnection: Upgrade\r\nUpgrade: {}\r\nContent-Length: 0\r\n\r\n", super::server::SESSION_UPGRADE)?;
        let head = read_head(&mut s)?;
        if !head.starts_with("HTTP/1.1 101") {
            return Err(io::Error::other(format!("the engine answered {}", head.lines().next().unwrap_or(""))));
        }
        s.set_read_timeout(None)?;
        Ok(s)
    }
}

/// Whole or not at all, and only this home's to read.
fn write_private(at: &Path, body: &[u8]) -> io::Result<()> {
    let partial = at.with_extension("partial");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&partial)?;
    f.write_all(body)?;
    f.sync_all()?;
    std::fs::rename(&partial, at)
}

/// The home's CA for its computers' intercepted hosts: made once, kept in
/// its state directory (the home's encrypted disk), so a computer kept
/// through a home restart still trusts it.
fn home_ca(state: &Path) -> io::Result<sandcastle_egress::ca::Ca> {
    let (cert, key) = (state.join(CA_CERT), state.join(CA_KEY));
    if let (Ok(c), Ok(k)) = (std::fs::read_to_string(&cert), std::fs::read_to_string(&key)) {
        return sandcastle_egress::ca::Ca::load(CA_NAME, &c, &k).map_err(io::Error::other);
    }
    let ca = sandcastle_egress::ca::Ca::generate(CA_NAME).map_err(io::Error::other)?;
    write_private(&key, ca.key_pem().as_bytes())?;
    write_private(&cert, ca.cert_pem().as_bytes())?;
    Ok(ca)
}

/// A document's checks for a claim: AWS's chain and the nonce
/// (`sandcastle_nitro_attest`), then a PCR0 of the pins; its key.
fn verify(trust: &sandcastle_nitro_attest::Trust, pins: &BTreeSet<[u8; 48]>, doc: &[u8], nonce: &[u8; 32], now_ms: u64) -> Result<[u8; 32], String> {
    let attested = sandcastle_nitro_attest::verify(trust, doc, nonce, now_ms).map_err(|e| e.to_string())?;
    let pcr0 = attested.pcr(0).ok_or("the document has no PCR0")?;
    if !pins.contains(pcr0) {
        return Err(format!("PCR0 {} is no image this home runs", hex::encode(pcr0)));
    }
    let key = attested.public_key.ok_or("the document binds no key")?;
    key.try_into().map_err(|_| "the document's key is not 32 bytes".to_string())
}

/// PCR0s, one in hex a line; blank lines and `#` comments skipped.
fn read_pins(text: &str) -> io::Result<BTreeSet<[u8; 48]>> {
    let mut pins = BTreeSet::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let pin: [u8; 48] = hex::decode(line).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a pin is a PCR0: 96 hex digits"))?;
        pins.insert(pin);
    }
    if pins.is_empty() || pins.len() > PINS_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("1 to {PINS_MAX} pins")));
    }
    Ok(pins)
}

/// An HTTP answer's head, read a byte at a time (what follows is the
/// session's).
fn read_head(s: &mut UnixStream) -> io::Result<String> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= HEAD_BYTES_MAX || s.read(&mut b)? == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "an upgrade's answer without its end"));
        }
        head.push(b[0]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

fn random32() -> io::Result<[u8; 32]> {
    let mut b = [0u8; 32];
    // SAFETY: getrandom writes at most the buffer's length.
    let n = unsafe { libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, b.len(), 0) };
    if n != b.len() as isize {
        return Err(io::Error::other("getrandom gave too few bytes"));
    }
    Ok(b)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Serves celld's `engine.sock` for the process's life.
pub fn serve_engine(listener: UnixListener, sessions: Arc<Sessions>) -> io::Result<()> {
    let rt = sessions.rt.clone();
    rt.block_on(async move {
        listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(listener)?;
        // Unbounded by design: the socket serves for the process's life.
        loop {
            let Ok((s, _)) = listener.accept().await else { continue };
            let sessions = sessions.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| route(sessions.clone(), req));
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc).with_upgrades().await;
            });
        }
    })
}

async fn route(sessions: Arc<Sessions>, req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    let path: Vec<String> = req.uri().path().trim_matches('/').split('/').map(str::to_string).collect();
    let p: Vec<&str> = path.iter().map(String::as_str).collect();
    let method = req.method().clone();
    Ok(match (&method, p.as_slice()) {
        (&Method::POST, ["v1", "containers", name, "exec"]) => exec(sessions, name.to_string(), req).await,
        (&Method::POST, ["v1", "containers", _, "session"]) => fail(ApiError::Invalid("a computer's session is its home's own".into())),
        (&Method::POST, ["v1", "containers", name, "start"]) => {
            let name = name.to_string();
            // Its policy, for the egress the home runs for it.
            let (req, start) = match buffered::<api::StartRequest>(req).await {
                Ok(r) => r,
                Err(e) => return Ok(fail(e)),
            };
            if let Some(image) = &start.image {
                if let Err(why) = wait_pinned(&sessions, &name, image, UNPINNED_WAIT, PINS_LOOK).await {
                    return Ok(fail(ApiError::Invalid(why)));
                }
            }
            let answer = forward(&sessions, req).await;
            if !answer.status().is_success() {
                return Ok(answer);
            }
            let policy = sandcastle_egress::Policy { internet: start.enable_internet, allow: start.allow.clone(), deny: start.deny.clone(), intercept: start.intercepts.clone() };
            let handler = PathBuf::from(start.handler.as_deref().and_then(|h| h.strip_prefix("unix:")).unwrap_or("/nonexistent"));
            if let Err(e) = sessions.register(&name, policy, handler) {
                let _ = destroy(&sessions, &name).await;
                return Ok(fail(ApiError::Invalid(format!("the computer's egress: {e}"))));
            }
            match claim_when_running(sessions.clone(), name.clone()).await {
                Ok(()) => answer,
                Err(why) => {
                    eprintln!("sandcastle-bridge: {name}: refused, destroyed: {why}");
                    let _ = destroy(&sessions, &name).await;
                    fail(ApiError::Internal(format!("the computer did not attest: {why}")))
                }
            }
        }
        (&Method::PUT, ["v1", "containers", name, "intercepts"]) => {
            let name = name.to_string();
            let (req, x) = match buffered::<api::InterceptsRequest>(req).await {
                Ok(r) => r,
                Err(e) => return Ok(fail(e)),
            };
            let answer = forward(&sessions, req).await;
            if answer.status().is_success() {
                if let Err(e) = sessions.set_intercepts(&name, x.intercepts) {
                    return Ok(fail(ApiError::Invalid(format!("the computer's intercepts: {e}"))));
                }
            }
            answer
        }
        (&Method::POST, ["v1", "containers", name, "destroy"]) => {
            let name = name.to_string();
            sessions.held.lock().expect("never poisoned").remove(&name);
            let answer = forward(&sessions, req).await;
            if answer.status().is_success() {
                let _ = sessions.forget(&name);
            }
            answer
        }
        _ => forward(&sessions, req).await,
    })
}

/// A request's body read whole (up to the engine's ceiling) and parsed, and
/// the same request again to forward.
async fn buffered<T: serde::de::DeserializeOwned>(req: Request<Incoming>) -> Result<(Request<Body>, T), ApiError> {
    let (parts, body) = req.into_parts();
    let bytes = http_body_util::Limited::new(body, super::server::BODY_BYTES_MAX)
        .collect()
        .await
        .map_err(|_| ApiError::Invalid(format!("a body of at most {} bytes", super::server::BODY_BYTES_MAX)))?
        .to_bytes();
    let parsed = serde_json::from_slice(&bytes).map_err(|e| ApiError::Invalid(format!("the body: {e}")))?;
    Ok((Request::from_parts(parts, Full::new(bytes).map_err(|never| match never {}).boxed()), parsed))
}

/// A start goes on at once when its image's PCR0 on this node is a pin, or
/// is not known (an engine that measures nothing, a full node: the claim
/// decides, as before). One the pins lack waits, the pins read again every
/// `look`, at most `wait`, and is refused then with no computer booted: a
/// missed pin costs a wait, not a computer booted to be refused, and a pin
/// added within the wait starts it.
async fn wait_pinned(sessions: &Arc<Sessions>, name: &str, image: &str, wait: Duration, look: Duration) -> Result<(), String> {
    let Some(pcr0) = image_pcr0(sessions, image).await else { return Ok(()) };
    if sessions.pins().contains(&pcr0) {
        return Ok(());
    }
    let shown = hex::encode(pcr0);
    eprintln!("sandcastle-bridge: {name}: its image's PCR0 {shown} is no pin: waiting up to {} s for it", wait.as_secs());
    sessions.held.lock().expect("never poisoned").insert(name.to_string());
    let t0 = std::time::Instant::now();
    // Bounded by `wait`.
    let r = loop {
        tokio::time::sleep(look).await;
        if sessions.pins().contains(&pcr0) {
            break Ok(());
        }
        if !sessions.held.lock().expect("never poisoned").contains(name) {
            break Err("destroyed while its start waited for its image's pin".to_string());
        }
        if t0.elapsed() >= wait {
            break Err(format!("PCR0 {shown} is no image this home runs (this node's measure of {image}); no computer was booted"));
        }
    };
    sessions.held.lock().expect("never poisoned").remove(name);
    match &r {
        Ok(()) => eprintln!("sandcastle-bridge: {name}: pinned after {} ms; starting", t0.elapsed().as_millis()),
        Err(why) => eprintln!("sandcastle-bridge: {name}: refused: {why}"),
    }
    r
}

/// The engine's PCR0 for `image` on its boot, measured now if it has none
/// (one small sandbox, once per image and boot). A hint only: the claim
/// still checks the computer's own document.
async fn image_pcr0(sessions: &Sessions, image: &str) -> Option<[u8; 48]> {
    let at = format!("/v1/images/{}", path_segment(image));
    let held = call(sessions, Method::GET, &at, None).await.ok()?;
    let pcr0 = match held["pcr0"].as_str() {
        Some(p) => p.to_string(),
        None => {
            let nonce = hex::encode(random32().ok()?);
            let measured = call(sessions, Method::POST, &format!("{at}/measure"), Some(serde_json::json!({ "nonce": nonce }))).await.ok()?;
            measured["pcr0"].as_str()?.to_string()
        }
    };
    hex::decode(pcr0).ok()?.try_into().ok()
}

/// `s` as one URL path segment: what is not unreserved, percent-encoded.
fn path_segment(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~:@".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// One JSON call to the parent's engine; a status that is not a success is
/// its error.
async fn call(sessions: &Sessions, method: Method, path: &str, body: Option<serde_json::Value>) -> Result<serde_json::Value, ApiError> {
    let body = body.map(|b| Bytes::from(serde_json::to_vec(&b).expect("serializes"))).unwrap_or_default();
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "engine")
        .header("content-type", "application/json")
        .body(Full::new(body).map_err(|never| match never {}).boxed())
        .map_err(|e| ApiError::Invalid(e.to_string()))?;
    let r = send(sessions, req).await.map_err(ApiError::Internal)?;
    let ok = r.status().is_success();
    let body = r.into_body().collect().await.map_err(|e| ApiError::Internal(e.to_string()))?.to_bytes();
    if !ok {
        return Err(ApiError::Internal(String::from_utf8_lossy(&body).chars().take(500).collect()));
    }
    serde_json::from_slice(&body).map_err(|e| ApiError::Internal(format!("{path}: {e}")))
}

/// The start's computer running, then claimed.
async fn claim_when_running(sessions: Arc<Sessions>, name: String) -> Result<(), String> {
    let t0 = std::time::Instant::now();
    // Bounded by RUNNING_WAIT.
    loop {
        match inspect(&sessions, &name).await {
            Ok(v) if v["state"] == "running" => break,
            Ok(v) if v["running"] == false => return Err("it ended as it started".into()),
            _ if t0.elapsed() > RUNNING_WAIT => return Err(format!("not running within {} s", RUNNING_WAIT.as_secs())),
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    tokio::task::spawn_blocking(move || sessions.claim(&name)).await.map_err(|e| e.to_string())?
}

/// An exec over the computer's session: the engine's plan, the agent's
/// session, then the same stream the engine's own exec answers.
async fn exec(sessions: Arc<Sessions>, name: String, mut req: Request<Incoming>) -> Response<Body> {
    let upgrading = req.headers().get("upgrade").and_then(|v| v.to_str().ok()) == Some(crate::exec_stream::UPGRADE);
    let on_upgrade = hyper::upgrade::on(&mut req);
    let x: ExecRequest = match super::server::body(req).await {
        Ok(_) if !upgrading => return fail(ApiError::Invalid(format!("exec upgrades to {}", crate::exec_stream::UPGRADE))),
        Ok(x) => x,
        Err(e) => return fail(e),
    };
    // The container's PATH, as its image gives it.
    let path = match inspect(&sessions, &name).await {
        Ok(v) => v["path"].as_str().map(str::to_string),
        Err(e) => return fail(e),
    };
    let plan = match api::exec_plan(x, path) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let agent = sessions.agent(&name);
    let opened = tokio::task::spawn_blocking(move || {
        let mut s = agent.exec_with(plan.process, plan.stdin, plan.pty, plan.stdout, plan.stderr)?;
        s.set_read_timeout(Some(EXEC_START_WAIT))?;
        let first = s.next_event();
        s.set_read_timeout(None)?;
        Ok::<_, ClientError>((s, first))
    })
    .await;
    match opened {
        Ok(Ok((s, Ok(sandcastle_vm::client::ExecEvent::Started(pid))))) => {
            tokio::spawn(async move {
                if let Ok(up) = on_upgrade.await {
                    super::exec::bridge(up, s, pid).await;
                }
            });
            full(super::server::switching())
        }
        Ok(Ok((_, Ok(other)))) => fail(ApiError::Internal(format!("exec: {other:?} before the process started"))),
        Ok(Ok((_, Err(ClientError::Refused(m))))) | Ok(Err(ClientError::Refused(m))) => fail(ApiError::Invalid(format!("exec: {m}"))),
        Ok(Ok((_, Err(e)))) | Ok(Err(e)) => fail(ApiError::Internal(format!("exec over its session: {e}"))),
        Err(e) => fail(ApiError::Internal(format!("exec: {e}"))),
    }
}

/// One request to the parent's engine, on a connection of its own.
async fn forward<B>(sessions: &Sessions, req: Request<B>) -> Response<Body>
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error> + Send + Sync + 'static,
{
    match send(sessions, req.map(|b| b.boxed())).await {
        Ok(r) => r.map(|b| b.boxed()),
        Err(e) => fail(ApiError::Internal(format!("the parent's engine: {e}"))),
    }
}

async fn send(sessions: &Sessions, req: Request<Body>) -> Result<Response<Incoming>, String> {
    let up = (sessions.up)().map_err(|e| e.to_string())?;
    up.set_nonblocking(true).map_err(|e| e.to_string())?;
    let up = tokio::net::UnixStream::from_std(up).map_err(|e| e.to_string())?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(up)).await.map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    sender.send_request(req).await.map_err(|e| e.to_string())
}

/// The parent's `inspect` of a computer.
async fn inspect(sessions: &Sessions, name: &str) -> Result<serde_json::Value, ApiError> {
    api::validate_name(name)?;
    let req = Request::get(format!("/v1/containers/{name}")).header("host", "engine").body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed()).expect("a request");
    let r = send(sessions, req).await.map_err(ApiError::Internal)?;
    let ok = r.status().is_success();
    let body = r.into_body().collect().await.map_err(|e| ApiError::Internal(e.to_string()))?.to_bytes();
    if !ok {
        return Err(ApiError::NotFound(String::from_utf8_lossy(&body).chars().take(500).collect()));
    }
    serde_json::from_slice(&body).map_err(|e| ApiError::Internal(format!("inspect: {e}")))
}

async fn destroy(sessions: &Sessions, name: &str) -> Result<(), String> {
    let req = Request::post(format!("/v1/containers/{name}/destroy"))
        .header("host", "engine")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(b"{}")).map_err(|never| match never {}).boxed())
        .expect("a request");
    send(sessions, req).await.map(|_| ())
}

/// One `ports.sock` request in the home, over the computer's session: the
/// agent's connect to the port, handed to celld as a unix socket.
pub fn port(client: UnixStream, sessions: &Arc<Sessions>) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    client.set_read_timeout(Some(ports::CONNECT_WAIT + Duration::from_secs(4)))?;
    let line = super::bridge::read_line(&client)?;
    let reply = |ok: bool, kind: &str, error: &str| -> Vec<u8> {
        if ok {
            br#"{"ok":true,"transport":"vsock"}"#.to_vec()
        } else {
            serde_json::to_vec(&serde_json::json!({ "ok": false, "kind": kind, "error": error })).expect("serializes")
        }
    };
    let req = match ports::parse_request(line.strip_suffix(b"\n").unwrap_or(&line)) {
        Ok(r) => r,
        Err(_) => return send_with_fd(client.as_raw_fd(), &reply(false, "invalid", "a container's name and a port from 1"), None),
    };
    match sessions.agent(&req.name).connect_exact(req.port) {
        Ok(conn) => send_with_fd(client.as_raw_fd(), &reply(true, "", ""), Some(conn.as_raw_fd())),
        Err(ClientError::Refused(m)) => send_with_fd(client.as_raw_fd(), &reply(false, "refused", &m), None),
        Err(e) => send_with_fd(client.as_raw_fd(), &reply(false, "internal", &e.to_string()), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: pins read as PCR0s and nothing else: comments and blanks
    // skipped, a short, long or non-hex line refused, none or too many
    // refused.
    #[test]
    fn pins_are_pcr0s() {
        let a = "ab".repeat(48);
        let pins = read_pins(&format!("# the Hermes image, node A\n{a}\n\n{}\n", "cd".repeat(48))).unwrap();
        assert_eq!(pins.len(), 2);
        assert!(pins.contains(&[0xab; 48]));
        for bad in ["", "# only a comment", &"ab".repeat(47), &"ab".repeat(49), &"zz".repeat(48)] {
            assert!(read_pins(bad).is_err(), "{bad}");
        }
        let many: String = (0..=PINS_MAX).map(|i| format!("{:096x}\n", i)).collect();
        assert!(read_pins(&many).is_err());
    }

    // Goal: credentials are kept across a home restart, and forgotten; the
    // file is the home's alone (0600). Method: a Sessions over a dir, its
    // credentials written, then a second Sessions reading them.
    #[test]
    fn credentials_survive_a_home_restart() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("home-sessions-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pins = dir.join("pins");
        std::fs::write(&pins, "ab".repeat(48)).unwrap();
        let up: Up = Arc::new(|| Err(io::Error::other("no parent in this test")));
        let a = Sessions::open(&dir.join("state"), &pins, up.clone()).unwrap();
        let c = Credential { guest_key: [1; 32], secret: [2; 32] };
        a.keep("c1", Some(c.clone())).unwrap();
        a.keep("c2", Some(c.clone())).unwrap();
        a.forget("c2").unwrap();
        let mode = std::fs::metadata(dir.join("state").join(STATE_FILE)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let b = Sessions::open(&dir.join("state"), &pins, up).unwrap();
        assert_eq!(b.credentials.lock().unwrap().get("c1"), Some(&c));
        assert!(b.credentials.lock().unwrap().get("c2").is_none());
        assert_eq!(b.dial("c2").unwrap_err().kind(), io::ErrorKind::NotFound, "no credential, no session");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Goal: a document whose PCR0 is not a pin is refused, whatever else it
    // says; one that does not verify is refused before that. Method: the
    // spike's test kit makes a document a test root signs.
    #[test]
    fn only_a_pinned_image_attests() {
        use sandcastle_nitro_attest::testkit::{document, Chain, Fields, T0_MS};
        let chain = Chain::new();
        let nonce = [9u8; 32];
        let mut f = Fields::new();
        f.nonce = Some(nonce.to_vec());
        f.public_key = Some(vec![7u8; 32]);
        f.pcrs = vec![(0, vec![0x11; 48]), (1, vec![0x01; 48])];
        let doc = document(&chain, &f);
        let pinned: BTreeSet<[u8; 48]> = [[0x11; 48]].into();
        let other: BTreeSet<[u8; 48]> = [[0x22; 48]].into();
        assert_eq!(verify(&chain.trust(), &pinned, &doc, &nonce, T0_MS).unwrap(), [7u8; 32]);
        assert!(verify(&chain.trust(), &other, &doc, &nonce, T0_MS).unwrap_err().contains("PCR0"));
        assert!(verify(&chain.trust(), &pinned, &doc, &[8u8; 32], T0_MS).is_err(), "another nonce");
        let aws = sandcastle_nitro_attest::Trust::aws_nitro_enclaves_root_g1();
        assert!(verify(&aws, &pinned, &doc, &nonce, T0_MS).is_err(), "another root");
        f.public_key = Some(vec![7u8; 294]);
        assert!(verify(&chain.trust(), &pinned, &document(&chain, &f), &nonce, T0_MS).unwrap_err().contains("32 bytes"));
    }

    /// A parent's engine for a test: each connection answers its one
    /// request (`answer` of its request line and body), and is closed.
    fn fake_up(answer: impl Fn(&str, &[u8]) -> (u16, String) + Send + Sync + 'static) -> Up {
        let answer = Arc::new(answer);
        Arc::new(move || {
            let (mine, mut theirs) = UnixStream::pair()?;
            let answer = answer.clone();
            std::thread::spawn(move || {
                let Ok(head) = read_head(&mut theirs) else { return };
                let length = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|n| n.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                let mut body = vec![0u8; length];
                if theirs.read_exact(&mut body).is_err() {
                    return;
                }
                let (status, text) = answer(head.lines().next().unwrap_or(""), &body);
                let _ = write!(theirs, "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}", text.len());
            });
            Ok(mine)
        })
    }

    fn pin(b: u8) -> String {
        hex::encode([b; 48])
    }

    // Goal: a start whose image's PCR0 is no pin waits, boots nothing, and
    // goes on once the pin is added; one already pinned goes on at once;
    // one never pinned is refused at the wait's end; a destroy ends a
    // wait; an image the engine has no PCR0 for is measured once, with a
    // fresh nonce; an engine that cannot say leaves it to the claim. And
    // pins that stop reading keep the last good ones.
    #[test]
    fn an_unpinned_start_waits_for_its_pin() {
        let dir = std::env::temp_dir().join(format!("home-pins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pins = dir.join("pins");
        std::fs::write(&pins, format!("{}\n", pin(0xaa))).unwrap();
        let measures = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = measures.clone();
        let up = fake_up(move |line, body| match line {
            l if l.starts_with("GET /v1/images/img ") => (200, format!(r#"{{"reference":"img","pcr0":"{}"}}"#, pin(0xbb))),
            l if l.starts_with("GET /v1/images/never ") => (200, format!(r#"{{"reference":"never","pcr0":"{}"}}"#, pin(0xcc))),
            l if l.starts_with("GET /v1/images/fresh%2Fone ") => (200, r#"{"reference":"fresh/one"}"#.to_string()),
            l if l.starts_with("POST /v1/images/fresh%2Fone/measure ") => {
                let v: serde_json::Value = serde_json::from_slice(body).unwrap();
                seen.lock().unwrap().push(v["nonce"].as_str().unwrap().to_string());
                (200, format!(r#"{{"pcr0":"{}","document":"00"}}"#, pin(0xaa)))
            }
            _ => (404, r#"{"error":"no such image","kind":"not_found"}"#.to_string()),
        });
        let s = Arc::new(Sessions::open(&dir.join("state"), &pins, up).unwrap());
        let (wait, look) = (Duration::from_secs(5), Duration::from_millis(50));
        let rt = s.rt.clone();

        // Pinned while it waits: it goes on, a look or so after the pin.
        let writer = {
            let pins = pins.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(400));
                std::fs::write(&pins, format!("{}\n{}\n", pin(0xaa), pin(0xbb))).unwrap();
            })
        };
        let t0 = std::time::Instant::now();
        rt.block_on(wait_pinned(&s, "c1", "img", wait, look)).unwrap();
        writer.join().unwrap();
        assert!(t0.elapsed() >= Duration::from_millis(400) && t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
        assert!(s.held.lock().unwrap().is_empty());

        // Pinned already: at once.
        let t0 = std::time::Instant::now();
        rt.block_on(wait_pinned(&s, "c1", "img", wait, look)).unwrap();
        assert!(t0.elapsed() < look, "{:?}", t0.elapsed());

        // Never pinned: refused when the wait ends, booting nothing.
        let t0 = std::time::Instant::now();
        let why = rt.block_on(wait_pinned(&s, "c2", "never", Duration::from_millis(300), look)).unwrap_err();
        assert!(why.contains(&pin(0xcc)) && why.contains("no computer was booted"), "{why}");
        assert!(t0.elapsed() >= Duration::from_millis(300));

        // A destroy while it waits ends the wait.
        let destroyer = {
            let s = s.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                s.held.lock().unwrap().remove("c3");
            })
        };
        let why = rt.block_on(wait_pinned(&s, "c3", "never", wait, look)).unwrap_err();
        destroyer.join().unwrap();
        assert!(why.contains("destroyed"), "{why}");

        // No PCR0 yet: measured, with a fresh nonce each time.
        rt.block_on(wait_pinned(&s, "c4", "fresh/one", wait, look)).unwrap();
        rt.block_on(wait_pinned(&s, "c4", "fresh/one", wait, look)).unwrap();
        let nonces = measures.lock().unwrap().clone();
        assert_eq!(nonces.len(), 2);
        assert!(nonces.iter().all(|n| n.len() == 64) && nonces[0] != nonces[1], "{nonces:?}");

        // The engine cannot say (no such image, no route): the claim decides.
        rt.block_on(wait_pinned(&s, "c5", "unknown", wait, look)).unwrap();

        // Pins that stop reading keep the last good ones.
        std::fs::write(&pins, "not a pin\n").unwrap();
        assert!(s.pins().contains(&[0xbb; 48]));
        std::fs::write(&pins, format!("{}\n", pin(0xcc))).unwrap();
        assert_eq!(s.pins(), [[0xcc; 48]].into());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
