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
//! **Several engines** (docs/nitro.md, "Computers on other parents"): a
//! home may drive engines on other parents too, each over the network.
//! A start goes to the first engine, in the home's order (its own
//! parent's first), that holds its image and whose memory takes it; each
//! computer's calls then go to its engine. The list and health are every
//! engine's; the images are those every engine that answers holds, and a
//! load goes to each.
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

/// A fresh stream to an engine's API: the parent's (the bridge's port
/// 5000), or another parent's over the network.
pub type Up = Arc<dyn Fn() -> io::Result<UnixStream> + Send + Sync>;

/// One engine a home drives: its name in logs and health, its API, and
/// where that engine is to send this home's computers' egress sessions
/// (the start's `egressTo`; none, the engine's own).
#[derive(Clone)]
pub struct EngineAt {
    pub name: String,
    pub up: Up,
    pub egress_to: Option<String>,
}

/// Engines a home drives, at most.
pub const ENGINES_MAX: usize = 16;

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
/// A load's frames on their way to one engine, at most.
const LOAD_FRAMES_QUEUED: usize = 4;

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
    /// The engines, its own parent's first.
    engines: Vec<EngineAt>,
    /// Which engine each computer runs on: set by its start, found again
    /// by asking each engine after a home restart, dropped by its destroy.
    placed: Mutex<BTreeMap<String, usize>>,
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
    pub fn open(state: &Path, pins: &Path, engines: Vec<EngineAt>) -> io::Result<Sessions> {
        if engines.is_empty() || engines.len() > ENGINES_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("1 to {ENGINES_MAX} engines")));
        }
        let names: BTreeSet<&str> = engines.iter().map(|e| e.name.as_str()).collect();
        if names.len() != engines.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "each engine its own name"));
        }
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
            engines,
            placed: Mutex::new(BTreeMap::new()),
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

    /// A stream to the computer's session port, through its engine (its
    /// start placed it, or `engine_of` found it).
    fn upgrade(&self, name: &str) -> io::Result<UnixStream> {
        api::validate_name(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let Some(i) = self.placed.lock().expect("never poisoned").get(name).copied() else {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("no engine of this home runs {name}")));
        };
        let mut s = (self.engines[i].up)()?;
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

impl Sessions {
    fn place_at(&self, name: &str, i: usize) {
        let mut placed = self.placed.lock().expect("never poisoned");
        if placed.contains_key(name) || placed.len() < CREDENTIALS_MAX {
            placed.insert(name.to_string(), i);
        }
    }

    fn unplace(&self, name: &str) {
        self.placed.lock().expect("never poisoned").remove(name);
    }

    /// The engine computer `name` runs on: where its start placed it, or
    /// the one that answers for it. Not found on any is a 404, as on one
    /// engine; an engine that cannot answer makes it unknown, never gone.
    async fn engine_of(&self, name: &str) -> Result<usize, ApiError> {
        if let Some(i) = self.placed.lock().expect("never poisoned").get(name).copied() {
            return Ok(i);
        }
        let mut unanswered = None;
        for i in 0..self.engines.len() {
            match inspect(self, i, name).await {
                Ok(_) => {
                    self.place_at(name, i);
                    return Ok(i);
                }
                Err(ApiError::NotFound(_)) => {}
                Err(e) => unanswered = Some(format!("engine {}: {e}", self.engines[i].name)),
            }
        }
        Err(match unanswered {
            Some(why) => ApiError::Internal(format!("{name} is on no engine that answered, and {why}")),
            None => ApiError::NotFound(format!("no container {name} is running")),
        })
    }

    /// Where a start of `memory_mib` of `image` goes: the first engine, in
    /// the home's order, that holds the image and whose memory takes the
    /// start (the engine's own test); with none, the one holding it with
    /// the most memory free, which refuses it as a full node does (429).
    async fn place(&self, image: Option<&str>, memory_mib: u64) -> usize {
        let mut fullest: Option<(usize, i64)> = None;
        for i in 0..self.engines.len() {
            let Ok(h) = call(self, i, Method::GET, "/v1/health", None).await else { continue };
            // The list, which every engine answers (not only one that
            // measures).
            if let Some(image) = image {
                let held = call(self, i, Method::GET, "/v1/images", None).await;
                if !held.is_ok_and(|l| l.as_array().is_some_and(|l| l.iter().any(|m| m["reference"] == image))) {
                    continue;
                }
            }
            let (used, max) = (h["memory_mib"].as_i64().unwrap_or(i64::MAX), h["memory_mib_max"].as_i64().unwrap_or(0));
            if used + memory_mib as i64 <= max {
                return i;
            }
            if fullest.is_none_or(|(_, free)| max - used > free) {
                fullest = Some((i, max - used));
            }
        }
        fullest.map(|(i, _)| i).unwrap_or(0)
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
            // A computer running already is its engine's to answer (a
            // conflict, as on one engine); a new one is placed.
            let (i, running) = match sessions.engine_of(&name).await {
                Ok(i) => (i, true),
                Err(ApiError::NotFound(_)) => {
                    let memory = api::resources(start.instance.as_ref()).map(|r| r.memory_mib as u64).unwrap_or(0);
                    (sessions.place(start.image.as_deref(), memory).await, false)
                }
                Err(e) => return Ok(fail(e)),
            };
            sessions.place_at(&name, i);
            let unplace = |sessions: &Sessions| {
                if !running {
                    sessions.unplace(&name);
                }
            };
            if let Some(image) = &start.image {
                if let Err(why) = wait_pinned(&sessions, i, &name, image, UNPINNED_WAIT, PINS_LOOK).await {
                    unplace(&sessions);
                    return Ok(fail(ApiError::Invalid(why)));
                }
            }
            if sessions.engines.len() > 1 {
                eprintln!("sandcastle-bridge: {name}: on engine {}", sessions.engines[i].name);
            }
            // Its egress sessions to this home, from whichever engine runs it.
            let req = match &sessions.engines[i].egress_to {
                Some(to) => {
                    let mut body = serde_json::to_value(&start).expect("serializes");
                    body["egressTo"] = serde_json::Value::String(to.clone());
                    let (mut parts, _) = req.into_parts();
                    parts.headers.remove(hyper::header::CONTENT_LENGTH);
                    Request::from_parts(parts, Full::new(Bytes::from(serde_json::to_vec(&body).expect("serializes"))).map_err(|never| match never {}).boxed())
                }
                None => req,
            };
            let answer = forward(&sessions, i, req).await;
            if !answer.status().is_success() {
                unplace(&sessions);
                return Ok(answer);
            }
            let policy = sandcastle_egress::Policy { internet: start.enable_internet, allow: start.allow.clone(), deny: start.deny.clone(), intercept: start.intercepts.clone() };
            let handler = PathBuf::from(start.handler.as_deref().and_then(|h| h.strip_prefix("unix:")).unwrap_or("/nonexistent"));
            if let Err(e) = sessions.register(&name, policy, handler) {
                let _ = destroy(&sessions, i, &name).await;
                unplace(&sessions);
                return Ok(fail(ApiError::Invalid(format!("the computer's egress: {e}"))));
            }
            match claim_when_running(sessions.clone(), i, name.clone()).await {
                Ok(()) => answer,
                Err(why) => {
                    eprintln!("sandcastle-bridge: {name}: refused, destroyed: {why}");
                    let _ = destroy(&sessions, i, &name).await;
                    unplace(&sessions);
                    fail(ApiError::Internal(format!("the computer did not attest: {why}")))
                }
            }
        }
        (&Method::PUT, ["v1", "containers", name, "intercepts"]) => {
            let name = name.to_string();
            let i = match sessions.engine_of(&name).await {
                Ok(i) => i,
                Err(e) => return Ok(fail(e)),
            };
            let (req, x) = match buffered::<api::InterceptsRequest>(req).await {
                Ok(r) => r,
                Err(e) => return Ok(fail(e)),
            };
            let answer = forward(&sessions, i, req).await;
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
            // On no engine: the first answers it, as one engine would.
            let i = match sessions.engine_of(&name).await {
                Ok(i) => i,
                Err(ApiError::NotFound(_)) => 0,
                Err(e) => return Ok(fail(e)),
            };
            let answer = forward(&sessions, i, req).await;
            if answer.status().is_success() {
                let _ = sessions.forget(&name);
                sessions.unplace(&name);
            }
            answer
        }
        (&Method::GET, ["v1", "containers"]) => every_engine(&sessions, "/v1/containers", merge_lists).await,
        (&Method::GET, ["v1", "health"]) => every_engine(&sessions, "/v1/health", merge_health).await,
        (&Method::GET, ["v1", "images"]) => every_engine(&sessions, "/v1/images", images_everywhere).await,
        (&Method::POST, ["v1", "images", "load"]) => load_everywhere(&sessions, req).await,
        (_, ["v1", "containers", name, ..]) => match sessions.engine_of(name).await {
            Ok(i) => forward(&sessions, i, req).await,
            Err(e) => fail(e),
        },
        _ => forward(&sessions, 0, req).await,
    })
}

/// One GET to every engine, the answers that came merged by `merge` with
/// their engines' names. An engine that does not answer is said in the
/// log and left out; with none answering, the first's error.
async fn every_engine(sessions: &Sessions, path: &str, merge: fn(Vec<(&str, serde_json::Value)>) -> serde_json::Value) -> Response<Body> {
    let mut answers = Vec::new();
    let mut first_error = None;
    for i in 0..sessions.engines.len() {
        match call(sessions, i, Method::GET, path, None).await {
            Ok(v) => answers.push((sessions.engines[i].name.as_str(), v)),
            Err(e) => {
                eprintln!("sandcastle-bridge: engine {}: {path}: {e}", sessions.engines[i].name);
                first_error.get_or_insert(e);
            }
        }
    }
    match (answers.is_empty(), first_error) {
        (true, Some(e)) => fail(e),
        _ => full(super::server::json(200, &merge(answers))),
    }
}

/// Every engine's computers, in one list.
fn merge_lists(answers: Vec<(&str, serde_json::Value)>) -> serde_json::Value {
    answers.into_iter().flat_map(|(_, v)| v.as_array().cloned().unwrap_or_default()).collect()
}

/// The engines' counts summed, and each engine's own.
fn merge_health(answers: Vec<(&str, serde_json::Value)>) -> serde_json::Value {
    let sum = |k: &str| answers.iter().map(|(_, v)| v[k].as_u64().unwrap_or(0)).sum::<u64>();
    let engines: Vec<serde_json::Value> = answers
        .iter()
        .map(|(name, v)| serde_json::json!({ "name": name, "vms": v["vms"], "memory_mib": v["memory_mib"], "memory_mib_max": v["memory_mib_max"] }))
        .collect();
    serde_json::json!({
        "vms": sum("vms"),
        "vms_max": sum("vms_max"),
        "memory_mib": sum("memory_mib"),
        "memory_mib_max": sum("memory_mib_max"),
        "ca_pem": answers.first().map(|(_, v)| v["ca_pem"].clone()).unwrap_or_default(),
        "engines": engines,
    })
}

/// The images every engine that answered holds, by reference: celld loads
/// one any of them lacks, and the load goes to each.
fn images_everywhere(answers: Vec<(&str, serde_json::Value)>) -> serde_json::Value {
    let refs = |v: &serde_json::Value| -> BTreeSet<String> { v.as_array().into_iter().flatten().filter_map(|i| i["reference"].as_str().map(str::to_string)).collect() };
    let Some(((_, first), rest)) = answers.split_first() else { return serde_json::json!([]) };
    let everywhere: BTreeSet<String> = rest.iter().fold(refs(first), |held, (_, v)| held.intersection(&refs(v)).cloned().collect());
    first.as_array().into_iter().flatten().filter(|i| i["reference"].as_str().is_some_and(|r| everywhere.contains(r))).cloned().collect()
}

/// A load (`docker save`'s tar) to every engine at once, its body sent to
/// each as it comes. It answers the first engine's answer once each
/// engine that took it loaded it; any that failed, its error. An engine
/// that cannot be reached is said in the log and left out: its starts go
/// elsewhere (`place` needs the image held).
async fn load_everywhere(sessions: &Arc<Sessions>, req: Request<Incoming>) -> Response<Body> {
    use http_body_util::channel::Channel;
    let (parts, mut body) = req.into_parts();
    let path = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/v1/images/load".into());
    let mut senders = Vec::new();
    let mut answers = Vec::new();
    for i in 0..sessions.engines.len() {
        let (tx, rx) = Channel::<Bytes, io::Error>::new(LOAD_FRAMES_QUEUED);
        let mut b = Request::post(path.as_str()).header("host", "engine");
        if let Some(t) = parts.headers.get("content-type") {
            b = b.header("content-type", t);
        }
        let r = b.body(rx).expect("a request");
        let s = sessions.clone();
        answers.push(tokio::spawn(async move { send(&s, i, r).await }));
        senders.push(Some(tx));
    }
    // Bounded by the body's length (each engine caps an image).
    let mut cut = None;
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    for tx in senders.iter_mut() {
                        if let Some(t) = tx {
                            if t.send_data(data.clone()).await.is_err() {
                                *tx = None;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                cut = Some(e.to_string());
                break;
            }
        }
    }
    for tx in senders.into_iter().flatten() {
        if cut.is_some() {
            // An engine must not build a cut tar as if whole.
            tx.abort(io::Error::other("the upload was cut"));
        }
    }
    if let Some(why) = cut {
        return fail(ApiError::Invalid(format!("the image's upload: {why}")));
    }
    let mut first: Option<Response<Body>> = None;
    for (i, answer) in answers.into_iter().enumerate() {
        let name = &sessions.engines[i].name;
        match answer.await {
            Ok(Ok(r)) if r.status().is_success() => {
                if first.is_none() {
                    first = Some(r.map(|b| b.boxed()));
                }
            }
            Ok(Ok(r)) => {
                let status = r.status();
                let text = r.into_body().collect().await.map(|b| String::from_utf8_lossy(&b.to_bytes()).chars().take(500).collect::<String>()).unwrap_or_default();
                return fail(ApiError::Internal(format!("engine {name}: {status} {text}")));
            }
            Ok(Err(e)) => eprintln!("sandcastle-bridge: engine {name}: a load: {e}; its starts go elsewhere"),
            Err(e) => eprintln!("sandcastle-bridge: engine {name}: a load: {e}"),
        }
    }
    first.unwrap_or_else(|| fail(ApiError::Internal("no engine took the image".into())))
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
async fn wait_pinned(sessions: &Arc<Sessions>, engine: usize, name: &str, image: &str, wait: Duration, look: Duration) -> Result<(), String> {
    let Some(pcr0) = image_pcr0(sessions, engine, image).await else { return Ok(()) };
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
async fn image_pcr0(sessions: &Sessions, engine: usize, image: &str) -> Option<[u8; 48]> {
    let at = format!("/v1/images/{}", path_segment(image));
    let held = call(sessions, engine, Method::GET, &at, None).await.ok()?;
    let pcr0 = match held["pcr0"].as_str() {
        Some(p) => p.to_string(),
        None => {
            let nonce = hex::encode(random32().ok()?);
            let measured = call(sessions, engine, Method::POST, &format!("{at}/measure"), Some(serde_json::json!({ "nonce": nonce }))).await.ok()?;
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

/// One JSON call to engine `engine`; a status that is not a success is its
/// error (a 404 as `NotFound`).
async fn call(sessions: &Sessions, engine: usize, method: Method, path: &str, body: Option<serde_json::Value>) -> Result<serde_json::Value, ApiError> {
    let body = body.map(|b| Bytes::from(serde_json::to_vec(&b).expect("serializes"))).unwrap_or_default();
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "engine")
        .header("content-type", "application/json")
        .body(Full::new(body))
        .map_err(|e| ApiError::Invalid(e.to_string()))?;
    let r = send(sessions, engine, req).await.map_err(ApiError::Internal)?;
    let status = r.status();
    let body = r.into_body().collect().await.map_err(|e| ApiError::Internal(e.to_string()))?.to_bytes();
    let text = || String::from_utf8_lossy(&body).chars().take(500).collect::<String>();
    if status == hyper::StatusCode::NOT_FOUND {
        return Err(ApiError::NotFound(text()));
    }
    if !status.is_success() {
        return Err(ApiError::Internal(text()));
    }
    serde_json::from_slice(&body).map_err(|e| ApiError::Internal(format!("{path}: {e}")))
}

/// The start's computer running, then claimed.
async fn claim_when_running(sessions: Arc<Sessions>, engine: usize, name: String) -> Result<(), String> {
    let t0 = std::time::Instant::now();
    // Bounded by RUNNING_WAIT.
    loop {
        match inspect(&sessions, engine, &name).await {
            Ok(v) if v["state"] == "running" => break,
            Ok(v) if v["running"] == false => return Err("it ended as it started".into()),
            // Its engine answered its start, then holds no such computer:
            // it ended and is gone, not on its way.
            Err(ApiError::NotFound(_)) => return Err("it was gone right after its start".into()),
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
    // The container's PATH, as its image gives it, from its engine.
    let engine = match sessions.engine_of(&name).await {
        Ok(i) => i,
        Err(e) => return fail(e),
    };
    let path = match inspect(&sessions, engine, &name).await {
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

/// One request to engine `engine`, on a connection of its own.
async fn forward<B>(sessions: &Sessions, engine: usize, req: Request<B>) -> Response<Body>
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error> + Send + Sync + 'static,
{
    match send(sessions, engine, req.map(|b| b.boxed())).await {
        Ok(r) => r.map(|b| b.boxed()),
        Err(e) => fail(ApiError::Internal(format!("engine {}: {e}", sessions.engines[engine].name))),
    }
}

async fn send<B>(sessions: &Sessions, engine: usize, req: Request<B>) -> Result<Response<Incoming>, String>
where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let up = (sessions.engines[engine].up)().map_err(|e| e.to_string())?;
    up.set_nonblocking(true).map_err(|e| e.to_string())?;
    let up = tokio::net::UnixStream::from_std(up).map_err(|e| e.to_string())?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(up)).await.map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    sender.send_request(req).await.map_err(|e| e.to_string())
}

/// An engine's `inspect` of a computer: a 404 is `NotFound`.
async fn inspect(sessions: &Sessions, engine: usize, name: &str) -> Result<serde_json::Value, ApiError> {
    api::validate_name(name)?;
    call(sessions, engine, Method::GET, &format!("/v1/containers/{name}"), None).await
}

async fn destroy(sessions: &Sessions, engine: usize, name: &str) -> Result<(), String> {
    let req = Request::post(format!("/v1/containers/{name}/destroy"))
        .header("host", "engine")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(b"{}")))
        .expect("a request");
    send(sessions, engine, req).await.map(|_| ())
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
    if let Err(e) = sessions.rt.block_on(sessions.engine_of(&req.name)) {
        let kind = if matches!(e, ApiError::NotFound(_)) { "not_found" } else { "internal" };
        return send_with_fd(client.as_raw_fd(), &reply(false, kind, &e.to_string()), None);
    }
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
        let one = || vec![EngineAt { name: "local".into(), up: up.clone(), egress_to: None }];
        let a = Sessions::open(&dir.join("state"), &pins, one()).unwrap();
        let c = Credential { guest_key: [1; 32], secret: [2; 32] };
        a.keep("c1", Some(c.clone())).unwrap();
        a.keep("c2", Some(c.clone())).unwrap();
        a.forget("c2").unwrap();
        let mode = std::fs::metadata(dir.join("state").join(STATE_FILE)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let b = Sessions::open(&dir.join("state"), &pins, one()).unwrap();
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
        let s = Arc::new(Sessions::open(&dir.join("state"), &pins, vec![EngineAt { name: "local".into(), up, egress_to: None }]).unwrap());
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
        rt.block_on(wait_pinned(&s, 0, "c1", "img", wait, look)).unwrap();
        writer.join().unwrap();
        assert!(t0.elapsed() >= Duration::from_millis(400) && t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
        assert!(s.held.lock().unwrap().is_empty());

        // Pinned already: at once.
        let t0 = std::time::Instant::now();
        rt.block_on(wait_pinned(&s, 0, "c1", "img", wait, look)).unwrap();
        assert!(t0.elapsed() < look, "{:?}", t0.elapsed());

        // Never pinned: refused when the wait ends, booting nothing.
        let t0 = std::time::Instant::now();
        let why = rt.block_on(wait_pinned(&s, 0, "c2", "never", Duration::from_millis(300), look)).unwrap_err();
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
        let why = rt.block_on(wait_pinned(&s, 0, "c3", "never", wait, look)).unwrap_err();
        destroyer.join().unwrap();
        assert!(why.contains("destroyed"), "{why}");

        // No PCR0 yet: measured, with a fresh nonce each time.
        rt.block_on(wait_pinned(&s, 0, "c4", "fresh/one", wait, look)).unwrap();
        rt.block_on(wait_pinned(&s, 0, "c4", "fresh/one", wait, look)).unwrap();
        let nonces = measures.lock().unwrap().clone();
        assert_eq!(nonces.len(), 2);
        assert!(nonces.iter().all(|n| n.len() == 64) && nonces[0] != nonces[1], "{nonces:?}");

        // The engine cannot say (no such image, no route): the claim decides.
        rt.block_on(wait_pinned(&s, 0, "c5", "unknown", wait, look)).unwrap();

        // Pins that stop reading keep the last good ones.
        std::fs::write(&pins, "not a pin\n").unwrap();
        assert!(s.pins().contains(&[0xbb; 48]));
        std::fs::write(&pins, format!("{}\n", pin(0xcc))).unwrap();
        assert_eq!(s.pins(), [[0xcc; 48]].into());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// What a stand-in engine saw: each request's method, path and query,
    /// its body's length and SHA-256, and a small body itself.
    type Seen = Arc<Mutex<Vec<(String, usize, String, String)>>>;

    /// A stand-in engine served by hyper on `rt`: `answer` of a request's
    /// method and path (with its query) and its body, as a status and JSON.
    fn fake_engine(rt: &tokio::runtime::Runtime, answer: impl Fn(&str, &str, &[u8]) -> (u16, String) + Send + Sync + 'static) -> (Up, Seen) {
        use sha2::Digest;
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let (answer, handle, log) = (Arc::new(answer), rt.handle().clone(), seen.clone());
        let up: Up = Arc::new(move || {
            let (mine, theirs) = UnixStream::pair()?;
            theirs.set_nonblocking(true)?;
            let (answer, log) = (answer.clone(), log.clone());
            handle.spawn(async move {
                let Ok(theirs) = tokio::net::UnixStream::from_std(theirs) else { return };
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let (answer, log) = (answer.clone(), log.clone());
                    async move {
                        let method = req.method().to_string();
                        let at = req.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
                        let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                        let small = if body.len() <= 4096 { String::from_utf8_lossy(&body).into_owned() } else { String::new() };
                        log.lock().unwrap().push((format!("{method} {at}"), body.len(), hex::encode(sha2::Sha256::digest(&body)), small));
                        let (status, text) = answer(&method, &at, &body);
                        let mut r = Response::new(Full::new(Bytes::from(text)));
                        *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
                        Ok::<_, Infallible>(r)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(theirs), svc).await;
            });
            Ok(mine)
        });
        (up, seen)
    }

    /// A stand-in engine's answers: its memory, its images, its computers.
    fn engine_answers(used: u64, images: &'static [&'static str], computers: &'static [&'static str]) -> impl Fn(&str, &str, &[u8]) -> (u16, String) + Send + Sync + 'static {
        move |method, at, _| {
            let path = at.split('?').next().unwrap_or("");
            let list = |names: &[&str], key: &str| serde_json::to_string(&names.iter().map(|n| serde_json::json!({ key: n })).collect::<Vec<_>>()).unwrap();
            match (method, path) {
                ("GET", "/v1/health") => (200, format!(r#"{{"vms":{},"vms_max":8,"memory_mib":{used},"memory_mib_max":17000,"ca_pem":"x"}}"#, computers.len())),
                ("GET", "/v1/images") => (200, list(images, "reference")),
                ("GET", "/v1/containers") => (200, list(computers, "name")),
                ("POST", "/v1/images/load") => (200, r#"{"reference":"loaded"}"#.into()),
                ("GET", p) if p.starts_with("/v1/images/") => match images.contains(&&p["/v1/images/".len()..]) {
                    true => (200, format!(r#"{{"reference":"{}"}}"#, &p["/v1/images/".len()..])),
                    false => (404, r#"{"error":"no such image","kind":"not_found"}"#.into()),
                },
                ("GET", p) if p.starts_with("/v1/containers/") && computers.contains(&&p["/v1/containers/".len()..]) => (200, format!(r#"{{"name":"{}","state":"running"}}"#, &p["/v1/containers/".len()..])),
                ("POST", p) if p.ends_with("/start") => (201, r#"{"state":"starting"}"#.into()),
                ("POST", p) if p.ends_with("/destroy") => (200, r#"{"destroyed":true}"#.into()),
                _ => (404, r#"{"error":"no such container","kind":"not_found"}"#.into()),
            }
        }
    }

    fn engines_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("home-engines-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pins"), format!("{}\n", pin(0xaa))).unwrap();
        dir
    }

    // Goal: a start goes to the first engine, in the home's order, that
    // holds its image and whose memory takes it; with none, to the one with
    // the most memory free; an engine without the image, or one that does
    // not answer, takes none. A computer is found on its engine after a
    // home restart; on none it is a 404, and with an engine not answering
    // it is unknown, never gone.
    #[test]
    fn a_start_goes_where_its_image_and_memory_are() {
        let fakes = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let dir = engines_test_dir("place");
        let (near, _) = fake_engine(&fakes, engine_answers(15_000, &["img", "near-only"], &["on-near"]));
        let (far, _) = fake_engine(&fakes, engine_answers(2_000, &["img"], &["on-far"]));
        let down: Up = Arc::new(|| Err(io::Error::other("no route to that parent")));
        let engines = vec![EngineAt { name: "local".into(), up: near, egress_to: None }, EngineAt { name: "down".into(), up: down, egress_to: None }, EngineAt { name: "far".into(), up: far, egress_to: None }];
        let s = Sessions::open(&dir.join("state"), &dir.join("pins"), engines).unwrap();
        let rt = s.rt.clone();
        assert_eq!(rt.block_on(s.place(Some("img"), 1_024)), 0, "the home's own parent takes it");
        assert_eq!(rt.block_on(s.place(Some("img"), 4_096)), 2, "its own is too full: the far one");
        assert_eq!(rt.block_on(s.place(Some("near-only"), 4_096)), 0, "only its own holds the image: there, to be refused as full");
        assert_eq!(rt.block_on(s.place(Some("img"), 16_000)), 2, "none takes it: the one with the most free");
        assert_eq!(rt.block_on(s.engine_of("on-far")).unwrap(), 2);
        assert_eq!(s.placed.lock().unwrap().get("on-far"), Some(&2), "found once, kept");
        assert!(matches!(rt.block_on(s.engine_of("on-near")), Ok(0)));
        assert!(matches!(rt.block_on(s.engine_of("nowhere")), Err(ApiError::Internal(m)) if m.contains("down")), "an engine not answering: unknown");
        let two = vec![EngineAt { name: "local".into(), up: fake_engine(&fakes, engine_answers(0, &[], &[])).0, egress_to: None }, EngineAt { name: "far".into(), up: fake_engine(&fakes, engine_answers(0, &[], &[])).0, egress_to: None }];
        let s2 = Sessions::open(&dir.join("state2"), &dir.join("pins"), two).unwrap();
        assert!(matches!(s2.rt.block_on(s2.engine_of("nowhere")), Err(ApiError::NotFound(_))), "on no engine that answers, all answering: gone");
        for bad in [vec![], (0..=ENGINES_MAX).map(|i| EngineAt { name: format!("e{i}"), up: s.engines[0].up.clone(), egress_to: None }).collect(), vec![EngineAt { name: "a".into(), up: s.engines[0].up.clone(), egress_to: None }, EngineAt { name: "a".into(), up: s.engines[0].up.clone(), egress_to: None }]] {
            assert!(Sessions::open(&dir.join("state3"), &dir.join("pins"), bad).is_err());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One HTTP request to a home's `engine.sock`, as celld makes it.
    fn ask(rt: &tokio::runtime::Runtime, sock: &Path, method: &str, at: &str, body: Vec<u8>) -> (u16, serde_json::Value) {
        rt.block_on(async {
            let s = tokio::net::UnixStream::connect(sock).await.unwrap();
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s)).await.unwrap();
            tokio::spawn(conn);
            let req = Request::builder().method(method).uri(at).header("host", "engine").header("content-type", "application/json").body(Full::new(Bytes::from(body))).unwrap();
            let r = sender.send_request(req).await.unwrap();
            let status = r.status().as_u16();
            let body = r.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
        })
    }

    // Goal: through a home of two engines, celld sees one engine: the
    // health summed with each engine's own, every computer in one list, the
    // images both hold, a load whose body reaches both whole, each
    // computer's calls on its own engine, and a start on the engine that
    // takes it (its failed claim destroys it there, and its placement
    // goes). An engine that stops answering leaves the rest served.
    #[test]
    fn a_home_of_two_engines_answers_as_one() {
        let fakes = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let client = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let dir = engines_test_dir("route");
        let (near, near_seen) = fake_engine(&fakes, engine_answers(15_000, &["img", "near-only"], &["on-near"]));
        let (far, far_seen) = fake_engine(&fakes, engine_answers(2_000, &["img"], &["on-far"]));
        let far_up = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let far_gate = far_up.clone();
        let far: Up = Arc::new(move || if far_gate.load(std::sync::atomic::Ordering::SeqCst) { far() } else { Err(io::Error::other("no route to that parent")) });
        let (near_egress, far_egress) = (Some("unix:/run/nitro-home/t1/egress.sock".to_string()), Some("tcp:10.0.1.5:5104".to_string()));
        let s = Arc::new(Sessions::open(&dir.join("state"), &dir.join("pins"), vec![EngineAt { name: "local".into(), up: near, egress_to: near_egress }, EngineAt { name: "far".into(), up: far, egress_to: far_egress }]).unwrap());
        let sock = dir.join("engine.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let served = s.clone();
        std::thread::spawn(move || serve_engine(listener, served));

        let (status, health) = ask(&client, &sock, "GET", "/v1/health", vec![]);
        assert_eq!((status, health["memory_mib"].as_u64(), health["memory_mib_max"].as_u64(), health["vms"].as_u64()), (200, Some(17_000), Some(34_000), Some(2)));
        assert_eq!(health["engines"][1]["name"], "far");
        let (_, list) = ask(&client, &sock, "GET", "/v1/containers", vec![]);
        assert_eq!(list.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect::<Vec<_>>(), ["on-near", "on-far"]);
        let (_, images) = ask(&client, &sock, "GET", "/v1/images", vec![]);
        assert_eq!(images, serde_json::json!([{ "reference": "img" }]), "only what both hold");

        let tar: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let (status, loaded) = ask(&client, &sock, "POST", "/v1/images/load?reference=new%2Fimage", tar.clone());
        assert_eq!((status, loaded["reference"].as_str()), (200, Some("loaded")));
        let sha = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(&tar))
        };
        for seen in [&near_seen, &far_seen] {
            let seen = seen.lock().unwrap();
            let load = seen.iter().find(|(r, _, _, _)| r.starts_with("POST /v1/images/load")).expect("a load");
            assert_eq!((load.0.as_str(), load.1, load.2.as_str()), ("POST /v1/images/load?reference=new%2Fimage", tar.len(), sha.as_str()));
        }

        let (status, c) = ask(&client, &sock, "GET", "/v1/containers/on-far", vec![]);
        assert_eq!((status, c["name"].as_str()), (200, Some("on-far")));
        assert_eq!(ask(&client, &sock, "GET", "/v1/containers/nowhere", vec![]).0, 404);

        // A start too big for the home's own parent goes far; with no guest
        // to attest, it is destroyed there and its placement goes.
        let start = serde_json::to_vec(&serde_json::json!({ "image": "img", "enableInternet": false, "instance": { "vcpu": 1, "memoryMib": 4096, "diskMb": 2000 } })).unwrap();
        let (status, _) = ask(&client, &sock, "POST", "/v1/containers/c1/start", start);
        assert_eq!(status, 500, "no guest attested");
        let far_calls: Vec<String> = far_seen.lock().unwrap().iter().map(|(r, _, _, _)| r.clone()).collect();
        let started: serde_json::Value = far_seen.lock().unwrap().iter().find(|(r, _, _, _)| r == "POST /v1/containers/c1/start").map(|(_, _, _, b)| serde_json::from_str(b).unwrap()).unwrap();
        assert_eq!((&started["egressTo"], &started["image"], &started["instance"]["memoryMib"]), (&serde_json::json!("tcp:10.0.1.5:5104"), &serde_json::json!("img"), &serde_json::json!(4096)), "its egress to this home, from the far engine; the rest as celld asked: {started}");
        assert!(far_calls.contains(&"POST /v1/containers/c1/start".to_string()) && far_calls.contains(&"POST /v1/containers/c1/destroy".to_string()), "{far_calls:?}");
        assert!(!near_seen.lock().unwrap().iter().any(|(r, _, _, _)| r.contains("/c1/")));
        assert!(!s.placed.lock().unwrap().contains_key("c1"));

        // The far one gone: the rest still answers, and its computers are
        // unknown, never gone.
        far_up.store(false, std::sync::atomic::Ordering::SeqCst);
        s.placed.lock().unwrap().clear();
        let (status, health) = ask(&client, &sock, "GET", "/v1/health", vec![]);
        assert_eq!((status, health["memory_mib_max"].as_u64()), (200, Some(17_000)));
        let (_, images) = ask(&client, &sock, "GET", "/v1/images", vec![]);
        assert_eq!(images.as_array().unwrap().len(), 2, "what the answering one holds");
        assert_eq!(ask(&client, &sock, "GET", "/v1/containers/on-far", vec![]).0, 500);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
