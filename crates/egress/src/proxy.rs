//! The node's egress proxy for one VM. The runner's forwarder hands it
//! every connection and lookup the guest makes; it answers lookups from
//! the rules and the fake range, and for a connection decides: refuse,
//! splice to the real destination, or intercept (terminate TLS with the
//! node's CA, then hand each request to the handler or substitute its
//! placeholders and send it on). A WebSocket's upgrade goes the same way,
//! and on a 101 the two connections are joined (`ws`). It runs outside the
//! VM's jail: the CA's key and every secret stay where an escape from the
//! VMM cannot reach.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::HeaderValue;
use hyper::{Request, Response};
use sandcastle_wire::egress::{Header, Kind, DNS_BYTES_MAX, HEADER_BYTES};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UnixListener, UnixStream};

use crate::ca::Ca;
use crate::dns;
use crate::fakeip::{self, FakeIps};
use crate::rules::{Action, AddrDecision, Compiled, NameDecision};
use crate::sni::{self, Peek, PEEK_BYTES_MAX};
use crate::ws;

/// A connection's first bytes, to decide from.
const PEEK_WAIT: Duration = Duration::from_secs(10);
/// Decisions kept for the evidence.
const LOG_MAX: usize = 1024;
/// A 101's hand-over of both connections, at most.
const UPGRADE_WAIT: Duration = Duration::from_secs(10);

type Body = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Refused(String),
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Decision {
    pub to: String,
    pub host: Option<String>,
    pub decision: String,
}

pub struct Egress {
    /// Replaced whole when the rules change (an intercept added while the
    /// VM runs); a connection decides on the rules it read.
    rules: std::sync::RwLock<Arc<Compiled>>,
    fake: Mutex<FakeIps>,
    ca: Arc<Ca>,
    /// The handler: an HTTP server on a unix socket (celld's callback, or
    /// a stand-in).
    handler: PathBuf,
    /// The container this proxy serves, named to the handler in
    /// `x-sandcastle-container`, so one handler serves a node's VMs.
    container: String,
    upstream: tokio_rustls::TlsConnector,
    log: Mutex<Vec<Decision>>,
    ws: ws::Limits,
    /// WebSockets joined now; each holds one of the forwarder's
    /// `FORWARDS_MAX` connections, which bounds them.
    websockets: Arc<AtomicUsize>,
}

/// One WebSocket counted while its join runs.
struct Joined(Arc<AtomicUsize>);

impl Drop for Joined {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A stream whose first bytes were already read to decide.
struct Prefixed<S> {
    prefix: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.at < self.prefix.len() {
            let n = buf.remaining().min(self.prefix.len() - self.at);
            let at = self.at;
            buf.put_slice(&self.prefix[at..at + n]);
            self.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Whether two host names are one, as DNS compares them.
fn same_host(a: &str, b: &str) -> bool {
    a.trim_end_matches('.').eq_ignore_ascii_case(b.trim_end_matches('.'))
}

fn text(status: u16, msg: &str) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from(msg.to_string())).map_err(|never| match never {}).boxed());
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("a valid status");
    r
}

impl Egress {
    pub fn new(rules: Compiled, ca: Arc<Ca>, handler: PathBuf, container: String) -> Egress {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Egress {
            rules: std::sync::RwLock::new(Arc::new(rules)),
            fake: Mutex::new(FakeIps::default()),
            ca,
            handler,
            container,
            upstream: tokio_rustls::TlsConnector::from(Arc::new(config)),
            log: Mutex::new(Vec::new()),
            ws: ws::Limits::default(),
            websockets: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Other limits for WebSockets than `ws`'s own (the tests' are short).
    pub fn with_ws_limits(mut self, limits: ws::Limits) -> Egress {
        self.ws = limits;
        self
    }

    /// WebSockets joined now.
    pub fn websockets(&self) -> usize {
        self.websockets.load(Ordering::SeqCst)
    }

    fn rules(&self) -> Arc<Compiled> {
        self.rules.read().expect("never poisoned").clone()
    }

    /// The new rules, for connections and lookups from now on.
    pub fn set_rules(&self, rules: Compiled) {
        *self.rules.write().expect("never poisoned") = Arc::new(rules);
    }

    pub fn decisions(&self) -> Vec<Decision> {
        self.log.lock().expect("never poisoned").clone()
    }

    fn note(&self, to: String, host: Option<&str>, decision: String) {
        let mut log = self.log.lock().expect("never poisoned");
        if log.len() < LOG_MAX {
            log.push(Decision { to, host: host.map(str::to_string), decision });
        }
    }

    /// Serves the forwarder's connections for the VM's life.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        // Unbounded by design: one VM's egress for its life; each
        // connection is bounded by the forwarder's FORWARDS_MAX.
        loop {
            let Ok((s, _)) = listener.accept().await else { continue };
            let me = self.clone();
            tokio::spawn(async move {
                let _ = me.connection(s).await;
            });
        }
    }

    async fn connection(self: Arc<Self>, mut s: UnixStream) -> Result<(), ProxyError> {
        let mut h = [0u8; HEADER_BYTES];
        s.read_exact(&mut h).await?;
        let header = Header::decode(&h).map_err(|e| ProxyError::Refused(e.to_string()))?;
        match header.kind {
            Kind::Dns => {
                let len = s.read_u16().await? as usize;
                if len > DNS_BYTES_MAX {
                    return Err(ProxyError::Refused("a DNS query too large".into()));
                }
                let mut q = vec![0u8; len];
                s.read_exact(&mut q).await?;
                let Some(answer) = self.answer(&q) else { return Ok(()) };
                s.write_u16(answer.len() as u16).await?;
                s.write_all(&answer).await?;
                Ok(())
            }
            Kind::Tcp => self.tcp(s, header.ip, header.port).await,
        }
    }

    /// The answer to a guest's lookup: a fake address for a name the rules
    /// let it reach, NXDOMAIN otherwise.
    pub fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        let q = dns::parse_query(query).ok()?;
        let decision = self.rules().name(&q.name);
        let answer = match decision {
            NameDecision::Refuse => dns::answer_nxdomain(&q),
            NameDecision::Intercept(_) | NameDecision::Resolve if q.qtype == dns::TYPE_A => {
                match self.fake.lock().expect("never poisoned").assign(&q.name) {
                    Some(ip) => dns::answer_a(&q, ip),
                    None => dns::answer_nxdomain(&q),
                }
            }
            NameDecision::Intercept(_) | NameDecision::Resolve => dns::answer_empty(&q),
        };
        self.note(format!("dns {} type {}", q.name, q.qtype), Some(&q.name), format!("{decision:?}"));
        Some(answer)
    }

    async fn tcp(self: Arc<Self>, s: UnixStream, ip: IpAddr, port: u16) -> Result<(), ProxyError> {
        let host = match ip {
            IpAddr::V4(a) if fakeip::in_range(a) => match self.fake.lock().expect("never poisoned").name(a) {
                Some(n) => Some(n.to_string()),
                None => {
                    self.note(format!("{ip}:{port}"), None, "Refuse(an unassigned fake address)".into());
                    return Ok(());
                }
            },
            _ => None,
        };
        let decision = self.rules().addr(ip, port, host.as_deref());
        self.note(format!("{ip}:{port}"), host.as_deref(), format!("{decision:?}"));
        match decision {
            AddrDecision::Refuse(_) => Ok(()),
            AddrDecision::Splice => self.splice(s, ip, port, host).await,
            // An address intercept (`ip:port`, a range, HTTP's `*`) matched
            // no name: the address the guest dialed is the host.
            AddrDecision::Intercept(i) => self.intercept(s, i, host, ip, port).await,
        }
    }

    /// A real address for `host`, public and not the node's; or the node's
    /// front door, where it serves `host` on `port`.
    async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, ProxyError> {
        let rules = self.rules();
        if let Some(door) = rules.front_door(host, port) {
            return door.map_err(|why| ProxyError::Refused(format!("{host}'s front door: {why}")));
        }
        let addrs = tokio::net::lookup_host((host, port)).await?;
        addrs
            .into_iter()
            .find(|a| rules.reachable(a.ip(), port))
            .ok_or_else(|| ProxyError::Refused(format!("{host} has no public address")))
    }

    async fn splice(&self, mut s: UnixStream, ip: IpAddr, port: u16, host: Option<String>) -> Result<(), ProxyError> {
        let target = match &host {
            Some(h) => self.resolve(h, port).await?,
            None => SocketAddr::new(ip, port),
        };
        let mut up = TcpStream::connect(target).await?;
        let _ = up.set_nodelay(true);
        tokio::io::copy_bidirectional(&mut s, &mut up).await?;
        Ok(())
    }

    /// An intercepted connection, to the destination the rules checked:
    /// the name the guest looked up (`host`), or the address it dialed.
    /// A TLS SNI names the certificate the guest gets, never where its
    /// requests go: by name, an SNI for another name is refused; by
    /// address, the requests go to that address.
    async fn intercept(self: Arc<Self>, mut s: UnixStream, i: usize, host: Option<String>, ip: IpAddr, port: u16) -> Result<(), ProxyError> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        // Bounded by PEEK_BYTES_MAX and PEEK_WAIT.
        let peeked = loop {
            match sni::peek(&buf) {
                Peek::More if buf.len() < PEEK_BYTES_MAX => {}
                p => break p,
            }
            let n = tokio::time::timeout(PEEK_WAIT, s.read(&mut chunk)).await.map_err(|_| ProxyError::Refused("no first bytes".into()))??;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let stream = Prefixed { prefix: buf, at: 0, inner: s };
        match peeked {
            Peek::Tls(sni) => {
                let (name, dialed) = match (host, sni) {
                    (Some(h), Some(sni)) if !same_host(&h, &sni) => {
                        self.note(format!("{ip}:{port}"), Some(&h), "Refuse(an SNI for another name than the one looked up)".into());
                        return Ok(());
                    }
                    (Some(h), _) => (h, None),
                    (None, sni) => (sni.unwrap_or_else(|| ip.to_string()), Some(ip)),
                };
                let config = self.ca.server_config(&name).map_err(|e| ProxyError::Refused(e.to_string()))?;
                let tls = tokio_rustls::TlsAcceptor::from(config).accept(stream).await?;
                self.serve_http(tls, i, name, dialed, true, port).await
            }
            Peek::Http(_) => match host {
                Some(h) => self.serve_http(stream, i, h, None, false, port).await,
                None => self.serve_http(stream, i, ip.to_string(), Some(ip), false, port).await,
            },
            Peek::More | Peek::Other => Ok(()),
        }
    }

    async fn serve_http<S>(self: Arc<Self>, io: S, i: usize, host: String, dialed: Option<IpAddr>, tls: bool, port: u16) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let me = self.clone();
        let service = hyper::service::service_fn(move |req: Request<Incoming>| {
            let me = me.clone();
            let host = host.clone();
            async move { Ok::<_, Infallible>(me.request(req, i, &host, dialed, tls, port).await) }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(io), service)
            .with_upgrades()
            .await
            .map_err(|e| ProxyError::Refused(e.to_string()))
    }

    async fn request(self: Arc<Self>, mut req: Request<Incoming>, i: usize, host: &str, dialed: Option<IpAddr>, tls: bool, port: u16) -> Response<Body> {
        // A WebSocket's upgrade is taken before the request goes on.
        let guest = ws::asks(req.headers()).then(|| hyper::upgrade::on(&mut req));
        let what = format!("{}://{host}:{port}{}", if tls { "wss" } else { "ws" }, req.uri().path());
        let resp = self.answer_for(req, i, host, dialed, tls, port).await;
        self.upgrade(resp, guest, what, host)
    }

    /// On a 101 for a WebSocket's upgrade, joins the guest's connection to
    /// the other side's (`ws::join`); a 101 for anything else is refused.
    fn upgrade(self: Arc<Self>, mut resp: Response<Body>, guest: Option<hyper::upgrade::OnUpgrade>, what: String, host: &str) -> Response<Body> {
        if resp.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
            return resp;
        }
        let Some(guest) = guest else {
            self.note(what, Some(host), "Refuse(a 101 for what is not a WebSocket's upgrade)".into());
            return text(502, "only a WebSocket's upgrade passes an intercept");
        };
        let other = hyper::upgrade::on(&mut resp);
        let host = host.to_string();
        self.websockets.fetch_add(1, Ordering::SeqCst);
        let joined = Joined(self.websockets.clone());
        tokio::spawn(async move {
            let _joined = joined;
            let end = match tokio::time::timeout(UPGRADE_WAIT, async { tokio::join!(guest, other) }).await {
                Ok((Ok(g), Ok(o))) => ws::join(hyper_util::rt::TokioIo::new(g), hyper_util::rt::TokioIo::new(o), self.ws).await.to_string(),
                Ok((Err(e), _) | (_, Err(e))) => format!("WebSocket not joined: {e}"),
                Err(_) => format!("WebSocket not joined in {} s", UPGRADE_WAIT.as_secs()),
            };
            self.note(what, Some(&host), end);
        });
        resp
    }

    async fn answer_for(&self, mut req: Request<Incoming>, i: usize, host: &str, dialed: Option<IpAddr>, tls: bool, port: u16) -> Response<Body> {
        match self.rules().action(i).clone() {
            Action::Handler => {
                // Each replaces whatever the guest sent under its name.
                let h = req.headers_mut();
                h.insert("x-sandcastle-host", HeaderValue::from_str(host).unwrap_or(HeaderValue::from_static("invalid")));
                h.insert("x-sandcastle-scheme", HeaderValue::from_static(if tls { "https" } else { "http" }));
                h.insert("x-sandcastle-container", HeaderValue::from_str(&self.container).unwrap_or(HeaderValue::from_static("invalid")));
                // Which intercept matched: its index in the start's list
                // (intercepts are only ever appended while a VM runs).
                h.insert("x-sandcastle-intercept", HeaderValue::from(i));
                match self.to_handler(req).await {
                    Ok(r) => r,
                    Err(e) => text(502, &format!("the handler: {e}")),
                }
            }
            Action::Substitute { placeholders } => {
                for value in req.headers_mut().values_mut() {
                    let Ok(s) = value.to_str() else { continue };
                    if placeholders.iter().any(|p| s.contains(&p.placeholder)) {
                        let mut out = s.to_string();
                        for p in &placeholders {
                            out = out.replace(&p.placeholder, &p.value);
                        }
                        if let Ok(v) = HeaderValue::from_str(&out) {
                            *value = v;
                        }
                    }
                }
                match self.to_upstream(req, host, dialed, tls, port).await {
                    Ok(r) => r,
                    Err(e) => text(502, &format!("{host}: {e}")),
                }
            }
        }
    }

    /// The request to the handler; an upgrade's connection is kept for
    /// whoever takes it from the answer.
    async fn to_handler(&self, req: Request<Incoming>) -> Result<Response<Body>, String> {
        let s = UnixStream::connect(&self.handler).await.map_err(|e| e.to_string())?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.map_err(|e| e.to_string())?;
        tokio::spawn(conn.with_upgrades());
        let resp = send.send_request(req).await.map_err(|e| e.to_string())?;
        Ok(resp.map(|b| b.boxed()))
    }

    /// The request to the real host, on the port the guest dialed: the
    /// name's (`resolve`), or the address it dialed, as the rules allow it.
    /// `host` is the name TLS checks there.
    async fn to_upstream(&self, req: Request<Incoming>, host: &str, dialed: Option<IpAddr>, tls: bool, port: u16) -> Result<Response<Body>, String> {
        let addr = match dialed {
            Some(ip) if self.rules().reachable(ip, port) => SocketAddr::new(ip, port),
            Some(ip) => return Err(format!("{ip} is not a public address")),
            None => self.resolve(host, port).await.map_err(|e| e.to_string())?,
        };
        let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        // A streamed body is many writes, and an upgrade's frames more.
        let _ = tcp.set_nodelay(true);
        let resp = if tls {
            let name = rustls_pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
            let s = self.upstream.connect(name, tcp).await.map_err(|e| e.to_string())?;
            let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.map_err(|e| e.to_string())?;
            tokio::spawn(conn.with_upgrades());
            send.send_request(req).await.map_err(|e| e.to_string())?
        } else {
            let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await.map_err(|e| e.to_string())?;
            tokio::spawn(conn.with_upgrades());
            send.send_request(req).await.map_err(|e| e.to_string())?
        };
        Ok(resp.map(|b| b.boxed()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Intercept, Placeholder, Policy};

    fn egress(internet: bool) -> Egress {
        let rules = Policy {
            internet,
            intercept: vec![Intercept::https("model.example.com", Action::Handler)],
            ..Policy::default()
        }
        .compile(&[])
        .unwrap();
        Egress::new(rules, Arc::new(Ca::generate("t").unwrap()), "/nonexistent".into(), "c".into())
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut b = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            b.push(l.len() as u8);
            b.extend_from_slice(l.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b
    }

    // Goal: with the internet off, only intercepted names resolve; with
    // it on, every name does, to a fake address; AAAA is always empty.
    #[test]
    fn lookups_follow_the_rules() {
        let off = egress(false);
        let a = off.answer(&query("model.example.com", dns::TYPE_A)).unwrap();
        assert_eq!(a[3] & 0xf, 0);
        assert_eq!(&a[a.len() - 4..a.len() - 2], &[198, 18]);
        let nx = off.answer(&query("example.org", dns::TYPE_A)).unwrap();
        assert_eq!(nx[3] & 0xf, 3);
        let on = egress(true);
        let a = on.answer(&query("example.org", dns::TYPE_A)).unwrap();
        assert_eq!(&a[a.len() - 4..a.len() - 2], &[198, 18]);
        let aaaa = on.answer(&query("example.org", dns::TYPE_AAAA)).unwrap();
        assert_eq!((aaaa[3] & 0xf, aaaa[7]), (0, 0));
        assert!(on.answer(b"junk").is_none());
    }

    // Goal: the proxy intercepts TLS for an intercepted name and hands the
    // request to the handler, which answers. Method: a handler on a unix
    // socket, the proxy on another, a client that trusts only the CA.
    #[tokio::test]
    async fn intercepts_tls_to_the_handler() {
        let dir = std::env::temp_dir().join(format!("sc-egress-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let handler_sock = dir.join("handler.sock");
        let handler = UnixListener::bind(&handler_sock).unwrap();
        tokio::spawn(async move {
            let (s, _) = handler.accept().await.unwrap();
            let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                let header = |n: &str| req.headers().get_all(n).iter().filter_map(|v| v.to_str().ok()).collect::<Vec<_>>().join(",");
                let (host, container, index) = (header("x-sandcastle-host"), header("x-sandcastle-container"), header("x-sandcastle-intercept"));
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!("stand-in for {host}{} from {container} by {index}", req.uri().path())))))
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
        });
        let rules = Policy {
            internet: false,
            intercept: vec![Intercept::https("model.example.com", Action::Handler)],
            ..Policy::default()
        }
        .compile(&[])
        .unwrap();
        let ca = Arc::new(Ca::generate("t").unwrap());
        let eg = Arc::new(Egress::new(rules, ca.clone(), handler_sock, "c-1".into()));
        // The guest's lookup assigns the fake address it then dials.
        eg.answer(&query("model.example.com", dns::TYPE_A)).unwrap();
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 1));
        let egress_sock = dir.join("egress.sock");
        let listener = UnixListener::bind(&egress_sock).unwrap();
        tokio::spawn(eg.clone().serve(listener));

        let mut s = UnixStream::connect(&egress_sock).await.unwrap();
        s.write_all(&Header { kind: Kind::Tcp, ip, port: 443 }.encode()).await.unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(rustls_pki_types::ServerName::try_from("model.example.com").unwrap(), s)
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.unwrap();
        tokio::spawn(conn);
        // A guest that names another container is overruled.
        let req = Request::get("/v1/chat")
            .header("host", "model.example.com")
            .header("x-sandcastle-container", "forged")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let resp = send.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"stand-in for model.example.com/v1/chat from c-1 by 0");
        let d = eg.decisions();
        assert!(d.iter().any(|d| d.decision == "Intercept(0)"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Serves `s`: each request answered with its `x-sandcastle-host`
    /// and `authorization`.
    fn mirror<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(s: S) {
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!("{} {}", h("x-sandcastle-host"), h("authorization"))))))
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
        });
    }

    async fn get(egress: &std::path::Path, ip: IpAddr, port: u16, auth: &str) -> String {
        let mut s = UnixStream::connect(egress).await.unwrap();
        s.write_all(&Header { kind: Kind::Tcp, ip, port }.encode()).await.unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.unwrap();
        tokio::spawn(conn);
        let req = Request::get("/").header("host", "anything.example").header("authorization", auth).body(http_body_util::Empty::<Bytes>::new()).unwrap();
        let resp = send.send_request(req).await.unwrap();
        String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    // Goal: a guest that looks a name up and dials it on the port a host
    // intercept names (a local stack's platform,
    // `http://<app>.fragment.localhost:8790/`) reaches the handler by that
    // name, its `Host` as it sent it; on another port, with the internet
    // off, it reaches nothing. Before, an HTTP host took no port, so no
    // rule could name it, and the connection went to the name's real host.
    #[tokio::test]
    async fn a_name_intercepted_on_its_port_reaches_the_handler() {
        let dir = std::env::temp_dir().join(format!("sc-egress-port-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let handler_sock = dir.join("handler.sock");
        let handler = UnixListener::bind(&handler_sock).unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = handler.accept().await {
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                        let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
                        let said = format!("{} {} {} {}", h("x-sandcastle-scheme"), h("x-sandcastle-host"), h("x-sandcastle-intercept"), h("host"));
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(said))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
                });
            }
        });
        let rules = Policy {
            internet: false,
            intercept: vec![Intercept::http("*.fragment.localhost", Action::Handler), Intercept::http("*.fragment.localhost:8790", Action::Handler)],
            ..Policy::default()
        }
        .compile(&[])
        .unwrap();
        let eg = Arc::new(Egress::new(rules, Arc::new(Ca::generate("t").unwrap()), handler_sock, "c-1".into()));
        let egress_sock = dir.join("egress.sock");
        tokio::spawn(eg.clone().serve(UnixListener::bind(&egress_sock).unwrap()));
        // the guest's resolver asks first, and dials the address it got
        let a = eg.answer(&query("shelf--e2e.fragment.localhost", dns::TYPE_A)).unwrap();
        let fake = IpAddr::V4(std::net::Ipv4Addr::new(a[a.len() - 4], a[a.len() - 3], a[a.len() - 2], a[a.len() - 1]));
        assert!(matches!(fake, IpAddr::V4(v4) if fakeip::in_range(v4)), "{fake}");
        let dial = |port: u16| {
            let egress_sock = egress_sock.clone();
            async move {
                let mut s = UnixStream::connect(&egress_sock).await.unwrap();
                s.write_all(&Header { kind: Kind::Tcp, ip: fake, port }.encode()).await.unwrap();
                let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.ok()?;
                tokio::spawn(conn);
                let req = Request::get("/?view=t").header("host", format!("shelf--e2e.fragment.localhost:{port}")).body(http_body_util::Empty::<Bytes>::new()).unwrap();
                let resp = send.send_request(req).await.ok()?;
                Some(String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap())
            }
        };
        assert_eq!(dial(8790).await.as_deref(), Some("http shelf--e2e.fragment.localhost 1 shelf--e2e.fragment.localhost:8790"));
        assert_eq!(dial(80).await.as_deref(), Some("http shelf--e2e.fragment.localhost 0 shelf--e2e.fragment.localhost:80"));
        assert_eq!(dial(8791).await, None, "another port, the internet off: refused, the connection closed");
        let d = eg.decisions();
        assert!(d.iter().any(|d| d.to == format!("{fake}:8791") && d.decision == "Refuse(\"the internet is off\")"), "{d:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A TLS client that trusts only `ca`, over `s`, asking `GET /` of
    /// `host`; its answer, or nothing when the connection is refused.
    async fn get_tls(s: UnixStream, ca: &Ca, host: &str) -> Option<String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
        let name = rustls_pki_types::ServerName::try_from(host.to_string()).unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, s).await.ok()?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.ok()?;
        tokio::spawn(conn);
        let req = Request::get("/").header("host", host).body(http_body_util::Empty::<Bytes>::new()).unwrap();
        let resp = send.send_request(req).await.ok()?;
        Some(String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap())
    }

    // Goal: a guest reaches the node's own apps by their names, as it
    // would a public host on Cloudflare: the connection goes as bytes to
    // the node's front door on loopback (the node's own address too), its
    // TLS end to end with the front door's certificate, which a client
    // trusting only the front door's CA (not the node's egress CA)
    // accepts. A name the operator did not give is refused at loopback,
    // and so is the front door dialed by its address. Before, every
    // connection to the node's apps was refused: their names resolve to
    // the node's own or a private (tailnet) address.
    #[tokio::test]
    async fn the_node_front_door_serves_its_names_with_its_own_tls() {
        let dir = std::env::temp_dir().join(format!("sc-egress-door-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let app = "todo--k2.box.example.org";
        let box_ca = Ca::generate("the box's own").unwrap();
        let front = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(box_ca.server_config(app).unwrap());
        tokio::spawn(async move {
            while let Ok((s, _)) = front.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(s).await else { return };
                    let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                        let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!("the front door for {host}")))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls), svc).await;
                });
            }
        });
        let door = crate::rules::FrontDoor { hosts: vec!["box.example.org".into(), "*.box.example.org".into()], ports: [(443, front_addr)].into() };
        let rules = Policy { internet: true, ..Policy::default() }.compile(&[front_addr.ip()]).unwrap().with_front_door(Arc::new(door.compile().unwrap()));
        let eg = Arc::new(Egress::new(rules, Arc::new(Ca::generate("the node's egress").unwrap()), "/nonexistent".into(), "c-1".into()));
        let egress_sock = dir.join("egress.sock");
        tokio::spawn(eg.clone().serve(UnixListener::bind(&egress_sock).unwrap()));
        let lookup = |name: &str| {
            let a = eg.answer(&query(name, dns::TYPE_A)).unwrap();
            IpAddr::V4(std::net::Ipv4Addr::new(a[a.len() - 4], a[a.len() - 3], a[a.len() - 2], a[a.len() - 1]))
        };
        let dial = |ip: IpAddr, port: u16| {
            let egress_sock = egress_sock.clone();
            async move {
                let mut s = UnixStream::connect(&egress_sock).await.unwrap();
                s.write_all(&Header { kind: Kind::Tcp, ip, port }.encode()).await.unwrap();
                s
            }
        };
        let fake = lookup(app);
        assert_eq!(get_tls(dial(fake, 443).await, &box_ca, app).await.as_deref(), Some("the front door for todo--k2.box.example.org"));
        // a name the operator did not give, at loopback, on the door's own
        // port: refused (spliced, the door would answer it)
        let localhost = lookup("localhost");
        assert_eq!(get_tls(dial(localhost, front_addr.port()).await, &box_ca, app).await, None);
        // the front door by its address: the node's own, refused
        assert_eq!(get_tls(dial(front_addr.ip(), front_addr.port()).await, &box_ca, app).await, None);
        let d = eg.decisions();
        assert!(d.iter().any(|d| d.to == format!("{}:{}", front_addr.ip(), front_addr.port()) && d.decision == "Refuse(\"the node's own address\")"), "{d:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stand-in that counts the connections it takes and closes each.
    async fn counting() -> (SocketAddr, Arc<AtomicUsize>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (addr, n) = (l.local_addr().unwrap(), Arc::new(AtomicUsize::new(0)));
        let counted = n.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                drop(s);
            }
        });
        (addr, n)
    }

    // Goal: a guest's TLS SNI never moves an intercepted request to
    // another destination than the rules checked. By name, an SNI for
    // another name (the node's front door) is refused, so the internet
    // off and the door's own rules hold; by address, the request goes to
    // the address dialed, its SNI only the name TLS checks there. Before,
    // the SNI was where a substitute's request went: the guest chose the
    // host its placeholders' values went to, the front door included.
    #[tokio::test]
    async fn an_sni_never_moves_an_intercept_elsewhere() {
        let dir = std::env::temp_dir().join(format!("sc-egress-sni-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (door_addr, door) = counting().await;
        let (up_addr, up) = counting().await;
        let placeholder = Placeholder { placeholder: "SC_PLACEHOLDER_TEST_0002".into(), value: "sk-test-not-a-secret".into() };
        let substitute = Action::Substitute { placeholders: vec![placeholder] };
        let rules = Policy {
            internet: false,
            allow: vec!["127.0.0.0/8".into()],
            intercept: vec![Intercept::https("model.example.com", substitute.clone()), Intercept::http(&up_addr.to_string(), substitute)],
            ..Policy::default()
        }
        .compile(&[])
        .unwrap()
        .with_front_door(Arc::new(crate::rules::FrontDoor { hosts: vec!["box.example.org".into()], ports: [(443, door_addr)].into() }.compile().unwrap()));
        let ca = Arc::new(Ca::generate("the node's egress").unwrap());
        let eg = Arc::new(Egress::new(rules, ca.clone(), "/nonexistent".into(), "c-1".into()));
        let egress_sock = dir.join("egress.sock");
        tokio::spawn(eg.clone().serve(UnixListener::bind(&egress_sock).unwrap()));
        let dial = |ip: IpAddr, port: u16| {
            let egress_sock = egress_sock.clone();
            async move {
                let mut s = UnixStream::connect(&egress_sock).await.unwrap();
                s.write_all(&Header { kind: Kind::Tcp, ip, port }.encode()).await.unwrap();
                s
            }
        };
        // by name: the model's address, the door's name in the SNI
        let a = eg.answer(&query("model.example.com", dns::TYPE_A)).unwrap();
        let fake = IpAddr::V4(std::net::Ipv4Addr::new(a[a.len() - 4], a[a.len() - 3], a[a.len() - 2], a[a.len() - 1]));
        assert_eq!(get_tls(dial(fake, 443).await, &ca, "box.example.org").await, None);
        let d = eg.decisions();
        assert!(d.iter().any(|d| d.host.as_deref() == Some("model.example.com") && d.decision.contains("an SNI for another name")), "{d:?}");
        // by address: the door's name in the SNI, the request to the address
        let said = get_tls(dial(up_addr.ip(), up_addr.port()).await, &ca, "box.example.org").await;
        assert!(said.as_deref().is_some_and(|s| s.starts_with("box.example.org: ")), "{said:?}");
        assert_eq!((door.load(Ordering::SeqCst), up.load(Ordering::SeqCst)), (0, 1), "the door never dialed; the address once");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Goal: an address intercept (a range, an `ip:port`) matched by no
    // name hands its request on with the address as its host, and a
    // substitute goes on to the port the guest dialed, not 80. Before,
    // the first was a panic (the whole engine, with panic = "abort") and
    // the second went to port 80.
    #[tokio::test]
    async fn address_intercepts_name_the_address_and_keep_the_port() {
        let dir = std::env::temp_dir().join(format!("sc-egress-addr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let handler_sock = dir.join("handler.sock");
        let handler = UnixListener::bind(&handler_sock).unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = handler.accept().await {
                mirror(s);
            }
        });
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = upstream.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = upstream.accept().await {
                mirror(s);
            }
        });
        let placeholder = Placeholder { placeholder: "SC_PLACEHOLDER_TEST_0001".into(), value: "sk-test-not-a-secret".into() };
        let rules = Policy {
            internet: false,
            // a range allows the loopback the stand-in upstream is on
            allow: vec!["127.0.0.0/8".into()],
            intercept: vec![
                Intercept::http("10.9.0.0/16", Action::Handler),
                Intercept::http(&format!("127.0.0.1:{up_port}"), Action::Substitute { placeholders: vec![placeholder] }),
            ],
            ..Policy::default()
        }
        .compile(&[])
        .unwrap();
        let eg = Arc::new(Egress::new(rules, Arc::new(Ca::generate("t").unwrap()), handler_sock, "c-1".into()));
        let egress_sock = dir.join("egress.sock");
        tokio::spawn(eg.clone().serve(UnixListener::bind(&egress_sock).unwrap()));

        let handled = get(&egress_sock, "10.9.1.1".parse().unwrap(), 80, "Bearer x").await;
        assert_eq!(handled, "10.9.1.1 Bearer x");
        let substituted = get(&egress_sock, "127.0.0.1".parse().unwrap(), up_port, "Bearer SC_PLACEHOLDER_TEST_0001").await;
        assert_eq!(substituted, "- Bearer sk-test-not-a-secret");
        let d = eg.decisions();
        assert_eq!(d.iter().filter(|d| d.decision.starts_with("Intercept(")).count(), 2, "{d:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
