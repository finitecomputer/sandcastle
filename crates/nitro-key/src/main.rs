//! `nitro-key`: a sealed disk's key, fetched by the guest itself
//! (docs/nitro-spike.md, acceptance 8).
//!
//! `nitro-key new --out <file>` (a new disk) or `nitro-key wake --wrapped
//! <base64> --out <file>` (a wake): a fresh RSA key and an attestation
//! document carrying it; a KMS request the guest composes, signed by the
//! parent (which sees only its target and its body's hash); TLS from the
//! guest to KMS through the parent, Amazon's roots the only ones trusted,
//! so the parent carries bytes it cannot read or change; KMS's envelope
//! opened with the guest's key. The disk's key goes to `<file>` (64 hex
//! digits, as FPAC's `--key-file` takes it); the wrapped key, for the
//! parent to keep, to stdout.
//!
//! `nitro-key attest --nonce <hex>` prints a document for the operator;
//! `nitro-key settime` sets the guest's clock from its NSM's time.
//!
//! Which KMS key: the measured command line's `nitro.kms_key=`, never the
//! parent's word, so the parent cannot point the guest at a key it holds.

mod kms;

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(match linux::run(std::env::args().skip(1).collect()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("nitro-key: {e}");
            1
        }
    })
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("nitro-key runs in a Nitro Sandbox's guest");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use base64::Engine as _;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::RsaPrivateKey;
    use sandcastle_nitro_probe::{cms, guest::dial, nsm};
    use sha2::{Digest, Sha256};

    use crate::kms;

    const HOST: &str = "kms.us-east-2.amazonaws.com";
    const CID_HOST: u32 = 2;
    const SIGNER_PORT: u32 = 9100;
    const KEY_ARG: &str = "nitro.kms_key=";
    const IO_MS_MAX: u64 = 30_000;

    fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
        args.windows(2).find(|w| w[0] == name).map(|w| w[1].as_str())
    }

    fn key_id() -> Result<String, String> {
        let cmdline = std::fs::read_to_string("/proc/cmdline").map_err(|e| format!("/proc/cmdline: {e}"))?;
        let ids: Vec<&str> = cmdline.split_ascii_whitespace().filter_map(|w| w.strip_prefix(KEY_ARG)).collect();
        match ids.as_slice() {
            [id] if id.len() == 36 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') => Ok(id.to_string()),
            _ => Err(format!("the command line names no KMS key ({KEY_ARG}<key id>, once)")),
        }
    }

    /// Only Amazon's roots: what KMS's certificates chain to.
    fn amazon_roots() -> rustls::RootCertStore {
        let roots: Vec<_> = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .filter(|a| {
                let s = a.subject.as_ref();
                let has = |n: &[u8]| s.windows(n.len()).any(|w| w == n);
                has(b"Amazon Root CA ") || has(b"Starfield Services Root Certificate Authority - G2")
            })
            .cloned()
            .collect();
        assert_eq!(roots.len(), 5, "Amazon Root CA 1 to 4 and Starfield Services G2");
        rustls::RootCertStore { roots }
    }

    fn ask_signer(target: &str, body: &[u8]) -> Result<kms::Signature, String> {
        let mut s = dial(CID_HOST, SIGNER_PORT).map_err(|e| format!("the parent's signer: {e}"))?;
        s.set_read_timeout(Some(Duration::from_millis(IO_MS_MAX))).map_err(|e| e.to_string())?;
        let ask = serde_json::json!({"target": target, "body_sha256": hex::encode(Sha256::digest(body))}).to_string();
        s.write_all(format!("{ask}\n").as_bytes()).map_err(|e| e.to_string())?;
        let mut line = String::new();
        BufReader::new(s).take(16 * 1024).read_line(&mut line).map_err(|e| e.to_string())?;
        serde_json::from_str(line.trim()).map_err(|_| format!("the signer refused: {}", line.trim()))
    }

    /// One KMS call over TLS the guest ends: the status and the body.
    fn call(target: &str, body: &[u8]) -> Result<(u16, Vec<u8>, serde_json::Value), String> {
        let t0 = Instant::now();
        let sig = ask_signer(target, body)?;
        let signed_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().map_err(|e| e.to_string())?.with_root_certificates(amazon_roots()).with_no_client_auth();
        let name = rustls_pki_types::ServerName::try_from(HOST.to_string()).map_err(|e| e.to_string())?;
        let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
        let tcp = TcpStream::connect((HOST, 443)).map_err(|e| format!("connecting to KMS: {e}"))?;
        tcp.set_read_timeout(Some(Duration::from_millis(IO_MS_MAX))).map_err(|e| e.to_string())?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        tls.write_all(&kms::request(HOST, target, body, &sig)).map_err(|e| format!("TLS to KMS: {e}"))?;
        let (status, answer) = kms::read_answer(&mut tls)?;
        let timing = serde_json::json!({"signed_ms": signed_ms, "kms_ms": t0.elapsed().as_secs_f64() * 1000.0 - signed_ms});
        Ok((status, answer, timing))
    }

    fn write_key(path: &str, key: &[u8]) -> Result<(), String> {
        assert_eq!(key.len(), 32, "AES-256");
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|e| format!("{path}: {e}"))?;
        f.write_all(hex::encode(key).as_bytes()).map_err(|e| format!("{path}: {e}"))
    }

    pub fn run(args: Vec<String>) -> Result<(), String> {
        let mode = args.first().map(String::as_str).unwrap_or("");
        if mode == "settime" {
            // The guest's clock from its NSM: the hypervisor's signed time,
            // never the parent's word (a confidential guest boots at 1970).
            let mut nonce = [0u8; 32];
            std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut nonce)).map_err(|e| e.to_string())?;
            let doc = nsm::attest(Some(&nonce), None)?;
            let a = sandcastle_nitro_attest::read_unverified(&doc).map_err(|e| e.to_string())?;
            let ts = libc::timespec { tv_sec: (a.timestamp_ms / 1000) as libc::time_t, tv_nsec: ((a.timestamp_ms % 1000) * 1_000_000) as libc::c_long };
            // SAFETY: clock_settime with a valid timespec, as root.
            if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) } != 0 {
                return Err(format!("clock_settime: {}", std::io::Error::last_os_error()));
            }
            println!("{}", a.timestamp_ms);
            return Ok(());
        }
        if mode == "attest" {
            let nonce = hex::decode(flag(&args, "--nonce").ok_or("--nonce")?).map_err(|e| e.to_string())?;
            println!("{}", hex::encode(nsm::attest(Some(&nonce), None)?));
            return Ok(());
        }
        let out = flag(&args, "--out").ok_or("--out <file>")?;
        let key_id = key_id()?;
        let t0 = Instant::now();
        let private = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).map_err(|e| e.to_string())?;
        let public = private.to_public_key().to_public_key_der().map_err(|e| e.to_string())?.as_bytes().to_vec();
        let mut nonce = [0u8; 32];
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut nonce)).map_err(|e| e.to_string())?;
        let key_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let document = nsm::attest(Some(&nonce), Some(&public))?;
        let (target, body) = match mode {
            "new" => (kms::GENERATE_DATA_KEY, kms::generate_data_key(&key_id, &document)),
            "wake" => {
                let wrapped = base64::engine::general_purpose::STANDARD.decode(flag(&args, "--wrapped").ok_or("--wrapped <base64>")?).map_err(|e| e.to_string())?;
                (kms::DECRYPT, kms::decrypt(&key_id, &wrapped, &document))
            }
            _ => return Err("usage: nitro-key new|wake [--wrapped b64] --out file | attest --nonce hex".into()),
        };
        let (status, answer, timing) = call(target, &body)?;
        let released = kms::released(status, &answer, &key_id)?;
        let key = cms::open(&private, &released.for_recipient).map_err(|e| e.to_string())?;
        if key.len() != 32 {
            return Err(format!("KMS released {} bytes, not an AES-256 key", key.len()));
        }
        write_key(out, &key)?;
        let wrapped = released.wrapped.map(|w| base64::engine::general_purpose::STANDARD.encode(w));
        println!("{}", serde_json::json!({"mode": mode, "wrapped": wrapped, "key_sha256": hex::encode(Sha256::digest(&key)), "key_ms": key_ms, "timing": timing, "total_ms": t0.elapsed().as_secs_f64() * 1000.0}));
        Ok(())
    }
}
