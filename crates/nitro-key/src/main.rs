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

mod disk;
mod kms;
mod s3;

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

    use crate::{disk, kms, s3};

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

    /// A key KMS released: the key, its wrapped form when new, the timing.
    type Release = ([u8; 32], Option<Vec<u8>>, serde_json::Value);

    /// A disk's key from KMS, released to this guest's document alone: a
    /// new one (`wrapped` none) or the one `wrapped` is. The key, its
    /// wrapped form when new, and the call's timing.
    fn release(wrapped: Option<&[u8]>) -> Result<Release, String> {
        let key_id = key_id()?;
        let private = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).map_err(|e| e.to_string())?;
        let public = private.to_public_key().to_public_key_der().map_err(|e| e.to_string())?.as_bytes().to_vec();
        let mut nonce = [0u8; 32];
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut nonce)).map_err(|e| e.to_string())?;
        let document = nsm::attest(Some(&nonce), Some(&public))?;
        let (target, body) = match wrapped {
            None => (kms::GENERATE_DATA_KEY, kms::generate_data_key(&key_id, &document)),
            Some(wrapped) => (kms::DECRYPT, kms::decrypt(&key_id, wrapped, &document)),
        };
        let (status, answer, timing) = call(target, &body)?;
        let released = kms::released(status, &answer, &key_id)?;
        let key = cms::open(&private, &released.for_recipient).map_err(|e| e.to_string())?;
        let key: [u8; 32] = key.try_into().map_err(|k: Vec<u8>| format!("KMS released {} bytes, not an AES-256 key", k.len()))?;
        Ok((key, released.wrapped, timing))
    }

    /// The counter's place and the credentials to it, from the home's sealed
    /// bucket configuration (celld's `CELLD_BUCKET_SEAL` file: its `counter`).
    struct CounterPlace {
        host: String,
        region: String,
        object: String,
        credentials: s3::Credentials,
    }

    fn counter_place(config: &str, object: &str) -> Result<CounterPlace, String> {
        let text = std::fs::read(config).map_err(|e| format!("{config}: {e}"))?;
        let v: serde_json::Value = serde_json::from_slice(&text).map_err(|_| format!("{config} is not JSON"))?;
        let c = &v["counter"];
        let field = |name: &str| c[name].as_str().map(str::to_string).ok_or(format!("{config}: the counter has no {name}"));
        let bucket = field("bucket")?;
        let bucket = bucket.strip_prefix("s3://").filter(|b| !b.contains('/') && !b.contains('.') && !b.is_empty()).ok_or(format!("{config}: the counter's bucket is s3://NAME (no prefix, no dots)"))?.to_string();
        let region = field("region")?;
        if !region.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(format!("{config}: the counter's region"));
        }
        if !s3::safe_key(object) {
            return Err("--object is a key of [A-Za-z0-9/_.-]".into());
        }
        Ok(CounterPlace {
            host: format!("{bucket}.s3.{region}.amazonaws.com"),
            region,
            object: object.to_string(),
            credentials: s3::Credentials { access_key_id: field("access_key_id")?, secret_access_key: field("secret_access_key")? },
        })
    }

    /// Now, as S3's `x-amz-date`, from the guest's clock (its NSM's time).
    fn amz_date() -> String {
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("a clock past 1970").as_secs() as i64;
        let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
        // days to a civil date (Howard Hinnant's algorithm)
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        format!("{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z", rest / 3600, rest / 60 % 60, rest % 60)
    }

    /// One S3 call over TLS the guest ends, Amazon's roots the only ones
    /// trusted.
    fn s3_call(place: &CounterPlace, method: &'static str, headers: Vec<(&'static str, String)>, body: &[u8]) -> Result<s3::Answer, String> {
        let path = format!("/{}", place.object);
        let request = s3::Request { method, host: &place.host, path: &path, headers, body };
        let signed = s3::sign(&place.credentials, &place.region, &amz_date(), &request);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().map_err(|e| e.to_string())?.with_root_certificates(amazon_roots()).with_no_client_auth();
        let name = rustls_pki_types::ServerName::try_from(place.host.clone()).map_err(|e| e.to_string())?;
        let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
        let tcp = TcpStream::connect((place.host.as_str(), 443)).map_err(|e| format!("connecting to the counter: {e}"))?;
        tcp.set_read_timeout(Some(Duration::from_millis(IO_MS_MAX))).map_err(|e| e.to_string())?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        tls.write_all(&s3::http(&request, &signed)).map_err(|e| format!("TLS to the counter: {e}"))?;
        let mut answer = Vec::new();
        match (&mut tls).take(s3::ANSWER_BYTES_MAX as u64 + 1).read_to_end(&mut answer) {
            Ok(_) => {}
            // S3 closes without a close_notify at times: what arrived is the answer.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !answer.is_empty() => {}
            Err(e) => return Err(format!("the counter's answer: {e}")),
        }
        if answer.len() > s3::ANSWER_BYTES_MAX {
            return Err("the counter's answer is too long".into());
        }
        s3::parse_answer(&answer)
    }

    /// The counter's record, checked under the disk's key, and its ETag.
    fn read_counter(place: &CounterPlace, macs: &disk::Macs) -> Result<Option<(disk::Counter, String)>, String> {
        let answer = s3_call(place, "GET", vec![], b"")?;
        match answer.status {
            200 => {
                let etag = answer.etag.ok_or("the counter's answer has no ETag")?;
                let counter = disk::Counter::from_json(&answer.body, macs).map_err(|e| e.to_string())?;
                Ok(Some((counter, etag)))
            }
            404 => Ok(None),
            status => Err(format!("the counter answered {status}")),
        }
    }

    /// The counter moved to `counter`: made when `etag` is none, else only
    /// over the record `etag` names.
    fn write_counter(place: &CounterPlace, macs: &disk::Macs, counter: &disk::Counter, etag: Option<&str>) -> Result<(), String> {
        let condition = match etag {
            Some(etag) => ("if-match", etag.to_string()),
            None => ("if-none-match", "*".to_string()),
        };
        let answer = s3_call(place, "PUT", vec![condition], counter.to_json(macs).as_bytes())?;
        match answer.status {
            200 => Ok(()),
            409 | 412 => Err("the counter moved under this open: another home has this disk's counter, refused".into()),
            status => Err(format!("the counter's write answered {status}")),
        }
    }

    fn read_block(device: &str) -> Result<Vec<u8>, String> {
        use std::os::unix::fs::FileExt as _;
        let file = std::fs::File::open(device).map_err(|e| format!("{device}: {e}"))?;
        let mut block = vec![0u8; disk::BLOCK_BYTES];
        file.read_exact_at(&mut block, 0).map_err(|e| format!("{device}: {e}"))?;
        Ok(block)
    }

    fn write_block(device: &str, block: &[u8]) -> Result<(), String> {
        use std::os::unix::fs::FileExt as _;
        let file = std::fs::OpenOptions::new().write(true).open(device).map_err(|e| format!("{device}: {e}"))?;
        file.write_all_at(block, 0).map_err(|e| format!("{device}: {e}"))?;
        file.sync_all().map_err(|e| format!("{device}: {e}"))
    }

    fn random_disk_id() -> Result<[u8; disk::DISK_ID_BYTES], String> {
        let mut id = [0u8; disk::DISK_ID_BYTES];
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut id)).map_err(|e| e.to_string())?;
        Ok(id)
    }

    /// A v2 disk checked against its counter, then both raised: the header
    /// first, so a stop between leaves it one ahead, which the next open
    /// takes.
    fn raise(device: &str, home: &str, place: &CounterPlace, macs: &disk::Macs, header: &disk::V2Header) -> Result<u64, String> {
        header.verify(macs, home).map_err(|e| e.to_string())?;
        let counter = read_counter(place, macs)?;
        let next = disk::admit(header, counter.as_ref().map(|(c, _)| c)).map_err(|e| e.to_string())?;
        write_block(device, &disk::write(macs, &header.wrapped, home, &header.disk, next))?;
        write_counter(place, macs, &disk::Counter { disk: header.disk, generation: next }, counter.as_ref().map(|(_, etag)| etag.as_str()))?;
        Ok(next)
    }

    fn write_secret(path: &str, bytes: &[u8]) -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|e| format!("{path}: {e}"))?;
        f.write_all(hex::encode(bytes).as_bytes()).map_err(|e| format!("{path}: {e}"))
    }

    fn read_secret<const N: usize>(path: &str) -> Result<[u8; N], String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        hex::decode(text.trim()).ok().and_then(|b| b.try_into().ok()).ok_or(format!("{path} is not {N} bytes of hex"))
    }

    /// `disk open`: the disk's key, once its header and its counter agree,
    /// both raised; `disk bump`: the same check and raise, while it runs.
    fn disk_run(args: &[String]) -> Result<(), String> {
        let usage = "usage: nitro-key disk open --device D --home H --counter-config F --object K --out KEYFILE --macs-out FILE | disk bump --device D --home H --counter-config F --object K --macs FILE";
        let action = args.first().map(String::as_str).ok_or(usage)?;
        let device = flag(args, "--device").ok_or(usage)?;
        let home = flag(args, "--home").ok_or(usage)?;
        if !disk::valid_home(home) {
            return Err("--home is [A-Za-z0-9_-], 1 to 64 bytes".into());
        }
        let place = counter_place(flag(args, "--counter-config").ok_or(usage)?, flag(args, "--object").ok_or(usage)?)?;
        let t0 = Instant::now();
        match action {
            "open" => {
                let out = flag(args, "--out").ok_or(usage)?;
                let macs_out = flag(args, "--macs-out").ok_or(usage)?;
                let (key, form, generation) = match disk::parse(&read_block(device)?).map_err(|e| e.to_string())? {
                    disk::Header::V2(header) => {
                        let (key, _, _) = release(Some(&header.wrapped))?;
                        let macs = disk::Macs::new(&key);
                        let generation = raise(device, home, &place, &macs, &header)?;
                        (key, "v2", generation)
                    }
                    first => {
                        // A blank disk, or a v1 one: v2 only while its counter is empty.
                        let form = if matches!(first, disk::Header::V1 { .. }) { "v1, now v2" } else { "new" };
                        let (key, wrapped) = match first {
                            disk::Header::V1 { wrapped } => (release(Some(&wrapped))?.0, wrapped),
                            _ => {
                                let (key, wrapped, _) = release(None)?;
                                (key, wrapped.ok_or("KMS gave no wrapped key for a new disk")?)
                            }
                        };
                        let macs = disk::Macs::new(&key);
                        disk::admit_first(read_counter(&place, &macs)?.is_some()).map_err(|e| e.to_string())?;
                        let id = random_disk_id()?;
                        write_block(device, &disk::write(&macs, &wrapped, home, &id, 1))?;
                        write_counter(&place, &macs, &disk::Counter { disk: id, generation: 1 }, None)?;
                        (key, form, 1)
                    }
                };
                write_key(out, &key)?;
                write_secret(macs_out, disk::Macs::new(&key).raw())?;
                println!("{}", serde_json::json!({"disk": form, "generation": generation, "ms": t0.elapsed().as_millis() as u64}));
                Ok(())
            }
            "bump" => {
                let macs = disk::Macs::from_raw(read_secret::<64>(flag(args, "--macs").ok_or(usage)?)?);
                let disk::Header::V2(header) = disk::parse(&read_block(device)?).map_err(|e| e.to_string())? else {
                    return Err("the disk is not v2: open it first".into());
                };
                let generation = raise(device, home, &place, &macs, &header)?;
                println!("{}", serde_json::json!({"generation": generation, "ms": t0.elapsed().as_millis() as u64}));
                Ok(())
            }
            _ => Err(usage.into()),
        }
    }

    /// One ask to the key service (docs/nitro-keys.md) through the parent's
    /// relay on `port`, and its answer.
    fn keys_ask(port: u32, ask: &serde_json::Value) -> Result<serde_json::Value, String> {
        let mut s = dial(CID_HOST, port).map_err(|e| format!("the key service: {e}"))?;
        s.set_read_timeout(Some(Duration::from_millis(IO_MS_MAX))).map_err(|e| e.to_string())?;
        s.write_all(format!("{ask}\n").as_bytes()).map_err(|e| e.to_string())?;
        let mut line = String::new();
        BufReader::new(s).take(64 * 1024).read_line(&mut line).map_err(|e| e.to_string())?;
        serde_json::from_str(line.trim()).map_err(|_| format!("the key service said: {}", line.trim()))
    }

    /// `keys release`: this home's key from the key service, for the image
    /// this guest's own document attests, sealed to a key made here.
    fn keys_run(args: &[String]) -> Result<(), String> {
        let usage = "usage: nitro-key keys release --port P --home H --out FILE [--entry LOG-ENTRY.json]";
        if args.first().map(String::as_str) != Some("release") {
            return Err(usage.into());
        }
        let port: u32 = flag(args, "--port").ok_or(usage)?.parse().map_err(|_| usage)?;
        let home = flag(args, "--home").ok_or(usage)?;
        let out = flag(args, "--out").ok_or(usage)?;
        let entry = match flag(args, "--entry") {
            Some(path) => Some(serde_json::from_slice::<serde_json::Value>(&std::fs::read(path).map_err(|e| format!("{path}: {e}"))?).map_err(|e| format!("{path}: {e}"))?),
            None => None,
        };
        let t0 = Instant::now();
        let nonce = keys_ask(port, &serde_json::json!({"ask": "nonce"}))?;
        let nonce = nonce["nonce"].as_str().and_then(|n| hex::decode(n).ok()).ok_or(format!("no nonce: {nonce}"))?;
        let private = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).map_err(|e| e.to_string())?;
        let public = private.to_public_key().to_public_key_der().map_err(|e| e.to_string())?.as_bytes().to_vec();
        let document = nsm::attest(Some(&nonce), Some(&public))?;
        let answer = keys_ask(port, &serde_json::json!({"ask": "release", "home": home, "document": base64::engine::general_purpose::STANDARD.encode(document), "entry": entry}))?;
        match answer["answer"].as_str() {
            Some("released") => {
                let sealed = answer["key"].as_str().and_then(|k| base64::engine::general_purpose::STANDARD.decode(k).ok()).ok_or("no key in the answer")?;
                let key = private.decrypt(rsa::Oaep::new::<Sha256>(), &sealed).map_err(|e| format!("the key does not open: {e}"))?;
                write_key(out, &key)?;
                println!("{}", serde_json::json!({"released": answer["why"], "key_sha256": hex::encode(Sha256::digest(&key)), "ms": t0.elapsed().as_millis() as u64}));
                Ok(())
            }
            _ => Err(format!("refused: {}", answer["why"].as_str().unwrap_or("(no reason)"))),
        }
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
        if mode == "disk" {
            return disk_run(&args[1..]);
        }
        if mode == "keys" {
            return keys_run(&args[1..]);
        }
        let out = flag(&args, "--out").ok_or("--out <file>")?;
        let t0 = Instant::now();
        let wrapped = match mode {
            "new" => None,
            "wake" => Some(base64::engine::general_purpose::STANDARD.decode(flag(&args, "--wrapped").ok_or("--wrapped <base64>")?).map_err(|e| e.to_string())?),
            _ => return Err("usage: nitro-key new|wake [--wrapped b64] --out file | attest --nonce hex | disk open|bump ...".into()),
        };
        let (key, wrapped, timing) = release(wrapped.as_deref())?;
        write_key(out, &key)?;
        let wrapped = wrapped.map(|w| base64::engine::general_purpose::STANDARD.encode(w));
        println!("{}", serde_json::json!({"mode": mode, "wrapped": wrapped, "key_sha256": hex::encode(Sha256::digest(key)), "timing": timing, "total_ms": t0.elapsed().as_secs_f64() * 1000.0}));
        Ok(())
    }
}
