//! `nitro-keys`: the key service (docs/nitro-keys.md), and its operator's
//! commands on the parent.
//!
//!   nitro-keys serve --port P --data DEV --log-key PEM --finite-key PEM   # in its own sandbox
//!   nitro-keys add-home --socket S --pcr0 X --home H --owner HEX --key-file F   # the operator, once per home
//!   nitro-keys say --socket S --event FILE          # an owner's statement, relayed as signed
//!   nitro-keys ask --socket S --json ASK             # any ask, its answer printed
//!
//! The service answers one ask per connection, one JSON line each way. Its
//! state's one share today comes from KMS (`nitro-key new`/`wake`, so only
//! its own image's document gets it) and is kept wrapped in its data disk's
//! first block; the state, sealed, follows it.

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(match linux::run(std::env::args().skip(1).collect()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("nitro-keys: {e}");
            1
        }
    })
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("nitro-keys runs on Linux");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::FileExt as _;
    use std::os::unix::net::UnixStream;
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use rsa::pkcs8::{DecodePublicKey as _, EncodePublicKey as _};
    use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
    use sandcastle_nitro_attest::Trust;
    use sandcastle_nitro_keys::log::P256Key;
    use sandcastle_nitro_keys::service::{refused, Answer, Ask, Service, ASK_BYTES_MAX};
    use sandcastle_nitro_keys::state::{Shares, State};

    const HEADER: &str = "nitro-keys v1 ";
    const BLOCK: u64 = 4096;
    const SHARE_FILE: &str = "/run/nitro-keys/share";

    fn b64() -> base64::engine::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    fn flag<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
        args.windows(2).find(|w| w[0] == name).map(|w| w[1].as_str()).ok_or(format!("{name} is needed"))
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).expect("a clock past 1970").as_millis() as u64
    }

    fn random32() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).expect("random");
        bytes
    }

    /// One JSON line read, at most `ASK_BYTES_MAX`.
    fn read_line(stream: &mut impl Read) -> Result<String, String> {
        let mut line = String::new();
        BufReader::new(stream.take(ASK_BYTES_MAX as u64 + 1)).read_line(&mut line).map_err(|e| e.to_string())?;
        if line.len() > ASK_BYTES_MAX {
            return Err("an ask past its limit".into());
        }
        Ok(line)
    }

    /// The share KMS releases to this image alone, and the state its disk
    /// holds. A blank disk gets a new share, its wrapped form in block 0.
    fn open_disk(data: &str) -> Result<(Shares, State), String> {
        let disk = std::fs::OpenOptions::new().read(true).write(true).open(data).map_err(|e| format!("{data}: {e}"))?;
        let mut block = vec![0u8; BLOCK as usize];
        disk.read_exact_at(&mut block, 0).map_err(|e| format!("{data}: {e}"))?;
        let text = String::from_utf8_lossy(block.split(|b| *b == 0).next().unwrap_or_default()).to_string();
        std::fs::create_dir_all("/run/nitro-keys").map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(SHARE_FILE);
        let (out, new) = match text.strip_prefix(HEADER) {
            Some(wrapped) => (std::process::Command::new("nitro-key").args(["wake", "--wrapped", wrapped.trim(), "--out", SHARE_FILE]).output(), false),
            None if text.is_empty() => (std::process::Command::new("nitro-key").args(["new", "--out", SHARE_FILE]).output(), true),
            None => return Err(format!("{data}'s first block is not the key service's")),
        };
        let out = out.map_err(|e| format!("nitro-key: {e}"))?;
        if !out.status.success() {
            return Err(format!("KMS released no share: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        let share = std::fs::read_to_string(SHARE_FILE).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(SHARE_FILE);
        let kms: [u8; 32] = hex::decode(share.trim()).ok().and_then(|s| s.try_into().ok()).ok_or("the share is not 32 bytes")?;
        let shares = Shares { kms, second: None };
        if new {
            let said: serde_json::Value = serde_json::from_slice(&out.stdout).map_err(|_| "nitro-key's answer")?;
            let wrapped = said["wrapped"].as_str().ok_or("KMS gave no wrapped share")?;
            let mut header = format!("{HEADER}{wrapped}").into_bytes();
            header.resize(BLOCK as usize, 0);
            disk.write_all_at(&header, 0).map_err(|e| e.to_string())?;
            disk.write_all_at(&[0u8; 8], BLOCK).map_err(|e| e.to_string())?;
            disk.sync_all().map_err(|e| e.to_string())?;
            println!("keys: a new share, wrapped in the disk's first block");
            return Ok((shares, State::default()));
        }
        let mut len = [0u8; 8];
        disk.read_exact_at(&mut len, BLOCK).map_err(|e| e.to_string())?;
        let len = u64::from_le_bytes(len) as usize;
        if len == 0 {
            return Ok((shares, State::default()));
        }
        if len > sandcastle_nitro_keys::state::SEALED_BYTES_MAX {
            return Err("the sealed state is past its limit".into());
        }
        let mut sealed = vec![0u8; len];
        disk.read_exact_at(&mut sealed, BLOCK + 8).map_err(|e| e.to_string())?;
        let state = State::open(&sealed, &shares, 0).map_err(|e| e.to_string())?;
        println!("keys: state opened at generation {}", state.generation);
        Ok((shares, state))
    }

    fn keep(data: &str, shares: &Shares, state: &State) -> Result<(), String> {
        let sealed = state.seal(shares);
        let disk = std::fs::OpenOptions::new().write(true).open(data).map_err(|e| format!("{data}: {e}"))?;
        disk.write_all_at(&sealed, BLOCK + 8).map_err(|e| e.to_string())?;
        disk.write_all_at(&(sealed.len() as u64).to_le_bytes(), BLOCK).map_err(|e| e.to_string())?;
        disk.sync_all().map_err(|e| e.to_string())
    }

    fn listen(port: u32) -> Result<OwnedFd, String> {
        // SAFETY: a socket call; the descriptor is owned at once.
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: a fresh descriptor we own.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: sockaddr_vm is plain data; zero is its empty value.
        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = libc::VMADDR_CID_ANY;
        addr.svm_port = port;
        // SAFETY: a valid sockaddr_vm and its size; then listen on it.
        let bound = unsafe { libc::bind(fd.as_raw_fd(), &addr as *const _ as *const libc::sockaddr, std::mem::size_of_val(&addr) as u32) };
        if bound != 0 || unsafe { libc::listen(fd.as_raw_fd(), 16) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(fd)
    }

    fn serve(args: &[String]) -> Result<(), String> {
        let port: u32 = flag(args, "--port")?.parse().map_err(|_| "--port")?;
        let data = flag(args, "--data")?.to_string();
        let pem = |name: &str| -> Result<P256Key, String> {
            let path = flag(args, name)?;
            P256Key::from_pem(&std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?).map_err(|e| e.to_string())
        };
        let (log, finite) = (pem("--log-key")?, pem("--finite-key")?);
        let (shares, state) = open_disk(&data)?;
        let mut service = Service::new(state, Trust::aws_nitro_enclaves_root_g1(), log, finite);
        let mut rng = rsa::rand_core::OsRng;
        // The operator seals a new home's key to this, which only this life holds.
        let own = RsaPrivateKey::new(&mut rng, 2048).map_err(|e| e.to_string())?;
        let own_public = own.to_public_key().to_public_key_der().map_err(|e| e.to_string())?.as_bytes().to_vec();
        let listener = listen(port)?;
        println!("keys: serving on vsock port {port}");
        loop {
            // SAFETY: accept on our listening descriptor; the peer address is not read.
            let fd = unsafe { libc::accept4(listener.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
            if fd < 0 {
                eprintln!("keys: accept: {}", std::io::Error::last_os_error());
                continue;
            }
            // SAFETY: a descriptor accept just gave us.
            let mut stream = UnixStream::from(unsafe { OwnedFd::from_raw_fd(fd) });
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            let answer = match read_line(&mut stream).and_then(|l| serde_json::from_str::<Ask>(&l).map_err(|e| format!("not an ask: {e}"))) {
                Err(why) => refused(why),
                Ok(Ask::Attest { nonce }) => match hex::decode(&nonce).ok().filter(|n| n.len() == 32) {
                    None => refused("a nonce is 32 bytes, hex"),
                    Some(nonce) => match sandcastle_nitro_probe::nsm::attest(Some(&nonce), Some(&own_public)) {
                        Ok(document) => Answer::Attested { document: b64().encode(document) },
                        Err(why) => refused(format!("the NSM: {why}")),
                    },
                },
                Ok(Ask::AddHome { home, owner, key }) => {
                    let opened = b64().decode(&key).ok().and_then(|k| own.decrypt(Oaep::new::<sha2::Sha256>(), &k).ok()).and_then(|k| <[u8; 32]>::try_from(k).ok());
                    let owner = hex::decode(&owner).ok().and_then(|o| <[u8; 32]>::try_from(o).ok());
                    match (opened, owner, sandcastle_nitro_keys::statement::valid_home(&home)) {
                        (Some(key), Some(owner), true) => match service.state.add_home(&home, owner, key) {
                            Ok(()) => match keep(&data, &shares, &service.state) {
                                Ok(()) => Answer::Added { generation: service.state.generation },
                                Err(why) => refused(format!("kept nothing: {why}")),
                            },
                            Err(why) => refused(why),
                        },
                        _ => refused("a home's name, its owner's key (hex) and its key sealed to this service's document"),
                    }
                }
                Ok(ask) => {
                    let (answer, changed) = service.answer(ask, now_ms(), random32(), &mut rng);
                    match changed.then(|| keep(&data, &shares, &service.state)) {
                        Some(Err(why)) => refused(format!("kept nothing: {why}")),
                        _ => answer,
                    }
                }
            };
            let line = serde_json::to_string(&answer).expect("an answer serializes");
            println!("keys: {}", match &answer {
                Answer::Released { why, .. } => format!("released: {why}"),
                Answer::Refused { why } => format!("refused: {why}"),
                Answer::Taken { generation } => format!("statement taken, generation {generation}"),
                Answer::Added { generation } => format!("home added, generation {generation}"),
                Answer::Nonce { .. } => "a nonce".into(),
                Answer::Attested { .. } => "attested".into(),
                Answer::Repair { until } => format!("repair until {until:?}"),
            });
            let _ = stream.write_all(format!("{line}\n").as_bytes());
        }
    }

    /// One ask over the parent's relay to the service, and its answer.
    fn ask(socket: &str, ask: &Ask) -> Result<Answer, String> {
        let mut stream = UnixStream::connect(socket).map_err(|e| format!("{socket}: {e}"))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(30))).map_err(|e| e.to_string())?;
        stream.write_all(format!("{}\n", serde_json::to_string(ask).expect("an ask serializes")).as_bytes()).map_err(|e| e.to_string())?;
        let line = read_line(&mut stream)?;
        serde_json::from_str(&line).map_err(|e| format!("not an answer ({e}): {line}"))
    }

    /// The operator makes a home: the service's own document checked (its
    /// chain to AWS's root, its nonce, its PCR0), then the home's key sealed
    /// to the key it carries.
    fn add_home(args: &[String]) -> Result<(), String> {
        let socket = flag(args, "--socket")?;
        let pcr0 = flag(args, "--pcr0")?;
        let nonce = random32();
        let Answer::Attested { document } = ask(socket, &Ask::Attest { nonce: hex::encode(nonce) })? else {
            return Err("the service gave no document".into());
        };
        let document = b64().decode(document).map_err(|e| e.to_string())?;
        let attested = sandcastle_nitro_attest::verify(&Trust::aws_nitro_enclaves_root_g1(), &document, &nonce, now_ms()).map_err(|e| format!("the service's document: {e}"))?;
        let found = attested.pcrs.iter().find(|(i, _)| *i == 0).map(|(_, p)| hex::encode(p)).ok_or("no PCR0")?;
        if found != pcr0 {
            return Err(format!("the service runs {found}, not {pcr0}: nothing sealed to it"));
        }
        let public = attested.public_key.as_deref().and_then(|k| RsaPublicKey::from_public_key_der(k).ok()).ok_or("the document carries no RSA key")?;
        let key_file = flag(args, "--key-file")?;
        let key = std::fs::read_to_string(key_file).map_err(|e| format!("{key_file}: {e}"))?;
        let key: [u8; 32] = hex::decode(key.trim()).ok().and_then(|k| k.try_into().ok()).ok_or("the key file is 64 hex digits")?;
        let sealed = public.encrypt(&mut rsa::rand_core::OsRng, Oaep::new::<sha2::Sha256>(), &key).map_err(|e| e.to_string())?;
        let answer = ask(socket, &Ask::AddHome { home: flag(args, "--home")?.into(), owner: flag(args, "--owner")?.into(), key: b64().encode(sealed) })?;
        println!("{}", serde_json::to_string(&answer).expect("JSON"));
        matches!(answer, Answer::Added { .. }).then_some(()).ok_or("not added".into())
    }

    pub fn run(args: Vec<String>) -> Result<(), String> {
        match args.first().map(String::as_str) {
            Some("serve") => serve(&args),
            Some("add-home") => add_home(&args),
            Some("say") => {
                let path = flag(&args, "--event")?;
                let event = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
                let answer = ask(flag(&args, "--socket")?, &Ask::Statement { event: event.trim().to_string() })?;
                println!("{}", serde_json::to_string(&answer).expect("JSON"));
                Ok(())
            }
            Some("ask") => {
                let parsed: Ask = serde_json::from_str(flag(&args, "--json")?).map_err(|e| format!("--json: {e}"))?;
                println!("{}", serde_json::to_string(&ask(flag(&args, "--socket")?, &parsed)?).expect("JSON"));
                Ok(())
            }
            _ => Err("usage: nitro-keys serve|add-home|say|ask (see the source's head)".into()),
        }
    }
}
