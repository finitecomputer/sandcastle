//! The spike's scenarios on the parent (docs/nitro-spike.md, acceptance 2
//! to 5), each printing its evidence as one JSON object. Run as root
//! (Firecracker opens `/dev/nitro_enclaves`; the scans read `/proc`).

use std::path::{Path, PathBuf};

use base64::Engine as _;
use sandcastle_nitro_attest::{verify, Trust};
use sandcastle_nitro_probe::protocol::{Answer, Command};
use serde_json::{json, Value};

use crate::config::{Boot, Drive, Enclave, Mode, Parent, Sandbox, Vsock};
use crate::run::{self, Failure};
use crate::scan;

/// Where each sandbox's files go: a tmpfs, so nothing outlives a reboot.
pub const RUN_ROOT: &str = "/run/nitro-spike";
/// The disk a canary is written to.
pub const DISK_MIB: u64 = 64;

pub fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].as_str())
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, Failure> {
    flag(args, name).ok_or_else(|| Failure(format!("{name} is required")))
}

fn number<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> Result<T, Failure> {
    match flag(args, name) {
        Some(v) => v.parse().map_err(|_| Failure(format!("{name}: not a number"))),
        None => Ok(default),
    }
}

fn yes(args: &[String], name: &str) -> bool {
    flag(args, name) == Some("true")
}

/// The parent as it is: its vCPUs, and its first core's threads.
pub fn parent() -> Parent {
    let vcpus = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1);
    let siblings = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list").unwrap_or_default();
    let first_core_vcpus = if siblings.contains(',') || siblings.contains('-') { 2 } else { 1 };
    Parent { vcpus, first_core_vcpus }
}

pub fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom").and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b)).expect("the kernel's randomness");
    hex::encode(b)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("after 1970").as_millis() as u64
}

/// The sandbox these flags describe, its files under `dir`.
fn sandbox(args: &[String], dir: &Path, drives: Vec<Drive>) -> Result<Sandbox, Failure> {
    let mode = match flag(args, "--mode").unwrap_or("confidential") {
        "confidential" => Mode::Confidential,
        "direct" => Mode::Direct,
        other => return Err(Failure(format!("--mode {other}: confidential or direct"))),
    };
    Ok(Sandbox {
        boot: Boot::Kernel { kernel: required(args, "--kernel")?.into(), initrd: Some(required(args, "--initrd")?.into()), cmdline: flag(args, "--cmdline").unwrap_or(crate::config::FIRECRACKER_DEFAULT_BOOT_ARGS).into() },
        vcpus: number(args, "--vcpus", 2)?,
        memory_mib: number(args, "--mem-mib", 512)?,
        drives,
        nics: vec![],
        vsock: Vsock { guest_cid: 3, uds_path: dir.join("v.sock"), dmb_mib: None },
        enclave: Enclave { mode, cpu_overcommit: yes(args, "--overcommit"), hotplug: false, debug: yes(args, "--debug"), cpu_accounting: false },
    })
}

fn stats(samples: &[f64]) -> Value {
    assert!(!samples.is_empty());
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    let n = s.len();
    let median = if n % 2 == 1 { s[n / 2] } else { (s[n / 2 - 1] + s[n / 2]) / 2.0 };
    let r = |x: f64| (x * 10.0).round() / 10.0;
    json!({"n": n, "median": r(median), "min": r(s[0]), "max": r(s[n - 1])})
}

fn hello_ms(a: &Answer) -> (u64, u64) {
    match a {
        Answer::Hello { init_ms, hello_ms, .. } => (*init_ms, *hello_ms),
        _ => unreachable!("launch checks the hello"),
    }
}

fn pool_mib(file: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/sys/class/misc/nitro_enclaves/{file}")).ok().and_then(|s| s.trim().parse::<u64>().ok()).map(|b| b >> 20)
}

/// Acceptance 2: launch to userspace, `--samples` times.
pub fn boot(args: &[String]) -> Result<Value, Failure> {
    let samples: usize = number(args, "--samples", 10)?;
    let p = parent();
    let (mut connect, mut hello, mut init, mut stop) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut first = None;
    for i in 0..samples {
        let dir = PathBuf::from(RUN_ROOT).join(format!("boot-{i}"));
        let s = sandbox(args, &dir, vec![])?;
        let session = run::launch(&s, &p, &dir)?;
        let (init_ms, guest_hello_ms) = hello_ms(&session.hello);
        if first.is_none() {
            first = Some(json!({"hello": session.hello, "config": serde_json::from_str::<Value>(&s.render(&p).expect("launched")).expect("JSON"), "pool_in_use_mib": pool_mib("mem_pool/in_use"), "slots_in_use": std::fs::read_to_string("/sys/class/misc/nitro_enclaves/pcie_slots_in_use").ok().map(|s| s.trim().to_string()), "pool_mib_expected": s.pool_mib()}));
        }
        connect.push(session.connect_ms);
        hello.push(session.hello_ms);
        init.push(init_ms as f64);
        let _ = guest_hello_ms;
        let (stop_ms, by_itself) = session.stop()?;
        if !by_itself {
            return Err(Failure(format!("sample {i}: Firecracker did not exit after the power-off")));
        }
        stop.push(stop_ms);
    }
    Ok(json!({
        "scenario": "boot",
        "what": "spawning Firecracker to the probe's vsock dial (connect) and hello; the guest's own boot clock when its init began (init); a power-off to Firecracker's exit (stop). All ms.",
        "connect_ms": stats(&connect),
        "hello_ms": stats(&hello),
        "guest_init_boottime_ms": stats(&init),
        "stop_ms": stats(&stop),
        "samples_connect_ms": connect,
        "first": first,
    }))
}

/// Acceptance 3: the canaries, and what the parent finds of them.
pub fn canary(args: &[String]) -> Result<Value, Failure> {
    let p = parent();
    let dir = PathBuf::from(RUN_ROOT).join("canary");
    let disk = PathBuf::from(RUN_ROOT).join("canary-disk.img");
    let f = std::fs::File::create(&disk).map_err(|e| Failure(format!("the disk: {e}")))?;
    f.set_len(DISK_MIB << 20).map_err(|e| Failure(format!("the disk: {e}")))?;
    drop(f);
    let s = sandbox(args, &dir, vec![Drive { id: "disk".into(), path: disk.clone(), read_only: false, dmb_mib: None }])?;
    let mib: u32 = number(args, "--canary-mib", 64)?;
    let memory = format!("NITRO-SPIKE-MEMORY-CANARY-{}", random_hex(8));
    let console = format!("NITRO-SPIKE-CONSOLE-CANARY-{}", random_hex(8));
    let on_disk = format!("NITRO-SPIKE-DISK-CANARY-{}", random_hex(8));
    let mut session = run::launch(&s, &p, &dir)?;
    let mut answers = Vec::new();
    for c in [Command::MemoryCanary { text: memory.clone(), mib }, Command::ConsoleCanary { text: console.clone() }, Command::DiskCanary { device: "/dev/vda".into(), text: on_disk.clone() }] {
        answers.push(session.ask(&c)?);
    }
    let guest_mib = u64::from(s.memory_mib);
    let mappings = scan::large_mappings(session.pid, guest_mib << 19).map_err(|e| Failure(format!("Firecracker's maps: {e}")))?;
    // `--process false` lists Firecracker's mappings without reading them.
    let process = if flag(args, "--process") == Some("false") { None } else { Some(scan::process(session.pid, &memory).map_err(|e| Failure(format!("Firecracker's memory: {e}")))?) };
    let locked = if yes(args, "--read-locked") { Some(scan::locked(session.pid, &memory).map_err(|e| Failure(format!("the locked mapping: {e}")))?) } else { None };
    let disk_scan = scan::file(&disk, &on_disk, "the disk's backing file on the parent").map_err(|e| Failure(format!("the disk: {e}")))?;
    // The physical scan last, and only when asked: in confidential mode it
    // reads pages the parent has given away.
    let physical = if yes(args, "--physical") { Some(scan::physical(&memory).map_err(|e| Failure(format!("kcore: {e}")))?) } else { None };
    let hello = session.hello.clone();
    let (stop_ms, _) = session.stop()?;
    // After Firecracker's exit: the serial console reaches its log
    // asynchronously, so a look while it runs can miss a line it shows.
    let log = dir.join("firecracker.log");
    let console_seen = scan::file_contains(&log, &console).map_err(|e| Failure(format!("the log: {e}")))?;
    let _ = std::fs::remove_file(&disk);
    Ok(json!({
        "scenario": "canary",
        "mode": flag(args, "--mode").unwrap_or("confidential"),
        "debug": yes(args, "--debug"),
        "hello": hello,
        "answers": answers,
        "needle": format!("each canary's text repeated {} times; the parent itself holds the text once in its command and once in the needle", scan::RUN_REPEATS),
        "firecracker_mappings_over_half_the_guest": mappings,
        "memory_in_firecracker": process,
        "memory_in_physical_ram": physical,
        "memory_in_firecrackers_locked_mapping": locked,
        "disk_on_parent": disk_scan,
        "console_in_firecracker_log": console_seen,
        "stop_ms": stop_ms,
    }))
}

/// Acceptance 4: `--samples` documents, each from its own launch, saved
/// under `--out-dir` with their nonces, and verified here at once.
pub fn attest(args: &[String]) -> Result<Value, Failure> {
    let p = parent();
    let samples: usize = number(args, "--samples", 2)?;
    let out = PathBuf::from(required(args, "--out-dir")?);
    std::fs::create_dir_all(&out).map_err(|e| Failure(format!("{}: {e}", out.display())))?;
    let trust = Trust::aws_nitro_enclaves_root_g1();
    let mut docs = Vec::new();
    for i in 0..samples {
        let dir = PathBuf::from(RUN_ROOT).join(format!("attest-{i}"));
        let s = sandbox(args, &dir, vec![])?;
        let mut session = run::launch(&s, &p, &dir)?;
        let nonce = random_hex(32);
        let answer = session.ask(&Command::Attest { nonce_hex: nonce.clone(), with_key: false })?;
        session.stop()?;
        let Answer::Attested { document_hex, nsm_ms, .. } = answer else {
            return Err(Failure(format!("sample {i}: {answer:?}")));
        };
        let document = hex::decode(&document_hex).expect("the probe sends hex");
        std::fs::write(out.join(format!("doc-{i}.bin")), &document).map_err(|e| Failure(e.to_string()))?;
        std::fs::write(out.join(format!("doc-{i}.nonce")), &nonce).map_err(|e| Failure(e.to_string()))?;
        let verified = match verify(&trust, &document, &hex::decode(&nonce).expect("hex"), now_ms()) {
            Ok(a) => json!({"verified": true, "pcrs": a.pcrs.iter().map(|(i, v)| (i.to_string(), Value::String(if *i == 3 || *i == 4 { "<parent>".into() } else { hex::encode(v) }))).collect::<serde_json::Map<_, _>>()}),
            Err(e) => json!({"verified": false, "error": e.to_string()}),
        };
        docs.push(json!({"sample": i, "bytes": document.len(), "nsm_ms": nsm_ms, "on_the_parent": verified}));
    }
    Ok(json!({"scenario": "attest", "mode": flag(args, "--mode").unwrap_or("confidential"), "debug": yes(args, "--debug"), "overcommit": yes(args, "--overcommit"), "cmdline": flag(args, "--cmdline"), "documents": docs}))
}

/// KMS's Decrypt through the AWS CLI on the parent, with the parent's
/// role: with a recipient (the sandbox's document), or without.
fn kms_decrypt(region: &str, key_id: &str, ciphertext: &[u8], document: Option<&[u8]>, dir: &Path) -> Result<Result<Value, String>, Failure> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut input = json!({"KeyId": key_id, "CiphertextBlob": b64.encode(ciphertext)});
    if let Some(d) = document {
        input["Recipient"] = json!({"KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256", "AttestationDocument": b64.encode(d)});
    }
    let path = dir.join("kms-input.json");
    std::fs::write(&path, input.to_string()).map_err(|e| Failure(e.to_string()))?;
    let out = std::process::Command::new("aws")
        .args(["kms", "decrypt", "--region", region, "--output", "json", "--cli-input-json"])
        .arg(format!("file://{}", path.display()))
        .output()
        .map_err(|e| Failure(format!("the AWS CLI: {e}")))?;
    let _ = std::fs::remove_file(&path);
    if out.status.success() {
        Ok(Ok(serde_json::from_slice(&out.stdout).map_err(|e| Failure(format!("KMS's answer: {e}")))?))
    } else {
        Ok(Err(String::from_utf8_lossy(&out.stderr).trim().to_string()))
    }
}

/// Acceptance 5: a Decrypt for this sandbox's image (`--expect allow`),
/// for another image (`--expect deny`), or from the parent alone
/// (`--parent-only`, no sandbox, no recipient).
pub fn release(args: &[String]) -> Result<Value, Failure> {
    let region = flag(args, "--region").unwrap_or("us-east-2");
    let key_id = required(args, "--key-id")?;
    let ciphertext = std::fs::read(required(args, "--secret-enc")?).map_err(|e| Failure(format!("--secret-enc: {e}")))?;
    let expect_sha = flag(args, "--expect-sha256");
    let dir = PathBuf::from(RUN_ROOT).join("release");
    if yes(args, "--parent-only") {
        std::fs::create_dir_all(&dir).map_err(|e| Failure(e.to_string()))?;
        let r = kms_decrypt(region, key_id, &ciphertext, None, &dir)?;
        return Ok(json!({"scenario": "release", "caller": "the parent's role, no recipient", "allowed": r.is_ok(), "kms": match r { Ok(v) => json!({"plaintext_sha256": v["Plaintext"].as_str().map(|p| hex::encode(sandcastle_nitro_attest::sha256(&base64::engine::general_purpose::STANDARD.decode(p).unwrap_or_default())))}), Err(e) => json!(e) }}));
    }
    let p = parent();
    let s = sandbox(args, &dir, vec![])?;
    let mut session = run::launch(&s, &p, &dir)?;
    let nonce = random_hex(32);
    let attested = session.ask(&Command::Attest { nonce_hex: nonce, with_key: true })?;
    let Answer::Attested { document_hex, key_ms, nsm_ms, public_key_sha256 } = attested else {
        return Err(Failure(format!("the attestation: {attested:?}")));
    };
    let document = hex::decode(&document_hex).expect("hex");
    let decrypt = kms_decrypt(region, key_id, &ciphertext, Some(&document), &dir)?;
    let (allowed, opened) = match &decrypt {
        Ok(v) => {
            let cms = v["CiphertextForRecipient"].as_str().ok_or_else(|| Failure("KMS answered no CiphertextForRecipient".into()))?;
            let cms = base64::engine::general_purpose::STANDARD.decode(cms).map_err(|e| Failure(format!("KMS's envelope: {e}")))?;
            assert!(v.get("Plaintext").is_none_or(Value::is_null), "with a recipient, KMS returns no plaintext");
            (true, Some(session.ask(&Command::Open { cms_hex: hex::encode(&cms) })?))
        }
        Err(_) => (false, None),
    };
    let matches = match (&opened, expect_sha) {
        (Some(Answer::Opened { plaintext_sha256, .. }), Some(want)) => Some(plaintext_sha256 == want),
        _ => None,
    };
    session.stop()?;
    Ok(json!({
        "scenario": "release",
        "caller": "the parent's role, carrying the sandbox's attestation document as the recipient",
        "cmdline": flag(args, "--cmdline"),
        "allowed": allowed,
        "kms_error": decrypt.as_ref().err(),
        "guest_key_ms": key_ms,
        "guest_nsm_ms": nsm_ms,
        "public_key_sha256": public_key_sha256,
        "opened_in_the_guest": opened,
        "plaintext_matches_the_secret": matches,
    }))
}
