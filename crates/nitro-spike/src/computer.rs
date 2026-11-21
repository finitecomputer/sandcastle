//! A computer as a Nitro Sandbox (docs/nitro-spike.md, acceptance 6 to 9):
//! sandcastle's guest as init from the initrd, Hermes' image as a raw disk
//! under dm-verity (its table, root hash included, on the measured command
//! line), a fresh scratch disk for the overlay, a tap to sandcastle's
//! egress, and FPAC's sealed disk at `/opt/data`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command as Process, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use sandcastle_egress::{Action, Intercept, Policy, Scheme};
use sandcastle_nitro_attest::{verify, Trust};
use sandcastle_wire::{GuestNet, Process as Proc, Start};
use serde_json::{json, Value};

use crate::config::{Boot, Drive, Enclave, Mode, Nic, Parent, Sandbox, Vsock};
use crate::guest::{self, Guest};
use crate::run::Failure;
use crate::scenarios::{flag, parent, random_hex, RUN_ROOT};
use crate::services::{Services, FPAC_HOST, KMS_HOST, MODEL_HOST, MODEL_REPLY, STAND_IN};

pub const TAP: &str = "nitrotap0";
/// The image's verity device, as the kernel makes it from `dm-mod.create=`.
pub const VERITY_NAME: &str = "sc-image";
/// The CA path sandcastle's guest writes the egress CA to.
pub const CA_IN_GUEST: &str = "/etc/cloudflare/certs/cloudflare-containers-ca.crt";

fn fail(what: &str, e: impl std::fmt::Display) -> Failure {
    Failure(format!("{what}: {e}"))
}

fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1000.0 * 10.0).round() / 10.0
}

/// The image's verity facts, as `verity-image.sh` wrote them.
pub struct Image {
    pub image: PathBuf,
    pub tree: PathBuf,
    pub blocks: u64,
    /// Where the tree starts on its disk, in blocks (1: after
    /// veritysetup's superblock).
    pub hash_start: u64,
    pub root_hash: String,
    pub salt: String,
    pub env: Vec<String>,
}

impl Image {
    pub fn load(args: &[String]) -> Result<Image, Failure> {
        let p = flag(args, "--image-json").ok_or_else(|| Failure("--image-json".into()))?;
        let v: Value = serde_json::from_slice(&std::fs::read(p).map_err(|e| fail(p, e))?).map_err(|e| fail(p, e))?;
        let s = |k: &str| v[k].as_str().map(str::to_string).ok_or_else(|| Failure(format!("{p}: no {k}")));
        // The image's own environment (its OCI config's), so the workload
        // and every exec run as the image expects.
        let env = match flag(args, "--image-config") {
            Some(c) => {
                let cfg: Value = serde_json::from_slice(&std::fs::read(c).map_err(|e| fail(c, e))?).map_err(|e| fail(c, e))?;
                cfg["Env"].as_array().map(|a| a.iter().filter_map(|e| e.as_str().map(str::to_string)).collect()).unwrap_or_default()
            }
            None => vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()],
        };
        Ok(Image { image: s("image")?.into(), tree: s("hash_tree")?.into(), blocks: v["data_blocks"].as_u64().ok_or_else(|| Failure("data_blocks".into()))?, hash_start: v["hash_start_block"].as_u64().ok_or_else(|| Failure("hash_start_block".into()))?, root_hash: s("root_hash")?, salt: s("salt")?, env })
    }

    /// The command line: the verity table (`/dev/vdb` its data, `/dev/vda`
    /// its tree), the guest told to mount it, and the KMS key it may use.
    pub fn cmdline(&self, kms_key: Option<&str>) -> String {
        assert!(self.root_hash.len() == 64 && self.root_hash.bytes().all(|b| b.is_ascii_hexdigit()), "a SHA-256 root hash");
        assert!(self.salt.bytes().all(|b| b.is_ascii_hexdigit()));
        let table = format!("{VERITY_NAME},,,ro,0 {} verity 1 /dev/vdb /dev/vda 4096 4096 {} {} sha256 {} {}", self.blocks * 8, self.blocks, self.hash_start, self.root_hash, self.salt);
        let mut c = format!("panic=1 initcall_blacklist=i8042_init quiet dm-mod.create=\"{table}\" dm-mod.waitfor=/dev/vda,/dev/vdb sandcastle.image=/dev/dm-0");
        if let Some(k) = kms_key {
            c.push_str(&format!(" nitro.kms_key={k}"));
        }
        c
    }
}

/// Where scratch disks live: the parent's own disk. Not /run: it is a
/// tmpfs of a fifth of the parent's memory, and a full one reaches the
/// guest as write errors (its ext4 goes read-only and FPAC fences).
pub const SCRATCH_ROOT: &str = "/var/lib/nitro-spike/scratch";

/// A fresh scratch disk: sparse, ext4, for the overlay's upper layer.
fn scratch(path: &Path, gib: u64) -> Result<(), Failure> {
    let _ = std::fs::remove_file(path);
    let f = std::fs::File::create(path).map_err(|e| fail("the scratch disk", e))?;
    f.set_len(gib << 30).map_err(|e| fail("the scratch disk", e))?;
    drop(f);
    let out = Process::new("mkfs.ext4").args(["-q", "-F", "-E", "lazy_itable_init=1,lazy_journal_init=1"]).arg(path).output().map_err(|e| fail("mkfs", e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(Failure(format!("mkfs: {}", String::from_utf8_lossy(&out.stderr))))
    }
}

/// What a computer's launch needs.
pub struct Plan<'a> {
    pub image: &'a Image,
    pub kernel: &'a str,
    pub initrd: &'a str,
    pub dir: PathBuf,
    pub scratch_gib: u64,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub net: bool,
    pub kms_key: Option<&'a str>,
    pub entrypoint: Vec<String>,
    pub env: Vec<String>,
    pub ca_pem: Option<String>,
}

pub fn launch(plan: &Plan<'_>, parent: &Parent) -> Result<(Guest, Sandbox), Failure> {
    launch_as(plan, parent, 3, false)
}

/// `launch` with a CID of its own and `cpu_overcommit` (several at once).
fn launch_as(plan: &Plan<'_>, parent: &Parent, cid: u32, cpu_overcommit: bool) -> Result<(Guest, Sandbox), Failure> {
    std::fs::create_dir_all(SCRATCH_ROOT).map_err(|e| fail(SCRATCH_ROOT, e))?;
    let scratch_path = PathBuf::from(SCRATCH_ROOT).join(format!("{}.img", plan.dir.file_name().and_then(|n| n.to_str()).unwrap_or("computer")));
    scratch(&scratch_path, plan.scratch_gib)?;
    let sandbox = Sandbox {
        boot: Boot::Kernel { kernel: plan.kernel.into(), initrd: Some(plan.initrd.into()), cmdline: plan.image.cmdline(plan.kms_key) },
        vcpus: plan.vcpus,
        memory_mib: plan.memory_mib,
        drives: vec![
            Drive { id: "tree".into(), path: plan.image.tree.clone(), read_only: true, dmb_mib: None },
            Drive { id: "image".into(), path: plan.image.image.clone(), read_only: true, dmb_mib: None },
            Drive { id: "scratch".into(), path: scratch_path, read_only: false, dmb_mib: None },
        ],
        nics: if plan.net { vec![Nic { id: "eth0".into(), tap: TAP.into(), dmb_mib: None }] } else { vec![] },
        vsock: Vsock { guest_cid: cid, uds_path: plan.dir.join("v.sock"), dmb_mib: None },
        enclave: Enclave { mode: Mode::Confidential, cpu_overcommit, hotplug: false, debug: false, cpu_accounting: false },
    };
    let mut env = plan.image.env.clone();
    env.extend(plan.env.iter().cloned());
    let net = plan.net.then(|| GuestNet { address: crate::net::GUEST_ADDR.into(), gateway: crate::net::HOST_ADDR.into(), dns: crate::net::HOST_ADDR.into(), mtu: crate::net::MTU });
    let start = Start::Run {
        entrypoint: Proc { argv: plan.entrypoint.clone(), env, cwd: Some("/".into()), user: None },
        hostname: "nitro".into(),
        data: false,
        data_path: None,
        ca_pem: plan.ca_pem.clone(),
        net,
    };
    let g = guest::launch(&sandbox, parent, &plan.dir, &start)?;
    Ok((g, sandbox))
}

/// An exec as the image's environment has it: its stdout, stderr, code
/// and the round trip in ms.
pub fn sh(g: &Guest, env: &[String], script: &str, stdin: Option<&[u8]>) -> Result<(String, String, Option<i32>, f64), Failure> {
    vm_sh(&g.vm, env, script, stdin)
}

/// `sh`, through a guest's agent client alone (shareable across threads).
pub fn vm_sh(vm: &sandcastle_vm::client::Vm, env: &[String], script: &str, stdin: Option<&[u8]>) -> Result<(String, String, Option<i32>, f64), Failure> {
    let t = Instant::now();
    let p = Proc { argv: vec!["/bin/sh".into(), "-c".into(), script.into()], env: env.to_vec(), cwd: Some("/".into()), user: None };
    let out = vm.exec(p, stdin).map_err(|e| fail("exec", e))?;
    Ok((String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned(), out.code, ms(t.elapsed())))
}

fn stats(samples: &[f64]) -> Value {
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    let n = s.len();
    let median = if n % 2 == 1 { s[n / 2] } else { (s[n / 2 - 1] + s[n / 2]) / 2.0 };
    json!({"n": n, "median": (median * 10.0).round() / 10.0, "min": s[0], "max": s[n - 1]})
}

fn base_plan<'a>(args: &'a [String], image: &'a Image, name: &str) -> Result<Plan<'a>, Failure> {
    Ok(Plan {
        image,
        kernel: flag(args, "--kernel").ok_or_else(|| Failure("--kernel".into()))?,
        initrd: flag(args, "--initrd").ok_or_else(|| Failure("--initrd".into()))?,
        dir: PathBuf::from(RUN_ROOT).join(name),
        scratch_gib: flag(args, "--scratch-gib").and_then(|v| v.parse().ok()).unwrap_or(16),
        vcpus: flag(args, "--vcpus").and_then(|v| v.parse().ok()).unwrap_or(2),
        memory_mib: flag(args, "--mem-mib").and_then(|v| v.parse().ok()).unwrap_or(4096),
        net: false,
        kms_key: flag(args, "--kms-key"),
        entrypoint: vec!["/opt/nitro/entrypoint.sh".into()],
        env: vec!["NITRO_FPAC=off".into()],
        ca_pem: None,
    })
}

/// The block of `path` in an ext4 image, by debugfs: its byte offset.
fn block_offset(image: &Path, path: &str) -> Result<u64, Failure> {
    let out = Process::new("debugfs").args(["-R", &format!("bmap {path} 0")]).arg(image).output().map_err(|e| fail("debugfs", e))?;
    let block: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().map_err(|_| Failure(format!("debugfs: {}", String::from_utf8_lossy(&out.stderr))))?;
    assert!(block > 0);
    Ok(block * 4096)
}

fn flip(image: &Path, offset: u64) -> Result<u8, Failure> {
    use std::os::unix::fs::FileExt;
    let f = std::fs::OpenOptions::new().read(true).write(true).open(image).map_err(|e| fail("the image", e))?;
    let mut b = [0u8; 1];
    f.read_exact_at(&mut b, offset).map_err(|e| fail("the image", e))?;
    let was = b[0];
    f.write_all_at(&[was ^ 0x01], offset).map_err(|e| fail("the image", e))?;
    f.sync_all().map_err(|e| fail("the image", e))?;
    Ok(was)
}

fn put_back(image: &Path, offset: u64, was: u8) -> Result<(), Failure> {
    use std::os::unix::fs::FileExt;
    let f = std::fs::OpenOptions::new().write(true).open(image).map_err(|e| fail("the image", e))?;
    f.write_all_at(&[was], offset).map_err(|e| fail("the image", e))?;
    f.sync_all().map_err(|e| fail("the image", e))
}

/// Acceptance 6: sandcastle's agent in the sandbox (exec, stdin, exit
/// code), the root under dm-verity, and a changed byte refused.
pub fn agent(args: &[String]) -> Result<Value, Failure> {
    let image = Image::load(args)?;
    let p = parent();
    let plan = base_plan(args, &image, "computer")?;
    let (g, _) = launch(&plan, &p)?;
    let env = &image.env;
    // The entrypoint's first act is the clock; the samples come after it,
    // so they time the agent, not a guest still starting.
    let (time_set_ms, time_lines) = g.wait_line("nitro: time", Duration::from_secs(30))?;
    let mut round = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        let out = g.vm.exec(Proc { argv: vec!["/bin/true".into()], env: env.clone(), cwd: None, user: None }, None).map_err(|e| fail("exec", e))?;
        round.push(ms(t.elapsed()));
        assert_eq!(out.code, Some(0));
    }
    let said = b"through the agent, over vsock, into the sandbox\n";
    let echoed = sh(&g, env, "cat", Some(said))?;
    let code = sh(&g, env, "echo out; echo err >&2; exit 7", None)?;
    let cmdline = sh(&g, env, "cat /proc/cmdline", None)?.0;
    let dm = sh(&g, env, "cat /sys/block/dm-0/dm/name /sys/block/dm-0/ro; ls /sys/block/dm-0/slaves", None)?.0;
    let nonce = random_hex(32);
    let attest = sh(&g, env, &format!("/opt/nitro/nitro-key attest --nonce {nonce}"), None)?;
    let doc = hex::decode(attest.0.trim()).map_err(|e| fail("the document", e))?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("after 1970").as_millis() as u64;
    let a = verify(&Trust::aws_nitro_enclaves_root_g1(), &doc, &hex::decode(&nonce).expect("hex"), now).map_err(|e| fail("the document", e))?;
    let pcr = |i: u8| a.pcr(i).map(hex::encode);
    let (hello_ms, ready_ms, guest_ready) = (g.hello_ms, g.ready_ms, g.guest_ready_uptime_ms);
    let stop_ms = g.stop()?;
    // A changed byte: one bit of a file's first block, flipped in the
    // image on the parent, the verity table and root hash unchanged.
    let target = "/opt/nitro/corrupt-me";
    let offset = block_offset(&image.image, target)?;
    let was = flip(&image.image, offset)?;
    let corrupted = (|| {
        let mut plan = base_plan(args, &image, "computer-corrupt")?;
        plan.env = vec!["NITRO_FPAC=off".into()];
        let (g, _) = launch(&plan, &p)?;
        let read = sh(&g, env, &format!("head -c 64 {target}; echo; echo code $?"), None)?;
        let kernel = sh(&g, env, "dmesg | grep -i verity | tail -3", None)?.0;
        let intact = sh(&g, env, "head -c 40 /opt/nitro/entrypoint.sh", None)?.0;
        g.stop()?;
        Ok::<Value, Failure>(json!({"read": read.0, "stderr": read.1, "kernel": kernel, "another_file_reads": intact}))
    })();
    put_back(&image.image, offset, was)?;
    Ok(json!({
        "scenario": "agent",
        "what": "sandcastle-guest as init; Hermes' image (upstream, arm64) as a raw disk under dm-verity; spawn to the guest's hello and ready; exec through sandcastle-vm's own client over vsock",
        "hello_ms": hello_ms, "ready_ms": ready_ms, "guest_uptime_at_ready_ms": guest_ready,
        "clock_from_the_nsm_at_ms": time_set_ms, "clock_line": time_lines.last(),
        "exec_true_round_trip_ms": stats(&round),
        "stdin_echoed": echoed.0 == String::from_utf8_lossy(said),
        "exit_code": code.2, "exit_stdout": code.0, "exit_stderr": code.1,
        "cmdline": cmdline.trim(),
        "verity_device": dm,
        "pcr0": pcr(0), "pcr1": pcr(1), "pcr2": pcr(2),
        "stop_ms": stop_ms,
        "changed_byte": {"file": target, "image_offset": offset, "result": corrupted.map_err(|e| e.0).unwrap_or_else(|e| json!({"error": e}))},
    }))
}

fn policy(intercepts: Vec<Intercept>) -> Policy {
    Policy { internet: false, allow: vec![KMS_HOST.into()], deny: vec![], intercept: intercepts }
}

fn intercepts() -> Vec<Intercept> {
    vec![
        Intercept { scheme: Scheme::Https, target: "handled.example.com".into(), action: Action::Handler },
        Intercept { scheme: Scheme::Http, target: FPAC_HOST.into(), action: Action::Handler },
        Intercept { scheme: Scheme::Http, target: MODEL_HOST.into(), action: Action::Handler },
    ]
}

/// Acceptance 7: the guest reaches out only through the tap to
/// sandcastle's egress on the parent.
pub fn network(args: &[String]) -> Result<Value, Failure> {
    let image = Image::load(args)?;
    let p = parent();
    let svc = Services::start(&PathBuf::from(RUN_ROOT).join("services"), &policy(intercepts()), None)?;
    crate::net::up(TAP)?;
    let mut plan = base_plan(args, &image, "computer-net")?;
    plan.net = true;
    plan.ca_pem = Some(svc.ca_pem.clone());
    let r = (|| {
        let (g, _) = launch(&plan, &p)?;
        let env = &image.env;
        let handled = sh(&g, env, &format!("curl -sS -m 10 --cacert {CA_IN_GUEST} https://handled.example.com/through/the/proxy 2>&1; ls -la {CA_IN_GUEST}"), None)?;
        let other = sh(&g, env, "getent hosts example.org; echo code $?", None)?;
        let by_ip = sh(&g, env, "curl -s -m 5 -o /dev/null -w '%{http_code} %{errormsg}' http://1.1.1.1/; echo; echo code $?", None)?;
        let imds = sh(&g, env, "curl -s -m 5 -o /dev/null -w '%{http_code} %{errormsg}' http://169.254.169.254/latest/meta-data/; echo; echo code $?", None)?;
        let parent_ssh = sh(&g, env, &format!("curl -s -m 5 -o /dev/null -w '%{{http_code}} %{{errormsg}}' telnet://{}:22; echo; echo code $?", crate::net::HOST_ADDR), None)?;
        let kms = sh(&g, env, &format!("getent hosts {KMS_HOST}; echo code $?"), None)?;
        let model = sh(&g, env, &format!("curl -s -m 10 http://{MODEL_HOST}/v1/models"), None)?;
        g.stop()?;
        Ok::<Value, Failure>(json!({
            "intercepted_https_answered_by_the_handler": handled.0.contains(STAND_IN), "handled": handled.0,
            "internet_off_other_name": other.0, "internet_off_by_address": by_ip.0,
            "imds": imds.0, "the_parents_own_ssh": parent_ssh.0,
            "kms_allowed_name": kms.0, "plain_http_intercept": model.0,
            "proxy_decisions": svc.egress.decisions(),
        }))
    })();
    crate::net::down(TAP);
    let mut v = r?;
    v["scenario"] = json!("network");
    v["policy"] = json!({"internet": false, "allow": [KMS_HOST], "intercept": ["https handled.example.com", "http fpac.fragment.internal", "http model.example.com"]});
    v["leak_1"] = json!("the proxy on the parent terminates the intercepted TLS with its own CA and reads every intercepted request in plaintext (the handler's answer above echoes its path); a spliced host (KMS here) it carries as bytes it cannot read");
    Ok(v)
}

/// FPAC's folder remote for one life, run as `fpac-bench serve-folder`.
struct Folder {
    child: Child,
}

impl Folder {
    fn start(args: &[String], store: &Path, disk: &str) -> Result<Folder, Failure> {
        let bench = flag(args, "--fpac-bench").ok_or_else(|| Failure("--fpac-bench".into()))?;
        let socket = PathBuf::from(RUN_ROOT).join(format!("folder-{disk}.sock"));
        std::fs::create_dir_all(store).map_err(|e| fail("the store", e))?;
        let mut c = Process::new(bench);
        c.arg("serve-folder").arg("--root").arg(store).args(["--disk", disk, "--listen"]).arg(&socket).arg("--head-file").arg(store.join(format!("{disk}.head")));
        for (f, name) in [("--object-ms", "--object-ms"), ("--put-bytes-per-s", "--put-bytes-per-s"), ("--volume-gb", "--volume-gb")] {
            if let Some(v) = flag(args, f) {
                c.args([name, v]);
            }
        }
        let mut child = c.stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().map_err(|e| fail("serve-folder", e))?;
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(child.stdout.take().expect("piped")), &mut line).map_err(|e| fail("serve-folder", e))?;
        if !line.contains("serving") {
            let _ = child.kill();
            return Err(Failure(format!("serve-folder: {line}")));
        }
        Ok(Folder { child })
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        // The head is written within 50 ms of moving; a sleep's last post
        // came before the guest said it had slept.
        std::thread::sleep(Duration::from_millis(200));
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Counts `needle` in every file under `dir` (the store) or in one file.
/// How often `needle` appears in the files under `path`, read in chunks
/// (a scratch image is 24 GiB, sparse: its holes are skipped, its data
/// streamed). Any error fails the count: a scan that cannot read is not
/// a zero.
fn count_in(path: &Path, needle: &[u8]) -> Result<u64, Failure> {
    let mut n = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            for e in std::fs::read_dir(&p).map_err(|e| fail(&p.display().to_string(), e))? {
                stack.push(e.map_err(|e| fail(&p.display().to_string(), e))?.path());
            }
        } else {
            n += count_in_file(&p, needle).map_err(|e| fail(&p.display().to_string(), e))?;
        }
    }
    Ok(n)
}

const SCAN_CHUNK_BYTES: usize = 8 << 20;

fn count_in_file(path: &Path, needle: &[u8]) -> std::io::Result<u64> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::AsRawFd;
    assert!(!needle.is_empty() && needle.len() < SCAN_CHUNK_BYTES);
    let mut f = std::fs::File::open(path)?;
    let finder = memchr::memmem::Finder::new(needle);
    let mut n = 0u64;
    let mut buf = vec![0u8; needle.len() - 1 + SCAN_CHUNK_BYTES];
    let mut pos: i64 = 0;
    loop {
        // SAFETY: lseek on an open descriptor; ENXIO means no data past pos.
        let data = unsafe { libc::lseek(f.as_raw_fd(), pos, libc::SEEK_DATA) };
        if data < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENXIO) {
                return Ok(n);
            }
            return Err(e);
        }
        // SAFETY: as above; a data offset always has a hole after it (EOF).
        let hole = unsafe { libc::lseek(f.as_raw_fd(), data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(std::io::Error::last_os_error());
        }
        f.seek(SeekFrom::Start(data as u64))?;
        // A run of data, in chunks; each chunk searched behind the last
        // needle-less-one bytes of the one before (no match is shorter).
        let mut left = (hole - data) as usize;
        let mut carry = 0;
        while left > 0 {
            let want = left.min(SCAN_CHUNK_BYTES);
            f.read_exact(&mut buf[carry..carry + want])?;
            let have = carry + want;
            n += finder.find_iter(&buf[..have]).count() as u64;
            carry = (needle.len() - 1).min(have);
            buf.copy_within(have - carry..have, 0);
            left -= want;
        }
        pos = hole;
    }
}

fn fpac_log(g: &Guest, env: &[String]) -> String {
    sh(g, env, "cat /run/fpac/log", None).map(|r| r.0).unwrap_or_default()
}

/// FPAC's sleep: SIGTERM to the daemon, then its last flush, timed.
fn sleep_disk(g: &Guest, env: &[String]) -> Result<f64, Failure> {
    sh(g, env, "kill -TERM $(cat /proc/[0-9]*/stat 2>/dev/null | awk '$2==\"(fpac)\" {print $1}')", None)?;
    let t = Instant::now();
    // Bounded: 600 s, a big disk's last flush.
    while t.elapsed() < Duration::from_secs(600) {
        if fpac_log(g, env).contains("\"fpac\":\"exit\"") {
            return Ok(ms(t.elapsed()));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(Failure(format!("no exit in 600 s: {}", fpac_log(g, env))))
}

/// Acceptance 8 and 9: lives of one sealed disk. The first makes the key
/// (GenerateDataKey) and fills the disk; each later one wakes it (Decrypt
/// of the wrapped key the parent kept) and asks Hermes once.
pub fn lives(args: &[String]) -> Result<Value, Failure> {
    let image = Image::load(args)?;
    let p = parent();
    let lives: usize = flag(args, "--lives").and_then(|v| v.parse().ok()).unwrap_or(3);
    let fill_gb: u64 = flag(args, "--fill-gb").and_then(|v| v.parse().ok()).unwrap_or(1);
    let disk = flag(args, "--disk").unwrap_or("hermes");
    let store = PathBuf::from(flag(args, "--store").ok_or_else(|| Failure("--store".into()))?);
    let mut rules = intercepts();
    if flag(args, "--intercept-kms") == Some("true") {
        // The parent trying to read or change the key: its proxy ends the
        // guest's TLS to KMS with its own CA, as it does for any host it
        // intercepts.
        rules.push(Intercept { scheme: Scheme::Https, target: KMS_HOST.into(), action: Action::Handler });
    }
    let svc = Services::start(&PathBuf::from(RUN_ROOT).join("services"), &policy(rules), Some(PathBuf::from(RUN_ROOT).join(format!("folder-{disk}.sock"))))?;
    crate::net::up(TAP)?;
    let canary = format!("NITRO-SPIKE-DISK-CANARY-{}", random_hex(8));
    let wrapped_file = store.join(format!("{disk}.wrapped"));
    let mut out = Vec::new();
    let r = (|| {
        for life in 0..lives {
            let folder = Folder::start(args, &store, disk)?;
            let mut plan = base_plan(args, &image, &format!("life-{life}"))?;
            plan.net = true;
            plan.ca_pem = Some(svc.ca_pem.clone());
            plan.env = match std::fs::read_to_string(&wrapped_file) {
                Ok(w) => vec![format!("NITRO_WRAPPED={}", w.trim())],
                Err(_) => vec![],
            };
            if flag(args, "--plain") == Some("true") {
                // The control: the same disk unsealed, no key at all.
                plan.env = vec!["NITRO_PLAIN=1".into()];
            }
            let (g, sandbox) = launch(&plan, &p)?;
            svc.signer(&sandbox.vsock.uds_path)?;
            let env = &image.env;
            let (key_ms, key_lines) = g.wait_line("nitro: key", Duration::from_secs(120))?;
            let key: Value = key_lines.last().and_then(|l| l.split_once("nitro: key ")).and_then(|(_, j)| serde_json::from_str(j).ok()).unwrap_or(Value::Null);
            if let Some(w) = key["wrapped"].as_str() {
                std::fs::write(&wrapped_file, w).map_err(|e| fail("the wrapped key", e))?;
            }
            let (mounted_ms, _) = g.wait_line("nitro: mounted", Duration::from_secs(600))?;
            let mut life_v = json!({"life": life, "hello_ms": g.hello_ms, "ready_ms": g.ready_ms, "key_ms": key_ms, "mounted_ms": mounted_ms, "key": key});
            if life == 0 {
                let t = Instant::now();
                let fill = sh(&g, env, &format!("cd /opt/data && printf '%s\\n' {canary} {canary} {canary} > canary.txt && dd if=/dev/urandom of=fill bs=4M count={} status=none && sync && echo filled", fill_gb * 256), None)?;
                life_v["fill_s"] = json!(t.elapsed().as_secs_f64());
                if fill.0.trim() != "filled" {
                    return Err(Failure(format!("life {life}: the fill failed (code {:?}): {}; FPAC: {}", fill.2, fill.1.trim(), fpac_log(&g, env).lines().rev().take(3).collect::<Vec<_>>().join(" | "))));
                }
                // Let the cut ship: FPAC flushes about a second after a
                // write; the backlog of the fill drains behind it.
                let t = Instant::now();
                sh(&g, env, "sleep 3", None)?;
                life_v["settle_s"] = json!(t.elapsed().as_secs_f64());
            }
            // Hermes' model is the stand-in, configured once on a new disk
            // (its config is in its home, so every later life has it).
            let mut env = env.clone();
            env.push("OPENAI_API_KEY=sk-stand-in".into());
            let env = &env;
            if life == 0 {
                let t = Instant::now();
                sh(&g, env, &format!("cd /opt/data && hermes config set model.provider custom && hermes config set model.base_url http://{MODEL_HOST}/v1 && hermes config set model.default stand-in && hermes config set model.api_key sk-stand-in"), None)?;
                life_v["hermes_configured_s"] = json!(t.elapsed().as_secs_f64());
            }
            let reply_t = Instant::now();
            let reply = sh(&g, env, "cd /opt/data && hermes chat -Q -q 'Say hello.' 2>&1 | tail -5", None)?;
            let reply_exec_ms = ms(reply_t.elapsed());
            life_v["hermes_reply_at_ms"] = json!(g.since_spawn_ms());
            life_v["hermes_reply_exec_ms"] = json!(reply_exec_ms);
            life_v["hermes_replied"] = json!(reply.0.contains(MODEL_REPLY));
            life_v["hermes_output"] = json!(reply.0.chars().rev().take(400).collect::<String>().chars().rev().collect::<String>());
            life_v["canary_read_back"] = json!(sh(&g, env, "head -1 /opt/data/canary.txt", None)?.0.trim() == canary);
            life_v["sleep_ms"] = json!(sleep_disk(&g, env)?);
            life_v["fpac_events"] = json!(fpac_log(&g, env).lines().filter(|l| l.contains("\"mounted\"") || l.contains("\"exit\"") || l.contains("\"opened\"")).map(str::to_string).collect::<Vec<_>>());
            let scratch_img = sandbox.drives[2].path.clone();
            g.stop()?;
            drop(folder);
            // What the parent holds of the disk: the store's objects and
            // the guest's scratch disk (FPAC's cache file is on it).
            life_v["canary_in_the_store"] = json!(count_in(&store, canary.as_bytes())?);
            life_v["canary_on_the_scratch_disk"] = json!(count_in(&scratch_img, canary.as_bytes())?);
            // A life's scratch disk dies with it (a wake starts empty).
            std::fs::remove_file(&scratch_img).map_err(|e| fail("the scratch disk", e))?;
            out.push(life_v);
        }
        Ok::<(), Failure>(())
    })();
    crate::net::down(TAP);
    r?;
    let signed = svc.signed.lock().expect("never poisoned").clone();
    Ok(json!({
        "scenario": "lives",
        "disk": disk, "fill_gb": fill_gb,
        "store": "FPAC's folder remote on the parent (a STAND-IN for the platform's route and its store)",
        "folder_object_ms": flag(args, "--object-ms"), "folder_put_bytes_per_s": flag(args, "--put-bytes-per-s"),
        "lives": out,
        "what_the_parent_signed": signed,
        "canary_needle": "the canary's text itself, counted in every file of the store and in the scratch disk's image",
        "plain": flag(args, "--plain") == Some("true"),
    }))
}

/// FPAC's conformance suite from inside the sandbox, against the folder
/// remote through sandcastle's egress, on a disk of its own.
pub fn conformance(args: &[String]) -> Result<Value, Failure> {
    let image = Image::load(args)?;
    let p = parent();
    let disk = format!("conformance-{}", random_hex(4));
    let store = PathBuf::from(flag(args, "--store").ok_or_else(|| Failure("--store".into()))?);
    let svc = Services::start(&PathBuf::from(RUN_ROOT).join("services"), &policy(intercepts()), Some(PathBuf::from(RUN_ROOT).join(format!("folder-{disk}.sock"))))?;
    crate::net::up(TAP)?;
    let r = (|| {
        let _folder = Folder::start(args, &store, &disk)?;
        let mut plan = base_plan(args, &image, "conformance")?;
        plan.net = true;
        let (g, _) = launch(&plan, &p)?;
        let suite = sh(&g, &image.env, "/opt/nitro/fpac-probe conformance", None)?;
        g.stop()?;
        Ok::<Value, Failure>(serde_json::from_str(suite.0.trim()).unwrap_or_else(|_| json!({"raw": suite.0, "stderr": suite.1})))
    })();
    crate::net::down(TAP);
    let _ = svc;
    Ok(json!({"scenario": "conformance", "suite": r?}))
}

/// The line-5 flow's weakness, shown: a probe guest attests with a key,
/// the parent seals a value of its own choosing to the document's public
/// key (OpenSSL, as anyone could), and the guest opens it as it would
/// KMS's. `--probe-initrd` is line 5's probe.
pub fn forged(args: &[String]) -> Result<Value, Failure> {
    use sandcastle_nitro_probe::protocol::{Answer, Command};
    let p = parent();
    let kernel = flag(args, "--kernel").ok_or_else(|| Failure("--kernel".into()))?;
    let initrd = flag(args, "--probe-initrd").ok_or_else(|| Failure("--probe-initrd".into()))?;
    let dir = PathBuf::from(RUN_ROOT).join("forged");
    let s = Sandbox {
        boot: Boot::Kernel { kernel: kernel.into(), initrd: Some(initrd.into()), cmdline: "panic=1 initcall_blacklist=i8042_init quiet".into() },
        vcpus: 2,
        memory_mib: 512,
        drives: vec![],
        nics: vec![],
        vsock: Vsock { guest_cid: 3, uds_path: dir.join("v.sock"), dmb_mib: None },
        enclave: Enclave { mode: Mode::Confidential, cpu_overcommit: false, hotplug: false, debug: false, cpu_accounting: false },
    };
    let mut session = crate::run::launch(&s, &p, &dir)?;
    let nonce = random_hex(32);
    let Answer::Attested { document_hex, .. } = session.ask(&Command::Attest { nonce_hex: nonce.clone(), with_key: true })? else {
        return Err(Failure("no attestation".into()));
    };
    // The public key the document carries, as anyone reading it can.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("after 1970").as_millis() as u64;
    let doc = hex::decode(&document_hex).expect("hex");
    let a = verify(&Trust::aws_nitro_enclaves_root_g1(), &doc, &hex::decode(&nonce).expect("hex"), now).map_err(|e| fail("the document", e))?;
    let public = a.public_key.ok_or_else(|| Failure("the document carries no public key".into()))?;
    let work = dir.join("forge");
    std::fs::create_dir_all(&work).map_err(|e| fail("forge", e))?;
    let chosen = random_hex(32);
    std::fs::write(work.join("chosen.bin"), hex::decode(&chosen).expect("hex")).map_err(|e| fail("forge", e))?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&public);
    let pem: String = b64.as_bytes().chunks(64).map(|c| format!("{}\n", std::str::from_utf8(c).expect("base64"))).collect();
    std::fs::write(work.join("guest.pub"), format!("-----BEGIN PUBLIC KEY-----\n{pem}-----END PUBLIC KEY-----\n")).map_err(|e| fail("forge", e))?;
    let script = "set -e; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out signer.pem 2>/dev/null; \
        openssl req -new -x509 -key signer.pem -subj /CN=forged -days 1 -out signer.crt; \
        openssl x509 -new -subj /CN=forged-recipient -force_pubkey guest.pub -CA signer.crt -CAkey signer.pem -days 1 -out recipient.crt; \
        openssl cms -encrypt -binary -aes256 -in chosen.bin -recip recipient.crt -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256 -keyopt rsa_mgf1_md:sha256 -outform DER -out forged.cms";
    let out = Process::new("sh").args(["-c", script]).current_dir(&work).output().map_err(|e| fail("openssl", e))?;
    if !out.status.success() {
        return Err(Failure(format!("openssl: {}", String::from_utf8_lossy(&out.stderr))));
    }
    let cms = std::fs::read(work.join("forged.cms")).map_err(|e| fail("forge", e))?;
    let opened = session.ask(&Command::Open { cms_hex: hex::encode(&cms) })?;
    session.stop()?;
    let chosen_sha = hex::encode(sandcastle_nitro_attest::sha256(&hex::decode(&chosen).expect("hex")));
    let accepted = matches!(&opened, Answer::Opened { plaintext_sha256, .. } if *plaintext_sha256 == chosen_sha);
    Ok(json!({
        "scenario": "forged",
        "what": "line 5's flow: the parent relays KMS's envelope to the guest. Here the parent never calls KMS: it seals a value it chose to the public key in the guest's own document",
        "the_guest_opened_the_parents_value": accepted,
        "opened": opened,
        "chosen_sha256": chosen_sha,
    }))
}

/// A computer held up for a look (debugging the spike's own runs): the
/// network, the services and FPAC's folder remote if `--store` is given,
/// until the driver is killed. `exec --dir <run dir> -- <argv>` reaches it.
pub fn hold(args: &[String]) -> Result<Value, Failure> {
    let image = Image::load(args)?;
    let p = parent();
    let disk = flag(args, "--disk").unwrap_or("held");
    let folder_sock = PathBuf::from(RUN_ROOT).join(format!("folder-{disk}.sock"));
    let svc = Services::start(&PathBuf::from(RUN_ROOT).join("services"), &policy(intercepts()), Some(folder_sock))?;
    crate::net::up(TAP)?;
    let _folder = match flag(args, "--store") {
        Some(st) => Some(Folder::start(args, Path::new(st), disk)?),
        None => None,
    };
    let mut plan = base_plan(args, &image, "held")?;
    plan.net = true;
    plan.ca_pem = Some(svc.ca_pem.clone());
    plan.env = args.windows(2).filter(|w| w[0] == "--env").map(|w| w[1].clone()).collect();
    if flag(args, "--hermes-gateway") == Some("true") {
        // Hermes as its image runs it: s6 and its gateway, behind the
        // spike's entrypoint (the clock, FPAC's disk at its home).
        plan.entrypoint.extend(["/opt/hermes/docker/entrypoint-dispatch.sh".into(), "gateway".into(), "run".into()]);
    }
    let (g, sandbox) = launch(&plan, &p)?;
    svc.signer(&sandbox.vsock.uds_path)?;
    println!("held {} (ready at {:.0} ms)", g.dir.display(), g.ready_ms);
    // Bounded by the operator: it holds until killed.
    loop {
        match g.said.recv_timeout(Duration::from_secs(3600)) {
            Ok(guest::Said::Line { text, .. }) => println!("guest: {text}"),
            Ok(other) => {
                println!("guest: {other:?}");
                break;
            }
            Err(_) => {}
        }
    }
    crate::net::down(TAP);
    Ok(json!({"held": "ended"}))
}

/// One exec in a held computer.
pub fn exec(args: &[String]) -> Result<Value, Failure> {
    let dir = flag(args, "--dir").ok_or_else(|| Failure("--dir".into()))?;
    let at = args.iter().position(|a| a == "--").ok_or_else(|| Failure("-- <argv>".into()))?;
    let env: Vec<String> = args.windows(2).filter(|w| w[0] == "--env").map(|w| w[1].clone()).collect();
    let vm = sandcastle_vm::client::Vm::new(dir);
    let out = vm.exec(Proc { argv: args[at + 1..].to_vec(), env, cwd: Some("/".into()), user: None }, None).map_err(|e| fail("exec", e))?;
    Ok(json!({"code": out.code, "stdout": String::from_utf8_lossy(&out.stdout), "stderr": String::from_utf8_lossy(&out.stderr)}))
}

/// Acceptance 10, the pool: sandboxes of `--mem-mib` launched one after
/// another and kept, until a launch is refused; the pool's use after each.
pub fn density(args: &[String]) -> Result<Value, Failure> {
    let p = parent();
    let kernel = flag(args, "--kernel").ok_or_else(|| Failure("--kernel".into()))?;
    let initrd = flag(args, "--probe-initrd").ok_or_else(|| Failure("--probe-initrd".into()))?;
    let mem: u32 = flag(args, "--mem-mib").and_then(|v| v.parse().ok()).unwrap_or(3072);
    let max: usize = flag(args, "--max").and_then(|v| v.parse().ok()).unwrap_or(8);
    // A computer's devices besides its vsock: Hermes' has three disks and
    // a NIC; each is a device with a DMB of its own in confidential mode.
    let drives: usize = flag(args, "--drives").and_then(|v| v.parse().ok()).unwrap_or(0);
    let cpu_overcommit = flag(args, "--overcommit") != Some("false");
    assert!(drives <= 8, "--drives: at most 8");
    std::fs::create_dir_all(SCRATCH_ROOT).map_err(|e| fail(SCRATCH_ROOT, e))?;
    let mut drive_files = Vec::new();
    for d in 0..drives {
        let path = PathBuf::from(SCRATCH_ROOT).join(format!("density-drive-{d}.img"));
        std::fs::File::create(&path).and_then(|f| f.set_len(1 << 20)).map_err(|e| fail("a density drive", e))?;
        drive_files.push(path);
    }
    let read = |f: &str| std::fs::read_to_string(format!("/sys/class/misc/nitro_enclaves/{f}")).map(|s| s.trim().to_string()).unwrap_or_default();
    let before = read("mem_pool/in_use");
    let mut held = Vec::new();
    let mut rows = Vec::new();
    let mut refused = None;
    for i in 0..max {
        let dir = PathBuf::from(RUN_ROOT).join(format!("density-{i}"));
        let s = Sandbox {
            boot: Boot::Kernel { kernel: kernel.into(), initrd: Some(initrd.into()), cmdline: "panic=1 initcall_blacklist=i8042_init quiet".into() },
            vcpus: 2,
            memory_mib: mem,
            drives: drive_files.iter().enumerate().map(|(d, path)| Drive { id: format!("d{d}"), path: path.clone(), read_only: true, dmb_mib: None }).collect(),
            nics: vec![],
            vsock: Vsock { guest_cid: 3 + i as u32, uds_path: dir.join("v.sock"), dmb_mib: None },
            enclave: Enclave { mode: Mode::Confidential, cpu_overcommit, hotplug: false, debug: false, cpu_accounting: false },
        };
        match crate::run::launch(&s, &p, &dir) {
            Ok(session) => {
                rows.push(json!({"sandbox": i + 1, "launch_ms": session.hello_ms, "pool_in_use_bytes": read("mem_pool/in_use"), "pool_free_bytes": read("mem_pool/free"), "slots_in_use": read("pcie_slots_in_use"), "expected_pool_mib": s.pool_mib()}));
                held.push(session);
            }
            Err(e) => {
                // Firecracker's own reason: its "Enclave VM error" line.
                let reason = e.0.lines().find(|l| l.contains("Enclave VM error")).or_else(|| e.0.lines().rev().find(|l| l.contains("error"))).unwrap_or(&e.0);
                refused = Some(json!({"sandbox": i + 1, "error": reason.to_string()}));
                break;
            }
        }
    }
    for s in held {
        let _ = s.stop();
    }
    Ok(json!({"scenario": "density", "memory_mib": mem, "vcpus_each": 2, "drives_each": drives, "cpu_overcommit": cpu_overcommit, "cpu_pool": read("cpu_pool/total"), "pool_total_bytes": read("mem_pool/total"), "pool_in_use_before_bytes": before, "slots": read("pcie_slots"), "launched": rows, "refused": refused}))
}

/// Acceptance 10, CPU: `--guests` computers with `cpu_overcommit`, each
/// running `--loops` busy loops for 5 s at once; each loop's iterations.
pub fn busy(args: &[String]) -> Result<Value, Failure> {
    let image = Image::load(args)?;
    let p = parent();
    let guests: usize = flag(args, "--guests").and_then(|v| v.parse().ok()).unwrap_or(1);
    let loops: usize = flag(args, "--loops").and_then(|v| v.parse().ok()).unwrap_or(2);
    let mut held = Vec::new();
    for i in 0..guests {
        let mut plan = base_plan(args, &image, &format!("busy-{i}"))?;
        plan.memory_mib = 1024;
        plan.scratch_gib = 2;
        let mut sandbox_plan = plan;
        sandbox_plan.env = vec!["NITRO_FPAC=off".into()];
        let (g, _) = launch_as(&sandbox_plan, &p, 3 + i as u32, true)?;
        g.wait_line("nitro: time", Duration::from_secs(30))?;
        held.push(g);
    }
    // One write a line: the image sets PYTHONUNBUFFERED, so a print's
    // number and its newline go out apart and two loops interleave.
    let script = format!("for i in $(seq {loops}); do python3 -c 'import os,time\nt=time.time()\nn=0\nwhile time.time()-t<5: n+=1\nos.write(1, b\"%d\\n\" % n)' & done; wait");
    let results: Vec<Result<String, Failure>> = std::thread::scope(|scope| {
        let handles: Vec<_> = held.iter().map(|g| { let (script, env, vm) = (script.clone(), image.env.clone(), &g.vm); scope.spawn(move || vm_sh(vm, &env, &script, None).map(|r| r.0)) }).collect();
        handles.into_iter().map(|h| h.join().expect("a thread")).collect()
    });
    for g in held {
        let _ = g.stop();
    }
    let mut per_loop = Vec::new();
    for r in results {
        let out = r?;
        for l in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
            per_loop.push(l.parse::<u64>().map_err(|e| Failure(format!("a busy loop's count {l:?}: {e}")))?);
        }
    }
    if per_loop.len() != guests * loops {
        return Err(Failure(format!("{} of {} busy loops answered", per_loop.len(), guests * loops)));
    }
    let total: u64 = per_loop.iter().sum();
    Ok(json!({"scenario": "busy", "guests": guests, "loops_per_guest": loops, "vcpus_per_guest": 2, "parent_vcpus": p.vcpus, "iterations_per_loop": per_loop, "iterations_total": total}))
}

#[cfg(test)]
mod count_tests {
    use super::count_in_file;

    // Goal: the scan finds every copy, across a chunk's edge and after a
    // hole, and never counts one twice. Method: a sparse file with the
    // needle at its start, astride the first chunk's edge, and 1 GiB in.
    #[test]
    fn the_scan_counts_across_chunks_and_holes() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = std::env::temp_dir().join(format!("count-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sparse.img");
        let mut f = std::fs::File::create(&path).unwrap();
        let needle = b"canary-0123456789";
        f.set_len(2 << 30).unwrap();
        for at in [0u64, (super::SCAN_CHUNK_BYTES as u64) - 5, 1 << 30] {
            f.seek(SeekFrom::Start(at)).unwrap();
            f.write_all(needle).unwrap();
        }
        drop(f);
        assert_eq!(count_in_file(&path, needle).unwrap(), 3);
        assert_eq!(count_in_file(&path, b"not-there-at-all").unwrap(), 0);
        assert!(count_in_file(&dir.join("missing"), needle).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
