//! Memory back to the node (docs/krun-engine.md, Memory): what a
//! computer's VM holds on the host as it allocates and frees memory, and
//! as it reads files and then idles. Each phase is its own container, the
//! size a computer is (2 vCPUs, 6 GiB, a data disk), so the samples are
//! the host's account of one guest's history: its cgroup's charge
//! (`memory.current`, and `memory.stat`'s anonymous and file pages), the
//! runner's resident memory, and the guest's own `/proc/meminfo`.

use std::time::{Duration, Instant};

use sandcastle_engine::api::Instance;
use sandcastle_engine::StartRequest;
use serde_json::{json, Value};

use crate::node::{engine_err, start, with_data, Ctr, Node};
use crate::Error;

/// A computer's image family (Debian, glibc, Python), so the allocation
/// is a real process's.
const IMAGE: &str = "python:3.14-slim";
const SLEEP: &[&str] = &["sleep", "infinity"];
/// The longest the driver waits for a guest step to say it is done.
const STEP: Duration = Duration::from_secs(120);

pub struct Opts {
    /// `anon`, `cache`, or both.
    pub phases: Vec<String>,
    pub gib: u64,
    /// How long each phase idles after its work, sampled along the way.
    pub idle_s: u64,
}

/// The VM's cgroup: the engine's `vm-<slot>`. The engine's own cgroup is
/// where its service manager put it (`KRUN_SPIKE_ENGINE_CGROUP`), the
/// spike node's by default.
fn vm_cgroup(c: &Ctr<'_>) -> std::path::PathBuf {
    let engine = std::env::var("KRUN_SPIKE_ENGINE_CGROUP").unwrap_or_else(|_| crate::node::ENGINE_CGROUP.into());
    let slot = c.run_dir.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
    std::path::Path::new(&engine).join(format!("vm-{slot}"))
}

fn mib(bytes: u64) -> u64 {
    bytes >> 20
}

/// A `key value` file's field (`memory.stat`, `/proc/*/status` in kB).
fn field(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once([' ', ':'])?;
        (k == key).then(|| v.split_whitespace().next()?.parse().ok()).flatten()
    })
}

fn sample(c: &Ctr<'_>, label: &str, t0: Instant) -> Value {
    let cg = vm_cgroup(c);
    let read = |name: &str| std::fs::read_to_string(cg.join(name)).unwrap_or_default();
    let current = read("memory.current").trim().parse::<u64>().unwrap_or(0);
    let stat = read("memory.stat");
    // The runner's resident memory, over every process in the VM's cgroup
    // (the runner; the jailer stays in the engine's).
    let rss_kib: u64 = read("cgroup.procs")
        .lines()
        .filter_map(|p| std::fs::read_to_string(format!("/proc/{p}/status")).ok())
        .filter_map(|s| field(&s, "VmRSS"))
        .sum();
    let guest = c.sh("cat /proc/meminfo").map(|(t, _)| t).unwrap_or_default();
    let g = |k: &str| field(&guest, k).map(|kib| kib >> 10);
    json!({
        "label": label,
        "t_s": (t0.elapsed().as_secs_f64() * 10.0).round() / 10.0,
        "cgroup_mib": mib(current),
        "cgroup_anon_mib": field(&stat, "anon").map(mib),
        "cgroup_file_mib": field(&stat, "file").map(mib),
        "runner_rss_mib": rss_kib >> 10,
        "guest_free_mib": g("MemFree"),
        "guest_cached_mib": g("Cached"),
        "guest_anon_mib": g("AnonPages"),
    })
}

/// Waits (bounded) for `path` to exist in the guest.
fn until_file(c: &Ctr<'_>, path: &str) -> Result<(), Error> {
    let t = Instant::now();
    while t.elapsed() < STEP {
        if c.sh(&format!("test -e {path}"))?.1 == Some(0) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(Error::msg(format!("{path} did not appear within {STEP:?}")))
}

/// Samples at each mark (seconds after `from`) until `idle_s`.
fn idle(c: &Ctr<'_>, samples: &mut Vec<Value>, what: &str, from: Instant, idle_s: u64, t0: Instant) {
    for at in [0u64, 5, 15, 30, 60, 90, 120, 150, 180, 240, 300].into_iter().filter(|a| *a <= idle_s) {
        std::thread::sleep(Duration::from_secs(at).saturating_sub(from.elapsed()));
        samples.push(sample(c, &format!("{what}+{at}s"), t0));
    }
}

fn computer(name: &str) -> StartRequest {
    let mut s = start(IMAGE, SLEEP);
    s.instance = Some(Instance::Custom { vcpu: 2.0, memory_mib: 6144, disk_mb: 16_000 });
    with_data(s, name, "/data", 10)
}

/// The guest's balloon as the kernel sees it: the virtio devices and
/// their negotiated feature bits (balloon is device 5; free-page
/// reporting is feature 5), and the reporting order.
fn balloon(c: &Ctr<'_>) -> Result<Value, Error> {
    let (devices, _) = c.sh("for d in /sys/bus/virtio/devices/*; do echo \"$(basename $d) $(cat $d/device) $(cat $d/features)\"; done")?;
    let (order, _) = c.sh("cat /sys/module/page_reporting/parameters/page_reporting_order")?;
    let (config, _) = c.sh("(zcat /proc/config.gz 2>/dev/null || true) | grep -E 'CONFIG_(PAGE_REPORTING|VIRTIO_BALLOON|MEMCG|PSI|BALLOON_COMPACTION|COMPACTION)='")?;
    Ok(json!({"virtio_devices": devices, "page_reporting_order": order.trim(), "kernel_config": config}))
}

/// Allocate and touch `gib`, hold it, free it, idle.
fn anon(node: &Node, o: &Opts) -> Result<Value, Error> {
    node.delete_data("mem-anon");
    let c = node.start("mem-anon", &computer("mem-anon"))?;
    let t0 = Instant::now();
    let balloon = balloon(&c)?;
    std::thread::sleep(Duration::from_secs(10));
    let mut samples = vec![sample(&c, "ready+10s", t0)];
    let script = format!(
        "import os, time\nb = b'\\x01' * ({gib} << 30)\nopen('/tmp/hog.held', 'w').close()\nwhile not os.path.exists('/tmp/hog.stop'):\n    time.sleep(0.1)\ndel b\nopen('/tmp/hog.freed', 'w').close()\n",
        gib = o.gib
    );
    c.exec(&["sh", "-c", "cat > /tmp/hog.py"], Some(script.as_bytes()))?;
    c.sh("setsid python3 /tmp/hog.py </dev/null >/dev/null 2>&1 &")?;
    until_file(&c, "/tmp/hog.held")?;
    samples.push(sample(&c, "held", t0));
    c.sh("touch /tmp/hog.stop")?;
    until_file(&c, "/tmp/hog.freed")?;
    let freed = Instant::now();
    idle(&c, &mut samples, "freed", freed, o.idle_s, t0);
    c.destroy(None)?;
    node.delete_data("mem-anon");
    Ok(json!({"gib": o.gib, "balloon": balloon, "samples": samples}))
}

/// Read `gib` of files, idle. The file is written first and the guest's
/// cache dropped, so the read is the guest's page cache filling.
fn cache(node: &Node, o: &Opts) -> Result<Value, Error> {
    node.delete_data("mem-cache");
    let c = node.start("mem-cache", &computer("mem-cache"))?;
    let t0 = Instant::now();
    let (_, code) = c.sh(&format!("dd if=/dev/zero of=/data/f bs=1M count={} 2>/dev/null && sync", o.gib << 10))?;
    if code != Some(0) {
        return Err(Error::msg("writing the file failed"));
    }
    drop_guest_cache(node, &c)?;
    std::thread::sleep(Duration::from_secs(20));
    let mut samples = vec![sample(&c, "written, guest cache dropped", t0)];
    let t = Instant::now();
    c.sh("cat /data/f > /dev/null")?;
    let read_ms = t.elapsed().as_millis();
    let read = Instant::now();
    idle(&c, &mut samples, "read", read, o.idle_s, t0);
    c.destroy(None)?;
    node.delete_data("mem-cache");
    Ok(json!({"gib": o.gib, "read_ms": read_ms, "samples": samples}))
}

fn drop_guest_cache(node: &Node, c: &Ctr<'_>) -> Result<Value, Error> {
    node.block(node.client.reclaim(&c.name)).map_err(engine_err)
}

pub fn scenario(node: &Node, o: &Opts) -> Result<Value, Error> {
    let mut out = serde_json::Map::new();
    out.insert("image".into(), json!(IMAGE));
    out.insert("instance".into(), json!({"vcpu": 2, "memoryMib": 6144}));
    for p in &o.phases {
        let v = match p.as_str() {
            "anon" => anon(node, o)?,
            "cache" => cache(node, o)?,
            other => return Err(Error::msg(format!("no phase {other}: anon, cache"))),
        };
        out.insert(p.clone(), v);
    }
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    #[test]
    fn fields() {
        assert_eq!(super::field("anon 4096\nfile 8192\n", "file"), Some(8192));
        assert_eq!(super::field("VmRSS:\t  1234 kB\n", "VmRSS"), Some(1234));
        assert_eq!(super::field("anon_thp 1\n", "anon"), None);
    }
}
