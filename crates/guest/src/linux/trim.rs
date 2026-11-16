//! Idle page cache back to the host, so a VM holds on the node only the
//! memory it uses.
//!
//! The balloon's free-page reporting returns memory the guest frees within
//! seconds, but page cache is never free: after a computer reads a few
//! gigabytes (a checkout, a build, an install) the guest keeps those file
//! pages until something needs the memory, and an idle guest never does.
//! So the host holds the high-water mark of the last heavy job for as long
//! as the VM runs.
//!
//! Once the guest has been quiet for the quiet period (little CPU, no task
//! stalled on memory), this thread reclaims page cache through the root
//! cgroup's `memory.reclaim`, a bounded step at a time, down to a floor
//! that keeps what running programs map. Every tick looks again: the first
//! busy or stalled tick stops the trim, and it waits out a whole quiet
//! period before it starts again, so a workload still reading its files
//! keeps them. What it frees, free-page reporting hands back (the engine's
//! `page_reporting.page_reporting_order=0` reports every 4 KiB page).
//!
//! The idea and its constants are smolvm's guest memory trim
//! (github.com/smol-machines/smolvm, `crates/smolvm-agent/src/memory_trim.rs`,
//! Apache-2.0), rewritten here: smaller ticks and steps, so a trim notices
//! work sooner, and no reporting-order switching, which the engine's kernel
//! line already settles.
//!
//! Off with `sandcastle.memory_trim=off` on the kernel line (the engine's
//! `kernel_args`); `sandcastle.memory_trim=<seconds>` sets the quiet period.

use std::time::Duration;

/// How often the guest is sampled: three small proc files a tick.
pub const TICK: Duration = Duration::from_secs(2);
/// Quiet time before the first step.
pub const QUIET_DEFAULT: Duration = Duration::from_secs(60);
pub const QUIET_MAX: Duration = Duration::from_secs(3600);
/// CPU the guest may use, in cores, beyond this thread's own, and still
/// count as quiet.
pub const QUIET_CORES: f64 = 0.25;
/// Share of a tick some task may spend stalled on memory (PSI `some`),
/// beyond this thread's own reclaim, and still count as quiet: refaulting
/// cache a workload needs shows here first.
pub const STALL_LIMIT: f64 = 0.001;
/// One reclaim request's bounds. The upper one keeps a step short (clean
/// page cache frees at gigabytes a second), so the next look comes soon.
pub const STEP_MIN: u64 = 32 << 20;
pub const STEP_MAX: u64 = 512 << 20;
/// Cache grown past the last trim's low water by this much arms another.
pub const REARM_GROWTH: u64 = 64 << 20;

const PARAM: &str = "sandcastle.memory_trim=";
const RECLAIM: &str = "/sys/fs/cgroup/memory.reclaim";

/// Page cache left in place: the binaries and libraries that run.
pub fn floor(total: u64) -> u64 {
    (total / 32).clamp(64 << 20, 256 << 20)
}

/// The quiet period from the kernel line, `None` when the trim is off.
pub fn setting(cmdline: &str) -> Result<Option<Duration>, String> {
    let Some(value) = cmdline.split_whitespace().filter_map(|w| w.strip_prefix(PARAM)).next_back() else {
        return Ok(Some(QUIET_DEFAULT));
    };
    if value == "off" || value == "0" {
        return Ok(None);
    }
    match value.parse::<u64>() {
        Ok(s) => Ok(Some(Duration::from_secs(s).clamp(TICK, QUIET_MAX))),
        Err(_) => Err(format!("{PARAM}{value}: off, or a quiet period in seconds")),
    }
}

/// One look at the guest, over the last tick.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Sample {
    /// CPU used by everything but this thread, in cores.
    pub busy_cores: f64,
    /// Share of the tick some task was stalled on memory, but for this
    /// thread's own reclaim.
    pub stall: f64,
    /// Page cache: `Active(file)` + `Inactive(file)`.
    pub file: u64,
    /// `MemTotal`.
    pub total: u64,
}

impl Sample {
    fn quiet(&self) -> bool {
        self.busy_cores <= QUIET_CORES && self.stall <= STALL_LIMIT
    }
}

/// The policy, free of I/O.
#[derive(Debug)]
pub struct Trimmer {
    quiet_needed: u32,
    quiet: u32,
    /// There is cache worth a trim since the last one settled.
    armed: bool,
    /// The least cache seen since the last trim settled.
    low_water: u64,
}

impl Trimmer {
    pub fn new(quiet: Duration) -> Trimmer {
        let ticks = quiet.as_millis().div_ceil(TICK.as_millis()).max(1);
        Trimmer { quiet_needed: u32::try_from(ticks).unwrap_or(u32::MAX), quiet: 0, armed: true, low_water: u64::MAX }
    }

    /// How much page cache to reclaim now, if any.
    pub fn next(&mut self, s: &Sample) -> Option<u64> {
        self.low_water = self.low_water.min(s.file);
        if !self.armed && s.file >= self.low_water.saturating_add(REARM_GROWTH) {
            self.armed = true;
        }
        if !s.quiet() {
            self.quiet = 0;
            return None;
        }
        self.quiet = self.quiet.saturating_add(1);
        if !self.armed || self.quiet < self.quiet_needed {
            return None;
        }
        let floor = floor(s.total);
        if s.file < floor.saturating_add(STEP_MIN) {
            self.settle(s.file);
            return None;
        }
        Some((s.file / 4).clamp(STEP_MIN, STEP_MAX).min(s.file - floor))
    }

    /// A step's outcome: `complete` is false when the kernel could not free
    /// all of it, so the rest is in use and the trim settles.
    pub fn reclaimed(&mut self, complete: bool, file_after: u64) {
        if !complete {
            self.settle(file_after);
        }
    }

    pub fn armed(&self) -> bool {
        self.armed
    }

    fn settle(&mut self, file: u64) {
        self.armed = false;
        self.low_water = file;
    }
}

/// Busy jiffies over every CPU, from `/proc/stat`'s `cpu` line: user, nice,
/// system, irq, softirq (guest time is inside user already).
pub fn busy_jiffies(stat: &str) -> Option<u64> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let f: Vec<u64> = line.split_whitespace().skip(1).map(|v| v.parse().ok()).collect::<Option<_>>()?;
    let at = |i: usize| f.get(i).copied().unwrap_or(0);
    Some(at(0) + at(1) + at(2) + at(5) + at(6))
}

/// Page cache and `MemTotal`, in bytes, from `/proc/meminfo`.
pub fn file_and_total(meminfo: &str) -> Option<(u64, u64)> {
    let kib = |key: &str| -> Option<u64> {
        meminfo.lines().find_map(|l| l.strip_prefix(key)).and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok()).map(|k| k << 10)
    };
    Some((kib("Active(file):")? + kib("Inactive(file):")?, kib("MemTotal:")?))
}

/// PSI's cumulative `some` stall, in microseconds.
pub fn stall_total_us(pressure: &str) -> Option<u64> {
    pressure.lines().find(|l| l.starts_with("some "))?.split_whitespace().find_map(|f| f.strip_prefix("total="))?.parse().ok()
}

/// Starts the trim unless the kernel line turns it off. The caller has
/// mounted cgroup2 at `/sys/fs/cgroup`, which the workload never sees (it
/// pivots away from the init's mounts).
pub fn spawn() {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let quiet = match setting(&cmdline) {
        Ok(Some(q)) => q,
        Ok(None) => return,
        Err(e) => {
            eprintln!("sandcastle-guest: memory trim off: {e}");
            return;
        }
    };
    if !std::path::Path::new(RECLAIM).exists() {
        eprintln!("sandcastle-guest: memory trim off: no {RECLAIM}");
        return;
    }
    let spawned = std::thread::Builder::new().name("memory-trim".into()).spawn(move || run(quiet));
    if let Err(e) = spawned {
        eprintln!("sandcastle-guest: memory trim off: {e}");
    }
}

fn run(quiet: Duration) {
    let mut trimmer = Trimmer::new(quiet);
    let mut probe = probe::Probe::new();
    let mut episode = 0u64;
    // Unbounded by design: the trim serves for the VM's life, a tick at a
    // time.
    loop {
        std::thread::sleep(TICK);
        let Some(s) = probe.sample() else { continue };
        if let Some(bytes) = trimmer.next(&s) {
            let complete = probe.reclaim(bytes);
            let after = probe.file().unwrap_or(s.file);
            episode = episode.saturating_add(s.file.saturating_sub(after));
            trimmer.reclaimed(complete, after);
        }
        if episode > 0 && !trimmer.armed() {
            eprintln!("sandcastle-guest: memory trim: {} MiB of idle page cache returned", episode >> 20);
            episode = 0;
        }
    }
}

mod probe {
    use std::io::Write;
    use std::time::Instant;

    use super::{busy_jiffies, file_and_total, stall_total_us, Sample, RECLAIM, TICK};

    /// The guest's counters, turned into a sample by their deltas.
    pub struct Probe {
        clk_tck: f64,
        last: Option<(Instant, u64, u64, f64)>,
        /// Stall this thread's own reclaim caused since the last sample.
        own_stall_us: u64,
    }

    fn stall_us() -> Option<u64> {
        stall_total_us(&std::fs::read_to_string("/proc/pressure/memory").ok()?)
    }

    /// This thread's CPU time, in seconds.
    fn thread_cpu_s() -> f64 {
        // SAFETY: getrusage writes only into the zeroed struct.
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut ru) } != 0 {
            return 0.0;
        }
        let s = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
        s(ru.ru_utime) + s(ru.ru_stime)
    }

    impl Probe {
        pub fn new() -> Probe {
            // SAFETY: sysconf has no preconditions.
            let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
            Probe { clk_tck: if tck > 0 { tck as f64 } else { 100.0 }, last: None, own_stall_us: 0 }
        }

        pub fn sample(&mut self) -> Option<Sample> {
            let now = Instant::now();
            let busy = busy_jiffies(&std::fs::read_to_string("/proc/stat").ok()?)?;
            let stall = stall_us().unwrap_or(0);
            let own = thread_cpu_s();
            let (file, total) = file_and_total(&std::fs::read_to_string("/proc/meminfo").ok()?)?;
            let own_stall = std::mem::take(&mut self.own_stall_us);
            let (then, busy0, stall0, own0) = self.last.replace((now, busy, stall, own))?;
            let secs = now.duration_since(then).as_secs_f64().max(TICK.as_secs_f64() / 10.0);
            let cpu = busy.saturating_sub(busy0) as f64 / self.clk_tck - (own - own0).max(0.0);
            let stalled = stall.saturating_sub(stall0).saturating_sub(own_stall);
            Some(Sample { busy_cores: cpu.max(0.0) / secs, stall: stalled as f64 / (secs * 1e6), file, total })
        }

        pub fn file(&self) -> Option<u64> {
            file_and_total(&std::fs::read_to_string("/proc/meminfo").ok()?).map(|(f, _)| f)
        }

        /// Asks the kernel to reclaim `bytes`: whether it freed them all.
        pub fn reclaim(&mut self, bytes: u64) -> bool {
            let before = stall_us().unwrap_or(0);
            let r = std::fs::OpenOptions::new().write(true).open(RECLAIM).and_then(|mut f| f.write_all(bytes.to_string().as_bytes()));
            let after = stall_us().unwrap_or(before);
            self.own_stall_us = self.own_stall_us.saturating_add(after.saturating_sub(before));
            match r {
                Ok(()) => true,
                // EAGAIN: it reclaimed less than asked; the rest is in use.
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => false,
                Err(e) => {
                    eprintln!("sandcastle-guest: memory trim: {RECLAIM}: {e}");
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    /// A computer: 6 GiB, so a 192 MiB floor.
    const TOTAL: u64 = 6 * GIB;

    fn quiet(file: u64) -> Sample {
        Sample { busy_cores: 0.02, stall: 0.0, file, total: TOTAL }
    }

    fn busy(file: u64) -> Sample {
        Sample { busy_cores: 1.0, ..quiet(file) }
    }

    /// A quiet guest that frees what it is asked: the requests.
    fn drive(t: &mut Trimmer, file: &mut u64, ticks: usize) -> Vec<u64> {
        let mut steps = vec![];
        for _ in 0..ticks {
            if let Some(b) = t.next(&quiet(*file)) {
                *file -= b;
                steps.push(b);
                t.reclaimed(true, *file);
            }
        }
        steps
    }

    // Goal: the kernel line turns the trim off or sets its quiet period,
    // and a value that is neither is refused rather than guessed at.
    #[test]
    fn the_kernel_line_sets_it() {
        let line = |s: &str| setting(&format!("root=/dev/vda ro init=/init page_reporting.page_reporting_order=0 {s}"));
        assert_eq!(line(""), Ok(Some(QUIET_DEFAULT)));
        assert_eq!(line("sandcastle.memory_trim=off"), Ok(None));
        assert_eq!(line("sandcastle.memory_trim=0"), Ok(None));
        assert_eq!(line("sandcastle.memory_trim=120"), Ok(Some(Duration::from_secs(120))));
        assert_eq!(line("sandcastle.memory_trim=1"), Ok(Some(TICK)));
        assert_eq!(line("sandcastle.memory_trim=999999"), Ok(Some(QUIET_MAX)));
        assert_eq!(line("sandcastle.memory_trim=30 sandcastle.memory_trim=off"), Ok(None), "the last one wins, as the kernel's own do");
        assert!(line("sandcastle.memory_trim=soon").is_err());
        assert!(line("sandcastle.memory_trim=").is_err());
    }

    // Goal: nothing is reclaimed until the guest has been quiet for the
    // whole quiet period.
    #[test]
    fn waits_out_the_quiet_period() {
        let mut t = Trimmer::new(Duration::from_secs(60));
        for _ in 0..29 {
            assert_eq!(t.next(&quiet(2 * GIB)), None);
        }
        assert_eq!(t.next(&quiet(2 * GIB)), Some(STEP_MAX));
    }

    // Goal: one busy tick stops a trim at once, and it starts over only
    // after another whole quiet period.
    #[test]
    fn busy_stops_it_at_once() {
        let mut t = Trimmer::new(TICK);
        let mut file = 4 * GIB;
        assert_eq!(drive(&mut t, &mut file, 2).len(), 2);
        assert_eq!(t.next(&busy(file)), None);
        let mut t = Trimmer::new(Duration::from_secs(10));
        let mut file = 4 * GIB;
        assert_eq!(drive(&mut t, &mut file, 5).len(), 1, "quiet for 10 s, then a step");
        assert_eq!(t.next(&busy(file)), None);
        for _ in 0..4 {
            assert_eq!(t.next(&quiet(file)), None, "a new quiet period first");
        }
        assert!(t.next(&quiet(file)).is_some());
    }

    // Goal: a task stalled on memory (a workload refaulting its files)
    // stops it as work does.
    #[test]
    fn a_memory_stall_stops_it() {
        let mut t = Trimmer::new(TICK);
        assert!(t.next(&quiet(2 * GIB)).is_some());
        assert_eq!(t.next(&Sample { stall: 0.01, ..quiet(2 * GIB) }), None);
        assert_eq!(t.next(&Sample { busy_cores: QUIET_CORES + 0.01, ..quiet(2 * GIB) }), None);
    }

    // Goal: 2 GiB of cache comes down to the floor within a minute of
    // ticks, never below it, then the trim settles and stays put.
    #[test]
    fn down_to_the_floor_and_settled() {
        let mut t = Trimmer::new(TICK);
        let mut file = 2 * GIB;
        let steps = drive(&mut t, &mut file, 30);
        assert!(steps.iter().all(|s| (STEP_MIN..=STEP_MAX).contains(s)), "{steps:?}");
        assert!(file >= floor(TOTAL), "below the floor: {} MiB", file / MIB);
        assert!(file < floor(TOTAL) + STEP_MIN, "{} MiB left", file / MIB);
        assert!(!t.armed());
        assert!(drive(&mut t, &mut file, 30).is_empty());
    }

    // Goal: steps are bounded both ways, and the floor follows memory.
    #[test]
    fn bounds() {
        assert_eq!(Trimmer::new(TICK).next(&quiet(64 * GIB)), Some(STEP_MAX));
        let small = floor(TOTAL) + STEP_MIN + MIB;
        assert_eq!(Trimmer::new(TICK).next(&quiet(small)), Some(STEP_MIN + MIB));
        assert_eq!(floor(6 * GIB), 192 * MIB);
        assert_eq!(floor(256 * MIB), 64 * MIB);
        assert_eq!(floor(64 * GIB), 256 * MIB);
        let mut t = Trimmer::new(TICK);
        let mut file = floor(TOTAL) + STEP_MIN / 2;
        assert!(drive(&mut t, &mut file, 10).is_empty(), "a small cache is left alone");
    }

    // Goal: after a trim settles, a little new cache is left alone and a
    // new job's worth arms the next trim.
    #[test]
    fn new_cache_rearms() {
        let mut t = Trimmer::new(TICK);
        let mut file = 2 * GIB;
        drive(&mut t, &mut file, 30);
        assert!(!t.armed());
        file += REARM_GROWTH / 2;
        assert!(drive(&mut t, &mut file, 5).is_empty());
        file += 2 * GIB;
        assert_eq!(t.next(&busy(file)), None);
        assert!(t.armed());
        assert!(!drive(&mut t, &mut file, 5).is_empty());
    }

    // Goal: when the kernel frees less than asked, the rest is in use: the
    // trim settles rather than asking again.
    #[test]
    fn an_incomplete_step_settles() {
        let mut t = Trimmer::new(TICK);
        let b = t.next(&quiet(4 * GIB)).expect("a step");
        t.reclaimed(false, 4 * GIB - b / 8);
        assert!(!t.armed());
        assert_eq!(t.next(&quiet(4 * GIB - b / 8)), None);
    }

    #[test]
    fn proc_files() {
        assert_eq!(busy_jiffies("cpu  100 5 50 9000 20 3 2 7 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n"), Some(160));
        assert_eq!(busy_jiffies("intr 1\n"), None);
        let meminfo = "MemTotal:        6000000 kB\nMemFree:  10 kB\nActive(file):     1000 kB\nInactive(file):    24 kB\n";
        assert_eq!(file_and_total(meminfo), Some((1024 * 1024, 6_000_000 * 1024)));
        assert_eq!(file_and_total("MemTotal: 1 kB\n"), None);
        let psi = "some avg10=0.00 avg60=0.00 avg300=0.00 total=12345\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=99\n";
        assert_eq!(stall_total_us(psi), Some(12345));
        assert_eq!(stall_total_us("garbage"), None);
    }
}
