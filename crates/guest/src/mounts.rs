//! What the guest mounts, as data: the basics the init needs, the
//! workload's root (the image read-only under a fresh scratch disk's
//! overlay, with `/data` on top), and the build target.

use sandcastle_wire::{disks, Process};

/// Where the init keeps the workload's layers, on its own tmpfs.
pub const RUN: &str = "/run/sc";
pub const LOWER: &str = "/run/sc/lower";
pub const SCRATCH: &str = "/run/sc/scratch";
pub const UPPER: &str = "/run/sc/scratch/upper";
pub const WORK: &str = "/run/sc/scratch/work";
pub const ROOT: &str = "/run/sc/root";
pub const TARGET: &str = "/run/sc/target";
/// Where Cloudflare's containers find the interception CA.
pub const CA_PATH: &str = "etc/cloudflare/certs/cloudflare-containers-ca.crt";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    pub read_only: bool,
    pub nosuid: bool,
    pub nodev: bool,
    pub noexec: bool,
    pub bind: bool,
    pub recursive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub source: String,
    pub target: String,
    pub fstype: Option<&'static str>,
    pub flags: Flags,
    pub data: Option<String>,
    /// Already mounted is fine (devtmpfs, which the kernel may mount).
    pub may_exist: bool,
}

fn m(source: &str, target: &str, fstype: &'static str, flags: Flags, data: Option<&str>) -> Mount {
    Mount { source: source.into(), target: target.into(), fstype: Some(fstype), flags, data: data.map(Into::into), may_exist: false }
}

const NOSUID_NODEV_NOEXEC: Flags = Flags { read_only: false, nosuid: true, nodev: true, noexec: true, bind: false, recursive: false };
const NOSUID_NODEV: Flags = Flags { read_only: false, nosuid: true, nodev: true, noexec: false, bind: false, recursive: false };

/// The init's own: proc, sys, dev, ptys, shared memory, and its tmpfs.
pub fn basics() -> Vec<Mount> {
    let mut dev = m("devtmpfs", "/dev", "devtmpfs", Flags { nosuid: true, ..Flags::default() }, Some("mode=0755"));
    dev.may_exist = true;
    vec![
        m("proc", "/proc", "proc", NOSUID_NODEV_NOEXEC, None),
        m("sysfs", "/sys", "sysfs", NOSUID_NODEV_NOEXEC, None),
        dev,
        m("devpts", "/dev/pts", "devpts", Flags { nosuid: true, noexec: true, ..Flags::default() }, Some("gid=5,mode=620,ptmxmode=666")),
        m("tmpfs", "/dev/shm", "tmpfs", NOSUID_NODEV, Some("mode=1777")),
        m("tmpfs", "/run", "tmpfs", NOSUID_NODEV, Some("mode=0755")),
    ]
}

/// The links every container's `/dev` has beside its devices (the OCI
/// runtime spec's, which Docker and runc make): bash's process
/// substitution, `<(…)`, opens `/dev/fd/N`, and a program that writes to
/// `/dev/stdout` means its own. A bare devtmpfs has none of them. Made in
/// the init's `/dev`, which the workload's is (`workload`).
pub const DEV_LINKS: [(&str, &str); 4] = [("/dev/fd", "/proc/self/fd"), ("/dev/stdin", "/proc/self/fd/0"), ("/dev/stdout", "/proc/self/fd/1"), ("/dev/stderr", "/proc/self/fd/2")];

/// Directories made before `basics` (they are on the read-only boot disk)
/// and after it (on the init's tmpfs).
pub fn dirs_after_basics(build: bool) -> Vec<&'static str> {
    if build {
        vec![RUN, TARGET]
    } else {
        vec![RUN, LOWER, SCRATCH, ROOT]
    }
}

/// The kernel command line's word naming the image's device in place of
/// `disks::IMAGE`: a verity device the kernel made from its own command
/// line (`dm-mod.create=`, so the root hash is measured with it), on a
/// Nitro Sandbox (docs/nitro.md).
pub const IMAGE_ARG: &str = disks::IMAGE_ARG;

/// The image's device: `disks::IMAGE`, or what the kernel's own command
/// line names. Read from the command line, never from the runner's start
/// message, because the command line is what attestation measures and the
/// runner is not trusted to pick the root. A named device that is not a
/// device-mapper node is refused, not ignored: a guest told to verify its
/// root must not boot an unverified one.
pub fn image_device(cmdline: &str) -> Result<String, &'static str> {
    let mut named = cmdline.split_ascii_whitespace().filter_map(|w| w.strip_prefix(IMAGE_ARG));
    let first = named.next();
    if named.next().is_some() {
        return Err("the command line names the image twice");
    }
    match first {
        None => Ok(disks::IMAGE.to_string()),
        Some(d) if d.strip_prefix("/dev/dm-").is_some_and(|n| !n.is_empty() && n.len() <= 3 && n.bytes().all(|b| b.is_ascii_digit())) => Ok(d.to_string()),
        Some(_) => Err("the command line names an image that is not /dev/dm-N"),
    }
}

/// A start file's ceiling: a command, its environment and a few paths.
pub const START_FILE_BYTES_MAX: usize = 64 * 1024;

/// What a guest's kernel line says of its doors and its start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Doors {
    /// The agent's work only over the attested session.
    pub session: bool,
    /// No door: the host's port takes only ping and a signal; no session.
    pub none: bool,
    /// The image's own start, not the host's.
    pub start_from_image: bool,
}

impl Doors {
    pub fn of(cmdline: &str) -> Result<Doors, &'static str> {
        let has = |w: &str| cmdline.split_whitespace().any(|x| x == w);
        let d = Doors { session: has(sandcastle_wire::SESSION_ARG), none: has(sandcastle_wire::AGENT_NONE_ARG), start_from_image: has(sandcastle_wire::START_IMAGE_ARG) };
        if d.session && d.none {
            return Err("the kernel line asks for a session and for no door at all");
        }
        Ok(d)
    }

    /// Whether the host's own agent port takes only what the parent keeps.
    pub fn host_restricted(&self) -> bool {
        self.session || self.none
    }
}

/// The entrypoint: the host's start message's, or, when the kernel line
/// says so, the image's own start file (`image_start`, its bytes as read
/// from the image's read-only layer, `None` when it has none).
pub fn entrypoint(doors: &Doors, from_host: Process, image_start: Option<&[u8]>) -> Result<Process, String> {
    if !doors.start_from_image {
        return Ok(from_host);
    }
    let bytes = image_start.ok_or_else(|| format!("the kernel line names the image's start, and the image has no {}", sandcastle_wire::START_FILE))?;
    if bytes.len() > START_FILE_BYTES_MAX {
        return Err(format!("{} is past {START_FILE_BYTES_MAX} bytes", sandcastle_wire::START_FILE));
    }
    let p: Process = serde_json::from_slice(bytes).map_err(|e| format!("{}: {e}", sandcastle_wire::START_FILE))?;
    p.validate().map_err(|e| format!("{}: {e}", sandcastle_wire::START_FILE))?;
    Ok(p)
}

/// The workload's root: the image read-only, a fresh scratch disk as the
/// overlay's upper layer, so every start begins from the image exactly.
/// `scratch` is the scratch disk itself, or its sealed mapping
/// (`linux::seal`) on a Nitro Sandbox.
pub fn run_root(image: &str, scratch: &str) -> Vec<Mount> {
    vec![
        m(image, LOWER, "ext4", Flags { read_only: true, nodev: true, ..Flags::default() }, Some("noload")),
        m(scratch, SCRATCH, "ext4", Flags::default(), None),
    ]
}

/// The overlay, once the scratch disk's `upper` and `work` exist. Its
/// layers are two filesystems (the image's disk and the scratch disk), so
/// without `xino=on` a file's `st_dev` is its layer's while a directory's
/// is the overlay's: anything that stays on one filesystem (the Sandbox
/// SDK's backup shim, `tar --one-file-system`, `find -xdev`) then skips
/// every file. With it, every object has the overlay's `st_dev`, as on
/// Docker's overlay2, whose layers share a filesystem.
pub fn overlay() -> Mount {
    let data = format!("lowerdir={LOWER},upperdir={UPPER},workdir={WORK},xino=on");
    m("overlay", ROOT, "overlay", Flags::default(), Some(&data))
}

/// The computer's own disk, over the root at `path` (`/data` by default).
pub fn data(path: Option<&str>) -> Mount {
    let path = path.unwrap_or("/data");
    assert!(path.starts_with('/') && path != "/", "validated by the wire");
    m(disks::DATA, &format!("{ROOT}{path}"), "ext4", Flags { nodev: true, ..Flags::default() }, None)
}

pub fn build_target() -> Mount {
    m(disks::TARGET, TARGET, "ext4", Flags::default(), None)
}

/// cgroup2 in the init's namespace, for the memory trim's root
/// `memory.reclaim`; the workload pivots away from it.
pub fn cgroup() -> Mount {
    m("cgroup2", "/sys/fs/cgroup", "cgroup2", NOSUID_NODEV_NOEXEC, None)
}

/// Inside the entrypoint's mount namespace, before it pivots into the
/// root: the init's `/dev` (so a PTY the agent opens is the workload's
/// too) and a fresh sysfs, read-only.
pub fn workload() -> Vec<Mount> {
    vec![
        Mount {
            source: "/dev".into(),
            target: format!("{ROOT}/dev"),
            fstype: None,
            flags: Flags { bind: true, recursive: true, ..Flags::default() },
            data: None,
            may_exist: false,
        },
        m("sysfs", &format!("{ROOT}/sys"), "sysfs", Flags { read_only: true, ..NOSUID_NODEV_NOEXEC }, None),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: the image is never mounted writable, the scratch layer is the
    // device it is given (the disk, or a Nitro guest's sealed mapping),
    // and the overlay's layers are the paths the plan mounts.
    #[test]
    fn image_read_only() {
        let r = run_root(disks::IMAGE, disks::SCRATCH);
        assert_eq!(r[0].source, disks::IMAGE);
        assert!(r[0].flags.read_only);
        assert!(!r[1].flags.read_only);
        assert_eq!(r[1].source, disks::SCRATCH);
        assert_eq!(run_root("/dev/dm-0", "/dev/dm-1")[1].source, "/dev/dm-1");
        let o = overlay();
        let data = o.data.unwrap();
        assert!(data.contains(LOWER) && data.contains(UPPER) && data.contains(WORK));
        assert!(data.split(',').any(|o| o == "xino=on"), "one st_dev for files and directories alike");
        assert!(UPPER.starts_with(SCRATCH) && WORK.starts_with(SCRATCH));
    }

    // Goal: the image's device comes from the kernel's command line only
    // as a device-mapper node; absent, the krun path's disk is unchanged.
    // Method: absent, present, twice, and not a dm node.
    #[test]
    fn image_device_from_the_command_line() {
        assert_eq!(image_device("panic=1 quiet").unwrap(), disks::IMAGE);
        assert_eq!(image_device("quiet sandcastle.image=/dev/dm-0 x=y").unwrap(), "/dev/dm-0");
        assert_eq!(image_device("sandcastle.image=/dev/dm-12").unwrap(), "/dev/dm-12");
        for bad in ["sandcastle.image=/dev/vdb", "sandcastle.image=/dev/dm-", "sandcastle.image=/dev/dm-1x", "sandcastle.image=/dev/dm-0 sandcastle.image=/dev/dm-1", "sandcastle.image=/dev/dm-1234"] {
            assert!(image_device(bad).is_err(), "{bad}");
        }
        assert_eq!(run_root("/dev/dm-0", disks::SCRATCH)[0].source, "/dev/dm-0");
        assert!(run_root("/dev/dm-0", disks::SCRATCH)[0].flags.read_only);
    }

    // Goal: the kernel line's words are read exactly (a word, not a part
    // of one), a session with no door at all is refused, and either one
    // restricts the host's port.
    #[test]
    fn doors_from_the_kernel_line() {
        let none = Doors::of("quiet sandcastle.agent=none sandcastle.start=image").unwrap();
        assert!(none.none && none.start_from_image && !none.session && none.host_restricted());
        let session = Doors::of("quiet sandcastle.session=required").unwrap();
        assert!(session.session && session.host_restricted() && !session.start_from_image);
        let open = Doors::of("quiet sandcastle.agent=nonex xsandcastle.start=image").unwrap();
        assert!(!open.host_restricted() && !open.start_from_image);
        assert!(Doors::of("sandcastle.session=required sandcastle.agent=none").is_err());
    }

    // Goal: with the image's start named, the host's entrypoint is never
    // run: the image's file is, checked; an image without one, a file past
    // its ceiling, or one that is not a process refuses the boot. Without
    // the word, the host's runs as before.
    #[test]
    fn the_images_start_wins_when_the_line_says_so() {
        let host = Process { argv: vec!["/bin/sh".into(), "-c".into(), "hand me the secrets".into()], ..Process::default() };
        let image = br#"{"argv":["/usr/local/bin/home-entry"],"env":["MODE=production"]}"#;
        let measured = Doors::of("sandcastle.agent=none sandcastle.start=image").unwrap();
        let p = entrypoint(&measured, host.clone(), Some(image)).unwrap();
        assert_eq!(p.argv, vec!["/usr/local/bin/home-entry"]);
        assert_eq!(p.env, vec!["MODE=production"]);
        assert!(entrypoint(&measured, host.clone(), None).unwrap_err().contains("no /etc/sandcastle/start.json"));
        assert!(entrypoint(&measured, host.clone(), Some(&vec![b' '; START_FILE_BYTES_MAX + 1])).is_err());
        assert!(entrypoint(&measured, host.clone(), Some(br#"{"argv":[]}"#)).is_err());
        assert!(entrypoint(&measured, host.clone(), Some(b"not json")).is_err());
        assert_eq!(entrypoint(&Doors::of("quiet").unwrap(), host.clone(), Some(image)).unwrap(), host);
    }

    #[test]
    fn workload_under_root() {
        for m in workload() {
            assert!(m.target.starts_with(ROOT));
        }
        assert!(data(None).target.starts_with(ROOT) && data(None).target.ends_with("/data"));
        assert_eq!(data(Some("/opt/data")).target, format!("{ROOT}/opt/data"));
        assert!(basics().iter().any(|m| m.target == "/dev" && m.may_exist));
    }

    // Goal: the workload's /dev has the links a container's has, each into
    // the process's own descriptors, under the /dev it binds. Method: the
    // list, against the OCI runtime spec's.
    #[test]
    fn dev_has_a_containers_links() {
        assert_eq!(DEV_LINKS[0], ("/dev/fd", "/proc/self/fd"), "process substitution opens /dev/fd/N");
        for (i, name) in ["stdin", "stdout", "stderr"].iter().enumerate() {
            assert_eq!(DEV_LINKS[i + 1], (format!("/dev/{name}").as_str(), format!("/proc/self/fd/{i}").as_str()));
        }
        assert!(DEV_LINKS.iter().all(|(link, _)| link.starts_with("/dev/")), "in the /dev the workload binds");
        assert!(basics().iter().any(|m| m.target == "/proc"), "their targets are proc's");
    }
}
