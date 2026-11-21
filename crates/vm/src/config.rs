//! A VM's configuration: what the runner is asked to boot, validated
//! before anything is opened. The runner, the jail, and the guest agree on
//! the disks' order through `sandcastle_wire::disks`, which this checks.

use std::path::{Component, Path, PathBuf};

use sandcastle_wire::Start;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ID_BYTES_MAX: usize = 32;
pub const VCPUS_MAX: u8 = 8;
pub const MEMORY_MIB_MIN: u32 = 128;
pub const MEMORY_MIB_MAX: u32 = 16 * 1024;
/// A boot that has not said ready by now has failed.
pub const BOOT_MS_MAX: u64 = 60_000;
/// A paused VM that takes longer than this to resume has failed.
pub const RESUME_MS_MAX: u64 = 1_000;
pub const PATH_BYTES_MAX: usize = 256;
/// A unix socket's path, without its NUL (`sun_path` is 108 bytes).
pub const SOCKET_PATH_BYTES_MAX: usize = 107;
pub const TAP_NAME_BYTES_MAX: usize = 15;
pub const KERNEL_ARGS_MAX: usize = 8;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiskRole {
    Boot,
    Image,
    Scratch,
    Data,
    Target,
    /// A Nitro Sandbox's first disk in place of the boot disk: the
    /// image's dm-verity hash tree (docs/nitro.md).
    Hashes,
}

impl DiskRole {
    /// Shared disks are never writable: a guest that could write one would
    /// reach every VM that boots from it.
    pub fn read_only(self) -> bool {
        matches!(self, DiskRole::Boot | DiskRole::Image | DiskRole::Hashes)
    }
}

/// The verity device the kernel makes from its command line, which names
/// the image's root hash, so the measured command line decides the root.
pub const VERITY_NAME: &str = "sc-image";
/// The kernel's line ahead of the root's: Firecracker's own default,
/// spelled out because it is measured, and `quiet`, because the parent
/// shows the console's boot log even outside debug mode (the spike's
/// line 2: 730 ms of serial log).
pub const NITRO_BOOT_ARGS: &str = "panic=1 initcall_blacklist=i8042_init quiet";

/// A disk image's dm-verity metadata, as `veritysetup format` wrote it
/// with 4 KiB blocks and SHA-256.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Verity {
    pub data_blocks: u64,
    /// Where the tree starts on its disk, in blocks: 1 after veritysetup's
    /// superblock.
    pub hash_start_block: u64,
    pub root_hash: String,
    pub salt: String,
}

impl Verity {
    fn validate(&self) -> Result<(), ConfigError> {
        let hex = |s: &str, max: usize| !s.is_empty() && s.len() <= max && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit());
        if self.data_blocks == 0 || self.data_blocks > (16u64 << 30) / 4096 || self.hash_start_block > 1 || self.root_hash.len() != 64 || !hex(&self.root_hash, 64) || !hex(&self.salt, 256) {
            return Err(ConfigError::Nitro("the verity table"));
        }
        Ok(())
    }

    /// `dm-mod.create`'s value: the image on `/dev/vdb`, its tree on
    /// `/dev/vda`, read-only.
    pub fn table(&self) -> String {
        format!(
            "{VERITY_NAME},,,ro,0 {} verity 1 {} {} 4096 4096 {} {} sha256 {} {}",
            self.data_blocks * 8,
            sandcastle_wire::disks::IMAGE,
            sandcastle_wire::disks::HASHES,
            self.data_blocks,
            self.hash_start_block,
            self.root_hash,
            self.salt
        )
    }
}

/// A Nitro Sandbox in place of libkrun (docs/nitro.md): Firecracker, the
/// measured kernel and initrd the guest boots from, and the image's
/// verity table. libkrun's two paths stay in the config, unopened.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Nitro {
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    /// The parent cannot read its memory (and an NSM attests), or it can.
    pub confidential: bool,
    /// vCPUs shared rather than each a hardware thread of the CPU pool
    /// (measured into PCR0).
    pub cpu_overcommit: bool,
    /// Unique on the parent while the sandbox runs.
    pub guest_cid: u32,
    /// The image's verity table: a run's measured root. A build has none.
    pub verity: Option<Verity>,
}

/// A Nitro Sandbox's memory: at least 256 MiB, in steps of 2.
pub const NITRO_MEMORY_MIB_MIN: u32 = crate::firecracker::MEMORY_MIB_MIN;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Disk {
    pub role: DiskRole,
    pub path: PathBuf,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Net {
    /// No network device: vsock only.
    None,
    /// virtio-net on a tap in the VM process's network namespace.
    Tap { name: String, mac: [u8; 6] },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VmConfig {
    pub id: String,
    pub vcpus: u8,
    pub memory_mib: u32,
    /// Loaded by path, never from the system's library path.
    pub libkrun: PathBuf,
    pub libkrunfw: PathBuf,
    /// The runner's sockets and the console log.
    pub run_dir: PathBuf,
    pub disks: Vec<Disk>,
    pub net: Net,
    /// virtio-balloon with free-page reporting: freed guest memory goes
    /// back to the host (libkrun only: a Nitro Sandbox has none).
    pub balloon: bool,
    /// Kernel parameters beyond the runner's own, `key=value` with plain
    /// characters only (a tuning, never a root or an init).
    #[serde(default)]
    pub kernel_args: Vec<String>,
    /// The runner's own seccomp allowlist, installed as its first act; the
    /// jailer sets it (an unjailed runner has none).
    #[serde(default)]
    pub seccomp: Option<crate::jail::SeccompMode>,
    pub start: Start,
    /// A Nitro Sandbox instead of libkrun.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nitro: Option<Nitro>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("id: lowercase letters, digits, and '-', 1 to {ID_BYTES_MAX} bytes")]
    Id,
    #[error("vcpus: 1 to {VCPUS_MAX}")]
    Vcpus,
    #[error("memory_mib: {MEMORY_MIB_MIN} to {MEMORY_MIB_MAX}")]
    Memory,
    #[error("{0}: an absolute, normal path within the limit")]
    Path(&'static str),
    #[error("a socket path passes {SOCKET_PATH_BYTES_MAX} bytes")]
    SocketPath,
    #[error("disks: {0}")]
    Disks(&'static str),
    #[error("net: {0}")]
    Net(&'static str),
    #[error("start: {0}")]
    Start(String),
    #[error("kernel_args: at most {KERNEL_ARGS_MAX}, each key=value of plain characters, none naming the root or init")]
    KernelArg,
    #[error("nitro: {0}")]
    Nitro(&'static str),
}

/// An absolute path with no `.` or `..`, so what is checked is what is
/// opened.
pub fn normal_absolute(p: &Path) -> bool {
    let s = p.as_os_str().len();
    p.is_absolute()
        && s <= PATH_BYTES_MAX
        && p.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

impl VmConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.id.is_empty()
            || self.id.len() > ID_BYTES_MAX
            || !self.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(ConfigError::Id);
        }
        if self.vcpus == 0 || self.vcpus > VCPUS_MAX {
            return Err(ConfigError::Vcpus);
        }
        if !(MEMORY_MIB_MIN..=MEMORY_MIB_MAX).contains(&self.memory_mib) {
            return Err(ConfigError::Memory);
        }
        for (name, p) in [("libkrun", &self.libkrun), ("libkrunfw", &self.libkrunfw), ("run_dir", &self.run_dir)] {
            if !normal_absolute(p) {
                return Err(ConfigError::Path(name));
            }
        }
        for name in [crate::paths::AGENT_SOCK, crate::paths::LIFECYCLE_SOCK, crate::paths::CONTROL_SOCK] {
            if self.run_dir.join(name).as_os_str().len() > SOCKET_PATH_BYTES_MAX {
                return Err(ConfigError::SocketPath);
            }
        }
        for d in &self.disks {
            if !normal_absolute(&d.path) {
                return Err(ConfigError::Path("disk"));
            }
        }
        let roles: Vec<DiskRole> = self.disks.iter().map(|d| d.role).collect();
        // A Nitro Sandbox's first disk is its image's hash tree: its guest
        // comes from the initrd, not a boot disk.
        let first = if self.nitro.is_some() { DiskRole::Hashes } else { DiskRole::Boot };
        match &self.start {
            Start::Run { data, .. } => {
                let want: &[DiskRole] = if *data {
                    &[first, DiskRole::Image, DiskRole::Scratch, DiskRole::Data]
                } else {
                    &[first, DiskRole::Image, DiskRole::Scratch]
                };
                if roles != want {
                    return Err(ConfigError::Disks("run takes boot (a Nitro Sandbox: hashes), image, scratch, and data if asked, in that order"));
                }
            }
            // A Nitro build's first disk is an empty one in the boot
            // disk's place: the guest is the initrd's, the target vdb.
            Start::Build if self.nitro.is_some() => {
                if roles != [DiskRole::Hashes, DiskRole::Target] {
                    return Err(ConfigError::Disks("a Nitro build takes an empty first disk and the target, in that order"));
                }
                if self.net != Net::None {
                    return Err(ConfigError::Net("a build has no network"));
                }
            }
            Start::Build => {
                if roles != [DiskRole::Boot, DiskRole::Target] {
                    return Err(ConfigError::Disks("build takes boot and target, in that order"));
                }
                if self.net != Net::None {
                    return Err(ConfigError::Net("a build has no network"));
                }
            }
        }
        if let Net::Tap { name, mac } = &self.net {
            if name.is_empty() || name.len() > TAP_NAME_BYTES_MAX || !name.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Err(ConfigError::Net("tap name"));
            }
            // Locally administered, unicast.
            if mac[0] & 0x02 == 0 || mac[0] & 0x01 != 0 {
                return Err(ConfigError::Net("mac must be locally administered unicast"));
            }
        }
        if self.kernel_args.len() > KERNEL_ARGS_MAX {
            return Err(ConfigError::KernelArg);
        }
        for a in &self.kernel_args {
            let ok = a.len() <= 64
                && a.split_once('=').is_some_and(|(k, v)| !k.is_empty() && !v.is_empty())
                && a.bytes().all(|b| b.is_ascii_alphanumeric() || b"._=-".contains(&b))
                && !["root=", "init=", "rootfstype=", "ro", "rw"].iter().any(|p| a.starts_with(p));
            if !ok {
                return Err(ConfigError::KernelArg);
            }
        }
        if let Start::Run { net, .. } = &self.start {
            if net.is_some() != matches!(self.net, Net::Tap { .. }) {
                return Err(ConfigError::Net("the guest has an address exactly when it has a tap"));
            }
        }
        self.start.validate().map_err(|e| ConfigError::Start(e.to_string()))?;
        if let Some(n) = &self.nitro {
            for p in [&n.firecracker, &n.kernel, &n.initrd] {
                if !normal_absolute(p) {
                    return Err(ConfigError::Path("nitro"));
                }
            }
            if self.memory_mib < NITRO_MEMORY_MIB_MIN || !self.memory_mib.is_multiple_of(crate::firecracker::MEMORY_MIB_STEP) {
                return Err(ConfigError::Nitro("memory: at least 256 MiB, in steps of 2"));
            }
            if n.guest_cid < crate::firecracker::GUEST_CID_MIN {
                return Err(ConfigError::Nitro("guest_cid"));
            }
            if self.run_dir.join(crate::paths::NITRO_LIFECYCLE_SOCK).as_os_str().len() > SOCKET_PATH_BYTES_MAX {
                return Err(ConfigError::SocketPath);
            }
            match (&self.start, &n.verity) {
                (Start::Run { .. }, Some(v)) => v.validate()?,
                (Start::Run { .. }, None) => return Err(ConfigError::Nitro("a run boots a measured root: its verity table")),
                (Start::Build, None) => {}
                (Start::Build, Some(_)) => return Err(ConfigError::Nitro("a build has no root yet")),
            }
        }
        Ok(())
    }

    /// A Nitro Sandbox's whole kernel command line, which PCR0 and PCR1
    /// measure: the boot arguments, the image's verity device and the guest
    /// told to mount it (a run's; a build has no root), then the node's own
    /// tunings.
    pub fn nitro_cmdline(&self) -> Option<String> {
        let n = self.nitro.as_ref()?;
        let mut c = NITRO_BOOT_ARGS.to_string();
        if let Some(v) = &n.verity {
            c.push_str(&format!(
                " dm-mod.create=\"{}\" dm-mod.waitfor={},{} {}{}",
                v.table(),
                sandcastle_wire::disks::HASHES,
                sandcastle_wire::disks::IMAGE,
                sandcastle_wire::disks::IMAGE_ARG,
                sandcastle_wire::disks::VERITY_DEVICE
            ));
        }
        for a in &self.kernel_args {
            c.push(' ');
            c.push_str(a);
        }
        Some(c)
    }

    /// What the runner appends to libkrun's kernel command line: the boot
    /// disk is the kernel's root, read-only, and our init runs from it.
    /// Later arguments win, so these replace libkrun's virtio-fs root.
    pub fn kernel_cmdline(&self) -> String {
        let mut c = format!("root={} rootfstype=ext4 ro init=/init", sandcastle_wire::disks::BOOT);
        // pci=off: libkrun's devices are all virtio-mmio, and probing PCI
        // configuration space that is not there costs 7 ms of every boot.
        // arm64's libkrunfw has no PCI, so there the word would only be
        // passed on to our init's environment.
        if cfg!(target_arch = "x86_64") {
            c.push_str(" pci=off");
        }
        for a in &self.kernel_args {
            c.push(' ');
            c.push_str(a);
        }
        c
    }

    pub fn sock(&self, name: &str) -> PathBuf {
        self.run_dir.join(name)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sandcastle_wire::Process;

    pub fn run_config() -> VmConfig {
        VmConfig {
            id: "t1".into(),
            vcpus: 1,
            memory_mib: 512,
            libkrun: "/opt/krun/lib/libkrun.so".into(),
            libkrunfw: "/opt/krun/lib/libkrunfw.so.5".into(),
            run_dir: "/run/krun/t1".into(),
            disks: vec![
                Disk { role: DiskRole::Boot, path: "/var/krun/boot.ext4".into() },
                Disk { role: DiskRole::Image, path: "/var/krun/images/abc/root.ext4".into() },
                Disk { role: DiskRole::Scratch, path: "/run/krun/t1/scratch.ext4".into() },
            ],
            net: Net::None,
            balloon: true,
            kernel_args: vec![],
            seccomp: None,
            start: Start::Run {
                entrypoint: Process { argv: vec!["/bin/sh".into()], ..Process::default() },
                hostname: "t1".into(),
                data: false,
                data_path: None,
                ca_pem: None,
                net: None,
            },
            nitro: None,
        }
    }

    /// A Nitro Sandbox's config as the jail hands it to the runner.
    pub fn nitro_config() -> VmConfig {
        let mut c = run_config();
        c.run_dir = "/vm".into();
        c.disks = vec![
            Disk { role: DiskRole::Hashes, path: "/disks/hashes.verity".into() },
            Disk { role: DiskRole::Image, path: "/disks/image.ext4".into() },
            Disk { role: DiskRole::Scratch, path: "/disks/scratch.ext4".into() },
        ];
        c.net = Net::Tap { name: "tap0".into(), mac: [0x02, 0x53, 0x43, 0, 0, 7] };
        if let Start::Run { net, .. } = &mut c.start {
            *net = Some(sandcastle_wire::GuestNet { address: "10.0.2.15/24".into(), gateway: "10.0.2.2".into(), dns: "10.0.2.2".into(), mtu: 1500 });
        }
        c.nitro = Some(Nitro {
            firecracker: "/nitro/firecracker".into(),
            kernel: "/nitro/kernel".into(),
            initrd: "/nitro/initrd".into(),
            confidential: true,
            cpu_overcommit: false,
            guest_cid: 10,
            verity: Some(Verity { data_blocks: 923_392, hash_start_block: 1, root_hash: "e1".repeat(32), salt: "6e17".repeat(16) }),
        });
        c
    }

    // Goal: a Nitro config is checked as strictly as libkrun's: its hash
    // tree first (no boot disk), no build, its memory in Firecracker's
    // steps, a CID past the reserved ones, a well-formed verity table.
    // Method: the good config, then each way to break it.
    #[test]
    fn a_nitro_config_is_checked() {
        nitro_config().validate().unwrap();
        type Breaks = Vec<(&'static str, Box<dyn Fn(&mut VmConfig)>)>;
        let broken: Breaks = vec![
            ("a boot disk", Box::new(|c| c.disks[0].role = DiskRole::Boot)),
            ("memory under 256", Box::new(|c| c.memory_mib = 254)),
            ("odd memory", Box::new(|c| c.memory_mib = 513)),
            ("a reserved CID", Box::new(|c| c.nitro.as_mut().unwrap().guest_cid = 2)),
            ("a short root hash", Box::new(|c| c.nitro.as_mut().unwrap().verity.as_mut().unwrap().root_hash = "e1".into())),
            ("a root hash that is not hex", Box::new(|c| c.nitro.as_mut().unwrap().verity.as_mut().unwrap().root_hash = "zz".repeat(32))),
            ("no data blocks", Box::new(|c| c.nitro.as_mut().unwrap().verity.as_mut().unwrap().data_blocks = 0)),
            ("a run with no root", Box::new(|c| c.nitro.as_mut().unwrap().verity = None)),
            ("a relative kernel", Box::new(|c| c.nitro.as_mut().unwrap().kernel = "kernel".into())),
            ("a build with a root", Box::new(|c| {
                c.start = Start::Build;
                c.disks = vec![Disk { role: DiskRole::Hashes, path: "/a".into() }, Disk { role: DiskRole::Target, path: "/b".into() }];
                c.net = Net::None;
            })),
        ];
        for (what, f) in broken {
            let mut c = nitro_config();
            f(&mut c);
            assert!(c.validate().is_err(), "{what}");
        }
        // A build: an empty first disk, the target, no root, no network.
        let mut b = nitro_config();
        b.start = Start::Build;
        b.disks = vec![Disk { role: DiskRole::Hashes, path: "/a".into() }, Disk { role: DiskRole::Target, path: "/b".into() }];
        b.net = Net::None;
        b.nitro.as_mut().unwrap().verity = None;
        b.validate().unwrap();
        assert_eq!(b.nitro_cmdline().unwrap(), NITRO_BOOT_ARGS);
        // The hash tree is shared, so it is never writable.
        assert!(DiskRole::Hashes.read_only());
    }

    // Goal: the kernel's line names the image's root exactly: its table
    // over /dev/vdb with the tree on /dev/vda, the guest told to mount the
    // verity device, the node's tunings last. libkrun's config has none.
    #[test]
    fn a_nitro_kernel_line() {
        let mut c = nitro_config();
        c.kernel_args = vec!["loglevel=4".into()];
        let line = c.nitro_cmdline().unwrap();
        let v = c.nitro.as_ref().unwrap().verity.as_ref().unwrap();
        assert_eq!(
            line,
            format!(
                "panic=1 initcall_blacklist=i8042_init quiet dm-mod.create=\"sc-image,,,ro,0 7387136 verity 1 /dev/vdb /dev/vda 4096 4096 923392 1 sha256 {} {}\" dm-mod.waitfor=/dev/vda,/dev/vdb sandcastle.image=/dev/dm-0 loglevel=4",
                v.root_hash, v.salt
            )
        );
        assert_eq!(run_config().nitro_cmdline(), None);
        assert_eq!(format!("{}_{}", crate::paths::NITRO_VSOCK, sandcastle_wire::PORT_LIFECYCLE), crate::paths::NITRO_LIFECYCLE_SOCK);
    }

    #[test]
    fn valid_config() {
        run_config().validate().unwrap();
        let line = run_config().kernel_cmdline();
        assert!(line.starts_with("root=/dev/vda rootfstype=ext4 ro init=/init"));
        assert_eq!(line.split(' ').any(|w| w == "pci=off"), cfg!(target_arch = "x86_64"));
    }

    // Goal: every limit refuses one past its edge.
    #[test]
    fn limits() {
        let c = |f: &dyn Fn(&mut VmConfig)| {
            let mut c = run_config();
            f(&mut c);
            c.validate()
        };
        assert_eq!(c(&|c| c.id = "".into()), Err(ConfigError::Id));
        assert_eq!(c(&|c| c.id = "A".into()), Err(ConfigError::Id));
        assert_eq!(c(&|c| c.id = "a".repeat(ID_BYTES_MAX + 1)), Err(ConfigError::Id));
        c(&|c| c.id = "a".repeat(ID_BYTES_MAX)).unwrap();
        assert_eq!(c(&|c| c.vcpus = 0), Err(ConfigError::Vcpus));
        assert_eq!(c(&|c| c.vcpus = VCPUS_MAX + 1), Err(ConfigError::Vcpus));
        c(&|c| c.vcpus = VCPUS_MAX).unwrap();
        assert_eq!(c(&|c| c.memory_mib = MEMORY_MIB_MIN - 1), Err(ConfigError::Memory));
        assert_eq!(c(&|c| c.memory_mib = MEMORY_MIB_MAX + 1), Err(ConfigError::Memory));
        assert_eq!(c(&|c| c.run_dir = "/run/../etc".into()), Err(ConfigError::Path("run_dir")));
        assert_eq!(c(&|c| c.run_dir = "relative".into()), Err(ConfigError::Path("run_dir")));
        assert_eq!(c(&|c| c.run_dir = format!("/{}", "a".repeat(100)).into()), Err(ConfigError::SocketPath));
        c(&|c| c.kernel_args = vec!["page_reporting.page_reporting_order=0".into()]).unwrap();
        for bad in ["init=/bin/sh", "root=/dev/vdb", "a b=c", "noequals", "x=$(y)"] {
            assert_eq!(c(&|c| c.kernel_args = vec![bad.into()]), Err(ConfigError::KernelArg), "{bad}");
        }
        assert_eq!(c(&|c| c.kernel_args = vec!["a=b".into(); KERNEL_ARGS_MAX + 1]), Err(ConfigError::KernelArg));
    }

    // Goal: the disks' order is the guest's, and shared disks stay
    // read-only by role.
    #[test]
    fn disks_in_order() {
        let mut c = run_config();
        c.disks.swap(1, 2);
        assert!(matches!(c.validate(), Err(ConfigError::Disks(_))));
        let mut c = run_config();
        if let Start::Run { data, .. } = &mut c.start {
            *data = true;
        }
        assert!(matches!(c.validate(), Err(ConfigError::Disks(_))));
        c.disks.push(Disk { role: DiskRole::Data, path: "/var/krun/data/t1.ext4".into() });
        c.validate().unwrap();
        assert!(DiskRole::Boot.read_only() && DiskRole::Image.read_only());
        assert!(!DiskRole::Scratch.read_only() && !DiskRole::Data.read_only() && !DiskRole::Target.read_only());

        let mut b = run_config();
        b.start = Start::Build;
        assert!(b.validate().is_err());
        b.disks = vec![
            Disk { role: DiskRole::Boot, path: "/var/krun/boot.ext4".into() },
            Disk { role: DiskRole::Target, path: "/var/krun/images/new.ext4".into() },
        ];
        b.validate().unwrap();
        b.net = Net::Tap { name: "tap0".into(), mac: [0x02, 0, 0, 0, 0, 1] };
        assert_eq!(b.validate(), Err(ConfigError::Net("a build has no network")));
    }

    #[test]
    fn tap_checked() {
        let mut c = run_config();
        c.net = Net::Tap { name: "tap0".into(), mac: [0x02, 0, 0, 0, 0, 1] };
        assert_eq!(c.validate(), Err(ConfigError::Net("the guest has an address exactly when it has a tap")));
        if let Start::Run { net, .. } = &mut c.start {
            *net = Some(sandcastle_wire::GuestNet { address: "10.0.2.15/24".into(), gateway: "10.0.2.2".into(), dns: "10.0.2.2".into(), mtu: 1500 });
        }
        c.validate().unwrap();
        c.net = Net::Tap { name: "tap0".into(), mac: [0x01, 0, 0, 0, 0, 1] };
        assert!(c.validate().is_err());
        c.net = Net::Tap { name: "tap-0;".into(), mac: [0x02, 0, 0, 0, 0, 1] };
        assert!(c.validate().is_err());
    }
}
