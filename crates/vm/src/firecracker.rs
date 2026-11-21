//! Firecracker's configuration for a Nitro Sandbox (docs/nitro.md), and
//! what one costs the parent; from the Nitro spike, whose launches it
//! described to the MiB. The sandbox is described as typed data, checked against every
//! limit AWS and Firecracker document (the EC2 User Guide's Nitro Sandboxes
//! pages, and Firecracker v1.18's `docs/nitro-sandboxes/`, both read
//! 2026-11-20), and only then written as the JSON `firecracker --no-api
//! --config-file` reads. Nothing here touches the host.
//!
//! Choices that differ from Firecracker's defaults, on purpose:
//! - The kernel's command line is always written out. Firecracker's own
//!   default (`panic=1 initcall_blacklist=i8042_init`) is measured into
//!   PCR0 and PCR1 like any other, so it is spelled out where it is chosen.
//! - Every `enclave` option this module knows is written, `false` ones
//!   included, and in confidential mode every device's DMB size, so a
//!   change in Firecracker's defaults cannot change a sandbox's mode or
//!   what it takes from the pool.
//! - No drive is ever the root device: Firecracker would add `root=/dev/vda`
//!   to the command line behind our back, and the guest's init mounts its
//!   own root.

use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

/// A sandbox's memory: at least 256 MiB, in steps of 2 MiB.
pub const MEMORY_MIB_MIN: u32 = 256;
pub const MEMORY_MIB_STEP: u32 = 2;
/// Virtual devices a sandbox may have, hot-plugged ones included. The
/// vsock is one of them.
pub const DEVICES_MAX: usize = 32;
/// The pool each sandbox takes beside its memory: its control page.
pub const POOL_MIB_PER_SANDBOX: u64 = 2;
/// A device's memory buffer (DMB) in confidential mode, where its
/// virtqueues live because the parent cannot reach guest memory: 2 to 256
/// MiB in steps of 2, 16 when unset. Direct mode has none, and refuses one.
pub const DMB_MIB_MIN: u32 = 2;
pub const DMB_MIB_MAX: u32 = 256;
pub const DMB_MIB_STEP: u32 = 2;
pub const DMB_MIB_DEFAULT: u32 = 16;
/// Sandboxes a parent runs: five per parent vCPU, 896 at most.
pub const SANDBOXES_PER_PARENT_VCPU: u32 = 5;
pub const SANDBOXES_PER_PARENT_MAX: u32 = 896;
/// Slots: four with a pool, then steps of eight, each step 128 MiB of the
/// pool until the next reboot.
pub const SLOTS_BASE: u32 = 4;
pub const SLOTS_STEP: u32 = 8;
pub const POOL_MIB_PER_SLOT_STEP: u64 = 128;
/// The kernel's command line on arm64 and x86 (`COMMAND_LINE_SIZE`, with
/// its terminating zero).
pub const BOOT_ARGS_BYTES_MAX: usize = 2047;
/// A drive's or a NIC's id: Firecracker takes letters, digits and `_`.
pub const DEVICE_ID_BYTES_MAX: usize = 64;
/// A tap's name: `IFNAMSIZ` less its terminating zero.
pub const TAP_NAME_BYTES_MAX: usize = 15;
/// The vsock's socket path. A unix socket's path is at most 107 bytes,
/// and Firecracker adds `_<port>` (up to eleven bytes) for each port the
/// guest dials.
pub const UDS_PATH_BYTES_MAX: usize = 96;
/// Guest CIDs 0 to 2 are the hypervisor's, the loopback's and the host's.
pub const GUEST_CID_MIN: u32 = 3;
/// Firecracker's command line when none is given, which this module never
/// relies on (the module's comment says why).
pub const FIRECRACKER_DEFAULT_BOOT_ARGS: &str = "panic=1 initcall_blacklist=i8042_init";

const _: () = assert!(MEMORY_MIB_MIN.is_multiple_of(MEMORY_MIB_STEP));
const _: () = assert!(DMB_MIB_DEFAULT.is_multiple_of(DMB_MIB_STEP) && DMB_MIB_MIN <= DMB_MIB_DEFAULT && DMB_MIB_DEFAULT <= DMB_MIB_MAX);
const _: () = assert!(UDS_PATH_BYTES_MAX + "_4294967295".len() <= 107);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// The default: the parent cannot read the sandbox's memory, devices
    /// move data through their own buffers, and an NSM attests.
    Confidential,
    /// The parent shares the sandbox's memory; no NSM, no attestation.
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enclave {
    pub mode: Mode,
    /// vCPUs share the parent's instead of each taking a hardware thread.
    pub cpu_overcommit: bool,
    /// Drives and NICs may be added while it runs; PCR5 then reads as
    /// `HOTPLUG_ENABLED` instead of measuring the devices.
    pub hotplug: bool,
    /// The guest's console on Firecracker's stdout, and PCRs 0, 1, 2, 5
    /// and 6 read as zero. Development only.
    pub debug: bool,
    /// Each vCPU's time attributed to an `fc_vcpu` thread of Firecracker
    /// (a developer preview): sandbox vCPUs are the Nitro System's, so the
    /// parent's own accounting never sees them otherwise.
    pub cpu_accounting: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Boot {
    /// An EFI-stub kernel, an optional initrd and a command line, which
    /// Firecracker makes into the image at launch.
    Kernel { kernel: PathBuf, initrd: Option<PathBuf>, cmdline: String },
    /// An image `eif_build` made in advance, its command line inside it.
    Eif { image: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drive {
    pub id: String,
    /// A raw image file or a block device on the parent, which the parent
    /// can read whatever the sandbox's mode.
    pub path: PathBuf,
    pub read_only: bool,
    /// Its DMB in confidential mode; `None` is the default.
    pub dmb_mib: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nic {
    pub id: String,
    pub tap: String,
    /// The guest's MAC; the jail makes it a permanent neighbor on the tap.
    pub guest_mac: Option<[u8; 6]>,
    pub dmb_mib: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vsock {
    pub guest_cid: u32,
    /// Where Firecracker listens for the parent's connections; the guest's
    /// dial to port P reaches `<uds_path>_P`.
    pub uds_path: PathBuf,
    pub dmb_mib: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sandbox {
    pub boot: Boot,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub drives: Vec<Drive>,
    pub nics: Vec<Nic>,
    pub vsock: Vsock,
    pub enclave: Enclave,
}

/// The parent, as far as a sandbox's size depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parent {
    pub vcpus: u32,
    /// The vCPUs of the parent's first core, which the Nitro Enclaves
    /// driver keeps for the parent: one on Graviton (one thread a core),
    /// two where cores have two threads.
    pub first_core_vcpus: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    #[error("{mib} MiB of memory, under {MEMORY_MIB_MIN}")]
    MemoryTooSmall { mib: u32 },
    #[error("{mib} MiB of memory, not a multiple of {MEMORY_MIB_STEP}")]
    MemoryNotInSteps { mib: u32 },
    #[error("no vCPU")]
    NoVcpu,
    #[error("{vcpus} vCPUs, over the {max} the parent can give")]
    TooManyVcpus { vcpus: u32, max: u32 },
    #[error("{n} virtual devices, over {DEVICES_MAX}")]
    TooManyDevices { n: usize },
    #[error("device {index}'s id is not 1 to {DEVICE_ID_BYTES_MAX} letters, digits or '_'")]
    DeviceId { index: usize },
    #[error("device {index}'s id is another device's")]
    DeviceIdRepeated { index: usize },
    #[error("NIC {index}'s tap name is not 1 to {TAP_NAME_BYTES_MAX} letters, digits, '-' or '_'")]
    TapName { index: usize },
    #[error("NIC {index}'s tap is another NIC's")]
    TapRepeated { index: usize },
    #[error("a command line of {len} bytes, over {BOOT_ARGS_BYTES_MAX}")]
    BootArgsTooLong { len: usize },
    #[error("a command line with a byte that is not printable ASCII")]
    BootArgsNotPrintable,
    #[error("the path {0:?} is not absolute UTF-8 without a zero byte")]
    Path(PathBuf),
    #[error("a vsock socket path of {len} bytes, over {UDS_PATH_BYTES_MAX}")]
    UdsPathTooLong { len: usize },
    #[error("guest CID {cid}, under {GUEST_CID_MIN}")]
    GuestCid { cid: u32 },
    #[error("a DMB of {mib} MiB, outside {DMB_MIB_MIN} to {DMB_MIB_MAX} in steps of {DMB_MIB_STEP}")]
    DmbSize { mib: u32 },
    #[error("a DMB size in direct mode, which has no DMBs")]
    DmbInDirectMode,
}

fn device_id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= DEVICE_ID_BYTES_MAX && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn tap_ok(tap: &str) -> bool {
    !tap.is_empty() && tap.len() <= TAP_NAME_BYTES_MAX && tap.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn path_str(p: &Path) -> Result<&str, ConfigError> {
    match p.to_str() {
        Some(s) if p.is_absolute() && !s.contains('\0') => Ok(s),
        _ => Err(ConfigError::Path(p.to_path_buf())),
    }
}

impl Sandbox {
    /// Its virtual devices: drives, NICs and the vsock.
    pub fn devices(&self) -> usize {
        self.drives.len() + self.nics.len() + 1
    }

    /// Each device's DMB setting: drives, NICs, then the vsock.
    fn dmbs(&self) -> impl Iterator<Item = Option<u32>> + '_ {
        self.drives.iter().map(|d| d.dmb_mib).chain(self.nics.iter().map(|n| n.dmb_mib)).chain([self.vsock.dmb_mib])
    }

    /// What it takes from the parent's pool while it runs, in MiB: its
    /// memory, its control page, and in confidential mode each DMB.
    pub fn pool_mib(&self) -> u64 {
        let buffers: u64 = match self.enclave.mode {
            Mode::Confidential => self.dmbs().map(|d| u64::from(d.unwrap_or(DMB_MIB_DEFAULT))).sum(),
            Mode::Direct => 0,
        };
        u64::from(self.memory_mib) + POOL_MIB_PER_SANDBOX + buffers
    }

    /// A device's DMB as written: explicit in confidential mode, absent in
    /// direct mode (validated first).
    fn dmb(&self, set: Option<u32>) -> Option<u32> {
        match self.enclave.mode {
            Mode::Confidential => Some(set.unwrap_or(DMB_MIB_DEFAULT)),
            Mode::Direct => None,
        }
    }

    pub fn validate(&self, parent: &Parent) -> Result<(), ConfigError> {
        assert!(parent.vcpus > parent.first_core_vcpus, "a parent has more than its first core");
        if self.memory_mib < MEMORY_MIB_MIN {
            return Err(ConfigError::MemoryTooSmall { mib: self.memory_mib });
        }
        if !self.memory_mib.is_multiple_of(MEMORY_MIB_STEP) {
            return Err(ConfigError::MemoryNotInSteps { mib: self.memory_mib });
        }
        // With overcommit, as many as the parent has; without, each takes
        // a thread of the CPU pool, which is the parent less its first core.
        let vcpus_max = if self.enclave.cpu_overcommit { parent.vcpus } else { parent.vcpus - parent.first_core_vcpus };
        if self.vcpus == 0 {
            return Err(ConfigError::NoVcpu);
        }
        if self.vcpus > vcpus_max {
            return Err(ConfigError::TooManyVcpus { vcpus: self.vcpus, max: vcpus_max });
        }
        if self.devices() > DEVICES_MAX {
            return Err(ConfigError::TooManyDevices { n: self.devices() });
        }
        let ids: Vec<&str> = self.drives.iter().map(|d| d.id.as_str()).chain(self.nics.iter().map(|n| n.id.as_str())).collect();
        for (index, id) in ids.iter().enumerate() {
            if !device_id_ok(id) {
                return Err(ConfigError::DeviceId { index });
            }
            if ids[..index].contains(id) {
                return Err(ConfigError::DeviceIdRepeated { index });
            }
        }
        for (index, nic) in self.nics.iter().enumerate() {
            if !tap_ok(&nic.tap) {
                return Err(ConfigError::TapName { index });
            }
            if self.nics[..index].iter().any(|n| n.tap == nic.tap) {
                return Err(ConfigError::TapRepeated { index });
            }
        }
        if let Boot::Kernel { cmdline, .. } = &self.boot {
            if cmdline.len() > BOOT_ARGS_BYTES_MAX {
                return Err(ConfigError::BootArgsTooLong { len: cmdline.len() });
            }
            if !cmdline.bytes().all(|b| (b' '..=b'~').contains(&b)) {
                return Err(ConfigError::BootArgsNotPrintable);
            }
        }
        let uds = path_str(&self.vsock.uds_path)?;
        if uds.len() > UDS_PATH_BYTES_MAX {
            return Err(ConfigError::UdsPathTooLong { len: uds.len() });
        }
        if self.vsock.guest_cid < GUEST_CID_MIN {
            return Err(ConfigError::GuestCid { cid: self.vsock.guest_cid });
        }
        for mib in self.dmbs().flatten() {
            if self.enclave.mode == Mode::Direct {
                return Err(ConfigError::DmbInDirectMode);
            }
            if !(DMB_MIB_MIN..=DMB_MIB_MAX).contains(&mib) || !mib.is_multiple_of(DMB_MIB_STEP) {
                return Err(ConfigError::DmbSize { mib });
            }
        }
        for d in &self.drives {
            path_str(&d.path)?;
        }
        match &self.boot {
            Boot::Kernel { kernel, initrd, .. } => {
                path_str(kernel)?;
                if let Some(i) = initrd {
                    path_str(i)?;
                }
            }
            Boot::Eif { image } => {
                path_str(image)?;
            }
        }
        Ok(())
    }

    /// The JSON for `firecracker --no-api --config-file`, once valid.
    pub fn render(&self, parent: &Parent) -> Result<String, ConfigError> {
        self.validate(parent)?;
        fn path(p: &Path) -> &str {
            path_str(p).expect("validated")
        }
        let boot_source = match &self.boot {
            Boot::Kernel { kernel, initrd, cmdline } => BootSource { kernel_image_path: path(kernel), initrd_path: initrd.as_deref().map(path), boot_args: Some(cmdline) },
            Boot::Eif { image } => BootSource { kernel_image_path: path(image), initrd_path: None, boot_args: None },
        };
        let doc = Doc {
            boot_source,
            machine_config: MachineConfig { vcpu_count: self.vcpus, mem_size_mib: self.memory_mib },
            drives: self.drives.iter().map(|d| DriveDoc { drive_id: &d.id, path_on_host: path(&d.path), is_root_device: false, is_read_only: d.read_only, dmb_size_mib: self.dmb(d.dmb_mib) }).collect(),
            network_interfaces: self
                .nics
                .iter()
                .map(|n| NicDoc { iface_id: &n.id, host_dev_name: &n.tap, guest_mac: n.guest_mac.map(|m| m.map(|b| format!("{b:02x}")).join(":")), dmb_size_mib: self.dmb(n.dmb_mib) })
                .collect(),
            vsock: VsockDoc { guest_cid: self.vsock.guest_cid, uds_path: path(&self.vsock.uds_path), dmb_size_mib: self.dmb(self.vsock.dmb_mib) },
            enclave: EnclaveDoc { cpu_overcommit: self.enclave.cpu_overcommit, direct_mode: self.enclave.mode == Mode::Direct, hotplug_mode: self.enclave.hotplug, debug_mode: self.enclave.debug, cpu_accounting: self.enclave.cpu_accounting },
        };
        let json = serde_json::to_string_pretty(&doc).expect("plain data serializes");
        assert!(json.contains("\"enclave\"") && json.contains("\"drives\""), "Firecracker needs both keys");
        Ok(json)
    }
}

/// The `pcie_slots` value that runs `sandboxes` at once (4, then steps of
/// 8), and what the steps above 4 take from the pool, in MiB.
pub fn slots_for(sandboxes: u32) -> (u32, u64) {
    assert!(sandboxes <= SANDBOXES_PER_PARENT_MAX);
    if sandboxes <= SLOTS_BASE {
        return (SLOTS_BASE, 0);
    }
    let steps = (sandboxes - SLOTS_BASE).div_ceil(SLOTS_STEP);
    let slots = SLOTS_BASE + steps * SLOTS_STEP;
    assert!(slots >= sandboxes && slots - sandboxes < SLOTS_STEP);
    (slots, u64::from(steps) * POOL_MIB_PER_SLOT_STEP)
}

#[derive(Serialize)]
struct Doc<'a> {
    #[serde(rename = "boot-source")]
    boot_source: BootSource<'a>,
    #[serde(rename = "machine-config")]
    machine_config: MachineConfig,
    drives: Vec<DriveDoc<'a>>,
    #[serde(rename = "network-interfaces")]
    network_interfaces: Vec<NicDoc<'a>>,
    vsock: VsockDoc<'a>,
    enclave: EnclaveDoc,
}

#[derive(Serialize)]
struct BootSource<'a> {
    kernel_image_path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    initrd_path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_args: Option<&'a str>,
}

#[derive(Serialize)]
struct MachineConfig {
    vcpu_count: u32,
    mem_size_mib: u32,
}

#[derive(Serialize)]
struct DriveDoc<'a> {
    drive_id: &'a str,
    path_on_host: &'a str,
    is_root_device: bool,
    is_read_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    dmb_size_mib: Option<u32>,
}

#[derive(Serialize)]
struct NicDoc<'a> {
    iface_id: &'a str,
    host_dev_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dmb_size_mib: Option<u32>,
}

#[derive(Serialize)]
struct VsockDoc<'a> {
    guest_cid: u32,
    uds_path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dmb_size_mib: Option<u32>,
}

#[derive(Serialize)]
struct EnclaveDoc {
    cpu_overcommit: bool,
    direct_mode: bool,
    hotplug_mode: bool,
    debug_mode: bool,
    cpu_accounting: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const M8G_XLARGE: Parent = Parent { vcpus: 4, first_core_vcpus: 1 };

    /// AWS's own example (the guide's `sandbox.json`, "Launch a Nitro
    /// Sandbox"): 2 vCPUs, 2 GiB, no drive, one NIC, the vsock, overcommit.
    fn aws_example() -> Sandbox {
        Sandbox {
            boot: Boot::Kernel { kernel: "/srv/sandbox/vmlinuz".into(), initrd: Some("/srv/sandbox/initrd.img".into()), cmdline: FIRECRACKER_DEFAULT_BOOT_ARGS.into() },
            vcpus: 2,
            memory_mib: 2048,
            drives: vec![],
            nics: vec![Nic { id: "eth0".into(), tap: "tap0".into(), guest_mac: None, dmb_mib: None }],
            vsock: Vsock { guest_cid: 3, uds_path: "/run/sandbox/v.sock".into(), dmb_mib: None },
            enclave: Enclave { mode: Mode::Confidential, cpu_overcommit: true, hotplug: false, debug: false, cpu_accounting: false },
        }
    }

    // Goal: what we write is AWS's example, plus only what we spell out on
    // purpose (the command line and the `false` options). Method: the
    // guide's JSON, key by key, against ours.
    #[test]
    fn renders_awss_example() {
        let ours: Value = serde_json::from_str(&aws_example().render(&M8G_XLARGE).unwrap()).unwrap();
        let theirs: Value = serde_json::from_str(
            r#"{
                "boot-source": {"kernel_image_path": "/srv/sandbox/vmlinuz", "initrd_path": "/srv/sandbox/initrd.img"},
                "machine-config": {"vcpu_count": 2, "mem_size_mib": 2048},
                "drives": [],
                "network-interfaces": [{"iface_id": "eth0", "host_dev_name": "tap0"}],
                "vsock": {"guest_cid": 3, "uds_path": "/run/sandbox/v.sock"},
                "enclave": {"cpu_overcommit": true}
            }"#,
        )
        .unwrap();
        for (section, fields) in theirs.as_object().unwrap() {
            match fields {
                Value::Object(map) => {
                    for (k, v) in map {
                        assert_eq!(&ours[section][k], v, "{section}.{k}");
                    }
                }
                Value::Array(items) => {
                    assert_eq!(ours[section].as_array().map(Vec::len), Some(items.len()), "{section}");
                    for (i, item) in items.iter().enumerate() {
                        for (k, v) in item.as_object().unwrap() {
                            assert_eq!(&ours[section][i][k], v, "{section}[{i}].{k}");
                        }
                    }
                }
                other => assert_eq!(&ours[section], other, "{section}"),
            }
        }
        assert_eq!(ours["boot-source"]["boot_args"], FIRECRACKER_DEFAULT_BOOT_ARGS);
        assert_eq!(ours["enclave"], serde_json::json!({"cpu_overcommit": true, "direct_mode": false, "hotplug_mode": false, "debug_mode": false, "cpu_accounting": false}));
        assert_eq!(ours["network-interfaces"][0]["dmb_size_mib"], DMB_MIB_DEFAULT, "written out in confidential mode");
        assert_eq!(ours["vsock"]["dmb_size_mib"], DMB_MIB_DEFAULT);
        assert_eq!(ours.as_object().unwrap().len(), theirs.as_object().unwrap().len(), "no section of our own");
    }

    // Goal: each mode and option reaches the `enclave` key, a drive is
    // never the root, and an EIF carries no initrd or command line.
    #[test]
    fn options_drives_and_eif_render() {
        let mut s = aws_example();
        s.enclave = Enclave { mode: Mode::Direct, cpu_overcommit: false, hotplug: true, debug: true, cpu_accounting: true };
        s.drives = vec![Drive { id: "data".into(), path: "/srv/sandbox/data.img".into(), read_only: false, dmb_mib: None }, Drive { id: "root".into(), path: "/srv/sandbox/root.img".into(), read_only: true, dmb_mib: None }];
        s.boot = Boot::Eif { image: "/srv/sandbox/sandbox.eif".into() };
        let v: Value = serde_json::from_str(&s.render(&M8G_XLARGE).unwrap()).unwrap();
        assert_eq!(v["enclave"], serde_json::json!({"cpu_overcommit": false, "direct_mode": true, "hotplug_mode": true, "debug_mode": true, "cpu_accounting": true}));
        assert_eq!(v["drives"][0], serde_json::json!({"drive_id": "data", "path_on_host": "/srv/sandbox/data.img", "is_root_device": false, "is_read_only": false}), "no DMB in direct mode");
        assert!(v["vsock"].get("dmb_size_mib").is_none());
        assert_eq!(v["drives"][1]["is_root_device"], false);
        assert_eq!(v["drives"][1]["is_read_only"], true);
        assert_eq!(v["boot-source"], serde_json::json!({"kernel_image_path": "/srv/sandbox/sandbox.eif"}));
    }

    fn refused(change: impl FnOnce(&mut Sandbox), parent: Parent) -> ConfigError {
        let mut s = aws_example();
        change(&mut s);
        s.render(&parent).expect_err("refused")
    }

    fn accepted(change: impl FnOnce(&mut Sandbox), parent: Parent) {
        let mut s = aws_example();
        change(&mut s);
        s.render(&parent).expect("accepted");
    }

    // Goal: every limit holds at its edge and refuses one past it.
    #[test]
    fn limits_at_the_edge_and_one_past() {
        let p = M8G_XLARGE;
        accepted(|s| s.memory_mib = MEMORY_MIB_MIN, p);
        assert_eq!(refused(|s| s.memory_mib = MEMORY_MIB_MIN - MEMORY_MIB_STEP, p), ConfigError::MemoryTooSmall { mib: 254 });
        assert_eq!(refused(|s| s.memory_mib = 2049, p), ConfigError::MemoryNotInSteps { mib: 2049 });
        assert_eq!(refused(|s| s.vcpus = 0, p), ConfigError::NoVcpu);
        accepted(|s| s.vcpus = 4, p);
        assert_eq!(refused(|s| s.vcpus = 5, p), ConfigError::TooManyVcpus { vcpus: 5, max: 4 });
        // Without overcommit the first core is the parent's.
        accepted(|s| (s.vcpus, s.enclave.cpu_overcommit) = (3, false), p);
        assert_eq!(refused(|s| (s.vcpus, s.enclave.cpu_overcommit) = (4, false), p), ConfigError::TooManyVcpus { vcpus: 4, max: 3 });
        let two_threads = Parent { vcpus: 16, first_core_vcpus: 2 };
        assert_eq!(refused(|s| (s.vcpus, s.enclave.cpu_overcommit) = (15, false), two_threads), ConfigError::TooManyVcpus { vcpus: 15, max: 14 });
        let drives = |n: usize| (0..n).map(|i| Drive { id: format!("d{i}"), path: format!("/srv/d{i}.img").into(), read_only: true, dmb_mib: None }).collect::<Vec<_>>();
        accepted(|s| s.drives = drives(DEVICES_MAX - 2), p);
        assert_eq!(refused(|s| s.drives = drives(DEVICES_MAX - 1), p), ConfigError::TooManyDevices { n: 33 });
        accepted(|s| s.boot = Boot::Kernel { kernel: "/k".into(), initrd: None, cmdline: "x".repeat(BOOT_ARGS_BYTES_MAX) }, p);
        assert_eq!(refused(|s| s.boot = Boot::Kernel { kernel: "/k".into(), initrd: None, cmdline: "x".repeat(BOOT_ARGS_BYTES_MAX + 1) }, p), ConfigError::BootArgsTooLong { len: 2048 });
        assert_eq!(refused(|s| s.boot = Boot::Kernel { kernel: "/k".into(), initrd: None, cmdline: "console=ttyS0\n".into() }, p), ConfigError::BootArgsNotPrintable);
        let uds = |n: usize| PathBuf::from(format!("/{}", "s".repeat(n - 1)));
        accepted(|s| s.vsock.uds_path = uds(UDS_PATH_BYTES_MAX), p);
        assert_eq!(refused(|s| s.vsock.uds_path = uds(UDS_PATH_BYTES_MAX + 1), p), ConfigError::UdsPathTooLong { len: 97 });
        assert_eq!(refused(|s| s.vsock.guest_cid = 2, p), ConfigError::GuestCid { cid: 2 });
        assert_eq!(refused(|s| s.vsock.uds_path = "run/v.sock".into(), p), ConfigError::Path("run/v.sock".into()));
        accepted(|s| s.drives = vec![Drive { id: "a".repeat(DEVICE_ID_BYTES_MAX), path: "/d".into(), read_only: true, dmb_mib: None }], p);
        assert_eq!(refused(|s| s.drives = vec![Drive { id: "a".repeat(DEVICE_ID_BYTES_MAX + 1), path: "/d".into(), read_only: true, dmb_mib: None }], p), ConfigError::DeviceId { index: 0 });
        assert_eq!(refused(|s| s.drives = vec![Drive { id: "eth0".into(), path: "/d".into(), read_only: true, dmb_mib: None }], p), ConfigError::DeviceIdRepeated { index: 1 });
        assert_eq!(refused(|s| s.nics.push(Nic { id: "eth1".into(), tap: "tap0".into(), guest_mac: None, dmb_mib: None }), p), ConfigError::TapRepeated { index: 1 });
        accepted(|s| s.vsock.dmb_mib = Some(DMB_MIB_MIN), p);
        accepted(|s| s.nics[0].dmb_mib = Some(DMB_MIB_MAX), p);
        assert_eq!(refused(|s| s.nics[0].dmb_mib = Some(DMB_MIB_MAX + DMB_MIB_STEP), p), ConfigError::DmbSize { mib: 258 });
        assert_eq!(refused(|s| s.nics[0].dmb_mib = Some(0), p), ConfigError::DmbSize { mib: 0 });
        assert_eq!(refused(|s| s.vsock.dmb_mib = Some(3), p), ConfigError::DmbSize { mib: 3 });
        assert_eq!(refused(|s| (s.enclave.mode, s.vsock.dmb_mib) = (Mode::Direct, Some(4)), p), ConfigError::DmbInDirectMode);
        assert_eq!(refused(|s| s.nics[0].tap = "t".repeat(TAP_NAME_BYTES_MAX + 1), p), ConfigError::TapName { index: 0 });
    }

    // Goal: the pool's accounting follows AWS's rule: memory, 2 MiB a
    // sandbox, and each device's DMB (16 MiB unless set) in confidential
    // mode only.
    #[test]
    fn pool_accounting() {
        let mut s = aws_example();
        assert_eq!(s.devices(), 2, "a NIC and the vsock");
        assert_eq!(s.pool_mib(), 2048 + 2 + 2 * 16);
        s.nics[0].dmb_mib = Some(4);
        assert_eq!(s.pool_mib(), 2048 + 2 + 4 + 16);
        s.nics[0].dmb_mib = None;
        s.enclave.mode = Mode::Direct;
        assert_eq!(s.pool_mib(), 2048 + 2);
    }

    // Goal: slots go 4, 12, 20, … and each step past 4 costs 128 MiB.
    #[test]
    fn slots_in_steps() {
        assert_eq!(slots_for(0), (4, 0));
        assert_eq!(slots_for(4), (4, 0));
        assert_eq!(slots_for(5), (12, 128));
        assert_eq!(slots_for(12), (12, 128));
        assert_eq!(slots_for(13), (20, 256));
        assert_eq!(slots_for(SANDBOXES_PER_PARENT_MAX), (900, 112 * 128));
    }
}
