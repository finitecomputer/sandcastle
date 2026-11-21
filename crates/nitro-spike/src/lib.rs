//! The Nitro spike's driver (docs/nitro-spike.md): Firecracker's
//! configuration for a Nitro Sandbox and the parent's pool accounting
//! (`config`), the probe's initrd (`initrd`), and on the parent (Linux) a
//! sandbox's life (`run`), what the parent can read (`scan`) and each
//! acceptance line's scenario (`scenarios`). The operator checks a
//! document with `sandcastle-nitro-spike verify`.

#[cfg(target_os = "linux")]
pub mod computer;
pub mod config;
#[cfg(target_os = "linux")]
pub mod guest;
pub mod initrd;
#[cfg(target_os = "linux")]
pub mod net;
#[cfg(target_os = "linux")]
pub mod run;
#[cfg(target_os = "linux")]
pub mod scan;
#[cfg(target_os = "linux")]
pub mod scenarios;
#[cfg(target_os = "linux")]
pub mod services;
pub mod sigv4;
