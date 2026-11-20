//! The Nitro spike's guest probe (docs/nitro-spike.md, acceptance 2 to 5):
//! the init of a minimal guest, and everything it shares with the driver.
//!
//! - [`protocol`]: one vsock connection the guest dials, JSON lines, each
//!   command and answer typed and bounded.
//! - [`nsm`]: the Nitro Security Module's CBOR for an attestation request
//!   and its answer, pinned to the NSM API's own encoding.
//! - [`cms`]: opens KMS's `CiphertextForRecipient`, a CMS envelope
//!   encrypted to the key the guest put in its attestation document.
//! - `guest` (Linux): the init itself, run as PID 1 from the initrd.

pub mod cms;
pub mod nsm;
pub mod protocol;

#[cfg(target_os = "linux")]
pub mod guest;
