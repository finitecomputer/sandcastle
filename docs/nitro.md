# sandcastle on AWS Nitro Sandboxes

A node whose computers run as confidential Nitro Sandboxes: AWS's
Firecracker on an EC2 instance (the "parent") whose memory the parent
cannot read, each sandbox attested by a document its Nitro Security
Module signs. This is the backend the Nitro spike measured (sandcastle
draft PR #18, `docs/nitro-spike.md` there) built into sandcastle's own
engine, one PR at a time. celld reaches it exactly as it reaches the krun
engine: the same `engine.sock`, Cloudflare's container API.

The stack, each a draft PR on `node`:

1. **The guest** (`nitro/guest-boot`): sandcastle's guest boots a Nitro
   Sandbox. Below.
2. **Release assets** (`nitro/release-assets`): the parent's setup, the
   guest kernel and initrd, a measured image.
3. **The runner** (`nitro/firecracker-runner`): `sandcastle-vm` runs
   Firecracker inside its jail.
4. **The engine** (`nitro/engine-backend`): the engine picks krun or Nitro
   per node; images become measured roots.

## The guest

What a Nitro Sandbox changes for sandcastle's guest, and why:

- **It boots from an initrd.** Only the kernel, its command line and the
  initrd are measured into the sandbox's PCRs, so the guest's own binary
  must be in the initrd, not on a disk the parent could swap. The kernel's
  rootfs is where `pivot_root` (the workload's start) is refused, so the
  init first moves itself onto a tmpfs of its own and runs again from
  there (`sys::leave_initrd_root`). It tells an initrd by its root's
  filesystem type, not by its own name: krun runs it as `/init` too.
- **Its image is the device the command line names**
  (`sandcastle.image=/dev/dm-N`, once), a dm-verity device the kernel
  makes from `dm-mod.create=` on that same command line. The root hash is
  measured with the command line, so the measured kernel line decides
  which root boots, never the runner's start message. A name that is not
  a device-mapper node is refused, not ignored. With no such word, the
  krun path's `/dev/vdb` is unchanged.
- **Its clock comes from its NSM.** A confidential sandbox boots at 1970,
  with no clock the parent sets (and none it could be trusted to set).
  The NSM signs the time into every attestation document, so the guest
  asks `/dev/nsm` for one with a random nonce and sets its clock from the
  document's `timestamp`, right after its lifecycle hello and before its
  start: before anything checks a certificate. A guest with an NSM that
  cannot give a plausible time fails its boot there, typed, rather than
  later as a TLS error in the workload. The document is read, not
  verified: the guest reads its own NSM, and verifying documents is the
  operator's job (`nsm.rs`).
