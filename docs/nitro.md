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
5. **The bridge** (`nitro/vsock-bridge`): the engine reached from a home
   that runs in a Nitro Sandbox of its own, over the home's vsock.

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

## Release assets

What a Nitro node runs beside sandcastle's own binaries, each pinned and
each built the same way every time, because each is measured:

- **The parent** (`nitro/parent-ready.sh`): a fresh Amazon Linux 2023
  Graviton instance, launched with enclaves on, to ready: kernel 6.18 at
  6.18.51 or later, the Nitro Enclaves memory pool on its command line,
  Firecracker v1.18.0 checked against its pinned SHA-256, the build tools,
  the slot budget, and `/dev/nitro_enclaves` in a group of its own (a udev
  rule), so a VM's jailed uid opens it as it opens `/dev/kvm` elsewhere.
  It prints the host's facts as JSON. Idempotent: run, reboot when it says
  so, run again.
- **The guest kernel** (`nitro/guest-kernel.sh`): Amazon Linux's 6.18
  tree at a pinned tag, Firecracker v1.18's CI config, and sandcastle's own
  lines (the NSM, dm-verity with `dm-mod.create=`, no modules). The build's
  user, host, time and counter are fixed, so the same source and config
  make the same bytes (the spike built it twice to the same SHA-256).
- **The initrd**: the engine makes it at open from its `guest` binary, as
  it makes the boot disk for libkrun: a newc archive with every owner,
  mode and time fixed (`sandcastle_rootfs::initrd`), so the same guest
  makes the same bytes.

PCR0 measures the kernel, the initrd and the command line; the command
line names the image's verity root hash. So a sandbox's PCR0 is a
function of the release (kernel and guest), the image's root, and the
launch's flags. A node builds an image's root in a build VM, as krun
nodes do, which is not byte-reproducible: two nodes' builds of one image
give two root hashes, each measured. Publishing one PCR0 per image needs a
deterministic build of the root; that is not done here.

## The runner

`sandcastle-vm` boots a Nitro Sandbox when its config carries a `nitro`
section: Firecracker v1.18 as the runner's child, inside the same jail,
in place of libkrun in the runner's own thread. Everything else the runner
does for libkrun it does unchanged, so the engine and its clients see one
VM either way:

- **The jail** binds Firecracker and the kernel from the node's lib dir,
  the initrd from the lib dir or the engine's state (the engine makes it),
  and `/dev/nitro_enclaves` in place of `/dev/kvm`, which a Nitro parent
  has none of. The VM's uid joins the device's group (`nitro_gid`); a node
  with none runs no Nitro Sandbox. libkrun's files are never bound then.
- **The disks** keep their order, so the guest's `wire::disks` hold: the
  first is the image's dm-verity hash tree (`DiskRole::Hashes`, read-only
  and shared) where libkrun has the boot disk, then the image, the scratch
  disk and the data disk.
- **The kernel's line** (`VmConfig::nitro_cmdline`) is spelled out whole,
  because PCR0 and PCR1 measure it: Firecracker's default, `quiet`, the
  verity table over the image with its root hash, the guest told to mount
  that device, then the node's tunings. A build has no root and no table.
- **Firecracker's config** (`firecracker.rs`, the spike's, which described
  its launches to the MiB) is written from the VM's: every DMB size in
  confidential mode, every enclave flag written, no drive the root device,
  the tap with the guest's MAC (the jail makes it a permanent neighbor).
- **The guest's channels:** Firecracker's vsock is a unix socket in the
  run directory. The guest's dial to the host's port 1025 reaches
  `v.sock_1025`, where the runner serves the lifecycle as it does for
  libkrun. `agent.sock`, which the engine's agent client opens, is a relay:
  each connection becomes `CONNECT 1024` on Firecracker's vsock, its `OK`
  read a byte at a time (what follows is the agent's), then a plain
  stream.
- **Control:** a Nitro Sandbox has no pause, so pause and resume answer an
  error; kill ends the runner, its PID namespace's first process, and
  Firecracker with it. The runner ends when Firecracker does, with its
  status.
- **Seccomp:** the runner installs libkrun's allowlist only for libkrun.
  Firecracker installs its own filter on its threads; the runner's own
  threads (lifecycle, relays, forwarder) run unfiltered in the jail. An
  allowlist for them, installed after Firecracker starts, is not done.

## The engine

A node is krun's or Nitro's by its config: `nitro` (`{}` takes every
default) names Firecracker and the kernel in `lib_dir`, the launch's mode
(confidential unless set) and `cpu_overcommit`. The API is unchanged:
celld's `CELLD_CONTAINER_ENGINE=krun:<socket>` reaches it as it reaches a
krun node.

- **At open** it needs `/dev/nitro_enclaves` in a group of its own (not
  root's) instead of `/dev/kvm`, and makes the guest's initrd from its
  `guest` binary instead of the boot disk.
- **Images** are built in a build VM as on krun, the build VM a Nitro
  Sandbox in direct mode (the layers are no secret, and untrusted layers
  are never unpacked on the host). Then the host formats the root's
  dm-verity tree (`veritysetup format`, `sandcastle_rootfs::verity`) and
  keeps its table in the image's record. An image built before the node
  ran Nitro is built again at its next load; a start on one is refused,
  typed.
- **A start** boots the image's measured root: its hash tree first, its
  table on the kernel's line, a vsock CID of the slot's own (3 plus the
  slot), no balloon (a sandbox's memory is the pool's until it stops).
  Memory under 256 MiB or odd is refused before anything is reserved.
- **Snapshots** freeze the guest's filesystems through its agent and copy
  the scratch disk, as on krun. The parent can read that copy: the
  scratch disk is not sealed here.
- **Capacity:** `memory_mib_max` is the operator's, sized to the pool
  less each sandbox's overheads (2 MiB and 16 MiB a device in confidential
  mode; the spike's line 10).

## The bridge

A home (celld and the cell) may run in a confidential sandbox of its own
on the parent that runs its computers. celld reaches the engine through
`sandcastle-bridge`, one binary in two halves, so celld and the engine are
unchanged:

- **home**, in the home: `engine.sock` and `ports.sock` in `/run/sandcastle`
  (`CELLD_CONTAINER_ENGINE=krun:/run/sandcastle/engine.sock`). Each
  connection becomes a vsock stream to the host: port 5000 the engine's
  API, 5001 `ports.sock`. It listens on its own vsock port 5002 for the
  intercepts and dials celld's intercept socket (`--intercepts`).
- **parent**, beside the home's Firecracker: it listens on the home's
  `<uds>_5000` and `<uds>_5001` (where Firecracker hands the home's dials)
  and dials the engine, and listens at celld's intercept path on the
  parent, where the engine dials it, each connection a `CONNECT 5002` into
  the home.

The API and the intercepts are bytes. `ports.sock` hands a connected
socket over, which no vsock can carry: the parent takes the engine's
socket and relays it on the stream the request came on, after the reply
(framed by its length); the home hands celld one end of a socketpair and
relays the other, saying `transport: "vsock"` as the engine does of its
own unix sockets. Every connection is a relay of its own, at most 1024
live per listener. The intercept path is celld's
`<data dir>/intercepts-<6 hex of sha256(node)>.sock`: run the home's celld
with a fixed `CELLD_NODE` and give both halves that path.

## What the parent can still see and do

A confidential sandbox keeps its memory from the parent. Everything that
crosses the sandbox's edge, the parent still holds. As built here, for a
computer:

**It sees:**

1. **Intercepted traffic, in plain text.** The egress proxy runs in the
   engine, on the parent, and terminates TLS for every intercepted host
   with the node's CA. On a Fragment node those are the platform's API,
   the model routes and the saves (`backups.sandbox.internal`): the
   agent's conversations, its tool calls and its saved files all pass
   through it. Hosts that are not intercepted are spliced, so the parent
   sees their names and sizes but not their contents.
2. **Exec and terminals.** `agent.sock` is relayed on the parent: every
   `exec()` (the saves' shim included), its output and a terminal's
   keystrokes.
3. **Ports.** A connection to a computer's port (the screen's VNC, an
   app) is the engine's TCP socket: the parent sees its bytes.
4. **Disks.** The scratch and data disks are plain ext4 files on the
   parent, readable while the computer runs and after. Snapshots copy the
   scratch disk. Only the image is protected, and only its integrity
   (dm-verity): its contents are public anyway.
5. **Metadata:** when each computer starts and stops, its size, its DNS
   names, and the timing and size of everything above.

**It can:**

6. **Run commands in a computer.** The guest's agent serves any
   connection to its vsock port, and the parent can open one: this alone
   undoes the memory's protection.
7. **Change what it relays:** answer or alter an intercepted request, a
   disk's blocks (the scratch and data disks have no integrity), or an
   exec's output.
8. **Boot something else in a computer's place.** A computer's NSM signs
   its PCRs, but nothing checks them: no one asks a computer for its
   document before trusting it.
9. **Stop, refuse or slow anything** (availability is never protected).

**What closes each, later:** an attested channel from the home to each
computer (the guest makes a key, its NSM document binds it, the home
checks the PCRs before it talks to it) closes 6, 7 and 8 for exec, and
carries 1 to 3 end to end if the proxy's TLS ends in the guest or in the
home instead of on the parent. Disks encrypted by the guest, with a key
released to an attested guest only, close 4 (the sealed scratch disk,
not built here).

## Evidence

`docs/nitro-evidence/` holds one real run on a parent (an m8g.xlarge,
Amazon Linux 2023, kernel 6.18): celld's engine conformance suite
(`celld dev` with `CELLD_CONTAINER_ENGINE=krun:<engine.sock>`) against
this engine in Nitro mode, every sandbox confidential.

- `conformance-nitro.json`: 25 passed, 0 failed, 0 unsupported: start,
  ports, exec (output, stdin, PTY and resize, kill, abort), signals,
  HTTP and HTTPS intercepts (HTTPS needs the guest's NSM clock), snapshot
  and start from a snapshot.
- `engine-log.txt`: the engine's own lines for that run: the image's
  build VM applying its five layers and ending, then each sandbox's start
  (ready in about 500 ms) and end.

The run found three bugs, each fixed in the PR that owns it: the guest
rebooted where Nitro's Firecracker ends only on a power-off (the guest),
Firecracker's vsock dropped a host's close so a build's guest waited on
a closed connection (the runner), and a build whose client went away
left its build VM running and the build lock held (the engine).
