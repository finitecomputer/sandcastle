# The Nitro spike: a computer as a confidential Nitro Sandbox

> **This branch merges nowhere until the owner decides.** It is a spike in
> [krun-spike.md](krun-spike.md)'s sense: a lower-rung diagnostic that
> proves or disproves one design on real hardware and records the
> evidence. It is written to the engineering style, so what it proves can
> become the product without a rewrite.

*Plan, 2026-11-20 (the owner: "go ahead on the Nitro spike. for now if you
need to make changes to sandcastle / macrofiche / fpac / fragment do the
work in draft PR branches so it's obvious it relates to the spike").*

## Problem

The owner wants to offer agents whose computer runs in a TEE: neither the
cloud nor Finite's own operators can read it. AWS Nitro Sandboxes (GA
2026-11-10) let a parent EC2 instance start child VMs whose memory the
parent cannot read, with an attestation document and KMS key release.
That is sandcastle's shape: an engine on a host starting one microVM per
computer. FPAC (our lazy disk) now seals a computer's disk, and needs no
snapshots, which Nitro Sandboxes lack.

The question: can a computer (sandcastle's guest agent, a Hermes image, a
sealed FPAC disk) run as a **confidential** Nitro Sandbox on a parent we
treat as **untrusted**, wake at light speed (nothing added beyond the VM's
start and Hermes' own work), and prove what it is by attestation? And what
would sandcastle need to run this way for real?

## What was known going in (verify, don't trust)

From AWS's EC2 User Guide (`amazon-ec2-nitro-sandboxes.html`,
`nitro-sandboxes-run-firecracker.html`, `nitro-sandboxes-attestation.html`,
`nitro-sandboxes-numa.html`), re-read 2026-11-20, and Firecracker v1.18's
own `docs/nitro-sandboxes/` (read the same day). Items marked † come from
Firecracker's docs and were not in the plan.

- **Parent:** Nitro Enclaves enabled at launch (`--enclave-options
  Enabled=true`); AL2023 `kernel6.18` at 6.18.51-120.162 or later;
  Firecracker 1.18 or later, the only VMM that supports it (v1.18.0,
  2026-11-09, is the first); a memory pool reserved at boot
  (`nitro_enclaves.mempool=8G@0`); `/dev/nitro_enclaves` (root, 0660);
  slots in `/sys/class/misc/nitro_enclaves/pcie_slots` (4, then steps of 8,
  128 MiB of the pool a step, until the next reboot).
- **Launch:** Firecracker's JSON has an `enclave` key: `cpu_overcommit`,
  `direct_mode`, `hotplug_mode`, `debug_mode`, and † `cpu_accounting`,
  `cpu_ids`, `numa_nodes`; † unknown fields are rejected. `firecracker
  --no-api --config-file`; `drives` is required even if empty. The image
  is an EFI-stub kernel, an optional initrd and a command line, or an EIF
  built in advance (whose capability flags must match the launch's
  exactly). † Firecracker does not report the measurements of an EIF it
  builds.
- **Devices:** virtio-pci; block devices appear as `/dev/vda` on in
  configuration order; at most 32 devices with the vsock, hot-plugged ones
  included. † In confidential mode each device's virtqueues live in its
  own Device Memory Buffer (DMB), sized per device by `dmb_size_mib` (2 to
  256 MiB in steps of 2, 16 by default); setting one in direct mode fails.
  † virtio-rng exists in direct mode only (the Nitro System refuses it in
  a confidential sandbox), so a confidential guest's entropy is its own.
- **Guest kernel:** EFI stub, ACPI, PCIe, virtio-pci, and for confidential
  mode the DMB virtio patches. † AL2023's `kernel6.18` from 6.18.51-120.162
  carries them, and Firecracker's CI builds its 6.18 guests from Amazon
  Linux's tags with no patch of its own. `CONFIG_NSM=y` gives `/dev/nsm`
  († the NSM is virtio type 33, PCI `1af4:1061`).
- **Not there:** balloon, virtio-mem, pmem, vhost-user block, huge pages,
  CPU templates, SMT, dirty-page tracking, snapshot, pause, resume, live
  migration, GPU passthrough. Memory and vCPUs are fixed at launch
  (multiples of 2 MiB, 256 MiB at least).
- **Limits:** 5 sandboxes per parent vCPU, 896 per parent; 2 MiB of the
  pool a sandbox plus each device's DMB in confidential mode; without
  `cpu_overcommit` each vCPU takes a hardware thread and the parent's first
  core is reserved. † A parent's cgroup neither counts nor limits a
  sandbox's CPU time.
- **Attestation:** `/dev/nsm`; SHA-384 PCRs: 0 the image (kernel, command
  line, initrds, then the launch's feature flags); 1 kernel, command line,
  first initrd; 2 later initrds; 3 the parent's IAM role ARN; 4 the
  parent's instance id; 5 the PCI functions at boot (`HOTPLUG_ENABLED`
  with hot plug); 6 the whole image file; 16 to 31 extendable. Block
  devices are not measured. Debug mode zeroes 0, 1, 2, 5 and 6 (3 and 4
  keep the parent's values). The chain ends at the Nitro Enclaves root
  certificate. KMS takes `kms:RecipientAttestation:PCR<N>` and
  `:ImageSha384` (= PCR0) with `StringEqualsIgnoreCase`; Decrypt and
  GenerateDataKey with a `Recipient` answer `CiphertextForRecipient`,
  encrypted to the document's RSA key (`RSAES_OAEP_SHA_256`).
- **What the parent keeps:** it carries all device traffic, picks the
  image, and can read every block device it presents, decrypted EBS
  included. A sandbox NATed through the parent can reach the parent's IMDS
  (169.254.169.254) unless blocked; IMDSv2 and a hop limit of 2 do not stop
  it.
- **Where sandcastle trusts its host today:** the egress proxy decrypts
  traffic and fills in secrets on the host; the host engine can run any
  command in a computer; the host reads every disk. This spike measures
  and documents these. It fixes only the disk (a sealed FPAC disk).

## Acceptance

The spike is done when this document's Results section holds each of
these, measured on the instance (10 samples where cheap, median and
range), each with an evidence file under `docs/nitro-spike-evidence/`:

1. **Host.** One script takes a fresh AL2023 Graviton instance to "ready
   for sandboxes". Host facts recorded: kernel, Firecracker, pool, slots.
2. **Boot.** A minimal guest, launch to userspace: confidential and direct
   mode, `cpu_overcommit` on and off. This is the number AWS does not
   publish.
3. **What the parent sees.** A canary string in guest memory: found from
   the parent in direct mode, not found in confidential mode. State
   exactly what was tried; "not found" claims nothing more. A canary on a
   plain block device: found from the parent. The console: hidden.
4. **Attestation.** A document fetched in the guest with the caller's
   nonce, verified on the operator's machine down to AWS's root
   certificate (its fingerprint pinned from AWS's docs). The PCR table.
   The same image twice gives the same PCR 0, 1, 2, 6; a changed command
   line changes them; debug mode zeroes them.
5. **Key release.** A KMS key whose policy requires the image's PCR0: a
   Decrypt from inside the sandbox succeeds; from the parent without
   attestation, and from another image, it is denied.

   **Stop here and report** (lines 1 to 5).

6. **Our guest.** sandcastle's guest agent in the sandbox over vsock: an
   exec round trip, stdin, the exit code. The root is a Hermes image as a
   raw disk under dm-verity, its root hash on the command line, so PCR0
   covers the root; a changed byte of the root disk is refused.
7. **Network.** The guest reaches out only through a tap wired to
   sandcastle's egress proxy on the parent: an intercepted host answered
   by a handler; with the internet off, another name does not resolve;
   169.254.169.254 refused. Record that this proxy sees plaintext on the
   parent: leak 1, not fixed here.
8. **The sealed disk.** FPAC mounted in the guest with the key from line 5,
   its objects in an S3 bucket through a remote on the parent that answers
   FPAC's `docs/contract.md`. FPAC's conformance suite passes against that
   remote. The parent and the bucket hold ciphertext only (a canary check).
9. **The wake.** Launch, agent ready, FPAC mounted, Hermes' first reply
   with an instant fake model: from the second wake on, at 1 GB and 10 GB
   disks. And the sleep: the flush. Beside Cloudflare's (Hermes' first
   reply 8.5 s) and krun's (2.87 s) numbers from FPAC's `docs/results.md`.
10. **Density and cost.** An idle Hermes' resident memory inside. How many
    3 GiB and 6 GiB computers fit an 8-vCPU instance with the pool's
    overheads; how `cpu_overcommit` behaves with several busy guests;
    dollars per awake computer-month on demand.
11. **The build is clean.** New crates pass `cargo clippy --workspace
    --all-targets --all-features -- -D warnings` and `cargo test
    --workspace --all-features` on the instance (arm64) and build on x86
    with no AWS.
12. **Nothing left behind.** The inventory and the teardown's evidence, and
    the credits spent.

Then, in Results, **design with no code**: sandcastle's Firecracker
backend as a list of PRs with what each needs first; a design for each of
the three host-trust leaks (egress and credentials inside the boundary,
the control channel attested end to end, disks sealed with keys released
by attestation); rollback (a host serving an older valid disk); and what
this backend loses (memory given back, pause).

## Constraints

### Musts

- **Draft PRs only, named for the spike**, on branch `nitro-spike` in each
  repository the spike changes, titled `SPIKE (Nitro): …`, first line
  saying it merges nowhere until the owner decides. sandcastle's holds
  this document, the evidence, the host scripts and the spike's crates.
  FPAC's holds only what FPAC must change (an S3 remote, an arm64 build).
  Additive: the krun engine's path does not change.
- **fragment** changes nothing; a change it would need is described, not
  made.
- **Public repositories:** no project id, instance id, address, ARN,
  bucket name, key id, person's name or email in any commit, PR, doc or
  evidence file: they are redacted as `<project>`, `<instance>`,
  `<parent-ip>`. PCR3 and PCR4 are hashes of the parent's role ARN and
  instance id; an ARN's hash is open to a search over a project's twelve
  digits, so the evidence redacts them too.
- **Every AWS resource** is in the project's one Region (us-east-2),
  tagged `project=nitro-spike`, and inventoried as it is made;
  `crates/nitro-spike/host/teardown.sh` removes everything by that tag.
- **Money:** the instance is stopped whenever it will sit idle for 30
  minutes; the plan's remaining credits are read at each phase's end; under
  $50 left, stop and report; at the end everything is terminated unless the
  report says why it should stay.
- **The instance is reached** by SSH with a key of the spike's own, inbound
  22 from the operator's address only (or by SSM). No other inbound.
- **Builds run on the instance**, not on the operator's shared machine.
- **Commits** end with the co-author line; PR bodies open in plain words;
  explicit `git add` paths; no force-push.

### Must-nots

- No EKS or ECS: plain EC2 with our own Firecracker.
- No change to the project's plan, no "advanced features", no other
  Region, no support case, no upstream issue (drafted for the owner).
- No paid model calls; no registry installs or third-party code run on the
  operator's machine; nothing installed into its engine.
- Never merge, never mark a PR ready, never touch `main`.

### Preferences

- Graviton (`m8g.xlarge` to start; an 8-vCPU type only for line 10).
- A small Rust driver that writes Firecracker's configuration and times
  each step, so line 6 onward reuses sandcastle's crates.
- Upstream's arm64 Hermes image first; ours only if it is cheap.
- A verifier written to become celld's: a library with typed errors and
  valid, invalid, replay and restart tests.

### Escalations (stop, and say so)

- The plan or its policies refuse an API the spike needs.
- The guest cannot boot in confidential mode with a kernel we control.
- No attestation document can be had, or KMS refuses the condition keys.
- Anything that needs a person in the AWS console.
- Credits under $50.

## Layout

| Path | What | Tested where |
|---|---|---|
| `crates/nitro-attest` (`sandcastle-nitro-attest`) | The attestation verifier: COSE Sign1 with ES384, the chain to the pinned root, validity, freshness, a single-use nonce. Pure: the caller passes the time and the randomness. Written to become celld's. Its `nitro-verify` binary is the operator's check of a document. | Any host: 29 tests on self-made documents; real documents on the operator's machine (line 4) |
| `crates/nitro-probe` (`sandcastle-nitro-probe`) | The guest's probe: a static init (aarch64 musl, pure Rust) that says hello over vsock, holds canaries, asks its NSM for documents and opens KMS's CMS envelope; its protocol, the NSM's CBOR and the CMS walk | Any host: 9 tests (the NSM API's own encodings, OpenSSL-made envelopes); on Nitro: lines 2 to 5 |
| `crates/nitro-spike` (`sandcastle-nitro-spike`) | The driver: Firecracker's configuration and the pool's accounting (`config`), the probe's initrd (`initrd`), and on the parent a sandbox's life (`run`), what the parent can read (`scan`) and each line's scenario (`scenarios`: `boot`, `canary`, `attest`, `release`) | Any host: 7 tests; on Nitro: lines 2 to 5 |
| `crates/nitro-spike/host/parent-ready.sh` | Line 1: a fresh AL2023 parent to ready, then its facts as JSON | Run (line 1) |
| `crates/nitro-spike/host/guest-kernel.sh` | The guest kernel the spike controls (Amazon Linux's 6.18 tree, Firecracker's CI config, NSM, dm-verity) | Run: built in about 4 minutes on the parent |
| `crates/nitro-spike/host/teardown.sh` | Line 12: list or remove everything tagged for the spike | `list` run |

### Dependencies

- **Already in the lock**, now named in the workspace's dependencies at
  their locked versions: `ring` 0.17.14 and `rustls-webpki` 0.103.14 (with
  `rustls-pki-types` 1.15.1), which came with `rustls`; `rcgen` 0.14.10
  and `time` 0.3.55 (tests only), with the egress crate's CA; `base64`
  0.23.1 and `memchr` 2.8.3.
- **New, for the probe alone:** `rsa` 0.9.10, `aes` 0.8.4, `cbc` 0.1.2,
  and their 21 dependencies (RustCrypto's `der`, `pkcs1`, `pkcs8`, `spki`,
  `num-bigint-dig`, `cipher`, `rand_core` and the like). KMS encrypts to an
  RSA key (`RSAES_OAEP_SHA_256` is its only recipient algorithm) and CMS's
  content is AES-256-CBC, so the guest needs both. All pure Rust, so the
  probe links static for musl with no C toolchain; `ring` (which has C) is
  kept out of it. `rsa` 0.9 has a published timing side channel in
  decryption (RUSTSEC-2023-0071, "Marvin"): the probe opens one envelope
  per key and then drops the key, so a parent cannot use it as an oracle.
- **Written here, not pulled in:** the attestation document's CBOR reader,
  the two facts read from certificates' DER, the NSM's request and answer,
  and the CMS walk: each a small fixed schema, where a general crate would
  be more to audit than to write.

## How the engineering style applies

- **Limits, named and asserted:** a document 32 KiB, its payload 16 KiB,
  a certificate 1 KiB, the bundle 8, PCRs 32 of 48 bytes, a document's age
  5 minutes and its skew 1 minute, 256 nonces outstanding for 60 s each; a
  sandbox's memory, vCPUs, devices, DMBs, command line, socket path and
  ids, each at AWS's or Firecracker's documented limit. Each is a constant
  with its reason; tests hold each at its edge and one past.
- **Typed errors:** `AttestError` names every check (`RootNotPinned`,
  `Chain(webpki::Error)`, `Signature`, `Stale`, `NonceUnknown`, …), and
  `ConfigError` every limit; no `anyhow`.
- **No recursion; bounded loops:** the CBOR reader is schema-directed (the
  caller says what comes next), every count is checked against its limit
  before the loop that consumes it, and every string it returns is a slice
  of the input, so no length in a document makes it allocate.
- **Pure core:** the verifier takes the time and the nonce's randomness as
  inputs, so every test is deterministic in what it checks.
- **Assertions stay on:** the pinned root's fingerprint is asserted when
  the trust is built; what a parse produced is asserted on its way out.
- **Fail closed:** unknown payload keys, a non-empty unprotected header,
  any algorithm but ES384, a repeated field or PCR: refused. The nonce
  ledger lives in memory, so a restart forgets every nonce and a document
  answering one from before is refused; the guest asks again.

## Results

### Status (2026-11-20): lines 1 to 5 measured; stopped for review

| # | What | Result |
|---|---|---|
| 1 | Host | `parent-ready.sh` took a fresh `m8g.xlarge` (AL2023, kernel 6.18.62) to ready in two runs and one reboot: Firecracker v1.18.0, an 8 GiB pool in 16 regions, 3 vCPUs in the CPU pool, 4 of 20 slots |
| 2 | Boot | Launch to the guest's userspace, 512 MiB: **453 ms confidential, 304 ms direct** (medians of 10, with `quiet`); `cpu_overcommit` adds 2 to 5 ms. Without `quiet`, 1,193 and 1,048 ms: the guest writes its boot log to the serial port. About 60 ms more per GiB of guest memory |
| 3 | What the parent sees | Guest memory: **found** from the parent in direct mode; **not found** in confidential mode, where the parent reads the sandbox's pages as zeros. A plain block device: found in both. The console: hidden unless in debug mode |
| 4 | Attestation | Real documents with the caller's nonce, **verified on the operator's machine** down to the pinned AWS root. Same image twice: PCR 0, 1, 2, 5, 6 equal; a changed command line changes 0, 1, 6; debug mode zeroes 0, 1, 2, 5, 6 |
| 5 | Key release | A key whose policy requires image A's PCR0: **released to image A** and opened only inside it; **denied** to image B, to A in debug mode, to A with overcommit, and to the parent without attestation |

**Spent on lines 1 to 5:** the parent (`m8g.xlarge`, **$0.17952 an hour**
on demand in us-east-2, from AWS's price list) ran 25 minutes ($0.076);
its 60 GB gp3 root ($0.08 a GB-month), its public address ($0.005 an hour)
and the KMS key ($1 a month, prorated) add about half a cent. About $0.08
in all. The plan still reported $120.00 of credits at the stop (billing
lags). The parent is **stopped** (it then costs its disk alone, $0.0066 an
hour); the KMS key and the free resources stay for lines 6 on.

### Deviations from the plan, and why

1. **The plan was upgraded.** The first attempt was blocked by the free
   plan (below, "Before line 1"). After the owner's upgrade the first
   real launch was the proof it took: a dry run proves nothing here.
2. **The guest boots with `quiet`.** Firecracker's default command line
   leaves the guest printing its whole boot log to the serial console,
   which the Nitro System presents even outside debug mode (ACPI's SPCR
   table names it): 727 ms of an 820 ms kernel boot. `quiet` takes the
   kernel to its init in 80 ms. Line 2 reports both.
3. **The Decrypt is made by the parent, for the sandbox.** AWS's
   documented flow: the guest's attestation document goes to the parent,
   whose role calls KMS with it as the `Recipient`; KMS answers
   `CiphertextForRecipient`, a CMS envelope encrypted to the key inside
   the document, which only the guest can open. The parent sees the
   document (public) and the envelope, never the plaintext. The guest
   making the call itself (TLS it ends, through the parent) is the design
   for later lines, for the reason in line 5's results.
4. **The verifier changed when it met a real document.** Its first look
   refused it at the payload's first byte: the real NSM writes its payload
   as a CBOR map of indefinite length, which neither AWS's specification
   nor the NSM API's own encoding shows (`line4-before-the-fix.txt`). It now
   reads maps and arrays of either length, still bounded, and its test kit
   writes the real NSM's shape by default.
5. **`nitro-verify` moved into the verifier's crate**, so the operator's
   machine builds it from crates it already has; the probe's new crates
   build on the parent only.
6. **The probe is a crate of its own** (pure Rust, static musl), and
   reuses nothing from `sandcastle-guest`: lines 1 to 5 need a minimal
   guest; line 6 runs sandcastle's own.

### Line 1: the host (`line1-host.json`)

`parent-ready.sh` as root on a fresh `al2023-ami-kernel-6.18-arm64`
instance, launched with enclaves on:

- **First run** (24.7 s): build packages, Firecracker v1.18.0 checked
  against its pinned SHA-256, Rust 1.99.0 with the musl target, and the
  pool on the kernel's command line; then exit 3, asking for a reboot.
- **Reboot** (about 25 s), then **the second run**: the facts.

| Fact | Value |
|---|---|
| Instance | `m8g.xlarge`, 4 vCPUs (one thread a core), 15.3 GiB |
| OS, kernel | Amazon Linux 2023.12.20261120, 6.18.62-127.179.amzn2023 (the AMI's own; above 6.18.51-120.162) |
| Firecracker | v1.18.0 |
| Pool | `nitro_enclaves.mempool=8G@0`: "8192 MiB reserved in 16 region(s)"; 4 MiB in use before any sandbox (the slots' own) |
| CPU pool | 3 vCPUs (the first core is the parent's) |
| Slots | 4 of 20 |
| `/dev/nitro_enclaves` | root:root, 0660 |

### Line 2: boot (`line2-*.json`)

The driver's clock, from spawning Firecracker to the probe's vsock dial
(its first act as init), and the guest's own boot clock when its init
began. Our kernel (`guest-kernel.json`), the probe's initrd
(`probe-images.sha256`), 2 vCPUs, 512 MiB, a vsock and no other device,
n = 10 each, median (range), ms.

| Mode | `cpu_overcommit` | Spawn to userspace | Guest kernel to init | Power-off to Firecracker's exit |
|---|---|---|---|---|
| Confidential | off | **453.2** (449.1–457.8) | 80 (76–81) | 82.4 |
| Confidential | on | **455.6** (451.2–476.9) | 80 (78–86) | 84.5 |
| Direct | off | **303.8** (297.6–306.8) | 80 (74–80) | 79.2 |
| Direct | on | **308.8** (302.5–317.2) | 80 (77–83) | 82.4 |
| Confidential, without `quiet` | off | 1,193.1 (1,184.1–1,204.9) | 821.5 (814–827) | 82.4 |
| Confidential, without `quiet` | on | 1,220.4 (1,200.7–1,226.1) | 839 (828–841) | 82.5 |
| Direct, without `quiet` | off | 1,047.8 (1,043.7–1,051.9) | 819.5 (811–822) | 84.4 |
| Direct, without `quiet` | on | 1,064.3 (1,048.5–1,073.7) | 832.5 (819–841) | 82.2 |

**By memory** (with `quiet`, overcommit off, n = 5): it grows about 60 ms
a GiB in both modes, so a 6 GiB Hermes computer starts its kernel about
0.8 s after the launch.

| Mode | 512 MiB | 2 GiB | 6 GiB |
|---|---|---|---|
| Confidential | 453.2 | 544.9 (544.0–549.9) | 802.6 (801.5–1,018.3) |
| Direct | 303.8 | 396.6 (395.3–398.5) | 630.7 (627.4–637.3) |

**Where a confidential launch's 453 ms go** (Firecracker's own log, one
launch, `line2-confidential-firecracker.log`): spawn to "Enclave started",
53 ms (the 512 MiB CMA allocation 24 ms, the image loaded and the memory
donated 11 ms, the vsock's 16 MiB DMB 1.5 ms); then 398 ms to the guest's
vsock driver ready, of which the kernel is about 80 ms and the rest the
Nitro System's UEFI firmware ("UEFI firmware (version built at 09:00:00 on
Nov 1 2018)"). Direct mode's 150 ms less is in that firmware's part.

**The pool, as accounted:** what `mem_pool/in_use` read with one sandbox
up is the memory, 2 MiB, 16 MiB for the vsock's DMB in confidential mode,
and the 4 MiB in use before: 534 MiB at 512 confidential, 2,070 and 2,054
at 2 GiB, 6,166 and 6,150 at 6 GiB. The configuration writer's
`pool_mib()` predicts each to the MiB (less the 4 MiB base).

### Line 3: what the parent sees (`line3-canary-*.json`)

The probe filled 64 MiB of fresh memory with a random canary, wrote a
second canary to the console and a third over the first MiB of a plain
virtio disk (a 64 MiB file on the parent). Then, as root on the parent,
with the sandbox running:

| Where the parent looked | Direct | Confidential |
|---|---|---|
| Firecracker's mapping of the guest's memory | `512 MiB rw-s /dev/nitro_enclaves` | `512 MiB ---s /dev/nitro_enclaves` (no access) |
| Firecracker's memory: every readable mapping, through `/proc/<pid>/mem` | **found** (24,546 matches in 542 MB) | not found (0 in 39 MB) |
| Firecracker's no-access mapping, read anyway through `/proc/<pid>/mem` | (readable above) | not found: all 512 MiB read, **every byte zero** |
| All of the parent's System RAM, through `/proc/kcore` (16.9 GB) | **found** (24,547) | not found (0) |
| The disk's backing file | **found** (409) | **found** (409) |
| The console, in Firecracker's log | hidden | hidden; shown in debug mode (the control) |

A "match" is the canary repeated 64 times (2.6 KB); the parent holds the
text itself once in its command and once in the scanner's needle, so a
count of one or two is its own copies. The parent stayed up through every
read (its kernel panics on an oops here, `panic_on_oops=1`).

**What this claims, and no more:** with a confidential sandbox running,
the parent's root reads its pages as zeros through Firecracker's process
and through the kernel's view of RAM, and finds no copy of the guest's
memory anywhere in RAM. It does not claim that no other route exists (DMA
from a device, the hypervisor, a cold-boot attack); those are AWS's
claim, not measured here. A plain disk is the parent's to read in either
mode, as AWS says: line 8's sealed disk is the answer.

### Line 4: attestation (`line4-*.json`)

The probe asked its NSM for a document carrying a fresh 32-byte nonce the
driver drew; the NSM answered in 2 ms. Each document (4,492 bytes) was
copied to the operator's machine and checked there by `nitro-verify` with
its nonce, about 106 s after it was made: **all five verified** down to
the root pinned by AWS's fingerprint.

A real document, as seen: a bare COSE_Sign1; the protected header
`{1: -35}`; the payload's map of indefinite length; PCRs 0 to 15 listed
(16 to 31 not); a 639-byte signing certificate named for the parent's
instance and its enclave, valid for 3 hours, key usage `digitalSignature`
and `nonRepudiation`, no extended key usage; a bundle of four (the
533-byte root, then three intermediates).

| PCR | What it measures | Image A | Image A again | Image B (`nitro.spike=b` added) | A, `cpu_overcommit` | A, debug mode |
|---|---|---|---|---|---|---|
| 0 | the image and the launch's flags | `e2c83d2a…` | same | `a8f73fcc…` | `d86ab99f…` | zero |
| 1 | kernel, command line, first initrd | `dfaf53ed…` | same | `7d48c5a7…` | same as A | zero |
| 2 | later initrds (none) | `21b9efbc…` | same | same | same | zero |
| 3 | the parent's role ARN | `<parent>` | same | same | same | same as A |
| 4 | the parent's instance id | `<parent>` | same | same | same | same as A |
| 5 | the PCI functions at boot | `271079fe…` | same | same | same | zero |
| 6 | the whole image file | `ad4f8f8a…` | same | `00100757…` | `75a32f28…` | zero |
| 7 to 15 | (not set) | zero | zero | zero | zero | zero |

- **The same image twice** gives the same PCR 0, 1, 2, 5 and 6 (and 6
  too: Firecracker builds the same image file from the same inputs).
- **A changed command line** changes 0, 1 and 6; 2 is the same, since
  there is one initrd. Its value, `21b9efbc…`, is AWS's own example's:
  the measurement of no second initrd.
- **`cpu_overcommit`** changes 0 and 6 and not 1: PCR0 records the
  launch's flags, as AWS's table says.
- **Debug mode** zeroes 0, 1, 2, 5 and 6; 3 and 4 keep the parent's.
- **PCR3 and PCR4** are SHA-384 of 48 zero bytes and then the role's ARN
  or the instance's id, in all five (AWS's formula, checked against the
  real ARN and id on the operator's machine and redacted here).
- **Refused, on a real document:** a changed byte in the bundle, in the
  signature or in the signing certificate; the other launch's nonce; the
  document an hour later (its age); a day later (the signing
  certificate's 3 hours).
- **Fail first:** before the change in deviation 4, every real document
  was refused at the payload's first byte; after it, all five verify. The
  verifier's tests now include both lengths of the payload's map.

### Line 5: key release (`line5-*.json`)

The key's policy (`line5-kms-key-policy.json`, redacted): the project's
administrators may manage and encrypt but never decrypt, grant or
re-encrypt; the parent's role may `Decrypt` and `GenerateDataKey` only
when `kms:RecipientAttestation:PCR0` is image A's. KMS took the condition
key. The secret: 32 random bytes made on the operator's machine, encrypted
there under the key, then shredded; only its SHA-256 (`ac756507…`) was
kept, so the parent never had it.

| Decrypt | Recipient | Result |
|---|---|---|
| The parent's role, for image A | image A's document, with its RSA key | **Allowed.** KMS answered only `CiphertextForRecipient`; the probe opened it: 32 bytes, SHA-256 `ac756507…`, the secret's |
| The parent's role, for image B | image B's document | **Denied** (`AccessDeniedException`) |
| The parent's role, for image A in debug mode | its document (PCR0 zero) | **Denied** |
| The parent's role, for image A with `cpu_overcommit` | its document (another PCR0) | **Denied** |
| The parent's role, alone | none | **Denied** |

In the guest: a fresh RSA-2048 key took 355 ms, the NSM 2 ms. The key
opens one envelope and is dropped.

**What this does not give, found here:** the envelope authenticates
nothing. Anyone who sees the document, the parent included, can seal an
envelope of its own to the public key the document carries, and the
guest cannot tell it from KMS's. So the parent cannot read what KMS
releases, but it can hand the guest a value of its choosing instead. A
guest can trust a released secret only by how it uses it (a disk key that
opens the disk's own seals proves itself; a new disk's key does not), or
by calling KMS over TLS it ends itself, the parent relaying only bytes.
Line 8's key, and the design for disks sealed with keys released by
attestation, have to take the second way or generate the key inside.

### Before line 1: blocked by the free plan (2026-11-20, resolved)

The project was first on AWS's free plan, which launches only
free-tier-eligible types; in us-east-2 none of the ten supports Nitro
Enclaves (`free-tier-types.txt`), and the launch was refused: "The
specified instance type is not eligible for Free Tier"
(`blocked-launch.txt`). A dry run of the same launch answers "would have
succeeded": it checks the caller's permissions and the request's
parameters (it does refuse enclaves on a type without them), not the
plan. The owner upgraded the project to the paid plan the same day.

### Built before the instance, and how it held

- **The verifier** (`crates/nitro-attest`): built on self-made documents
  first (AWS publishes no sample; searched aws-nitro-enclaves-nsm-api,
  -cose, -sdk-c, -samples, -image-format). Six planted bugs, each caught
  by a named test (`planted-bugs.txt`). The real documents then found the
  one shape the fixtures lacked (deviation 4); nothing else changed.
- **The configuration writer**: launched every sandbox above; the pool's
  accounting held to the MiB.
- **The root, pinned from AWS's documentation** (`root-certificate.txt`):
  the certificate in `AWS_NitroEnclaves_Root-G1.zip` hashes to
  `641a0321…79bb5b`, the fingerprint on the Nitro Enclaves User Guide's
  "Verifying the root of trust" page; the zip to `8cf60e2b…faff7c`, as the
  NSM API's `docs/attestation_process.md` says. Every real document's
  bundle starts with it.

### Line 8, decided (the coordinator, 2026-11-20)

No S3 remote is built. FPAC's contract has the guest speak plain HTTP to
the platform's route and hold no credential; in the product that route is
the cell's, which has its own S3 client. So line 8 runs FPAC's test-kit
folder remote on the parent, reached over the sandbox's network, with its
per-object delay and put rate set from S3 round trips measured on the
parent (a small tagged bucket, removed at teardown). Every line-8 and
line-9 number that depends on it will say "modelled from measured S3
round trips".

### Acceptance so far

| # | What | Result |
|---|---|---|
| 1 | Host | **Pass** |
| 2 | Boot | **Measured**: 453 ms confidential, 304 ms direct |
| 3 | What the parent sees | **Pass**, with what was tried stated |
| 4 | Attestation | **Pass** on real documents |
| 5 | Key release | **Pass**; the envelope's lack of authentication recorded |
| 6 to 10 | Our guest, network, sealed disk, wake, density | Not started (waiting for "continue") |
| 11 | The build | The three new crates' tests and clippy (warnings denied) pass on arm64 (the parent) and the verifier's on x86_64 here; CI builds and tests the whole workspace on x86_64 |
| 12 | Nothing left behind | Not yet: the parent (stopped), its disk, the KMS key and four free resources, all tagged and inventoried |

### Gaps

- One instance type, one Region, one day. Boot times on other sizes and
  on x86 parents are not measured.
- The boot's firmware part (about 320 ms confidential) is attributed by
  subtraction, not by a timestamp of its own.
- Line 3's "not found" covers the routes stated; others are AWS's claim.
- Line 5's Decrypt was made by the parent for the guest (AWS's flow), not
  by the guest over its own TLS.
