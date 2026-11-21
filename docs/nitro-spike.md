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
| `crates/nitro-attest` (`sandcastle-nitro-attest`) | The attestation verifier: COSE Sign1 with ES384, the chain to the pinned root, validity, freshness, a single-use nonce. Pure: the caller passes the time and the randomness. Written to become celld's. Its `nitro-verify` binary is the operator's check of a document; `read_unverified` is a guest's read of its own document's time. | Any host: 30 tests on self-made documents; real documents on the operator's machine (line 4) |
| `crates/nitro-probe` (`sandcastle-nitro-probe`) | The guest's probe: a static init (aarch64 musl, pure Rust) that says hello over vsock, holds canaries, asks its NSM for documents and opens KMS's CMS envelope; its protocol, the NSM's CBOR and the CMS walk | Any host: 9 tests (the NSM API's own encodings, OpenSSL-made envelopes); on Nitro: lines 2 to 5 |
| `crates/nitro-spike` (`sandcastle-nitro-spike`) | The driver: Firecracker's configuration and the pool's accounting (`config`), the probe's initrd (`initrd`), and on the parent a sandbox's life (`run`), what the parent can read (`scan`) and lines 2 to 5's scenarios (`scenarios`). From line 6: a computer with sandcastle's guest (`guest`: its lifecycle and agent over vsock), its tap (`net`), the parent's services (`services`: the egress proxy, the stand-in model and handler, the KMS signer), SigV4 (`sigv4`), and lines 6 to 10's scenarios (`computer`: `agent`, `network`, `lives`, `conformance`, `forged`, `hold`, `exec`, `density`, `busy`) | Any host: 12 tests; on Nitro: lines 2 to 10 |
| `crates/nitro-key` (`sandcastle-nitro-key`) | In the guest: the disk's key from KMS over TLS it ends itself, Amazon's roots pinned; the clock from the NSM | Any host: its tests; on Nitro: line 8 |
| `crates/guest` (changed) | Boots as an initrd's init (leaves the initramfs's root), its root named by `sandcastle.image=` | Its tests; on Nitro: line 6 |
| `crates/vm` (changed) | Builds on arm64: seccomp lists for x86_64 only, failing closed elsewhere | Its tests |
| `crates/nitro-spike/host/parent-ready.sh` | Line 1: a fresh AL2023 parent to ready, then its facts as JSON | Run (line 1, and line 10's resize) |
| `crates/nitro-spike/host/guest-kernel.sh` | The guest kernel the spike controls (Amazon Linux's 6.18 tree, Firecracker's CI config, NSM, dm-verity, `dm-mod.create=`, writes to mounted block devices), built to the same bytes each time | Run: built in about 4 minutes on the parent, twice to the same bytes |
| `crates/nitro-spike/host/verity-image.sh` | An image's root as a raw ext4 disk with its verity tree, built to the same bytes each time; its table and root hash as JSON | Run (line 6) |
| `crates/nitro-spike/host/nitro-entrypoint.sh` | The image's entrypoint: the clock, the key, FPAC's mount at Hermes' home, then Hermes | Run (lines 6 to 10) |
| `crates/nitro-spike/host/teardown.sh` | Line 12: list everything tagged for the spike, or remove all of it or the types named | `list` and `delete s3-bucket` run |
| `crates/nitro-spike/host/cold-reads.py`, `cold-entry.sh` | Line 9's cold-read study: one computer a sample on the plain disk, a cold, warm and cache-dropped `hermes chat` or a gateway's first reply, under the driver's study settings (`--mode direct`, `--root linear`, `--entrypoint-file`, `exec --stdin`) and the guest's sysfs ones | Run (line 9, 2026-11-21) |

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

### Status (2026-11-21 UTC): all twelve lines measured, the design written; the parent stopped

| # | What | Result |
|---|---|---|
| 1 | Host | `parent-ready.sh` took a fresh `m8g.xlarge` (AL2023, kernel 6.18.62) to ready in two runs and one reboot: Firecracker v1.18.0, an 8 GiB pool in 16 regions, 3 vCPUs in the CPU pool, 4 of 20 slots |
| 2 | Boot | Launch to the guest's userspace, 512 MiB: **453 ms confidential, 304 ms direct** (medians of 10, with `quiet`); `cpu_overcommit` adds 2 to 5 ms. Without `quiet`, 1,193 and 1,048 ms: the guest writes its boot log to the serial port. About 60 ms more per GiB of guest memory |
| 3 | What the parent sees | Guest memory: **found** from the parent in direct mode; **not found** in confidential mode, where the parent reads the sandbox's pages as zeros. A plain block device: found in both. The console: hidden unless in debug mode |
| 4 | Attestation | Real documents with the caller's nonce, **verified on the operator's machine** down to the pinned AWS root. Same image twice: PCR 0, 1, 2, 5, 6 equal; a changed command line changes 0, 1, 6; debug mode zeroes 0, 1, 2, 5, 6 |
| 5 | Key release | A key whose policy requires image A's PCR0: **released to image A** and opened only inside it; **denied** to image B, to A in debug mode, to A with overcommit, and to the parent without attestation |
| 6 | Our guest | sandcastle's guest agent as init, Hermes' image as the root under dm-verity (its root hash on the measured command line): ready **927 ms** after spawn, an exec round trip **0.5 ms**; stdin and exit codes right; a changed byte of the root refused (EIO) |
| 7 | Network | Through sandcastle's egress proxy on the parent: an intercepted host answered by the handler; internet off; the metadata service and the parent's own address refused. Leak 1 recorded: the proxy reads intercepted traffic |
| 8 | Sealed disk | The key reaches the guest **only over TLS the guest ends**, Amazon's roots pinned; the parent signs a hash and carries bytes, and **cannot choose or learn the key** (a forged envelope and an intercepting CA both refused). FPAC's conformance **19 of 19**; the canary **0** in the store and the scratch disk, against 15 to 18 with no key (modelled from measured S3 round trips) |
| 9 | Wake | From the second wake on: FPAC mounted **1.13 s** after spawn at 1 GB, 1.23 s at 10 GB (n = 5); Hermes' first one-shot reply 14.3 s, about 9 s of it Hermes starting its gateway (not reads: corrected 2026-11-21). Through its gateway, as FPAC measured: **11.5 s**, of which Nitro's own share is about 0.3 s (modelled from measured S3 round trips) |
| 10 | Density and cost | An idle Hermes: 238 MiB resident, but its 3 GiB stay taken. On an 8-vCPU `m8g.2xlarge`: **8 computers of 3 GiB or 4 of 6 GiB** (3 without overcommit); **$32.76 and $65.53 per awake computer-month** on demand |
| 11 | Build | Workspace clippy (warnings denied) clean and **147 of 147 tests** on arm64, after two small fixes; x86_64 by CI |
| 12 | Left behind | The S3 bucket removed; the parent **stopped** and its KMS key kept, by decision: **about $5.80 a month** |

**Spent on lines 1 to 5:** the parent (`m8g.xlarge`, **$0.17952 an hour**
on demand in us-east-2, from AWS's price list) ran 25 minutes ($0.076);
its 60 GB gp3 root ($0.08 a GB-month), its public address ($0.005 an hour)
and the KMS key ($1 a month, prorated) add about half a cent. About $0.08
in all. The plan still reported $120.00 of credits at the stop (billing
lags). The parent is **stopped** (it then costs its disk alone, $0.0066 an
hour); the KMS key and the free resources stay for lines 6 on.

**Spent in all, lines 1 to 12:** the parent ran about 122 minutes as
`m8g.xlarge` ($0.17952 an hour: $0.36) and 6.4 minutes as `m8g.2xlarge`
for line 10 ($0.35904 an hour: $0.04). Its disk, its public address
while running, the KMS key (prorated), about fifty KMS calls and the S3
timing bucket add about $0.07. **About $0.47 in all.** The plan still
reports $120.00 of credits (billing lags), well above the $50 line. The
parent is stopped.

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
7. **Line 8's key and store changed by decision** (the coordinator,
   2026-11-20): the key comes over TLS the guest ends, from
   `GenerateDataKey` and `Decrypt` with the guest's document as the
   recipient, not line 5's key; the store is FPAC's folder remote on the
   parent with S3's measured round trips, not objects in an S3 bucket.
8. **Hermes' first reply is a one-shot `hermes chat`**, not a message
   through its gateway: upstream's image has no fragment bridge, and the
   one-shot needs no platform configured. FPAC's numbers it is set beside
   go through the gateway (line 9 says what differs).
9. **Scratch disks moved off the parent's `/run`.** They were sparse files
   on a tmpfs of a fifth of the parent's memory (3.1 GiB). The first 10 GB
   fill filled it, the guest's scratch ext4 got write errors and went
   read-only, and FPAC fenced itself ("the cache file: Read-only file
   system"), as it should. They are now on the parent's disk, and each
   life's is deleted after its scan.
10. **Line 10's 8-vCPU numbers** come from the same instance resized to
    `m8g.2xlarge` for that line alone.

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

**Who can change the rule: anyone who administers the project.** The
policy's first statement gives the project's administrators `kms:Put*`,
which is `PutKeyPolicy`. So whoever administers the AWS project can
rewrite the release rule at any time, in one call. They could drop the
PCR0 condition, or add another image's PCR0, and then decrypt every
wrapped key the parent keeps. AWS can too. The rule holds only because
we choose to keep it. It is not a promise our users can check, and it
does not meet "repair access is the user's decision, never ours alone".
The design (below, "A release rule we cannot change alone") says what
would close this. Nothing here changes it.

### The guest kernel, built to the same bytes (`guest-kernel.json`)

The kernel used to name the parent's host in its version string (`uname
-v`, and the boot log of `line2-confidential-debug-console.log`, now
scrubbed as `<parent-host>`). `guest-kernel.sh` now fixes the build's
user, host, counter and time (`KBUILD_BUILD_USER=builder`,
`KBUILD_BUILD_HOST=nitro-spike`, `KBUILD_BUILD_VERSION=1`, the time the
source tag's own commit date) and sets `LOCALVERSION` empty. **Built twice
from a clean tree, the two images were byte-identical** (SHA-256
`fed9687f…`, `kernel-twice.txt`). PCR0 is a function of the image, the
initrd, the command line and the launch's flags (line 4: the same inputs
twice gave the same PCR0), so the same source and config give the same
PCR0 on any machine. The final kernel adds one line to the config
(`CONFIG_BLK_DEV_WRITE_MOUNTED`, line 8) and is a third build of the same
script (`09f1ba2c…`); it was not built twice.

### Line 6: our guest (`line6-agent.json`)

sandcastle's own guest agent is the sandbox's init, reached by
sandcastle-vm's own client over vsock. The root is upstream Hermes'
arm64 image (v0.23.2, plus e2fsprogs for FPAC's `mkfs`) as a raw ext4
disk under dm-verity. `verity-image.sh` builds it the same way each time
(a fixed time, UUID, hash seed and salt). The hash tree is on a second
disk, and the verity table, root hash included, is on the measured
command line (`dm-mod.create=`). So PCR0 covers every byte of the root.
One launch, 2 vCPUs, 4 GiB:

| What | Result |
|---|---|
| Spawn to the agent's hello over vsock | 904 ms |
| Spawn to ready | 927 ms (the guest's own uptime at ready: 124 ms) |
| An exec of `true`, round trip | **0.5 ms** median (0.5–7.2), n = 20 |
| stdin | echoed back exactly |
| An exit code | 7, with stdout and stderr apart |
| The root | `/dev/dm-0`: verity over the image disk, the tree on the other |
| A changed byte of the root disk | **refused**: one bit flipped in the image on the parent (inside a file planted for it, found with `debugfs`); reading that file gives EIO, the kernel logs "data block 567496 is corrupted", and another file still reads. The byte was put back after |
| PCR0 of this image | `0cfbaab0…`; the key's policy names it from here on |

The image's record is `line6-image.json`. Its `tree_bytes` is the size of
the root's files, a misnamed field, now `files_bytes` in the script.

Four things sandcastle's guest needed here, each a fact about the
platform:

- **It boots as an initrd's init.** `pivot_root` refuses an initramfs's
  root, so the guest first moves itself onto a tmpfs and runs itself again
  (`sys::leave_initrd_root`). It tells an initramfs by the root's
  filesystem type, not by its own name: krun runs it as `/init` too.
- **The root is the device the command line names** (`sandcastle.image=`,
  only `/dev/dm-N`, only once), so the measured line decides it, not the
  parent.
- **A confidential guest has no clock.** It boots at 1970, and TLS then
  refuses every certificate as not yet valid. `nitro-key settime` sets the
  clock from the NSM's document, which is the hypervisor's signed time,
  never the parent's word. Here that was 961 ms after spawn.
- **sandcastle-vm builds on arm64.** Its seccomp lists name x86_64 calls
  only. On other architectures the lists are now empty, and the filter's
  first check (x86_64's audit architecture) kills a krun jail at its first
  call: it fails closed until lists are gathered for arm64. The spike uses
  only the crate's client.

### Line 7: the network (`line7-network.json`)

The guest's one NIC is a tap on the parent (`nitrotap0`). nftables there
sends all of its TCP and DNS to sandcastle's egress forwarder and proxy,
as on krun. The policy: the internet off, KMS's host allowed (spliced, not
opened), and three intercepts: `https handled.example.com`, `http
fpac.fragment.internal` (line 8's store), `http model.example.com` (the
stand-in model).

| From the guest | Result |
|---|---|
| `https://handled.example.com/through/the/proxy` | **answered by the handler** on the parent, through the proxy's TLS (the guest trusts the proxy's CA, which is handed to it at the start) |
| `http://model.example.com/v1/models` | answered by the stand-in model |
| `example.org`, internet off | does not resolve (the proxy refuses the name) |
| `1.1.1.1:80` by address | refused: "the internet is off" |
| `169.254.169.254` (the parent's metadata service) | **refused**: "not a public address" |
| The parent's own address, port 22 | refused: "the node's own address" |
| `kms.us-east-2.amazonaws.com` | resolves (to the proxy's own address range), spliced through as bytes |

**Leak 1, recorded, not fixed:** this proxy runs on the parent. For an
intercepted host it ends the guest's TLS with its own CA and reads every
request in plaintext; the handler's answer above echoes the path it saw.
Only a spliced host (KMS here) passes as bytes it cannot read. The design
below moves it inside the boundary.

### Line 8: the sealed disk

**The key** (`lives-sealed-1gb.json`, `line8-forged-old-flow.json`,
`line8-intercept-kms.txt`, `line8-kms-key-policy.json`).

The disk key now reaches the guest only over TLS that ends inside the
guest. `nitro-key` (in the measured image) makes a fresh RSA-2048 key and
an NSM document carrying it. Then it calls KMS itself: rustls, with only
Amazon's five roots trusted (Amazon Root CA 1 to 4 and Starfield Services
G2, picked from `webpki-roots` and asserted by count), to
`kms.us-east-2.amazonaws.com`. The TCP goes through line 7's egress path,
where KMS is a spliced host: a tunnel the parent carries and does not
open. Which KMS key it uses comes from the measured command line
(`nitro.kms_key=`), never from the parent.

- **A new disk:** `GenerateDataKey` with the guest's document as the
  `Recipient`. KMS answers the wrapped key (`CiphertextBlob`, which the
  parent keeps) and the key itself only as `CiphertextForRecipient`, an
  envelope to the guest's RSA key.
- **A wake:** `Decrypt` of the wrapped key the parent hands back, the
  same recipient rule.
- The guest opens the envelope and writes the key to a tmpfs file, mode
  0600, for FPAC's `--key-file`; FPAC reads it and removes it.

**Signing: the guest composes the request and the parent signs it.** That
was the smaller of the two options. The parent's signer (`sigv4.rs`, 115
lines with its tests, and about 80 lines in `services.rs`) gets only the
request's target and its body's SHA-256. It refuses any target but `Decrypt` and
`GenerateDataKey`, and signs with the role's short-lived credentials from
its metadata service. No credential ever enters the guest, and the guest
needs no STS or metadata client. AWS's own worked SigV4 example is the
signer's test. The guest's side, `nitro-key`, is 356 lines with its
tests. It uses rustls, ring and webpki-roots, already in the lock for the
egress proxy, and the probe's RSA and CMS code. No new dependency.

**What the parent can still do,** and what it cannot:

- **Refuse:** not sign, or not carry the bytes. The guest gets no key,
  FPAC never mounts, and the computer stops before its entrypoint (fail
  closed).
- **Delay:** hold the bytes. Each read waits at most 30 s
  (`IO_MS_MAX`); then the start fails as above.
- **Replay:** it cannot replay a request. It sees only TLS records of a
  fresh session, and a recorded session does not play into a new one.
  What it can replay is the **wrapped key**: it could hand back another
  disk's wrapped key under the same KMS key, and the guest would open
  that disk if the parent also serves its objects. Binding the disk's name
  as KMS encryption context closes this only when the guest learns which
  disk it should be from a party it trusts (the design: the attested
  control channel). Here the parent decides which disk the guest opens.
- **It cannot choose the key.** The guest trusts only an answer from
  KMS's own TLS. A forged envelope never reaches it, and when the proxy is
  told to intercept KMS's host with its own CA, the guest refuses: "invalid
  peer certificate: UnknownIssuer", no key, no mount
  (`line8-intercept-kms.txt`).
- **It cannot learn the key.** KMS releases it only inside an envelope to
  the RSA key in a document whose PCR0 the policy names. Only an NSM of a
  sandbox running that image makes such a document, and that image never
  exports its RSA key. The parent's role alone, or with a debug or other
  image's document, is denied (line 5). What the parent signed, in full:
  six records, each a target and a body's hash
  (`what_the_parent_signed`).

**Line 5's flow, kept as evidence of its weakness** (`line8-forged-old-
flow.json`): the parent never calls KMS. It seals a value it chose, with
OpenSSL, to the public key in the guest's own document. The guest of the
old flow opens it and takes it (SHA-256 `49405844…`, the parent's own
value). In the new flow there is no envelope from the parent to accept.
The guest reads KMS's answer only from inside its own TLS session.

**The store** (`line8-s3-rtt.json`, `line8-conformance.json`). As
decided, FPAC's test-kit folder remote runs on the parent (`fpac-bench
serve-folder`, a new subcommand in FPAC's branch), behind the egress
proxy's intercept for `fpac.fragment.internal`, so the guest reaches it
over its own network exactly as it would reach the platform's route. Its
per-object delay and put rate come from real S3 round trips measured from
the parent: a tagged bucket in us-east-2, SigV4 by curl.

| S3, from the parent | Measured |
|---|---|
| A 64 KiB ranged GET | first byte p50 23.5 ms, p99 37.2 ms; whole p50 25.3 ms (16.4–69.2), n = 59 |
| An 8 MiB PUT, one stream | p50 90.9 ms: 89.8 MB/s, n = 15 |
| 8 MiB PUTs, eight streams | 661.7 MB/s (32 puts in 0.41 s) |

So the folder remote ran with `object_ms` = 23 and `put_bytes_per_s` =
90,000,000 (one stream, the slower). Every number below that depends on
the store is **modelled from measured S3 round trips**.

| What | Result |
|---|---|
| FPAC's conformance suite, from inside the sandbox, through the egress path | **19 of 19 pass** (modelled from measured S3 round trips) |
| A canary written into the sealed disk: in the store's objects, on the parent | **0** in every life, n = 6 (`lives-sealed-1gb.json`) |
| The same canary on the guest's scratch disk (FPAC's cache file), on the parent | **0** in every life, n = 6 |
| The control: the same run with no key (FPAC plain) | **15 and 18** copies in the store, **9 and 3** on the scratch disk (`lives-plain-1gb.json`) |
| The canary read back on every wake | yes, 6 of 6 |
| The key across wakes | the same (its SHA-256, from the guest, equal in all 6 lives) |
| The parent holds | the wrapped key and ciphertext objects only |

Two fixes found on the way, kept as findings:

- **FPAC needs `CONFIG_BLK_DEV_WRITE_MOUNTED=y` in the guest kernel.**
  FPAC's daemon keeps its loop device open for writing while ext4 is
  mounted on it, and Firecracker's CI config turns that off (EBUSY at the
  mount).
- **A scan that cannot read is not a zero.** The first canary counts on
  the scratch disk read 0 even in the plain control, because the scan read
  each 24 GiB sparse image into memory and took the failure for "none".
  The scan now streams the file's data and skips its holes, fails loudly
  on any error, and has a test. The plain control above is what shows the
  scratch-disk count can be non-zero.

### Line 9: the wake (`lives-*.json`, `line9-hermes-cold-warm.txt`)

Each life is a new sandbox: a fresh scratch disk, the key from KMS
(`GenerateDataKey` on life 0, `Decrypt` after), FPAC's open and mount at
Hermes' home, then one `hermes chat` against the instant stand-in model,
then FPAC's sleep (SIGTERM, its last flush). 2 vCPUs, 4 GiB, a 40 GB
volume. Times are from Firecracker's spawn. Every number in this section
is **modelled from measured S3 round trips**, except the agent's ready
time and the key's.

| From the second wake on, median (range) | 1 GB disk, n = 4 | 10 GB disk, n = 5 |
|---|---|---|
| The agent ready | 738 ms (732–744) | 879 ms (725–892) |
| The key in hand (the clock, a new RSA key, the NSM, KMS over TLS) | 998 ms (958–1,153) | 1,115 ms (919–1,417) |
| FPAC mounted | **1,127 ms** (1,104–1,273) | **1,231 ms** (1,046–1,532) |
| FPAC's open: one round to the store | 23 asks, 40–63 ms; 29 map pages | 22 asks, 39–49 ms; 61 map pages |
| Misses before the reply | 0 | 0 |
| Hermes' first reply (the one-shot CLI) | **14.3 s** (14.25–24.3) | **13.0 s** (12.76–13.39) |
| The sleep: FPAC's last flush | 2.58 s (2.57–2.61) | 2.55 s (2.54–2.56) |

The 10 GB column is the rerun of 2026-11-21, seven lives (`lives-sealed-10gb-7.json`). The first run's two wakes (`lives-sealed-10gb.json`) mounted at 1,085 and 1,315 ms.

- **The key costs about 260 ms** after ready (the median). `nitro-key`
  itself took 118–740 ms over the ten lives, almost all of it the fresh
  RSA-2048 key (83–700 ms: its prime search varies). KMS's round trip was
  29–37 ms and the parent's signature about 2 ms. The RSA key could be
  made at boot, in parallel with the clock; it is in series here.
- **The first wake** reads more of the store: mounted at 1.33 s (1 GB) and
  2.0 s (10 GB), with Hermes' reply at 15.5 and 16.8 s.
- **A new 10 GB disk**: the fill wrote 10 GiB in 168 s (64 MB/s, behind
  the modelled 90 MB/s put), and its sleep took 33.5 s while the backlog
  drained (148 s and 46.3 s in the rerun).
- **The canary**, read back on every wake: yes, at both sizes. The key was
  the same on every wake, and the canary was in neither the store nor the
  scratch disk.

**Where Hermes' 14 s go.** One computer, the plain disk, one `hermes chat`
and then another: **13.0 s cold, 4.1 s warm**. The image disk reads at
215 MB/s in one stream and 3,871 random 4 KiB reads a second
(`line9-hermes-cold-warm.txt`). *Corrected 2026-11-21:* this section first
read the 9 s difference as the first read of Hermes' files from the root
image. The study below shows otherwise: the first `hermes chat` starts
Hermes' gateway and waits for it, and the root's reads are under a second.

**Beside FPAC's numbers** (its `docs/results.md`): Hermes' first reply was
8.52 s on Cloudflare and 2.87 s on krun, through Hermes' gateway (its
boot, then a message). The one-shot CLI above is a different path
(deviation 8); the study below measures the gateway's path too. FPAC's
open and mount take about 130 ms here after the key (modelled, one round
at S3's 23 ms), against 0.97 s on Cloudflare (R2's round, about 300 ms).

#### Where the cold 9 s go (2026-11-21)

**In plain words:** the 9 s are not reads of the image. They are Hermes
starting its gateway. The first `hermes chat` after a boot starts Hermes'
gateway in the background and waits for it, and that start is about 9 s
of CPU work. No disk setting gets it back. The root's reads cost about
half a second to a second of the cold start, dm-verity about 0.4 s of
that, and Nitro's confidential mode about 0.15–0.3 s, most of it the
boot's firmware (line 2). The earlier reading of this section (that the 9
s were the first read of Hermes' files) was wrong.

Same parent (`m8g.xlarge`), one fresh computer a sample, 2 vCPUs, 4 GiB,
line 8's plain disk (no key: this is about the root, not the seal). The
parent's page cache held the image, as a node serving many computers
would. Each sample: a cold `hermes chat`, a warm one, then one more after
dropping the guest's whole page cache. The guest's block counters were
read around the cold run. The harness is `host/cold-reads.py`. Its
workload starts from `host/cold-entry.sh`: the image's entrypoint less its
NSM clock, since a direct sandbox has no NSM. Every row ran that same
entrypoint. Evidence: `line9-cold-reads.jsonl`.

| Setting | Cold | Warm | Page cache dropped | Root reads in the cold run |
|---|---|---|---|---|
| Confidential, dm-verity (as shipped), n = 7 | **12.93 s** (12.61–13.64) | 3.81 s | 4.06 s | 8,172 (131 MB); on the devices 13,659 image + 2,176 tree |
| Direct mode, n = 3 | 12.77 s (12.55–12.78) | 3.72 s | 3.87 s | the same |
| No dm-verity (dm-linear), confidential, n = 3 | 12.49 s (12.43–12.69) | 3.80 s | 3.96 s | the same, no tree reads |
| No dm-verity, direct, n = 3 | 12.38 s (12.34–12.45) | 3.69 s | 3.88 s | the same, no tree reads |
| Readahead 4 MiB on the root's devices (128 KiB before), n = 3 | 12.60 s (12.51–12.63) | 3.68 s | 3.89 s | 7,722 (170 MB): fewer, larger |
| dm-verity's hash prefetch 4 MiB (256 KiB before), n = 3 | 13.01 s (12.89–13.01) | 3.67 s | 4.09 s | 8,171 (131 MB), 2,944 tree reads |
| The working set read ahead, in parallel with the mount, n = 3 | **12.41 s** (12.34–12.52) | 3.83 s | 3.94 s | 840 (4 MB): the rest already read |

- **The reads, counted** (`line9-trace-reads.txt`, Firecracker traced on
  the parent in one cold run): 13,858 reads of the image (131 MB, 82% of
  them 4 KiB, none over 1 MiB) and 2,176 of the verity tree (all 4 KiB).
  About 16,000 round trips. The guest's own counters put the root's
  summed wait at 0.55–1.8 s per cold run, and each round trip at roughly
  0.07 ms on the image disk and 0.2 ms on the tree.
- **Reading every file again costs about 0.2 s.** With the whole page
  cache dropped, a run takes 3.9–4.1 s against 3.7–3.8 s warm. The
  cold-only 8.5–8.9 s survives the drop, so it is not the cache.
- **It is Hermes' gateway** (`line9-first-run-probe.txt`). After the first
  `hermes chat`, a gateway (`hermes_cli.main gateway run --quiet
  --idle-exit`, 298 MB) is running that was not there before. It had been
  running 9 s when the 13 s chat returned. Later runs find it up. The cold
  run uses 13–15 s of CPU against 3.65 s warm, while Python's imports take
  0.85 s both times. The CPU is not slower in the sandbox: the same Python
  loop counts 32.5–36.8 M iterations in 5 s in a guest in either mode, and
  35.4–36.1 M on the parent itself (`line9-cpu.txt`).
- **The working set**, recorded once by `mincore` over the root's files
  after a cold start (the image has no `fincore`): 6,610 files, 273 MB,
  173 MB of them touched. Read by 16 readers at once from the moment the
  clock is set, they took 0.43–0.49 s and were done before the chat
  began. The cold run then read 4–11 MB from the root instead of 131 MB.
  The gain is 0.5 s.
- **Not Nitro's, not the disk's:** confidential against direct is 0.16 s
  cold (with dm-verity) and 0.11 s (without), and the boot to the clock
  line is 0.16 s longer in confidential mode (858 against 697 ms): line
  2's firmware. dm-verity against dm-linear is 0.44 s (confidential) and
  0.39 s (direct).

**The path FPAC measured: Hermes through its gateway** (its image's own
entrypoint, `gateway run` under s6, its loopback API server; one message
to `/v1/chat/completions` from the moment the disk is mounted; launch to
the reply):

| Setting | First reply, normal starts | Starts that waited 10 or 20 s more |
|---|---|---|
| As shipped (confidential, dm-verity) | **11.51 s** (11.32–11.70), n = 14 | 4 of 18 |
| The working set read ahead | 11.04 s (11.03–11.06), n = 2 | 5 of 7 |
| Direct mode | 11.20 s (11.18–11.21), n = 3 | 3 of 6 |

Where a normal start's 11.5 s go (one start, `line9-gateway-11s.txt`;
times from Firecracker's spawn):

| Step | At |
|---|---|
| The guest's entrypoint starts | 0.72 s |
| FPAC mounted | 1.10 s |
| Hermes' container setup (stage2 0.73 s, profile reconcile 0.35 s, s6) | 1.15–2.26 s |
| The gateway's Python start, to its API server listening | 2.26–7.56 s (**5.3 s**) |
| The message in (sent as soon as the port answers) | 8.13 s |
| The first turn (its "turn machinery warmed in 1.4 s", the model call) | 8.13–11.56 s (3.4 s) |

**Beside FPAC's numbers:** 11.5 s here, 8.52 s on Cloudflare and 2.87 s
on krun. They used a different Hermes (fragment's image and its bridge)
on other CPUs. Here, nearly all of the gap after the mount is Hermes'
own start and first turn on this CPU. The root's reads are about 0.5 s of
it (what reading the working set ahead saved). Nitro's own cost is about
0.3 s (11.51 s against 11.20 s in direct mode), half of it the boot's
firmware.

**The 10-second waits** (12 of 31 gateway starts, any setting;
`line9-gateway-21s.txt`): Hermes' gateway prints its banner on time, then
nothing for 10 s (20 s twice) before its control socket opens. In that
gap Hermes' start replaces an existing gateway it finds recorded: SIGTERM
to the recorded PID, then up to 10 s for it to exit (`_wait_for_pid_exit(
existing_pid, 20, 0.5)` in `gateway/run_bootstrap.py`), then SIGKILL. In
a fresh VM a PID recorded by the last life on the persistent disk can
belong to some other live process. That is the likely cause but it is
**not confirmed**: in five later starts that checked, `/opt/data/
gateway.pid` was absent at the mount, and all five ran normally. It is
Hermes' behaviour on a home that outlives its machine, not this host's.

**What gets the cold 9 s back:** no disk setting. The best of them, the
working set read ahead, saves 0.5 s. The 9 s are only paid because the
one-shot CLI starts the gateway on demand. A computer that starts Hermes'
gateway at its boot, as the gateway path does, pays Hermes' start there
instead, in the 11.5 s above. Anything still left after that is Hermes,
not Nitro.

### Line 10: density and cost (`line10-*.json`, `line10-idle-hermes.txt`)

**An idle Hermes**: its gateway under s6 (Hermes' own image entrypoint,
`gateway run`, its loopback API server on), idle for 90 s, in a 3 GiB
computer.

| Inside the guest | |
|---|---|
| `hermes` (the gateway) | 238 MiB resident |
| `fpac` | 12.5 MiB resident |
| The guest's memory | 2,913 MiB total, 2,471 MiB available, 196 MiB page cache |

The pool holds the whole 3 GiB (3,154 MiB with its overheads) for the
computer's life, whatever it uses: nothing is given back (the design,
"What this backend loses").

**How many fit an 8-vCPU parent.** The same instance resized to
`m8g.2xlarge` (8 vCPUs, 31.5 GiB) for this line alone
(`line10-host-2xlarge.json`): a 26 GiB pool, leaving 4.8 GiB and one vCPU
to the parent; 7 vCPUs in the CPU pool; 20 slots. Each sandbox was the
probe with a computer's devices: four disks (three, and one standing in
for the NIC) and the vsock. Launched one after another, kept, until one
was refused:

| Each | `cpu_overcommit` | Fit | The next one refused by Firecracker |
|---|---|---|---|
| 3 GiB, 2 vCPUs | on | **8** | "Failed to allocate CMA memory: … Out of memory" |
| 6 GiB, 2 vCPUs | on | **4** | the same |
| 3 GiB, 2 vCPUs | off | **3** | "NE_ERR_NO_CPUS_AVAIL_IN_POOL" |

- **The pool's overheads, measured:** each sandbox takes its memory, 2
  MiB, and 16 MiB per device in confidential mode: 3,154 MiB at 3 GiB and
  6,226 at 6 GiB, as `pool_mib()` predicts to the MiB. The 20 slots
  themselves take 260 MiB of the pool at boot (4 slots took 4 MiB), and
  each sandbox takes one slot, not one per device.
- **Without overcommit** a sandbox owns its vCPUs, so the CPU pool (7)
  limits a node to 3 two-vCPU computers. With it, memory does, and PCR0
  is the overcommit launch's (line 4): the key's policy must name that one.
- **A launch with these devices** took 637–750 ms at 3 GiB and 820–870 ms
  at 6 GiB (the probe, to its first word).

**Busy guests with `cpu_overcommit`** (1 GiB guests, 2 vCPUs each, every
guest running two 5-second Python loops at once; `line10-busy-*.json`):

| Guests | vCPUs asked, on 7 in the pool | Iterations, all loops | Per loop |
|---|---|---|---|
| 1 | 2 | 71.7 M | 35.0–36.7 M |
| 2 | 4 | 143.0 M | 34.8–36.2 M |
| 4 | 8 | 277.2 M | 33.4–36.1 M |
| 6 | 12 | 281.7 M | 8 loops 16.2–18.7 M, 4 loops 32.8–36.8 M |

Up to the pool's size every loop runs at full speed. Past it the total
stops at the pool's 7 CPUs, and the sharing is uneven: at 6 guests eight
loops ran at half speed and four at full speed. Overcommit is safe for
mostly idle computers; a busy node is not fair between them.

**Dollars per awake computer-month,** on demand in us-east-2 (AWS's price
list): `m8g.2xlarge` **$0.35904 an hour**, $262.10 for a 730-hour month.

| Computer | Per parent | Per awake computer-month |
|---|---|---|
| 3 GiB, overcommit on | 8 | **$32.76** |
| 6 GiB, overcommit on | 4 | **$65.53** |
| 3 GiB, overcommit off | 3 | $87.37 |

Not counted: each computer's disks on the parent (gp3 at $0.08 a GB-month
for the scratch actually written; the 3.6 GB image is shared), the store
(R2 or S3), and KMS ($0.03 per 10,000 calls, one a wake). A computer that
sleeps costs nothing but its store: these are prices for awake ones.

### Line 11: the build (`line11-clippy.txt`, `line11-test.txt`)

On the parent (arm64, Rust 1.99.0, locked):

- `cargo clippy --workspace --all-targets --all-features -- -D
  warnings`: **clean**. It needed two fixes first. `c_char` is `u8` on
  arm64, so a cast in the krun runner that x86_64 needs was a no-op there
  (now `pointer::cast`). And one test module had to move below the code.
- `cargo test --workspace --all-features`: **147 passed, 0 failed**.
- FPAC's branch: `cargo clippy -p fpac-bench --all-targets -- -D
  warnings` clean on arm64.
- x86_64 with no AWS: this branch's CI (build, clippy, tests).

### Line 12: what is left (`line12-teardown.txt`)

Changed by decision: the parent and its KMS key stay, the parent stopped;
everything else no longer needed goes. `teardown.sh` gained `delete
<type> …` to remove chosen types only. The evidence: `list`, then
`delete s3-bucket` (the S3 timing bucket, emptied and deleted), then
`list` again.

| Left in place | Why | A month |
|---|---|---|
| The parent, **stopped** (`m8g.xlarge` again, its pool back at 8 GiB) | kept by decision | $0 while stopped |
| Its root volume, 60 GB gp3 | goes with the parent | $4.80 |
| The KMS key (policy: the Hermes image's PCR0) | kept by decision | $1.00 |
| Security group, key pair, IAM role and instance profile | the parent's | $0 |
| **In all** | | **about $5.80** |

The parent has no public address while stopped. Everything left is
tagged `project=nitro-spike` and in the inventory, with the bucket marked
removed.

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

### Acceptance

| # | What | Result |
|---|---|---|
| 1 | Host | **Pass** |
| 2 | Boot | **Measured**: 453 ms confidential, 304 ms direct |
| 3 | What the parent sees | **Pass**, with what was tried stated |
| 4 | Attestation | **Pass** on real documents |
| 5 | Key release | **Pass**; the envelope's lack of authentication recorded; the project's administrators can rewrite the rule (`kms:Put*`) |
| 6 | Our guest | **Pass** |
| 7 | Network | **Pass**; leak 1 recorded, not fixed |
| 8 | Sealed disk | **Pass**, the store modelled from measured S3 round trips |
| 9 | Wake | **Measured**, modelled from measured S3 round trips: the mount is quick; Hermes' own start is most of the rest, the root's reads under a second, Nitro's own share about 0.3 s |
| 10 | Density and cost | **Measured** on `m8g.2xlarge` |
| 11 | Build | **Pass** on arm64; x86_64 by CI |
| 12 | Nothing left behind | **Done as changed**: the bucket removed, the parent stopped, the key kept |

### Gaps

- One instance family, one Region, one day. Boot times on other sizes and
  on x86 parents are not measured.
- The boot's firmware part (about 320 ms confidential) is attributed by
  subtraction, not by a timestamp of its own.
- Line 3's "not found" covers the routes stated; others are AWS's claim.
- **The store is modelled.** FPAC's folder remote on the parent, with S3's
  measured round trips, stands in for the platform's route and S3 or R2.
  Every line 8 and 9 number that depends on it says so.
- **Line 9's gateway path** uses upstream Hermes v0.23.2 and its API
  server, not fragment's image and bridge as FPAC measured. 12 of 31
  gateway starts waited 10 or 20 s more inside Hermes' start; its likely
  cause (a recorded PID reused in a fresh VM) is not confirmed. The study
  ran on the plain disk, and its clock came from the parent.
- **The parent can roll a disk back, or swap one**, today: it keeps the
  head and the wrapped keys, and it decides which disk a guest opens. The
  design says what closes it; nothing here does.
- **Leaks 1 and 2 are unchanged**: the proxy reads intercepted traffic,
  and the host engine can run any command in a computer. The scratch disk
  is plain on the parent; only FPAC's disk (and its cache) is sealed, and
  the canary was written only there.
- **The release rule is ours to change** (`kms:Put*`), and AWS's.
- The final kernel's config was built once; the twice-built one lacked one
  line (`CONFIG_BLK_DEV_WRITE_MOUNTED`).
- Line 10: one idle sample after 90 s; density with the probe and four
  small disks standing in for a computer's devices (no NIC); Python loops
  for the busy guests. The 8-vCPU numbers come from a resize of the same
  parent.
- x86_64 is built and tested by CI only; nothing ran on an x86 parent.

## Design (no code)

What the spike would become, if the owner decides to go on. Nothing in
this section is built.

### sandcastle's Firecracker backend, as PRs

Each row is one PR. "Needs" names the PRs that must land first.

| # | PR | Needs |
|---|---|---|
| 1 | **The guest's boot on Nitro**: sandcastle-guest as an initrd's init (it leaves the initramfs's root), its root named by `sandcastle.image=`, its clock from the NSM; with valid/invalid/restart tests. From this spike's `mounts.rs`, `sys.rs`, `init.rs` | – |
| 2 | **Release assets for a measured image**: `guest-kernel.sh` (reproducible, as here), `verity-image.sh` and the image's verity table, built in CI. Each release publishes its kernel, initrd, image root hash and the **expected PCR0**, recorded by one launch on a release parent until AWS documents the measurement well enough to compute it offline | – |
| 3 | **A Firecracker engine in `sandcastle-vm`**, beside krun: the configuration writer and pool accounting (`config.rs`), the jailer, a CID and a tap per VM, the egress forwarder per tap, scratch disks on the parent's disk and deleted with their VM, image disks shared read-only | 1 |
| 4 | **The engine service picks the backend per node** (krun or Nitro), with one API: exec, stdin, exit codes, ports over the NIC, stop. Conformance runs against both | 3 |
| 5 | **The key in the guest**: `nitro-key` folded into the guest agent, so the key arrives before the entrypoint; the parent's signer as part of the engine; the wrapped key kept beside the disk's head by the platform's route (a fragment change, described below, not made) | 1, 3; FPAC's sealed mode (exists) |
| 6 | **The attested control channel** (leak 2, below) | 1, 3; the verifier (`nitro-attest`, written to become celld's) |
| 7 | **The scratch disk sealed** with a key made in the guest at boot, which never leaves it and dies with the life (dm-crypt) | 1 |
| 8 | **Egress and credentials inside the boundary** (leak 1, below) | 6 |
| 9 | **Rollback and disk swaps closed** (below) | 5, 6 |
| 10 | **A release rule we cannot change alone** (below) | 5 |
| 11 | **The parent as an image**: `parent-ready.sh` as an AMI build, the pool sized per instance type, a node's memory and slot budget published to the scheduler | 3 |

fragment would need, described and not made: its cell's route for FPAC
stores the wrapped key beside the disk's head and hands it back at each
start; its scheduler places a computer by memory alone (no ballooning
here); its exec path speaks the attested channel (PR 6) instead of
trusting the host engine.

### Leak 1: egress and credentials on the parent

Today the proxy runs on the parent, ends intercepted TLS with its own
CA, and fills in secrets there (line 7). The design moves it inside the
boundary:

- **The proxy runs in the guest**, or in a sibling sandbox of its own
  with its own PCR0. TLS to a vendor then ends inside the boundary, and
  the parent carries TCP as it carries KMS's bytes now. It can still see
  addresses, names (SNI) and timing, and refuse or delay, but not read or
  change.
- **Secrets are released like the disk key**: by KMS (or the key service
  below) to a document with the proxy's PCR0, never through the parent.
- **Intercepts the platform answers** (FPAC's route, the callback route)
  go over TLS to the cell, with the cell's certificate pinned in the
  measured image, instead of to a handler on the parent.
- **The policy** (which hosts, which intercepts) comes over the attested
  control channel from the cell, not from the parent.

### Leak 2: the control channel

Today the host engine can run any command in a computer: the agent
accepts exec over vsock from whoever holds the socket. The design:

- At its start the guest makes a key pair and gets an NSM document
  carrying the public key and a nonce the cell chose.
- The cell checks the document with `nitro-attest` (line 4: the chain to
  the pinned root, freshness, the single-use nonce) and its PCR0 against
  the release's (PR 2).
- The two then speak over a session keyed to that document (TLS or Noise),
  end to end; the parent carries its bytes. The agent takes exec, files
  and ports only on that session.
- The parent keeps start, stop, kill, refuse and delay. That is
  availability, never content.
- **Repair access** (a person running a command in someone's computer) is
  a grant the owner signs, time-limited and named in the session. Never
  ours alone. For users who are not technical, the owner's app signs the
  grant when they say yes in plain words.

### Leak 3: the disks

FPAC's disk is sealed here, with its key released by attestation (line
8). What is left:

- **The scratch disk** (the overlay's writable layer: anything written
  outside `/opt/data`, and FPAC's cache, itself sealed) is plain on the
  parent. PR 7 seals it with a key made at boot that never leaves the guest.
- **The image disk** is public by design; dm-verity, measured into PCR0,
  makes it tamper-evident.
- **Memory** is the Nitro System's to protect (line 3 states what was
  tried).

### Rollback: a host serving an older valid disk

Every object FPAC writes is authentic under the disk's key, and the key is
the same in every life. So a parent that keeps an older head and its
objects can serve them, and the disk opens intact and stale. In this spike
the folder remote on the parent holds the head too, so **the parent can
roll a disk back today**. The wrapped-key swap above is the same attack
with another disk.

The design: the head the guest opens must come with a counter the guest
can check against something the parent does not hold.

- The guest signs each head it writes with a key derived from the disk's
  key, counter included. The latest counter is kept by the cell (the
  platform's state, as in FPAC's design), not by the parent.
- At a start the cell sends, over the attested channel (leak 2), the disk
  the guest is to open and the counter it must find. The guest refuses an
  older head or another disk. The disk's name also goes into KMS's
  encryption context, so a swapped wrapped key fails at KMS.
- That moves the trust from the parent to the cell, which is ours. To
  hold against us too, the counter must also live where we cannot rewrite
  it: in the key service below, or in the owner's own signed log.

### A release rule we cannot change alone

Line 5's policy lets the project's administrators change the release
rule in one `PutKeyPolicy` call. AWS can too. Two things would make the
rule hold against us:

- **A key service in its own sandbox**, with its own published PCR0, holds
  each disk's wrapping key. It acts only on statements the owner signed,
  under the owner's key bound to the disk when the disk was made. Examples:
  "release disk D's key to images whose PCR0 is X", "grant repair access
  to this person until noon", "accept releases signed by Finite's release
  key that have been in the public log for a day". The last is a default
  the owner's app signs once, so a non-technical owner never sees a
  prompt for an image update. A new image we publish is then released to
  only after the owner's own rule says yes, and we cannot change the rule.
- **KMS at most as a second lock.** The key service's own state is
  sealed so that opening it needs both KMS (policy: the key service's
  PCR0) and a second share KMS never sees: one held by a key service in
  another trust domain (another cloud's TEE, another operator), or by the
  owner's device. Then rewriting the KMS policy alone releases nothing.
  KMS cannot be the only lock: AWS runs it, and whoever writes its
  policy holds the rule.

What this costs: a second service on every start's path (one more round
trip, in parallel with the boot, about 30 ms like KMS's here), and a
second trust domain to run. What it gives: neither we nor AWS alone can
release a user's disk.

### What this backend loses

- **Memory given back.** A sandbox's memory is taken from the pool at its
  launch and is the sandbox's until it stops. There is no balloon and no
  free-page reporting across the boundary. krun gives an idle Hermes back
  to 604 MiB from 906 MiB (docs/krun-engine.md); here a 3 GiB computer
  holds 3 GiB of the pool for its whole life. Density is by the memory
  asked for, not the memory used (line 10).
- **Pause and snapshots.** Not tried here. A memory snapshot would need
  the guest's memory, which the parent reads as zeros (line 3), so at best
  it could be one the Nitro System makes. Plan as on krun and Cloudflare:
  an idle computer stops, and a wake is a cold start.
- **The console**, outside debug mode. Debug mode zeroes the PCRs, so a
  debugged computer cannot get its key (line 5).
- **The pool is fixed at the parent's boot** (`nitro_enclaves.mempool=` on
  its command line). Changing it takes a reboot of the node.
