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
| `crates/nitro-attest` (`sandcastle-nitro-attest`) | The attestation verifier: COSE Sign1 with ES384, the chain to the pinned root, validity, freshness, a single-use nonce. Pure: the caller passes the time and the randomness. Written to become celld's. | Any host: 27 tests on self-made documents |
| `crates/nitro-spike` (`sandcastle-nitro-spike`) | The driver. So far: Firecracker's configuration for a sandbox and the pool's accounting (`config`), and `verify`, the operator's check of a document. | Any host: 5 tests |
| `crates/nitro-spike/host/parent-ready.sh` | Line 1: a fresh AL2023 parent to ready, then its facts as JSON | Written, not run |
| `crates/nitro-spike/host/guest-kernel.sh` | The guest kernel the spike controls (Amazon Linux's 6.18 tree, Firecracker's CI config, NSM, dm-verity) | Written, not run |
| `crates/nitro-spike/host/teardown.sh` | Line 12: list or remove everything tagged for the spike | `list` run |

### Dependencies

None new to the workspace's lock. `ring` 0.17.14 and `rustls-webpki`
0.103.14 (with `rustls-pki-types` 1.15.1) came in with `rustls`; `rcgen`
0.14.10 and `time` 0.3.55 (tests only) with the egress crate's CA. They are
now named in the workspace's dependencies, pinned to the locked versions.
The CBOR reader and the two facts read from certificates' DER are written
here (below), not pulled in: the documents' CBOR is a small fixed schema,
and a general CBOR crate would be three more crates to audit for it.

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

### Status: blocked before line 1 (2026-11-20), escalated

**The project's plan refuses the parent instance.** Launching an
enclave-enabled `m8g.xlarge` on the AL2023 6.18 arm64 AMI failed:

> An error occurred (InvalidParameterCombination) when calling the
> RunInstances operation: The specified instance type is not eligible for
> Free Tier.

The project is on AWS's free plan, which launches only free-tier-eligible
instance types. In us-east-2 those are ten small types (`t3`, `t4g`,
`t8i`, `t9g` micro and small, `c7i-flex.large`, `m7i-flex.large`), and
**none supports Nitro Enclaves**, on which Nitro Sandboxes are built
(`free-tier-types.txt`). So no instance this plan can launch can run a
sandbox. That is the brief's first escalation ("the plan or its policies
refuse an API the spike needs"); the way on is the paid plan, which is the
owner's decision, not the spike's.

**What the plan's dry run proved, and what it did not.** The plan said a
dry run of this launch had succeeded, and it still does: `run-instances
--dry-run` answers "Request would have succeeded" for `m8g.xlarge` with
and without enclaves, and for `c7g.xlarge` with them
(`blocked-launch.txt`). A dry run checks the caller's permissions and the
request's parameters: it does refuse enclaves on a type without them
(`t4g.small`: "You cannot enable Nitro Enclaves"). It does not apply the
free plan's eligibility rule, which only the real launch applies. So the
dry run proved that the API, the enclave option and the instance type are
permitted to the caller, and nothing about the plan. A dry run is not
evidence that a launch will pass on the free plan.

**Spent: $0.** The plan reports $120 of credits left (the brief expected
$100). On AWS now, all free: the spike's SSH key pair, a security group
whose only inbound rule is port 22 from the operator's address, and the
parent's IAM role (KMS on keys tagged for the spike only, S3 on the
spike's buckets only) with its instance profile (`teardown-list.txt`).
They are kept for the run.

**When the plan changes:** on the paid plan a spend limit, when it trips,
pauses the project and stops every resource. A launch or a `kms:CreateKey`
refused after the upgrade is reported at once as that, not retried.

### Built while blocked, with no AWS spend

#### The attestation verifier (line 4's operator half): `crates/nitro-attest`

It checks, in order, what AWS's "Verifying the root of trust" and the NSM
API's `docs/attestation_process.md` (3.2.2 to 3.2.4) require:

1. The envelope: a COSE_Sign1 (tag 18 or bare), four items, the protected
   header exactly `{1: -35}` (ES384), the unprotected header empty, the
   signature 96 bytes.
2. The payload: the nine known fields, each typed and bounded; the six
   mandatory ones present, none repeated, no unknown key; the digest
   `SHA384`, so every PCR is 48 bytes.
3. The chain: the bundle's first certificate is the pinned root, byte for
   byte, within its validity (webpki does not check a trust anchor's); the
   signing certificate chains to it through the rest (webpki: signatures,
   basic constraints, path lengths, every certificate's validity at the
   given time); and its key usage allows `digitalSignature`.
4. The signature: ES384 over COSE's `Sig_structure` by the signing
   certificate's key.
5. Freshness: the document's own time at most 5 minutes old, at most 1
   minute ahead.
6. The nonce: the caller's exactly (`verify`), or one this verifier issued,
   live and never used (`verify_issued` with `Nonces`). A forged document is
   refused before it can use up a nonce.

It does not judge the PCRs: which image is acceptable is the caller's
policy.

**The root, pinned from AWS's documentation** (`root-certificate.txt`).
The certificate in `AWS_NitroEnclaves_Root-G1.zip`
(`https://aws-nitro-enclaves.amazonaws.com/`) hashes to
`641a0321…79bb5b`: the fingerprint the Nitro Enclaves User Guide gives
on its "Verifying the root of trust" page
(`docs.aws.amazon.com/enclaves/latest/user/verify-root.html`, read
2026-11-20). The zip itself hashes to `8cf60e2b…faff7c`, as the NSM API's
`docs/attestation_process.md` says. The certificate is embedded in the
crate and checked against the pinned fingerprint whenever the trust is
built: `CN=aws.nitro-enclaves`, P-384 with SHA-384, valid 2019-10-28 to
2049-10-28.

**Its tests** (`unit-tests.txt`, 27, all pass; clippy with warnings
denied, `clippy.txt`). AWS publishes no sample attestation document or
test vector (searched: aws-nitro-enclaves-nsm-api, -cose, -sdk-c,
-samples, -image-format), so **the fixtures are built from a self-made
chain**, labeled so in the code: a root, an intermediate and a signing
certificate valid for three hours, all P-384 with SHA-384 as AWS's are,
and documents in the NSM's encoding (its field order and null optionals,
as the NSM API's own encoding tests pin them).

| Kind | Cases |
|---|---|
| Valid | a whole document, bare and tagged, every field returned as signed; optional fields null or absent |
| Invalid | a changed byte at 150+ places spread over the whole document; every prefix of it; another root; AWS's real root (a self-made chain is refused by it); a bundle that starts at the trusted root but whose intermediate another root signed; an expired and a not-yet-valid signing certificate; a time past the root's own validity; a signing certificate without `digitalSignature`; a signature by another key; a wrong, short or missing nonce; a document one millisecond too old and one too far ahead (and exactly at each limit, accepted); each field's rule (14 cases); the envelope's shape (8 cases); CBOR and DER faults (truncation at every length, indefinite lengths, reserved values, wrong types, trailing bytes, bad times) |
| Replay | a document verified, then the same one again: refused; a forged one does not use up the nonce it names |
| Restart | a nonce issued before a restart, answered after it: refused (and still good on the ledger that issued it) |

**The tests bite** (`planted-bugs.txt`): six bugs planted one at a time,
each caught by a named test: the root not pinned, the root's validity
skipped, the key usage skipped, the COSE signature ignored, the nonce not
used up, the age limit off by one.

**What this does not prove yet:** that a real Nitro document parses and
verifies. A real one may show what self-made ones cannot: an extension
webpki refuses, an extended key usage, a field order or a tag the fixtures
lack. Line 4 runs it against a real document first, and its evidence will
say so either way.

`sandcastle-nitro-spike verify --document <file> --nonce <hex>` runs it on
the operator's machine and prints what the document attests, PCR3, PCR4
and the module id redacted unless `--reveal-parent` is given.

#### Firecracker's configuration (lines 1, 2, 6): `crates/nitro-spike/src/config.rs`

A sandbox as typed data (`Boot` as kernel, initrd and command line, or a
pre-built EIF; vCPUs; memory; drives; NICs; the vsock; the `enclave`
options; each device's DMB), validated against every documented limit
before it is written as Firecracker's JSON. Choices that differ from
Firecracker's defaults, on purpose:

- The command line is always written out: it is measured into PCR0 and
  PCR1 like any other, so it is chosen where it is spelled.
- Every `enclave` option is written, `false` ones included, and in
  confidential mode every device's DMB size, so a change in Firecracker's
  defaults cannot change a sandbox's mode or its pool.
- No drive is ever the root device: Firecracker would append `root=` to
  the command line (and so to the measurements), and the guest's init
  mounts its own root.
- `cpu_ids` and `numa_nodes` are not modeled: an `m8g.xlarge` is one NUMA
  node. Line 10's 8-vCPU type is checked for nodes first.

Its pool accounting is AWS's: memory, 2 MiB a sandbox, and in confidential
mode each device's DMB; slots 4, then steps of 8 at 128 MiB each. Line 10
checks it against `mem_pool/in_use` on the parent.

Tests (`unit-tests.txt`, 5): AWS's own example `sandbox.json` key by key,
with only the deliberate additions; each mode and option rendered; every
limit at its edge and one past (memory, vCPUs with and without
overcommit and with two-thread cores, devices, command line, socket path,
CID, ids, taps, DMB sizes, a DMB in direct mode); the pool's accounting;
the slot steps.

#### The host scripts (lines 1 and 12): written, not run

- `parent-ready.sh`: as root on a fresh AL2023 parent; idempotent, exit 3
  asking for a reboot. The kernel (6.18.51-120.162 or later), the pool
  on every kernel's command line, build packages, Firecracker v1.18.0
  checked against the SHA-256 its release publishes (pinned in the
  script), Rust 1.99.0 with the musl target for the build user, the slots;
  then the host's facts as JSON, with no instance id, AMI id or address.
- `guest-kernel.sh`: Amazon Linux's `kernel6.18-6.18.62-127.179.amzn2023`
  tag, Firecracker v1.18's 6.18 microVM config and EFI fragment, then the
  spike's own lines (NSM, dm-verity, loop, FUSE, no modules), refusing a
  line `olddefconfig` dropped; the image's SHA-256 and every input's pin
  in `kernel.json`.
- `teardown.sh list|delete`: everything tagged `project=nitro-spike` in
  the Region (instances, volumes, snapshots, security groups, key pairs,
  KMS keys, S3 buckets) and the IAM role and profile by name and tag; ids
  printed as hashes. `list` found exactly the four resources above.

#### FPAC's remote on the parent (line 8): sized, not built

FPAC's folder remote (`crates/testkit/src/folder.rs`, 325 lines) answers
the contract from local files. An S3 remote on the parent needs what it
does not have: SigV4 signing, credentials from the parent's IMDS, TLS to
S3, put-if-absent as S3's conditional `If-None-Match: *` (a 412 then read
back for its stored checksum: same or conflict), ranged gets with S3's
416, and the disk's head and epoch kept by the parent across lives (the
platform's part, contract section 3). Estimate: about 500 non-test lines
and 250 of tests (AWS's published SigV4 vectors, the status mapping
against a local stand-in, the head file's restart), as one draft FPAC PR
on `nitro-spike`: the folder remote's HTTP front split from its storage
behind one trait, and an S3 store beside the folder. The AWS SDK for Rust
would make it about 150 lines but add about a hundred crates to audit, so
it is not proposed. Not built: it is over the few hundred lines the
coordinator set as the line for asking first.

### Acceptance so far

| # | What | Result |
|---|---|---|
| 1 | Host | **Not run: blocked before launch.** The script is written. |
| 2 | Boot | Not run. The configuration writer is built and tested. |
| 3 | What the parent sees | Not run. |
| 4 | Attestation | Not run on the instance. The verifier is built and tested on self-made documents, the root pinned from AWS's docs. |
| 5 | Key release | Not run. |
| 6 to 10 | Our guest, network, sealed disk, wake, density | Not run. |
| 11 | The build | The two new crates: clippy (warnings denied) and every test pass on x86_64 here. The whole workspace and arm64: on the instance and CI. |
| 12 | Nothing left behind | Four free resources kept for the run, listed by `teardown.sh list`; $0 spent. |

### What runs first once an instance can launch

Each a step on this branch, in order, each needing the one before:

1. Launch the parent (tagged, inventoried), run `parent-ready.sh`, reboot,
   run it again: line 1's facts.
2. `guest-kernel.sh` on the parent.
3. The guest probe: a static init for an initrd that says hello over vsock
   with its uptime, holds a canary in memory and writes one to a disk,
   asks the NSM for a document with the caller's nonce and a fresh RSA key,
   and opens KMS's `CiphertextForRecipient`. Its tests run on any host.
4. The driver's launch half: the configuration above, Firecracker
   spawned, each step timed: lines 2 and 3.
5. The KMS key and its policy (PCR0 only for Decrypt, no root delegation
   for it), and the three Decrypts: lines 4 and 5. Then stop and report.

### Gaps

- Nothing has run on Nitro hardware. Every AWS-side fact above is the
  documentation's, read 2026-11-20.
- The verifier has seen no real document (above).
- The two pages disagree on the largest `user_data` and `nonce` (AWS's
  guide 1024 bytes, the NSM's process document 512); the verifier takes
  1024.
- The whole workspace was not built here: the operator's machine builds
  only crates whose sources it already has (no registry downloads on it).
  CI on this branch builds the whole workspace on x86_64.
