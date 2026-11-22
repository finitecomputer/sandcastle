# A Fragment home on Nitro

> **This branch merges nowhere until the owner decides.** It builds on the
> Nitro spike ([nitro-spike.md](nitro-spike.md)) and is phase 1 of "the
> real thing": a Fragment deployment people use from a browser, with the
> platform and each agent's computer inside confidential Nitro sandboxes.

## In plain words

A **home** is one organisation's Fragment, inside one confidential Nitro
sandbox of its own. It runs celld with fragment's real cell, its sign-in,
its files and its secrets. The parent EC2 instance boots it and carries its
bytes, but cannot read its memory. Its computers (lane A's work) are
sibling sandboxes on the same parent.

A person reaches the home from a browser over public HTTPS. The parent
forwards port 443 to the home untouched. The home ends TLS itself, with
certificates it gets itself from Let's Encrypt (TLS-ALPN-01), so the parent
carries ciphertext.

People sign in with their own passkeys, checked by the home's identity
door, so nobody else can sign in as them, the home's operators included.
A first passkey comes only with a one-time invite. A later one needs the
account's own passkey, or one of its recovery codes.

The home's secrets come to it sealed: KMS releases their key only to the
home's own image, measured by its PCR0. Its local disk is encrypted with a
key KMS releases the same way. Its durable state is in an S3 bucket, and
only the home holds the bucket's credentials.

## What runs in the home

| Piece | What it is | Where its state is |
|---|---|---|
| celld | The node (the fork's `selfhost` line), running the cell's release build, on loopback behind Caddy | The fleet bucket (S3); its work files on the encrypted disk |
| The cell | fragment master's release build. The home deploys it to the bucket at boot whenever its release changed | The bucket |
| The identity door | fragment's `crates/identity-door` in its passkey mode, at `<platform>/__door`, playing WorkOS's endpoints to the cell | The encrypted disk (accounts, public keys, hashes) |
| macrofiche | The fragments' git, the code-store contract, at `<platform>/__git` (the CLI and computers reach it there) | The encrypted disk |
| OpenBao | celld's secrets backend, in memory (`-dev`), seeded from the sealed bundle at each boot; its root token is revoked once the cell's is minted | Memory |
| Caddy | The front door: TLS ended here, its certificates got by TLS-ALPN-01 (the platform's at the start, a fragment's on its first visit, once `nitro-home-guest ask` says the cell holds that name) | The encrypted disk |

## A boot

The parent's launcher (`nitro-home up`, a systemd service) boots the
sandbox with:

- sandcastle's guest as init (lane A's node line, `nitro/home-no-door`),
  with a static `mke2fs` beside it in the initrd;
- the home's root under dm-verity, with its root hash, the home's KMS key
  id and two more words on the measured command line:
  `sandcastle.agent=none` (the guest takes no exec and no session; its
  host may only ping it and signal its entrypoint) and
  `sandcastle.start=image` (the guest runs `/etc/sandcastle/start.json`
  from the measured root, and ignores the entrypoint and environment the
  start message names);
- a fresh, bare scratch disk for the overlay, which the guest seals under
  a key of its own and formats inside;
- the home's data disk, which the guest leaves raw for the workload.

The image carries its own start (`start.json`: `entry.sh` and its
settings), its sealed bundle, and its computers' pins. So what the home
runs, with what, is a function of its PCR0, and a key released only to
that PCR0 is released only to it.

The workload (`host/entry.sh`) then:

1. sets the clock from the NSM;
2. prints an attestation document, whose PCR0 the key policy names;
3. opens the sealed bundle: its key comes from KMS over TLS the guest ends
   (`nitro-key wake`), and its files go to a tmpfs;
4. opens the data disk with dm-crypt, under a key from KMS. On the first
   boot `nitro-key new` makes it and writes its wrapped form to the disk's
   first block; later boots use `nitro-key wake`;
5. seeds OpenBao, then starts macrofiche, the door and the certificate
   check;
6. deploys the release to the bucket when it changed, then starts celld;
7. starts Caddy last, once what it lets in is ready behind it.

Any service that exits takes the home down, and the systemd service
starts it again. A stop is graceful: the launcher signals `entry.sh`
(SIGTERM, the one thing besides a ping the guest takes from its host);
celld goes first, asked to keep its computers running for the next start,
so its last writes reach the bucket; then the rest, and the disk is closed
last.

Nothing runs a command in the home, its operator included: its logs are
its only voice. Invites come only through its door (`passkeys.inviter`:
a hosted platform's signed ask; fragment#1449), and a new computer image's
pin is a new home image.

## Secrets

`nitro-home-seal` makes the bundle (`src/sealed.rs`) on the operator's
machine. It seals every file of a directory with AES-256-GCM under a fresh
key K, and K goes to KMS's `Encrypt` under the home's key. The parent hands
the home the bundle as it came.

The key's policy:

- The project's administrators may manage the key and `Encrypt`, never
  `Decrypt` or `GenerateDataKey`.
- The parent's role may `Decrypt` and `GenerateDataKey` only for a
  recipient document whose PCR0 is the home image's. KMS then answers only
  inside an envelope to the document's key. `nitro-key` takes that answer
  only from KMS's own TLS, which ends in the guest.

The bundle holds:

- the cell's store secrets: the host secret, the code store's key, the
  door client's secret and the model key;
- the door's own secret;
- the fleet bucket's credentials, for an IAM user whose policy names that
  bucket alone, so the parent's role cannot reach it.

`cargo xtask home render` (fragment, `nitro/home-release`) writes what the
image carries and what the bundle seals, apart. The image carries the
bundle too, sealed (`/opt/fragment-home/sealed.json`): the guest runs the
image's own start and takes no environment from the parent. Nothing in
the image is secret in the clear.

## The release rule

A new image has a new PCR0, and the key releases nothing to it until the
policy names that PCR0. `host/pin-pcr0.sh` does that on the operator's
machine: it verifies the image's own attestation document down to AWS's
pinned root (`nitro-verify`), and puts the document's PCR0 into the
policy, beside the running image's (`--keep`), for a rollback.

## Deploys

One command on the operator's machine, `host/home-deploy.sh`, takes a
running home to a new image: a new release (`cargo xtask home render`'s),
new programs, or a computer image's pin (`--pin <pcr0>`). It:

1. seals the bundle again only when what it seals changed;
2. ships the trees, the release, the bundle, the conf and the pins, and
   has the parent build what changed (`home-build.sh`);
3. stages the image in a slot of its own beside the running home
   (`home-stage.sh`: `/var/lib/nitro-home/slots/<time>`; the unit runs
   whichever slot `current` names);
4. measures it beside the running home (`nitro-home measure`: its own CID,
   no NIC, 1 vCPU, 1 GiB, throwaway disks; it prints its attestation and
   dies at KMS), verifies the document on the operator's machine, records
   the slot's PCR0 there (`attest/slots.tsv`), and pins it, keeping the
   running slot's from that record;
5. switches the home onto it (`home-switch.sh`): a graceful restart (its
   computers kept), healthy when this start serves with its door holding
   as many accounts as the start before; otherwise back onto the slot it
   ran, by itself.

`home-deploy.sh --rollback` moves the home back onto the slot before (its
PCR0 is the policy's second).

Measured on the owner's home (2026-11-22): a deploy 121 to 127 s end to
end; the pause, from the restart to serving, 10.2 to 11.8 s; a rollback
10.9 to 11.3 s; the door's accounts and the operator's counts (people,
fragments) unchanged across each. The measuring boot reads PCR0 in 0.9 s,
the same PCR0 as the image's own boot.

## Logs and numbers

The parent sees the home's console. A home with no exec says how it is in
numbers there, never in anyone's words:

- **at each boot:** its steps and their times, how many accounts its door
  holds, the bucket's migration (objects, bytes), and its time to serve;
- **a line a minute** (`home: stats {…}`): resident cells, the isolates'
  census (cells, heap and external bytes, requests), the deployment's
  version and generation, memory, load, the data disk's use, celld's RSS,
  and celld's WARN and ERROR lines since the last minute, counted by their
  event's name.

`host/home-status.sh` (on a parent, as root) answers JSON for each home
unit on it (state, restarts, slot, time to serve, door accounts, last
stats, the last hour's boots, failures, error lines and refused computer
starts), the computers' engine (its health: VMs and memory), the Nitro
pool (CPUs, memory and PCIe slots free) and the host. `host/nitro-status.sh`
asks every parent listed on the operator's machine and prints a line per
home and per parent (`--json` for the whole).

## Many homes on one parent

A parent holds several homes, each an org's, each its own confidential
sandbox, disk, key and bucket prefix. One command on the operator's
machine makes one:

    host/home-create.sh <name> --parent <dir>

It prints `{"home": "https://<name>.<suffix>", "door": "…/__door"}`: the
door is what a hosted platform's "Add a private agent" asks (fragment's
`private_home.door`). `<dir>/homes.json`, the operator's, names what the
parent's homes share (its ssh host, the suffix, the region, the parent's
instance role, the fleet and counter buckets, the fragment tree that
renders, the models, the inviter's npub, a home's size, and the CID and
subnet bases). Each home's own files are in `~/.cache/nitro-real/homes/<name>`
on the operator's machine. The command makes, each only when missing (a
run that stopped is run again to finish):

1. **its place:** the first number n no home on that parent holds, and
   from it a CID, a tap (`nitroh<n>`) and a /24;
2. **its key** (KMS, tagged): admins seal with it and never open; the
   parent's role opens it only for the home's own image, which the first
   deploy pins (until then, no image);
3. **its bucket's credentials:** an IAM user that reaches the prefix
   `<name>/` of the fleet bucket and nothing else (its list limited to that
   prefix too), and the bucket's seal (celld#30): a new key, and a counter
   at `homes/<name>/bucket` in the counter bucket, behind an IAM user of
   its own;
4. **its confs and release:** `cargo xtask home render` with
   `proxy_from` (below), and a launcher conf with no port forwarded;
5. **its first deploy:** `home-deploy.sh --home <name>`, as any deploy:
   sealed, built, staged, measured, pinned, switched onto.

On the parent, a named home's slots, disks and conf are under
`/var/lib/nitro-home/homes/<name>`, its sockets under `/run/nitro-home/<name>`,
and its unit is `nitro-home@<name>` (`home-name.sh`; stage, switch and deploy
take `--home <name>`). Staging refuses a CID, tap or address another home
there holds. The parent's one home from before names keeps its layout and
unit. Deploys to one parent go one at a time (a lock on the operator's
machine); the parent's build is shared, and a step whose pin and outputs
are unchanged is kept, so a new parent given another's `out/` builds only
the sandcastle tree.

**The SNI router.** Several homes cannot each have the parent's 443
forwarded. `home-router.sh` runs HAProxy there in TCP mode: it reads each
connection's ClientHello for its server name and passes the connection,
untouched, to the home that holds the name (its `HOME_PLATFORM`
exactly, or any name under its `HOME_SUFFIX`), first sending the PROXY
protocol's header (v2) with the client's address. TLS still ends in the
home, and Let's Encrypt's TLS-ALPN-01 passes through the same way. The
home's Caddy reads that header from the parent's address alone
(`proxy_from`), so the client's address reaches celld as before. A name no
home holds, or no name, is closed. The router's config is written from the
homes' running confs at each switch, and HAProxy reloads only when it
changed (open connections stay on the old process, for up to an hour).
It logs abnormal connections alone. A parent whose one home takes 443
forwarded can run no router.

## Network

The home's NIC is a tap with plain NAT on the parent (`src/net.rs`):

- Every private, shared, link-local and loopback range is refused,
  including the parent's metadata service, its VPC and its own addresses.
- Inbound, only the conf's ports (443) are forwarded, untouched, from the
  parent's own addresses.

The home is our own measured code, so it takes no egress proxy. Its
traffic is KMS, S3, the model API and Let's Encrypt, all over TLS the home
ends, plus DNS.

### Certificates and CAA

Caddy in the home holds one ACME account, at Let's Encrypt's production
directory. Its key and the certificates live in Caddy's storage on the
encrypted disk (`/var/lib/fragment-home/caddy`), so the parent never sees
the key. The DNS then names that account as the only one that may be
issued certificates for the home's names (RFC 8659, and RFC 8657 for
`accounturi`), on the platform's name alone:

```
nitro.<zone>  CAA 0 issue     "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/<n>"
nitro.<zone>  CAA 0 issuewild ";"
```

A fragment's name (`<app>.nitro.<zone>`) holds no CAA of its own, so a CA
climbs to the platform's name and finds these. Every other CA refuses
(each must check CAA), Let's Encrypt refuses every other account, and no
CA may issue a wildcard, which the home never takes.

Proved on 2026-11-21, with the records in place:

- a fragment deployed from the CLI under a new name got its certificate on
  its first visit, in 4.2 s (Let's Encrypt, issued for that name alone);
- another account (a new one, on Let's Encrypt's staging directory, by
  DNS-01) asking for a name under the platform's was refused:
  `urn:ietf:params:acme:error:caa`, "CAA record for nitro.<zone> prevents
  issuance".

The home's account URI is the `location` in
`/var/lib/fragment-home/caddy/acme/acme-v02.api.letsencrypt.org-directory/users/default/default.json`
(the account key beside it never leaves the home).

**If the home ever gets a new ACME account** (its disk remade, the home
moved, the key rotated), change the `issue` record **before** that home
needs a certificate:

1. Start the new home. Caddy registers its new account at its first order,
   which the CAA record refuses: nothing is issued yet.
2. Read the new account's URI from that `default.json`.
3. Replace the `accounturi` in the `issue` record (a DNS change, so the
   owner's), keeping the TTL at 300 s.
4. After the TTL, restart the home or wait for Caddy's retry. It then gets
   its certificates.

Caddy renews a certificate when a third of its life is left (about 30 of
90 days), always with the same account, so renewal needs no change to the
record. Losing the key by accident means losing the disk, and so the
certificates with it: the front door then has none until step 3 is done.
For a planned move, let both accounts be named for a while: two `issue`
records, one for each `accounturi`, then the old one removed.

## Computers

Lane A's engine (sandcastle's Nitro backend) runs on the parent.
`sandcastle-bridge` carries its sockets over vsock (ports 5000 to 5002 on
the home's CID), and celld reaches the engine as it reaches the krun engine
(`CELLD_CONTAINER_ENGINE=krun:/run/sandcastle/engine.sock`). With no engine
(`HOME_ENGINE=none`), fragments and apps work, and a computer is refused,
typed.

Each computer is reached over its attested session alone (lane A's PR 6),
and its egress runs through the home (PR 8: port 5003, the home's CA). The
home's bridge claims a computer at its start against the PCR0s pinned in
the home's image (`/opt/fragment-home/pins`): a start of any other image
is refused, and counts as a failed start.

## Phase 1's acceptance

| # | What | Result |
|---|---|---|
| 1 | From a browser: sign in, make an agent, chat, a real reply | **Pass.** A passkey sign-in; the agent made from the shell; its greeting and replies from GLM-5.3 Flash through the platform's model route |
| 2 | The agent's computer is a confidential sandbox from our image; its terminal works | **Pass.** Lane A's engine starts it from our Hermes image's measured root (arm64, Hermes v0.23.2). In the chat, the agent's terminal answers `aarch64`, `/dev/nsm` present, 2 CPUs, 5,924 MiB. Its screen (the desktop, through the engine's ports over the bridge) shows |
| 3 | The agent sleeps and wakes with its data; the home restarts and everything is still there | **Pass.** A file the agent wrote survived a computer restart (save, new VM, restore) and a restart of the home (new VM, restore). The home restart lost the last minute of the computer's changes (below) |
| 4 | A fragment app deploys from the CLI and loads | **Pass** (below) |
| 5 | Numbers | Below |
| 6 | What the parent can still see or do | Below |

## Results (2026-11-21, one run each)

The home's own rows ran on one `m8g.xlarge` parent, and the computers' on
the same parent resized to `m8g.2xlarge` (pool 22 GiB). The home is a
2-vCPU, 4 GiB confidential sandbox (`cpu_overcommit` off); a computer is
2 vCPU, 6 GiB, the cell's own size. The browser was headless Chrome on the
operator's machine, reaching the home over the public internet, with a CDP
virtual authenticator (CTAP2, user verification).

| What | Result |
|---|---|
| Launch to the guest's ready | 0.72 s |
| Secrets opened (two KMS round trips through `nitro-key`) | 0.95 to 1.1 s after launch |
| The encrypted disk mounted | 1.2 to 1.7 s |
| OpenBao seeded | 2.3 to 3.4 s |
| celld serving: a warm restart, release unchanged | 3.2 s |
| celld serving: the release changed (deployed first) | 5.7 to 6.4 s; the deploy itself 1.4 to 2.0 s |
| **Launch to the front door answering with a valid certificate:** a warm restart | **3.4 s** |
| Launch to the front door answering: a first boot, its certificate got by TLS-ALPN-01 | 10.8 s |
| `systemctl restart`, to the platform answering again, seen from the operator's machine | 12.9 s (the graceful stop is 5 s of it) |
| The parent rebooted, to the home serving again by itself | about 31 s |
| A passkey enrolled from an invite, then a sign-in to the platform with it | both pass; the account and its passkey kept across door and home restarts |
| `fragment login` approved at `/cli` by that session; `fragment init <app> --template todo` | logged in; deployed in 6.0 s |
| The app's first visit, its certificate got on demand | 4.6 s; a made-up subdomain gets no certificate |
| A todo item written, the home restarted, the item read back | **there**, the CLI's key still valid, the person still signed in |
| A recovery code on a new device; the same code again | a new passkey; then refused |
| A second device added, proved by the first; the first lost; sign-out and sign-in | signed in by the second device alone |
| An invite for an email that has an account | refused |
| KMS refused an image the policy did not name | refused, then released once its own PCR0 was pinned |
| A canary written in the home, searched for in the disk files on the parent | data disk **0**; tmpfs 0; the control written to the plain scratch layer: 4,096 |
| **An agent's first start** (the cell's `start` event, fresh path) | ready at 141 ms in the cell's clock, Hermes heard at 2.6 s, its first turn begun at 3.8 s; lane A's engine reports the VM itself ready 1.3 s after its launch. The greeting then took "8 s, 3 steps" |
| **The first reply, cold:** from the agent's start to its greeting | about 12 s (3.8 s to its first turn, then 8 s of work) |
| **A warm reply:** from sending to the reply on the page | **4.1 s** ("worked for 2 to 3 s") |
| **A wake:** the computer asleep, a message sent, to the reply on the page | **8.1 s**. The cell's `start` event: VM up 1.0 s, data restored from its save (2.7 MB) at 1.3 s, Hermes heard at 1.75 s, its turn begun at 2.9 s |
| Settings → Restart computer (save, new VM, restore) | Awake again in 5.1 s; the file kept |
| The home restarted with the computer awake | the platform answering in 11.0 s; the next message woke a new VM ("up 0 min") with the file, 7.1 s from send to reply |
| The same, since its stop keeps the computers (celld's `containers=keep`, lane A's) | the platform answering in 10.7 s; a file written 6 s before the restart read back by the **same VM** (its boot time unchanged, "up 7 min"), 18 s from send to reply, the cell's wake and its adoption of the computer included |

## What the parent can still see or do

Each item is with the design PR that closes it
([nitro-spike.md](nitro-spike.md), "Design").

| # | What | Closed by |
|---|---|---|
| 1 | ~~It can run any command in the home, and picks its entrypoint and environment~~ | **Closed** 2026-11-21 on the shared parent (lane A's #27 guest): `sandcastle.agent=none` on the measured line, so the parent's exec is refused ("this guest takes that only over its attested session, or not at all"); `sandcastle.start=image`, so the home runs its measured root's `start.json`, its sealed bundle and pins in that root too. The parent keeps a ping, a signal to the entrypoint (its stop), and kill |
| 2 | **Whoever ships a new home image can ship one that skips the passkey check**, or anything else: the project's administrators can name any PCR0 in the key's policy (`kms:Put*`), and AWS can too | PR 10, a release rule we cannot change alone |
| 3 | **It can roll back or swap the home's data disk** (an older copy, or another home's under the same key). It cannot read it: AES-XTS under a key from KMS. The encryption is not authenticated, so it can also corrupt blocks | PR 9 (rollback), with dm-integrity |
| 4 | **The fleet bucket is unsealed.** The parent's role has no access, and the home's traffic to S3 is TLS the home ends. But whoever holds AWS administration, or the home's IAM key, reads every object, and can roll the bucket back | The sealed fleet bucket (phase 2) |
| 5 | ~~It could get a certificate for the home's names~~ (TLS-ALPN-01 validates whoever answers on the address the DNS names, and the parent holds that address) | **Closed** 2026-11-21: CAA records name the home's own ACME account (`accounturi`, RFC 8657), whose key never leaves the home, and forbid wildcards. Another account was refused ("Certificates and CAA") |
| 6 | It sees traffic metadata: clients' addresses, the names they ask for (SNI, so the fragments' names), sizes and timing, and the names the home resolves | Inherent to the parent carrying the bytes; DNS over TLS would hide the last |
| 7 | It sees the home's log lines: the boot's steps, celld's warnings, the attestation document. The door's, macrofiche's and celld's full logs stay on the encrypted disk | Keep the parent's view to the boot's steps |
| 8 | ~~It sees an invite link made over its own exec~~ | **Closed** with item 1: no exec. Invites come through the door alone (a hosted platform's signed ask, over TLS the home ends), and their links go from the home to that platform to the person's browser |
| 9 | It can stop, kill, refuse, delay or throttle the home: availability, never content | Inherent |
| 10 | ~~The home's scratch disk is plain on the parent~~ | **Closed** 2026-11-21 with #27: the home's guest seals its scratch disk under a key of its own and formats it inside; the parent hands it a bare file and holds ciphertext |

**The computers' side** (lane A's engine; nitro-spike.md's leaks):

| # | What | Closed by |
|---|---|---|
| 11 | ~~The engine's egress proxy on the parent reads every intercepted request in plaintext~~ (the computers' calls to the platform, the model route, their saves) | **Closed** 2026-11-21 on the shared parent (lane A's PR 8, sandcastle#28): each computer's egress runs through its session into the home, ended there under the home's CA. A canary the agent's terminal sent 3 times reached the home's celld 3 times, and the parent's engine and the bridge's parent half 0 times (of 8,457 and 10,775 traced syscalls); the parent can no longer reach a computer's ports |
| 12 | ~~The engine can run any command in a computer~~ (exec over vsock) | **Closed** 2026-11-21 on the shared parent: each computer is reached over its attested session alone (lane A's PR 6, sandcastle#26), claimed by the home's bridge against the PCR0s the home pins; the parent's own exec is refused ("this guest takes that only over its attested session"). The parent still picks which image it starts, and a start the home has not pinned is refused |
| 13 | The computer's `/data` lives in its saves in the bucket, unsealed (its scratch disk is sealed since lane A's PR 7, sandcastle#25, on the shared engine) | FPAC's sealed disk in place of the saves (PR 5) |
| 14 | ~~A home restart reaps its computers without a final save~~ | **Closed** 2026-11-21: the home's stop asks celld to keep its computers running (`POST /shutdown?handoff=preserve&containers=keep`, lane A's celld change), and the next start adopts them. A turn in flight at the stop still loses its model call: its retries fail until its cell is adopted, which waits for the cell to be touched |

Outside the parent:

- the operator's machine saw every secret it sealed;
- OpenRouter sees the agents' prompts (the model route);
- an email in an invite is the invite's word, not verified;
- whoever can change the zone's DNS (its DNS host's account, or a token
  for the zone) can change the CAA records and get certificates for the
  home's names by DNS-01;
- **the hosted platform that adds private agents (preview, so Finite) can
  start new accounts at the home, and never get into an existing one.**
  Its admin asks the home's door, signed with the one key the door trusts
  (`passkeys.inviter`), for an invite for its signed-in operator's own
  email. The door makes one only for an email with no account there, and
  answers "sign in" for any other; every later passkey on an account needs
  one of its own (fragment#1449, and the platform's side on master). So
  whoever holds that key, or runs that platform, can start an account in
  any email's name that has none yet, and make its first passkey from the
  invite before its person does.

## Not verified

- A deploy of a new computer image with its pin measured by the engine
  (lane A's S3 `POST /v1/images/<key>/measure`): `--pin` takes a PCR0
  by hand until then.
- The home's image is not built reproducibly: each staging measures to a
  new PCR0 (its files' times), so a PCR0 cannot be predicted before the
  build, nor published ahead of it.

- The computer's idle sleep (the seat's) was not waited for: the wakes
  above follow a computer restart, a home restart and a reap.
- A second computer; a computer's own disk past its saves (FPAC's sealed
  disk is not in this path).
- Adding a second passkey through its page's one button. Chrome attaches
  every virtual authenticator to the ceremony, and one holding an excluded
  credential refuses the whole `create()`. So the step ran end to end
  through the door's own endpoints instead, as the page calls them: proved
  by the first device's passkey, the first device removed, the new passkey
  made on a second device. Signing out and in with the second device alone
  then worked.
- One run each; no load, no density, no x86 parent.
- The home's ACME account is Let's Encrypt's production. Its rate limits
  were not hit (50 a week for a registered domain): six certificates were
  issued for the zone's names today, the five the home holds and the
  unused DNS-01 wildcard from before the CAA records.
- A renewal under the CAA records (none is due for about 60 days), and
  any CA other than Let's Encrypt refusing.
