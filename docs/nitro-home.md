# A Fragment home on Nitro

> **This branch merges nowhere until the owner decides.** It builds on the
> Nitro spike ([nitro-spike.md](nitro-spike.md)) and is phase 1 of "the
> real thing": a Fragment deployment people use from a browser, with the
> platform and each agent's computer inside confidential Nitro sandboxes.

## In plain words

A **home** is one organisation's Fragment: celld running fragment's real
cell, with its sign-in, its files and its secrets, inside one
confidential Nitro sandbox of its own. The parent EC2 instance boots it
and carries its bytes, but cannot read its memory. Its computers (lane A's
work) are sibling sandboxes on the same parent.

A person reaches the home from a browser over the owner's tailnet. The
home is a tailnet node itself, and TLS ends inside it, so the parent
carries only WireGuard packets. The home's secrets come to it sealed: KMS
releases their key only to the home's own image, measured by its PCR0.
Its local disk is encrypted with a key KMS releases the same way. Its
durable state is in an S3 bucket only the home holds credentials for.

## What runs in the home

| Piece | What it is | Where its state is |
|---|---|---|
| celld | The node (fork's `selfhost` line), running the cell's release build, on loopback behind nginx | The fleet bucket (S3); its work files on the encrypted disk |
| The cell | fragment master's release build, deployed by the home itself at boot when its release changed | The bucket |
| The identity door | fragment's `crates/identity-door`: sign-in through tsidp, the tailnet's OpenID Connect provider | None (codes in memory) |
| macrofiche | The fragments' git, the code-store contract | The encrypted disk |
| OpenBao | celld's secrets backend, in memory (`-dev`), seeded from the sealed bundle at each boot; its root token revoked once the cell's is minted | Memory |
| nginx | The front door: TLS for the platform, its fragments and the door, ended here | None |
| tailscaled | The home as a node of the owner's tailnet | The encrypted disk |

## A boot

The parent's launcher (`nitro-home up`, a systemd service) boots the
sandbox: sandcastle's guest as init, the home's root under dm-verity (its
root hash and the home's KMS key id on the measured command line), a
fresh scratch disk for the overlay, and the home's data disk. The
workload (`host/entry.sh`) then:

1. sets the clock from the NSM;
2. prints an attestation document, whose PCR0 the key policy names;
3. opens the sealed bundle: its key from KMS over TLS the guest ends
   (`nitro-key wake`), its files to a tmpfs;
4. opens the data disk: dm-crypt under a key from KMS (`nitro-key new` on
   the first boot, its wrapped form written to the disk's first block;
   `nitro-key wake` after);
5. seeds OpenBao, then starts macrofiche, the door, tailscaled and nginx;
6. deploys the release to the bucket when it changed, then starts celld.

Any service that exits takes the home down, and the service starts it
again. A stop is graceful: celld first, so its last writes are in the
bucket, then the rest, the disk closed last.

## Secrets

The bundle (`src/sealed.rs`) is made on the operator's machine by
`nitro-home-seal`: every file of a directory, sealed with AES-256-GCM
under a fresh key K. K goes to KMS's `Encrypt` under the home's key; the
parent hands the home the bundle as it came. The key's policy:

- the project's administrators may manage the key and `Encrypt`, never
  `Decrypt` or `GenerateDataKey`;
- the parent's role may `Decrypt` and `GenerateDataKey` only for a
  recipient document whose PCR0 is the home image's. KMS then answers only
  inside an envelope to the document's key, and `nitro-key` takes that
  answer only from KMS's own TLS, which ends in the guest.

The bundle holds the cell's store secrets (the host secret, the code
store's key, the door client's secret, the model key), the door's own
secrets, the TLS key and chain, the fleet bucket's credentials (an IAM
user whose policy names that bucket alone), and on a first boot the
tailnet's auth key.

## Network

The home's NIC is a tap with plain NAT on the parent (`src/net.rs`):
every private, shared, link-local and loopback range refused (the parent's
metadata service, its VPC, the parent's own addresses), nothing inbound.
The home is our own measured code, so it takes no egress proxy. Its
traffic: WireGuard (the tailnet), KMS, S3 and the model API over TLS the
home ends, and DNS (the names it resolves are the parent's to see).

## Computers

Lane A's engine (sandcastle's Nitro backend) runs on the parent;
`sandcastle-bridge` carries its sockets over vsock (ports 5000 to 5002 on
the home's CID), and celld reaches it as it reaches the krun engine
(`CELLD_CONTAINER_ENGINE=krun:/run/sandcastle/engine.sock`). With no
engine (`HOME_ENGINE=none`), fragments and apps work and a computer is
refused, typed.

## Results

(Filled in by phase 1's runs.)

## What the parent can still see or do

(Filled in at the end of phase 1.)
