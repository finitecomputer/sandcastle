# The sealed scratch disk, one run

The engine of `nitro/sealed-scratch` on a parent (an m8g.xlarge, Amazon
Linux 2023, kernel 6.18), every sandbox confidential. Its release assets:

| Asset | SHA-256 | Built |
|---|---|---|
| Guest kernel (dm-crypt, AES-XTS, the CPU's AES added) | `79868751a4a813e409ef6b066f1b2b76beb4eb43d09200668c6723215c2044cc` | `nitro/guest-kernel.sh`, 5 min |
| Static mke2fs (e2fsprogs 1.47.4) | `6a7492a974ad2312961a0ce9ed831fcded4593d1570f7277c1c55f11b1db4ea2` | `nitro/guest-mke2fs.sh`, 18 s; built twice, the same bytes |

## The planted-string scan

A test container writes a canary into its writable root (16,384 copies
of a 64-character string, synced), then root on the parent counts it in
the scratch disk's file while the container runs. The guest makes the
canary from a seed (its SHA-256), so the start request the parent holds
names the seed, never the canary. The control is the same container on a
parent whose engine does not seal (the `nitro/vsock-bridge` engine), the
same image, the same procedure.

| | Sealed | Control (not sealed) |
|---|---|---|
| Canary pairs found on the scratch disk | **0** | **8,192** (every one) |
| Files in the engine's state naming the canary | **0** | 1 (the scratch disk) |
| The scratch disk's written blocks | 2.3 MB | 2.6 MB |

Then on the parent that runs a home (an m8g.2xlarge), once its engine
had the seal (installed with no computer running): **0** pairs found, on
2.3 MB written, where the same parent's control before the seal had found
8,192.

`canary-scan.sh` is the scan, as run.

## celld's conformance, sealed

`conformance-nitro-sealed.json`: **23 passed, 2 failed, 0 unsupported**.
The two failures are the two this engine now refuses by design on Nitro,
with its typed answer: `snapshotContainer` ("a Nitro Sandbox's scratch
disk is sealed by a key only its guest held, gone with it: there is
nothing to snapshot or start from"), and `start_from_snapshot`, which
has no snapshot to start from. Every other case passes on the sealed
disk, the writable root's marker included.

## What sealing costs a start

The engine's own "ready in" for the suite's container: **525 to 537 ms**
sealed, against **502 to 514 ms** before (the device-mapper calls and
mke2fs on the mapping, about 20 ms). The first, cold start: 741 ms,
against 750 ms.
