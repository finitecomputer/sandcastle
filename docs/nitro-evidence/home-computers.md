# A home's computers on this engine, one run

One parent (an m8g.2xlarge, Amazon Linux 2023, kernel 6.18) ran two
things: a home (celld with the real cell, in a confidential Nitro Sandbox
of its own, the home lane's) and this engine, which ran the home's
computers as confidential Nitro Sandboxes. celld reached the engine
through `sandcastle-bridge` (`docs/nitro.md`, "The bridge") over the
home's vsock, with `CELLD_CONTAINER_ENGINE=krun:/run/sandcastle/engine.sock`
in the home. Everything below was driven from a browser on the public
internet; this engine and the bridge were not changed for it.

## The image

Fragment's Hermes computer image, built for arm64 (fragment master merged
with its arm64 branch: Hermes v0.23.2), loaded into the engine under the
reference celld gives it, its content key:

| | |
|---|---|
| Reference | `celld-image:c35bf99bbed2605ec668fd2f122d3311fe2aa1db76b04c454d4e602071af435d` |
| Image tar | 3.92 GB, 13 layers (the base layer 3.79 GB) |
| Build VM | 92 s (the base layer applied in 56 s) |
| dm-verity format | 33 s, 3,957,903 data blocks |
| Root hash | `6d07f5dda9c784d98529783be7b86edc02d7e1e0d5111f4453bfcd194c96ff89` |

Its PCRs on this node, from an NSM document read inside a test computer
of the image (with `nsm-attest.py`, a fresh nonce) and verified down to
AWS's pinned Nitro root with the spike's `nitro-verify`:

| PCR | Value (SHA-384) |
|---|---|
| 0, the image (kernel, command line, initrd, launch flags) | `e8c570c5b167678ffa00e0f55c175a1515567317e127df23961c9b7b429566ecce0493883402310296db78e468055839` |
| 1, kernel, command line, first initrd | `97131cdeadb8ed7d55e25e4757364206f880754d508c8fb295cc654fb13aeabeb3ffbfd423bffe6b2acea0c8ea83b931` |
| 2, later initrds | `21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a` |
| 3, 4 | the parent's role and instance (not recorded here) |

This PCR0 is this node's, not the image's everywhere. The command line
carries the root's dm-verity hash, and a node builds the root in a build
VM, which is not byte-reproducible (`docs/nitro.md`, "Release assets").
Another node's build of the same image gives another root hash, so
another PCR0. A PCR0 that anyone can check before trusting a computer
needs the root built the same way everywhere, then published with it.

A bare start of it through the engine (a shell entrypoint, no cell) was
ready in 1,562 ms cold and 976 ms warm. Inside: `aarch64`, the arm64
`sandbox-shim` and `hermes-boot` run, Python 3.14.9, and the clock read
2026, set from the NSM.

## The engine's log

The engine's own lines for the home's first computer (UTC, parent clock):

```
17:59:37 celld-4ea140-73b6febae1df89204: started in slot 0
17:59:38 celld-4ea140-73b6febae1df89204: ready in 1308 ms
18:02:39 celld-4ea140-73b6febae1df89204: ended {"code":0,"signal":null,"destroyed":false,"error":null}
18:02:39 celld-4ea140-73b6febae1df89204: started in slot 0
18:02:40 celld-4ea140-73b6febae1df89204: ready in 930 ms
18:03:11 celld-4ea140-73b6febae1df89204: ended {"code":null,"signal":9,"destroyed":true,"error":null}
18:03:23 celld-4ea140-73b6febae1df89204: started in slot 0
18:03:24 celld-4ea140-73b6febae1df89204: ready in 927 ms
18:05:17 celld-4ea140-73b6febae1df89204: ended {"code":null,"signal":9,"destroyed":true,"error":null}
18:06:52 celld-4ea140-73b6febae1df89204: started in slot 0
18:06:53 celld-4ea140-73b6febae1df89204: ready in 910 ms
```

| When | What happened | Seen from |
|---|---|---|
| 17:59:37 | The first agent is made: its computer starts, 2 vCPU and 6 GiB (the cell's own instance), ready in 1.3 s | engine |
| +1 to +7 s | Its boot reaches the cell through the intercepts: 45 skills fetched from the platform, its channels subscribed, the chat's turn claimed and work posted back; Hermes replies | the computer's log |
| | Its terminal tool writes a file; `uname -m` says aarch64, `/dev/nsm` is there | the home lane, in the chat |
| 18:02:39 | Restart computer: the cell saves `/data`, signals the computer, which exits 0, and starts a new VM from the save, ready in 930 ms. The file is still there | engine; home lane |
| 18:03:11, 18:05:17 | Home restarts: celld reaps its node's computers (`destroyed: true`), then answers again (11.0 s for the second) | engine; home lane |
| 18:06:52 | The next message wakes a new VM, ready in 910 ms, restored from the last save. The file is still there; the reply comes 7.1 s after sending | engine; home lane |
| later | The computer's screen (its desktop over VNC) through `ports.sock`, the bridge's socket handover | home lane |

Nothing on the parent carried `/data` across a restart: every start makes
a new scratch disk (the one of 18:03:23 was born that second), and the
engine held no data disk and no snapshot. What came back came through the
save and the restore: `DirectoryBackup` through the intercepts into the
home's bucket, then, at the next boot, the restore before the computer's
gate opened. celld's side, as the home lane read it (ids masked):
`restored {after: sleep, from: backup, generation 2, …}`, then
`start {path: restore, bytes: 2,664,440, readyMs: 3,933}`, the
`DirectoryBackup` intercepts before it.

## Found

A home restart reaps each awake computer without a final save, so the
shell says the changes of the minute before it stopped were not kept.
That is celld's restart (it destroys its node's containers at shutdown
and again at start), not this engine or the bridge: a Fragment computer
is saved only by its cell's sleep, and SIGTERM means stop now.
