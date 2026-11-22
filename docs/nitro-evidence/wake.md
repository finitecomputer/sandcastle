# Where a wake goes, on the computer's side (S6, 2026-11-22)

The home's acceptance run (lane B's, `docs/nitro-home.md`) timed a wake at
**8.1 s** from a message to the reply on the page: the VM up at 1.0 s, its
data restored (2.7 MB) at 1.3 s, Hermes heard at 1.75 s, its turn begun at
2.9 s. A warm reply took 4.1 s, so a wake cost about 4 s more than a warm
reply: 2.9 s before the turn, and about 1 s more inside it.

This is what each piece costs on the computer's side, measured with test
computers of lane A's (our Hermes image, the cell's 2 vCPU / 6 GiB, a
temporary home half on the parent claiming each one), and what to cut.

## The parent's part: about 1 s, nearly all of it AWS's launch

| Step | Measured |
|---|---|
| a start through the home, as celld asks it (`?wait=ready`) | 928 to 1,181 ms |
| — the engine's own work before the launch (jail, network, nft, Firecracker built) | 6 to 15 ms |
| — **the sandbox's launch**, Firecracker built to the guest kernel's start | **about 760 to 890 ms** |
| — the guest kernel, to the init's first word | 97 to 108 ms |
| — the home's part: its pin check, its look for the computer running, the claim | 16 to 18 ms |
| each exec over the attested session | 2 to 7 ms |
| the guest's random numbers at boot (`getrandom`) | 0 ms (the CRNG is ready at once) |

The launch grows with the sandbox's memory, about 65 ms a GiB on top of
about 365 ms (Nitro clears a sandbox's memory before it starts):

| Memory | 1 GiB | 3 GiB | 4 GiB | 6 GiB |
|---|---|---|---|---|
| Launch (second of two rounds) | 430 ms | 560 ms | 628 ms | 766 ms |

## The computer's own work

| Step | Measured |
|---|---|
| the image's root read cold (Hermes and its Python, 2,332 MiB, 16 readers) | 4,853 ms (about 480 MiB/s); one reader over the 515 MiB of packages: 1,361 ms |
| a restore's or a save's stream (an exec's stdin or stdout over the session) | 140 MiB/s in, 112 MiB/s out, at 1 vCPU and at 2: so a 2.7 MB save is about 20 ms of it |
| the sealed scratch disk written | 512 MiB synced in 240 ms; 5,000 small files in 100 ms |
| one new connection out, through the home's egress (plain HTTP / HTTPS / the model host) | 30 / 50 to 60 / 80 to 90 ms, against 28 / 32 to 43 / 25 to 28 ms from the parent itself |
| the gateway's imports (its preload reads the image's bytecode) | 612 ms warm, 1,464 ms cold |

## Where the rest goes

The parent's second and the computer's reads, streams and connections
above are all of the computer's side; the rest of lane B's 2.9 s before
the turn is Hermes' own boot, which none of them slows. fragment's Docker test of
a wake (`a_cold_wake_by_its_steps`, images/bridge/tests/docker.rs) times
it step by step: on this box's Docker, a wake's boot to its turn handed
over takes 1.1 s (boot 0.3 s, configured 0.6, the gateway told 0.6, the
gateway up 1.3, the turn handed 1.4), and lane B's Nitro wake took about
1.9 s for the same span, on the cell's 2 vCPUs. What the computer's side
adds, measured above, is too small to explain the difference; the CPUs
are the likely cause (not measured). The first turn after a wake (about
1 s slower than a warm one) is Hermes' and the model's.

## A smaller cut found on the way: `hermes` commands compile their imports

Hermes' launcher (v0.23, `libexec/hermes`, which `hermes` and the venv's
`hermes` both run) sets `PYTHONPYCACHEPREFIX` to
`$HOME/.cache/hermes-pycache` unless one is set. Under a prefix Python
reads no `__pycache__` beside a source, so the image's compiled Hermes went
unread, and with the image's `PYTHONDONTWRITEBYTECODE` each `hermes`
command compiled its imports again: `hermes --version` took 872 ms on a
fresh computer, 215 ms reading the image's bytecode. The gateway is not
among them: hermes-boot preloads it with the venv's Python directly
(`preload.py`), which has no prefix, and a wake's timings are the same
with or without the fix. It costs each `hermes` command run through the
launcher (an agent's own, the Bot Desktop's `computer-use screen start`).
The fix is fragment's (`images/hermes/Dockerfile`, draft PR
`nitro/hermes-bytecode-prefix`): the build deletes the launcher's line,
an exact match.

## The cut left on the computer's side: a computer launched before it is wanted

The launch is most of the parent's second, and only a sandbox already
launched skips it. The engine could keep one sandbox of the cell's size
booted and unclaimed per image; a start then takes it, renamed, and the
home's claim brings its start (its entrypoint, env and hostname) in place
of the runner's start message. That saves about 0.85 s a wake (8.1 s to
about 7.3). Its costs: the warm sandbox's memory, held idle (6 GiB of the
parent's 17,000 MiB each), and a guest change (its start from the claim),
so a new PCR0 for every image. Not built: holding idle memory is a
capacity decision.

## What was not measured

- A wake through the real cell and home: lane B's 8.1 s is the only such
  timing on Nitro; the steps after the VM are from fragment's Docker test
  on this box, not from Nitro.
- The cold first reply's 8 s of work (its three steps: model calls and
  tools) is mostly the model's and Hermes's own, not the computer's.
