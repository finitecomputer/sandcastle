# The attested session, one run

The engine of `nitro/attested-session` on a parent (an m8g.xlarge, Amazon
Linux 2023), every sandbox confidential, with `"nitro": {"session_required":
true}`: each computer's measured kernel line requires its session. A home
on the parent itself: the home half of `sandcastle-bridge` with
`--sessions`, `--pins` and `--up` (the engine's socket on the same host in
place of vsock), and celld in front of it. Every computer below is the
suite's image on that node, sealed scratch disk included.

## The pin

The first start through the home, with no pin of this image yet, was
refused, and the computer destroyed:

```
sandcastle-bridge: lane-a-session: refused, destroyed: the guest's attestation:
PCR0 f225b303803a0d70f1a4e974b66cc194b53384f1a306a178fbd6cbd30aae51d94acb6ff77c9cf92867dce9e85762e790
is no image this home runs
```

A real NSM document, verified to AWS's root with the home's nonce; only
the PCR0 was not yet the home's. That PCR0 went into the pin file.

## What each side could do

| | Result |
|---|---|
| A start through the home | claimed: attested and its session's secret sent before the start answered |
| An exec through the home (over the session) | **answered**: `101`, then the command's output |
| The same exec by the parent, at the engine | **refused**: `400 {"error":"exec: this guest takes that only over its attested session"}` |
| The parent claiming the computer's session itself (an attest hello on the engine's session upgrade) | **refused**: the guest closed the connection, 0 bytes |
| A port through the home | `transport: vsock` (over the session), `HTTP/1.0 200 OK` |
| The same port by the parent, at the engine's `ports.sock` | `transport: nic`, `HTTP/1.0 200 OK`: **still open**, the NIC path (docs/nitro.md, item 3) |

## celld's conformance through the home

`conformance-nitro-session.json`: **23 passed, 2 failed, 0 unsupported**,
the same as with the scratch disk sealed alone. Every exec case (output,
stdin, PTY and resize, kill, abort) and every port case went over
sessions; the 2 failures are the snapshot cases a Nitro node refuses by
design.
