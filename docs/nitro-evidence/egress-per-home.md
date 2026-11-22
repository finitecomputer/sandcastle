# Each computer's egress to its own home (2026-11-22)

One real run on two parents of lane A's: three temporary home halves on
the first (homes A, B and C, each with its own parent-half egress socket),
the first parent's engine and the second's (reached over its API relay),
the suite's test image. The first engine's own `session_egress` is home
A's socket; its `session_egress_allow` takes `unix:/run/lane-a/` and the
VPC's range, the second's the VPC's range. Home A names
`--egress-to unix:…/a-egress.sock` and `--remote far=…,egress=tcp:<the
first parent>:5103`; home B the same with its own socket and port 5104;
home C names none. "Internet" is `wget http://checkip.amazonaws.com` inside
the computer, through its egress sessions to its home.

| Step | Result |
|---|---|
| home C's computer (no `egressTo`): its egress to the engine's one socket, home A's | running in 618 ms; its internet: **`wget: bad address`** (its lookups' sessions reached a home that never claimed it) |
| a start naming an `egressTo` outside the node's ranges (a public resolver's address) | 400: "egressTo: … is not one this node allows (nitro.session_egress_allow)" |
| a1 and b1 (3 GiB each) | on the first parent's engine, running in 742 and 730 ms |
| a2 and b2 (the first parent full for them) | on the **second** parent's engine, running in 726 and 722 ms |
| each one's internet | **the first parent's public address**, all four: each computer's egress reached its own home |
| the second engine restarted | "recovered {adopted: [a2, b2]}"; each one's internet the same again: an adopted computer keeps its end |
| the destroys | no computer left on either engine |

Before this, home C's case was every home's but one: a node had one egress
socket for all its computers.
