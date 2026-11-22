# Computers on another parent (S8, 2026-11-22)

One real run on two parents of lane A's own (m8g.xlarge each, one subnet,
one security group that takes 5100 and 5103 only from itself):

- **The home's parent**: the S3 engine (7,000 MiB for computers), a
  temporary home half of lane A's own (`--remote far=tcp:<the other
  parent>:5100`), and the egress relay in (`relay --listen tcp:…:5103 --to
  unix:<the home half's egress socket> --allow <the other parent>/32`).
- **The far parent**: made fresh for this run by `nitro/parent-ready.sh`
  (8 GiB pool), the same engine (7,000 MiB), its API relay (`relay --listen
  tcp:…:5100 --to unix:<engine.sock> --allow <the home's parent>/32`), and
  its egress relay out (its `nitro.session_egress` a relay to the home's
  parent's 5103).

The far parent built the test image's root itself, so its PCR0 is its own:
`f8d5a9dc…` there, `fb3b28b7…` on the home's parent (each read by `POST
/v1/images/<ref>/measure`). The home's pins held both.

| Step | Result |
|---|---|
| health through the home | 0 of 14,000 MiB; `local` 0 of 7,000, `far` 0 of 7,000 |
| c1, 4,096 MiB | on `local`; answered in 828 ms |
| c2, 4,096 MiB (`local` has 2,904 left) | on **`far`**; answered in 834 ms |
| c3, 1,024 MiB | on `local` again (it still takes it); 625 ms |
| the far engine's own list, over its relay | `c2`, running |
| the list through the home | `c3, c1, c2` |
| exec over each claimed session | each answered with its boot time; c3's memory 1 GiB, c1's and c2's 4 GiB |
| c2's egress: `wget http://checkip.amazonaws.com` | **the home's parent's** public address, not the far parent's own: its connection left through its home |
| a home restart, then exec into c2 | answered after 1,053 ms, the home finding it on `far` again, with its kept credential |
| health through the home | 3 computers: `local` 2 (5,120 MiB), `far` 1 (4,096 MiB) |
| a `docker save` (4.35 MB) loaded through the home | both engines built it, and each lists it |
| a connection to the far API relay from an address it does not allow | reset; the relay logged the refusal |
| the destroys through the home | no computer left on either engine |

The first two runs of the same script failed only at c3, from the run's
own request: 2,048 MiB with one vCPU breaks the engine's 3 GiB a vCPU, and
a custom instance takes at least one vCPU. Its placement (`local`) was
already the right one.

## What it does not show

- **A real home in its own sandbox.** The home half here runs on the
  parent as a process, as in S1 and S3. In a home's sandbox the home half
  would dial the far relay over the home's own network (its tap's NAT),
  and the egress relay in would point at the parent half's `--egress`
  socket. That's a home image change.
- **The cell's computer image** (Hermes, 3.9 GB) through the load's tee:
  the test used a 4.35 MB image.
- **An engine that dies with computers on it**: its computers become
  unknown (500) to the home, never gone (the unit test covers this; this
  run did not kill a parent).
