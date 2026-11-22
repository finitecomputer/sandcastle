# Computers through an engine restart (S1, 2026-11-22)

Each row is one computer of a test of lane A's own: a Nitro Sandbox
claimed by a home half over its attested session, its workload writing a
heartbeat a second. "Answered" is an exec over the session: its boot time
(`born`), its heartbeats, its uptime.

## Before: the documented unit (one unit, `Delegate=yes`)

| The engine's unit | After `systemctl restart sandcastle-engine` |
|---|---|
| default stop (`KillMode=control-group`), as on the shared parent | the computer **ended**: its Firecracker gone, and the new engine "recovered {adopted: [], cleared: [lane-a-s1]}" |
| `KillMode=process` | the computer ran on, but the engine **looped**: `status=219/CGROUP`, 5 restarts in 12 s, nothing serving it |

Why: on systemd 252 a restarted delegated unit's process goes into the
unit's root cgroup, and cgroup v2 refuses a process in a cgroup that hands
controllers to its children (the VMs' `vm-<slot>`). The jailer, which
answers a SIGTERM by killing its VM, also sat in the engine's cgroup.

## After: the VMs' own unit (docs/nitro.md, "Restarts"), on lane A's parent

| Step | The same computer, after it |
|---|---|
| running | `born=1795315406 beats=26 up=25.23`; Firecracker 6540 |
| `systemctl restart sandcastle-engine` | recovered `{adopted: [lane-a-s1]}`; Firecracker **6540**; answered `born=1795315406 beats=32 up=31.41` |
| `stop`, 5 s with no engine, `start` | while stopped, Firecracker 6540 ran on; recovered `{adopted: [lane-a-s1]}`; answered `born=1795315406 beats=43 up=42.60` |
| the engine's binary reinstalled, then started | recovered `{adopted: [lane-a-s1]}`; Firecracker **6540**; answered `born=1795315406 beats=49 up=48.77` |

No `ended` for it until its destroy; the engine's unit restarted 0 times;
after the destroy, no Firecracker and no `vm-` cgroup were left. Its cgroup
held the jailer (root), the runner and Firecracker; the engine's unit held
the engine alone.

## A parent reboot (S2's half that is lane A's), on lane A's parent

A computer running, then `systemctl reboot`: back 10 s later with the VMs'
unit and the engine active (0 restarts), `/dev/nitro_enclaves` still the
`nitro` group's, the pool on the kernel's line; the engine "recovered
{adopted: [], cleared: [lane-a-s2]}" (it ended with the host), and a new
computer's start answered in 1,144 ms and ran.

## On the shared parent, beside the real home

The same switch on the parent that runs lane B's home (no computer
running): one engine stop, the VMs' unit, the engine's unit without
`Delegate`, `vm_cgroup`. The engine came back with "recovered {adopted: [],
cleared: []}", the keeper in `sandcastle-vms.service/keeper`, the engine
alone in its unit, the VMs' cgroup handing out `cpu memory pids`; the home
stayed active. Then a test computer of lane A's (the Hermes image, claimed
by a temporary home half of lane A's own):

| Step | The same computer, after it |
|---|---|
| running | `born=1795317133 beats=25 up=25.20`; Firecracker 193912 |
| `systemctl restart sandcastle-engine` | recovered `{adopted: [lane-a-s1]}`; Firecracker **193912**; answered `born=1795317133 beats=32 up=31.36` |

No `ended` for it until its destroy, 0 restarts of the engine's unit; after
the destroy, no computer and no `vm-` cgroup were left, and the home was
still active.

## A reboot of the shared parent (S2), beside the real home

Lane B rebooted the parent that runs the owner's home (no computer
running). Everything came back by itself: the home answered again 25 s
after the reboot (lane B's check, its owner's counts unchanged), and 34 s
after it:

| | After the reboot |
|---|---|
| the units | `sandcastle-vms`, `sandcastle-engine`, `nitro-home` active, 0 restarts each |
| the VMs' cgroup | the keeper in `sandcastle-vms.service/keeper`, handing out `cpu memory pids` |
| the device and the pool | `/dev/nitro_enclaves` 0660 in group `nitro`; `nitro_enclaves.mempool=22G@0` on the kernel's line |
| the engine | "recovered {adopted: [], cleared: []}", serving; 0 VMs, 0 of 17,000 MiB |
| a computer of lane A's (the Hermes image, 6 GiB, a temporary home half) | started in 1,200 ms; exec over its session answered (2 CPUs) |
| after its destroy | no computer and no `vm-` cgroup left; the home active |
