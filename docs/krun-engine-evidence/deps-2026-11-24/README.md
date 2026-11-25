# Dependencies, 2026-11-24: unjailed evidence

What ran without the box's engine. Each file is one VM started with
`sandcastle-vm run` (unjailed, no seccomp, in a user scope of its own), with
2 vCPUs, 2 GiB, the balloon on, and a busybox 1.38 image running `sleep`. The
host's THP is `always`. The same sandcastle binaries (this branch) ran both:

- `vm-old*.txt`: the libraries the box runs today, libkrun c9327bda and
  libkrunfw v5.6.3;
- `vm-new*.txt`: libkrun 715c1c98 and libkrunfw v5.6.4, built from source.

Memory is the VM scope's `memory.current` and the VMM's `smaps_rollup`,
idle, with 1 GiB held in a guest tmpfs, and after that memory is freed. Pause
and resume go through the runner's control socket. That was before the
runner refused both: libkrun only queues them, so the times are a queue's.

`kernel-v5.6.3-to-v5.6.4.diff` is `diff -r` of libkrun/linux's two tags:
one change, in `net/vmw_vsock/af_vsock.c`.
