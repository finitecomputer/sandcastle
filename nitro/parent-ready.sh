#!/usr/bin/env bash
# Takes a fresh Amazon Linux 2023 parent, launched with Nitro Enclaves
# enabled, to "ready for sandboxes" (docs/nitro.md, "Release assets"),
# then prints the host's facts as one JSON object on stdout. It is
# idempotent: run it, reboot when it says so, run it again.
#
#   sudo POOL=8G SLOTS=4 ./parent-ready.sh
#
# Exit codes: 0 ready, facts printed; 3 a reboot is needed (it says why);
# 1 anything else.
#
# Shell, not Rust (docs/engineering-style.md: scripts are Rust "unless a
# non-Rust tool is clearly better"): every step is one dnf, grubby, sysfs
# or download line, and it runs on a fresh instance before any toolchain
# exists. What it sets up, from the EC2 User Guide's "Run Firecracker"
# page and Firecracker v1.18's docs/nitro-sandboxes/ (read 2026-11-20):
#
#  1. kernel6.18 at 6.18.51-120.162.amzn2023 or later: the Nitro Enclaves
#     driver's sandbox support.
#  2. A memory pool reserved at boot: nitro_enclaves.mempool=<POOL>@0.
#  3. Firecracker v1.18.0 (the first with Nitro Sandboxes), its release
#     archive checked against the SHA-256 pinned here.
#  4. Build tools for the guest kernel and the spike's crates, and Rust
#     (pinned) for the user who builds.
#  5. The slot budget raised to SLOTS (4, then steps of 8).
#  6. /dev/nitro_enclaves in a group of its own (NITRO_GROUP), by a udev
#     rule, so sandcastle's jailed VM uids open it as they open /dev/kvm
#     elsewhere, never as root.
set -euo pipefail

POOL=${POOL:-8G}
SLOTS=${SLOTS:-4}
KERNEL_MIN=6.18.51-120.162.amzn2023
FIRECRACKER_VERSION=1.18.0
# From the release's own .sha256.txt files, fetched 2026-11-20.
declare -A FIRECRACKER_SHA256=(
    [aarch64]=2a6130ff0338901ff9d7fbd73ce046c6b1c6123889dc84a34d678aa53bd0c0c2
    [x86_64]=1ac8eec866dd5eea14efecf6323e22b23eea24054545338a5b34bc5bca6623cd
)
RUST_TOOLCHAIN=1.99.0
BUILD_USER=${SUDO_USER:-ec2-user}
NE=/sys/class/misc/nitro_enclaves
NITRO_GROUP=${NITRO_GROUP:-nitro}

die() { echo "parent-ready: $*" >&2; exit 1; }
say() { echo "parent-ready: $*" >&2; }
# ver_ge A B: version A is B or later.
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

[ "$(id -u)" = 0 ] || die "run as root (sudo)"
ARCH=$(uname -m)
[ -n "${FIRECRACKER_SHA256[$ARCH]:-}" ] || die "unsupported architecture $ARCH"
. /etc/os-release
[ "$ID" = amzn ] && [ "$VERSION_ID" = 2023 ] || die "Amazon Linux 2023 only (found $ID $VERSION_ID)"
[ -c /dev/nitro_enclaves ] || die "/dev/nitro_enclaves is missing: launch the instance with --enclave-options Enabled=true"

reboot_for=()

# 1. The kernel. The running one decides; a newer one installed but not
# yet booted asks for a reboot.
running=${KERNEL_RUNNING:-$(uname -r)}
running=${running%".$ARCH"}
if ! ver_ge "$running" "$KERNEL_MIN"; then
    newest=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' kernel6.18 2>/dev/null | sort -V | tail -n1 || true)
    if [ -z "$newest" ] || ! ver_ge "$newest" "$KERNEL_MIN"; then
        say "installing kernel6.18 >= $KERNEL_MIN (running $running)"
        # The AMI's repository is locked to its release; the latest one
        # carries the kernel the sandbox support landed in.
        dnf -y -q --releasever=latest install kernel6.18
        newest=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' kernel6.18 | sort -V | tail -n1)
        ver_ge "$newest" "$KERNEL_MIN" || die "the newest kernel6.18 is $newest, under $KERNEL_MIN"
    fi
    grubby --set-default "/boot/vmlinuz-$newest.$ARCH"
    reboot_for+=("kernel $newest")
fi

# 2. The pool, on every installed kernel's command line.
want="nitro_enclaves.mempool=${POOL}@0"
if ! grubby --info=DEFAULT | grep -q -- "$want"; then
    grubby --update-kernel=ALL --args="$want"
fi
if ! grep -q -- "$want" /proc/cmdline; then
    reboot_for+=("$want")
fi

# 3. Packages: the guest kernel's build, the initrd, dm-verity, the
# network (nftables), and the spike's crates.
dnf -y -q --setopt=install_weak_deps=False install \
    gcc make git flex bison bc perl elfutils-libelf-devel openssl-devel dwarves \
    cpio e2fsprogs cryptsetup veritysetup nftables socat python3 tar gzip

# 4. Firecracker, checked against the pinned digest before it is installed.
installed=$(/usr/local/bin/firecracker --version 2>/dev/null | head -n1 || true)
if [ "$installed" != "Firecracker v$FIRECRACKER_VERSION" ]; then
    work=$(mktemp -d /var/tmp/firecracker.XXXXXX)
    tgz=$work/firecracker.tgz
    curl -sSfL -o "$tgz" "https://github.com/firecracker-microvm/firecracker/releases/download/v$FIRECRACKER_VERSION/firecracker-v$FIRECRACKER_VERSION-$ARCH.tgz"
    echo "${FIRECRACKER_SHA256[$ARCH]}  $tgz" | sha256sum -c --quiet - || die "Firecracker's archive does not match its pinned SHA-256"
    tar -xzf "$tgz" -C "$work"
    rel=$work/release-v$FIRECRACKER_VERSION-$ARCH
    install -m 0755 "$rel/firecracker-v$FIRECRACKER_VERSION-$ARCH" /usr/local/bin/firecracker
    install -m 0755 "$rel/jailer-v$FIRECRACKER_VERSION-$ARCH" /usr/local/bin/jailer
    rm -rf "$work"
fi
[ "$(/usr/local/bin/firecracker --version | head -n1)" = "Firecracker v$FIRECRACKER_VERSION" ] || die "Firecracker is not v$FIRECRACKER_VERSION"

# 5. Rust for the build user: a pinned toolchain and the static target
# the guest's init is built for.
if ! sudo -u "$BUILD_USER" -i bash -c "rustup toolchain list 2>/dev/null | grep -q '^$RUST_TOOLCHAIN'"; then
    sudo -u "$BUILD_USER" -i bash -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain $RUST_TOOLCHAIN -c clippy"
fi
sudo -u "$BUILD_USER" -i bash -c "rustup target add --toolchain $RUST_TOOLCHAIN $ARCH-unknown-linux-musl >/dev/null"

if [ ${#reboot_for[@]} -gt 0 ]; then
    say "reboot, then run this again; it needs: ${reboot_for[*]}"
    exit 3
fi

# 6. The device's group, now and at every boot.
getent group "$NITRO_GROUP" > /dev/null || groupadd --system "$NITRO_GROUP"
rule=/etc/udev/rules.d/90-sandcastle-nitro.rules
want_rule="KERNEL==\"nitro_enclaves\", GROUP=\"$NITRO_GROUP\", MODE=\"0660\""
if [ "$(cat "$rule" 2>/dev/null)" != "$want_rule" ]; then
    echo "$want_rule" > "$rule"
    udevadm control --reload
fi
chgrp "$NITRO_GROUP" /dev/nitro_enclaves
chmod 0660 /dev/nitro_enclaves

# 7. Slots: only up, in steps of 8 (the parent rounds a value up).
if [ "$(cat $NE/pcie_slots)" -lt "$SLOTS" ]; then
    echo "$SLOTS" > $NE/pcie_slots
fi

# 8. The facts. No instance id, AMI id or address: they go into a public
# repository.
pool_line=$(dmesg | grep -m1 "nitro_enclaves: CMA pool" || true)
# Amazon Linux's own reader of the instance metadata (amazon-ec2-utils).
itype=$(ec2-metadata --instance-type 2>/dev/null | awk '{print $2}' || true)
python3 -I - "$NE" "$pool_line" "$itype" "$RUST_TOOLCHAIN" <<'PY'
import json, os, platform, subprocess, sys
ne, pool_line, itype, rust = sys.argv[1:5]
def read(p):
    try:
        return open(os.path.join(ne, p)).read().strip()
    except OSError:
        return None
def mib(v):
    return None if v is None else int(v) // (1 << 20)
dev = os.stat("/dev/nitro_enclaves")
meminfo = dict(l.split(":", 1) for l in open("/proc/meminfo"))
facts = {
    "instance_type": itype or None,
    "arch": platform.machine(),
    "os": open("/etc/system-release").read().strip(),
    "kernel": platform.release(),
    "cmdline_pool": next((a for a in open("/proc/cmdline").read().split() if a.startswith("nitro_enclaves.mempool=")), None),
    "pool_kernel_log": pool_line or None,
    "mem_pool_mib": {"total": mib(read("mem_pool/total")), "in_use": mib(read("mem_pool/in_use")), "free": mib(read("mem_pool/free"))},
    "cpu_pool": {"total": read("cpu_pool/total"), "in_use": read("cpu_pool/in_use"), "free": read("cpu_pool/free")},
    "pcie_slots": {"now": read("pcie_slots"), "total": read("pcie_slots_total"), "in_use": read("pcie_slots_in_use")},
    "dev_nitro_enclaves": {"mode": oct(dev.st_mode & 0o777), "uid": dev.st_uid, "gid": dev.st_gid},
    "vcpus": os.cpu_count(),
    "mem_total_mib": int(meminfo["MemTotal"].split()[0]) // 1024,
    "firecracker": subprocess.run(["/usr/local/bin/firecracker", "--version"], capture_output=True, text=True).stdout.splitlines()[0],
    "rust": rust,
}
print(json.dumps(facts, indent=1))
PY
