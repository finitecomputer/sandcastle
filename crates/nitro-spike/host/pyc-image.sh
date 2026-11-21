#!/usr/bin/env bash
# Line 9's bytecode study: the shipped Hermes root with valid bytecode for
# every module, compiled once at image build by the image's own Python in a
# chroot (so each file's recorded path is its path in the guest), as
# unchecked-hash pycs: the import system loads them without looking at the
# source's time, so a read-only root and PYTHONDONTWRITEBYTECODE cost nothing.
set -euo pipefail
SRC=/srv/hermes-root
DST=/srv/hermes-root-pyc
E=$HOME/nitro/image-extra
t0=$(date +%s.%N)
sudo rm -rf --one-file-system "$DST"
sudo cp -a --reflink=auto "$SRC" "$DST"
t1=$(date +%s.%N)
sudo mount --rbind /dev "$DST/dev"
sudo mount -t proc proc "$DST/proc"
set +e
sudo chroot "$DST" /opt/hermes/.venv/bin/python -m compileall -q -j 4 --invalidation-mode unchecked-hash /opt/hermes > $HOME/pyc-compile.log 2>&1
rc=$?
set -e
sudo umount "$DST/proc"
sudo umount -R "$DST/dev"
t2=$(date +%s.%N)
pycs=$(sudo find "$DST/opt/hermes" -name '*.pyc' -newer "$SRC/opt" | wc -l)
bytes=$(sudo find "$DST/opt/hermes" -name '*.pyc' -newer "$SRC/opt" -printf '%s\n' | awk '{s+=$1} END {print s}')
sudo $HOME/sandcastle/crates/nitro-spike/host/verity-image.sh "$DST" "$E" $HOME/nitro/images/hermes-pyc > /dev/null
sudo chown ec2-user: $HOME/nitro/images/hermes-pyc.*
t3=$(date +%s.%N)
echo "copy_s=$(echo "$t1 - $t0" | bc) compile_s=$(echo "$t2 - $t1" | bc) compileall_exit=$rc new_pycs=$pycs new_pyc_bytes=$bytes image_s=$(echo "$t3 - $t2" | bc)"
grep -c . $HOME/pyc-compile.log || true
