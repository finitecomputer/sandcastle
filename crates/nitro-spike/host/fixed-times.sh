#!/usr/bin/env bash
# Every inode of an ext4 image given the same times, so the same files make
# the same image (verity-image.sh, before its hash tree):
#
#   ./fixed-times.sh <image> <unix seconds>
#
# `mke2fs -d` copies each file's atime, mtime and ctime into the image, and a
# ctime is the moment its file was last written or changed, which no tool
# can set: a stage copied afresh makes another image, and so another root
# hash and PCR0. This sets atime, mtime, ctime and crtime (and their
# nanoseconds) of every inode in use, under the same fake clock as the
# filesystem's own times (E2FSPROGS_FAKE_TIME), so the superblock's write
# time is fixed too.
set -euo pipefail
image=$1
at=$2
[[ "$at" =~ ^[0-9]+$ ]] || { echo "fixed-times: <unix seconds>" >&2; exit 2; }
export E2FSPROGS_FAKE_TIME=$at
inodes=$(dumpe2fs -h "$image" 2>/dev/null | sed -n 's/^Inode count: *//p')
[ -n "$inodes" ] || { echo "fixed-times: $image is no ext4 image" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
seq 1 "$inodes" | sed 's/.*/testi <&>/' > "$work/test"
debugfs -f "$work/test" "$image" 2>&1 | sed -n 's/^Inode \([0-9]*\) is marked in use$/\1/p' > "$work/used"
while read -r n; do
    for f in atime mtime ctime crtime; do
        echo "sif <$n> $f @$at"
        echo "sif <$n> ${f}_extra 0"
    done
done < "$work/used" > "$work/set"
debugfs -w -f "$work/set" "$image" > "$work/out" 2>&1
! grep -qiE "error|invalid|unknown" "$work/out" || { grep -iE "error|invalid|unknown" "$work/out" | head -3 >&2; exit 1; }
echo "fixed-times: $(wc -l < "$work/used") inodes at $at" >&2
