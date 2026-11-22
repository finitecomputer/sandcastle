#!/usr/bin/env bash
# Makes a computer's root a raw disk under dm-verity (docs/nitro-spike.md,
# acceptance 6), on the parent, as root:
#
#   sudo ./verity-image.sh <root dir> <extra dir> <out prefix>
#
# <root dir> is an image's whole filesystem (Hermes, flattened by
# `docker export`, so owners and modes are exact); <extra dir>'s files go
# under its /opt/nitro (the spike's key helper, FPAC, the entrypoint).
# Out: <prefix>.ext4 (the root, read-only to the guest), <prefix>.verity
# (its hash tree, a disk of its own) and <prefix>.json (what the kernel's
# command line needs: the data blocks, the root hash, the salt).
#
# The root hash goes on the kernel's command line (`dm-mod.create=`), which
# PCR0 and PCR1 measure, so the attestation covers every byte of the root:
# a block that does not hash to the tree is refused by the guest's kernel.
#
# Shell, not Rust, for the reason parent-ready.sh gives: mkfs.ext4 and
# veritysetup are the tools.
set -euo pipefail

root=$1
extra=$2
out=$3
[ "$(id -u)" = 0 ] || { echo "verity-image: run as root" >&2; exit 1; }
[ -d "$root/usr" ] || { echo "verity-image: $root is not a root filesystem" >&2; exit 1; }

stage=$(mktemp -d /var/tmp/verity-stage.XXXXXX)
trap 'rm -rf "$stage"' EXIT
# A copy, so the image's own directory is never changed; reflinks where
# the filesystem has them, a plain copy otherwise.
cp -a --reflink=auto "$root/." "$stage/"
mkdir -p "$stage/opt/nitro"
cp -a "$extra/." "$stage/opt/nitro/"
chown -R 0:0 "$stage/opt/nitro"

used=$(du -sb "$stage" | cut -f1)
# Room for ext4's own metadata and a little slack; the image is read-only,
# so nothing grows into it.
size_mib=$(( used * 115 / 100 / 1048576 + 256 ))
rm -f "$out.ext4" "$out.verity"
# A fixed UUID and hash seed, and a fixed time for every inode and the
# superblock, so the same tree makes the same bytes and so the same root
# hash.
E2FSPROGS_FAKE_TIME=1767225600 mkfs.ext4 -q -F -b 4096 -O ^has_journal -U 6e17f0a5-0000-4000-8000-00000000c0de -E hash_seed=6e17f0a5-0000-4000-8000-00000000c0de,root_owner=0:0 -d "$stage" "$out.ext4" "${size_mib}M"
# `mke2fs -d` copies every file's ctime, which no tool can set: the same
# files staged again make another image, unless every inode's times are set
"$(dirname "$(realpath "$0")")/fixed-times.sh" "$out.ext4" 1767225600
format=$(veritysetup format --data-block-size=4096 --hash-block-size=4096 --uuid=6e17f0a5-0000-4000-8000-00000000c0de --salt=6e17f0a50000400080000000000c0de06e17f0a50000400080000000000c0de0 "$out.ext4" "$out.verity")
field() { echo "$format" | awk -F: -v k="$1" '$1 == k {gsub(/[ \t]/, "", $2); print $2}'; }
root_hash=$(field "Root hash")
salt=$(field "Salt")
blocks=$(field "Data blocks")
python3 -I - "$out" "$root_hash" "$salt" "$blocks" "$size_mib" "$used" > "$out.json" <<'PY'
import json, sys, hashlib
out, root_hash, salt, blocks, size_mib, used = sys.argv[1:7]
# veritysetup's default format puts a superblock in the tree's first
# block, so the tree itself starts at block 1.
print(json.dumps({"image": out + ".ext4", "hash_tree": out + ".verity", "hash_start_block": 1, "data_block_bytes": 4096, "data_blocks": int(blocks), "algorithm": "sha256", "root_hash": root_hash, "salt": salt, "image_mib": int(size_mib), "files_bytes": int(used)}, indent=1))
PY
cat "$out.json"
