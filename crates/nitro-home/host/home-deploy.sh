#!/usr/bin/env bash
# A home's deploy, one command on the operator's machine (docs/nitro-home.md,
# "Deploys"):
#
#   home-deploy.sh [--home <name>] [--door <fragment tree> <git ref>] [--pin <pcr0>]...
#   home-deploy.sh [--home <name>] --rollback
#
# It reads the operator's directory ($NITRO_HOME_DIR, default
# ~/.cache/nitro-real/home, or ~/.cache/nitro-real/homes/<name> for
# --home): the parent (`parent`: `<ssh config> <ssh host>`; without it,
# ssh/config's host `nitro-home`), out/release and out/sealed-files
# (`cargo xtask home render`'s), sealed.json, launcher.json, pins,
# kms/key-id and kms/policy.json. Then:
#
#  1. the bundle is sealed again only when what it seals changed;
#  2. this sandcastle tree, the release, the bundle, the conf and the pins
#     go to the parent (and fragment's tree at --door's ref, for the door);
#  3. the parent builds what changed (home-build.sh) and stages a slot
#     beside the running home (home-stage.sh);
#  4. the slot's image is measured beside the running home (`nitro-home
#     measure`), its document verified here, and its PCR0 pinned in the
#     key's policy, the running image's kept for a rollback;
#  5. the home switches onto it (home-switch.sh): a graceful restart, its
#     health checked, and back onto the slot before by itself on failure;
#     never while its sealed journal has a hole after its newest snapshot
#     (home-journal-check.py, which a start would refuse: exit 3).
#
# `--pin` adds a computer image's PCR0 to the home's pins first.
# `--rollback` moves the home back onto the slot before (its PCR0 is the
# policy's second).
#
# `--home <name>` deploys one of several homes on its parent
# (docs/nitro-home.md, "Many homes on one parent"): its own slots, unit and
# files on the parent (~/homes/<name>), the parent's build shared. Deploys
# to one parent go one at a time (a lock here, per parent); a new home's
# key releases to its first image alone.
set -euo pipefail
SC=$(realpath "$(dirname "$(realpath "$0")")/../../..")
say() { echo "home-deploy: $*" >&2; }
name= named=
if [ "${1:-}" = "--home" ]; then
    name=${2:?--home takes a name}
    named="--home $name"
    shift 2
    H=${NITRO_HOME_DIR:-$HOME/.cache/nitro-real/homes/$name}
    remote=homes/$name base=/var/lib/nitro-home/homes/$name
else
    H=${NITRO_HOME_DIR:-$HOME/.cache/nitro-real/home}
    remote=. base=/var/lib/nitro-home
fi
if [ -s "$H/parent" ]; then read -r pconf P < "$H/parent"; else pconf=$H/ssh/config P=nitro-home; fi
S="-F $pconf"
host='~/sandcastle/crates/nitro-home/host'
t0=$(date +%s)
mkdir -p "$HOME/.cache/nitro-real/locks"
exec 9> "$HOME/.cache/nitro-real/locks/$P.lock"
flock 9 || { say "the parent's lock"; exit 1; }
# Before any restart: a home whose sealed journal has a hole after its
# newest snapshot would refuse to start (celld#30; celld#31 stops new ones).
# Its running celld still holds the index, and its next snapshot puts the
# hole behind it, so the restart waits until then.
journal_ok() {
    "$SC/crates/nitro-home/host/home-journal-check.py" "$H/launcher.json" >&2 || {
        say "not restarting the home: its journal must have no hole after its newest snapshot (home-journal-check.py); try again after its next snapshot"
        exit 3
    }
}
if [ "${1:-}" = "--rollback" ]; then
    journal_ok
    ssh $S "$P" "sudo bash $host/home-switch.sh $named --rollback"
    exit
fi
door_tree= door_ref=
while [ $# -gt 0 ]; do
    case "$1" in
        --door) door_tree=$2 door_ref=$3; shift 3 ;;
        --pin)
            [[ "$2" =~ ^[0-9a-f]{96}$ ]] || { say "--pin takes a PCR0: 96 hex"; exit 2; }
            grep -qx "$2" "$H/pins" || printf '%s\n%s\n' "# pinned by home-deploy $(date -u +%Y-%m-%dT%H:%MZ)" "$2" >> "$H/pins"
            shift 2 ;;
        *) say "unknown $1"; exit 2 ;;
    esac
done
# 1. the bundle: sealed again only when its files changed (KMS Encrypt)
digest=$(cd "$H/out/sealed-files" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-64)
if [ "$(cat "$H/sealed.digest" 2>/dev/null)" != "$digest" ]; then
    say "the bundle's files changed: sealing it again"
    "$SC/target/release/nitro-home-seal" --dir "$H/out/sealed-files" --kms-key "$(cat "$H/kms/key-id")" --out "$H/sealed.json.new" > /dev/null
    mv "$H/sealed.json.new" "$H/sealed.json"
    echo "$digest" > "$H/sealed.digest"
fi
# 2. what the parent builds from, and what it stages
rsync -a --delete --exclude target --exclude .git -e "ssh $S" "$SC/" "$P:sandcastle/"
ssh $S "$P" "mkdir -p -m 0700 ~/$remote"
rsync -a --delete -e "ssh $S" "$H/out/release/" "$P:$remote/home-release/"
scp $S -q "$H/sealed.json" "$P:$remote/sealed.json"
scp $S -q "$H/launcher.json" "$P:$remote/launcher.json"
scp $S -q "$H/pins" "$P:$remote/pins"
if [ -n "$door_ref" ]; then
    # over the tree the parent has, so its build cache stays
    sha=$(git -C "$door_tree" rev-parse "$door_ref")
    git -C "$door_tree" archive "$sha" | ssh $S "$P" "mkdir -p ~/fragment && tar -x -C ~/fragment && echo $sha > ~/fragment/.source-sha"
fi
# 3. built and staged beside the running home
say "building on the parent"
ssh $S "$P" 'mkdir -p ~/home-build && bash ~/sandcastle/crates/nitro-home/host/home-build.sh ~/fragment ~/sandcastle > ~/home-build/build.log 2>&1 || { tail -n 20 ~/home-build/build.log; exit 1; }'
slot=$(ssh $S "$P" "sudo bash $host/home-stage.sh $named ~/home-build/out ~/$remote/home-release ~/$remote/sealed.json ~/$remote/launcher.json ~/$remote/pins" | tail -n 1)
say "staged $slot"
# 4. measured beside it, verified here, pinned. Each slot's PCR0, once
# verified here, is kept here ($H/attest/slots.tsv): the policy then keeps
# the running slot's, so a rollback to it opens, and the parent naming the
# running slot can only name one of the home's own verified images.
mkdir -p "$H/attest"
ssh $S "$P" "sudo $base/slots/$slot/nitro-home measure --conf $base/slots/$slot/home.json" > "$H/attest/measure-$slot.json"
python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["attestation"])' "$H/attest/measure-$slot.json" > "$H/attest/measure-$slot.log"
line=$(cat "$H/attest/measure-$slot.log")
nonce=${line#*nonce=}; nonce=${nonce%% *}
echo "${line#*document=}" | python3 -I -c "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().strip()))" > "$H/attest/measure-$slot.doc"
pcr0=$("$SC/target/release/nitro-verify" --document "$H/attest/measure-$slot.doc" --nonce "$nonce" | python3 -I -c 'import json,sys; d=json.load(sys.stdin); assert d["verified"] is True; print(d["pcrs"]["0"])')
printf '%s\t%s\n' "$slot" "$pcr0" >> "$H/attest/slots.tsv"
running_slot=$(ssh $S "$P" "sudo readlink -e $base/current || true")
if [ -z "$running_slot" ]; then
    # a new home: its key releases to this image alone
    running=$pcr0
else
    running_slot=$(basename "$running_slot")
    running=$(awk -F'\t' -v s="$running_slot" '$1 == s { p = $2 } END { print p }' "$H/attest/slots.tsv")
    [ -n "$running" ] || { say "the running slot $running_slot has no PCR0 verified here (attest/slots.tsv): refusing to drop it from the policy"; exit 1; }
fi
PATH="$SC/target/release:$PATH" "$SC/crates/nitro-home/host/pin-pcr0.sh" "$H/attest/measure-$slot.log" "$(cat "$H/kms/key-id")" "$H/kms/policy.json" --keep "$running" >&2
# 5. switched onto, its health checked, back by itself on failure, once its
# journal lets it start again
journal_ok
say "switching"
ssh $S "$P" "sudo SWITCH_S_MAX=${SWITCH_S_MAX:-300} bash $host/home-switch.sh $named $slot"
say "done in $(( $(date +%s) - t0 )) s"
