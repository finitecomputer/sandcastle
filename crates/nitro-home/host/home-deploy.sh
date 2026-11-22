#!/usr/bin/env bash
# A home's deploy, one command on the operator's machine (docs/nitro-home.md,
# "Deploys"):
#
#   home-deploy.sh [--door <fragment tree> <git ref>] [--pin <pcr0>]...
#   home-deploy.sh --rollback
#
# It reads the operator's directory ($NITRO_HOME_DIR, default
# ~/.cache/nitro-real/home): ssh/config (host `nitro-home`, the parent),
# out/release and out/sealed-files (`cargo xtask home render`'s),
# sealed.json, launcher.json, pins, kms/key-id and kms/policy.json. Then:
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
#     health checked, and back onto the slot before by itself on failure.
#
# `--pin` adds a computer image's PCR0 to the home's pins first.
# `--rollback` moves the home back onto the slot before (its PCR0 is the
# policy's second).
set -euo pipefail
H=${NITRO_HOME_DIR:-$HOME/.cache/nitro-real/home}
SC=$(realpath "$(dirname "$(realpath "$0")")/../../..")
S="-F $H/ssh/config"
say() { echo "home-deploy: $*" >&2; }
t0=$(date +%s)
if [ "${1:-}" = "--rollback" ]; then
    ssh $S nitro-home 'sudo bash ~/sandcastle/crates/nitro-home/host/home-switch.sh --rollback'
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
rsync -a --delete --exclude target --exclude .git -e "ssh $S" "$SC/" nitro-home:sandcastle/
rsync -a --delete -e "ssh $S" "$H/out/release/" nitro-home:home-release/
scp $S -q "$H/sealed.json" nitro-home:sealed.json
scp $S -q "$H/launcher.json" nitro-home:launcher.json
scp $S -q "$H/pins" nitro-home:pins
if [ -n "$door_ref" ]; then
    # over the tree the parent has, so its build cache stays
    sha=$(git -C "$door_tree" rev-parse "$door_ref")
    git -C "$door_tree" archive "$sha" | ssh $S nitro-home "mkdir -p ~/fragment && tar -x -C ~/fragment && echo $sha > ~/fragment/.source-sha"
fi
# 3. built and staged beside the running home
say "building on the parent"
ssh $S nitro-home 'bash ~/sandcastle/crates/nitro-home/host/home-build.sh ~/fragment ~/sandcastle > ~/home-build/build.log 2>&1 || { tail -n 20 ~/home-build/build.log; exit 1; }'
slot=$(ssh $S nitro-home 'sudo bash ~/sandcastle/crates/nitro-home/host/home-stage.sh ~/home-build/out ~/home-release ~/sealed.json ~/launcher.json ~/pins' | tail -n 1)
say "staged $slot"
# 4. measured beside it, verified here, pinned
mkdir -p "$H/attest"
ssh $S nitro-home "sudo /var/lib/nitro-home/slots/$slot/nitro-home measure --conf /var/lib/nitro-home/slots/$slot/home.json" > "$H/attest/measure-$slot.json"
python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["attestation"])' "$H/attest/measure-$slot.json" > "$H/attest/measure-$slot.log"
PATH="$SC/target/release:$PATH" "$SC/crates/nitro-home/host/pin-pcr0.sh" "$H/attest/measure-$slot.log" "$(cat "$H/kms/key-id")" "$H/kms/policy.json" >&2
# 5. switched onto, its health checked, back by itself on failure
say "switching"
ssh $S nitro-home "sudo bash ~/sandcastle/crates/nitro-home/host/home-switch.sh $slot"
say "done in $(( $(date +%s) - t0 )) s"
