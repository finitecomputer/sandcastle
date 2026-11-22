#!/usr/bin/env bash
# Stages a home image on its parent (docs/nitro-home.md, "Deploys"), as
# root, beside the running home:
#
#   sudo ./home-stage.sh <home-build out> <release dir> <sealed bundle> <launcher conf> <pins>
#
# A slot of its own, /var/lib/nitro-home/slots/<UTC time>: the image
# (home-image.sh: the release, the bundle, the pins and the start baked
# into its measured root), its kernel and initrd, the launcher, and the
# conf with its paths into the slot. Its data disk, scratch disk and
# sockets stay the home's. Nothing running is touched; home-switch.sh moves
# the home onto a slot. The newest SLOTS_KEPT slots are kept (the running
# one, the one before it, the new one). Prints the slot's name.
set -euo pipefail
build=$(realpath "$1")
release=$(realpath "$2")
sealed=$(realpath "$3")
conf=$(realpath "$4")
pins=$(realpath "$5")
here=$(dirname "$(realpath "$0")")
base=/var/lib/nitro-home
SLOTS_KEPT=3
[ "$(id -u)" = 0 ] || { echo "home-stage: run as root" >&2; exit 1; }
install -d -m 0700 "$base" "$base/slots"
# a home installed before slots runs from the old layout: it becomes the
# slot `legacy`, which `current` names (nothing restarts), so the first
# switch has a slot to go back to
if [ ! -e "$base/current" ] && [ -x /usr/local/bin/nitro-home ] && [ -s /etc/nitro-home/home.json ]; then
    install -d -m 0700 "$base/slots/legacy"
    install -m 0755 /usr/local/bin/nitro-home "$base/slots/legacy/nitro-home"
    install -m 0600 /etc/nitro-home/home.json "$base/slots/legacy/home.json"
    ln -sfn "$base/slots/legacy" "$base/current"
fi
slot=$(date -u +%Y%m%dT%H%M%SZ)
dir=$base/slots/$slot
[ ! -e "$dir" ] || { echo "home-stage: $dir exists" >&2; exit 1; }
install -d -m 0700 "$dir" "$dir/image"
# the first slot's base digest is the image's from before slots, if any
[ -s "$base/base-digest" ] || { [ -s "$base/image/home.base-digest" ] && cp "$base/image/home.base-digest" "$base/base-digest"; } || true
BASE_DIGEST_FILE="$base/base-digest" "$here/home-image.sh" "$build" "$release" "$dir/image/home" "$sealed" "$conf" "$pins" > "$dir/image-facts.json"
install -m 0644 "$build/Image" "$dir/image/Image"
install -m 0644 "$build/guest.initrd" "$dir/image/guest.initrd"
install -m 0755 "$build/nitro-home" "$dir/nitro-home"
install -m 0600 "$sealed" "$dir/sealed.json"
install -m 0644 "$build/build.json" "$dir/build.json"
python3 -I - "$conf" "$dir" > "$dir/home.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
d = sys.argv[2]
c.update({"kernel": f"{d}/image/Image", "initrd": f"{d}/image/guest.initrd", "image_json": f"{d}/image/home.json",
          "image_config": f"{d}/image/home.config.json", "sealed": f"{d}/sealed.json"})
print(json.dumps(c, indent=1))
PY
chmod 0600 "$dir/home.json"
# the unit runs whichever slot `current` names
install -m 0644 "$here/nitro-home.service" /etc/systemd/system/nitro-home.service
systemctl daemon-reload
# older slots go, never the running one or the one before it
keep="$(readlink -f "$base/current" 2>/dev/null || true) $(readlink -f "$base/previous" 2>/dev/null || true)"
ls -1d "$base"/slots/*/ 2>/dev/null | sed 's#/$##' | sort -r | tail -n +$((SLOTS_KEPT + 1)) | while read -r old; do
    case " $keep " in *" $old "*) ;; *) rm -rf "$old" ;; esac
done
echo "$slot"
