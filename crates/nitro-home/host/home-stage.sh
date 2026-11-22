#!/usr/bin/env bash
# Stages a home image on its parent (docs/nitro-home.md, "Deploys"), as
# root, beside the running home:
#
#   sudo ./home-stage.sh [--home <name>] <home-build out> <release dir> <sealed bundle> <launcher conf> <pins>
#
# A slot of its own, /var/lib/nitro-home/slots/<UTC time>: the image
# (home-image.sh: the release, the bundle, the pins and the start baked
# into its measured root), its kernel and initrd, the launcher, and the
# conf with its paths into the slot. Its data disk, scratch disk and
# sockets stay the home's. Nothing running is touched; home-switch.sh moves
# the home onto a slot. The newest SLOTS_KEPT slots are kept (the running
# one, the one before it, the new one). Prints the slot's name.
#
# With --home (home-name.sh), one of several homes on the parent: its
# disks and sockets are its own (the conf's paths for them are replaced),
# and its CID, tap and addresses must be no other home's here.
set -euo pipefail
here=$(dirname "$(realpath "$0")")
source "$here/home-name.sh"
home_name "$@"
set -- "${HOME_ARGS[@]}"
build=$(realpath "$1")
release=$(realpath "$2")
sealed=$(realpath "$3")
conf=$(realpath "$4")
pins=$(realpath "$5")
SLOTS_KEPT=3
[ "$(id -u)" = 0 ] || { echo "home-stage: run as root" >&2; exit 1; }
install -d -m 0700 /var/lib/nitro-home "$base" "$base/slots"
# a home installed before slots runs from the old layout: it becomes the
# slot `legacy`, which `current` names (nothing restarts), so the first
# switch has a slot to go back to
if [ -z "$name" ] && [ ! -e "$base/current" ] && [ -x /usr/local/bin/nitro-home ] && [ -s /etc/nitro-home/home.json ]; then
    install -d -m 0700 "$base/slots/legacy"
    install -m 0755 /usr/local/bin/nitro-home "$base/slots/legacy/nitro-home"
    install -m 0600 /etc/nitro-home/home.json "$base/slots/legacy/home.json"
    ln -sfn "$base/slots/legacy" "$base/current"
fi
slot=$(date -u +%Y%m%dT%H%M%SZ)
dir=$base/slots/$slot
[ ! -e "$dir" ] || { echo "home-stage: $dir exists" >&2; exit 1; }
install -d -m 0700 "$dir" "$dir/image"
# the slot's conf first: a home's CID, tap or address taken is refused
# before anything is built
python3 -I - "$conf" "$dir" "$name" "$base" "$run" > "$dir/home.json" <<'PY' || { rm -rf "$dir"; exit 1; }
import glob, json, os, sys
conf, d, name, base, run = sys.argv[1:6]
c = json.load(open(conf))
c.update({"kernel": f"{d}/image/Image", "initrd": f"{d}/image/guest.initrd", "image_json": f"{d}/image/home.json",
          "image_config": f"{d}/image/home.config.json", "sealed": f"{d}/sealed.json"})
if name:
    c.update({"data": f"{base}/data.img", "scratch": f"{base}/scratch.img", "dir": f"{run}/run", "vsock_dir": f"{run}/vsock"})
    # what two homes on one parent can never share
    others = {p for p in glob.glob("/var/lib/nitro-home/homes/*/current/home.json") + ["/var/lib/nitro-home/current/home.json"]
              if os.path.exists(p) and not p.startswith(base + "/")}
    for p in sorted(others):
        o = json.load(open(p))
        for k in ("cid", "tap", "host_addr", "guest_addr"):
            if o.get(k) == c.get(k):
                sys.exit(f"home-stage: {k} {c.get(k)} is {p.split('/')[-3]}'s already")
        if 443 in o.get("inbound_tcp", []) or 443 in c.get("inbound_tcp", []):
            sys.exit("home-stage: a home here takes 443 forwarded untouched: several homes need the SNI router (home-router.sh), inbound_tcp []")
print(json.dumps(c, indent=1))
PY
chmod 0600 "$dir/home.json"
# the first slot's base digest is the image's from before slots, if any;
# every home on the parent builds on the same base
digest=/var/lib/nitro-home/base-digest
[ -s "$digest" ] || { [ -s /var/lib/nitro-home/image/home.base-digest ] && cp /var/lib/nitro-home/image/home.base-digest "$digest"; } || true
BASE_DIGEST_FILE="$digest" "$here/home-image.sh" "$build" "$release" "$dir/image/home" "$sealed" "$conf" "$pins" > "$dir/image-facts.json"
install -m 0644 "$build/Image" "$dir/image/Image"
install -m 0644 "$build/guest.initrd" "$dir/image/guest.initrd"
install -m 0755 "$build/nitro-home" "$dir/nitro-home"
install -m 0600 "$sealed" "$dir/sealed.json"
install -m 0644 "$build/build.json" "$dir/build.json"
# the unit runs whichever slot `current` names
if [ -z "$name" ]; then
    install -m 0644 "$here/nitro-home.service" /etc/systemd/system/nitro-home.service
else
    install -m 0644 "$here/nitro-home@.service" /etc/systemd/system/nitro-home@.service
fi
systemctl daemon-reload
# older slots go, never the running one or the one before it
keep="$(readlink -e "$base/current" 2>/dev/null || true) $(readlink -e "$base/previous" 2>/dev/null || true)"
ls -1d "$base"/slots/*/ 2>/dev/null | sed 's#/$##' | sort -r | tail -n +$((SLOTS_KEPT + 1)) | while read -r old; do
    case " $keep " in *" $old "*) ;; *) rm -rf "$old" ;; esac
done
echo "$slot"
