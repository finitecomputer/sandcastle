#!/usr/bin/env bash
# Moves the home onto a staged slot, or back to the one before, as root
# (docs/nitro-home.md, "Deploys"):
#
#   sudo ./home-switch.sh <slot> | --rollback
#
# `current` then names the slot and `previous` the one it ran before; the
# home restarts onto it gracefully (its stop keeps its computers running),
# and the switch waits for this start to serve ("home: serving") with its
# door holding as many accounts as the start before. If it fails, or does
# not within SWITCH_S_MAX, the home goes back onto the slot it ran, and the
# switch exits non-zero. Prints the pause: from the restart to serving.
set -euo pipefail
base=/var/lib/nitro-home
SWITCH_S_MAX=${SWITCH_S_MAX:-300}
[ "$(id -u)" = 0 ] || { echo "home-switch: run as root" >&2; exit 1; }
ran=$(readlink -f "$base/current" 2>/dev/null || true)
case "${1:?a slot, or --rollback}" in
    --rollback) target=$(readlink -f "$base/previous" 2>/dev/null || true); [ -n "$target" ] || { echo "home-switch: no slot before this one" >&2; exit 1; } ;;
    *) target=$base/slots/$1 ;;
esac
[ -x "$target/nitro-home" ] && [ -s "$target/home.json" ] || { echo "home-switch: $target is no staged slot" >&2; exit 1; }
point() { ln -sfn "$2" "$base/$1.new" && mv -T "$base/$1.new" "$base/$1"; }
# the door's account count at the start before: a count, nothing else
accounts() { journalctl -u nitro-home --since "$1" -o cat --no-pager | sed -n 's/.*home: door: \([0-9]*\) accounts.*/\1/p' | tail -n 1; }
before=$(accounts "-30 days")
# waits for this start's verdict, from its own process's lines alone (the
# one it replaced says "exited" as it stops); prints "ok <ms>" or why not
serve() {
    local pid=$1 t0=$2 line
    for _ in $(seq $((SWITCH_S_MAX * 2))); do
        line=$(journalctl _PID="$pid" -o cat --no-pager | grep -E 'home: (serving|failed)|"home":"(failed|exited|lost)"' | head -n 1 || true)
        case "$line" in
            *"home: serving"*) echo "ok $(( ($(date +%s%N) - t0) / 1000000 ))"; return 0 ;;
            ?*) echo "failed: $line"; return 1 ;;
        esac
        sleep 0.5
    done
    echo "not serving within ${SWITCH_S_MAX}s"
    return 1
}
start() {
    local pid t0 verdict now
    t0=$(date +%s%N)
    systemctl restart nitro-home
    pid=$(systemctl show -p MainPID --value nitro-home)
    [ "${pid:-0}" != 0 ] || { echo "no process after the restart"; return 1; }
    verdict=$(serve "$pid" "$t0") || { echo "$verdict"; return 1; }
    now=$(journalctl _PID="$pid" -o cat --no-pager | sed -n 's/.*home: door: \([0-9]*\) accounts.*/\1/p' | tail -n 1)
    if [ -n "$before" ] && [ "$now" != "$before" ]; then echo "the door holds $now accounts, $before before"; return 1; fi
    echo "${verdict#ok }"
}
point current "$target"
[ -n "$ran" ] && [ "$ran" != "$target" ] && point previous "$ran"
if pause=$(start); then
    echo "{\"slot\": \"$(basename "$target")\", \"pause_ms\": $pause, \"door_accounts\": \"${before:-?}\"}"
    exit 0
fi
echo "home-switch: $(basename "$target") did not serve ($pause); back onto $(basename "${ran:-none}")" >&2
[ -n "$ran" ] || exit 1
point current "$ran"
point previous "$target"
back=$(start) || { echo "home-switch: the slot before did not serve either ($back)" >&2; exit 2; }
echo "{\"slot\": \"$(basename "$ran")\", \"rolled_back_from\": \"$(basename "$target")\", \"pause_ms\": $back}"
exit 1
