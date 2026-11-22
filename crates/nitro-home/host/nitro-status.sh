#!/usr/bin/env bash
# Every parent's homes, engine, pool and host, from the operator's machine
# (docs/nitro-home.md, "Logs and numbers"):
#
#   nitro-status.sh [--json]
#
# Parents are listed in $NITRO_PARENTS (default ~/.cache/nitro-real/parents),
# one a line: `<label> <ssh config> <ssh host>`. Each runs home-status.sh
# (counts, sizes and times alone). Without --json, a line per home and one
# per parent's capacity.
set -euo pipefail
list=${NITRO_PARENTS:-$HOME/.cache/nitro-real/parents}
here=$(dirname "$(realpath "$0")")
json=false
[ "${1:-}" = "--json" ] && json=true
all=()
while read -r label config host; do
    case "$label" in ''|'#'*) continue ;; esac
    out=$(ssh -F "$config" -o ConnectTimeout=10 "$host" 'sudo bash -s' < "$here/home-status.sh" 2>/dev/null || echo '{"unreachable": true}')
    all+=("$(jq -c --arg parent "$label" '. + {parent: $parent}' <<< "$out")")
done < "$list"
report=$(printf '%s\n' "${all[@]}" | jq -s '.')
if $json; then echo "$report"; exit 0; fi
jq -r '.[] | .parent as $p | if .unreachable then "\($p): UNREACHABLE" else
    (.homes[] | "\(.unit | sub("^nitro-home@?"; "") | sub("\\.service$"; "") | if . == "" then "home" else . end) on \($p): \(.state), up since \(.since), \(.restarts) restarts, slot \(.slot), served in \(.serve_ms // "?") ms, door \(.door_accounts // "?") accounts, cells \(.stats.cells // "?"), mem \(.stats.mem_mib.available // "?")/\(.stats.mem_mib.total // "?") MiB free, data \(.stats.data_mib.free // "?") MiB free; last hour: \(.last_hour.boots) boots, \(.last_hour.failed) failed, \(.last_hour.error_lines) error lines, \(.last_hour.computer_starts_refused) computer starts refused"),
    "\(.parent) capacity: engine \(.engine.state) \(.engine.health.vms // "?")/\(.engine.health.vms_max // "?") VMs, \(.engine.health.memory_mib // "?")/\(.engine.health.memory_mib_max // "?") MiB; pool \(.pool.cpus.free)/\(.pool.cpus.total) CPUs and \(.pool.memory_mib.free)/\(.pool.memory_mib.total) MiB free, \(.pool.pcie_slots.used)/\(.pool.pcie_slots.total) PCIe slots used; host load \(.host.load), \(.host.memory_available_mib) MiB free, disk \(.host.disk_free_mib) MiB free" end' <<< "$report"
