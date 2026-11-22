#!/usr/bin/env bash
# One parent's health, capacity and errors, as JSON (docs/nitro-home.md,
# "Logs and numbers"), as root:
#
#   sudo ./home-status.sh
#
# For each home on it (each `nitro-home*.service`): its state, restarts,
# time up, the slot it runs, its last boot's time to serve, its door's
# account count, its last stats line (the home's own counts and sizes),
# and the boots, refusals and failures in its console over the last hour.
# Then the computers' engine (its health), the SNI router (for several
# homes: its connections now and since its start, per home, and those
# closed for want of a home), the Nitro pool (CPUs, memory, PCIe slots
# free) and the host (load, memory, disk). Counts, sizes and times alone:
# no name, no path inside a home, no message.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "home-status: run as root" >&2; exit 1; }
pool=/sys/devices/virtual/misc/nitro_enclaves
homes=()
for unit in $(systemctl list-units --all --plain --no-legend 'nitro-home*.service' | awk '{print $1}'); do
    show() { systemctl show "$unit" -p "$1" --value; }
    pid=$(show MainPID)
    lines=$( [ "$pid" != 0 ] && journalctl _PID="$pid" -o cat --no-pager 2>/dev/null || true)
    serve_ms=$(echo "$lines" | sed -n 's/.*home: serving in \([0-9]*\) ms.*/\1/p' | tail -n 1)
    certificate=$(echo "$lines" | grep -q 'home: serving in' && echo valid || { echo "$lines" | grep -q 'no valid certificate' && echo pending; } || true)
    accounts=$(echo "$lines" | sed -n 's/.*home: door: \([0-9]*\) accounts.*/\1/p' | tail -n 1)
    stats=$(echo "$lines" | sed -n 's/.*home: stats \({.*}\)$/\1/p' | tail -n 1)
    hour=$(journalctl -u "$unit" --since "-1 hour" -o cat --no-pager 2>/dev/null || true)
    count() { echo "$hour" | grep -cE "$1" || true; }
    slot=$(basename "$(readlink -f "$(dirname "$(show ExecStart | sed -n 's/.*path=\([^ ;]*\).*/\1/p')")" 2>/dev/null)" 2>/dev/null || true)
    homes+=("$(jq -cn --arg unit "$unit" --arg state "$(show ActiveState)" --argjson restarts "$(show NRestarts)" \
        --arg since "$(show ActiveEnterTimestamp)" --arg slot "$slot" --arg serve_ms "${serve_ms:-}" --arg certificate "${certificate:-}" --arg accounts "${accounts:-}" \
        --argjson stats "${stats:-null}" --argjson boots "$(count 'home: started')" --argjson failed "$(count 'home: failed|"home":"(failed|lost)"')" \
        --argjson errors "$(count ' ERROR |cell_console: ERROR')" --argjson refused "$(count 'refused, destroyed|is no image this home runs')" \
        '{unit: $unit, state: $state, restarts: $restarts, since: $since, slot: $slot,
          serve_ms: ($serve_ms | tonumber? // null), certificate: (if $certificate == "" then null else $certificate end), door_accounts: ($accounts | tonumber? // null), stats: $stats,
          last_hour: {boots: $boots, failed: $failed, error_lines: $errors, computer_starts_refused: $refused}}')")
done
engine=$(curl -s -m 5 --unix-socket /var/lib/sandcastle-engine/engine.sock http://engine/v1/health 2>/dev/null | jq -c 'del(.ca_pem)' 2>/dev/null || echo null)
read_pool() { cat "$pool/$1" 2>/dev/null || echo 0; }
# HAProxy's own counters, from its stats socket: backend rows alone
router=$(python3 -I - <<'PY' 2>/dev/null || echo null
import csv, io, json, socket
s = socket.socket(socket.AF_UNIX)
s.settimeout(5)
s.connect("/run/haproxy/admin.sock")
s.sendall(b"show stat\n")
data = b""
while chunk := s.recv(65536):
    data += chunk
rows = list(csv.DictReader(io.StringIO(data.decode().lstrip("# "))))
homes = {r["pxname"][5:]: {"now": int(r["scur"] or 0), "since_start": int(r["stot"] or 0)} for r in rows if r["svname"] == "BACKEND" and r["pxname"].startswith("home_")}
closed = sum(int(r["stot"] or 0) for r in rows if r["svname"] == "BACKEND" and r["pxname"] == "no_home")
print(json.dumps({"homes": homes, "closed_no_home": closed}))
PY
)
jq -n --argjson homes "$(printf '%s\n' "${homes[@]:-}" | jq -s 'map(select(. != null))')" --argjson engine "${engine:-null}" \
    --argjson router "${router:-null}" \
    --arg engine_state "$(systemctl show sandcastle-engine -p ActiveState --value 2>/dev/null || echo none)" \
    --argjson cpu_free "$(read_pool cpu_pool/free)" --argjson cpu_total "$(read_pool cpu_pool/total)" \
    --argjson mem_free "$(read_pool mem_pool/free)" --argjson mem_total "$(read_pool mem_pool/total)" \
    --argjson pcie_used "$(read_pool pcie_slots_in_use)" --argjson pcie_total "$(read_pool pcie_slots)" \
    --arg load "$(cut -d' ' -f1-3 /proc/loadavg)" --argjson mem_avail "$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)" \
    --argjson disk_free "$(df -m --output=avail / | tail -n 1)" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{at: $at, homes: $homes, engine: {state: $engine_state, health: $engine}, router: $router,
      pool: {cpus: {free: $cpu_free, total: $cpu_total}, memory_mib: {free: ($mem_free / 1048576 | floor), total: ($mem_total / 1048576 | floor)}, pcie_slots: {used: $pcie_used, total: $pcie_total}},
      host: {load: $load, memory_available_mib: $mem_avail, disk_free_mib: $disk_free}}'
