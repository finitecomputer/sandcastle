#!/usr/bin/env bash
# The parent's SNI router, for several homes on one parent (docs/nitro-home.md,
# "Many homes on one parent"), as root:
#
#   sudo ./home-router.sh
#
# HAProxy on the parent's 443, in TCP mode: it reads each connection's TLS
# ClientHello for its server name and passes the connection, untouched, to
# the home that name belongs to, its first bytes the PROXY protocol (v2)
# header that carries the client's address. TLS still ends in the home
# (its own certificates, by TLS-ALPN-01, which passes through the same
# way); the parent sees names and addresses, as a forwarded port lets it,
# and nothing inside.
#
# Each home's names come from its own running conf
# (/var/lib/nitro-home/homes/<name>/current/home.json): HOME_PLATFORM
# exactly, and any name under HOME_SUFFIX; its address is the conf's
# guest_addr. A name no home holds, or a connection with no name, is
# closed. The config is written again from the confs alone; HAProxy reloads
# (gracefully: open connections stay on the old process) only when it
# changed. Logs: abnormal connections alone (no visit is logged).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "home-router: run as root" >&2; exit 1; }
cfg=/etc/haproxy/haproxy.cfg
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 -I - "$work" <<'PY'
import glob, json, os, re, sys
work = sys.argv[1]
exact, under, backends = [], [], []
host = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
if os.path.exists("/var/lib/nitro-home/current/home.json"):
    c = json.load(open("/var/lib/nitro-home/current/home.json"))
    if 443 in c.get("inbound_tcp", []):
        sys.exit("home-router: this parent's one home takes 443 forwarded untouched: no router beside it")
seen = {}
for p in sorted(glob.glob("/var/lib/nitro-home/homes/*/current/home.json")):
    name = p.split("/")[-3]
    c = json.load(open(p))
    env = dict(e.split("=", 1) for e in c.get("env", []))
    platform, suffix, guest = env.get("HOME_PLATFORM", "").lower(), env.get("HOME_SUFFIX", "").lower(), c["guest_addr"]
    for h in (platform, suffix):
        if not host.match(h):
            sys.exit(f"home-router: {name}: {h!r} is no host name")
        if h in seen and seen[h] != name:
            sys.exit(f"home-router: {h} is both {seen[h]}'s and {name}'s")
        seen[h] = name
    b = "home_" + name.replace("-", "_")
    exact.append(f"{platform} {b}")
    under.append(f".{suffix} {b}")
    backends.append(f"backend {b}\n    server home {guest}:443 send-proxy-v2\n")
# HAProxy's maps: a name exactly (str), or a name ending in .<suffix> (end)
open(f"{work}/homes.exact.map", "w").write("".join(l + "\n" for l in exact))
open(f"{work}/homes.under.map", "w").write("".join(l + "\n" for l in under))
open(f"{work}/haproxy.cfg", "w").write(f"""# The parent's SNI router (sandcastle's home-router.sh), written from the
# homes' own confs: edit those, not this.
global
    log stdout format raw daemon
    maxconn 50000
    stats socket /run/haproxy/admin.sock mode 600 level admin
    hard-stop-after 1h

defaults
    mode tcp
    log global
    option tcplog
    option dontlog-normal
    timeout connect 5s
    timeout client 1h
    timeout server 1h
    timeout client-fin 30s
    timeout server-fin 30s

frontend homes
    bind :443
    tcp-request inspect-delay 5s
    tcp-request content accept if {{ req.ssl_hello_type 1 }}
    use_backend %[req.ssl_sni,lower,map_str(/etc/haproxy/homes.exact.map)] if {{ req.ssl_sni,lower,map_str(/etc/haproxy/homes.exact.map) -m found }}
    use_backend %[req.ssl_sni,lower,map_end(/etc/haproxy/homes.under.map)] if {{ req.ssl_sni,lower,map_end(/etc/haproxy/homes.under.map) -m found }}
    default_backend no_home

backend no_home
    tcp-request content reject

""" + "\n".join(backends))
print(f"home-router: {len(backends)} homes", file=sys.stderr)
PY
# its stats socket's directory, made by systemd at each start (/run is
# empty after a reboot)
dropin=/etc/systemd/system/haproxy.service.d/nitro-home.conf
want=$'# home-router.sh: the stats socket\'s directory\n[Service]\nRuntimeDirectory=haproxy\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\n'
if [ "$(cat "$dropin" 2>/dev/null)"$'\n' != "$want" ]; then
    install -d -m 0755 "$(dirname "$dropin")"
    printf '%s' "$want" > "$dropin"
    systemctl daemon-reload
fi
changed=false
for f in haproxy.cfg homes.exact.map homes.under.map; do
    cmp -s "$work/$f" "/etc/haproxy/$f" || changed=true
done
$changed || systemctl is-active -q haproxy || changed=true
$changed || { echo "home-router: unchanged" >&2; exit 0; }
# the maps first (the running process holds its own until it reloads),
# then the config, checked before it replaces the one running
for f in homes.exact.map homes.under.map; do install -m 0644 "$work/$f" "/etc/haproxy/$f.new" && mv -T "/etc/haproxy/$f.new" "/etc/haproxy/$f"; done
install -m 0644 "$work/haproxy.cfg" "$cfg.new"
haproxy -c -q -f "$cfg.new" || { echo "home-router: the new config is refused by haproxy -c" >&2; rm -f "$cfg.new"; exit 1; }
mv -T "$cfg.new" "$cfg"
if systemctl is-active -q haproxy; then systemctl reload haproxy; else systemctl enable -q haproxy && systemctl restart haproxy; fi
echo "home-router: written and $(systemctl is-active haproxy)" >&2
