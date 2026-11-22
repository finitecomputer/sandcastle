#!/bin/bash
# The home's workload (docs/nitro-home.md, "A boot"), run by sandcastle's
# guest as the PID namespace's first process. Each step says "home:
# <step>" on stdout, which the parent's launcher times as it arrives.
#
#   1. The clock from the NSM (the hypervisor's signed time; a
#      confidential guest boots at 1970, and every TLS check needs it).
#   2. An attestation document, printed: its PCR0 is what the home's KMS
#      key releases to (docs/nitro-home.md, "The release rule").
#   3. The sealed bundle ($HOME_SEALED) opened: its key from KMS over TLS
#      ended here (nitro-key), its files on a tmpfs, never on a disk.
#   4. The data disk (/dev/vdd) opened: dm-crypt under a key from KMS, its
#      wrapped form in the disk's first block; a new disk gets a new key
#      and a filesystem.
#   5. OpenBao in memory, seeded from the bundle: the node's secrets
#      backend, its token for celld minted fresh, its root token revoked.
#   6. macrofiche, the identity door (people's own passkeys), and the
#      front door's certificate check.
#   7. celld: the release deployed to the fleet bucket when it changed,
#      then the node, on loopback.
#   8. Caddy, the front door on 443 (which the parent forwards untouched):
#      TLS ended here, with certificates it gets itself by TLS-ALPN-01, or,
#      for a wildcard home, the one the operator's issuer answers for this
#      home's own key (tls.sh, docs/nitro-issuer.md).
#
# Settings, none secret, from the launcher's conf: HOME_BUCKET (s3://…),
# HOME_REGION, HOME_PLATFORM (the platform's host), HOME_SUFFIX (the
# fragments'), HOME_ENGINE (none, or bridge: the parent's container
# engine through sandcastle-bridge), and the home's size: HOME_IDLE_EVICT_S
# and HOME_MAX_RESIDENT_CELLS (celld's idle eviction and resident cap).
#
# Any service that exits takes the home down (the parent's service starts
# it again); SIGTERM stops it gracefully: celld first (its last data
# durable in the bucket, its computers kept running for the next start),
# then the rest, the disk closed last.
set -euo pipefail
say() { echo "home: $*"; }
# ms since t0, set once the clock is (before it, the clock reads 1970)
ms_since() { echo $(( (10#$(date +%s%N) - 10#$1) / 1000000 )); }
die() { say "failed: $*"; exit 1; }
R=/opt/fragment-home/release
S=/run/fragment-home/secrets
STATE=/var/lib/fragment-home
: "${HOME_BUCKET:?}" "${HOME_REGION:?}" "${HOME_PLATFORM:?}" "${HOME_SUFFIX:?}"
HOME_ENGINE=${HOME_ENGINE:-none}
umask 077

say started
say "time $(/usr/local/bin/nitro-key settime)"
t0=$(date +%s%N)
# celld holds a file per resident cell: room for many fragments
ulimit -n 65536
# Nothing secret is written to the root: its upper layer is the plain
# scratch disk on the parent. Secrets and temporary files go to tmpfs; the
# home's state (its certificates among it) to its encrypted disk.
mkdir -p /run/fragment-home /var/lib/fragment-home
mountpoint -q /run/fragment-home || mount -t tmpfs -o mode=0700,size=64m tmpfs /run/fragment-home
mountpoint -q /tmp || mount -t tmpfs -o mode=1777,size=1g tmpfs /tmp
mkdir -p /run/fragment-home/celld

# 2. what the parent can check this home is: its document, for its PCR0
nonce=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
say "attestation nonce=$nonce document=$(/usr/local/bin/nitro-key attest --nonce "$nonce")"

# 3. the bundle: the image's own (its measured root's), since the guest
# runs this image's start and no environment the parent names
export HOME_SEALED
HOME_SEALED=$(cat /opt/fragment-home/sealed.json)
wrapped=$(/usr/local/bin/nitro-home-guest wrapped)
/usr/local/bin/nitro-key wake --wrapped "$wrapped" --out /run/fragment-home/bundle.key > /run/fragment-home/bundle.json || die "the bundle's key: KMS released nothing (is this image's PCR0 the key policy's?)"
/usr/local/bin/nitro-home-guest open --key-file /run/fragment-home/bundle.key --out "$S" > /dev/null
unset HOME_SEALED wrapped
say "secrets opened"

# 4. the data disk: block 0 holds "nitro-home-disk v1 <wrapped key>",
# the rest is dm-crypt (AES-XTS) under the key KMS releases for it
DISK=/dev/vdd
header=$(dd if=$DISK bs=4096 count=1 status=none | tr -d '\000')
case "$header" in
    "nitro-home-disk v1 "*)
        /usr/local/bin/nitro-key wake --wrapped "${header#nitro-home-disk v1 }" --out /run/fragment-home/disk.key > /run/fragment-home/disk.json || die "the data disk's key"
        new=0 ;;
    "")
        /usr/local/bin/nitro-key new --out /run/fragment-home/disk.key > /run/fragment-home/disk.json || die "a new data disk's key"
        w=$(sed -n 's/.*"wrapped":"\([^"]*\)".*/\1/p' /run/fragment-home/disk.json)
        [ -n "$w" ] || die "KMS gave no wrapped key for the new disk"
        printf 'nitro-home-disk v1 %s' "$w" | dd of=$DISK bs=4096 count=1 conv=sync,notrunc,fsync status=none
        new=1 ;;
    *) die "the data disk's first block is not a home's" ;;
esac
sectors=$(( $(blockdev --getsz $DISK) - 8 ))
dmsetup create --noudevsync home --table "0 $sectors crypt aes-xts-plain64 $(cat /run/fragment-home/disk.key) 0 $DISK 8"
rm -f /run/fragment-home/disk.key
dmsetup mknodes home
if ! dumpe2fs -h /dev/mapper/home > /dev/null 2>&1; then
    [ "$new" = 1 ] || say "the data disk opened to no filesystem: making one (its key is the disk's own, so this disk held nothing of this home's)"
    mkfs.ext4 -q -E lazy_itable_init=1,lazy_journal_init=1 -L home /dev/mapper/home
fi
mount -o noatime /dev/mapper/home $STATE
mkdir -p $STATE/celld $STATE/macrofiche $STATE/door $STATE/caddy $STATE/log
LOG=$STATE/log
say "disk mounted (new=$new)"
# how many accounts the door holds, a count and nothing else: with no
# exec, the only way to see from outside that they came through a change
say "door: $(grep -o '"created_at_s"' $STATE/door/accounts.json 2>/dev/null | wc -l) accounts"

pids=()
stop_all() {
    # celld first: its handoff makes the last write durable in the bucket.
    # With an engine, it is asked to keep its computers running for the
    # next start of this home, which adopts them (celld's
    # `containers=keep`); SIGTERM, which reaps them, only if that fails.
    if [ -n "${celld_pid:-}" ]; then
        if [ "${engine:-none}" != none ] && curl -sf -m 5 -X POST 'http://127.0.0.1:8081/shutdown?handoff=preserve&containers=keep' > /dev/null; then
            say "celld stopping, its computers kept"
        else
            kill -TERM "$celld_pid" 2>/dev/null || true
        fi
        wait "$celld_pid" 2>/dev/null || true
    fi
    [ -n "${stats_pid:-}" ] && kill "$stats_pid" 2>/dev/null || true
    for p in "${pids[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
    for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
    [ -n "${bao_pid:-}" ] && kill -TERM "$bao_pid" 2>/dev/null || true
    sync
    umount $STATE 2>/dev/null || true
    dmsetup remove home 2>/dev/null || true
}
trap 'say stopping; stop_all; say stopped; exit 0' TERM INT

# 5. OpenBao, in memory: the node's secrets backend (celld reads the
# Secrets Store's bindings from it), seeded from the bundle at each boot
cat $R/hosts >> /etc/hosts
root=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
BAO_DEV_ROOT_TOKEN_ID=$root /usr/local/bin/bao server -dev -dev-listen-address=127.0.0.1:8200 -dev-no-store-token > $LOG/bao.log 2>&1 &
bao_pid=$!
export BAO_ADDR=http://127.0.0.1:8200
for _ in $(seq 100); do curl -sf $BAO_ADDR/v1/sys/health > /dev/null && break; sleep 0.1; done
export BAO_TOKEN=$root
for f in "$S"/store/*; do
    /usr/local/bin/bao kv put -mount=secret "$(basename "$f")" value=@"$f" > /dev/null
done
printf 'path "secret/data/*" { capabilities = ["read"] }\n' | /usr/local/bin/bao policy write fragment-cell - > /dev/null
/usr/local/bin/bao token create -policy=fragment-cell -no-default-policy -orphan -period=720h -field=token > /run/fragment-home/celld/openbao.token
/usr/local/bin/bao token revoke -self > /dev/null
unset BAO_TOKEN root
say "openbao seeded ($(ls "$S"/store | wc -l) secrets)"

# 6. the services beside celld
/usr/local/bin/macrofiche serve --config $R/macrofiche.json > $LOG/macrofiche.out 2> $LOG/macrofiche.log &
pids+=($!)
/usr/local/bin/fragment-identity-door --config $R/door.json 2> $LOG/door.log &
pids+=($!)
/usr/local/bin/nitro-home-guest ask --listen 127.0.0.1:8805 --platform "$HOME_PLATFORM" --suffix "$HOME_SUFFIX" --cell 127.0.0.1:8080 2> $LOG/ask.log &
pids+=($!)

# the parent's container engine (sandcastle's, its Nitro backend), over
# vsock: sandcastle-bridge's home half serves the engine's sockets here and
# relays the engine's intercepts to celld (docs/nitro-home.md, "Computers")
engine=none
case "$HOME_ENGINE" in
    none) ;;
    bridge)
        mkdir -p /run/sandcastle $STATE/sessions
        # each computer is reached over its attested session alone (lane
        # A's PR 6), claimed at its start against the PCR0s pinned in this
        # image (measured: a new computer image's pin is a new home image,
        # since nothing can exec into this home to change a file)
        # celld's intercept socket, as celld names it for CELLD_NODE=home
        # (`intercepts-` and the first 6 hex of the node's SHA-256)
        /usr/local/bin/sandcastle-bridge home --intercepts $STATE/celld/intercepts-$(printf %s home | sha256sum | cut -c1-6).sock --sessions $STATE/sessions --pins /opt/fragment-home/pins > $LOG/bridge.log 2>&1 &
        pids+=($!)
        for _ in $(seq 100); do [ -S /run/sandcastle/engine.sock ] && break; sleep 0.05; done
        engine=krun:/run/sandcastle/engine.sock ;;
    *) die "HOME_ENGINE is none or bridge" ;;
esac

# 7. celld: the release deployed when it changed, then the node, on the
# fleet bucket's sealed form (celld#30): every object sealed before it
# leaves the home, the chain's head in a counter outside the bucket, behind
# other credentials. The first boot copies the plain objects into it and
# keeps them (deleting them is the owner's call); later boots find it
# sealed already.
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
AWS_ACCESS_KEY_ID=$(cat "$S/aws/access-key-id")
AWS_SECRET_ACCESS_KEY=$(cat "$S/aws/secret-access-key")
[ -f "$S/bucket-seal.json" ] || die "the bundle holds no bucket-seal.json"
install -m 600 "$S/bucket-seal.json" /run/fragment-home/bucket-seal.json
export CELLD_BUCKET_SEAL=/run/fragment-home/bucket-seal.json
SEALED=$HOME_BUCKET/sealed
m0=$(date +%s%N)
/usr/local/bin/celld seal-bucket migrate --from "$HOME_BUCKET" --to "$SEALED" --region "$HOME_REGION" > $LOG/seal-migrate.log 2>&1 || { tail -c 2000 $LOG/seal-migrate.log; die "the bucket's migration"; }
say "the bucket sealed in $(ms_since "$m0") ms ($(tail -n 1 $LOG/seal-migrate.log | tr -cd '[:alnum:] ,:.()-' | cut -c1-100))"
export AWS_REGION=$HOME_REGION CELLD_BUCKET=$SEALED
# the home's size (its launcher conf, none secret): idle cells evicted
# after HOME_IDLE_EVICT_S, at most HOME_MAX_RESIDENT_CELLS resident (celld's
# own defaults when unset: none evicted, no cap)
[ -z "${HOME_IDLE_EVICT_S:-}" ] || export CELLD_IDLE_EVICT_S=$HOME_IDLE_EVICT_S
[ -z "${HOME_MAX_RESIDENT_CELLS:-}" ] || export CELLD_MAX_RESIDENT_CELLS=$HOME_MAX_RESIDENT_CELLS
release=$(cat $R/release-id)
if [ "$(cat $STATE/deployed 2>/dev/null || true)" != "$release" ]; then
    d0=$(date +%s%N)
    ( cd $STATE && CELLD_ESBUILD=/usr/local/bin/esbuild CELLD_CONTAINER_ENGINE=$engine /usr/local/bin/celld deploy $R/cell/wrangler.home.jsonc --bucket "$SEALED" --region "$HOME_REGION" ) > $LOG/deploy.log 2>&1 || { tail -c 2000 $LOG/deploy.log; die "celld deploy"; }
    echo "$release" > $STATE/deployed
    say "deployed $release in $(ms_since "$d0") ms"
fi
CELLD_WATCH=$STATE/celld CELLD_NODE=home CELLD_SECRETS_FILE=$R/celld-secrets.json CELLD_CONTAINER_ENGINE=$engine \
CELLD_TRUST_FORWARDED_HEADERS=1 CELLD_DURABILITY=bucket CELLD_SHUTDOWN_TOTAL_MS=40000 \
CELLD_FACET_MAX_BYTES=20971520 CELLD_DYNAMIC_LOCKDOWN=1 CELLD_MAX_CELL_REQUESTS=512 \
    /usr/local/bin/celld --no-control-plane --listen 127.0.0.1:8080 --internal-listen 127.0.0.1:8081 --region "$HOME_REGION" \
    > >(tee -a $LOG/celld.log | grep --line-buffered -E " (WARN|ERROR) |listening|panicked|^Error|^Caused by|^ +[0-9]+: ") 2>&1 &
celld_pid=$!
# celld's whole log, the cell's lines among them, stays on the home's
# disk; the parent sees its warnings and errors
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
# celld answers once it is ready: after a crash, that is once it has taken
# back what the stopped node held, which grows with the home's cells; its
# bound is HOME_CELLD_READY_S (default 600), and the wait says how it goes
ready_max=${HOME_CELLD_READY_S:-600}
w0=$(date +%s)
until curl -sf -m 5 http://127.0.0.1:8080/.well-known/celld/health > /dev/null; do
    waited=$(( $(date +%s) - w0 ))
    [ "$waited" -lt "$ready_max" ] || die "celld never answered its health (${ready_max} s)"
    kill -0 $celld_pid 2>/dev/null || die "celld exited before it answered its health"
    [ $(( waited % 30 )) -ne 29 ] || say "celld not serving yet (${waited} s)"
    sleep 1
done
say "celld serving in $(ms_since "$t0") ms from the clock"

# 8. the front door, last: what it lets in is ready behind it. Its
# certificates, as the release says (`certificate`, docs/nitro-issuer.md):
# Caddy's own, each name's by TLS-ALPN-01 (`acme`, and a release without
# the file), or one for the home's name and its fragments' wildcard, which
# the operator's issuer gets for a key made here (`wildcard`).
certificate=$(cat $R/certificate 2>/dev/null || echo acme)
caddy_run() { XDG_DATA_HOME=$STATE/caddy XDG_CONFIG_HOME=$STATE/caddy exec /usr/local/bin/caddy run --config $R/Caddyfile --adapter caddyfile "$@" > $LOG/caddy.out 2>&1; }
case "$certificate" in
acme)
    caddy_run &
    pids+=($!)
    # its ACME account's URI (public: the CAA record names it), once Caddy
    # has registered it, which it does at its first order: the operator
    # names it in the home's CAA record (docs/nitro-home.md, "Certificates
    # and CAA"); its key never leaves this disk
    account=$STATE/caddy/acme/acme-v02.api.letsencrypt.org-directory/users/default/default.json
    for _ in $(seq 300); do [ -s "$account" ] && break; sleep 0.1; done
    acme_account() {
        local uri
        uri=$(jq -r '.location // empty' "$account" 2>/dev/null || true)
        [[ "$uri" =~ ^https://acme-v02\.api\.letsencrypt\.org/acme/acct/[0-9]+$ ]] && say "acme account $uri"
    }
    acme_account || say "acme account: none yet (said once it is)"
    ;;
wildcard)
    # one certificate for the home's name and its fragments' wildcard, for
    # a key of its own, from the operator's issuer (tls.sh says how)
    TLS=$STATE/tls
    tls_names="$HOME_PLATFORM,*.$HOME_SUFFIX"
    [ "$HOME_PLATFORM" = "$HOME_SUFFIX" ] || die "a wildcard home's platform host is its fragments' suffix"
    b=${HOME_BUCKET#s3://}
    [[ "$b" == */* ]] || die "HOME_BUCKET names no prefix of the home's own"
    mailbox_url="https://${b%%/*}.s3.$HOME_REGION.amazonaws.com/${b#*/}/tls"
    . /opt/fragment-home/tls.sh
    tls_ask || die "the certificate's request"
    tls_take || true
    # Caddy once there is a certificate to serve; until then it waits for
    # the issuer's, every service behind it already up
    (
        n=0
        until [ -s $TLS/caddy-tls ]; do
            [ $(( n % 60 )) -ne 0 ] || say "tls: waiting for the issuer's certificate ($(( n * 5 )) s)"
            sleep 5
            n=$(( n + 1 ))
            tls_take || true
        done
        caddy_run --watch
    ) &
    pids+=($!)
    ;;
*) die "the release's certificate is acme or wildcard, not $certificate" ;;
esac
for _ in $(seq 600); do curl -s -o /dev/null --resolve "$HOME_PLATFORM:443:127.0.0.1" "https://$HOME_PLATFORM/" && break; sleep 0.1; done
if curl -sf -o /dev/null --resolve "$HOME_PLATFORM:443:127.0.0.1" "https://$HOME_PLATFORM/"; then
    say "serving in $(ms_since "$t0") ms from the clock (TLS here, its certificate valid)"
else
    say "the front door has no valid certificate yet (see its log); serving behind it"
fi

# 9. its numbers, a line a minute on the console (docs/nitro-home.md,
# "Logs and numbers"): counts and sizes alone, never a name, a path or a
# message, so the parent learns the home's health and nothing of anyone's.
# Its errors are counted by their event's name, from celld's log since the
# line before.
stats_line() {
    local cells version gen isolates mem_total mem_avail load disk_used disk_free rss events
    read -r cells version gen isolates < <(curl -s -m 5 http://127.0.0.1:8081/state | jq -r '[(.deployment.cells // {} | length), (.deployment.version // "-"), (.deployment.generation // "-"), (.deployment.isolates // {} | tostring)] | @tsv' 2>/dev/null || echo "- - - -")
    mem_total=$(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo)
    mem_avail=$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)
    load=$(cut -d' ' -f1 /proc/loadavg)
    read -r disk_used disk_free < <(df -m --output=used,avail $STATE | tail -n 1)
    rss=$(awk '/^VmRSS:/ {print int($2/1024)}' /proc/$celld_pid/status 2>/dev/null || echo 0)
    # each WARN and ERROR line since the last minute, counted by its event's name
    # since the last line's offset, kept in a file: this runs in $(…), whose
    # variables do not outlive it
    local stats_at; stats_at=$(cat /run/fragment-home/stats-at 2>/dev/null || echo 0)
    events=$(tail -c +$((stats_at + 1)) $LOG/celld.log 2>/dev/null | grep -E ' (WARN|ERROR) |"level":"(warn|error)"|cell_console: ERROR' \
        | grep -oE 'event="[a-z0-9_.-]+"|"event":"[a-z0-9_.-]+"' | tr -d '"' | sed 's/^event[=:]//' | sort | uniq -c \
        | awk 'BEGIN { printf "{" } { printf "%s\"%s\":%d", (NR > 1 ? "," : ""), $2, $1 } END { printf "}" }')
    stat -c %s $LOG/celld.log > /run/fragment-home/stats-at 2>/dev/null || true
    jq -cn --argjson cells "${cells:-0}" --arg version "$version" --arg generation "$gen" --argjson isolates "${isolates:-null}" \
        --argjson mem_total "$mem_total" --argjson mem_avail "$mem_avail" --argjson load "$load" \
        --argjson disk_used "$disk_used" --argjson disk_free "$disk_free" --argjson celld_rss "$rss" --argjson events "${events:-{\}}" \
        '{cells: $cells, deployment: {version: $version, generation: $generation}, isolates: $isolates, mem_mib: {total: $mem_total, available: $mem_avail}, load1: $load, data_mib: {used: $disk_used, free: $disk_free}, celld_rss_mib: $celld_rss, events: $events}' 2>/dev/null
}
stat -c %s $LOG/celld.log > /run/fragment-home/stats-at 2>/dev/null || echo 0 > /run/fragment-home/stats-at
# and, for a wildcard home, its certificate: while the one in use is due
# for renewal (or no longer serves), the issuer's next answer is looked for
( said=false; if [ "$certificate" != acme ] || [ -s "$account" ]; then said=true; fi
  while sleep 60; do
    line=$(stats_line) && [ -n "$line" ] && say "stats $line"
    $said || { acme_account && said=true; } || true
    [ "$certificate" != wildcard ] || [ ! -s $TLS/caddy-tls ] || tls_take || true
  done ) &
stats_pid=$!

# a service that exits takes the home down
set +e
wait -n "$celld_pid" "${pids[@]}"
code=$?
say "a service exited ($code): stopping"
stop_all
exit 1
