#!/usr/bin/env bash
# The issuer's round over its homes (docs/nitro-issuer.md), on the
# operator's machine, which holds the zone's DNS token and the issuer's
# ACME account:
#
#   issuer-sweep.sh --parent <dir> <home>...
#
# For each home: its request (`<its prefix>/tls/request.csr` in the fleet
# bucket, which the home writes at each boot); the certificate already
# answered (`tls/chain.pem`), when it serves for that request's key and the
# home's names and is not due for renewal, and nothing more; else one kept
# here that does, written back; else an order (`nitro-issuer issue`, for the
# home's names from its name, never from its request) and its chain written
# back. A home whose order failed is not ordered for again within
# ISSUER_RETRY_S (default 3600: Let's Encrypt allows 5 failed validations
# an hour per account and name, and its resolvers hold a TXT record's
# answer for its TTL).
#
# <dir>/homes.json names `suffix` and `dns` ({zone, token_file}), as for
# home-create.sh. ISSUER_STATE (default ~/.cache/nitro-real/issuer) holds
# the account and each home's last request and chain; ISSUER_STAGING=1 uses
# Let's Encrypt's staging directory. The mailbox is reached by curl's SigV4
# with a fleet key: ISSUER_AWS_DIR's (access-key-id, secret-access-key) when
# set, else each home's own in its directory (this spike's operator holds
# them; an issuer key that reads */tls/request.csr and writes
# */tls/chain.pem alone is the production form: docs/nitro-issuer.md, "What
# is left"). Nothing secret is printed or put on a command line. Exits 1
# when a home was not answered, else 3 when a home has not asked yet, else 0.
set -uo pipefail
say() { echo "issuer-sweep: $*" >&2; }
[ "${1:-}" = --parent ] && [ -n "${2:-}" ] || { say "usage: issuer-sweep.sh --parent <dir> <home>..."; exit 2; }
P=$(realpath "$2")/homes.json
shift 2
homes=${NITRO_HOMES:-$HOME/.cache/nitro-real/homes}
state=${ISSUER_STATE:-$HOME/.cache/nitro-real/issuer}
issuer=${NITRO_ISSUER:-nitro-issuer}
retry=${ISSUER_RETRY_S:-3600}
read -r zone token_file suffix < <(python3 -I -c 'import json,os,sys; p=json.load(open(sys.argv[1])); print(p["dns"]["zone"], os.path.expanduser(p["dns"]["token_file"]), p["suffix"])' "$P") || { say "$P: its dns and suffix"; exit 2; }
staging=()
[ "${ISSUER_STAGING:-}" = 1 ] && staging=(--staging)
failed=0
pending=0

# <method> <name> <out> [curl args]: a call on the home's mailbox, its HTTP
# status printed; the key goes to curl by its config on stdin
mailbox() {
    local m=$1 k=$2 o=$3
    shift 3
    printf 'user = "%s:%s"\n' "$(cat "$keys/access-key-id")" "$(cat "$keys/secret-access-key")" |
        curl -sS -K - -m 30 --aws-sigv4 "aws:amz:$region:s3" -X "$m" -o "$o" -w '%{http_code}' "$@" "https://$bucket.s3.$region.amazonaws.com/$prefix/tls/$k" 2> /dev/null || true
}

# <chain>: it serves for the request's key and the home's names, not due
serves() { "$issuer" verify --cert "$1" --csr "$W/request.csr" --names "$names" 2> /dev/null; }

answer() {
    local code
    code=$(mailbox PUT chain.pem /dev/null --data-binary @"$W/chain.pem" -H 'content-type: application/pem-certificate-chain')
    if [ "$code" = 200 ]; then say "$name: certificate answered"; else say "$name: the certificate not written back ($code)"; failed=1; fi
}

for name in "$@"; do
    H=$homes/$name
    W=$state/homes/$name
    if ! [[ "$name" =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$ ]] || [ ! -s "$H/launcher.json" ]; then
        say "$name: no such home"
        failed=1
        continue
    fi
    mkdir -p -m 700 "$W"
    read -r bucket prefix region < <(python3 -I -c '
import json, sys
env = dict(e.split("=", 1) for e in json.load(open(sys.argv[1]))["env"])
b = env["HOME_BUCKET"].removeprefix("s3://")
print(b.split("/", 1)[0], b.split("/", 1)[1], env["HOME_REGION"])' "$H/launcher.json")
    keys=${ISSUER_AWS_DIR:-$H/secrets/aws}
    names="$name.$suffix,*.$name.$suffix"
    code=$(mailbox GET request.csr "$W/request.csr.part")
    case $code in
        200) mv "$W/request.csr.part" "$W/request.csr" ;;
        404) rm -f "$W/request.csr.part"; say "$name: no request yet (the home asks at its boot)"; pending=1; continue ;;
        *) rm -f "$W/request.csr.part"; say "$name: its request not read ($code)"; failed=1; continue ;;
    esac
    code=$(mailbox GET chain.pem "$W/answered.pem.part")
    if [ "$code" = 200 ] && serves "$W/answered.pem.part"; then
        rm -f "$W/answered.pem.part"
        say "$name: its certificate serves, not due"
        continue
    fi
    rm -f "$W/answered.pem.part"
    # one issued here and not written back (the PUT failed) is answered
    # again, never ordered a second time
    if [ -s "$W/chain.pem" ] && serves "$W/chain.pem"; then
        answer
        continue
    fi
    if [ -e "$W/failed-at" ] && [ $(( $(date +%s) - $(stat -c %Y "$W/failed-at") )) -lt "$retry" ]; then
        say "$name: its last order failed less than $retry s ago; not ordered again yet"
        failed=1
        continue
    fi
    if "$issuer" issue --state "$state" "${staging[@]}" --zone "$zone" --token-file "$token_file" --suffix "$suffix" --home "$name" --csr "$W/request.csr" --out "$W/chain.pem"; then
        rm -f "$W/failed-at"
        answer
    else
        touch "$W/failed-at"
        say "$name: its order failed"
        failed=1
    fi
done
[ "$failed" = 0 ] || exit 1
[ "$pending" = 0 ] || exit 3
