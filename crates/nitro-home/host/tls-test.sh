#!/usr/bin/env bash
# tls.sh's certificates, taken and renewed: the mailbox a local directory,
# the certificates a test CA's (openssl 3.4 or later), the checks the home's
# own build of nitro-issuer:
#
#   cargo build -p sandcastle-nitro-issuer --no-default-features --target-dir target/in-home
#   NITRO_ISSUER=target/in-home/debug/nitro-issuer crates/nitro-home/host/tls-test.sh
#
# Each case says what it proves; the script stops at the first that fails.
set -euo pipefail
here=$(dirname "$(realpath "$0")")
: "${NITRO_ISSUER:?the home build of nitro-issuer: cargo build -p sandcastle-nitro-issuer --no-default-features}"
NITRO_ISSUER=$(realpath "$NITRO_ISSUER")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
TLS=$work/tls
box=$work/mailbox
mkdir -p "$box"
tls_names="test1.homes.example,*.test1.homes.example"
say() { echo "    home: $*"; }
ok() { echo "ok: $*"; }
fail() { echo "FAILED: $*"; exit 1; }
# shellcheck source=tls.sh
. "${TLS_SH:-$here/tls.sh}"

# tls.sh's own mailbox, against a curl that gets its 200 and then fails
# (exit 18, a transfer cut short): no status but 000 comes of it
mkdir -p "$work/bin" "$work/s/aws"
printf '#!/bin/sh\ncat > /dev/null\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && echo partial > "$2"; shift; done\nprintf 200\nexit 18\n' > "$work/bin/curl"
chmod 755 "$work/bin/curl"
echo id > "$work/s/aws/access-key-id"
echo secret > "$work/s/aws/secret-access-key"
code=$(S=$work/s HOME_REGION=x mailbox_url=https://bucket.invalid/p/tls PATH="$work/bin:$PATH" mailbox GET chain.pem "$work/cut.pem")
[ "$code" = 000 ] || fail "a transfer curl reports failed is 000, not $code"
ok "a GET whose transfer curl cut short after its 200: 000"
# the bucket's stand-in, a directory; each GET counted. $work/fail-put
# makes the next PUT fail before it lands (curl's 000); $work/cut-get makes
# the next GET stop halfway (curl's failure after its 200: tls.sh's mailbox
# prints 000 for it)
mailbox() {
    local m=$1 k=$2 o=$3
    shift 3
    case $m in
        GET)
            echo >> "$work/gets"
            if [ -f "$work/cut-get" ] && [ -f "$box/$k" ]; then rm "$work/cut-get"; head -c 900 "$box/$k" > "$o"; echo 000; return; fi
            if [ -f "$box/$k" ]; then cp "$box/$k" "$o"; echo 200; else echo 404; fi ;;
        PUT)
            if [ -f "$work/fail-put" ]; then rm "$work/fail-put"; echo 000; return; fi
            [ "$1" = --data-binary ] && cp "${2#@}" "$box/$k" && echo 200 ;;
    esac
}
gets() { [ -f "$work/gets" ] && wc -l < "$work/gets" || echo 0; }
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/ca.key" -out "$work/ca.pem" -subj /CN=tls-test -days 2 2> /dev/null
# <csr> <days from now> <out>: a chain (the certificate for the CSR's key
# and names, then the CA's) as an issuer answers it
sign() {
    openssl x509 -req -in "$1" -CA "$work/ca.pem" -CAkey "$work/ca.key" -not_before "$(date -u -d '-1 day' +%Y%m%d%H%M%SZ)" \
        -not_after "$(date -u -d "+$2 days" +%Y%m%d%H%M%SZ)" -copy_extensions copy -out "$3" 2> /dev/null
    cat "$work/ca.pem" >> "$3"
}
# <chain>: put in use as tls_take would have
use() {
    local id
    id=$(sha256sum "$1" | cut -c1-16)
    cp "$1" "$TLS/chain-$id.pem"
    printf 'tls %s %s\n' "$TLS/chain-$id.pem" "$TLS/key.pem" > "$TLS/caddy-tls"
}
taken() { tls_take >&2 && echo 0 || echo $?; }

touch "$work/fail-put"
tls_ask
[ ! -e "$box/request.csr" ] && [ ! -e "$TLS/request.sent" ] || fail "a failed PUT is not taken as sent"
tls_tick || true
[ -s "$box/request.csr" ] && [ -e "$TLS/request.sent" ] && [ "$(stat -c %a "$TLS/key.pem")" = 600 ] || fail "the request sent again, and the key the home's alone"
ok "the first boot's request lost in transit: sent again at the next tick; the key the home's own (0600)"
key=$(sha256sum < "$TLS/key.pem")
[ "$(taken)" = 1 ] && [ -z "$(tls_in_use)" ] || fail "nothing taken from an empty mailbox"
ok "no answer yet: nothing in use, and the front door waits"

sign "$box/request.csr" 90 "$box/chain.pem"
touch "$work/cut-get"
[ "$(taken)" = 1 ] && [ -z "$(tls_in_use)" ] || fail "a download cut short is not taken"
ok "the answer's download cut short (curl failed after its 200): not taken"
sed '/-----END CERTIFICATE-----/q' "$box/chain.pem" > "$work/leaf.pem"
cp "$box/chain.pem" "$work/whole.pem"
cp "$work/leaf.pem" "$box/chain.pem"
[ "$(taken)" = 1 ] && [ -z "$(tls_in_use)" ] || fail "a chain without its issuer refused"
ok "a certificate without its issuer (the chain's intermediate missing): refused"
cp "$work/whole.pem" "$box/chain.pem"
[ "$(taken)" = 0 ] && [ "$(tls_in_use)" = "$TLS/chain-$(sha256sum < "$box/chain.pem" | cut -c1-16).pem" ] || fail "the answer taken"
grep -q "^tls $TLS/chain-[0-9a-f]\{16\}\.pem $TLS/key.pem$" "$TLS/caddy-tls" || fail "caddy-tls names the chain and the key"
ok "the issuer's answer (90 days) taken: caddy-tls names it"
g=$(gets)
[ "$(taken)" = 0 ] && [ "$(gets)" = "$g" ] || fail "a certificate that serves is kept without asking"
ok "while it serves and is not due, the mailbox is not read"

tls_ask
[ "$(sha256sum < "$TLS/key.pem")" = "$key" ] && [ "$(taken)" = 0 ] && [ "$(gets)" = "$g" ] || fail "a restart keeps the key and the certificate"
ok "a restart: the same key, the certificate in use still taken, nothing read"

mkdir -p "$work/other"
"$NITRO_ISSUER" csr --key "$work/other/key.pem" --names "$tls_names" --out "$work/other/request.csr"
sign "$box/request.csr" 10 "$work/due.pem"
use "$work/due.pem"
sign "$work/other/request.csr" 90 "$box/chain.pem"
in=$(tls_in_use)
[ "$(taken)" = 1 ] && [ "$(tls_in_use)" = "$in" ] || fail "another key's certificate refused"
ok "due (10 days left), and the mailbox holds a certificate for ANOTHER key: refused, the one in use kept"

"$NITRO_ISSUER" csr --key "$TLS/key.pem" --names "test2.homes.example,*.test2.homes.example" --out "$work/names.csr"
sign "$work/names.csr" 90 "$box/chain.pem"
[ "$(taken)" = 1 ] && [ "$(tls_in_use)" = "$in" ] || fail "another home's names refused"
ok "a certificate for this key and another home's names: refused"

echo "not a certificate" > "$box/chain.pem"
[ "$(taken)" = 1 ] && [ "$(tls_in_use)" = "$in" ] || fail "garbage refused"
ok "garbage in the mailbox: refused"

cp "$work/due.pem" "$box/chain.pem"
[ "$(taken)" = 1 ] && [ "$(tls_in_use)" = "$in" ] || fail "the same due certificate is not taken again"
sign "$box/request.csr" 12 "$box/chain.pem"
[ "$(taken)" = 1 ] && [ "$(tls_in_use)" = "$in" ] || fail "a due one does not replace a due one"
ok "due, and the issuer has not renewed yet (the same, or another due one): the one in use kept"

before=$in
sign "$box/request.csr" 90 "$box/chain.pem"
[ "$(taken)" = 0 ] && [ "$(tls_in_use)" != "$before" ] && [ -f "$before" ] || fail "the renewal taken, the one before kept"
ok "the renewal (90 days) taken; the one before kept until the next"
second=$(tls_in_use)
sign "$box/request.csr" 91 "$box/chain.pem"
sign "$box/request.csr" 11 "$work/due2.pem"
use "$work/due2.pem"
third=$(tls_in_use)
[ "$(taken)" = 0 ] && [ ! -f "$before" ] && [ ! -f "$second" ] && [ -f "$third" ] && [ "$(ls "$TLS"/chain-*.pem | wc -l)" = 2 ] || fail "older chains removed"
ok "the next renewal: the chain before is kept, any older one removed"

openssl x509 -req -in "$box/request.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" -not_before 20260101000000Z -not_after 20260102000000Z -copy_extensions copy -out "$work/expired.pem" 2> /dev/null
use "$work/expired.pem"
sign "$box/request.csr" 10 "$box/chain.pem"
[ "$(taken)" = 1 ] && [ "$(tls_in_use)" != "$TLS/chain-$(sha256sum < "$work/expired.pem" | cut -c1-16).pem" ] || fail "a due one replaces an expired one"
ok "expired in use, and the mailbox's is due: taken (a due one beats none), and still looked for again"
sign "$box/request.csr" 90 "$box/chain.pem"
use "$work/due.pem"
before=$(cat "$TLS/caddy-tls")
mkdir "$TLS/caddy-tls.part"
[ "$(taken)" = 1 ] && [ "$(cat "$TLS/caddy-tls")" = "$before" ] || fail "a failed write leaves caddy-tls as it was"
rmdir "$TLS/caddy-tls.part"
[ "$(taken)" = 0 ] && [ "$(cat "$TLS/caddy-tls")" != "$before" ] || fail "taken once it can be written"
ok "caddy-tls not writable (as on a full disk): left as it was, not said to serve; taken at the next tick"
echo "tls-test: every case passed"
