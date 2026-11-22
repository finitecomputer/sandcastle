# A wildcard home's certificate (docs/nitro-issuer.md), sourced by entry.sh
# (and by tls-test.sh): its key, made here once and kept on the encrypted
# disk, never leaves the home. The home asks the operator's issuer through
# its own prefix in the fleet bucket, which only it and the operator reach:
# its request (tls/request.csr) at each boot, the issuer's answer
# (tls/chain.pem) taken once it serves for this key and these names. The
# Caddyfile imports $TLS/caddy-tls, which names the chain in use; Caddy,
# watching its config (--watch: in process, its admin stays off), serves a
# new one within a second of that file naming it.
#
# Set before: TLS (the directory), tls_names (`<home>,*.<home>`),
# mailbox_url (https://<bucket>.s3.<region>.amazonaws.com/<prefix>/tls),
# HOME_REGION, S (the opened bundle: aws/access-key-id and
# aws/secret-access-key), and say.

# <method> <name> <out> [curl args]: a call on the mailbox, its HTTP status
# printed; the home's fleet key goes to curl by its config on stdin, never
# on a command line
mailbox() {
    local m=$1 k=$2 o=$3
    shift 3
    printf 'user = "%s:%s"\n' "$(cat "$S/aws/access-key-id")" "$(cat "$S/aws/secret-access-key")" |
        curl -sS -K - -m 20 --aws-sigv4 "aws:amz:$HOME_REGION:s3" -X "$m" -o "$o" -w '%{http_code}' "$@" "$mailbox_url/$k" 2>/dev/null || true
}

# <chain>: 0 it serves for this key and these names, 3 it serves and its
# renewal is due, else it does not serve
tls_check() {
    local v=0
    "${NITRO_ISSUER:-/usr/local/bin/nitro-issuer}" verify --cert "$1" --key "$TLS/key.pem" --names "$tls_names" 2>/dev/null || v=$?
    return $v
}

# the home's request, made for its key (made too, the first time) and sent;
# nonzero only when no request could be made
tls_ask() {
    local code
    mkdir -p "$TLS"
    "${NITRO_ISSUER:-/usr/local/bin/nitro-issuer}" csr --key "$TLS/key.pem" --names "$tls_names" --out "$TLS/request.csr" || return 1
    code=$(mailbox PUT request.csr /dev/null --data-binary @"$TLS/request.csr" -H 'content-type: application/pkcs10')
    if [ "$code" = 200 ]; then say "tls: the issuer asked for $tls_names"; else say "tls: the request not sent ($code): the issuer is asked again at the next boot"; fi
}

# the chain in use, as caddy-tls names it (nothing when none is)
tls_in_use() {
    if [ -s "$TLS/caddy-tls" ]; then cut -d' ' -f2 "$TLS/caddy-tls"; fi
}

# the mailbox's chain, taken when it serves and the one in use does not
# serve as well (none, due, or no longer serving): fresh, or due when the
# one in use no longer serves at all. 0 when what is in use then serves and
# is not due.
tls_take() {
    local in now=1 got="$TLS/mailbox-$BASHPID.pem" v id f
    in=$(tls_in_use)
    if [ -n "$in" ]; then
        now=0
        tls_check "$in" || now=$?
    fi
    [ "$now" -ne 0 ] || return 0
    [ "$(mailbox GET chain.pem "$got")" = 200 ] || { rm -f "$got"; return 1; }
    v=0
    tls_check "$got" || v=$?
    id=$(sha256sum "$got" | cut -c1-16)
    if [ "$TLS/chain-$id.pem" = "$in" ] || ! { [ "$v" -eq 0 ] || { [ "$v" -eq 3 ] && [ "$now" -ne 3 ]; }; }; then
        rm -f "$got"
        return 1
    fi
    mv "$got" "$TLS/chain-$id.pem"
    printf 'tls %s %s\n' "$TLS/chain-$id.pem" "$TLS/key.pem" > "$TLS/caddy-tls.part"
    mv "$TLS/caddy-tls.part" "$TLS/caddy-tls"
    # the one before is kept until the next is taken
    for f in "$TLS"/chain-*.pem; do
        [ "$f" = "$TLS/chain-$id.pem" ] || [ "$f" = "$in" ] || rm -f "$f"
    done
    say "tls: certificate $id taken"
    [ "$v" -eq 0 ]
}
