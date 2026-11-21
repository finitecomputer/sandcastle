#!/bin/sh
# The spike's entrypoint in the computer's image (docs/nitro-spike.md,
# acceptance 8 and 9), at /opt/nitro/entrypoint.sh, run by sandcastle's
# guest as the workload's PID 1. Each step says "nitro: <step>" on stdout,
# which the parent times as it arrives.
#
#   NITRO_WRAPPED unset: a new disk's key, from KMS's GenerateDataKey;
#   NITRO_WRAPPED=<base64>: a wake's, from KMS's Decrypt of the wrapped key.
#   NITRO_FPAC=off: no disk (line 6's runs).
#
# Then FPAC's sealed disk at /opt/data (Hermes' home), and either the
# arguments (Hermes' own entrypoint, say) or a wait.
set -eu
echo "nitro: started"
# The clock first: a confidential guest boots at 1970, and TLS (KMS's,
# line 8) needs the time. It comes from the NSM, the hypervisor's signed
# time, never from the parent.
echo "nitro: time $(/opt/nitro/nitro-key settime)"
if [ "${NITRO_FPAC:-on}" = on ]; then
    # The key and FPAC's state live in memory only: never on a disk the
    # parent can read (FPAC's docs/release.md, /run/fpac on a tmpfs).
    mkdir -p /run/fpac /var/lib/fpac /opt/data
    mount -t tmpfs -o mode=0700,size=16m tmpfs /run/fpac
    if [ "${NITRO_PLAIN:-0}" = 1 ]; then
        # The control run: the same disk unsealed, no key at all.
        echo 'nitro: key {"plain":true}'
        key_arg=""
    else
        if [ -n "${NITRO_WRAPPED:-}" ]; then
            /opt/nitro/nitro-key wake --wrapped "$NITRO_WRAPPED" --out /run/fpac/key > /run/fpac/key.json
        else
            /opt/nitro/nitro-key new --out /run/fpac/key > /run/fpac/key.json
        fi
        echo "nitro: key $(cat /run/fpac/key.json)"
        key_arg="--key-file /run/fpac/key"
    fi
    /opt/nitro/fpac mount --dir /opt/data $key_arg ${NITRO_FPAC_ARGS:-} > /run/fpac/log 2>&1 &
    i=0
    until grep -q '"mounted"' /run/fpac/log 2>/dev/null; do
        if grep -q '"error"' /run/fpac/log 2>/dev/null; then echo "nitro: fpac failed $(cat /run/fpac/log)"; exit 1; fi
        i=$((i + 1)); [ $i -gt 12000 ] && { echo "nitro: fpac never mounted"; exit 1; }
        sleep 0.01
    done
    # A new disk's root is root's; the image's home is its user's (Hermes
    # runs as `hermes`), as the image's own volume was.
    if id hermes > /dev/null 2>&1 && [ "$(stat -c %U /opt/data)" != hermes ]; then
        chown hermes:hermes /opt/data && chmod 0700 /opt/data
    fi
    echo "nitro: mounted $(grep '"mounted"' /run/fpac/log)"
fi
if [ $# -gt 0 ]; then
    exec "$@"
fi
exec sleep infinity
