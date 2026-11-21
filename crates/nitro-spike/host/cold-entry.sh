# Line 9 cold-read study's workload start (host/cold-reads.py): the image's
# entrypoint (nitro-entrypoint.sh) on the plain disk, less its NSM clock: a
# direct sandbox has no NSM, and every setting of the study runs this same
# start. The clock is the parent's word here (NITRO_NOW), which a
# measurement on a plain disk can take; a computer never does.
set -eu
echo 'nitro: started'
date -s "@${NITRO_NOW}" > /dev/null
echo "nitro: time $(date +%s)"
mkdir -p /run/fpac /var/lib/fpac /opt/data
mount -t tmpfs -o mode=0700,size=16m tmpfs /run/fpac
echo 'nitro: key {"plain":true}'
/opt/nitro/fpac mount --dir /opt/data > /run/fpac/log 2>&1 &
i=0
until grep -q '"mounted"' /run/fpac/log 2>/dev/null; do
    if grep -q '"error"' /run/fpac/log 2>/dev/null; then echo "nitro: fpac failed $(cat /run/fpac/log)"; exit 1; fi
    i=$((i + 1)); [ $i -gt 12000 ] && { echo 'nitro: fpac never mounted'; exit 1; }
    sleep 0.01
done
if id hermes > /dev/null 2>&1 && [ "$(stat -c %U /opt/data)" != hermes ]; then chown hermes:hermes /opt/data && chmod 0700 /opt/data; fi
echo "nitro: mounted $(grep '"mounted"' /run/fpac/log)"
if [ $# -gt 0 ]; then exec "$@"; fi
exec sleep infinity
