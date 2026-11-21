#!/bin/bash
# The planted-string scan (sandcastle docs/nitro.md, "The sealed scratch
# disk"): a test container writes a canary into its writable root (the
# scratch disk), synced; root on the parent then counts it in the scratch
# disk's file while the container runs. The canary is made inside the
# guest from a seed (sha256 of it, in hex), so the start request the
# parent holds names the seed, never the canary.
set -u
IMG=$1; NAME=lane-a-canary
E="curl -sS --unix-socket /var/lib/sandcastle-engine/engine.sock"
SEED=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
CANARY=$(printf '%s' "$SEED" | sha256sum | cut -d' ' -f1)
cat > /tmp/$NAME.json <<J
{"image":"$IMG","enableInternet":false,"env":{"SEED":"$SEED"},
 "entrypoint":["python3","-c","import hashlib,os,time; c=hashlib.sha256(os.environ['SEED'].encode()).hexdigest(); f=open('/canary.txt','w'); f.write((c*64+chr(10))*256); f.flush(); os.fsync(f.fileno()); os.sync(); print('planted', flush=True); time.sleep(120)"],
 "instance":{"vcpu":1,"memoryMib":3072,"diskMb":2000},"labels":{"lane":"a-canary"}}
J
$E -X POST -H 'Content-Type: application/json' --data-binary @/tmp/$NAME.json http://e/v1/containers/$NAME/start > /dev/null
planted=no
for i in $(seq 30); do $E http://e/v1/containers/$NAME/logs 2>/dev/null | grep -q planted && { planted=yes; break; }; sleep 1; done
[ "$planted" = yes ] || { echo "{\"error\": \"the canary was never planted\"}"; $E -X POST -H 'Content-Type: application/json' --data-binary '{}' http://e/v1/containers/$NAME/destroy > /dev/null; exit 1; }
slot_dir=$($E http://e/v1/containers/$NAME | python3 -c 'import json,sys,os; print(os.path.dirname(json.load(sys.stdin)["agentSocket"]))')
disk=$slot_dir/scratch.ext4
bytes=$(sudo stat -c %s "$disk"); used=$(sudo du -k "$disk" | cut -f1)
found=$(sudo grep -a -o -F "$CANARY$CANARY" "$disk" | wc -l)
seeds=$(sudo grep -a -o -F "$SEED" "$disk" | wc -l)
anywhere=$(sudo grep -r -a -l -F "$CANARY" /var/lib/sandcastle-engine 2>/dev/null | wc -l)
$E -X POST -H 'Content-Type: application/json' --data-binary '{}' http://e/v1/containers/$NAME/destroy > /dev/null
echo "{\"planted_copies\": 16384, \"scratch_disk_bytes\": $bytes, \"scratch_disk_written_kib\": $used, \"canary_pairs_found_on_scratch\": $found, \"seed_found_on_scratch\": $seeds, \"engine_state_files_naming_the_canary\": $anywhere}"
