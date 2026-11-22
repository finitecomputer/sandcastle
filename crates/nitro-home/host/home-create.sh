#!/usr/bin/env bash
# A new home, one command on the operator's machine (docs/nitro-home.md,
# "Many homes on one parent"):
#
#   home-create.sh <name> --parent <dir>
#
# The home of an org called <name>, on the parent <dir> describes, served at
# https://<name>.<suffix>, its fragments at https://<fragment>.<name>.<suffix>.
# Prints, on its last line, {"home": <its address>, "door": <its door>}: the
# door is what a hosted platform's "Add a private agent" asks
# (`private_home.door`, fragment docs/api.md, "A private agent").
#
# <dir>/homes.json (the operator's, never in a repo) names what every home
# on that parent shares: `ssh` ([<ssh config>, <host>]), `suffix`,
# `region`, `parent_role` (the parent's instance role, which the keys
# name), `fleet_bucket` and `counter_bucket` (each home its prefix in
# both), `fragment_tree` (a fragment tree after `cargo xtask build`, which
# renders the release), `models_file`, `model_key_file`, `default_plan`,
# `operators`, `inviter` (the platform's npub whose asks make accounts),
# `size` ({vcpus, memory_mib, cpu_overcommit, data_gib, scratch_gib}),
# `cid_base`, `subnet` (`a.b`: home n is on a.b.n.0/24), `env` (more
# settings for every home, such as HOME_ENGINE=none), `door` ([<fragment
# tree>, <git ref>]: the identity door's source, home-deploy.sh --door),
# `address` (the parent's public address) and `dns` ({zone, token_file}:
# a token that edits that zone's DNS, home-dns.py).
#
# Made for the home, each only when missing (so a run that stopped is run
# again to finish), in $NITRO_HOMES/<name> (default ~/.cache/nitro-real/homes):
#
#  1. its place on the parent: the first number n no home there holds, and
#     from it a CID, a tap and a /24;
#  2. its KMS key (tagged), which admins may seal with and never open, and
#     which the parent's role opens only for the home's own image (until
#     its first deploy pins one, no image);
#  3. its fleet-bucket credential: an IAM user that reaches <name>/ in the
#     fleet bucket and nothing else, and its bucket's seal (celld#30): a
#     new key, and a counter at homes/<name>/bucket in the counter bucket
#     behind an IAM user of its own;
#  4. its render conf, its launcher conf (behind the parent's SNI router:
#     no port forwarded, the PROXY protocol from the parent's address) and
#     its release (`cargo xtask home render`);
#  5. its DNS (home-dns.py): its name and its fragments' pointing at the
#     parent (their CAA is the suffix's, which names the issuer's account
#     alone: docs/nitro-issuer.md);
#  6. then its first deploy (home-deploy.sh --home): sealed, built, staged,
#     measured, pinned, started and routed;
#  7. its certificate, one for its name and its fragments' wildcard
#     (docs/nitro-issuer.md): the home asks at its first start, for a key
#     it makes and keeps; the issuer's round, which home-deploy.sh runs
#     beside the switch (nitro-issuer's issuer-sweep.sh, built here:
#     NITRO_ISSUER, default the tree's target/release/nitro-issuer),
#     answers, and the home serves it within seconds.
#
# Secrets go only into the home's directory (owner-only) and its sealed
# bundle; nothing secret is printed or passed on a command line. Every AWS
# resource is tagged project=nitro-spike, lane=home, home=<name>.
set -euo pipefail
umask 077
here=$(dirname "$(realpath "$0")")
say() { echo "home-create: $*" >&2; }
name=${1:?usage: home-create.sh <name> --parent <dir>}
[ "${2:-}" = "--parent" ] || { say "usage: home-create.sh <name> --parent <dir>"; exit 2; }
pdir=$(realpath "${3:?--parent <dir>}")
[[ "$name" =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$ ]] || { say "$name: a name is a DNS label of at most 32 (a-z, 0-9, inner -)"; exit 2; }
homes=${NITRO_HOMES:-$HOME/.cache/nitro-real/homes}
H=$homes/$name
P=$pdir/homes.json
[ -s "$P" ] || { say "$P: the parent's homes.json"; exit 2; }
get() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print(v if isinstance(v,str) else json.dumps(v))' "$P" "$1"; }
region=$(get region)
aws() { command aws --profile "${AWS_PROFILE:-finite}" --region "$region" "$@"; }
tags_kv=(Key=project,Value=nitro-spike Key=lane,Value=home "Key=home,Value=$name")
tags_kms=(TagKey=project,TagValue=nitro-spike TagKey=lane,TagValue=home "TagKey=home,TagValue=$name")
if [ -e "$H/created" ]; then
    say "$name exists"
    cat "$H/created"
    exit 0
fi
aws sts get-caller-identity --query Account --output text > /dev/null || { say "no AWS session (aws login)"; exit 1; }
account=$(aws sts get-caller-identity --query Account --output text)
mkdir -p "$H/secrets/aws" "$H/kms" "$H/attest"

# 1. its place on the parent
if [ ! -s "$H/alloc.json" ]; then
    python3 -I - "$homes" "$name" "$P" > "$H/alloc.json.new" <<'PY'
import glob, json, os, sys
homes, name, conf = sys.argv[1:4]
p = json.load(open(conf))
taken = set()
for a in glob.glob(f"{homes}/*/alloc.json"):
    o = json.load(open(a))
    if o["parent"] == os.path.dirname(conf):
        taken.add(o["n"])
n = next(i for i in range(1, 255) if i not in taken)
net = f"{p['subnet']}.{n}"
print(json.dumps({"parent": os.path.dirname(conf), "n": n, "cid": p["cid_base"] + n, "tap": f"nitroh{n}", "host_addr": f"{net}.1", "guest_addr": f"{net}.2"}, indent=1))
PY
    mv "$H/alloc.json.new" "$H/alloc.json"
fi
alloc() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$H/alloc.json" "$1"; }
say "place: n=$(alloc n), cid $(alloc cid), tap $(alloc tap)"

# 2. its key
if [ ! -s "$H/kms/key-id" ]; then
    python3 -I - "$account" "$(get parent_role)" > "$H/kms/policy.json" <<'PY'
import json, sys
account, role = sys.argv[1:3]
print(json.dumps({"Version": "2012-10-17", "Statement": [
    {"Sid": "AdministerAndSealButNeverOpen", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
     "Action": ["kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*", "kms:Disable*", "kms:Get*", "kms:Delete*",
                "kms:TagResource", "kms:UntagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:Encrypt"], "Resource": "*"},
    # no image's PCR0 is 96 f's: nothing opens it until the first deploy
    # pins the home's own image (pin-pcr0.sh)
    {"Sid": "ReleaseOnlyToTheHomeImage", "Effect": "Allow", "Principal": {"AWS": role},
     "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*",
     "Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": ["f" * 96]}}}]}, indent=1))
PY
    aws kms create-key --description "nitro-spike: home $name" --policy "file://$H/kms/policy.json" --tags "${tags_kms[@]}" \
        --query KeyMetadata.KeyId --output text > "$H/kms/key-id.new"
    mv "$H/kms/key-id.new" "$H/kms/key-id"
    say "its key made"
fi

# 3. its bucket's credentials and seal
fleet=$(get fleet_bucket) counter=$(get counter_bucket)
user() { # <user> <policy json>: the user, its one policy, an access key once
    local u=$1 doc=$2 out=$3
    aws iam get-user --user-name "$u" > /dev/null 2>&1 || aws iam create-user --user-name "$u" --tags "${tags_kv[@]}" > /dev/null
    aws iam put-user-policy --user-name "$u" --policy-name its-prefix-only --policy-document "$doc"
    if [ ! -s "$out" ]; then
        aws iam create-access-key --user-name "$u" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text > "$out.new"
        mv "$out.new" "$out"
    fi
}
fleet_doc=$(python3 -I -c 'import json,sys; b,n=sys.argv[1:3]; print(json.dumps({"Version":"2012-10-17","Statement":[
 {"Sid":"ItsPrefixListed","Effect":"Allow","Action":"s3:ListBucket","Resource":f"arn:aws:s3:::{b}","Condition":{"StringLike":{"s3:prefix":[f"{n}/*"]}}},
 {"Sid":"WhereItIs","Effect":"Allow","Action":"s3:GetBucketLocation","Resource":f"arn:aws:s3:::{b}"},
 {"Sid":"ItsPrefix","Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],"Resource":f"arn:aws:s3:::{b}/{n}/*"}]}))' "$fleet" "$name")
counter_doc=$(python3 -I -c 'import json,sys; b,n=sys.argv[1:3]; print(json.dumps({"Version":"2012-10-17","Statement":[
 {"Sid":"ItsCounterListed","Effect":"Allow","Action":"s3:ListBucket","Resource":f"arn:aws:s3:::{b}","Condition":{"StringLike":{"s3:prefix":[f"homes/{n}/*"]}}},
 {"Sid":"ItsCounter","Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":f"arn:aws:s3:::{b}/homes/{n}/*"}]}))' "$counter" "$name")
user "nitro-home-$name-fleet" "$fleet_doc" "$H/secrets/aws/fleet-key"
user "nitro-home-$name-counter" "$counter_doc" "$H/secrets/aws/counter-key"
read -r id secret < "$H/secrets/aws/fleet-key"
printf '%s' "$id" > "$H/secrets/aws/access-key-id"
printf '%s' "$secret" > "$H/secrets/aws/secret-access-key"
if [ ! -s "$H/secrets/bucket-seal.json" ]; then
    python3 -I - "$H/secrets/aws/counter-key" "$counter" "$name" "$region" > "$H/secrets/bucket-seal.json.new" <<'PY'
import base64, json, secrets, sys
keyfile, bucket, name, region = sys.argv[1:5]
kid, ksecret = open(keyfile).read().split()
print(json.dumps({"key": base64.b64encode(secrets.token_bytes(32)).decode().rstrip("="),
                  "counter": {"bucket": f"s3://{bucket}", "name": f"homes/{name}/bucket", "region": region,
                              "access_key_id": kid, "secret_access_key": ksecret}}))
PY
    mv "$H/secrets/bucket-seal.json.new" "$H/secrets/bucket-seal.json"
fi
install -m 0600 "$(get model_key_file)" "$H/secrets/model-key"
say "its bucket's credentials and seal made"

# 4. its confs and release
host=$name.$(get suffix)
python3 -I - "$P" "$host" "$(alloc host_addr)" > "$H/home.json" <<'PY'
import json, sys
p, host, parent = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
print(json.dumps({"platform_host": host, "fragment_suffix": host, "models_file": p["models_file"], "default_plan": p["default_plan"],
                  "operators": p["operators"], "inviter": p["inviter"], "proxy_from": parent, "certificate": "wildcard"}, indent=1))
PY
python3 -I - "$P" "$H/alloc.json" "$(cat "$H/kms/key-id")" "$host" "$fleet" "$name" > "$H/launcher.json" <<'PY'
import json, sys
p, a = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
key, host, fleet, name = sys.argv[3:7]
s = p["size"]
# the paths are home-stage.sh's: the slot's, and the home's own disks and sockets
print(json.dumps({"dir": "", "vsock_dir": "", "kernel": "", "initrd": "", "image_json": "", "image_config": "", "sealed": "", "data": "", "scratch": "",
    "kms_key": key, "data_gib": s["data_gib"], "scratch_gib": s["scratch_gib"], "vcpus": s["vcpus"], "memory_mib": s["memory_mib"],
    "cpu_overcommit": s["cpu_overcommit"], "cid": a["cid"], "tap": a["tap"], "host_addr": a["host_addr"], "guest_addr": a["guest_addr"],
    "dns": "1.1.1.1", "entrypoint": ["/opt/fragment-home/entry.sh"],
    "env": [f"HOME_BUCKET=s3://{fleet}/{name}", f"HOME_REGION={p['region']}", f"HOME_PLATFORM={host}", f"HOME_SUFFIX={host}"] + p["env"],
    "inbound_tcp": []}, indent=1))
PY
[ -e "$H/pins" ] || echo "# the computer images this home starts (none yet)" > "$H/pins"
python3 -I -c 'import json,sys; print(*json.load(open(sys.argv[1]))["ssh"])' "$P" > "$H/parent"
tree=$(get fragment_tree)
# rendered again only when its conf changed: a render stamps its time
# (FRAGMENT_DEPLOYED_AT), so a new one is a new image and a new PCR0
if [ "$(sha256sum < "$H/home.json")" != "$(cat "$H/out/home.json.sha256" 2>/dev/null)" ] || [ ! -s "$H/out/release/release-id" ]; then
    ( cd "$tree" && cargo xtask home render --conf "$H/home.json" --secrets "$H/secrets" --out "$H/out" ) > "$H/render.log" 2>&1 || { tail -n 20 "$H/render.log" >&2; say "the render"; exit 1; }
    sha256sum < "$H/home.json" > "$H/out/home.json.sha256"
    say "its release rendered"
fi

# 5. its DNS
"$here/home-dns.py" "$P" point "$host" >&2

# 6. its first deploy (a wildcard home's certificate is answered during it)
echo "$pdir" > "$H/parent-dir"
door=$(python3 -I -c 'import json,sys; print(*json.load(open(sys.argv[1]))["door"])' "$P")
NITRO_HOME_DIR=$H "$here/home-deploy.sh" --home "$name" --door $door

# 7. its certificate, answered by the issuer's round during the deploy
for _ in $(seq 60); do curl -s -o /dev/null -m 10 "https://$host/" && break; sleep 1; done
curl -s -o /dev/null -m 10 "https://$host/" || { say "https://$host/ does not answer with a valid certificate"; exit 1; }
python3 -I -c 'import json,sys; h=sys.argv[1]; print(json.dumps({"home": f"https://{h}", "door": f"https://{h}/__door"}))' "$host" > "$H/created"
cat "$H/created"
