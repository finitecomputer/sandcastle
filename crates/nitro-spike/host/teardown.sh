#!/usr/bin/env bash
# Lists, or removes, every AWS resource of this spike (docs/nitro-spike.md,
# acceptance 12): whatever carries the tag project=nitro-spike in the
# spike's Region, and its IAM role and instance profile by name and tag.
# Run on the operator's machine with the AWS CLI:
#
#   AWS_PROFILE=<profile> ./teardown.sh list
#   AWS_PROFILE=<profile> ./teardown.sh delete [type ...]
#
# With types (instance, volume, snapshot, security-group, key-pair,
# kms-key, s3-bucket, iam-instance-profile, iam-role), delete removes only
# those: the end of the spike keeps the stopped parent and its key.
#
# It prints what it found or removed by type, with each id shortened to a
# hash, so the output can go into the public evidence; SHOW_IDS=1 prints
# the ids themselves for the operator. KMS keys cannot be deleted at once:
# they are disabled and scheduled for deletion after AWS's shortest wait,
# 7 days. Shell, for the reason parent-ready.sh gives.
set -euo pipefail

REGION=${REGION:-us-east-2}
TAG_KEY=project
TAG_VALUE=nitro-spike
NAME_PREFIX=nitro-spike
mode=${1:-}
[ "$mode" = list ] || [ "$mode" = delete ] || { echo "usage: teardown.sh list | delete [type ...]" >&2; exit 2; }
shift
TYPES="instance volume snapshot security-group key-pair kms-key s3-bucket iam-instance-profile iam-role"
only=" $* "
for t in "$@"; do
    case " $TYPES " in *" $t "*) ;; *) echo "teardown: unknown type $t (one of: $TYPES)" >&2; exit 2 ;; esac
done
# want TYPE: delete removes this type (all of them when none is named).
want() { [ "$only" = "  " ] || [[ "$only" == *" $1 "* ]]; }

aws_r() { aws --region "$REGION" "$@"; }
show() { # type, id
    if [ "${SHOW_IDS:-0}" = 1 ]; then echo "$1 $2"; else echo "$1 <id:$(printf %s "$2" | sha256sum | cut -c1-8)>"; fi
}

filter=(--filters "Name=tag:$TAG_KEY,Values=$TAG_VALUE")
instances=$(aws_r ec2 describe-instances "${filter[@]}" "Name=instance-state-name,Values=pending,running,stopping,stopped" --query 'Reservations[].Instances[].InstanceId' --output text)
volumes=$(aws_r ec2 describe-volumes "${filter[@]}" --query 'Volumes[].VolumeId' --output text)
groups=$(aws_r ec2 describe-security-groups "${filter[@]}" --query 'SecurityGroups[].GroupId' --output text)
keypairs=$(aws_r ec2 describe-key-pairs "${filter[@]}" --query 'KeyPairs[].KeyPairId' --output text)
snapshots=$(aws_r ec2 describe-snapshots --owner-ids self "${filter[@]}" --query 'Snapshots[].SnapshotId' --output text)
tagged=$(aws_r resourcegroupstaggingapi get-resources --tag-filters "Key=$TAG_KEY,Values=$TAG_VALUE" --query 'ResourceTagMappingList[].ResourceARN' --output text)
kms_keys=$(printf '%s\n' $tagged | grep ':kms:' | sed 's#.*:key/##' || true)
buckets=$(printf '%s\n' $tagged | grep '^arn:aws:s3:::' | sed 's#^arn:aws:s3:::##' || true)
roles=$(aws iam list-roles --query "Roles[?starts_with(RoleName, '$NAME_PREFIX')].RoleName" --output text)
profiles=$(aws iam list-instance-profiles --query "InstanceProfiles[?starts_with(InstanceProfileName, '$NAME_PREFIX')].InstanceProfileName" --output text)

# A role or profile is the spike's only if it also carries the tag.
tagged_role() { aws iam list-role-tags --role-name "$1" --query "Tags[?Key=='$TAG_KEY' && Value=='$TAG_VALUE'] | length(@)" --output text; }
tagged_profile() { aws iam list-instance-profile-tags --instance-profile-name "$1" --query "Tags[?Key=='$TAG_KEY' && Value=='$TAG_VALUE'] | length(@)" --output text; }

for i in $instances; do show instance "$i"; done
for v in $volumes; do show volume "$v"; done
for s in $snapshots; do show snapshot "$s"; done
for g in $groups; do show security-group "$g"; done
for k in $keypairs; do show key-pair "$k"; done
for k in $kms_keys; do show kms-key "$k"; done
for b in $buckets; do show s3-bucket "$b"; done
for r in $roles; do if [ "$(tagged_role "$r")" = 1 ]; then show iam-role "$r"; fi; done
for p in $profiles; do if [ "$(tagged_profile "$p")" = 1 ]; then show iam-instance-profile "$p"; fi; done
if [ "$mode" = list ]; then exit 0; fi

if [ -n "$instances" ] && want instance; then
    aws_r ec2 terminate-instances --instance-ids $instances >/dev/null
    aws_r ec2 wait instance-terminated --instance-ids $instances
    echo "terminated: $(wc -w <<<"$instances") instance(s)"
fi
# Volumes deleted with their instance are gone by now; the rest go here.
want volume && for v in $(aws_r ec2 describe-volumes "${filter[@]}" --query 'Volumes[].VolumeId' --output text); do
    aws_r ec2 delete-volume --volume-id "$v"
    show deleted-volume "$v"
done
want snapshot && for s in $snapshots; do aws_r ec2 delete-snapshot --snapshot-id "$s"; show deleted-snapshot "$s"; done
want security-group && for g in $groups; do aws_r ec2 delete-security-group --group-id "$g"; show deleted-security-group "$g"; done
want key-pair && for k in $keypairs; do aws_r ec2 delete-key-pair --key-pair-id "$k" >/dev/null; show deleted-key-pair "$k"; done
want kms-key && for k in $kms_keys; do
    state=$(aws_r kms describe-key --key-id "$k" --query KeyMetadata.KeyState --output text)
    if [ "$state" != PendingDeletion ]; then
        aws_r kms disable-key --key-id "$k" || true
        aws_r kms schedule-key-deletion --key-id "$k" --pending-window-in-days 7 >/dev/null
    fi
    show scheduled-kms-key-deletion "$k"
done
want s3-bucket && for b in $buckets; do
    # Every version and delete marker, then the bucket.
    aws_r s3 rm "s3://$b" --recursive --quiet
    while :; do
        batch=$(aws_r s3api list-object-versions --bucket "$b" --max-items 1000 --query '{Objects: [Versions[].{Key:Key,VersionId:VersionId}, DeleteMarkers[].{Key:Key,VersionId:VersionId}][] }' --output json)
        [ "$(python3 -I -c 'import json,sys; print(len(json.load(sys.stdin).get("Objects") or []))' <<<"$batch")" = 0 ] && break
        aws_r s3api delete-objects --bucket "$b" --delete "$batch" >/dev/null
    done
    aws_r s3api delete-bucket --bucket "$b"
    show deleted-s3-bucket "$b"
done
want iam-instance-profile && for p in $profiles; do
    [ "$(tagged_profile "$p")" = 1 ] || continue
    for r in $(aws iam get-instance-profile --instance-profile-name "$p" --query 'InstanceProfile.Roles[].RoleName' --output text); do
        aws iam remove-role-from-instance-profile --instance-profile-name "$p" --role-name "$r"
    done
    aws iam delete-instance-profile --instance-profile-name "$p"
    show deleted-iam-instance-profile "$p"
done
want iam-role && for r in $roles; do
    [ "$(tagged_role "$r")" = 1 ] || continue
    for pol in $(aws iam list-role-policies --role-name "$r" --query 'PolicyNames' --output text); do
        aws iam delete-role-policy --role-name "$r" --policy-name "$pol"
    done
    for arn in $(aws iam list-attached-role-policies --role-name "$r" --query 'AttachedPolicies[].PolicyArn' --output text); do
        aws iam detach-role-policy --role-name "$r" --policy-arn "$arn"
    done
    aws iam delete-role --role-name "$r"
    show deleted-iam-role "$r"
done
echo "teardown: done${*:+ ($*)}; run 'list' again to see what is left"
