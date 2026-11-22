#!/usr/bin/env python3
"""Does a home's sealed fleet journal let it start again? On the operator's
machine, read-only (docs/nitro-home.md, "Deploys"):

    home-journal-check.py <launcher conf> [--wait <s>] [--profile P] [--region R]

A home's start replays the sealed bucket's journal (celld#30) from its newest
snapshot up to the counter, and refuses when a commit's record is missing
("the journal's commit N is gone"). celld#31 stops such holes forming, but a
home must never be restarted onto one: its running celld still holds the
index, and its next snapshot puts the hole behind it. The journal's object
names are its commits' numbers (16 hex digits), so a listing shows a hole:
every commit after the newest snapshot, up to the newest record, must be
there. A record lost at the very end shows as a hole once the next commits
land, so the journal is listed twice, --wait seconds apart (a running home
commits about once a second), and the union is checked.

Prints one line; exits 0 when the journal has no hole after its newest
snapshot, 1 when it has one (naming the missing commits), 2 when it cannot
tell. Uses the operator's AWS session; reads object names alone.
"""
import json
import subprocess
import sys
import time


def listing(profile, region, bucket, prefix):
    out = subprocess.run(["aws", "--profile", profile, "--region", region, "s3api", "list-objects-v2", "--bucket", bucket, "--prefix", prefix,
                          "--output", "json"], capture_output=True, text=True, timeout=300)
    if out.returncode != 0:
        print(f"home-journal-check: cannot list {prefix}: {out.stderr.strip()[:200]}")
        sys.exit(2)
    # without --query the CLI merges every page into one document
    keys = [o["Key"] for o in (json.loads(out.stdout) if out.stdout.strip() else {}).get("Contents", [])]
    seqs = set()
    for k in keys:
        tail = k.rsplit("/", 1)[-1]
        try:
            seqs.add(int(tail, 16))
        except ValueError:
            pass
    return seqs


def main():
    args = sys.argv[1:]
    conf = args[0]
    opt = lambda name, default: args[args.index(name) + 1] if name in args else default
    wait = float(opt("--wait", "15"))
    profile, region = opt("--profile", "finite"), opt("--region", "us-east-2")
    env = dict(e.split("=", 1) for e in json.load(open(conf)).get("env", []))
    spec = env.get("HOME_BUCKET", "")
    if not spec.startswith("s3://"):
        print(f"home-journal-check: {conf} names no HOME_BUCKET")
        sys.exit(2)
    bucket, _, prefix = spec[len("s3://"):].partition("/")
    base = "/".join(p for p in (prefix.strip("/"), "sealed", "sealed-bucket") if p)
    # the snapshots first: one written meanwhile is newer than every record
    # listed after it would cover
    snapshots = listing(profile, region, bucket, base + "/snapshot/")
    first = listing(profile, region, bucket, base + "/journal/")
    if wait > 0:
        time.sleep(wait)
    journal = first | listing(profile, region, bucket, base + "/journal/")
    if not journal and not snapshots:
        print("home-journal-check: no sealed journal yet (a new home): nothing to check")
        return
    # with no snapshot yet, a start replays the journal from its first commit
    newest = max(snapshots) if snapshots else 0
    after = sorted(s for s in journal if s > newest)
    if not after:
        print(f"home-journal-check: ok: no commit after the newest snapshot ({newest})")
        return
    missing = sorted(set(range(newest + 1, after[-1] + 1)) - journal)
    if missing:
        print(f"home-journal-check: HOLE: commits {missing[:10]}{'…' if len(missing) > 10 else ''} are missing between the newest snapshot ({newest}) and the newest record ({after[-1]}): do not restart this home")
        sys.exit(1)
    print(f"home-journal-check: ok: commits {newest + 1}..{after[-1]} after the newest snapshot ({newest}), none missing")


if __name__ == "__main__":
    main()
