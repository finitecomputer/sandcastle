#!/usr/bin/env python3
"""A home's DNS, on the operator's machine (docs/nitro-home.md, "Many homes on
one parent"), through Cloudflare's API with a token that edits one zone's DNS:

    home-dns.py <homes.json> point <host>    its name and its fragments' -> the parent

homes.json names `address` (the parent's public address) and `dns`
({"zone": ..., "token_file": ...}). Each record is made, or changed to what
it should be; the rest of the zone is untouched. A home's name holds its own
records because a name with any record is no longer answered by the zone's
`*.<suffix>` wildcard: `<host>` and `*.<host>` (A, DNS only). Its CAA is
the suffix's, which names the issuer's ACME account alone (sandcastle's
docs/nitro-issuer.md, `nitro-issuer caa`). The token is read from its file
and sent only to the API, never printed.
"""
import json
import os
import re
import sys
import urllib.request

API = "https://api.cloudflare.com/client/v4"
TTL = 60
NOTE = "Nitro home (home-dns.py)"


def main():
    conf, what, host = sys.argv[1], sys.argv[2], sys.argv[3].lower()
    p = json.load(open(conf))
    zone, token_file = p["dns"]["zone"], os.path.expanduser(p["dns"]["token_file"])
    if not (host.endswith("." + zone) and re.fullmatch(r"[a-z0-9.-]+", host)):
        sys.exit(f"home-dns: {host} is not a name in {zone}")
    token = open(token_file).read().strip()
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}

    def call(path, body=None, method="GET"):
        req = urllib.request.Request(API + path, data=json.dumps(body).encode() if body is not None else None, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=20) as r:
            out = json.load(r)
        if not out.get("success"):
            sys.exit(f"home-dns: {method} {path.split('?')[0]}: {out.get('errors')}")
        return out["result"]

    (z,) = call(f"/zones?name={zone}")
    zid = z["id"]

    def records(rtype, name):
        return call(f"/zones/{zid}/dns_records?type={rtype}&name={name}&per_page=100")

    def ensure(rtype, name, want):
        """The records of `rtype` at `name` become exactly `want` (bodies)."""
        have = records(rtype, name)
        key = lambda r: r["content"]
        wkey = lambda b: b["content"]
        keep = {wkey(b) for b in want}
        for r in have:
            if key(r) not in keep:
                call(f"/zones/{zid}/dns_records/{r['id']}", method="DELETE")
        present = {key(r) for r in have}
        for b in want:
            if wkey(b) not in present:
                call(f"/zones/{zid}/dns_records", dict(b, type=rtype, name=name, ttl=TTL, comment=NOTE), "POST")

    if what == "point":
        for name in (host, "*." + host):
            ensure("A", name, [{"content": p["address"], "proxied": False}])
        print(f"home-dns: {host} and *.{host} point at the parent")
    else:
        sys.exit("home-dns: point")


if __name__ == "__main__":
    main()
