#!/usr/bin/env python3
"""A home's DNS, on the operator's machine (docs/nitro-home.md, "Many homes on
one parent"), through Cloudflare's API with a token that edits one zone's DNS:

    home-dns.py <homes.json> point <host>           its name and its fragments' -> the parent
    home-dns.py <homes.json> caa <host> none         no CA may issue for it (before its account exists)
    home-dns.py <homes.json> caa <host> <account>    only that ACME account, at Let's Encrypt, and no wildcard

homes.json names `address` (the parent's public address) and `dns`
({"zone": ..., "token_file": ...}). Each record is made, or changed to what
it should be; the rest of the zone is untouched. A home's name holds its own
records because a name with any record is no longer answered by the zone's
`*.<suffix>` wildcard: `<host>` and `*.<host>` (A, DNS only), and its CAA
(RFC 8659, `accounturi` RFC 8657), which its fragments' names inherit. The
token is read from its file and sent only to the API, never printed.
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
        key = (lambda r: r["content"]) if rtype == "A" else (lambda r: (r["data"]["tag"], r["data"]["value"]))
        wkey = (lambda b: b["content"]) if rtype == "A" else (lambda b: (b["data"]["tag"], b["data"]["value"]))
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
    elif what == "caa":
        account = sys.argv[4]
        if account == "none":
            issue = ";"
        elif re.fullmatch(r"https://acme-v02\.api\.letsencrypt\.org/acme/acct/[0-9]+", account):
            issue = f"letsencrypt.org; accounturi={account}"
        else:
            sys.exit(f"home-dns: {account}: none, or a Let's Encrypt account URI")
        ensure("CAA", host, [{"data": {"flags": 0, "tag": "issue", "value": issue}}, {"data": {"flags": 0, "tag": "issuewild", "value": ";"}}])
        print(f"home-dns: {host}'s CAA: " + ("no CA may issue" if account == "none" else "only its own account"))
    else:
        sys.exit("home-dns: point or caa")


if __name__ == "__main__":
    main()
