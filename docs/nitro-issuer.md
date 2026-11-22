# A home's certificate: one wildcard, from the operator's issuer

A home serves its own name and every fragment's under it
(`<home>.<suffix>` and `<app>.<home>.<suffix>`) with **one certificate**
for `<home>.<suffix>` and `*.<home>.<suffix>`. The home makes the key and
keeps it; a small issuer outside the home, holding the zone's DNS token,
gets the certificate from Let's Encrypt by DNS-01 and hands it back. CAA on
the suffix names that issuer's ACME account alone.

Why: Let's Encrypt issues at most **50 new certificates a week per
registered domain**, and every home's names share one. A certificate per
name (Caddy's own, by TLS-ALPN-01, one per fragment on its first visit)
spends that on fragments: one home of a thousand fragments needs twenty
weeks of the domain's limit (S9, docs/nitro-home.md). A certificate per
home spends one.

## The parts

| Part | Where | What it does |
|---|---|---|
| `nitro-issuer csr`, `verify` | the home (its build has no ACME or DNS code: `--no-default-features`) | the key (P-256, made once, 0600 on the encrypted disk) and its request for the two names; the check of a certificate against the key, the names and the clock (exit 0 serves, 3 serves and due for renewal, 1 does not) |
| `tls.sh` | the home, sourced by `entry.sh` | the request sent at each boot, the issuer's answer taken once it serves, a renewal looked for once a minute while the one in use is due |
| the mailbox | the home's own prefix in the fleet bucket: `tls/request.csr` and `tls/chain.pem` | only the home's fleet key and the operator reach it (the home's IAM user reaches its prefix alone); celld's sealed store is under `sealed/`, apart from it |
| `nitro-issuer account`, `issue`, `caa` | the operator's machine | the issuer's ACME account (kept 0600 in its state directory); one order for a home's two names, from the home's name, never from its request, proved by TXT records at `_acme-challenge.<home>.<suffix>` that are removed whatever the outcome, and finalized with the home's request; the suffix's CAA |
| `issuer-sweep.sh` | the operator's machine | its round over the homes: each home's request read, the answer already given kept while it serves and is not due, else an order and its chain written back; a home whose order failed is not ordered for again within an hour |

The Caddyfile of a wildcard home (`cargo xtask home render` with
`"certificate": "wildcard"`) imports `/var/lib/fragment-home/tls/caddy-tls`
in both of its sites; `tls.sh` writes it as `tls <chain> <key>`. Caddy runs
with `--watch`, which reloads its config in process when the adapted config
changes, so its admin endpoint stays off; it serves a new certificate
within a second of that file naming it. Until the home has one, Caddy
waits for it, and every service behind it is up.

## Once, for a suffix

```
nitro-issuer account --state <dir>                       # prints the account's URI
nitro-issuer caa --zone <zone> --token-file <file> --suffix homes.<zone> --account <that URI>
```

`caa` makes the suffix's CAA exactly `issue` and `issuewild`
`"letsencrypt.org; accounturi=<URI>"` (RFC 8659, RFC 8657), and removes
every CAA record **below** the suffix (a home's own, from before), so each
home's name inherits the suffix's. A name outside the suffix is never
touched. It also covers a name no home holds yet: no other account, and
no other CA, may issue for anything under the suffix.

## A new home, and an existing one

`home-create.sh` gives a new home `"certificate": "wildcard"`, points its
names at the parent (no CAA of its own), deploys it, and runs the round for
it until it is answered. For a home made before: add `"certificate":
"wildcard"` to its `home.json`, render, deploy (`home-deploy.sh`), then run
`issuer-sweep.sh --parent <dir> <home>`. A home whose conf says nothing is
`acme`, as before, byte for byte.

## Renewal

A production certificate lasts 90 days (the one below: 22 Nov to 20 Feb;
staging's, 64), and Let's Encrypt is shortening that. Renewal is due 30
days before the end. The round renews
a home's certificate once the one in the mailbox is due (it checks it
against the request's key, having no key of its own), and the home takes
the new one at its next minute. So the round must run at least daily, for
every home; today it runs by hand on the operator's machine.

## The limit that remains

**50 new homes a week per registered domain.** Let's Encrypt counts a new
certificate per home against the registered domain (`<zone>`), and renewals
of the same names do not count. Other limits that a home meets: 5
certificates a week for exactly the same names (a home that loses its key
more than that waits), and 5 failed validations an hour per account and
name (the round's hour between tries).

Ways past it, none of them done:

- **Let's Encrypt's rate limit increase** for hosting providers (their
  request form): the domain's weekly limit raised.
- **A Public Suffix List entry** for the suffix (`homes.<zone>`): each home's
  name becomes a registered domain of its own, with its own 50 a week. It
  also makes each home its own site for browsers' cookies. The list's
  inclusion takes weeks and its rules ask for a lasting commitment.
- **A second CA** by ACME (Google Trust Services, ZeroSSL): its own limits,
  and the suffix's CAA names its account too.

## Who can get a certificate for a home's names

- **The parent** cannot: it holds the address the names point at, so it
  could answer TLS-ALPN-01 or HTTP-01, but CAA names the issuer's account
  alone, and Let's Encrypt refuses every other account (proved below).
- **The issuer** can, for any home under the suffix. It is the operator,
  who holds the zone and so could always have had one (by changing the
  CAA). Every certificate issued is in the public Certificate Transparency
  logs, the issuer's among them.
- **The home's key** never leaves the home: the issuer gets a certificate
  for the home's own key, and could only get one for a key of its own.

## Proved, 2026-11-22

| Step | Result |
|---|---|
| unit tests (`cargo test -p sandcastle-nitro-issuer`, both builds) | a home's names and their challenge name; the CAA set and what it removes (below the suffix only); a request for another home's names, or fewer, refused before an order; the key made once, 0600, kept; a certificate checked against the key and against the request (another key's, other names, not yet or no longer valid, due) |
| `tls-test.sh` (the home's build, a local mailbox, a test CA) | 12 cases: the first boot's key and request; no answer yet; the answer taken; kept without reading the mailbox while it serves; a restart; refused: another key's, another home's names, garbage; due and not renewed yet (the same or another due one): kept; the renewal taken and the one before kept; older ones removed; an expired one replaced by a due one. A bug it found (a good certificate never taken) failed before its fix |
| Caddy 2.11.9 in Docker, `admin off`, `--watch` | `caddy-tls` rewritten: the platform's name and the fragments' names served the new certificate 1,055 ms later; the old file deleted after, still served; the rendered wildcard Caddyfile is a valid configuration |
| an order on Let's Encrypt's **staging** directory, for a name no home holds | issued in 23 s: both names, a 4-certificate chain, 64 days; `verify` against the home's key: serves; no `_acme-challenge` record left |
| the suffix's CAA set to the issuer's production account | 2 records added; the 20 that `home-create.sh` had written at test1 to test10 removed; the system's resolver: the suffix's two records, none at a home's name, the owner's own name unchanged; a second run changed nothing |
| an order by an account the CAA does not name (the issuer's staging account), for a new name | refused for both names: "CAA record for homes.&lt;zone&gt; prevents issuance"; its records removed |
| a retry of a failed order within a minute | refused: "Incorrect TXT record … found": Let's Encrypt's other vantage points still held the first try's records (their TTL is 60 s); so a home is not ordered for again within the hour |
| curl's own SigV4 on the home's prefix (`--aws-sigv4`, the home's fleet key on stdin) | PUT 200, GET 200, DELETE 204, then 404 |
| **the loop end to end, on Let's Encrypt production**, for a check name (`lanea-check`) whose mailbox was a test home's prefix plus `lane-a-check/` | the home side (`tls.sh` itself) sent its request and found no answer; the round (`issuer-sweep.sh`) ordered, was issued in 20 s and wrote the chain back; the home side took it (`verify`: serves, 89 days); a second round ordered nothing ("serves, not due"); the chain verifies to the system's roots |
| that certificate served by Caddy 2.11.9 (`import` of `caddy-tls`, `--watch`, `admin off`) | the platform's name and two fragments' names, each 200 with TLS checked against the system's roots; then the mailbox's objects deleted (204) and no `_acme-challenge` record left |

## What is left

- **A real home on the wildcard**, its apps served: waits for a test home
  that can start (the test parent is refused `ec2:StartInstances`
  by an organization policy since 2026-11-22) and for lane B's rebuild of
  the home image with this change.
- **Where the issuer runs.** By hand on the operator's machine today, with
  each home's own fleet key from the operator's directory. Its production
  form: a scheduled round with a key of its own that reads
  `*/tls/request.csr` and writes `*/tls/chain.pem` and nothing else. Remove
  the per-home keys' use once that key exists.
- **The owner's home** keeps its own account and per-name certificates.
