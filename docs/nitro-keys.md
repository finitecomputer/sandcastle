# The key service: a release rule we cannot change alone

The design's PR 10 ([nitro-spike.md](nitro-spike.md), "A release rule we
cannot change alone"). Today a home's keys are released by KMS to the PCR0
its key policy names, and whoever can rewrite that policy (the AWS
project's administrators, and AWS) can name another image, one that skips
the passkey check or anything else. The key service moves that decision to
the home's owner.

## In plain words

- A key service runs in its own Nitro Sandbox, from its own measured image,
  with its own PCR0. It holds each home's wrapping key, the key the home's
  own keys (its bundle's, its disk's) are wrapped with.
- It gives a home its key only when the home proves which image it runs (an
  NSM attestation document) and the home's owner has said yes to that
  image, in a statement signed with the owner's own device key: the nostr
  key the fragment CLI and the iPhone app already hold. Never a browser's.
- The owner signs one default statement, once: **accept the images Finite
  publishes in the public log, a day after they are published.** A new
  image then reaches the owner's home only after the world could see it for
  a day, and we cannot change the owner's rule.
- A repair (a person running commands in someone's home) is a grant the
  owner signs, naming the person and ending within a day.

## Statements

A statement is a nostr event (NIP-01), kind 30078 (NIP-78, an application's
own data), whose `d` tag is `finite.home/<home>/<slot>` and whose content is
one of:

| `says` | Slot | Means |
|---|---|---|
| `accept-published-releases` `{after_s}` | `releases` | release the key to an image Finite published in the public log at least `after_s` ago (the default: a day) |
| `release` `{pcr0}` | `release/<pcr0>` | release the key to this image, now |
| `repair` `{to, until}` | `repair/<key>` | the person whose key is `to` may repair the home until `until` (at most a day) |
| `withdraw` | any | what that slot said no longer holds |

A newer statement in a slot replaces the older; an older one is refused, so
a statement replayed later cannot undo a withdrawal. A statement is checked
whole: its id is its hash, its signature is its key's, and its key is the
home's owner's, bound when the home was made. `fragment private-home`
signs them (fragment's `cli/src/private_home.rs`).

## The public log

The default rule asks whether Finite published an image, and when. The log
is Sigstore's Rekor, or one of its shape. Finite signs a release,
`{"finite-release":1,"image":"…","pcr0":"…"}`, with its release key, and
the log returns an entry and its signed entry timestamp (SET): the log's
signature over the entry and the time it took it. The key service checks,
offline, against the two keys pinned in its own measured image: the log's
SET, the entry's signer (Finite's release key), the signature over the
release's exact bytes, and the PCR0. The parent may hand the entry over; it
cannot make one. The time is the log's, signed, never the parent's or ours.

## Its own state

The service's state (each home's owner, statements and key) is sealed
(AES-256-GCM) under a key made from **shares**:

- **Today, one share, from KMS**, released only to the key service's PCR0.
  So KMS is the only lock on the key service's state, and **whoever can
  rewrite that KMS key's policy (the AWS project's administrators, and AWS
  itself) can still open the state, and so change every owner's rule, until
  a second lock exists.** This is not yet a rule we cannot change alone.
- **A second share slots in beside it**, from a lock KMS never sees: a key
  service in another trust domain, another operator, or the owner's device.
  Where it lives is the owner's decision. A state sealed with two shares
  does not open with one, so the second lock, once added, cannot be
  quietly dropped.

The state carries a generation, raised at every write, and the service
refuses a state older than the one it holds. Its storage's holders can
still serve an older one to a fresh start, which the counter of PR 9 closes
for the home, and the second lock closes for this service.

## Not built yet

- The second share (above), and the owner's choice of where it lives.
- The iPhone app's signing of statements: the CLI's is built.
- The home asking the key service instead of KMS (lane B's home image).
- Publishing Finite's releases in the public Rekor log: an outward step,
  for the owner to approve.
