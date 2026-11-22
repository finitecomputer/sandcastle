# The key service, one real run (2026-11-22)

Lane A's parent (one m8g.xlarge, its own Nitro pool), two confidential
sandboxes booted by the home's launcher (`nitro-home up`) from measured
dm-verity roots: **the key service** (`nitro-keys serve`, its image's PCR0
`3d4a4539…b20e0d2026b3`) and **a test home** (asking for its key every
15 s with `nitro-key keys release`, PCR0 `1db7893a…ea6f406062`). The test
home reached the service only through the parent's vsock relay. Both
documents were verified down to AWS's Nitro root (`nitro-verify`). The
owner's statements were signed by the real fragment CLI
(`fragment private-home`, fragment's `cli/src/private_home.rs`) with a
fresh nostr key of its own.

## The service's own key

| Step | Result |
|---|---|
| First boot, the KMS key's policy naming the service's PCR0 | "a new share, wrapped in the disk's first block": KMS's `GenerateDataKey` answered only into the document's envelope |
| The operator makes the home, expecting another PCR0 | refused: "the service runs 3d4a4539…, not 0000…: nothing sealed to it" |
| The operator makes the home, the right PCR0 | `{"answer":"added","generation":1}`: the home's key sealed to the RSA key in the service's own document |
| A restart of the service | "state opened at generation 4": the share released again (`Decrypt`), the sealed state opened |
| What the parent signed for it, in that life | one request: `TrentService.Decrypt`. It saw its target and its body's hash; KMS's answer went into the document's envelope |

## The owner's word

Each row is the test home's next try (or the service's answer).

| What was signed (and by whom) | The home's try |
|---|---|
| nothing | refused: "nothing the owner signed covers the image 1db7893a…" |
| `release --pcr0 1db7893a…`, by **another key** | the statement refused: "the statement is not the home's owner's" |
| `release --pcr0 1db7893a…`, by the owner | **released**: "the owner named this image"; the key's SHA-256 `1595becc…` is the operator's key's |
| `withdraw --slot release/1db7893a…` | refused again: "nothing the owner signed covers the image" |
| the earlier `release`, sent again | the statement refused: "a newer statement already fills its slot" |
| `accept-releases` (the default: a day after publication), no log entry offered | refused (no publication) |
| … with an entry the log took an hour ago | refused: "the owner's rule takes this image from …, not yet" |
| … with an entry whose log signature is a stranger's | refused: "the log's signature on the entry does not verify under the pinned log key" |
| … with an entry the log took 25 hours ago | **released**: "the owner's rule: Finite published this image at …" |
| after the service's restart | **released**, by the same rule |
| `repair --to <a person> --hours 1` | the service: until one hour on for that person, `null` for anyone else; the CLI refused 30 hours ("1 to 24 hours") |

## What this run used in place of the real thing

- **The public log** was a test log of Rekor's shape (its signed entry
  timestamps, its `hashedrekord` bodies), with a test log key and a test
  release key pinned in the service's image. Publishing Finite's releases
  in the public Rekor log is an outward step, not taken here.
- **The test home** is not lane B's home: the home still asks KMS for its
  keys. Moving it to the key service is a home image change.

## What it does not close yet

- **KMS is the only lock on the service's state.** Whoever can rewrite
  that KMS key's policy (the AWS project's administrators, and AWS) can
  name another image, open the state, and change every owner's rule. The
  rule is not yet one we cannot change alone. A second share slots in
  beside KMS (`state.rs`, `Shares::second`); where it lives is the owner's
  decision.
- **The service's state can be rolled back by the parent**: its data disk
  is the parent's file, and a state older than the last one written opens
  at a fresh start (the generation is checked within a life only). The
  counter of PR 9 (sandcastle#30) is what closes it.
- **Making a home is trusted at creation**: the operator gives the home's
  key and its owner; a parent could make a new home name of its own.
- **Repair is answered, not enforced**: nothing runs a repair session yet
  (the home takes no exec at all since #27).
- The iPhone app's signing of statements is not built; the CLI's is.
