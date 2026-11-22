# Measuring an image, and a start that waits for its pin (S3, 2026-11-22)

One real run on lane A's parent (its own Nitro pool, the S3 engine and
bridge), with the suite's test image and a temporary home half of lane A's
own. "Answered" is an exec over the home's claimed session.

## The measure

| Step | Result |
|---|---|
| `GET /v1/images/<ref>` before | no `pcr0` |
| `POST /v1/images/<ref>/measure`, a fresh nonce | answered in **685 ms**: PCR0 `fb3b28b7…`, a document of 4,524 bytes; the engine's log: the sandbox ready in 654 ms, then ended, destroyed |
| `nitro-verify --document … --nonce …` on that document | exit 0, the same PCR0, to AWS's root |
| The PCR0 against the one a real claim verified on this node earlier | **the same** |
| `GET /v1/images/<ref>`, and the list | `pcr0` `fb3b28b7…` in both |
| an engine restart, then `GET` | `pcr0` still shown (the same boot) |
| a second measure, another nonce | the same PCR0 |
| a nonce that is not 64 hex digits | 400 `invalid` |
| an image the node does not hold | 404 `not_found` |
| computers left after each | none |

The sandbox was 1 GiB; the computer below was 3 GiB, and its claim checked
its own document against the measured PCR0: the size is not measured.

## A start whose image is no pin

The home's pins: a placeholder only.

| Step | Result |
|---|---|
| a start through the home | the home: "its image's PCR0 fb3b28b7… is no pin: waiting up to 90 s" |
| 12 s into it | **no computer** on the engine |
| the measured PCR0 written to the pins file | the start answered **2,806 ms** after the pin (14,849 ms in all); the home: "pinned after 14007 ms; starting" |
| an exec over its claimed session | answered (`born=…`, `up=0.25`) |
| a start never pinned | no computer at 30, 60 and 85 s; answered at **90,058 ms**, 400: "PCR0 fb3b28b7… is no image this home runs (this node's measure of celld-image:ec11…); no computer was booted"; the engine's log names it **0** times |
| a start destroyed 5 s into its wait | answered at 6,008 ms: "destroyed while its start waited for its image's pin" |

Before this, a start of an image the home did not pin booted a computer,
was refused at its claim, and was destroyed: each such start a strike for
the cell, three of them a computer that would not wake for 30 minutes.
