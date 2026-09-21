# witness-gauntlet

Drive a [C2SP tlog-witness](https://c2sp.org/tlog-witness) through a set of adversarial
checkpoints and see what it does. One Python file, no dependencies, no network beyond the
witness under test.

The suite signs its own test log. The witness under test has to be told to trust that log's
key for one origin — which also means the run touches nothing else that witness holds.

```
python3 gauntlet.py --print-vkey
gauntlet.example/log+85f57892+AUy1q/atefv1q7zK/MJp2FzSZR7UuIW1hp8kGu3wpbop

# configure the witness to trust that key for gauntlet.example/log, then:
python3 gauntlet.py --url http://127.0.0.1:8477
```

Each case names the rule it checks and where the rule comes from:

- **spec** — the tlog-witness or tlog-checkpoint spec says so. A failure is a defect, and the
  run exits 1.
- **strict** — stricter than the Go reference witness (`transparency-dev/witness`), which
  accepts the input. A failure is reported as `MISS` and never fails the run; it is a choice
  for the operator, not a bug.

## What it checks

Trust on first use; growth with and without a consistency proof; a garbage proof; a stale
old size; a second root at a size already cosigned; a rollback; an unknown origin; a
signature that does not verify; more than 63 proof lines; a size-0 checkpoint whose root is
not `MTH({}) = SHA-256("")`; a non-canonical base64 root; a wrong-length root; and a fork
below the witness's current size.

## Measured

| witness | spec failures | strict misses |
|---|---|---|
| `transparency-dev/witness` @55a5a0b (the reference) | 0 | 1 — accepts a non-canonical base64 root |
| `cryptovalid-opencore` 0.14.0 | 0 | 0 |
| `markovianprotocol.com/witness` | 0 | 0 |

The Markovian witness scored two spec failures the first time this suite was pointed at it,
both now fixed: it cosigned a size-0 checkpoint carrying a fabricated root, and it recorded a
malformed root as equivocation evidence on a public page. That is what the suite is for.

## Limits worth stating

The HTTP interface shows a status code, so the suite sees which refusal a witness picks, not
why. Three consequences:

- Whether a witness *keeps* the two signed notes after refusing a fork is invisible here.
  Keeping them is the difference between refusing misbehaviour and being able to prove it
  happened, and it can only be checked in that witness's own published evidence.
- The wrong-length root case runs against a size the witness already holds, so a refusal may
  be the ordinary root mismatch rather than a judgement about length.
- A run leaves state behind: the witness now holds a cosigned checkpoint for the test origin.
  A second run needs a fresh origin (`--origin`, with a matching `--seed-hex`) or a witness
  that has been reset. The suite detects the stale case and stops rather than reporting its
  own staleness as a defect.

Cases are ordered so that the checks needing an empty tree run before anything is cosigned.

## Checking the suite itself

Every PASS depends on this suite's own RFC 6962 being right, so `selftest.py` checks it
against a different implementation in a different language: the roots and consistency proofs
in `rfc6962_kat.json` come from `github.com/transparency-dev/merkle`. The Ed25519 vector is
RFC 8032 section 7.1, test 1.

```
python3 selftest.py
10 checks, 0 failures
```

## Files

- `gauntlet.py` — the suite.
- `selftest.py`, `rfc6962_kat.json` — the check on the suite's own crypto.
- `ed25519.py` — a from-scratch RFC 8032 implementation, so a run does not lean on the same
  crypto library the witness under test uses.
