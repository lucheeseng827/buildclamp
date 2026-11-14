# Negative verification vectors

**Run these against your own verifier, not only against ours.**

A verifier that rejects everything passes a naive negative suite. So every vector here
carries the reason it must be rejected *for*, and a verifier that rejects the right
documents for the wrong reasons fails this file as surely as one that accepts them.

```console
$ for f in schemas/v1/negative/*.json; do
    case "$f" in */vectors.json) continue;; esac
    cargo buildclamp verify "$f" --require-fully-enforced >/dev/null 2>&1
    printf '%-38s exit=%s\n' "$(basename "$f")" "$?"
  done
```

Exactly one file — `VALID-control.json` — may exit `0`. Every other exits `2`, and they do
so for **two different reasons** that a suite has to keep apart:

* most are **rejected as documents**: a wrong `predicateType`, a subject that disagrees with
  the predicate, a payload that is not base64;
* four (`read-deny-off`, `compile-units-unheld`, `one-advisory-capability`,
  `operator-override`, `no-tiers-at-all`) **verify perfectly well** and must not be reported
  as describing a fully enforced run. Without `--require-fully-enforced` they exit `0`, and
  that is correct: they are valid statements about builds that were not fully enforced.
  Confusing the two classes is how an attestation becomes a laundering machine.

`vectors.json` is the machine-readable form: one entry per file, `expect` naming the class
of rejection — or `not-fully-enforced`, or `accept` for the control — and `given` naming the
digests a verifier should be handed, for the vectors whose rejection needs a file to compare
against. `crates/core/tests/negative.rs` is what this project runs it with, and it asserts
the *reason* rather than merely that something failed.

## The one that is not hypothetical

`wrong-predicate-type.json` is CVE-2022-35929: cosign returned **success** when no
attestation of the requested type existed at all, because the type came from a `--type`
flag rather than from the document. `cargo buildclamp verify` reads `predicateType` out of
the document and has no such flag. The fixed cosign is **≥ 1.10.1**; if your verification
path includes an older one, this vector is the one that matters most.

## What these vectors cannot test

Signatures. Every document here is unsigned, because the free binary checks everything
except the signature and says so on every run — see `cargo buildclamp verify --help`. A
complete negative suite for *your* pipeline needs the cryptographic vectors too: a
truncated signature, an algorithm swapped for a weaker one, a valid signature over a
different payload. Those belong wherever the signature is checked, which is cosign or
`gh attestation verify`, and both ship their own.
