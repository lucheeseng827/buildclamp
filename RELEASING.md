# Release policy

What this project promises about versions, support windows and the compiler floor — so
somebody deciding whether to put it in their build path can read the commitment rather
than infer it from the tags.

**Status: nothing has been released.** Everything below is the policy that will apply from
`v0.1.0`. Two things it describes do not exist yet and are marked where they appear: the
signed and reproducible release pipeline, and the rebuilder. Publishing this before the
first release is deliberate — a policy written after the fact is written around whatever
happened.

## Four things are versioned, and they move independently

A reader who assumes one number covers all of them will be wrong in the direction that
costs them a debugging session.

| what | where | changes when |
|---|---|---|
| the binaries, by semver | `Cargo.toml` | any user-visible change |
| `POLICY_VERSION` | `crates/core/src/policy.rs` | `buildclamp.toml` gains a key that an older release cannot ignore safely |
| `REPORT_FORMAT_VERSION` | `crates/core/src/report.rs` | `report.json` changes in a way an older reader cannot parse |
| the attestation statement format | the signer, outside this repository | the signed statement changes shape |

**Additive changes do not bump a schema version.** A new optional field takes
`#[serde(default)]`, and old documents keep parsing with the default as their correct
reading. A change that *cannot* be defaulted is breaking and takes a bump — which the
reader then refuses by version and by name rather than by whichever field it noticed
first. `crates/core/tests/schema.rs` pins that rule against a real v1 report kept in the
repository, and it is the test that catches the mistake: it caught one the day it landed.

**Readers refuse the future, accept the past.** A report from a newer buildclamp is
refused with its version named. An older report parses. Gating both directions would make
every schema bump a flag day across a fleet for no safety gained.

## Upgrade notes, every release

Every release ships upgrade notes, and they are part of the release rather than a courtesy
afterwards. A tool that holds a build to a policy can change what that policy *means*
without changing its shape, and a reader who upgrades without being told is one whose build
breaks for a reason the changelog did not mention.

Four questions, answered in the release notes whether or not the answer is "nothing":

1. **Does an existing `buildclamp.toml` still parse and still mean the same thing?** A new
   key is not a break; a changed default is. Name it, say which direction it moves, and say
   what to write to keep the old behaviour.
2. **Does an existing report still read?** The report is a versioned wire format and only
   the *future* is refused, so the answer should be yes — and when `REPORT_FORMAT_VERSION`
   moves, say what a consumer that has not upgraded loses.
3. **Can a build that passed now fail?** A tightened default, a new refusal, a fixed false
   negative. This is the one people need before they upgrade rather than after.
4. **Can a build that failed now pass?** A fixed false positive is still a behaviour change,
   and somebody gating on the old answer deserves to know.

Where the answer to 3 or 4 is yes, the notes name the crates it was measured against and the
date, not an adjective.

## Cadence and support

* **Minor releases every 8–12 weeks.** Patches whenever a fix warrants one.
* **N-2 supported**, where N is the latest minor. Three minors is roughly six to nine
  months at that cadence.
* **Every release stays installable.** A yank marks a version as not-to-be-newly-depended-on;
  it does not remove it. Pinning to a previous release is therefore always one line, which
  is what makes the rollback runbook in [`docs/OPERATIONS.md`](docs/OPERATIONS.md) a
  runbook rather than a hope.

## Security backports

Fixes for anything reported through [`SECURITY.md`](SECURITY.md) are backported to every
supported release, not only the latest.

**How an embargoed fix reaches the public mirror without leaking it.** This repository is
published one-way from a private source, so a fix exists here before it appears there. An
embargoed fix is developed in the private tree, and the mirror receives it **in the same
sync as the release that contains it** — never earlier as an isolated commit whose diff
is the vulnerability with an arrow pointing at it. The advisory and the code become public
together. This is a property of the sync mechanism rather than a promise: the mirror only
ever receives what a sync stages, and a sync is a release.

## MSRV

**The floor moves no faster than one Rust release per two minor versions, and never in a
patch.**

It is `rust-version` in the workspace manifest, currently **1.91**, and it is *measured*
rather than declared: CI builds with exactly that toolchain against the committed
lockfile. An earlier version of this project claimed 1.82 and would have failed on its
first run, because `clap_lex` needs edition 2024 and `cargo-platform` declares 1.91. A
floor nobody compiles against is a number in a manifest.

Raising it is a minor-version change and goes in the changelog with the reason.

## Deprecation

A removal is announced one minor release before it happens, and the release that announces
it keeps the old behaviour working. For anything that appears in `buildclamp.toml` or
`report.json`, that means one full cadence — 8 to 12 weeks — between "this is deprecated"
and "this is gone".

## Signed, reproducible releases

**Not built yet.** Stated here as the shape rather than as a claim, because this project's
rule is that an absence is written down rather than left to be discovered:

* crates.io Trusted Publishing, so no long-lived token exists to leak.
* GitHub Artifact Attestations, verifiable with `gh attestation verify`.
* A pinned container image with `--remap-path-prefix` and `SOURCE_DATE_EPOCH`, because
  Rust is not byte-reproducible out of the box and pretending otherwise would be the exact
  overstatement this repository's `CLAIMS.toml` exists to prevent.
* A rebuilder job that rebuilds the *previous* release from its tag and byte-diffs it.

When it exists the claim will be stated precisely — "byte-reproducible from this pinned
image with these flags, verified on every release" — and never as bare "reproducible
builds" or "SLSA Level 3". The rebuilder must be green on two consecutive releases before
any of it is claimed anywhere.

## Dependencies

A **monthly** scheduled pull request refreshes the lockfile. Not a per-commit bot: a
stream of individual bumps trains reviewers to approve without reading, which is the
opposite of what a tool whose subject is dependency behaviour should be teaching its own
maintainers.

Adding a dependency needs an argument in the pull request. See
[`CONTRIBUTING.md`](CONTRIBUTING.md); the workspace manifest already argues for each
absence, and `ops/no-network-closure.sh` will reject a network client outright.
