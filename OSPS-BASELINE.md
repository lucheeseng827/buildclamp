# OSPS Baseline self-assessment

A self-assessment against the [OpenSSF Open Source Project Security
Baseline](https://baseline.openssf.org/), published **with its gaps** rather than as a
badge.

That distinction is the whole point of the file. A badge says a project passed on the day
somebody ran the check; a published gap list says what it does not do, which is the thing
a person deciding whether to depend on it actually needs. This project's only real asset
is that its limits are written down, and a security baseline it graded itself on privately
would be worth nothing.

**Self-assessed, not certified.** Nobody external has checked this. Where a row is
generous to us, that is a bug — [`SECURITY.md`](SECURITY.md) has the route.

*Assessed 2026-09-09 at Level 1, against a project that has not released.*

## Met

| control | how |
|---|---|
| Public source, public history | this repository |
| OSI licence, stated per path | Apache-2.0; the boundary is a directory, answerable by looking at a path |
| Contribution guide | [`CONTRIBUTING.md`](CONTRIBUTING.md), including the mirror replay |
| Code of conduct | [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) |
| Security policy with a reporting route | [`SECURITY.md`](SECURITY.md) |
| Machine-readable security metadata | [`SECURITY-INSIGHTS.yml`](SECURITY-INSIGHTS.yml) |
| Versioned releases with a stated policy | [`RELEASING.md`](RELEASING.md) |
| Change history | [`CHANGELOG.md`](CHANGELOG.md), with the host and tier beside every measurement |
| CI on every change | `.github/workflows/ci.yml` |
| Automated tests, and gates that are observed to fail | the fixture gates; every gate in this repository is mutation-tested |
| Dependency inventory | `Cargo.lock`, committed, and CI builds `--locked` |
| Static analysis | `clippy -D warnings` on both planes, all targets |
| Contributor provenance | DCO sign-off, checked in CI |
| Documented build and test | `CONTRIBUTING.md`; `cargo test --workspace --locked` |

## Not met, and what it would take

| control | status | what is missing |
|---|---|---|
| Signed releases | **no** | nothing has been released. The pipeline is designed in `RELEASING.md` and not built: Trusted Publishing, artifact attestations, a pinned image |
| Reproducible builds | **no** | Rust is not byte-reproducible out of the box. Needs `--remap-path-prefix`, `SOURCE_DATE_EPOCH` and a rebuilder green on two consecutive releases before it may be claimed at all |
| Independent security review | **no** | no third-party audit of `crates/sandbox/src/linux`, which is where every `unsafe` block lives. Grant applications are the funding route and none has been submitted |
| Two or more maintainers | **no** | one. This is the project's largest single risk and it is not a documentation problem: if one person is unavailable for a quarter, nothing ships |
| Branch protection and required reviews | **no** | a one-maintainer repository cannot require a second reviewer without blocking itself. Honest answer rather than a workaround |
| Multi-factor authentication policy | **partial** | in force for the maintainer; not enforceable at org level with one member |
| Fuzzing | **no** | the policy parser and the BPF generator are the obvious targets and neither is fuzzed |
| Dependency update automation | **partial** | a monthly lockfile refresh is policy in `RELEASING.md`; the scheduled job is not wired |
| Vulnerability disclosure track record | **n/a** | none reported, none fixed. A clean record on a project nobody has attacked is not evidence |
| SBOM published per release | **no** | generated ad hoc, not attached to a release, because there are no releases |

## The honest summary

Ten of the fourteen Level 1 controls this project can meet without releasing or funding,
it meets. The four that matter most to somebody evaluating a **security** tool — signed
releases, reproducibility, independent review, and more than one maintainer — it does not.

Three of those four are blocked on money or time rather than on knowing what to do. The
fourth, the single maintainer, is the one that would still be true with both.
