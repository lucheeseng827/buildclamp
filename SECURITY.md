# Security policy

A tool that constrains other people's build code and does not run a visible security
process itself is not one anybody should install.

## Reporting

Open a private security advisory on the repository, or email the maintainer. Include what
you did, what happened, what you expected, and a version or commit. A proof of concept
helps and is not required.

**Do not open a public issue for a vulnerability.** Do open one for anything in this
document that is wrong or unclear.

## What is in scope, most interesting first

**An escape from the sandbox.** A build script that reaches the network, writes outside its
granted directories, or reads an environment variable it was not granted, on a host where
`cargo buildclamp doctor` reports the relevant tier as `enforced:`. This is the highest
severity finding in the product and the one most wanted. The known-weak paths are already
documented below and are not findings unless you can do better than the documentation says.

**A report that says a build was clean when it was not.** More serious than an escape,
because an escape is a failure and a false report is a lie. Anything that makes a unit run
unheld without appearing in the report, or a capability appear as `enforced:` when it was
not, is in scope. The sweep exists because of exactly such a bug, found in review.

**Attribution that names the wrong crate.** A report that blames a crate for something
another crate did is an accusation made on a user's behalf that they never checked.

**Anything that gets a secret out.** Including through a telemetry envelope built on
the report.

**Resource exhaustion from one build unit** that a policy cannot bound.

## What is out of scope, and why

**The advisory tier being defeated.** When `doctor` reports `advisory:seccomp-notify`, path
decisions are made by reading the target's memory and answering, and the kernel re-reads
the argument afterwards. A build script can change it in between. This is documented
everywhere it appears, it is what `advisory` means, and `--require-enforced` exists to
refuse a run that only got that far. Defeating it is expected. Defeating an `enforced:`
tier is a finding.

**Reads.** Reads are unrestricted **by default**, so a build script can read
`~/.aws/credentials`. It cannot send them anywhere or write them outside `OUT_DIR` — but it
can stage them into `OUT_DIR`, which is `include!`d into your binary by design. That default
is the drawn boundary, not a bug: it is documented, it is in the README, and closing it is
what the opt-in `withhold-secret-reads` is for. **A bypass of that opt-in is in scope,
though:** once `withhold-secret-reads` is on and the host has Landlock, a read of a withheld
path under an `enforced:` tier is a sandbox escape and a reportable finding, exactly like
any other `enforced:` bypass. Unrestricted default reads are the boundary; defeating an
enabled withholding is crossing it.

**Reading another process's environment without a user namespace.** Documented, probed by
`doctor`, and closed by the namespace tier — by the *user* namespace, which is a correction
to what this file used to attribute it to. A process in a child user namespace cannot pass
`ptrace_may_access` against one in the parent, so the open fails with `EPERM`. The PID
namespace does not close it: unshared on its own the read still returns the full
environment, and it did not apply to the unit in any case, since `unshare(CLONE_NEWPID)`
moves the next process forked and the unit execs without forking. It is no longer requested
at all — the kernel refuses `CLONE_THREAD` once `pid_for_children` differs from the active
namespace, so requesting it left every held unit unable to create a thread. On a host with no user
namespaces the capability reports `advisory` and says so. A fixture in this repository
demonstrates the read.

**A proc-macro detecting that it is held and emitting different code.** Inherent to
compiling untrusted code at all. `cargo-acl` says the same thing about itself and it is
right to.

**Anything requiring an attacker who can already edit `buildclamp.toml`.** Someone who can
change the policy in the same commit has already won. Put the policy under CODEOWNERS.

**A grant doing what it says.** A crate granted `net` reaching the network is the policy
working.

## Our own supply chain

This tool is about build-time supply chain, so its own is checked on every commit:
`cargo-deny` (advisories, bans, licences, sources), `cargo audit`, and a CycloneDX SBOM.
Its dependency set is deliberately small and the workspace manifest argues for each
absence — no `seccompiler`, no `nix`, no HTTP client, no `birdcage`.

**No published binary links a network client, and two checks assert it.** CI greps every
`Cargo.toml`, and `ops/no-network-closure.sh` walks the resolved `cargo tree -e normal`
closure of each shipped binary — the grep alone missed three of four ways a client can
arrive, including any that comes in transitively. Run the script against your own
checkout; that is what it is mirrored for.

The claim is about linking rather than behaviour, and the difference matters: the binary
spawns `cargo`, which fetches crates, so buildclamp is one `exec` from the network at the
process level. What is checkable from `cargo tree` is that no code path inside the artefact
opens a socket. [`ADR-0005`](docs/adr/0005-the-artefact-boundary.md) states the rule and
what it gives up.

## Cryptography

Stated per artefact, because "how many cryptographic implementations are in this?" is a
question every reviewer asks and the honest answer differs across the things built here.

**`cargo-buildclamp` (the free binary).** One asymmetric-crypto implementation: `ring`, for
Ed25519 signature **verification only** — checking that a distributed policy layer was signed
by a key in the repository's committed `trust-root` (the `--require-signed-policy` authority
model). It holds no signing key, and it compiles in **no vendor key**: the trust root is
always the customer's, read from their policy, so a vendor's key rotation or lapse can never
be a customer's build outage. `crates/cli/tests/no_vendor_key.rs` is the source-scanning test
that keeps both true. SHA-256, used only to **name** documents by content hash (policy and
baseline digests), is the sixty-line FIPS 180-4 implementation in
`crates/core/src/sha256.rs`, tested against NIST's own vectors — a content name is not a
security boundary, and pulling a crate and its closure to compute one digest is the trade
that file explains declining. So: one asymmetric implementation, one hand-written hash for
naming, and **no `ed25519-dalek`** — the more obvious choice, declined so a review counts one
asymmetric library rather than two.

**A signer outside this repository.** `ring` for Ed25519 signing and verification and
for SHA-256. It is the half that holds a signing key; this binary does not, which is why
signature verification could live in `cargo-buildclamp` while signing did not.

No asymmetric cryptography is hand-written anywhere in this repository. The single
hand-written primitive is the content-naming SHA-256 in the free binary, and it is
hand-written deliberately, for the reason a tool whose subject is a build's closure has to be
able to answer that question about its own.

## A note on the fixtures

`tests/fixtures/evil` is a working replica of a real malicious build script. It targets
`127.0.0.1:9`, never a real host, and it is excluded from every workspace so that no
`cargo build` anywhere in this repository can execute it. If you find a path by which it
*can* be executed outside the integration tests, that is a finding, and a serious one.
