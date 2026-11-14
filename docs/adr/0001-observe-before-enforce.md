# ADR-0001: Observe mode is the first command, not a flag

**Status:** accepted · **Date:** 2026-09

## Context

The obvious shape for a capability-gating tool is `cargo buildclamp build`: default-deny,
fail on anything unexpected, add exceptions as they appear. It is one command and it
sounds decisive.

It also breaks a real repository on the first run. The `-sys` crates that make up most of
the build-script population — `openssl-sys`, `zstd-sys`, `ring`, `prost-build`,
`pyo3-build-config`, `vergen` — spawn compilers, run `git`, run `protoc`, run `python`,
and some fetch. A first run that produces forty failures is a tool that gets uninstalled
before anybody reads the second one.

The `-Zsandbox` experiment in cargo hit the same wall from the other direction, and the
dossier this module came from names the ordering explicitly: *"the observe-mode-first
ordering is not a nicety, it is the adoption path."*

## Decision

`cargo buildclamp observe` is the first documented command and refuses nothing.
`cargo buildclamp init` writes the policy from what it recorded. Enforcement is third.

Three properties make that more than a suggestion:

1. `observe` cannot fail a build. Its exit code is the build's own unless `--gate` is
   passed.
2. `init` writes `reviewed = false` on every grant it generates, and puts the observation
   and its date in the `why`. The tool observed; it did not approve.
3. `--strict` refuses to pass while any applicable grant is still unreviewed, so the
   generated file cannot quietly become permanent.

## Consequences

**The default envelope is tuned for the honest case, not the paranoid one.** `exec` is
granted by default and the `benign` fixture — the shape shared by `cc`, `bindgen` and
`pkg-config` — is a regression test asserting **zero** ungranted requests. A change that
makes that fixture fail is a change that makes the tool unadoptable, and it fails CI.

**The first thing a user experiences is measurement.** That also happens to be the honest
framing: buildclamp does not know whether a build script *should* reach the network, only
that it did.

**There is a window where a repository has a policy that grants everything it observed,
including anything malicious that was already there.** Observe mode records a compromise
as faithfully as it records `pkg-config`. This is real and unavoidable for any
observe-first tool, and the mitigation is social rather than technical: the generated
`why` says OBSERVED with a date, every grant is unreviewed, and `--strict` makes a human
look. The README says so rather than implying the first run establishes a safe baseline.
