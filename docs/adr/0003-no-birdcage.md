# ADR-0003: Do not depend on `birdcage`

**Status:** accepted · **Date:** 2026-09

## Context

`phylum-dev/birdcage` is a cross-platform embeddable sandbox with 132,906 downloads:
user, mount, PID and network namespaces plus a seccomp allowlist on Linux, Seatbelt on
macOS, and a capability-shaped `Exception` API very close to what this project needs. It
is the obvious way to avoid writing any of `buildclamp-sandbox`.

## Decision

Do not depend on it. Take the design ideas — namespaces plus a syscall allowlist, a
capability enum rather than a permission bag — and write the enforcement here.

## Consequences

Four independent reasons, any one of which would be sufficient:

1. **Licence.** `birdcage` is **GPL-3.0-or-later**. Linking it would make
   `cargo-buildclamp` GPL-3.0, and the OSS half of this project is Apache-2.0 on purpose:
   a security tool people cannot embed freely is a security tool that does not get adopted
   into a build.
2. **Archived.** The repository was archived read-only on **2026-07-06**, after Veracode
   acquired Phylum's technology assets (announced 2025-01-06). crates.io is frozen at
   0.8.1 from 2024-04-19.
3. **It panics in our process shape.** `Sandbox::spawn` asserts the calling process is
   single-threaded. buildclamp's seccomp supervisor thread must already be blocked in
   `recvmsg` before the fork, or the child's own first `execve` notification deadlocks —
   so the assertion fires exactly where we need it not to.
4. **No tier concept.** One Linux backend, no fallback ladder, no way to report which
   mechanism actually applied, and it does not use Landlock at all. Naming the tier is
   this project's central honesty property, so a dependency that cannot express it is not
   a dependency that can be adapted into one.

We implement the tier ladder directly instead, over `libc`, and each rung reports the
mechanism that actually applied — Landlock included, built the way ADR 0002's in-process
decision requires: ruleset in the parent, one `landlock_restrict_self` in the child.
