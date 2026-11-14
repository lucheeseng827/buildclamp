# ADR-0002: Enforce in-process, never through a helper binary

**Status:** accepted · **Date:** 2026-09

## Context

The nearest existing tool, `cargo-acl`, sandboxes build scripts with **bubblewrap**. It is
a good choice: `bwrap --unshare-all --clearenv` with a read-only root and a writable
`OUT_DIR` bind is most of what is needed, in one well-tested external program.

It has one failure mode, and it is in its own source. When `bwrap` is not on `PATH`,
`cargo-acl` prints *"bwrap (bubblewrap) doesn't seem to be installed, so sandboxing will
be disabled"* and **continues**. In a CI container — a minimal image, a distroless
builder, anywhere nobody installed bubblewrap — that is a security control reporting
success while enforcing nothing, and nothing in the output of a passing build says so.

`birdcage`, the other obvious answer, is archived, GPL-3.0-or-later, panics if the calling
process has more than one thread, and has a single Linux backend with no tier concept.

## Decision

buildclamp establishes its own sandbox in-process, using `seccomp`, `unshare` and `mount`
directly through `libc`. It requires no external binary.

**Landlock is among them, and the decision above dictated its shape.** The ruleset is
built in the PARENT, before the fork, because the `pre_exec` closure runs in a process
that already has a supervisor thread and therefore must not allocate — and every ergonomic
Landlock API allocates, since building a ruleset means building a list. The child issues
`landlock_restrict_self` on the inherited descriptor and nothing else: one syscall, no
allocation. That is why `crates/sandbox/src/linux/landlock.rs` is raw syscalls over `libc`
rather than a dependency; a crate cannot be adapted into that shape from outside.

An earlier revision of this ADR claimed Landlock was in use when no code path touched it,
and a later one recorded the rung as unbuilt. Both were accurate when written. The rung
exists now, and the filesystem tier falls back to a mount namespace, then to seccomp
notification, where the kernel does not have it.

It also **cannot be configured into the failure above**: there is no code path where a
missing mechanism results in an unheld run. A capability that cannot be constrained at all
is reported as `Tier::None` with a reason, `--require-enforced` fails such a run, and a
setup error in enforce mode is an error rather than a fallback to running unheld.

## Consequences

**We own the pitfalls.** The ordering rules, the capability lock, the fork/handoff dance
and the notification protocol are all ours to get right, and all of them cost a spike to
discover. `ARCHITECTURE.md` §4 records them because they are not obvious and re-deriving
them would be expensive.

**We must write and maintain `unsafe`.** All of it is in `buildclamp-sandbox`, each block
carries the invariant that makes it sound, and every other crate is
`#![forbid(unsafe_code)]`.

**The `pre_exec` closure must allocate nothing, take no locks and never panic** — every
buffer, path and BPF program is built before the fork. This is a real constraint on how
the crate can be written and it is not negotiable: the process is mid-fork with a
supervisor thread already running.

**We get the tier ladder, which is the point.** An external sandboxer gives one answer:
it worked or it is not installed. Doing it in-process is what makes "Landlock is absent,
so the filesystem fell back to a mount namespace, and here is the label in the report"
expressible at all — and on this project's own host, Landlock *is* absent.
