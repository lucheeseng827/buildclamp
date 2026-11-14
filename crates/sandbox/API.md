# The frozen surface of `buildclamp-sandbox`

This crate is meant to be cut out and published on its own. "Run this command under a
capability envelope and tell me which tier held it" is useful to anyone building a CI
runner, a package manager, a plugin host or a test harness, and none of them want a cargo
subcommand. So the surface is frozen **before** the cut rather than after the first
complaint — a crate whose API moves under its consumers is one nobody depends on twice.

## What is frozen

| item | what it is |
|---|---|
| `Plan` and every field | the envelope: what a unit may do, where it may write, what it may read |
| `Plan::default()` | so `Plan { allow_net: true, ..Default::default() }` keeps working |
| `Plan::hold(&self, Command) -> Result<Held, HoldError>` | the whole arrow, in one call |
| `Held` and every field | the tiers that applied, everything the unit asked for, how it ended |
| `HoldError` and every variant | why a unit could not be held |
| `projected_tiers(&HostCapabilities)` | what this host would reach, without running anything |
| `probe::host()` | what the kernel offers |

That is deliberately small. It is the arrow the crate exists for — describe an envelope,
run a command inside it, find out which tier held each capability — and nothing else.

`crates/sandbox/tests/frozen_api.rs` pins each of these at its exact type: every item is
*used*, so a removal, a rename, a changed argument or a changed return type fails to
compile, and the failure names the item. A promise written only in this document would not
survive a refactor.

### One promise that is not a signature

**Every `HoldError` variant is a refusal to run, never a reason to run unheld.** A future
variant meaning "could not hold it, ran it anyway" would satisfy every type in this
document and break the only thing the crate is for. It is asserted in the same test, from
the error text.

## What is not frozen

`bpf` and `bpfcheck`. They are public because a reviewer who does not trust us should be
able to read *and execute* the filter rather than take its behaviour on faith, and because
the fuzz targets are a separate crate that calls them. But a syscall added to the tables
changes `bpf`'s surface, and freezing it would make the filter harder to correct — the
wrong trade for the part of this crate most likely to need correcting.

Depend on them for auditing. Do not depend on them for compiling.

## Additions

A compiler cannot see a *new* public item: a `pub fn` added to this crate compiles
perfectly and quietly enlarges what it promises to keep working forever. `API.txt` is the
snapshot of the declared surface and `tests/api.rs` compares the source against it, so an
addition is a line in a diff somebody looked at rather than something that happened.

Additions are not forbidden. Unconsidered ones are.

## The compatibility suite

[`docs/MATRIX.md`](../../docs/MATRIX.md).

A frozen signature says the calls still typecheck. It says nothing about what they still
*do*, which is the half that decides whether a green build means anything: `Plan::hold`
returning `Ok` with every tier at `none` is a correctly-typed call that enforced nothing.
The matrix is the behavioural half, it is published including the rows that say `none`, and
a consumer regenerates it for their own fleet in one command:

```console
$ ops/matrix-row.sh --label "GKE 1.31 default node image"
```

So "compatible with `buildclamp-sandbox` 0.x" means both: the signatures in this document,
and a matrix row you can reproduce.

## What a version bump means

Nothing above changes without a major version, with one exception stated here rather than
discovered: **a tier may get weaker between patch releases**, because the hosts get weaker.
`projected_tiers` returning `none` where it used to return `enforced:landlock-v7` is a
kernel, a distribution or a container runtime having changed, not this crate breaking its
promise — and reporting the weaker answer is the promise. `docs/MATRIX.md` says the same
thing at more length, under *This is a decaying measurement*.
