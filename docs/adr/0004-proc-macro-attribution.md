# ADR-0004: Attribute proc-macro requests inside rustc, and state the confidence

**Status:** accepted · **Date:** 2026-09

## Context

A proc-macro is a shared object that **rustc loads and calls while compiling the
consumer**. There is no separate process. A sandbox around rustc therefore constrains
every proc-macro in that compilation identically, and when something reaches the network
it can only say "something in this compilation did it".

`cargo-acl` documents the consequence plainly: *"if one proc macro needs more access it
needs to be granted to all"*, and *"Controlling the sandbox on a per-proc-macro basis
unfortunately isn't supported yet."* Nobody has shipped better. In a graph where `serde`
pulls `serde_derive`, that means a grant covering one macro covers every macro.

Doing nothing was an option: hold rustc, name the consumer, list the proc-macros in its
closure, and say so. It is honest and it is what every other tool does.

## Decision

Try harder, and record how confident the answer is rather than pretending it is always
exact.

At a seccomp notification the supervisor already has the notifying **thread id**. From
there:

1. `/proc/<tid>/syscall` yields `nr arg0..arg5 sp pc`.
2. `/proc/<tid>/maps` says which mapping `pc` falls in.
3. The run directory already holds an inventory of the proc-macro shared objects this
   build produced, recorded when each was compiled.

If `pc` is inside a known proc-macro's `.so`, the request is attributed to **that macro by
name** with confidence `exact`. If `pc` is in libc or libstd — which it will be whenever
the call goes through the dynamically linked C library — scan the stack below `sp` for
return addresses inside a known `.so` and report `stack-scan`. If neither works, report
`closure`.

## Consequences

**It degrades to the incumbent's answer, never to nothing.** `closure` is exactly what
`cargo-acl` gives, so the worst case is parity.

**`stack-scan` is a heuristic and the type says so.** A stack scan can find a stale frame
left by an earlier call, so it names a likely culprit rather than a certain one. The
report carries the confidence and the README has a table explaining the three values;
presenting a stack-scan hit as certain would be exactly the overclaiming this project
criticises elsewhere.

**It fails on some builds and that is acceptable.** `/proc/<tid>/syscall` can be
unavailable or return `pc = 0` under some hardening configurations. The rule is to degrade
to `closure`, never to guess.

**It costs a read per notification.** Only on the compile-unit path, where notifications
are already rare because the filesystem tier is kernel-enforced there.

**This is the strongest genuinely unclaimed thing in the product**, so it is worth the
complexity. If it turns out to be unreliable in practice, the honest response is to say so
in the README and keep the `closure` fallback — not to quietly report a guess.

## Validation — what is measured, and what is not

The design above was dead until the compile-hold path (Y1 Q4) started threading the
recorded proc-macro inventory into the sandbox, and it stayed *unproven at `exact`* until
an executing test drove a real proc-macro's own code to the syscall. Both now exist. The
rule for this ADR is the milestone's own: **accuracy is published before it is claimed**, so
this section states exactly what has been demonstrated and, more importantly, what has not.

### `exact` — demonstrated, precision 1.0 on the demonstrated corpus

`a_held_compile_names_the_exact_proc_macro_that_reached_out`
(`crates/cli/tests/procmacro.rs`) is the proof, and it is an executing end-to-end test, not
a unit test over fabricated `/proc` maps. A probe proc-macro (`tests/fixtures/probemacro`)
issues `socket(AF_INET, …)` with an inline `syscall` instruction compiled into its own
shared object, so the instruction pointer the kernel records falls inside
`libprobemacro-*.so`. A second proc-macro (`tests/fixtures/quietmacro`) is in the same
closure and does nothing. Under a held compile the report attributes the `socket` request
`exact` to `probemacro`, and `quietmacro` is never named as a culprit of anything.

The corpus is one probe on x86_64, so the number that can honestly be published is small:
**one `exact` attribution, correct, zero false — precision 1.0**. What makes it a release
gate rather than a happy-path demo is that the test also fails if the innocent macro is
named or the wrong crate is, so a regression that made `exact` imprecise would block the
build. This is how "precision at `exact` must be 1.0 or the release blocks" is realised
here: as an executing gate, not a promise. The `closure` fallback is demonstrated
separately by `a_refusal_inside_a_compile_names_the_macros_that_could_have_been_responsible`,
where the set correctly names *both* macros — the incumbent's answer, which `exact` improves
on by naming the one that actually reached out.

### Not measured, and therefore not claimed

Three things the full version of this milestone (8 PW, deferred) would establish are
**absent on purpose**, stated here so a reader does not read the demonstration above as a
benchmark:

- **`exact` precision across a synthetic sweep.** Ground-truth graphs varying closure size,
  depth, macro count and expansion order, with an instrumented probe, are not built. The
  precision figure above is one point, not a distribution.
- **`stack-scan` precision.** `stack-scan` is emitted by the code and labelled a heuristic
  by its type, but no accuracy has been measured for it, so **it is not a claimed
  confidence level**. A stack scan can find a stale frame; until its false-attribution rate
  is measured on a real corpus, the honest position is the ADR's own — keep it, label it,
  and claim nothing about how often it is right. The reduced scope for this milestone is
  deliberately "`exact` only".
- **The `closure` size distribution.** That distribution *is* the precision bound of the
  fallback — a closure of two names is a far tighter answer than one of forty — and it is
  not published here.

If a later measurement shows `exact` mis-attributing even once, the response is the one
SECURITY.md ranks above an escape: withdraw the claim, not reword it, and record the
outcome in `CLAIMS.toml`.
