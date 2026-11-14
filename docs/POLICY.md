# Writing a policy

You should not write `buildclamp.toml` by hand. `observe` then `init` writes it from what
your build actually did, and this page is about the part that comes after: deciding whether
each grant should exist, widening one when a crate legitimately needs more, and getting a
real repository to the point where `--strict` passes.

The [configuration reference](CONFIG.md#buildclamptoml) has every key. This is the
reasoning.

## What a grant is for

A grant is a sentence a colleague reads in a pull request. Everything else about the format
follows from that.

```toml
[grants."openssl-sys"]
version = ">=0.9, <0.10"
capabilities = ["net", "fs-write", "exec", "unix"]
write-zones = ["out-dir", "tmp"]
net-destinations = ["downloads.example.org:443"]
why = "downloads and verifies a pinned upstream tarball when no system library is found"
reviewed = true
```

`why` is required and may not be empty — a grant without one is a parse error before any
unit runs. That is the `cargo-vet` ergonomic applied to capabilities: the cost of widening
an envelope is that somebody writes a sentence. A grant that appears silently in a diff is
the failure this file exists to prevent.

**A grant replaces the defaults; it never adds to them.** Writing `capabilities = ["net"]`
for a crate that also writes `OUT_DIR` takes the write away. `init` folds the defaults in
for you, and by hand you list everything the crate needs. A reader should be able to see
the whole envelope in one place rather than compose it in their head.

## What the defaults already allow

Most crates need no grant at all. Before adding one, check that the crate is actually
outside this:

| a build script may, by default | a build script may not |
|---|---|
| write in `OUT_DIR` and the system temporary directory | write anywhere else |
| read anything | — (reads are unrestricted unless you turn `withhold-secret-reads` on) |
| run another program | reach the network |
| connect to a unix socket | read a credential-shaped environment variable |

Measured on 2026-09-15: `libc`, `libz-sys`, `openssl-sys` including the `vendored` feature,
`bindgen`, `ring`, `zstd-sys`, `lz4-sys`, `brotli-sys`, `blake3`, `proc-macro2`, `quote`,
`prettyplease` and `clang-sys` all stay inside it and `init` writes no grant for any of
them. The heaviest of those — vendored OpenSSL, which compiles the whole library from
source — made 32,762 file operations and left `OUT_DIR` for none of them.

## The four things a crate can need

### It reaches the network

```toml
capabilities = ["net", "fs-write", "exec", "unix"]
net-destinations = ["downloads.example.org:443"]
```

`net-destinations` is **reported and never enforced**, and the format says so in the same
sentence as the field. Enforcing a destination allowlist would need a resolving proxy, and
a tool that appeared to enforce one while a build script can resolve a name itself is worse
than one that admits it does not. Write them down anyway: the destination is the single
most useful line in an incident, and the report records what was actually reached, so a
difference between the two is a finding.

### It writes outside `OUT_DIR`

```toml
capabilities = ["fs-write", "exec", "unix"]
write-zones = ["out-dir", "tmp", "manifest-dir"]
```

`manifest-dir` is a build script writing into its own source tree, which cargo documents as
unsupported and which a handful of crates do anyway. `target` is the whole target
directory, and it is the one to think about twice: a build script that can write into
`target/*/deps` can drop a replacement shared object for a proc-macro another crate is
about to load.

For a path no zone describes, `write-paths` takes absolute paths. Use it rarely — a policy
full of absolute paths does not survive being moved to a CI runner.

### It needs a variable buildclamp treats as a credential

```toml
env-allow = ["OPENSSL_DIR"]
```

and for a name on the hard-deny list — `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`,
`CARGO_REGISTRY_TOKEN` and the rest — the parser additionally requires:

```toml
env-allow-secrets = true
```

so that the choice is visible in the diff rather than inferred from a name in a list. There
is a cost stated in the reference and worth repeating: a name re-admitted by any grant stays
in *cargo's* environment for the whole build, because the per-unit scrub cannot put back
what was removed before cargo started. Every other unit still has it withheld.

### It reads a path you are withholding

Only relevant with `withhold-secret-reads = true`, which is off by default:

```toml
capabilities = ["fs-read", "fs-write", "exec", "unix"]
```

## Versions

`init` writes the observed **minor series** — `>=0.9.4, <0.10` — rather than the exact
version. Pinning exactly would make every patch bump a fresh failure, which trains people
to widen the requirement until it means nothing; leaving it off entirely would let a future
version inherit a grant nobody looked at. The middle is where drift is visible without
being noise.

Two grants for one crate at the same specificity is an **error**, not last-one-wins: a
policy whose meaning depends on the order of its lines is one nobody can review. A
version-qualified grant beats an unqualified one, so a tie only happens when the policy is
genuinely ambiguous. A crate needing two envelopes at two versions is written as two blocks:

```toml
[[grants."libc"]]
version = "<1"
capabilities = ["exec", "fs-write", "unix"]
why = "probes the target with a compiler"

[[grants."libc"]]
version = ">=1"
capabilities = ["exec", "fs-write", "unix"]
why = "same, and the 1.x probe also writes a cfg table"
```

## Making `--strict` reachable on a real repository

A first `init` on a large graph can write a couple of hundred grants, all unreviewed, and
nobody reads two hundred build scripts in an afternoon. The realistic outcomes without help
are `--strict` never being turned on, or somebody setting every `reviewed` to true with
`sed`. Both leave a gate that gates nothing.

Two mechanisms, and they compose.

**`--grace <days>`** makes a grant `init` first wrote within the window warn rather than
fail. It measures from the grant's `first-seen`, which `init` writes and nothing else
touches; a grant carrying no `first-seen` is never in grace, which is what stops it becoming
a way never to review anything.

**`init --accept-baseline <file>`** marks grants reviewed where a published document
vouches for that exact crate version, and records the document's SHA-256 in the policy as
the reviewer of record. It matches the *exact* version and pins each accepted grant to it,
so a patch bump comes back for review rather than inheriting an approval nobody made; it
only ever narrows, so a crate that did something the document does not describe stays
unreviewed. `init` prints how many are left, which is the number that says whether a
baseline is worth anything. [`examples/baseline.toml`](../examples/baseline.toml) is the
format.

Neither is a way to skip the work. What they buy is that the work is a list somebody can
read rather than a wall nobody starts.

## More than one repository

A single file per repository is right for one repository and wrong for forty. What a
security team actually wants to say — "no build script in this organisation reaches the
network, and here are the nine crates that may" — has nowhere to live in a flat file, so it
gets said in a wiki and enforced by nobody.

```toml
# org/buildclamp.toml
version = 2
[layer]
name = "org"
may-widen = false          # nothing above may confer what this does not

[grants."openssl-sys"]
capabilities = ["net", "fs-write", "exec", "unix"]
write-zones = ["out-dir", "tmp"]
why = "downloads a pinned tarball when no system library is found"
reviewed = true
```

```toml
# each repository
version = 2
[layer]
name = "repo"
extends = ["../org/buildclamp.toml"]
```

A repository may **narrow** freely and may grant anything the org's ceiling already allows.
A grant that exceeds the ceiling is refused before cargo starts, naming both files — never
merged, and never quietly narrowed. `cargo buildclamp explain <crate>` says which layer
produced each answer and which layer bounded it.

The full rules, the three other refusals, and what stays the nearest layer's alone are in
the [configuration reference](CONFIG.md#layer).

**The mechanism is free and it always will be.** A proprietary policy dialect forks the
tool. What is worth selling is authorship and distribution — writing the org layer, keeping
it current, getting it onto forty machines — and none of that is the resolution algorithm.

**Not measured yet.** Whether one central policy actually *applies* across a real forty-repo
estate, or whether every repository ends up with bespoke grants anyway, is the experiment
this feature stands or falls on, and it has not been run. If a human still faces thousands
of grants after `--accept-baseline`, the review workflow is theatre. The mechanism ships
because a customer with a hand-written org policy in git should not have to wait for that
answer; the claim that it *scales* does not ship, because nothing here has earned it.

## Two hardening options, and why both are off

`withhold-secret-reads` makes named credential paths unreadable; `env-allowlist` gives a
unit only a base set of environment variables plus what its grant names, instead of
everything minus a deny-list. Both are stronger than the default, and both are opt-in.

That is a decision with a date on it rather than caution. Each would break builds that pass
today, for people who changed nothing, and a security tool whose upgrade breaks your build
is one you pin and stop upgrading. The break rate gets measured on real graphs and making
either the default is a separate decision with a named release and a number behind it.

Turn them on deliberately, on a branch, and read the diff `observe` produces.

## Reviewing a policy somebody else wrote

Four questions, in this order:

1. **Which grants have `reviewed = false`?** Those are observations, not approvals, whatever
   their `why` says.
2. **Which have `capabilities` containing `net` or `env-secret`, or `write-zones` containing
   `target` or `manifest-dir`?** Those are the four that matter; everything else is a build
   script doing its job.
3. **Is there an `[[exception]]`?** It is time-boxed and it expires by itself, but it means
   somebody shipped past a refusal. `git log -p buildclamp.toml` says who and when.
4. **Is there a `[baseline]`?** Then some `reviewed = true` was set by a document rather
   than a person, and the digest says which document. Fetch it and check.

`cargo buildclamp explain <crate>` answers the first question for one crate, from the policy
as it stands, including a live exception widening it.
