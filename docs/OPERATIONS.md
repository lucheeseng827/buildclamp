# Operations

How to run buildclamp in a pipeline, what it does to a machine, and what to do when it
tells you something you did not expect.

buildclamp is not a service. It listens on nothing, opens no port, and holds no state
between runs beyond a report and a policy file, both of which live in the repository or
the target directory. That removes most of an operations runbook and leaves three things
that genuinely matter: how it lands in CI, what it costs, and what a failure means.

## Landing it in a pipeline

Adopt in the order the commands were designed in. A default-deny policy that breaks
common crates on its first run is dead on arrival, so nothing is enforced until a human
has read a generated policy.

```console
$ cargo buildclamp observe          # refuses nothing; records everything
$ cargo buildclamp init             # writes buildclamp.toml, every grant reviewed = false
$ $EDITOR buildclamp.toml           # replace each generated `why` with a real one
$ cargo buildclamp check            # enforce it
```

Three stages, each of which is a reasonable place to stop for a while:

| stage | command | what a red build means |
|---|---|---|
| watching | `cargo buildclamp observe --gate` | a build unit asked for something it would not have got. Nothing was refused |
| enforcing | `cargo buildclamp check --strict` | either a unit asked for something ungranted, or a grant is still unread |
| attesting | add `--require-enforced` | the above, or the host could only manage an advisory tier |

`--strict` is the flag that stops `init`'s output from quietly becoming permanent. Every
grant it writes carries `reviewed = false` and a `why` that says it is an observation with
a date. `--strict` refuses to pass while any of them are still unread, so the review is
work somebody does rather than work that gets skipped.

A caveat worth knowing before you rely on it: cargo re-runs a build script only when its
inputs are dirty, so a second `--strict` run in the same target directory may execute no
build units at all. The unreviewed-grant count is therefore read from the **policy file**,
not from the units that happened to run, and a run where nothing rebuilt says so in its
report rather than passing silently.

## What it costs

Measured on this project's own host, against its own fixtures:

| measurement | value |
|---|---|
| per held build unit | 2.5 ms |
| hooked build, wall clock | 4.86 s |
| unhooked build, wall clock | 5.06 s |
| per notified syscall, `--deep` | 10 to 40 µs |

The two build numbers are within run-to-run noise of each other, which is the honest way
to state it: on this workload buildclamp's cost is not measurable against cargo's own
variance. That will not hold for a build with thousands of build scripts, and it says
nothing about a machine under different load. Measure your own.

`--deep` is the exception and the reason it is off by default. It notifies on every write
a compile unit makes, and rustc opens thousands of files.

## Capacity and state

| question | answer |
|---|---|
| what is the state? | `buildclamp.toml` in the repository, and `<target>/buildclamp/` in the target directory |
| what should be backed up? | the policy, which is in git already. The target directory is disposable |
| what should be alerted on? | exit code 2 from a pipeline that previously exited 0 |
| what grows? | one run directory per invocation under `<target>/buildclamp/`; removed with the target directory |
| how many processes? | one supervisor thread per held unit, alive only for that unit |

There is no daemon to restart, no database to migrate, and no upgrade path to plan: the
tool is a binary invoked by cargo and the report format carries a version so an older
reader refuses a newer file rather than misreading it.

## Security posture

Distinct from `SECURITY.md`, which is the disclosure policy. This is what the tool does to
the machine it runs on.

**What it opens.** Nothing. No socket is created, no port is bound, and there is no HTTP
client in this tool. CI greps for one, because a tool that denies build scripts the
network must not itself be able to reach it, and a reader must be able to establish
that from `cargo tree` rather than from a promise.

**What privilege it needs.** None beyond an ordinary user. It uses unprivileged user
namespaces, seccomp-BPF and Landlock, all of which are available to a normal user on a
kernel that has them. It never asks for root, and it drops capabilities in the child
before the build script runs rather than after.

**What it can read.** The policy, the target directory, and the environment of the process
cargo started it from. It writes the report, the run records and the shims, all under the
target directory.

**What is deliberately out of scope.** Four things, stated because a security tool's
silence about a limit reads as a claim:

- **Destination allowlists are reported, never enforced.** Enforcing one needs a resolving
  proxy. A tool that appears to enforce a destination list while a build script can
  resolve a name itself is worse than one that admits it does not.
- **Environment scrubbing controls exposure, not access.** There is no syscall for
  `getenv`. Only a user namespace closes the hole of a unit reading a sibling process's
  environment, and the report says whether one applied.
- **A kernel escape is out of scope.** It is a bug in the kernel. A tier this tool reports
  as `enforced` that is not enforced is a bug in this tool, and the more serious of the
  two, because it is the one that makes somebody stop looking.
- **The compiler is not held by default.** Build scripts are; a compile unit — where
  proc-macros expand — is held only when `hold-compile-units` is enabled, because holding
  every rustc in the graph is a cost a lane opts into rather than one it pays by default.

## Turning it off in a hurry

buildclamp runs inside every build in your pipeline. Before you adopt a thing like that
you are entitled to know how to remove it at three in the morning without a pull request,
so that is documented here rather than left to be discovered.

**The switch.**

```console
$ BUILDCLAMP_MODE=off cargo buildclamp build
```

Every build unit runs exactly as it would if buildclamp were not installed: no envelope,
no environment scrub, no namespaces. All three roles the binary takes — driver, wrapper
and launcher — honour it independently, so it works from wherever you can set it, and it
is checked before the policy file is read. If the policy is what broke, the exit does not
depend on parsing it.

The same switch travels with a policy, for an organisation-wide off that needs no change
to two hundred repositories:

```toml
version = 1
enforcement = "disabled"
```

**It is not silent, and that is deliberate.** A run with enforcement off still writes a
report, the report names the switch and its value in `disable_overrides`, and the terminal
says so above the counts:

```
buildclamp 0.1.0 — off mode

  !! ENFORCEMENT WAS SWITCHED OFF: BUILDCLAMP_MODE = off
     all enforcement; every build unit ran unheld
     This was somebody's decision, not a limit of this machine.
```

An emergency exit that leaves no trace is indistinguishable from a tool that was never
installed, and six months later nobody can tell which builds were held. This is also why
`BUILDCLAMP_DISABLE` — which removes one mechanism rather than all of them — is recorded
the same way even though the run stays in enforce mode: the remaining mechanism still
reports `enforced:`, so nothing else in the report would show that somebody had reached in
and weakened it.

A signed attestation over such a run **cannot claim full enforcement**. The override
vetoes the claim before the tiers are consulted, because the tiers describe what the
mechanisms that ran achieved and cannot describe one that was switched off.

**Who can reach each switch, which is the part worth thinking about.**

| switch | who can set it | recorded as |
|---|---|---|
| `BUILDCLAMP_MODE=off` | anyone with control of the CI environment | `BUILDCLAMP_MODE` |
| `enforcement = "disabled"` | anyone who can commit to `buildclamp.toml` | `buildclamp.toml` |
| `BUILDCLAMP_DISABLE=ns,notify` | anyone with control of the CI environment | `BUILDCLAMP_DISABLE` |

The environment switches are reachable by a **larger** set of people than the policy one.
That is not a reason to remove them — an emergency exit that needs a merged pull request
is not an emergency exit — but it is a reason the report names which one was used.

## Rolling back to the previous release

The switch above stops enforcement. This removes the version.

1. **Pin the previous release.** Every release stays installable; a yank marks a version
   as not-to-be-newly-depended-on and does not remove it. So the rollback is one line:

   ```console
   $ cargo install cargo-buildclamp --version <N-1> --locked
   ```

   In CI, pin the version in the install step rather than tracking latest. A pipeline that
   installs the newest release on every run cannot be rolled back without a commit, which
   is the same problem the kill switch exists to avoid.

2. **Confirm what you got**, because the point of rolling back is to change behaviour:

   ```console
   $ cargo buildclamp --version
   $ cargo buildclamp doctor --json
   ```

3. **If the policy is the problem rather than the binary**, roll that back instead —
   `buildclamp.toml` is a file in your repository with your own history on it, and
   reverting it is an ordinary revert.

4. **Report it.** A rollback is the most useful bug report this project can receive: it
   means something got past the fixture gates. `SECURITY.md` has the route for anything
   that looks like an enforcement hole; ordinary breakage is an issue.

**What is not promised.** A report written by a newer buildclamp is refused by an older
one, by version and by name — see `Report::from_json`. Rolling the binary back therefore
also rolls back what can read the reports already in your artefact store. That is the
deliberate behaviour rather than an oversight: the alternative is an old reader silently
parsing what it recognises out of a newer document.

## Troubleshooting

Written from the failure you see, not from the subsystem that produced it.

### `the build script for \`X\` asked to open a network socket and the policy does not grant it`

The tool worked and the answer was no. The message names the crate, the syscall, the
destination and the grant that would allow it. Three things to do, in order:

1. Run `cargo buildclamp explain X` and read the whole envelope, including which rule
   produced it.
2. Decide whether the crate should be doing that. A crate fetching a binary at build time
   is a real and common thing; so is a crate that started doing it in the version you just
   picked up.
3. If it should, add the grant the message prints, and replace the `why` with a sentence a
   colleague will read in the pull request.

Exit code 2, not 1. Your pipeline should tell them apart.

### A crate that everyone depends on was refused, and you want to know if it is you

Start here, because the answer is usually "no grant is needed at all".

**Measured on 2026-09-15**, Linux 6.18, Landlock ABI 7, `cargo buildclamp observe --deep`
over a graph containing each of these, with the tool's own tier at `enforced` for every
capability:

| crate | version | what its build script did | grant needed |
|---|---|---|---|
| `libc` | 0.2.189 | spawned the compiler to probe the target | **none** |
| `cc` (via `libz-sys`) | 1.1.29 | compiled C, wrote objects to `OUT_DIR` and `TMPDIR` | **none** |
| `pkg-config` (via `openssl-sys`) | 0.9.117 | ran `pkg-config`, read its output | **none** |
| `openssl-sys` + `vendored` | 0.9.117 | compiled **all of OpenSSL** from source: 32,762 file operations, perl and make | **none** |
| `bindgen` | 0.71.1 | loaded libclang, generated Rust into `OUT_DIR` | **none** |
| `ring` | 0.17.14 | assembled and compiled its own primitives | **none** |
| `zstd-sys` | 2.1.0 | compiled zstd | **none** |
| `lz4-sys` | 1.11.1 | compiled lz4 | **none** |
| `brotli-sys` | 0.3.2 | compiled brotli | **none** |
| `blake3` | 1.8.7 | compiled its SIMD kernels | **none** |
| `proc-macro2` | 1.0.107 | probed the compiler for an unstable API, then deleted what it wrote | **none** |
| `quote`, `prettyplease`, `clang-sys` | | compiler probes | **none** |

Fourteen crates, zero grants, and `cargo buildclamp init` writes an empty `[grants]` table
for that whole graph. If your first `init` produces a long file, the interesting question is
which crates are in it — not whether the defaults are too tight.

**Not measured, and named rather than guessed at:** `prost-build`, which needs `protoc` and
was not installed on the machine this was run on. The 200-crate compatibility sweep the plan
calls for has not been run, so this table is fourteen crates chosen because they are the
common offenders, not a sample of anything.

If one of these *is* refused on your machine, the difference is the host rather than the
crate. Run `cargo buildclamp doctor` and compare with [the matrix](MATRIX.md).

### The three shapes that do need a grant

The refusal message already prints the grant to add, so this is the reasoning rather than
the syntax. [Policy authoring](POLICY.md#the-four-things-a-crate-can-need) has the syntax.

**It reaches the network.** Vendored `-sys` crates that download a tarball rather than
vendoring it, and anything with a `download` or `fetch` feature. Add `net` and write the
destinations down — they are reported and never enforced, and the report records what was
actually reached, so a difference between the two is a finding.

**It writes outside `OUT_DIR`.** Code generators configured to write into `src/`
(`prost-build` with `out_dir` set that way is the common one), and anything that caches into
the target directory. Add the zone. `target` is the one to think about twice: a build script
that can write into `target/*/deps` can drop a replacement shared object for a proc-macro
another crate is about to load.

**It reads a credential-shaped environment variable.** Usually a crate that wants
`*_TOKEN`, `*_KEY` or a registry credential at build time. Add it to `env-allow`, and for a
hard-denied name the parser additionally demands `env-allow-secrets = true` so the choice is
in the diff.

### `--require-enforced` fails and the build looked fine

The host could not enforce something and buildclamp will not report a tier it did not
achieve. Run `doctor`:

```console
$ cargo buildclamp doctor
host: linux 6.18.44-fc-v22 on x86_64

what this machine can enforce:
  landlock (filesystem)        no   absent — the filesystem falls back to a mount namespace
  user namespaces              yes  read-only root and a private network are enforceable
  seccomp notification         yes  requests can be observed and answered
  /proc hides other processes  no   a unit could read secrets from another process of the same user, unless a user namespace applies
```

`no` on user namespaces is the common one. Some distributions disable unprivileged user
namespaces outright, and several container runtimes forbid them under their default
seccomp profile. Docker needs `--security-opt seccomp=unconfined` or a profile that permits
`unshare` and `clone` with the namespace flags; a GitHub Actions ubuntu runner has them.

`no` on both Landlock and user namespaces means this host can observe but not enforce.
buildclamp says so rather than passing, which is the entire point of the flag.

### The tool seems to do nothing

Its presence is switched by an environment variable the driver sets, so a wrapper invoked
outside a `cargo buildclamp` run passes straight through by design. Check that you ran a
buildclamp subcommand and not a bare `cargo build` in a shell that still has a stale
`RUSTC_WRAPPER` exported.

The other cause is cargo not rebuilding. Changing the wrapper changes every fingerprint,
so the first run after adopting the tool rebuilds everything; a later run may execute no
build units at all because none are dirty. The report says "no build units ran" rather
than reporting a clean run, and `--strict` still reads the policy file.

### A held build script fails with an error that is not about buildclamp

Cargo captures a build script's stderr and prints it only when the unit fails, so a
refusal and an ordinary build-script bug arrive through the same channel and look similar.
If the output has no `buildclamp:` line, the script failed on its own terms. Run the build
without the tool to confirm, then look at the script.

### A crate that worked yesterday is now refused

That is the tool doing its job, and the interesting question is which side changed. Compare
the report to the last one: `cargo buildclamp report --all` prints every unit and its
envelope, not only the ones with ungranted requests. A new capability in a version you did
not choose to change is what a drift feed over these reports exists to notice earlier
than you can.

### It is 17:00, a dependency bump went red, and the release has to go

There is an unblock path, it is in the free tool, and it needs no account, no network and
no server. It is also not quiet: every use is a block in a committed file that names
somebody, carries a reason and stops working by itself.

```console
$ cargo buildclamp except openssl-sys --reason "release blocked; INFRA-4412 tracks pinning the vendored source"
buildclamp: narrowing this exception to net — what `openssl-sys` was actually refused in
            the last run. Pass --capability to override.
buildclamp: `openssl-sys` is excused until 2026-09-16 — appended to buildclamp.toml.

  Commit it: the diff is what makes this visible, and it is the only thing that does.
  It stops applying on 2026-09-17, with no edit and no reminder.
```

The block it writes is an ordinary part of the policy format, so you can write one by hand
too:

```toml
[[exception]]
crate = "openssl-sys"
capabilities = ["net"]      # omit to cover whatever that crate asks for
expires = "2026-09-16"      # MANDATORY, and at most 7 days from the day the build runs
reason = "release blocked; INFRA-4412 tracks pinning the vendored source"
author = "ada@example.com"  # MANDATORY; `except` fills it in from your git identity
```

**What it does.** It grants the named capabilities to that crate until the date, and it
stands the run's verdict down for it. `cargo buildclamp explain <crate>` shows the widened
envelope and names the block behind it.

**What it does not do.** It does not widen `write-zones`. A write outside them is still
refused by the kernel, and only the verdict stands down — an exception that could grant
"write anywhere" would be an off switch wearing the word `exception`, and there is already
an honest way to say that (`enforcement = "disabled"`, recorded in the report as an
operator override). `crate = "*"` is refused for the same reason. Nor does it suppress
`--require-enforced`: that asks whether this *host* could hold a capability, and a block
naming a crate has nothing to say about a machine.

**The bounds, and how to get past each one.**

| bound | default | how to change it |
|---|---|---|
| how long one may run | 7 days, hard | not configurable — shorten the date, or review the grant |
| `--days` | 1 | `--days N`, up to 7 |
| how many may be live | 3 | `max-active-exceptions` in `[defaults]`; `0` forbids break-glass here entirely |

The seven-day ceiling is measured against **today**, not against the day the block was
written, so an exception cannot be backdated into a long one and cannot outlive its week by
being committed early. A lapsed block is not an error — the build simply goes red again for
the reason it went red originally — and the summary names it by date, so nobody writes the
same block twice wondering why the first stopped working.

### `--strict` is refusing two hundred grants on the first day

Two answers, and they compose.

**`--grace <days>`** makes a grant that `init` first wrote within the last N days warn
rather than fail, so the ordinary flow — bump, red build, `init`, commit, ticket — is not
also blocked on the review happening the same afternoon.

```console
$ cargo buildclamp build --strict --grace 14
  --grace: 1 grant(s) are new enough to warn rather than fail
      openssl-sys first seen 2026-09-15, 14 more run(s) before it fails
```

It measures from the grant's `first-seen`, which `init` writes and nothing else touches. A
grant carrying no `first-seen` — every policy written before the field existed, and every
grant added by hand — is **never** in grace, which is what stops `--grace 3650` on a
year-old policy excusing anything.

**`--accept-baseline <file>`** marks grants reviewed where a published document vouches for
that exact crate version.

```console
$ cargo buildclamp init --accept-baseline baseline.toml
buildclamp: wrote buildclamp.toml with 213 grant(s).

  accepted from the baseline   198
  still unreviewed             15
      some-vendored-sys 0.9.4
      …
```

The residual is the point. A baseline that covers everything in your graph is making a very
strong claim and is worth looking at twice; the fifteen left over are a list somebody can
read in an afternoon. `examples/baseline.toml` is the format, with its own note that the
entries in it are illustrative — a baseline whose author has not read those build scripts
at those releases is worth nothing.

Three rules keep an acceptance from being a rubber stamp: it matches the **exact** version
and pins the grant it writes to it, so a patch bump comes back for review rather than
inheriting an approval nobody made; it only narrows, so a crate that did something the
document does not describe stays unreviewed; and it records the document's SHA-256 in
`buildclamp.toml` as the reviewer of record. That digest answers "which document?", not
"who may say?" — anyone who can write `reviewed = true` can write a digest beside it.

**Not measured yet.** How many grants remain unreviewed after `--accept-baseline` on a real
estate is a number this project intends to publish and has not. Until it does, the residual
your own run prints is the only evidence there is about it.

### The target directory has buildclamp shims in it and you want them gone

```console
$ cargo buildclamp unhook
buildclamp: restored 3 build script(s) in /path/to/target
```

Rarely necessary — changing the wrapper already changes every fingerprint — but a tool
that can only be added is one people are reluctant to try.

### A report will not parse

A corrupt run record is a hard error rather than a skipped unit, deliberately: a report
missing a unit reads as a build where that unit asked for nothing, which is the most
dangerous possible way for this tool to fail. Delete `<target>/buildclamp/` and re-run.

## Testing the fallback tiers

The advisory and refuse-rather-than-run paths need to be exercisable on a host that has
everything, otherwise they are only ever exercised by a user on a machine that happened to
lack the mechanism.

```console
$ BUILDCLAMP_DISABLE=ns cargo buildclamp check       # no namespaces
$ BUILDCLAMP_DISABLE=notify cargo buildclamp check   # no seccomp notification
$ BUILDCLAMP_DISABLE=ns,notify cargo buildclamp check
```

It can only take capability away, never add it. A build that sets it gets less enforcement
and a report that says so.
