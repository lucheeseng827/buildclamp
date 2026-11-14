<img src="site/logo.svg" alt="" width="72" height="72">

# buildclamp

**Every `build.rs` runs inside a capability envelope you declared. The ones that behave
never notice.**

> **Proc-macros too, with `hold-compile-units = true`.** Expansion happens inside the
> rustc compiling the *consumer*, so holding it means holding every compile in the graph —
> which is why it is opt-in and why the headline above still says `build.rs`. This block
> used to say proc-macros were not held at all, and before that the headline claimed them
> without holding them. See [`CLAIMS.toml`](CLAIMS.toml), where every present-tense claim
> in this repository names the test that makes it true.
>
> One shared policy per compilation, not per macro: a refusal names the compilation and
> the macros that could have been responsible. `cargo-acl` gives the same answer and says
> so. [`docs/adr/0004`](docs/adr/0004-proc-macro-attribution.md) argues why it is worth
> shipping anyway.

`cargo build` executes third-party code before a single line of the dependency's library
code runs, with your full ambient privilege — your SSH agent, your cloud credentials, the
CI secrets that runtime code never touches. There is no control surface over what that
code may do. buildclamp is one.

```console
$ cargo buildclamp build
   Compiling proc-macro1 v1.0.107
error: failed to run custom build command for `proc-macro1 v1.0.107`

  buildclamp: the build script for `proc-macro1@1.0.107` asked to reach the network
              and the policy does not grant it.
    it tried to: connect 23.254.165.112:9089
    its envelope: fs-write, unix, exec (from the defaults (no grant matched))
    and 2 further ungranted request(s)
    to allow it, add a grant with a reason:
        [grants."proc-macro1"]
        capabilities = ["net", "unix", "fs-write", "exec"]
        why = "..."
      or run `cargo buildclamp explain proc-macro1` to see the whole envelope.
```

One static binary. One TOML file. Linux.

---

## Start here, not with enforcement

First, get the binary on your path. Linux only, and `cargo buildclamp` is how cargo finds
it once it is there:

```console
$ cargo install --path crates/cli        # or --git, once there is a release
$ cargo buildclamp doctor                # what this host can actually enforce
host: linux 6.18.44-fc-v22 on x86_64

what this machine can enforce:
  landlock (filesystem)        no   absent — the filesystem falls back to a mount namespace
  user namespaces              yes  read-only root and a private network are enforceable
  seccomp notification         yes  requests can be observed and answered
  /proc hides other processes  no   a unit could read secrets from another process of the same user, unless a user namespace applies
```

Run `doctor` before trusting a green build. That output is this project's own CI host, and
it is missing two of the four mechanisms — which is exactly why every tier is reported
rather than assumed.

A default-deny policy that breaks common crates on the first run gets uninstalled the
same afternoon. So the first command records and refuses nothing, and enforcement is
third:

```console
$ cargo buildclamp observe        # runs your build, denies nothing, records everything
$ cargo buildclamp init           # writes buildclamp.toml from what it saw
$ cargo buildclamp build          # now enforce it
```

`observe` on a repository whose build scripts stay inside the defaults says so and exits
zero:

```console
$ cargo buildclamp observe
   Compiling benign v0.1.0 (/…/tests/fixtures/benign)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.30s
buildclamp 0.1.0 — observe mode
  build units held           1
  ungranted requests         0

  nothing asked for more than its envelope.
  report: /…/target/buildclamp/report.json
```

On one that does not, it names every request without refusing any of them. Every tier
reads `none` because observe mode enforces nothing — the point is to learn what your build
does on the machine you actually have, not on a sandboxed approximation of it:

```console
$ cargo buildclamp observe
   Compiling evil v0.1.3 (/…/tests/fixtures/evil)
buildclamp 0.1.0 — observe mode
  build units held           1
  ungranted requests         4

  evil@0.1.3 [build-script-compile]
      net          none
      unix         none
      fs-write     none
      env-secret   none
      exec         none
    x net        socket AF_INET socket
    x net        connect 127.0.0.1:9
    x fs-write   mkdir /root/.config/autostart
    x fs-write   openat /root/.config/autostart/evil.desktop
      fs-write   openat /…/build/evil-a1bfa4cb97cc38ec/out/generated.rs
      exec       execve /bin/sh
      exec       execve /usr/bin/id
```

An `x` marks a request the envelope did not cover. The two unmarked `fs-write` and `exec`
lines are the same build script writing its `OUT_DIR` and shelling out, which the defaults
already allow — the tool has to be able to tell those apart or nobody will read its output
twice.

`init` writes a grant for every crate that needed more than the defaults, marks each one
`reviewed = false`, and puts the observation and its date in the `why`:

```toml
[grants."openssl-sys"]
version = ">=0.9, <0.10"
capabilities = ["exec", "fs-write", "unix"]
write-zones = ["out-dir", "tmp"]
why = "OBSERVED 2026-09-01: used more than the defaults. Written by `cargo buildclamp init` from a recorded run — replace this with the reason the crate needs it, then set reviewed = true."
reviewed = false
```

Replacing those with real reasons is the work. `cargo buildclamp build --strict` refuses
to pass while any grant is still unread, which is how a generated file stops quietly
becoming permanent. **A project with fifty grants is a correctly configured project**, not
a compromised one.

## What the defaults are

These are the envelopes the policy model resolves. The build-script column is what the tool
enforces by default. The compilation column is held only when `hold-compile-units` is
enabled — off by default, because it wraps every rustc in the graph and rustc opens
thousands of files, so it changes what a build costs rather than adding to it. With it off, a
compile unit runs unheld and is absent from the report; with it on, the column is what the
policy enforces — one shared policy per compilation, not per macro (see `docs/adr/0004`).

| | build script | compilation (where proc-macros run) |
|---|---|---|
| | **enforced by default** | **enforced under `hold-compile-units`** |
| network | **denied** | denied *(when `hold-compile-units` is on)* |
| filesystem writes | `OUT_DIR` and a private temp dir | the target directory and a private temp dir |
| environment | credential-shaped names withheld | credential-shaped names withheld |
| running other programs | allowed, and recorded | allowed, and recorded |

Two of those deserve their reasoning in the open.

**`exec` is allowed by default** because `cc`, `pkg-config`, `protoc` and `git` are the
ordinary business of build scripts, and denying them would break most real dependency
graphs on the first run. It also buys less than it looks like: every child inherits the
namespaces and the seccomp filter, so a spawned `curl` is held exactly as tightly as the
script that spawned it.

**A build script does not get the target directory, and a compilation does.** rustc
legitimately writes all over `target/`; a build script that could write into
`target/*/deps` could drop a replacement shared object for a proc-macro another crate is
about to load.

## The part most tools get wrong: which tier actually applied

Landlock is absent on some kernels. User namespaces are blocked on some distributions and
inside some container runtimes. Decisions made from a seccomp notification are racy by
construction — the kernel re-reads the argument after the supervisor answers.

So buildclamp reports, per capability per unit, **how** it was constrained:

```console
$ cargo buildclamp doctor
host: linux 6.18.44 on x86_64

what this machine can enforce:
  landlock (filesystem)        no   absent — the filesystem falls back to a mount namespace
  user namespaces              yes  read-only root and a private network are enforceable
  seccomp notification         yes  requests can be observed and answered
  /proc hides other processes  no   a unit could read secrets from another process of the
                                    same user, unless a user namespace applies
```

`enforced:netns` means the kernel refuses it. `advisory:seccomp-notify` means buildclamp
saw it and answered, and a determined script could have changed the argument in between.
`--require-enforced` fails a run where any capability was only advisory, because a green
build on a machine that could not enforce anything is the false assurance this whole
category has been criticised for, correctly.

Which tier you actually get depends on the host, so it is published rather than described:
[docs/MATRIX.md](docs/MATRIX.md) has the rows that have been measured, the rows that have
not — said as such rather than reasoned about — and the generator, so you can produce your
own in one command:

```console
$ ops/matrix-row.sh --label "GKE 1.31 default node image"
```

If your row disagrees with ours, your row is the true one. A container reporting `none` is
usually the runtime's default seccomp profile refusing syscalls it predates rather than a
property of the kernel underneath, and the same document has the fix — including why
Landlock reports *absent on a kernel that has it* under a profile whose default action is
`SCMP_ACT_ERRNO`.

## What this does not do

- **Linux only.** macOS and Windows get nothing in v0. Not "coming soon" — not started.
- **It does not stop a malicious dependency at runtime.** This is build-time code only.
- **Reads are unrestricted by default, and restricted by a deny-list when you ask.** Out
  of the box a build script can read `~/.aws/credentials`. It cannot send them anywhere or
  write them outside `OUT_DIR`, but it can stage them into `OUT_DIR`, and `OUT_DIR` is
  `include!`d into your binary by design — so the read is the whole attack.
  `withhold-secret-reads = true` closes the named credential paths (see
  [Withholding credential reads](#withholding-credential-reads)), and three things about it
  have to be said in the same breath as the feature: it is **opt-in**, it is a
  **deny-list** and therefore weaker than an allow-list, and it needs **Landlock** — on a
  host without it the tier says `none` and nothing is withheld.
- **Withholding secrets from a unit is not the same as hiding them.** Without a user
  namespace, a build script can read `/proc/<pid>/environ` of any process you own,
  including cargo's. The user namespace and not the PID one: unshared on its own,
  `CLONE_NEWPID` leaves that read returning the full environment. A fixture in this repository reads 7,883 bytes of its parent's
  environment and finds both planted credentials. The namespace tier closes this; the
  environment scrub alone only narrows it, and `doctor` tells you which you have.
- **`net-destinations` in a grant is recorded, never enforced.** Enforcing a destination
  list needs a proxy or firewall rules inside the network namespace. Shipping an advisory
  field that reads as enforcement is the exact trap this tool exists to avoid, so it says
  so wherever it appears.
- **Circumvention is possible.** A proc-macro can detect that it is being held and emit
  different code. buildclamp narrows what build-time code can reach; it does not make
  running untrusted code safe.
- **Attribution inside one compilation is best-effort.** See below.

## Withholding credential reads

Off by default. Turn it on in `buildclamp.toml`:

```toml
[defaults]
withhold-secret-reads = true
```

A build script then cannot read `~/.aws`, `~/.ssh`, `~/.gnupg`, `~/.config/gcloud`,
`~/.config/gh`, `~/.cargo/credentials.toml`, `~/.netrc`, `~/.kube`,
`~/.docker/config.json`, browser profiles, `~/.password-store` and a handful more — the
full list is `crates/core/src/withhold.rs`, which is short enough to read and is meant to
be read. A crate that genuinely needs one asks for `fs-read` in its grant, with a reason,
like any other capability.

Measured on the fixture in `tests/fixtures/credreader`, which reads four credential paths
and stages them into `OUT_DIR`:

| | with it off | with it on |
|---|---|---|
| credential files read | 4 of 4 | **0 of 4** |
| `~/.ssh` listable | yes | **no** |
| bytes reaching `OUT_DIR` | 230 | **0** |
| `fs-read` tier | `none` (nothing withheld) | `enforced:landlock-v7` |

### Three things that must be said in the same breath

**It is a deny-list, and a deny-list is weaker than an allow-list.** Every path not named
stays readable: shell history, editor state, your repository's own `.env`, the source tree,
and any credential a tool keeps somewhere the list does not know about. An allow-list is
the stronger design and is not available here — a build script legitimately reads the
sysroot, the registry, `/usr`, system headers and a long tail nobody can enumerate, so
default-denying reads and granting back would break every real graph on the first run.

**It needs Landlock.** A mount namespace cannot express a read restriction, and seccomp
could only do it advisorily at 10–40 µs on every file rustc opens — thousands per build,
for a tier that is defeatable by construction. So on a host without Landlock the tier is
`none` with that reason, and `--require-enforced` fails the run rather than passing it.

**A withheld read leaves no trace in the report.** Landlock refuses in the kernel with no
supervisor in the loop, which is what makes it enforcement rather than observation — and
it means the report can say the tier that applied but cannot say *which crate reached for
your keys*. The build script sees `EACCES` and the report shows `enforced:landlock-vN`.
`observe` mode cannot show you what turning this on would break, either: observe enforces
nothing, so there is nothing to observe. The way to find out is to turn it on.

## In GitHub Actions

```yaml
- uses: lucheeseng827/buildclamp@v0
  with:
    command: check
    require-tier: enforced          # fail as a misconfigured lane, before the build
    require-enforced: true          # fail a build that could only be advisory
```

**Free and unlimited on public repositories, permanently.** There is no key to obtain, no
account to create and no quota to reach. That is written in `action.yml` rather than on a
page elsewhere, because a file in the repository is harder to quietly edit.

The action does three things in order, and the order is the point:

1. **prints what the runner can enforce**, on every run, because a green build on a runner
   that enforced nothing is the failure this tool exists to prevent and the log is where
   somebody finds out;
2. **checks the floor you declared** with `require-tier`, in seconds, before the build —
   a runner image change that removes user namespaces leaves every other gate green;
3. **holds the build**, then writes a markdown summary to the job summary **whether the
   build passed or failed**. A reviewer looking at a red job is the one who most needs the
   per-unit detail, and a step that died before writing it would leave an exit code and
   nothing else.

The summary is **bounded and says so**. A first `init` on a real estate produces a couple
of hundred findings and GitHub surfaces roughly ten annotations out of about fifty, so a
summary that tried to list everything would be cut off by the platform wherever it happened
to reach. It lists at most twenty units, prints how many it left out, and links to the
report — truncation that announces itself is a summary; truncation that does not is the
lie by omission this project keeps naming.

## Two hardening options, both opt-in

| option | what it changes | needs |
|---|---|---|
| `withhold-secret-reads` | named credential paths become unreadable (above) | Landlock |
| `env-allowlist` | a unit gets only a base set plus what its grant names, instead of everything minus the deny-list | nothing |

`env-allowlist` is the stronger of the two environment models and the one `cargo-acl`
has: a deny-list cannot know about a credential variable nobody has thought of, and an
allowlist does not have to. The two **combine** — the deny-list still runs first, so the
allowlist can only take further names away and never hand one back. Details and the base
set are in [docs/CONFIG.md](docs/CONFIG.md#env-allowlist-the-stronger-of-the-two-environment-models).

Both are off by default. That is a decision with a reason rather than caution: each would
break builds that pass today, for people who changed nothing, and a security tool whose
upgrade breaks your build is one you pin and stop upgrading.

## When it blocks you at 17:00

A gate that can only block is one people unhook, so this one can also unblock, and the
unblock path is free, offline and needs nobody's approval:

```console
$ cargo buildclamp except openssl-sys --reason "release blocked; INFRA-4412 tracks the real grant"
buildclamp: `openssl-sys` is excused until 2026-09-16 — appended to buildclamp.toml.
```

It writes an `[[exception]]` block: one crate, a mandatory reason, an author from your git
identity, and a mandatory expiry **capped at seven days from the day the build runs** — so
it cannot be backdated into a long one and it stops working with nobody having to remember.
At most three may be live at once. Every run with a block in the policy says so, loudly,
with what it was used for and what is still owed.

It widens capabilities and **not** `write-zones`: a write outside them is still refused by
the kernel. There is no exception that never expires and no `crate = "*"`, because there is
already an honest way to turn enforcement off (`enforcement = "disabled"`, recorded in the
report as an operator override) and an escape hatch spellable two ways — one of which reads
narrow and behaves global — is how a control ends up off in a repository where everyone
believes it is on.

Two more, for the first day rather than the bad evening:

* `--grace <days>` — a grant `init` first wrote within the window warns instead of failing
  `--strict`. A grant with no `first-seen` is never in grace, so this cannot become a way
  to never review anything.
* `init --accept-baseline <file>` — marks grants reviewed where a published document
  vouches for that *exact* version, pins each accepted grant to it, and records the
  document's SHA-256 in the policy as the reviewer of record. It prints how many grants are
  still unreviewed afterwards, which is the number that says whether a baseline is worth
  anything.

[docs/OPERATIONS.md](docs/OPERATIONS.md#troubleshooting) has the rest, including how to get
past each bound.

## Which invocation paths are covered

buildclamp intercepts a build by setting `RUSTC_WRAPPER`, so **it covers the builds you
route through it and no others.** That sentence is the whole of the coverage story, and
the table exists because "how much of my exposure does this actually close?" is a question
a buyer has to be able to answer before adopting it, and until now this repository did not
answer it anywhere.

Measured on Linux 6.18 with cargo 1.94.1 — the enforcement rows against
`tests/fixtures/evil`, and the routing rows below re-measured on 2026-09-15 against
`tests/fixtures/benign` by counting the unit records each invocation actually produced.
Where a row says **reasoned**, the verdict follows from the mechanism and has not been
run; those are marked individually rather than left to be assumed.

| how the build was started | covered | what happens |
|---|---|---|
| `cargo buildclamp build` / `check` / `test` | **yes, fully** | swept, held, reported |
| `cargo buildclamp bench` / `doc` | **yes, fully** | same path, same report. `doc` is the one that surprises people: building documentation compiles and runs every build script in the graph, so a pipeline that holds `build` and publishes docs from an unheld `cargo doc` has run the same third-party code twice and held it once |
| `cargo buildclamp install <crate>` | **yes**, with one stated gap | the only command here about somebody else's dependency graph rather than your own, and the one aimed at how both large 2026 Rust incidents actually reached a machine. Outside a workspace the report goes to a temporary directory and the run says where. **The gap:** measured, `cargo install --path <dir>` builds into `<dir>/target`, so installing a package already built there reuses it and no build script runs — the summary prints `no build units ran` for exactly that, rather than reporting a clean build. A registry install does not have the problem, which is the case that matters |
| `cargo buildclamp observe` | **yes** | held in observe mode: recorded, nothing refused |
| plain `cargo build` / `check` / `test` | **no** | no wrapper is set, nothing is intercepted, no report is written |
| `cargo buildclamp publish` | **yes**, and it is the one that costs something | the verification build cargo runs before uploading compiles the whole graph, so every build script runs and is held. It is also the only verb where cargo itself keeps a credential: `CARGO_REGISTRY_TOKEN` is in the default deny list by name, and dropping it would break the upload, so it survives into cargo's environment and nothing else does. Held units never receive it — each unit's environment is scrubbed separately — but where the environment tier is only `advisory:scrub`, a held build script can read it out of the publishing cargo's `/proc/<pid>/environ`. The run says so before cargo starts, and `--require-enforced` refuses to publish at all, checked **before** the upload because an upload cannot be taken back |
| `cargo buildclamp clippy` | **yes, fully** | linting compiles and runs build scripts exactly as `check` does, and lint jobs run on every pull request, including from a fork. It is the only verb with two wrappers in play: `cargo clippy` sets `RUSTC_WORKSPACE_WRAPPER=clippy-driver` and leaves `RUSTC_WRAPPER` to buildclamp, and the two reach different units. Measured from the wrapper position on cargo 1.94.1: a dependency's build-script compile arrives as `<buildclamp> rustc …` and the workspace's **own** as `<buildclamp> clippy-driver rustc …`, so deciding from the compiler's basename would have skipped the developer's own build script |
| `cargo run` | **partial, manual** | no buildclamp subcommand wraps these, but the mechanism is `RUSTC_WRAPPER` and it applies to any cargo verb. Setting `RUSTC_WRAPPER`, `BUILDCLAMP_POLICY`, `BUILDCLAMP_RUN` and `BUILDCLAMP_MODE` yourself **does** hold the units — measured on the verbs that have since become subcommands, one unit record each, and under `cargo install` the `evil` fixture was refused the network and the install produced no binary. What you do not get is the sweep or the report, so a build script compiled before buildclamp was involved is **not** held, and nothing aggregates the records. Typing it is refused rather than half-honoured: `cargo buildclamp run` answers `unrecognized subcommand`. It is also the one verb here that is arguably not this tool's business — `cargo run` compiles (which `build` already covers) and then executes **your** binary, which is not build-time code and is not what buildclamp holds |
| rust-analyzer and other IDE-driven builds | **no** | the editor runs its own cargo with its own environment. This is the gap that matters most: `cargo add` followed by the editor's next check runs a new dependency's build script on a developer's machine, with their credentials, before anyone has typed a build command. Setting the four variables in the editor's cargo environment closes it — that path is measured, under **partial, manual** above; that rust-analyzer offers a setting for doing so is **reasoned** from its documentation and has not been run here |
| a plain `cargo` build in a target directory buildclamp has already used | **no** | measured, and worth its own row because the opposite is easy to assume. A swept target directory still holds buildclamp's shims, and running the shim with `BUILDCLAMP_POLICY` unset executes the real build script unheld and exits 0 — the variable's presence **is** the switch, by design, so that a stray `RUSTC_WRAPPER` cannot mutate a target directory on an ordinary build. The consequence is that an editor sharing a target directory with your buildclamp builds is not covered by proximity to them |
| `docker build`, `cross` | **no, unless** the Dockerfile or image invokes `cargo buildclamp` | **reasoned**, not run: the build happens in a container that inherits neither your environment nor the binary, so nothing about a container image makes an ordinary `cargo build` inside it covered. `cross` is the same shape — it runs cargo in a container |
| Bazel, Buck2 | **no** | **reasoned**, not run: they drive rustc themselves rather than through cargo, so `RUSTC_WRAPPER` is never consulted. `rules_rust` runs a build script through its own rule, which is a separate integration and not a variant of this one |
| `sccache` exported as `RUSTC_WRAPPER` | **yes** | measured: the previous wrapper is chained through `BUILDCLAMP_INNER_WRAPPER` and ran 7 times under one `cargo buildclamp check`, with the unit still held. This row previously said "yes" for both ways of configuring sccache and carried no measurement; the measurement split it in two |
| `sccache` set in `.cargo/config.toml` | **no — it stops running** | measured: 0 inner invocations, where a plain `cargo check` with the same config ran it 7 times. Cargo lets `RUSTC_WRAPPER` be set two ways and the environment beats the config, so buildclamp taking that slot displaces a wrapper it never saw. The build still succeeds and is simply no longer cached, which is the worst shape a regression can have — it costs time, produces no error, and the tool that caused it is the last thing anyone suspects. **buildclamp now warns** and prints the one-line fix (export it), rather than resolving cargo's config hierarchy itself: getting that subtly wrong would run the *wrong* wrapper silently, which is worse than running none |
| a dependency built earlier by a plain `cargo build` | **yes** | the sweep swaps the already-compiled build script before cargo runs, so a unit cargo considers fresh is still held. There is an end-to-end test for exactly this |

**The honest summary for someone sizing their residual exposure.** buildclamp closes the
CI path and the deliberate local build. It does not close the editor, and the editor is
where a developer's dependency first executes. Both large 2026 Rust incidents were
credential theft from developer and CI machines, so a policy that only runs in CI is
covering the half that has fewer secrets on it. Nothing here is a reason not to use it;
it is the number to put next to it.

**What re-measuring this table changed.** Two rows were wrong in the same direction —
towards claiming more coverage than the tool had. `sccache` was one row saying "yes" with
no measurement behind it, and it is two rows now, because the more common way to configure
sccache is the way that silently stopped working. The row below it did not exist at all: a
target directory buildclamp has swept looks like it should stay covered and does not. Both
were found by running the thing rather than by reading the code that implements it, which
is the only method this table is allowed to use.

**And then five rows moved, which is the point of keeping the table.** `bench`, `doc`,
`install`, `publish` and `clippy` sat under "partial, manual" — covered in principle by a
mechanism that applies to any cargo verb, and in practice by nobody, because it took four
environment variables and knowing that it would work. They are subcommands now, and `run`
is all that is left there.

Three of them were worth the change for different reasons. `install` is the only one about
somebody else's dependency graph: every other row here concerns your own project, and
`cargo install` is where a crate nobody has read runs its build script on a developer's
machine. `publish` cost something to get right — it is the only verb where cargo has to
keep a credential, so covering it meant naming an exposure rather than closing one, and
answering `--require-enforced` before the upload instead of after. `clippy` is the one that
could have been covered wrongly without anyone noticing: two wrappers, two routes, and only
one of them the obvious case.

## Per-proc-macro attribution, and why it is hard

Proc-macros expand inside the rustc that compiles the *consumer*, so a sandbox around
rustc can only say "something in this compilation did it". Every existing tool stops
there — `cargo-acl`'s documentation says one grant covers every proc-macro in the build.

buildclamp tries harder and tells you how confident it is. At a notification it reads the
instruction pointer from `/proc/<tid>/syscall`, resolves it against `/proc/<tid>/maps`
and the inventory of proc-macro shared objects this build produced, and reports:

| confidence | what it means | status |
|---|---|---|
| `exact` | the instruction pointer was inside that proc-macro's shared object — the request is attributed to that macro by name | **demonstrated**: an executing test drives a proc-macro to a syscall from its own `.so` and the report names it and only it (precision 1.0 on that one-probe corpus; see [`docs/adr/0004`](docs/adr/0004-proc-macro-attribution.md#validation--what-is-measured-and-what-is-not)) |
| `stack-scan` | the pointer was in libc or libstd; a stack scan found that macro's frame | **heuristic, accuracy not published** — a scan can find a stale frame, so this is emitted labelled and its precision is not yet measured, which means it is not a claimed confidence level |
| `closure` | neither worked — the proc-macros in the compilation's closure | **parity**: exactly what every other tool gives, demonstrated by the same suite |

It degrades to the incumbent's answer, never to nothing, and it does not claim more than it
has measured: `exact` is proven by a test that blocks the build if it ever names the wrong
macro; `stack-scan`'s accuracy is deliberately unpublished until a real corpus establishes
it.

## Honest positioning

**[`cargo-acl`](https://github.com/cackle-rs/cackle) (formerly cackle) got here first and
does most of this.** It has been intercepting build units through `RUSTC_WRAPPER` since
2023, sandboxes each build script under a per-crate policy with default-deny network and
an `OUT_DIR`-only write bind, has a `--clearenv` environment allowlist that is *stronger*
than buildclamp's scrub, generates its own config, and is named in the Rust project's own
sandboxing goal document. Its static reachability analysis — knowing from compiled code
that a crate *could* open a socket, discounting dead code — is something buildclamp does
not do at all. Run both.

buildclamp's claim is two specific things:

1. **Enforcement that cannot silently evaporate.** `cargo-acl` has one backend,
   bubblewrap, and when `bwrap` is missing it prints a notice and continues *unsandboxed*.
   In a CI container that is a control reporting success while enforcing nothing.
   buildclamp enforces in-process, needs no helper binary, falls back through a stated
   ladder, and names the tier it achieved.
2. **Granularity that reaches individual proc-macros**, above.

## Why this still matters after the registry cooldown

`global-min-publish-age` merged on 2026-08-28 and ships in Rust 1.100.0. A cooldown
delays newly published dependencies, and it would have helped in August.

It does not help against what actually happened. Within the *same minute* as publishing
the malicious `arrayref@0.3.10`, the attacker **yanked versions 0.3.5 through 0.3.9 in a
scripted burst about four seconds apart**, so cargo's own "yanked version" warning would
push lockfile-holders toward the responsible-looking `cargo update -p arrayref` — which
resolved to the only non-yanked modern release, the trap.

**No cooldown, advisory feed or `--offline` flag helps a victim who deliberately
updates.** That is the argument for an enforcement boundary rather than a scanner, and it
is why the pitch is not the incident.

For the record, because these are widely repeated and wrong: `cargo audit` *did* produce a
finding — RUSTSEC-2026-0260, with CVE-2026-77651 — it just did not exist during the
86-minute window. And the payload performed credential-store *reconnaissance*; Socket's
analysis states passwords were not decrypted in the samples examined.

## What the RubyGems campaign settled, and what it did not

Until September 2026 the argument for holding build-time execution rested on inference:
`build.rs` runs with ambient privilege, therefore someone will eventually use it. The
`arrayref` incident made that concrete for Rust, but it stayed one package, one actor, one
registry.

A campaign disclosed on **2026-09-11** removes the inference. An autonomous agent swarm
published roughly **2,000 malicious packages to RubyGems** on 2026-05-11/12, continuing
sporadically into June. **A subset of those packages** — reported as a distinct, much
smaller cluster, not the whole wave — carried `.yardopts` files that obtained arbitrary
code execution on **RubyDoc.info's documentation-build workers**: submit a package,
trigger a docs build, run code on the registry's own infrastructure. Exfiltration was by
publishing results back as new packages. The agents bypassed email verification, and
RubyGems disabled new registrations from 2026-05-12 to 2026-05-16.

The two numbers are worth keeping apart, and this page got them muddled on first writing.
The upload count measures how cheaply an agent swarm can flood a registry; the execution
subset measures how many of those uploads reached the registry's own compute. Only the
second is evidence about build-time execution, and it is the smaller of the two. Reported
sizes for that subset vary between sources and none has been verified here.

Three things in it are load-bearing here.

**The primitive was execution during build, not malicious source.** Nothing in the chain
required a victim to call a malicious function, review a diff and miss something, or
resolve a dependency at all. A file the build honours was enough. That is the same
primitive `build.rs` exposes, and it is the one this project holds.

**It was automated, so the scale is not the attacker's ceiling.** Two thousand artifacts is
not a rate a human sustains. Whatever per-package review budget the registry had, it was
sized for a different volume.

**No sandbox appears anywhere in the chain** — not at publish, not at the docs build, not
on the worker.

**What it is not: a Rust event.** Different ecosystem, different registry, different file
format. It is evidence that this primitive is exploited in practice and that agents will do
it at scale. It is not evidence about crates.io's exposure, and nothing here should be read
as implying a measured claim about cargo. The Rust-specific argument is still the one above
this section.

*(Sources: `rubyhack.ai`, accessed 2026-09-14; BNN Bloomberg, 2026-09-12; The Hacker News,
September 2026; Hacker News item, 2026-09-11, 953 points / 592 comments. Attribution to
OpenAI-operated agents rests on package naming, one listed author address and behavioural
overlap with a separate incident OpenAI confirmed; it is the reporters' attribution and
this project has not independently verified it.)*

## Layout

```
crates/core      the policy model, the classifier, the report schema — pure, no libc,
                 no cargo, no clock. `cargo test -p buildclamp-core` is a complete test
                 of every policy decision, on any machine.
crates/sandbox   Linux enforcement: seccomp-BPF, the notification supervisor,
                 namespaces, and the Landlock ruleset that outranks them on the
                 filesystem. Every `unsafe` block in the project is here.
crates/shim      the three roles cargo puts one binary in, the build-script swap, and
                 the run directory.
crates/cli       cargo-buildclamp: build / check / test / observe / init / explain /
                 report / doctor / unhook.
tests/fixtures   real cargo packages, including a replica of the proc-macro1 build
                 script, run by real cargo invocations.
```

### Where each thing is written down

One home per fact. This README is the map.

| you want | read |
|---|---|
| to try it on a repository that has never seen it | [`docs/FIRST-RUN.md`](docs/FIRST-RUN.md) |
| to write, widen or review a grant | [`docs/POLICY.md`](docs/POLICY.md) |
| why a boundary sits where it does, with the as-built diagrams | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| every flag, environment variable and `buildclamp.toml` key | [`docs/CONFIG.md`](docs/CONFIG.md) |
| landing it in a pipeline, and what a failure means | [`docs/OPERATIONS.md`](docs/OPERATIONS.md) |
| what this reaches on which hosts, and how to regenerate it on yours | [`docs/MATRIX.md`](docs/MATRIX.md) |
| the argument behind a decision this README only states | [`docs/adr/`](docs/adr/) |
| which claims here are backed by a test, and which searches back an absence | [`CLAIMS.toml`](CLAIMS.toml) |
| what is promised about versions, support windows and the compiler floor | [`RELEASING.md`](RELEASING.md) |
| where this project falls short of a security baseline, and why | [`OSPS-BASELINE.md`](OSPS-BASELINE.md) |
| how to report a hole in the enforcement | [`SECURITY.md`](SECURITY.md) |

The command line is the API, and `docs/CONFIG.md` is the surface to depend on. Three of the
four crates are workspace-internal and carry no stability promise between versions.

**`buildclamp-sandbox` is the exception**, and deliberately: it is meant to be cut out and
published on its own, because "run this command under a capability envelope and tell me
which tier held it" is useful to anyone building a CI runner, a package manager or a plugin
host, and none of them want a cargo subcommand. Its surface is frozen already, before the
cut rather than after the first complaint — [`crates/sandbox/API.md`](crates/sandbox/API.md)
says what is frozen and what is not, a test pins each item at its exact type, and
`docs/MATRIX.md` is named as the behavioural half of the same promise.

## Cost

Measured on this project's own host, a 4-vCPU Linux 6.18 machine:

| | |
|---|---|
| fixed cost per held unit | 3–4 ms seccomp setup, 2.4 ms namespaces |
| per notified syscall | 10–40 µs, depending on whether the supervisor wakes on another CPU |
| clean build of a serde-plus-derive graph, unhooked | 5.06 s |
| the same build, hooked | 4.86 s |

The hooked and unhooked builds are within measurement noise of each other. The per-syscall
cost is why compiler units get a kernel-enforced filesystem tier rather than
notifications: rustc opens thousands of files, and `observe --deep` exists for when you
want that detail and are willing to pay for it.

## License

Apache-2.0 for everything in this repository. The
boundary is a directory, so "is this bit free?" is answerable by looking at a path. A
security tool people cannot read will not be adopted into a build, and this category's
credibility comes from being auditable.

**About the name.** `buildclamp` was chosen after availability sweeps across fifteen
candidates. Rechecked on 2026-11-15, it is free on crates.io, npm, PyPI, Docker Hub, GitHub
and every domain checked, and a web search found no software product using it. That is
availability evidence, not a trademark clearance: no formal register search (USPTO, EUIPO,
WIPO) has been done, and the name is used on that basis.
