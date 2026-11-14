# Configuration reference

Every knob, in one place. Three sources, in the order they override one another:

```
buildclamp.toml   ──▶  environment  ──▶  command-line flags
   (the policy)         (mostly internal)     (the run)
```

Source of truth, so a reviewer can diff this file against the code that reads it:

| section | comes from |
|---|---|
| Commands and flags | the clap definitions in `crates/cli/src/args.rs` |
| Environment | the constants in `crates/core/src/lib.rs` and `Disabled::from_env` in `crates/sandbox/src/linux/mod.rs` |
| `buildclamp.toml` | the serde types in `crates/core/src/policy.rs` |

Regenerate the tables when those change. `deny_unknown_fields` is set on every policy
type, so a key this file lists and the code does not is a parse error rather than a
silent no-op — which is the direction you want the drift to fail in.

## Commands

| command | runs cargo? | what it is for |
|---|---|---|
| `observe` | `cargo check` | the first thing to run in a repository. Refuses nothing, records everything |
| `init` | no | writes `buildclamp.toml` from a recorded run |
| `build` | `cargo build` | enforce the policy |
| `check` | `cargo check` | enforce the policy, fastest. Still compiles and runs every build script |
| `test` | `cargo test` | enforce the policy through the test build |
| `bench` | `cargo bench` | enforce the policy through the benchmark build |
| `doc` | `cargo doc` | enforce the policy while building documentation. Building docs compiles and runs every build script in the graph, so a docs job runs the same third-party code a build does |
| `install` | `cargo install` | enforce the policy while installing a crate. `cargo buildclamp install ripgrep` — the only one of these that is about somebody else's dependency graph rather than your own |
| `publish` | `cargo publish` | enforce the policy through the verification build cargo runs before uploading |
| `clippy` | `cargo clippy` | enforce the policy through the lint build. Linting compiles and runs build scripts exactly as `check` does |
| `policy migrate` | no | rewrite a policy at the current format version. Only the number changes — and buildclamp checks that before writing, by re-resolving every grant against the original |
| `verify` | no | check an attestation: that it is an in-toto Statement v1 of this project's predicate type, that its subject digest is the artefact in front of you, and that its policy and report hashes are the files in front of you. **Not the signature** — see below |
| `except` | no | write an `[[exception]]`: the unblock path for a red build at 17:00. One crate, a mandatory reason, an author from your git identity, an expiry capped at 7 days |
| `explain` | no | print the envelope one crate would get, and the rule that produced it |
| `report` | no | print or convert the last run's report |
| `doctor` | no | print what this host can actually enforce, and with `--require`, fail a lane that cannot reach the floor it declared |
| `selftest` | no | check buildclamp's own claims on this machine |
| `unhook` | no | remove the shims from a target directory |

`observe` runs `check` rather than `build` because check is the cheapest cargo
subcommand that still compiles and runs every build script and every proc-macro, which
is the entire population being observed. Pass `-- --release` to observe a release build.

#### `install`, and where its report goes

`cargo buildclamp install <crate>` is the one command here that is not about your own
project. Installing a tool compiles somebody else's dependency graph on your machine, with
your credentials in the environment, and nothing is reviewed first — which is the shape of
both large 2026 Rust incidents. It takes the crate name directly, with no `--` needed:

```console
$ cargo buildclamp install ripgrep
```

Run inside a workspace, the report lands under that workspace's `target/` like any other
run. Run outside one — the ordinary way to install a tool — there is no target directory to
put it in, so it goes to `<tmp>/buildclamp-scratch/buildclamp/` and the last line of output
says where. It is deliberately not `$CARGO_HOME`: reports would accumulate there forever
with nothing to clean them, and the rule the rest of this layout follows — everything under
a directory `cargo clean` removes — has no equivalent there.

**One case holds nothing, and says so.** Measured: `cargo install --path <dir>` builds into
`<dir>/target`, so installing a package already built there reuses it and no build script
runs. The summary then prints `no build units ran`, because a clean report over a build
that never happened is the false assurance this tool exists to prevent. Installing from a
registry does not have the problem — cargo builds it fresh — which is the case that
matters, since a crate you have not read is the one whose build script you wanted held.

#### `publish`, and the one credential cargo keeps

`cargo publish` compiles the packaged crate before uploading it — measured, in
`target/package/<name>-<version>/` — so every build script in the graph runs and the
wrapper reaches them like any other build.

It is also the **only** subcommand where cargo itself keeps a credential. Everywhere else
buildclamp drops credential-shaped names from its own environment before cargo inherits
them, so that no process in the build tree holds a secret a build script could read out of
`/proc`. `CARGO_REGISTRY_TOKEN` is in the default deny list by name, along with
`CARGO_REGISTRIES_*`, and dropping it here would break the upload with an authentication
error pointing nowhere near buildclamp. So for this verb, and only this verb, those names
survive into cargo's environment. Nothing else does: an `AWS_SECRET_ACCESS_KEY` or a
`GITHUB_TOKEN` is still taken out of the build tree, and a test pins that the exception is
that narrow.

Held units never receive the token either way — each unit's environment is scrubbed
separately by the launcher. What remains is the `/proc` read, and it is a tier question:

| environment tier | what a held build script can do |
|---|---|
| `enforced:scrub+userns` | nothing: the read of cargo's `/proc/<pid>/environ` returns `EPERM` |
| `advisory:scrub` | it can read the token out of the publishing cargo's environment |

On the second, the run says so **before cargo starts**, and with `--require-enforced` it
refuses to publish at all:

```console
$ cargo buildclamp publish --require-enforced
buildclamp: publishing needs your registry token in cargo's own environment, and the
  environment tier on this host is `advisory:scrub`. …
buildclamp: refusing to publish, because --require-enforced was asked for and
  this host cannot provide it. This is checked before the upload rather
  than after it: an upload cannot be taken back.
```

That ordering is the point. Everywhere else `--require-enforced` reads the finished report,
which is the right place for it; here the report would be written after the crate was
already on the registry, and a verdict delivered then is not a verdict.

`cargo publish` cannot run `--offline` at all — measured, even `--dry-run` with a warm
index — so there is no way to exercise the upload path without a registry.

#### `clippy`, and the two wrappers in the chain

Linting compiles and runs build scripts exactly as `check` does, so a pipeline that holds
`build` and lints unheld has run the same third-party build-time code twice and held it
once. Lint jobs are also the ones that run on every pull request, including from a fork.

`cargo clippy` is the only verb with **two** wrappers in play: it sets
`RUSTC_WORKSPACE_WRAPPER=clippy-driver` and leaves `RUSTC_WRAPPER` to buildclamp, which
stays outermost. The two are not applied to the same units, and that asymmetry is the whole
difficulty. Measured on cargo 1.94.1 / clippy 0.1.94, by putting a logging script in the
wrapper position:

| unit | what arrives in the wrapper position |
|---|---|
| a **dependency's** build-script compile | `<buildclamp> rustc --crate-name build_script_build …` |
| the **workspace's own** build-script compile | `<buildclamp> clippy-driver rustc --crate-name build_script_build …` |

A wrapper that decided what it was looking at from the compiler's basename would hold the
first and skip the second — and the second is the developer's own build script. So the
classifier scans the whole argv for markers instead of trusting `argv[1]`, and
`crates/cli/tests/verbs.rs` drives real clippy over a package that has a build script of
its own, naming both units rather than counting them.

(`cargo -vv` does not show this. Its `Running` lines print the resolved rustc command
without the workspace wrapper, which is why the table above was measured from the wrapper
position rather than read out of a build log.)

## Flags

Everything after a bare `--` reaches cargo unchanged. That is how `--release`,
`--features`, `-p` and `--target` work.

### Shared by `build`, `check`, `test`, `bench`, `doc`, `install`, `publish`, `clippy`, `observe`

| flag | type | default | what it does | when to change it |
|---|---|---|---|---|
| `--policy <FILE>` | path | `buildclamp.toml` beside the workspace manifest | which policy to load | a repository holding several policies, or a policy kept outside the tree |
| `--strict` | bool | off | exit 2 if any grant is still `reviewed = false` | in CI, once the policy has been through review. This is what stops `init`'s output becoming permanent |
| `--require-enforced` | bool | off | exit 2 if any capability buildclamp can refuse was only advisory on this host. **Exec is excluded**: it is observe-only — recorded, never refused, on every host — so requiring it enforced would fail everywhere | in CI, when a green build on a host that could not enforce anything would be worse than a red one |
| `--require-signed-policy` | bool | off | refuse the build if any distributed (`extends`ed) policy layer is not signed by a key in the committed `trust-root`. The committed `buildclamp.toml` itself is trusted because it is committed, not by signature, so a repository with no distributed layers has nothing to refuse. Checked before the build, like every other policy error | in CI, once the org distributes a signed policy bundle and you want an unsigned or tampered one to fail rather than be silently accepted |
| `--deep` | bool | off | record every write a held unit makes, not only the ones the policy refused | seeing what a build script actually wrote. On an enforcing run the kernel refuses out-of-zone writes and the permitted ones are never notified, so without this the report lists what was stopped and not what was done. Not something to leave on: each notified syscall costs 10 to 40 microseconds. It does **not** reach inside a compile unit — those are not held |
| `--grace <DAYS>` | integer | off | warn rather than fail on a grant `init` first wrote within the last N days | the first weeks of a policy, and after a dependency bump. Only affects `--strict`, and only for grants carrying `first-seen`; a grant with no date is never in grace, so `--grace 3650` on a year-old policy excuses nothing |
| `--report <FILE>` | path | `<target>/buildclamp/report.json` | where to write the machine-readable report | collecting reports from several builds into one directory |

### `observe` only

| flag | type | default | what it does | when to change it |
|---|---|---|---|---|
| `--gate` | bool | off | exit 2 if the recorded run *would have had* an ungranted request under enforcement | watching for capability drift in a pipeline before committing to enforcement |

### `init` only

| flag | type | default | what it does |
|---|---|---|---|
| `--from <FILE>` | path | the last run's report | the report to generate from |
| `--out <FILE>` | path | `buildclamp.toml` beside the workspace manifest | where to write |
| `--force` | bool | off | overwrite an existing policy. Refused by default, because every generated grant is `reviewed = false` and overwriting a reviewed policy undoes exactly the work the file exists to record |
| `--accept-baseline <FILE>` | path | none | mark grants reviewed where a published baseline vouches for that **exact** crate version, and record the document's SHA-256 in the policy as the reviewer of record. Pins each accepted grant to that version, so a patch bump comes back for review. Prints the residual — how many grants are still unreviewed — which is the number that says whether a baseline is worth anything |
| `--stdout` | bool | off | print instead of writing |

### `verify` only

| flag | type | default | what it does |
|---|---|---|---|
| `<FILE>` | path | required | the attestation: a DSSE envelope, or a bare in-toto Statement (which is what `cosign verify-attestation` hands its caller once it has checked the signature) |
| `--artefact <FILE>` | path | none | hash it here and compare with the statement's subject digest |
| `--policy <FILE>` | path | none | compare with the statement's `policy_sha256` |
| `--report <FILE>` | path | none | compare with the statement's `report_sha256` |
| `--erratum <FILE>` | repeatable | none | a signed correction. **Supplied locally, never fetched**: a verifier that reached the network would be unusable air-gapped and would put the vendor's availability in your verification path |
| `--require-fully-enforced` | bool | off | exit 2 unless the statement describes a run with both optional hardenings on, nothing switched off, and every capability's weakest tier `enforced:` |

**It does not check the signature, and it says so on every run.** That is deliberate rather
than an omission: the free binary links no cryptography and no network client, a property CI
asserts, and adding a signature algorithm here would be choosing one on behalf of a signer
that lives elsewhere. `cosign verify-attestation` and `gh attestation verify` are free and
are the tools for it.

The two halves are genuinely separable, and the half this does is the one that catches
laundering: a cryptographically perfect signature over a statement about a *different
artefact*, or over a run with reads unrestricted, is still the wrong document.

The `predicateType` is read **out of the document**, never from a flag. That is
CVE-2022-35929, where cosign returned success when no attestation of the requested type
existed at all; the fixed cosign is ≥ 1.10.1, and if your verification path includes an
older one, `schemas/v1/negative/wrong-predicate-type.json` is the vector that matters.

### `except` only

| flag | type | default | what it does |
|---|---|---|---|
| `<CRATE>` | string | required | the crate to stand the refusal down for. One name, never a pattern |
| `--reason <TEXT>` | string | **required** | what happened today that made refusing unacceptable. The one field the tool cannot fill in for you |
| `--days <DAYS>` | integer | `1` | how long it lasts, capped at 7 |
| `--capability <NAME>` | repeatable | narrowed from the last report | limit it to specific capabilities. Left off with no report to read, the block covers whatever that crate asks for |
| `--author <WHO>` | string | your git identity | who is breaking the glass. Self-asserted either way |
| `--policy <FILE>` | path | `buildclamp.toml` beside the workspace manifest | which policy to append to. Creates one if there is none |
| `--stdout` | bool | off | print the block instead of appending it |

### `explain` / `report` / `unhook`

| flag | applies to | default | what it does |
|---|---|---|---|
| `<CRATE>` | `explain` | required | the crate to explain |
| `--version <REQ>` | `explain` | none | its version, when a grant is version-qualified |
| `--env` | `explain` | off | also print the environment names this crate would not see, and why |
| `--from <FILE>` | `report` | the last run's | the report to read |
| `--json` | `report` | off | emit the raw JSON rather than the human summary |
| `--markdown` | `report` | off | emit a bounded GitHub-flavoured markdown summary, for a job summary or a PR comment. Lists at most 20 units and says how many it left out |
| `--all` | `report` | off | show every unit, not only those with ungranted requests |
| `--target-dir <DIR>` | `unhook` | this workspace's | the target directory to clean |

### `doctor` / `selftest`

| flag | applies to | default | what it does |
|---|---|---|---|
| `--json` | `doctor` | off | emit `HostCapabilities` instead of the table — the same object that appears under `host` in `report.json`, so a consumer needs no second schema |
| `--require <TIER_SET>` | `doctor` | none | the enforcement floor this lane requires. `--require net=enforced,fs-write=enforced`, or a bare `--require enforced` for every capability buildclamp can refuse. `exec` is observe-only and refused in a floor by name. Exit 2 when the host falls short, exit 1 when the floor itself cannot be parsed |
| `--no-network` | `selftest` | off | run a command inside a build script's envelope with the network denied, and fail if anything in it asked for the network |
| `<COMMAND>` | `selftest` | this binary | the command to run, after a bare `--` |

**Declare the floor in every CI lane.** `--require-enforced` is checked at the *end* of a
build, against what happened; that is the right place for it and the wrong place to find
out that the lane itself cannot enforce. A container image that lost `CAP_SYS_ADMIN`, a
host with `kernel.apparmor_restrict_unprivileged_userns=1`, a runner whose seccomp profile
denies `unshare` — each turns an enforcing lane into an advisory one, and the build stays
green, because advisory enforcement still runs the build. Nobody is told the control
stopped controlling.

```yaml
- run: cargo buildclamp doctor --require net=enforced,fs-write=enforced,env-secret=enforced
- run: cargo buildclamp build --require-enforced --strict
```

The first line fails in seconds, as a misconfigured lane. The second answers the question
about your dependencies. `--require` also honours `BUILDCLAMP_DISABLE`, so a lane that
switched a mechanism off is told what it actually gets rather than what the kernel could
have provided.

### What `selftest --no-network` proves

That **this invocation of this binary, on this machine, opened no socket** — observed by
the kernel, through the same enforcement a held build script gets, and printed with the
tier that achieved it. On a host that can enforce nothing it exits 1 rather than 0: an
absence of network requests that nothing was watching for is not evidence.

It does not prove the binary *cannot* reach the network. A code path nothing exercised
could still hold a client, which is why `ops/no-network-closure.sh` exists alongside it and
walks the resolved `cargo tree -e normal` closure of each published binary, failing if a
client is linked at all. The closure check cannot observe behaviour and the selftest cannot
observe unreached code. Neither replaces the other.

[`docs/adr/0005`](adr/0005-the-artefact-boundary.md) states the narrow version of the claim
both serve: it is about linking, not behaviour. The free binary spawns `cargo`, and `cargo`
downloads crates — at the process level this tool has always been one `exec` from the
network, and it says so rather than being caught.

## Environment

Most of these are set by the driver and read by the wrapper it spawns. You set exactly
one of them by hand.

| variable | set by | read by | effect |
|---|---|---|---|
| `BUILDCLAMP_DISABLE` | **you** | the sandbox | comma-separated list of `ns` and `notify`. Switches a mechanism off |
| `BUILDCLAMP_POLICY` | the driver | the wrapper and launcher | names the policy file. **Its presence is the switch**: unset, every role passes straight through and touches nothing, so a stray `RUSTC_WRAPPER` left in a shell cannot mutate a target directory |
| `BUILDCLAMP_RUN` | the driver | every held unit | the run directory each unit writes its JSON record into. One directory per run, because units run concurrently under `cargo --jobs N` and appending to one shared file from several processes is a corruption waiting for a busy build |
| `BUILDCLAMP_MACROS` | the driver | the wrapper | the trusted directory holding the proc-macro inventory (object→unit mappings). Kept **outside** `target/` on purpose: a held compile is granted all of `target/`, so an inventory under the run directory could be forged by the code the sandbox is holding. On no sandbox-writable path, so only the trusted wrapper writes it. Unset falls back to the run directory, at the cost of the pre-inventory attribution |
| `BUILDCLAMP_INSIDE` | the launcher | the wrapper | set inside every held unit; a wrapper that sees it passes through |
| `BUILDCLAMP_INNER_WRAPPER` | the driver | the wrapper | a previous `RUSTC_WRAPPER` to chain to, such as `sccache` |
| `BUILDCLAMP_MODE` | the driver | the launcher | the mode override, so `observe` needs no second policy file. `off` is the kill switch: every unit runs unheld and the report says so. See [OPERATIONS.md](OPERATIONS.md#turning-it-off-in-a-hurry) |
| `BUILDCLAMP_WORKSPACE_MEMBERS` | the driver | the wrapper and launcher | path to a trusted file listing the workspace members' manifest directories, one per line, from `cargo metadata`, matched against `CARGO_MANIFEST_DIR`. Lets a held unit tell a first-party crate from a dependency — directories, not names, so a registry dependency that shares a member's name is not mistaken for it and run unheld under `trust-workspace`. A file path, not the list inline, because a large monorepo's list can exceed one environment entry's `MAX_ARG_STRLEN` (128 KiB) and fail `execve` with `E2BIG`; the file sits outside every sandbox-writable path so a held unit cannot forge its own membership. `CARGO_PRIMARY_PACKAGE` marks only the packages cargo selected on the command line, so a workspace member built as a dependency would otherwise resolve as third-party. Absent or unreadable falls back to `CARGO_PRIMARY_PACKAGE` |
| `BUILDCLAMP_DEEP` | the driver | the launcher | set by `observe --deep` |
| `BUILDCLAMP_TODAY` | the driver | the launcher | the day the driver started, `YYYY-MM-DD`, so every unit in one run answers the same calendar question about an `[[exception]]`'s expiry. Passed rather than read per-process: a build that crossed midnight would otherwise run half its units under an exception and half without one, and a launcher could honour a block against a day the driver never checked the seven-day bound against. Absent or unreadable means **no exception applies** |
| `BUILDCLAMP_AGENT_ID` | **you** | the driver | an opaque name for the agent that produced this report, recorded in the run header. Set it when more than one runner reports into the same place and you need to tell two reports apart. Unset, the field is null — nothing derives it from the hostname, the MAC address or the user |
| `BUILDCLAMP_CI_CORRELATION` | **you** | the driver | an opaque string tying this report back to the CI job that produced it — a job id, a pipeline URL, whatever your system has. Recorded verbatim and never parsed |

`BUILDCLAMP_DISABLE` **can only ever take capability away, never add it.** A build that
sets it gets less enforcement and a report that says so, which is the safe direction for
a switch to point. It exists because the fallback tiers have to be testable on a host
that has everything — otherwise the advisory path would only ever be exercised by a
user, on a machine that happened to lack the mechanism, rather than by a test.

Cargo's own variables buildclamp reads, and does not set: `CARGO`, `CARGO_MANIFEST_DIR`,
`CARGO_TARGET_DIR`, `CARGO_PRIMARY_PACKAGE`, `CARGO_PKG_NAME`, `CARGO_PKG_VERSION`,
`OUT_DIR`, `RUSTC_WRAPPER`.

### If you already use `sccache`

buildclamp has to occupy `RUSTC_WRAPPER`, so what happens to yours depends on how it is
configured, and the two ways do not behave the same:

| how sccache is configured | what happens |
|---|---|
| `RUSTC_WRAPPER=sccache` in the environment | **chained.** buildclamp passes it on through `BUILDCLAMP_INNER_WRAPPER` and every rustc invocation still reaches it — measured at 7 inner invocations under one `cargo buildclamp check`, with the build unit still held |
| `[build] rustc-wrapper = "sccache"` in a `config.toml` | **displaced.** Cargo's environment variable overrides the config, so sccache stops running — measured at 0 inner invocations, against 7 for a plain `cargo check` with the same config |

The second case is a silent regression in the worst shape one can take: the build still
succeeds, it is merely no longer cached, there is no error, and the tool that caused it is
the last thing anyone suspects. So buildclamp **warns**, names the file it found the key
in, and prints the fix:

```console
$ cargo buildclamp check
buildclamp: /repo/.cargo/config.toml sets `build.rustc-wrapper = sccache`, and buildclamp
  has to put itself in that slot — the RUSTC_WRAPPER environment variable overrides the
  config, so that wrapper will NOT run and your builds will not be cached.
  Export it instead and buildclamp will chain to it:
    RUSTC_WRAPPER=sccache cargo buildclamp build
```

It warns rather than chaining the configured value itself, and that is a deliberate
limit. Chaining would mean resolving cargo's config hierarchy — every ancestor
`.cargo/config.toml`, `$CARGO_HOME`, the extensionless `.cargo/config` spelling, `--config`
arguments and the precedence among them — and getting that subtly wrong would run the
**wrong** wrapper without saying so, which is worse than running none. The detection is
best effort and scoped to say so: it reads the files listed above, parses them rather than
grepping (a commented-out `rustc-wrapper` is correctly silent), and a wrapper passed with
`--config` on the cargo command line is not seen.

## `buildclamp.toml`

```toml
version = 1

[defaults]
mode = "enforce"
trust-workspace = false

[grants."openssl-sys"]
version = ">=0.9, <0.10"
capabilities = ["fs-write", "exec"]
write-zones = ["out-dir", "tmp"]
env-allow = ["OPENSSL_DIR", "OPENSSL_LIB_DIR"]
why = "pkg-config plus cc; writes only under OUT_DIR"
reviewed = true
```

### Top level

| key | type | default | notes |
|---|---|---|---|
| `version` | integer | required | the policy format version, currently `2`. Bumped only for a change an older buildclamp would **misread**. A version 1 file still parses — only the *future* is refused — and `cargo buildclamp policy migrate` writes the number when you are ready |
| `min-tool-version` | semver | none | the oldest buildclamp that can honour this file. An older binary refuses by name — "this file needs 0.4, you are running 0.2" — instead of parsing it and being wrong quietly. `init` writes the version that generated the file; a hand-written policy needs no floor |

`min-tool-version` is not a second spelling of `version`, and the difference is the case
`version` cannot express. `version` moves when the format changes **shape**, which is
deliberately rare. The far more common problem is a file whose shape is unchanged and
which relies on behaviour a given binary does not have: a grant with `net-destinations`
written for an agent that records destinations, read by one that does not, parses
perfectly and grants something nobody meant. That failure is silent and it is in the
permissive direction, so a policy author who needs a floor states one.

A **release candidate satisfies the floor for its own release**: `0.4.0-rc.1` honours
`min-tool-version = "0.4.0"`. Semver orders a pre-release before its release, which is
right for dependency resolution and wrong here — the question is whether the binary has
the behaviour, and a candidate for 0.4.0 has it.

### `[defaults]`

| key | type | default | what it does |
|---|---|---|---|
| `mode` | `"observe"` \| `"enforce"` | `"enforce"` | whether an ungranted request is recorded or refused |
| `trust-workspace` | bool | `false` | run the workspace's own build scripts unheld |
| `withhold-secret-reads` | bool | `false` | make the credential paths in `crates/core/src/withhold.rs` unreadable to build units. Needs Landlock; a crate that needs one asks for `fs-read` in its grant |
| `env-allowlist` | bool | `false` | give units only the base set in `ENV_ALLOWLIST_BASE` plus what a grant names, instead of everything minus `env-deny` |
| `hold-compile-units` | bool | `false` | hold the rustc invocations where proc-macros expand, not only build scripts. One shared policy per compilation, not per macro |
| `env-deny` | list of patterns | the built-in list | **replaces** the built-in list entirely when present |
| `max-active-exceptions` | integer | `3` | how many `[[exception]]` blocks may be live at once before the policy is refused. `0` forbids break-glass in this repository entirely |
| `trust-root` | list of base64 Ed25519 public keys | empty | keys this repository trusts to have signed a policy layer it pulls in through `extends`. Several are allowed, for key rotation. A malformed key is a policy error at parse |

`trust-root` is the authority half of policy distribution. `policy_sha256` proves a
distributed layer is byte-identical to what was recorded, but a curl'd bundle hashes the
same as a committed one, so a hash cannot say the layer came from someone allowed to write
it. A trust root can: a distributed layer carries a detached `<layer>.sig`, and
`--require-signed-policy` refuses any `extends`ed layer that no key in the root verifies. It
belongs in the **committed** `buildclamp.toml`, under CODEOWNERS, because that file's
authority is that it is reviewed in the repository — it is never itself signature-checked,
and it is what vouches for the layers beneath it. The report and any attestation carry
`policy_signature_verified` and the `policy_signer_key_id` that verified. No vendor key is
ever compiled in and no network request is made: verification reads bytes already on disk,
and the key is always yours. See `SECURITY.md` for the per-artefact cryptography answer.

`trust-workspace = false` is an argument, not caution. The threat is code you did not
write arriving through a dependency, and a workspace member is code you did write — but
"you wrote it" is exactly what a compromised maintainer account looks like from inside a
monorepo, and a workspace member's build script is the easiest place for an attacker with
commit access to hide. Holding it costs nothing when it is honest.

### `[grants."<crate>"]`

| key | type | default | what it does |
|---|---|---|---|
| `why` | string | **required, non-empty** | why this grant exists |
| `version` | semver req | any version | which versions the grant applies to |
| `capabilities` | list | none | `net`, `unix`, `fs-write`, `fs-read`, `env-secret`, `exec` |
| `write-zones` | list | none | `out-dir`, `tmp`, `target`, `manifest-dir` |
| `write-paths` | list of paths | none | additional writable paths |
| `env-allow` | list of names | none | environment names re-admitted to this unit |
| `env-allow-secrets` | bool | `false` | permits `env-allow` to re-admit a hard-denied name |
| `net-destinations` | list of `host:port` | none | **reported, never enforced** |
| `reviewed` | bool | `false` | whether a human has read this grant. `init` writes `false` |
| `first-seen` | date | none | the day `init` first wrote this grant, `YYYY-MM-DD`. What `--grace` measures from. Absent is **not** a synonym for new: a grant with no date gets no grace at all |

Four rules the parser enforces, each of which is a refusal rather than a guess:

1. **`why` is required and may not be empty.** A grant without one is a parse error before
   any unit runs. This is the `cargo-vet` ergonomic applied to capabilities: the cost of
   widening an envelope is that somebody writes a sentence a colleague reads in a pull
   request. A grant that appears silently in a diff is the failure mode the file exists
   to prevent.
2. **Ambiguity is an error, not last-one-wins.** Two grants for one crate at the same
   specificity is a policy whose meaning depends on file order. Specificity is well
   defined — a version-qualified grant beats an unqualified one — so a tie only happens
   when the policy is genuinely ambiguous.
3. **A grant replaces the defaults; it never adds to them.** A reader should see the whole
   envelope in one place rather than compose it in their head.
4. **Unknown keys are errors.** `deny_unknown_fields` on every type, so a typo in
   `capabilties` fails the parse instead of quietly granting nothing.

`net-destinations` is reported and never enforced, and the code says so in the same
sentence as the field. Enforcing a destination allowlist would need a resolving proxy, and
a tool that appears to enforce one while a build script can resolve a name itself is worse
than one that admits it does not.

### `[layer]`

Composition: an org layer, a policyset layer, a repository layer. Absent means one file and
no layering, which is what every policy before version 2 was and what most stay.

| key | type | default | what it does |
|---|---|---|---|
| `name` | string | **required** | what a refusal and `explain` call this layer. "layer 2" is not something anybody can act on |
| `extends` | list of paths | none | files this layer is composed **on top of**, nearest last. Relative to *this file*, never to the working directory |
| `may-widen` | bool | `true` | `false` makes this layer a **ceiling**: no layer above it may confer anything it did not |

```toml
# org/buildclamp.toml — the ceiling
version = 2
[layer]
name = "org"
may-widen = false

[grants."openssl-sys"]
capabilities = ["net", "fs-write", "exec", "unix"]
write-zones = ["out-dir", "tmp"]
why = "downloads a pinned tarball when no system library is found"
reviewed = true
```

```toml
# repo/buildclamp.toml
version = 2
[layer]
name = "repo"
extends = ["../org/buildclamp.toml"]
```

**The ceiling declaration belongs to the layer being protected.** A layer that could be
marked widenable from above would be no protection at all — the repository could simply say
so.

**A ceiling bounds every crate, including ones it never mentions.** The org's answer for a
crate it does not name is "the defaults". If a repository could exceed the defaults for any
crate the org had not thought of, the ceiling would hold only for the crates somebody had
already worried about, which is the set that needs it least.

**Exceeding a ceiling is a hard error naming both files**, checked before cargo starts. Not
a merge, and not a silent narrowing: narrowing would leave the build passing, one file
saying the crate has the capability, the envelope saying it does not, and nothing to tell a
reader which.

Three more refusals:

* a **cycle** in `extends`, with the chain printed — a cycle has no nearest layer, so there
  is no answer to "which file is the last word";
* two layers with the **same name**, because a refusal naming one of them sends a reader to
  the wrong file;
* a **ceiling with nothing above it**, because a `may-widen = false` nobody is under is a
  line that reads like a control and is not one.

Narrowing is always allowed. A repository that wants less than its organisation permits is
a repository doing the right thing, and it needs no permission for it.

Two things are the **nearest layer's** alone: `mode` and the off switch, because they are
decisions about this run; and `[[exception]]`, because break-glass is somebody in this
repository shipping past a refusal today, and an org layer that could carry one would be
breaking glass on forty repositories from a file none of their engineers read.

`--strict` counts unreviewed grants across **every** layer. A grant nobody has read is a
grant nobody has read whichever file it is in, and the org layer's grants apply to forty
repositories at once.

### `[[exception]]`

Break-glass: the unblock path that needs nobody's approval. `cargo buildclamp except` writes
one; the block is ordinary policy, so it can also be written by hand.

| key | type | default | what it does |
|---|---|---|---|
| `crate` | string | **required** | the crate this covers. One name; a pattern is refused |
| `expires` | date | **required** | the day it stops applying, `YYYY-MM-DD`. At most **7 days from the day the build runs** |
| `reason` | string | **required, non-empty** | what happened that made refusing unacceptable today |
| `author` | string | **required, non-empty** | who broke the glass. Written from your git identity by `except` |
| `capabilities` | list | none | narrow it. **Empty means every capability that crate asks for** |

**What it does.** Grants the named capabilities to that crate until the date, and stands the
run's verdict down for it — including the `--strict` failure for an unreviewed grant on the
same crate.

**What it does not do.** It does not widen `write-zones`: a write outside them is still
refused by the kernel, and only the verdict stands down. It does not suppress
`--require-enforced`, which asks what this *host* can hold and has nothing to do with a
crate. And there is no exception that never expires and no `crate = "*"` — both already
exist under a name that says what they are, `enforcement = "disabled"`, which the report
records as an operator override rather than as a narrow exception.

Four refusals, each before any unit runs:

1. **No `expires` is refused by name.** An absent field reads, to somebody skimming, like a
   deliberate "no expiry", and a permanent exception is what this format must make
   unwritable.
2. **An expiry more than 7 days out is refused**, measured against *today* rather than
   against the day the block was written — so it cannot be backdated into a long one, and
   cannot outlive its week by being committed early.
3. **More live blocks than `max-active-exceptions` is refused**, and the message names the
   key. An expired block does not count against the cap.
4. **A lapsed block is not an error.** The build goes red again for the reason it went red
   originally, and the summary names the block and its date so nobody writes the same one
   twice wondering why the first stopped working.

Every run with a block in the policy — live or lapsed — says so on stdout, with what was
excused, what it was used for and what is still owed. The report carries the same under
`break_glass`.

### `[baseline]`

Written by `init --accept-baseline`, never by hand. It records which published document
vouched for the grants in this file that carry `reviewed = true`.

| key | type | what it is |
|---|---|---|
| `digest` | string | `sha256:<hex>` of the document's bytes as they were read |
| `source` | string | where it came from, copied from the baseline |
| `published` | date | when it was published, copied from the baseline |
| `accepted` | date | the day the acceptance was made |

The digest identifies **which** document, and defends against nobody: anyone who can write
`reviewed = true` can write a digest beside it. What makes a baseline acceptance meaningful
is that the document is published and the digest is in the diff.

The baseline format itself is in [`examples/baseline.toml`](../examples/baseline.toml),
whose header says at length that its own entries are illustrative — a baseline whose author
has not read those build scripts at those releases is worth nothing.

### `env-allowlist`: the stronger of the two environment models

The default is a **deny-list**: a unit gets everything except names matching `env-deny`.
That cannot know about a credential variable nobody has thought of, which is why
`cargo-acl`'s `--clearenv` allowlist is the stronger model.

`env-allowlist = true` inverts it. A unit then gets:

* the base set — what cargo and the toolchain tell a build script, plus the few system
  variables a compiler needs. It is `ENV_ALLOWLIST_BASE` in `crates/core/src/policy.rs`
  and it is a list you can read: `CARGO*`, `OUT_DIR`, `TARGET`, `HOST`, `NUM_JOBS`,
  `OPT_LEVEL`, `PROFILE`, `DEP_*`, `RUSTC*`, `PATH`, `HOME`, `TMPDIR`, `LANG`/`LC_*`,
  `TERM`, `PWD`, `SOURCE_DATE_EPOCH`;
* plus whatever the crate's own grant lists in `env-allow`.

Everything else is gone — every variable your CI exported, every one in your shell.

**The two combine; the allowlist never widens.** The deny-list runs first and
independently, so a name it removes stays removed. That ordering is load-bearing rather
than tidy: `CARGO_*` is in the base set and `CARGO_REGISTRY_TOKEN` starts with it, so an
allowlist consulted first would hand back the exact credential the deny-list exists to
take away — turning a feature sold as stronger into a hole. A test is named for it.

A grant **adds** to the base set rather than replacing it, so a build script that needs
`ACME_SDK_ROOT` names that one variable and still gets `PATH` and `OUT_DIR`. And a
hard-denied name still needs the loud `env-allow-secrets = true` opt-in here, so the
allowlist does not become a second, quieter way to re-admit a credential.

It is **opt-in**, for the same reason withholding reads is: the deny-list is what every
existing build passes under, and an allowlist switched on underneath somebody would break
a build that reads some ordinary variable nobody wrote down — with a missing-variable panic
from inside a dependency, which is not an error anyone would connect to this tool.

The report records `env_allowlist` on each unit's envelope, so "why did my variable
disappear?" is answerable from the run rather than from a policy file that may have
changed since.

### Environment scrubbing

Unless a grant re-admits a name, these patterns are removed from every held unit. A
pattern supports one leading and/or trailing `*`; anything more expressive would need a
glob dependency and would let a policy author write a pattern whose behaviour they cannot
predict.

```
*_TOKEN  *_SECRET  *_PASSWORD  *_API_KEY  *_ACCESS_KEY  *_CREDENTIALS  *_PRIVATE_KEY
AWS_*  AZURE_*  GCP_*  ACTIONS_*  CARGO_REGISTRIES_*
GOOGLE_APPLICATION_CREDENTIALS  GITHUB_TOKEN  GH_TOKEN  CARGO_REGISTRY_TOKEN
NPM_TOKEN  DOCKER_PASSWORD  VAULT_TOKEN  SSH_AUTH_SOCK
OPENAI_API_KEY  ANTHROPIC_API_KEY
```

These eight cannot be re-admitted by `env-allow` alone. A grant needs
`env-allow-secrets = true` as well, which exists to make the choice loud in a diff rather
than to make it impossible — a tool that cannot express what a user actually needs gets
replaced by no tool at all.

```
GITHUB_TOKEN  AWS_SECRET_ACCESS_KEY  AWS_SESSION_TOKEN  CARGO_REGISTRY_TOKEN
ACTIONS_ID_TOKEN_REQUEST_TOKEN  ACTIONS_RUNTIME_TOKEN  VAULT_TOKEN  NPM_TOKEN
```

**The honest limit.** There is no syscall for `getenv`, so scrubbing controls *exposure*
rather than enforcing a rule the kernel can check. Three layers do it: the unit's own
environment is filtered before exec, the driver scrubs its own before executing cargo so
the whole build tree leaves the exposure set, and the user namespace closes what is left.
Only the third is complete. `hidepid` is not one of the three — the sandbox never
remounts `/proc` with it, `doctor` only reports whether the host already had it set, and
it hides other *users*' processes, so it does nothing about cargo. A report says which
layer was achieved.

## Exit codes

The contract with CI, shared with every sibling module in this repository:

| code | meaning |
|---|---|
| 0 | everything the policy asked for held |
| 1 | buildclamp itself failed, or the underlying cargo build failed |
| 2 | the policy's answer was no: an ungranted request, an unreviewed grant under `--strict`, or an advisory-only tier under `--require-enforced` |

The 0/1/2 split is what lets a pipeline tell "the tool broke" from "the tool worked and
the answer was no". A pipeline treating them the same either ignores real findings or
blocks on unrelated breakage.

## Formats and compatibility

| artefact | version key | where | rule |
|---|---|---|---|
| policy | `version` | `buildclamp.toml` | bumped only when an older buildclamp would misread the file. Unknown keys are already errors, so most additions need no bump |
| report | `format_version` | `<target>/buildclamp/report.json` | currently `2`. Additive fields do not bump it; a changed shape or meaning does. A version 1 report is migrated on read, so an older file keeps working; a **higher** number is refused by name rather than half-understood |
| run record | none | `<target>/buildclamp/run-*/` | internal to a single run, written and read by the same binary version. A corrupt record is a hard error, never a skipped unit |

A run record filename carries the unit's instance discriminator and the writing process
id, because one crate can be built more than once in a single cargo invocation — once for
the host and once for the target — and two units sharing a name is not the same as two
units sharing an identity.

### What changed in report format version 2

Two things, and a v1 file is migrated on read rather than rejected:

* **A `run` object beside `units`**, holding what is true of the whole build: a run id,
  the start and finish times, the git remote / commit / ref where there is a checkout, the
  **target triple**, an agent id, a CI correlation string and the ecosystem. Version 1 had
  nowhere to put any of it, so a consumer that needed one invented it — the fleet ingester
  put `host.arch`, `x86_64`, into a field documented as a target triple, which merges
  `-gnu` and `-musl` builds into one bucket.
* **`tiers` is a map keyed by capability**, not an array of `[capability, tier]` pairs. An
  array can represent one capability with two tiers — a document saying a thing was both
  enforced and not — and forces every reader to scan.

Everything that legitimately differs between two runs of the same build lives in the `run`
object, so two reports still diff to nothing once it is stripped. Two exceptions are in the
units and are deliberate: `duration_ms` and each request's `at_ms` and `tid` are
measurements of a particular run, and a build script that writes a path containing its own
pid still shows up as a difference, because normalising that away would mean the tool
deciding which of your build's paths are "really" the same.

**A name this buildclamp does not recognise** — a capability, a write zone, a unit kind, a
tier grade or an attribution confidence from a newer agent — is carried through verbatim
rather than failing the document, and `cargo buildclamp report` says which names it did not
know. An unrecognised tier grade is treated as *not enforced*, so `--require-enforced` can
never pass on enforcement this build could not evaluate.
