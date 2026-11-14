//! The command line.
//!
//! The shape follows the adoption path rather than the feature list, because the order
//! someone meets these commands in decides whether they keep the tool:
//!
//! ```console
//! $ cargo buildclamp observe        # run the build, refuse nothing, record everything
//! $ cargo buildclamp init           # write buildclamp.toml from what was recorded
//! $ cargo buildclamp build          # enforce it
//! ```
//!
//! A default-deny policy that breaks common crates on the first run is dead on arrival,
//! so `observe` is documented first and `build` third. Everything else — `explain`,
//! `report`, `doctor`, `unhook` — exists to answer a question someone will have while
//! standing in the middle of that path.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// `cargo buildclamp <command>`.
///
/// The binary is `cargo-buildclamp`, which is how cargo finds a subcommand, and cargo
/// passes `buildclamp` back as the first argument when it dispatches. `bin_name` and the
/// hidden leading argument below are what make `--help` print the command a person
/// actually typed.
#[derive(Parser, Debug)]
#[command(
    name = "cargo-buildclamp",
    bin_name = "cargo buildclamp",
    version,
    about = "Run every build.rs and proc-macro inside a declared capability envelope",
    long_about = "buildclamp holds every third-party build script and proc-macro to a \
                  capability envelope you declare: no network, no writes outside OUT_DIR, \
                  no CI secrets, unless buildclamp.toml grants them.\n\n\
                  Start with `cargo buildclamp observe`, which refuses nothing and records \
                  what your build actually does. Then `cargo buildclamp init` writes the \
                  policy from that recording, and `cargo buildclamp build` enforces it."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run `cargo build` with every build unit held.
    Build(CargoArgs),
    /// Run `cargo check` with every build unit held.
    ///
    /// Worth knowing: `cargo check` compiles and runs build scripts too, so this holds
    /// exactly as much as `build` does. It is the fastest way to exercise a policy.
    Check(CargoArgs),
    /// Run `cargo test` with every build unit held.
    Test(CargoArgs),
    /// Run `cargo bench` with every build unit held.
    Bench(CargoArgs),
    /// Run `cargo doc` with every build unit held.
    ///
    /// Worth knowing, because it surprises people: building documentation compiles and
    /// runs every build script in the graph. A pipeline that holds `build` and publishes
    /// docs from an unheld `cargo doc` has left the same code an unheld run.
    Doc(CargoArgs),
    /// Run `cargo install` with every build unit held.
    ///
    /// The one in this list that is not about your own project. `cargo install ripgrep`
    /// compiles somebody else's dependency graph on your machine, with your credentials
    /// in the environment, and nothing about it is reviewed first — which is the shape of
    /// both large 2026 Rust incidents. Run it as `cargo buildclamp install ripgrep`.
    ///
    /// Where the report goes: beside the workspace you are standing in, as usual. Run it
    /// outside a workspace — the ordinary way to install a tool — and there is no target
    /// directory to put one in, so it goes to a temporary directory and the last line of
    /// output says where.
    ///
    /// **One case holds nothing, and the run says so rather than looking clean.**
    /// `cargo install --path <dir>` builds into `<dir>/target`, measured, so a package
    /// that has already been built there is reused and no build script runs at all. The
    /// summary prints "no build units ran" for exactly that, because a report over a
    /// build that never happened is the false assurance this tool exists to avoid.
    /// Installing from a registry does not have the problem — cargo builds it fresh —
    /// which is the case that matters, since a crate you have not read is the one whose
    /// build script you wanted held.
    Install(CargoArgs),
    /// Run `cargo publish` with the verification build held.
    ///
    /// Publishing compiles the packaged crate before uploading it — measured, in
    /// `target/package/<name>-<version>/` — so every build script in the graph runs, and
    /// the wrapper reaches them like any other build.
    ///
    /// **This is the one command where cargo itself must keep a credential.** The driver
    /// normally drops credential-shaped names from its own environment before cargo
    /// inherits them, so that no process in the build tree holds a secret a build script
    /// could read out of `/proc`. `CARGO_REGISTRY_TOKEN` is in the default deny list by
    /// name, and dropping it here would simply break the upload — so for this subcommand,
    /// and only this one, the registry token is kept. Held units never see it: the
    /// launcher scrubs each unit's own environment separately.
    ///
    /// What remains is the `/proc` read, and it is a tier question rather than a policy
    /// one. With `enforced:scrub+userns` a held unit cannot read cargo's environment at
    /// all. With `advisory:scrub` it can, and the run says so before cargo starts, because
    /// publishing is the moment your registry token and third-party build-time code are
    /// alive in the same process tree.
    ///
    /// `--require-enforced` is checked **before** the upload for this subcommand rather
    /// than after it. Everywhere else the flag reads the finished report; an upload cannot
    /// be taken back, so a verdict delivered afterwards would not be one.
    Publish(CargoArgs),
    /// Run `cargo clippy` with every build unit held.
    ///
    /// Linting compiles and runs build scripts exactly as `check` does, so a pipeline that
    /// holds `build` and lints unheld has run the same third-party build-time code twice
    /// and held it once. Lint jobs are also the ones that run on every pull request,
    /// including from a fork.
    ///
    /// **This is the one verb with two wrappers in the chain.** `cargo clippy` sets
    /// `RUSTC_WORKSPACE_WRAPPER=clippy-driver` and leaves `RUSTC_WRAPPER` to buildclamp,
    /// so a dependency's build script arrives as `<buildclamp> <rustc> …` while the
    /// workspace's OWN arrives as `<buildclamp> clippy-driver <rustc> …`. A classifier
    /// that keyed on the compiler's basename would skip precisely the build script a
    /// developer most wants held — theirs. `crates/core/src/unit.rs` scans the whole argv
    /// instead, and `crates/cli/tests/verbs.rs` drives real clippy over a package with a
    /// build script of its own to keep that true.
    Clippy(CargoArgs),
    /// Run the build, refuse nothing, and record what every build unit asked for.
    ///
    /// The first command to run in a repository that has never seen buildclamp. It
    /// cannot break your build: nothing is denied, and the exit code is the build's own
    /// unless you pass `--gate`.
    Observe(ObserveArgs),
    /// Write buildclamp.toml from a recorded run.
    ///
    /// Every grant it writes is `reviewed = false` and its `why` says it is an
    /// observation with a date. Replacing those with real reasons is the work; `--strict`
    /// on a later run refuses to pass while any are still unread.
    Init(InitArgs),
    /// Print the envelope a crate would get, and which rule produced it.
    Explain(ExplainArgs),
    /// Print or convert the report from the last run.
    Report(ReportArgs),
    /// Print what this host can actually enforce.
    ///
    /// Run it before trusting a green build. Landlock is absent on some kernels, user
    /// namespaces are blocked on some distributions and inside some container runtimes,
    /// and buildclamp says so rather than reporting enforcement it did not achieve.
    Doctor(DoctorArgs),
    /// Check that buildclamp's own claims hold on this machine.
    ///
    /// Today one check: `--no-network`, which runs a binary inside the same envelope a
    /// build script gets and fails if anything in it tried to reach the network. Point it
    /// at buildclamp itself — the default — to check the artefact boundary on the machine
    /// in front of you rather than on the dependency graph.
    Selftest(SelftestArgs),
    /// Work on the policy file itself.
    Policy(PolicyCmd),
    /// Check a buildclamp attestation, without checking its signature.
    ///
    /// # What it checks, and what it leaves to cosign
    ///
    /// It checks, **itself**, that the document is an in-toto Statement v1, that its
    /// `predicateType` is buildclamp's — rather than trusting a `--type` flag, which is the
    /// shape of CVE-2022-35929, where cosign returned success when no attestation of the
    /// requested type existed at all — that the subject digest is the artefact you pointed
    /// at, and that the policy and report hashes are the files you pointed at.
    ///
    /// It does **not** check the signature, and it says so on every run rather than leaving
    /// it to be discovered. `cosign verify-attestation` and `gh attestation verify` are the
    /// tools for that, they are free, and the free buildclamp binary links no cryptography
    /// and no network client — a property CI asserts. The two halves are genuinely
    /// separable, and the half this does is the one that catches laundering: a
    /// cryptographically perfect signature over a statement about a different artefact, or
    /// over a run with reads unrestricted, is still the wrong document.
    ///
    /// Exit codes are the usual three: `0` the statement checks out, `2` it does not, `1`
    /// the check could not be carried out.
    Verify(VerifyArgs),
    /// Write an `[[exception]]` — the unblock path that needs nobody's approval.
    ///
    /// For 17:00 on the day a dependency bump turns the build red. It appends a block to
    /// `buildclamp.toml` that stands the refusal down for one crate until a date at most a
    /// week out, fills the author in from your git identity, and refuses to write anything
    /// without a reason.
    ///
    /// It needs no account, no network and no server, and nothing outside this
    /// repository can take it away. Other tooling may add *visibility* — who is breaking
    /// glass, across an estate — and the ability to shorten or forbid it org-wide. Never
    /// the ability to unblock at all: a tool that can block and cannot unblock is one
    /// people unhook.
    Except(ExceptArgs),
    /// Remove buildclamp's shims from a target directory.
    ///
    /// Restores each real build script. Not usually needed — changing the wrapper already
    /// changes every fingerprint — but a tool that can only be added is one people are
    /// reluctant to try.
    Unhook(UnhookArgs),
}

#[derive(Args, Debug, Clone)]
pub struct PolicyCmd {
    #[command(subcommand)]
    pub what: PolicyAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum PolicyAction {
    /// Rewrite a policy at the current format version.
    ///
    /// Only the version number changes. There is no semantic difference between a version 1
    /// policy and the version 2 this writes — composition is opt-in, through a `[layer]`
    /// table a migration has no business inventing — so this is a one-line edit you could
    /// make by hand, and it exists so that nobody has to wonder whether it is.
    ///
    /// **A v1 policy keeps working without it.** Only the future is refused; the past is
    /// read and upgraded in memory on every run. Migrating is how you stop seeing the note
    /// saying so, not how you keep your build working.
    Migrate(MigrateArgs),
}

#[derive(Args, Debug, Clone)]
pub struct MigrateArgs {
    /// The policy to migrate. Defaults to `buildclamp.toml` beside the workspace manifest.
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Print the migrated file instead of writing it.
    ///
    /// Worth using first. The rewrite goes through the parser and the serialiser, so
    /// comments and key order do not survive it — see the note the command prints.
    #[arg(long)]
    pub stdout: bool,
}

#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    /// The attestation: a DSSE envelope, or a bare in-toto Statement.
    ///
    /// A bare Statement is accepted because that is what `cosign verify-attestation` hands
    /// its caller once it has checked the signature. Refusing it would mean nobody could
    /// chain the two, which is exactly the workflow this command is for.
    pub file: PathBuf,

    /// The artefact the statement should be about. Hashed here and compared with the
    /// statement's subject digest.
    #[arg(long, value_name = "FILE")]
    pub artefact: Option<PathBuf>,

    /// The policy the statement should have been made under.
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// The report the statement should be about.
    #[arg(long, value_name = "FILE")]
    pub report: Option<PathBuf>,

    /// A file of errata — signed corrections saying that statements matching some criteria
    /// overstate a tier. Repeatable.
    ///
    /// **Supplied locally, never fetched.** A verifier that reached the network to decide
    /// would be unusable in the air-gapped case this tool is built for, and would put the
    /// vendor's availability in the customer's verification path.
    #[arg(long = "erratum", value_name = "FILE")]
    pub errata: Vec<PathBuf>,

    /// Require the statement to describe a fully enforced run.
    ///
    /// False unless **both** optional hardenings were on, nothing was switched off, and
    /// every capability's weakest tier was `enforced:`. That is what makes the attestation
    /// something other than a laundering machine for the gaps the README documents: a run
    /// with `withhold-secret-reads` off produces tiers that all say `enforced:`, truthfully,
    /// about the capabilities that were held — while a build script read every credential
    /// file on the host.
    #[arg(long)]
    pub require_fully_enforced: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ExceptArgs {
    /// The crate to stand the refusal down for. One name, never a pattern.
    pub crate_name: String,

    /// What happened that made refusing unacceptable today. Required.
    ///
    /// Not what the crate does — the grant's `why` is for that — but what this is instead
    /// of, and where the work went. "release blocked, INFRA-4412 tracks pinning the
    /// vendored source" is the shape; "temporary" is not, and the tool cannot tell the
    /// difference, so this is the one thing it cannot fill in for you.
    #[arg(long)]
    pub reason: String,

    /// How many days it should last. Defaults to 1, and capped at 7.
    ///
    /// One by default because the common case is getting through the evening, and an
    /// exception that outlives its incident is one nobody deletes.
    #[arg(long, value_name = "DAYS", default_value_t = 1)]
    pub days: u32,

    /// Narrow it to specific capabilities — `--capability net`, repeatable.
    ///
    /// Left off, the block covers whatever that crate asks for. That is the honest default
    /// for the moment it is written in: the person unblocking knows which crate went red
    /// and often not yet which of its requests did.
    #[arg(long = "capability", value_name = "NAME")]
    pub capabilities: Vec<String>,

    /// Who is breaking the glass. Defaults to the checkout's git identity.
    ///
    /// Self-asserted either way, and the format says so rather than implying an
    /// attestation: what makes an exception accountable is that it is a committed block
    /// with a diff and an expiry, not that this string is verified.
    #[arg(long)]
    pub author: Option<String>,

    /// Path to the policy. Defaults to `buildclamp.toml` beside the workspace manifest.
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Print the block instead of appending it.
    #[arg(long)]
    pub stdout: bool,
}

#[derive(Args, Debug, Clone)]
pub struct SelftestArgs {
    /// Run the command with the network denied and fail if it asked for it.
    ///
    /// # What this proves, and what it does not
    ///
    /// It proves that **this invocation of this binary, on this machine, opened no
    /// socket** — observed by the kernel, through the same enforcement a held build script
    /// gets, and reported with the tier that achieved it.
    ///
    /// It does not prove the binary *cannot*. A code path nothing exercised here could
    /// still contain a client, which is why it is the second of two checks and not the
    /// only one: `ops/no-network-closure.sh` walks the resolved `cargo tree -e normal`
    /// closure of each published binary and fails if a client is LINKED at all. The
    /// closure check cannot observe behaviour and this cannot observe unreached code, so
    /// neither is the other and neither is dropped.
    ///
    /// ADR-0005 states the narrow version of the claim that both of these serve: it is
    /// about linking, not about behaviour, and the free binary spawns `cargo`, which
    /// downloads crates. At the process level the tool has always been one `exec` from the
    /// network.
    #[arg(long)]
    pub no_network: bool,

    /// The command to run. Defaults to this binary printing what the host can enforce.
    ///
    /// Anything after `--`, so a negative fixture can be pointed at: a binary that does
    /// reach the network must fail this, and a check nobody has watched fail is not a
    /// check.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND"
    )]
    pub command: Vec<String>,
}

/// Options shared by every command that runs cargo.
#[derive(Args, Debug, Clone)]
pub struct CargoArgs {
    /// Path to the policy. Defaults to `buildclamp.toml` beside the workspace manifest.
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Fail if any grant is still `reviewed = false`.
    ///
    /// What CI should use once a policy has been through review. It is the mechanism
    /// that stops `init`'s output from quietly becoming permanent.
    #[arg(long)]
    pub strict: bool,

    /// Fail if any capability could only be constrained advisorily on this host.
    ///
    /// A green build on a machine where nothing could actually be enforced is the false
    /// assurance this tool exists to avoid, so CI can refuse to accept one.
    #[arg(long)]
    pub require_enforced: bool,

    /// Refuse a build whose distributed policy layers are not signed by a key in the
    /// repository's committed `trust-root`.
    ///
    /// `policy_sha256` proves a layer is byte-identical to what was recorded; it cannot prove
    /// the layer came from someone allowed to write it. This adds that: an `extends`ed layer
    /// — an org policy, a curl'd bundle — must carry a detached `<path>.sig` made by a trusted
    /// key, or the build is refused before it starts. The committed `buildclamp.toml` itself
    /// is trusted because it is committed under CODEOWNERS, not by a signature, so a
    /// repository with no distributed layers has nothing to refuse. Checked before the build,
    /// like every other policy error, not after a target directory is half written.
    #[arg(long)]
    pub require_signed_policy: bool,

    /// Record every write a held unit makes, not only the ones the policy refused.
    ///
    /// Off by default because each notified syscall costs 10 to 40 microseconds —
    /// measured on this project's own host — and a build script that generates a large
    /// table makes thousands of them.
    ///
    /// It belongs to every mode rather than to `observe` alone, which is where it used
    /// to live and where it could not do anything: an observe run already notifies every
    /// write, because notification is the only way it can see one. The flag's effect is
    /// on an ENFORCING run, where the filesystem tier is a mount namespace or Landlock —
    /// there the kernel refuses the writes outside the envelope and the permitted ones
    /// are never seen at all, so the report shows what was stopped and not what was
    /// done. `--deep` is how you see the second list.
    ///
    /// It does NOT reach inside a compile unit. Compile units are not held in this
    /// version, so no flag can record what a proc-macro touched; see the README.
    #[arg(long)]
    pub deep: bool,

    /// Warn rather than fail on a grant first seen in the last N days.
    ///
    /// The pressure valve for the failure that removes this tool from a pipeline: a
    /// transitive dependency bump adds a capability, the build goes red at 17:00, and the
    /// only way forward is to approve a third-party build script under time pressure. With
    /// a window, the ordinary flow — bump, red build, `cargo buildclamp init`, commit,
    /// file a ticket — is not also blocked on the review happening the same afternoon.
    ///
    /// It only ever affects `--strict`, and only for grants `init` dated. A grant with no
    /// `first-seen` gets no grace at all, so `--grace 30` on a year-old unreviewed policy
    /// excuses exactly nothing — which is what stops this becoming a way never to review.
    /// It does not touch an ungranted request: a capability nothing has written down still
    /// fails, because a warning about a build that was never recorded is not a record.
    /// `[[exception]]` is the instrument for that, and `cargo buildclamp except` writes one.
    #[arg(long, value_name = "DAYS")]
    pub grace: Option<u32>,

    /// Where to write the report. Defaults to `<target>/buildclamp/report.json`.
    #[arg(long, value_name = "FILE")]
    pub report: Option<PathBuf>,

    /// Everything after `--` goes to cargo unchanged.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "CARGO_ARGS"
    )]
    pub cargo_args: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ObserveArgs {
    #[command(flatten)]
    pub common: CargoArgs,

    /// Exit 2 if the recorded run would have had an ungranted request under enforcement.
    ///
    /// Lets a pipeline watch for capability drift without enforcing anything yet.
    #[arg(long)]
    pub gate: bool,
}

#[derive(Args, Debug, Clone)]
pub struct InitArgs {
    /// The report to read. Defaults to the last run's.
    #[arg(long, value_name = "FILE")]
    pub from: Option<PathBuf>,

    /// Where to write. Defaults to `buildclamp.toml` beside the workspace manifest.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,

    /// Overwrite an existing policy.
    ///
    /// Refused by default. Overwriting a reviewed policy with generated grants — every
    /// one of them `reviewed = false` — would undo exactly the work the file exists to
    /// record.
    #[arg(long)]
    pub force: bool,

    /// Mark grants reviewed where a published baseline vouches for that exact version.
    ///
    /// What makes `--strict` reachable on the first day. A first `init` on a real graph
    /// writes a couple of hundred grants, all unreviewed, and nobody reads two hundred
    /// build scripts in an afternoon — so the realistic outcomes without this are
    /// `--strict` never being turned on, or somebody setting every `reviewed` to true
    /// with `sed`. Both leave a gate that gates nothing.
    ///
    /// Three rules keep it from being a rubber stamp. It matches the **exact** version and
    /// pins the grant it writes to that version, so a patch bump does not inherit an
    /// approval nobody made. It only ever narrows: a crate that did something the baseline
    /// does not describe stays unreviewed, and the acceptance cannot add a capability to a
    /// grant. And it records the document's digest in the policy as the reviewer of
    /// record, so a reader can tell which baseline vouched.
    ///
    /// The last line `init` prints is the residual: how many grants are still unreviewed
    /// after the baseline. That number is the measure of whether a baseline is worth
    /// anything — one that accepts everything is one nobody checked.
    #[arg(long, value_name = "FILE")]
    pub accept_baseline: Option<PathBuf>,

    /// Print to stdout instead of writing a file.
    #[arg(long)]
    pub stdout: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ExplainArgs {
    /// The crate to explain.
    pub crate_name: String,

    /// Its version, when a grant is version-qualified.
    #[arg(long)]
    pub version: Option<String>,

    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Print the environment names this crate would not see, and why.
    #[arg(long)]
    pub env: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ReportArgs {
    /// The report to read. Defaults to the last run's.
    #[arg(long, value_name = "FILE")]
    pub from: Option<PathBuf>,

    /// Emit the raw JSON rather than the human summary.
    #[arg(long, conflicts_with = "markdown")]
    pub json: bool,

    /// Emit a GitHub-flavoured markdown summary, for a CI job summary or a PR comment.
    ///
    /// Bounded on purpose. A first `init` on a real estate can produce a couple of hundred
    /// grants, and GitHub's own limits are low — roughly fifty annotations per update, of
    /// which about ten are surfaced — so a summary that tried to list everything would be
    /// truncated by the platform at whatever point it happened to reach, which is the
    /// worst way to lose information. This prints the findings that matter, says how many
    /// it left out, and points at the report on disk for the rest.
    #[arg(long, conflicts_with = "json")]
    pub markdown: bool,

    /// Show every unit, not only those with ungranted requests.
    #[arg(long)]
    pub all: bool,
}

#[derive(Args, Debug, Clone)]
pub struct DoctorArgs {
    /// Emit the probe results as JSON instead of the table.
    ///
    /// The table is for a person deciding whether to trust a green build; this is for
    /// anything that has to *branch* on the answer — a CI step, a fleet inventory, or
    /// this project's own end-to-end suite.
    ///
    /// It exists because the suite used to decide whether the host could enforce by
    /// matching the rendered table with a fixed-width string. The column was one space
    /// narrower than the pattern, so the match failed on every host, every test skipped
    /// everywhere, and the suite reported "7 passed" having asserted nothing — the
    /// false assurance this whole tool exists to prevent, inside its own tests. A
    /// consumer that needs to branch gets a parsed object, not a column layout.
    ///
    /// The shape is `HostCapabilities` exactly as it appears under `host` in
    /// `report.json`, so there is one schema for the host and not two.
    #[arg(long)]
    pub json: bool,

    /// The enforcement floor this lane requires, and fail if this host cannot reach it.
    ///
    /// `--require net=enforced,fs-write=enforced`, or a bare `--require enforced` to mean
    /// every capability. Exit 2 when the host falls short.
    ///
    /// It exists because `--require-enforced` is checked at the END of a build, against
    /// what happened. That is the right place for it and it is the wrong place to learn
    /// that the *lane* cannot enforce: a container image that lost `CAP_SYS_ADMIN`, an
    /// Ubuntu host with `apparmor_restrict_unprivileged_userns=1`, a runner whose seccomp
    /// profile denies `unshare` — each quietly turns an enforcing lane into an advisory
    /// one, and the build stays green because advisory enforcement still runs the build.
    /// Nobody is told the control stopped controlling.
    ///
    /// So the lane declares its floor and the declaration is checked in seconds, before a
    /// test runs, and a lane that cannot meet it fails as what it is: misconfigured.
    #[arg(long, value_name = "TIER_SET")]
    pub require: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct UnhookArgs {
    /// The target directory to clean. Defaults to this workspace's.
    #[arg(long, value_name = "DIR")]
    pub target_dir: Option<PathBuf>,
}

impl Command {
    /// The cargo subcommand this maps to, for the commands that run one.
    pub fn cargo_subcommand(&self) -> Option<&'static str> {
        match self {
            Command::Build(_) => Some("build"),
            Command::Check(_) => Some("check"),
            Command::Test(_) => Some("test"),
            Command::Bench(_) => Some("bench"),
            Command::Doc(_) => Some("doc"),
            Command::Install(_) => Some("install"),
            Command::Publish(_) => Some("publish"),
            Command::Clippy(_) => Some("clippy"),
            // Observe runs a check rather than a build: it is the cheapest cargo
            // subcommand that still compiles and runs every build script and every
            // proc-macro, which is the whole population being observed. Someone
            // measuring a release build passes `-- --release` and gets it.
            Command::Observe(_) => Some("check"),
            _ => None,
        }
    }

    /// The options shared with cargo-running commands, when this is one.
    pub fn cargo_args(&self) -> Option<&CargoArgs> {
        match self {
            Command::Build(a)
            | Command::Check(a)
            | Command::Test(a)
            | Command::Bench(a)
            | Command::Doc(a)
            | Command::Install(a)
            | Command::Publish(a)
            | Command::Clippy(a) => Some(a),
            Command::Observe(o) => Some(&o.common),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_clap_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn cargo_arguments_after_a_double_dash_reach_cargo_unchanged() {
        // Someone will need `--release`, `--features`, `-p`, `--target`. Swallowing or
        // re-interpreting any of them would make the tool unusable on a real workspace.
        let cli = Cli::try_parse_from([
            "cargo buildclamp",
            "build",
            "--strict",
            "--",
            "--release",
            "-p",
            "mycrate",
            "--features",
            "a,b",
        ])
        .unwrap();
        let Command::Build(a) = cli.command else {
            panic!()
        };
        assert!(a.strict);
        assert_eq!(
            a.cargo_args,
            vec!["--release", "-p", "mycrate", "--features", "a,b"]
        );
    }

    #[test]
    fn every_cargo_verb_this_tool_wraps_maps_to_the_verb_of_the_same_name() {
        // Except `observe`, which is a mode rather than a verb and is pinned separately
        // below. A subcommand that ran a DIFFERENT cargo verb than it is named for would
        // hold the wrong population of units and nothing would say so.
        for verb in [
            "build", "check", "test", "bench", "doc", "install", "publish", "clippy",
        ] {
            let cli = Cli::try_parse_from(["cargo buildclamp", verb]).unwrap();
            assert_eq!(
                cli.command.cargo_subcommand(),
                Some(verb),
                "`{verb}` must run `cargo {verb}`"
            );
            assert!(
                cli.command.cargo_args().is_some(),
                "`{verb}` must accept the shared cargo options"
            );
        }
    }

    #[test]
    fn install_takes_a_crate_name_without_needing_a_double_dash() {
        // `cargo buildclamp install ripgrep` is how a person would type it, and the whole
        // reason the subcommand exists is the crate you have not read. Requiring `--`
        // before the name would make the common case the awkward one.
        let cli = Cli::try_parse_from(["cargo buildclamp", "install", "ripgrep"]).unwrap();
        let args = cli.command.cargo_args().expect("install takes cargo args");
        assert_eq!(args.cargo_args, vec!["ripgrep"]);
    }

    #[test]
    fn buildclamps_own_flags_are_still_its_own_on_the_new_subcommands() {
        // `--strict` belongs to buildclamp and `--path` belongs to cargo, and they arrive
        // in the same argument list. If `--strict` were swallowed into the trailing args
        // it would reach cargo, which does not have it, and the run would fail for a
        // reason nobody could read.
        let cli = Cli::try_parse_from(["cargo buildclamp", "install", "--strict", "--path", "."])
            .unwrap();
        let args = cli.command.cargo_args().unwrap();
        assert!(args.strict, "--strict is buildclamp's");
        assert_eq!(args.cargo_args, vec!["--path", "."], "--path is cargo's");
    }

    #[test]
    fn observe_runs_a_check_because_that_still_runs_every_build_script() {
        let cli = Cli::try_parse_from(["cargo buildclamp", "observe"]).unwrap();
        assert_eq!(cli.command.cargo_subcommand(), Some("check"));
    }

    #[test]
    fn the_commands_that_do_not_run_cargo_say_so() {
        for args in [
            vec!["cargo buildclamp", "doctor"],
            vec!["cargo buildclamp", "explain", "serde"],
            vec!["cargo buildclamp", "report"],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert_eq!(cli.command.cargo_subcommand(), None);
        }
    }

    #[test]
    fn every_subcommand_clap_knows_is_one_the_role_detector_also_knows() {
        // The role detector tells a person's subcommand from cargo handing us a compiler
        // path. A subcommand clap accepts but the detector does not would be read as a
        // compiler and silently mangled.
        let known = buildclamp_shim::roles::DRIVER_SUBCOMMANDS;
        for sub in Cli::command().get_subcommands() {
            let name = sub.get_name();
            assert!(
                known.contains(&name),
                "`{name}` is a clap subcommand but not in DRIVER_SUBCOMMANDS"
            );
        }
    }
}
