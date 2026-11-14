//! `buildclamp.toml`: the policy, its parse rules, and how a unit's envelope is
//! resolved from it.
//!
//! # The shape
//!
//! ```toml
//! version = 1
//!
//! [defaults]
//! mode = "enforce"                  # "observe" | "enforce"
//! trust_workspace = false
//!
//! # A grant is a normal, expected, first-class entry. A project with fifty grants is a
//! # correctly configured project, not a compromised one.
//! [grants."openssl-sys"]
//! version = ">=0.9, <0.10"
//! capabilities = ["fs-write", "exec"]
//! write-zones = ["out-dir", "tmp"]
//! env-allow = ["OPENSSL_DIR", "OPENSSL_LIB_DIR"]
//! why = "pkg-config plus cc; writes only under OUT_DIR"
//! reviewed = true
//! ```
//!
//! # Two rules that are not negotiable
//!
//! **`why` is required and may not be empty.** This is the `cargo-vet` ergonomic
//! applied to capabilities instead of to review: the cost of widening an envelope is
//! that somebody has to write a sentence a colleague will read in a pull request. A
//! grant without one is a parse error, before any unit runs, because a grant that
//! silently appeared in a diff is the failure mode the whole file exists to prevent.
//!
//! **Ambiguity is an error, not a last-one-wins.** Two grants for the same crate at the
//! same specificity is a policy whose meaning depends on file order, and a security
//! policy whose meaning depends on file order is a bug waiting for a merge conflict to
//! trigger it. Specificity is well defined — a version-qualified grant beats an
//! unqualified one — so ties are only possible when a policy is genuinely ambiguous.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::baseline::BaselineRef;
use crate::breakglass::{BreakGlass, Exception, Grace, GraceNote, Unreviewed, MAX_EXCEPTION_DAYS};
use crate::capability::{Capability, CapabilitySet};
use crate::civil::Date;
use crate::envelope::{Envelope, EnvelopeSource, WriteZone};
use crate::layer::LayerDecl;
use crate::unit::{UnitId, UnitKind};
use crate::wire::Forward;

/// The policy format version. Bumped only for a change that an older buildclamp would
/// misread — a tool that silently ignores rules it does not understand is worse than
/// one that refuses to run.
///
/// # 2 — composition
///
/// Version 1 was one flat file with no `include`, `extends`, `inherit` or `import`
/// anywhere. A security team's actual sentence — "no build script in this organisation
/// reaches the network, and here are the nine crates that may" — had nowhere to live, so it
/// got said in a wiki and enforced by nobody. `[layer]` is where it lives; see
/// [`crate::layer`].
///
/// A v1 file **still parses**, and that is the whole point of moving the number: a version
/// that refused every file in the field would be a migration nobody performs. The rule is
/// the report's, which has worked since format version 2 landed — **only the future is
/// refused.** A v1 policy is read, upgraded in memory, and `cargo buildclamp policy
/// migrate` writes the upgraded file when somebody is ready.
///
/// [`OLDEST_POLICY_VERSION`] is how far back that goes, and `crates/core/tests/golden` is
/// what keeps it true.
pub const POLICY_VERSION: u32 = 2;

/// The oldest policy format this build still reads.
///
/// A number rather than a `1` written into three conditions, because the day it moves is
/// the day every file at that version stops working, and that decision should be visible in
/// one place with the release policy's compatibility window beside it.
pub const OLDEST_POLICY_VERSION: u32 = 1;

/// How a run treats an ungranted request.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Record everything, refuse nothing. The first thing anyone runs, and the only way
    /// a real repository adopts this without a week of breakage.
    Observe,
    /// Refuse ungranted requests and fail the unit.
    #[default]
    Enforce,
    /// **The kill switch.** Hold nothing, refuse nothing, record that this happened.
    ///
    /// A vendor binary sitting in every build needs an emergency-off that is not a
    /// per-mechanism debug knob, and a platform team asks for it before they ask what the
    /// tool does. `BUILDCLAMP_DISABLE` is not that switch: it takes away one mechanism at
    /// a time, it exists so the fallback tiers are testable on a host that has
    /// everything, and its name does not say what a reader of a report needs to know.
    ///
    /// The rule that makes this safe to ship is that **the switch can never be silent.**
    /// A run in this mode still produces a report, and that report says enforcement was
    /// off and who turned it off. An emergency exit that leaves no trace is
    /// indistinguishable from a tool that was never installed, and six months later
    /// nobody can tell which builds were held.
    Off,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Observe => "observe",
            Mode::Enforce => "enforce",
            Mode::Off => "off",
        }
    }
}

/// The environment names scrubbed from every build unit unless a grant re-admits them.
///
/// This list is a default, replaceable wholesale by `defaults.env-deny`. It is
/// deliberately pattern-based and deliberately broad: the cost of scrubbing a variable
/// a build script wanted is a clear failure a grant fixes, and the cost of missing one
/// is a credential in someone else's hands.
///
/// Patterns support a single leading and/or trailing `*`. Anything more expressive
/// would need a glob dependency and would let a policy author write a pattern they
/// cannot predict the behaviour of.
pub const DEFAULT_ENV_DENY: &[&str] = &[
    "*_TOKEN",
    "*_SECRET",
    "*_PASSWORD",
    "*_API_KEY",
    "*_ACCESS_KEY",
    "*_CREDENTIALS",
    "*_PRIVATE_KEY",
    "AWS_*",
    "AZURE_*",
    "GCP_*",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "ACTIONS_*",
    "CARGO_REGISTRY_TOKEN",
    "CARGO_REGISTRIES_*",
    "NPM_TOKEN",
    "DOCKER_PASSWORD",
    "VAULT_TOKEN",
    "SSH_AUTH_SOCK",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
];

/// The environment a build unit keeps when `env-allowlist` is on.
///
/// # Why an allowlist needs a base set at all
///
/// Cargo communicates with a build script almost entirely through the environment: which
/// features are on, which target triple, where `OUT_DIR` is, what the profile is, what the
/// linked system libraries said. A literal allowlist — nothing but what the policy names —
/// would not survive the first build of anything, and the build script would fail with a
/// missing-variable panic rather than anything a person could connect to this tool.
///
/// So the base is "what cargo and the toolchain set, plus the handful of system variables a
/// compiler needs to run", and a grant's `env-allow` adds to it. Everything else — every
/// variable a CI system exported, every one in the developer's shell — is gone.
///
/// # This narrows and never widens
///
/// The deny-list runs **first** and independently. `CARGO_*` is in the base set and
/// `CARGO_REGISTRY_TOKEN` starts with it, so a base set applied on its own would re-admit a
/// credential the deny-list exists to remove. It cannot: a name the deny-list scrubs stays
/// scrubbed whatever this list says, and the allowlist can only take further names away.
/// The test named for it is what keeps that true.
pub const ENV_ALLOWLIST_BASE: &[&str] = &[
    // What cargo tells a build script. `CARGO_*` covers CARGO_PKG_*, CARGO_FEATURE_*,
    // CARGO_CFG_*, CARGO_MANIFEST_DIR and the rest; the deny-list takes the token-shaped
    // ones back out.
    "CARGO",
    "CARGO_*",
    "OUT_DIR",
    "TARGET",
    "HOST",
    "NUM_JOBS",
    "OPT_LEVEL",
    "DEBUG",
    "PROFILE",
    "DEP_*",
    // The toolchain.
    "RUSTC",
    "RUSTC_*",
    "RUSTDOC",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_*",
    // This tool's own wrapper protocol. Without these a held unit cannot find its policy
    // or write its record, and the run reports nothing at all.
    "BUILDCLAMP_*",
    // What a compiler needs to be a compiler. `PATH` above all: without it `cc`,
    // `pkg-config` and `git` cannot be found and every `-sys` crate fails.
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LANGUAGE",
    "LC_*",
    "TERM",
    "PWD",
    // Reproducible builds set this and a build script that stamps a date reads it.
    "SOURCE_DATE_EPOCH",
];

/// Names that a plain `env-allow` cannot re-admit.
///
/// These are the ones whose presence in a build script's environment has no innocent
/// explanation. A grant can still re-admit them, but only by also setting
/// `env-allow-secrets = true`, which exists to make that choice loud in a diff rather
/// than to make it impossible — a tool that cannot express what a user actually needs
/// gets replaced by no tool at all.
pub const HARD_DENY: &[&str] = &[
    "GITHUB_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "CARGO_REGISTRY_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "VAULT_TOKEN",
    "NPM_TOKEN",
];

/// One entry in `[grants."<crate>"]`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Grant {
    /// A semver requirement the unit's version must satisfy. Absent means any version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The capabilities this grant confers. Replaces the defaults, never adds to them:
    /// a reader of the policy should be able to see the whole envelope in one place
    /// rather than compose it in their head.
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub write_zones: Vec<WriteZone>,
    #[serde(default)]
    pub write_paths: Vec<String>,
    #[serde(default)]
    pub env_allow: Vec<String>,
    /// Permit `env-allow` to re-admit a name from [`HARD_DENY`].
    #[serde(default)]
    pub env_allow_secrets: bool,
    /// Destinations expected for this unit. **Reported, never enforced** — see
    /// [`crate::envelope::Envelope::net_destinations`].
    #[serde(default)]
    pub net_destinations: Vec<String>,
    /// Why this grant exists. Required, non-empty.
    pub why: String,
    /// Whether a human has read this grant. `init` writes `false`.
    #[serde(default)]
    pub reviewed: bool,

    /// The day this grant was first written, `YYYY-MM-DD`. What `--grace` measures from.
    ///
    /// Written by `init`, never by anything that reviews. It records when the tool first
    /// saw a crate need this envelope, which is the only thing a grace window can
    /// honestly be counted from — a grant's age is not the same as the age of the
    /// capability, and this says which one it is.
    ///
    /// **Absent is not a synonym for new.** A grant with no date gets no grace at all,
    /// which is what makes `--grace 30` on a year-old policy excuse nothing. See
    /// [`crate::Grace::covers`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
}

/// The `[defaults]` table.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Defaults {
    #[serde(default)]
    pub mode: Mode,
    /// Run the workspace's own build scripts unheld.
    ///
    /// `false` by default, and that default is an argument rather than caution. The
    /// threat this tool addresses is code you did not write arriving through a
    /// dependency, and a workspace member is code you did write — but "you wrote it" is
    /// exactly what a compromised maintainer account also looks like from inside a
    /// monorepo, and a workspace member's build script is the easiest place for an
    /// attacker with commit access to hide. Holding it costs nothing when it is honest.
    #[serde(default)]
    pub trust_workspace: bool,
    /// Replaces [`DEFAULT_ENV_DENY`] entirely when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_deny: Option<Vec<String>>,

    /// Withhold the credential paths in [`crate::WITHHELD_READ_PATHS`] from build units.
    ///
    /// **Off by default, and that is a decision with a date on it rather than an
    /// oversight.** Reads have been unrestricted since this tool existed, the README said
    /// so, and turning a default-deny on underneath existing users would break builds that
    /// worked yesterday for a reason they did not change. It ships opt-in, the break rate
    /// gets measured on real graphs, and making it default is a separate decision with a
    /// named release and a numeric threshold behind it.
    ///
    /// With it off, every unit is granted [`Capability::FsRead`] outright — which is the
    /// literal truth, not a formality: nothing withholds any read, so every unit may read
    /// everything, and a report that showed the capability as ungranted would be
    /// describing a restriction that is not in force.
    #[serde(default, rename = "withhold-secret-reads")]
    pub withhold_secret_reads: bool,

    /// Give build units only [`ENV_ALLOWLIST_BASE`] plus what a grant names, instead of
    /// everything minus the deny-list.
    ///
    /// **Off by default, and opt-in for the same reason withholding reads is.** The
    /// deny-list is what every existing user's builds pass under; switching to an allowlist
    /// underneath them would break a build that reads some ordinary variable nobody wrote
    /// down, and it would break it with a missing-variable panic from inside a dependency.
    ///
    /// The two combine rather than replace: the deny-list still runs, so this can only
    /// take further names away. `cargo-acl`'s `--clearenv` allowlist is stronger than a
    /// deny-scrub, which it is — a deny-list cannot know about
    /// a credential variable nobody has thought of, and an allowlist does not have to.
    #[serde(default, rename = "env-allowlist")]
    pub env_allowlist: bool,

    /// Hold the rustc invocations where proc-macros expand, not only build scripts.
    ///
    /// **Off by default, and this is the setting whose default costs the most to get
    /// wrong.** A build script is one process per crate that has one; a compile unit is
    /// every rustc in the graph, and rustc opens thousands of files. Holding all of them
    /// changes the cost of a build rather than adding to it, which is why the overhead
    /// measurement is the gate for making this default and not the gate for shipping it.
    ///
    /// What it buys: proc-macro expansion happens inside the rustc compiling the
    /// *consumer*, so nothing that only holds build scripts sees it at all. That is the
    /// half of the threat a build-script-only tool misses entirely.
    ///
    /// What it does not buy, said here because the README must not imply otherwise: **one
    /// shared policy per compilation**, not per macro. Expansion happens inside a process
    /// that has already loaded every proc-macro in the closure, so a refusal names the
    /// compilation and the macros that could have been responsible. That is what
    /// `cargo-acl` does too, and `docs/adr/0004` argues why it is worth shipping anyway.
    #[serde(default, rename = "hold-compile-units")]
    pub hold_compile_units: bool,

    /// How many `[[exception]]` blocks may be live at once before the policy is refused.
    ///
    /// Defaults to [`crate::DEFAULT_ACTIVE_EXCEPTION_CAP`]. Raising it is a one-line edit
    /// in the same file, and the refusal names this key so that the person who hits the
    /// cap at 17:00 can see their way past it without reading the documentation. Lowering
    /// it to `0` forbids break-glass in this repository entirely, which is a legitimate
    /// thing for a team to decide about their own policy.
    #[serde(
        default = "default_active_exception_cap",
        rename = "max-active-exceptions"
    )]
    pub max_active_exceptions: usize,

    /// Ed25519 public keys, base64, that this repository trusts to have signed a policy
    /// layer it pulls in through `extends`.
    ///
    /// The authority half of policy distribution: `policy_sha256` proves a layer is
    /// byte-identical to what was recorded, but a curl'd bundle hashes the same as a
    /// committed one, so a hash cannot say a layer came from someone allowed to write it. A
    /// trust root can. It belongs in the **committed** anchor policy — the `buildclamp.toml`
    /// in the repository, protected by CODEOWNERS — because that file's authority comes from
    /// being reviewed in the repository, not from a signature, and it is what vouches for
    /// the distributed layers beneath it. A distributed layer carries a detached
    /// `<layer>.sig`, and `--require-signed-policy` refuses any extended layer that no key
    /// here verifies. Empty by default: a repository that has not adopted signed policy.
    ///
    /// Several keys are allowed so a customer can rotate without a window where builds
    /// break — publish the new key, re-sign, retire the old. Each is validated at parse, so
    /// a malformed key is a policy error rather than a silent verification failure later.
    #[serde(default, rename = "trust-root", skip_serializing_if = "Vec::is_empty")]
    pub trust_root: Vec<String>,
}

fn default_active_exception_cap() -> usize {
    crate::breakglass::DEFAULT_ACTIVE_EXCEPTION_CAP
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            mode: Mode::Enforce,
            trust_workspace: false,
            env_deny: None,
            withhold_secret_reads: false,
            env_allowlist: false,
            hold_compile_units: false,
            max_active_exceptions: crate::breakglass::DEFAULT_ACTIVE_EXCEPTION_CAP,
            trust_root: Vec::new(),
        }
    }
}

/// A parsed `buildclamp.toml`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    /// The oldest buildclamp that can honour this file, as a semantic version.
    ///
    /// # Why this is not the same thing as `version`
    ///
    /// `version` moves when the *format* changes shape. It is deliberately slow to move —
    /// `deny_unknown_fields` means most additions need no bump at all — and that is the
    /// right trade for a file people edit by hand.
    ///
    /// What it cannot express is the far more common case: the format is unchanged and
    /// the file relies on behaviour a given binary does not have. A grant with
    /// `net-destinations` written for an agent that records destinations but has never
    /// enforced them, read by an older agent, parses perfectly and grants something
    /// nobody meant. The failure is silent, it is in the permissive direction, and no
    /// format version can catch it, because the format did not change.
    ///
    /// So a policy author who needs a floor states one, and an older agent refuses by
    /// name — "this file needs 0.4, you are running 0.2" — instead of parsing it and
    /// being wrong quietly. `init` writes the version that generated the file.
    ///
    /// Optional, and absent means no floor: a hand-written policy must not have to carry
    /// a version number to work.
    // `rename` to the kebab-case spelling `docs/CONFIG.md` documents and the one every other
    // struct here uses; `alias` keeps the snake_case spelling that the golden fixtures and
    // early files were written with. Without the rename, `deny_unknown_fields` on this struct
    // rejected the documented `min-tool-version` outright — and the probe below missed it too,
    // so the tool floor a policy declared was silently not enforced.
    #[serde(
        default,
        rename = "min-tool-version",
        alias = "min_tool_version",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_tool_version: Option<String>,
    /// An org-wide off switch that travels with the policy.
    ///
    /// Reserved here so the format does not break when central policy distribution lands:
    /// `deny_unknown_fields` above means a release that had never heard of this key would
    /// reject a whole bundle carrying it, which would make the switch undeployable
    /// exactly when it is needed.
    ///
    /// **The roadmap reserved this to be parsed and ignored. It is honoured instead**,
    /// because a key named `enforcement = "disabled"` that silently does nothing is the
    /// defect this project keeps finding in itself — a control that looks present
    /// wherever a reader would check. Honouring it is also the smaller risk: editing
    /// `buildclamp.toml` needs commit access, which is a *narrower* set of people than
    /// those who can set an environment variable in CI, and every use is recorded in the
    /// report's `disable_overrides` either way.
    #[serde(default)]
    pub enforcement: Option<Enforcement>,
    #[serde(default)]
    pub defaults: Defaults,
    /// Keyed by crate name. A crate needing two different envelopes at two versions has
    /// two entries under one key via [`Grant::version`] — see [`Grants`].
    #[serde(default)]
    pub grants: BTreeMap<String, Grants>,

    /// Break-glass. Each block names one crate, one reason, one person and one date.
    ///
    /// Singular because that is how TOML spells an array of tables: the blocks in the
    /// file are written `[[exception]]`, and a key named `exceptions` would make every
    /// one of them a typo. See [`crate::breakglass`] for what these do and what bounds
    /// them.
    #[serde(default, rename = "exception", skip_serializing_if = "Vec::is_empty")]
    pub exceptions: Vec<Exception>,

    /// This file's position in a composed policy, and whether anything above it may
    /// exceed it.
    ///
    /// Absent means what it has always meant: one file, no layering, and behaviour
    /// identical to every release before composition existed. See [`crate::layer`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<LayerDecl>,

    /// The published document whose entries vouch for the grants in this file that
    /// `init --accept-baseline` marked reviewed.
    ///
    /// The reviewer of record. Absent means every `reviewed = true` in this file was set
    /// by a person, which is the ordinary case and the one that needs no record: a name
    /// is in the commit. See [`crate::baseline`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineRef>,
}

/// The buildclamp this policy code was compiled into.
///
/// The crates in this workspace share one version through `workspace.package`, so core's
/// own `CARGO_PKG_VERSION` is the binary's. Taken at compile time rather than passed in
/// because this crate is pure and has no way to ask the process what it is.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Refuse a policy that names a floor this build is below.
///
/// A **pre-release** running version satisfies a floor it would otherwise be below:
/// `0.4.0-rc.1` honours `min_tool_version = "0.4.0"`. Semver orders a pre-release before
/// its release, which is right for dependency resolution and wrong here — the thing being
/// asked is "does this binary have the behaviour", and a release candidate for 0.4.0 has
/// 0.4.0's behaviour. Refusing it would make every policy unusable on exactly the builds
/// that are testing the release it was written for.
fn check_tool_floor(required: &str, running: &str) -> Result<(), PolicyError> {
    let want = semver::Version::parse(required).map_err(|_| PolicyError::BadToolFloor {
        found: required.to_string(),
    })?;
    // An unparseable RUNNING version is not the policy author's fault and must not fail
    // their build. It cannot happen from a cargo-built binary, and if it somehow does, the
    // floor is the thing to give up rather than the run.
    let Ok(have) = semver::Version::parse(running) else {
        return Ok(());
    };
    let have_release = semver::Version::new(have.major, have.minor, have.patch);
    if have_release < want {
        return Err(PolicyError::ToolTooOld {
            required: required.to_string(),
            running: running.to_string(),
        });
    }
    Ok(())
}

/// Whether the policy itself switches enforcement off.
///
/// One variant today. It is an enum rather than a bool so that a later value — a
/// scheduled window, a per-repository exception — is an additive change to a name a
/// reader already understands, rather than a second boolean beside the first.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Enforcement {
    /// Hold nothing. Equivalent to `BUILDCLAMP_MODE=off`, and recorded the same way.
    Disabled,
}

/// One or more grants for a single crate name.
///
/// TOML has no way to write two tables with the same key, so a crate that needs
/// different envelopes at different versions is written as an array of tables:
///
/// ```toml
/// [[grants."ring"]]
/// version = "<0.17"
/// capabilities = ["fs-write", "exec"]
/// why = "..."
///
/// [[grants."ring"]]
/// version = ">=0.17"
/// capabilities = ["fs-write"]
/// why = "..."
/// ```
///
/// The single-table form stays legal because it is what almost every entry looks like
/// and forcing `[[…]]` on everyone to serve the rare case would be a worse file.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Grants {
    One(Box<Grant>),
    Many(Vec<Grant>),
}

impl Grants {
    /// Every grant under this key, whichever shape the file used.
    ///
    /// Public because [`crate::layer::Stack::check`] needs the version requirements to
    /// build its candidate set, and a stack that could not see them would sweep only
    /// unqualified grants — which are the ones least likely to compose surprisingly.
    pub fn every(&self) -> impl Iterator<Item = &Grant> {
        self.iter()
    }

    fn iter(&self) -> impl Iterator<Item = &Grant> {
        match self {
            Grants::One(g) => std::slice::from_ref(&**g).iter(),
            Grants::Many(v) => v.iter(),
        }
    }
}

/// Everything that can be wrong with a policy, all of it caught before any unit runs.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("buildclamp.toml is not valid TOML: {0}")]
    Toml(#[from] toml::de::Error),

    #[error(
        "a `trust-root` entry is not a usable Ed25519 public key: {source}. It must be a \
         base64-encoded 32-byte key — the customer's own, committed under CODEOWNERS."
    )]
    BadTrustRootKey {
        /// Why the key did not parse.
        source: crate::signed_policy::TrustRootError,
    },

    #[error(
        "buildclamp.toml declares version {found}. This buildclamp writes version \
         {POLICY_VERSION} and reads back to version {OLDEST_POLICY_VERSION}. A higher \
         number means the file was written by a newer buildclamp — upgrade, rather than \
         let this one honour the parts it understands and ignore the rest, which is the \
         permissive direction and the wrong one for a policy."
    )]
    Version { found: u32 },

    #[error(
        "the grant for `{crate_name}` has no `why`. Every grant needs one sentence \
         saying what the crate needs the capability for — it is what a reviewer reads \
         in the pull request that widens it."
    )]
    MissingWhy { crate_name: String },

    #[error(
        "buildclamp.toml needs buildclamp {required} or newer, and this one is {running}. \
         The file was written for a later version: parsing it here would honour the parts \
         this binary understands and silently ignore the rest, which is the permissive \
         direction and the wrong one for a policy. Upgrade buildclamp, or remove \
         `min_tool_version` if you are certain the file does not rely on anything newer."
    )]
    ToolTooOld { required: String, running: String },

    #[error(
        "buildclamp.toml has `min_tool_version = \"{found}\"`, which is not a semantic \
         version. It names the oldest buildclamp that can honour this file, so it has to \
         be comparable — `0.4.0`, not `0.4` and not `latest`."
    )]
    BadToolFloor { found: String },

    #[error("the grant for `{crate_name}` has an invalid version requirement `{req}`: {source}")]
    BadVersionReq {
        crate_name: String,
        req: String,
        source: semver::Error,
    },

    #[error(
        "`{crate_name}` has {count} grants that all match version `{version}`. Which one \
         applies would depend on the order they appear in the file, so buildclamp \
         refuses rather than guess. Narrow their `version` requirements so at most one \
         matches."
    )]
    Ambiguous {
        crate_name: String,
        version: String,
        count: usize,
    },

    #[error(
        "the grant for `{crate_name}` re-admits `{name}`, which buildclamp treats as a \
         credential. If that is deliberate, add `env-allow-secrets = true` to the same \
         grant so the choice is visible in the diff."
    )]
    HardDenyWithoutOptIn { crate_name: String, name: String },

    #[error(
        "the grant for `{crate_name}` lists `{zone}` in `write-zones` but does not grant \
         the `fs-write` capability, so the zone would have no effect. Add \"fs-write\" to \
         `capabilities`, or drop the zone."
    )]
    ZoneWithoutWrite { crate_name: String, zone: String },

    #[error(
        "the `[[exception]]` for `{crate_name}` has no `expires`. Every exception needs \
         one — an exception with no end is an off switch, and this file already has a \
         way to say that out loud (`enforcement = \"disabled\"`). Write a date at most \
         {cap} days out, or let `cargo buildclamp except` write the block for you."
    )]
    ExceptionNoExpiry { crate_name: String, cap: i64 },

    #[error(
        "the `[[exception]]` for `{crate_name}` has `expires = \"{found}\"`, which is not \
         a date. It has to be `YYYY-MM-DD`, in full — `2026-09-07`, not `2026-9-7`, \
         because the short spelling sorts after `2026-09-10` and an expiry that sorts \
         wrongly is one that does not expire."
    )]
    ExceptionBadDate { crate_name: String, found: String },

    #[error(
        "the `[[exception]]` for `{crate_name}` has no `reason`. It is what the person \
         reading the ticket next week needs: not what the crate does, which belongs in \
         the grant's `why`, but what happened today that made refusing unacceptable."
    )]
    ExceptionNoReason { crate_name: String },

    #[error(
        "the `[[exception]]` for `{crate_name}` has no `author`. Run `cargo buildclamp \
         except` and it is filled in from your git identity; it is not verified and does \
         not pretend to be, but an exception nobody's name is on is one nobody owns."
    )]
    ExceptionNoAuthor { crate_name: String },

    #[error(
        "`[[exception]]` has `crate = \"{found}\"`. An exception names one crate. A \
         pattern here would be an off switch wearing the word `exception`, and this file \
         already has an honest way to turn enforcement off: `enforcement = \"disabled\"`, \
         which the report records as an operator override rather than as a narrow \
         exception."
    )]
    ExceptionWildcard { found: String },

    #[error(
        "the `[[exception]]` for `{crate_name}` expires on {expires}, which is {days} \
         days away, and an exception may run at most {cap}. That bound is the point of \
         the mechanism: a week covers an incident, and anything longer is a decision that \
         belongs in a grant somebody reviewed. Shorten the date, and when the week runs \
         out either the grant is reviewed or the exception is written again — visibly."
    )]
    ExceptionTooLong {
        crate_name: String,
        expires: String,
        days: i64,
        cap: i64,
    },

    #[error(
        "{active} exceptions are live at once and this policy allows {cap}. A repository \
         with this many does not have an incident, it has a policy that no longer \
         describes its build. Review a grant and delete its exception, or raise \
         `max-active-exceptions` in `[defaults]` in the same edit."
    )]
    TooManyExceptions { active: usize, cap: usize },

    #[error("a policy stack with no layers in it was resolved; this is a bug in buildclamp")]
    EmptyStack,

    #[error(
        "`{layer}` ({origin}) declares `may-widen = false`, and nothing is stacked on top \
         of it. A ceiling nobody is under is a line that reads like a control and is not \
         one — so it is refused rather than left to be believed in. Either something \
         should be extending this file, or the line should go."
    )]
    CeilingWithNothingAbove { layer: String, origin: String },

    #[error(
        "two layers are both called `{layer}` — {first} and {second}. A refusal that named \
         one of them would send a reader to the wrong file, and the whole value of \
         layering is that a reader can tell which document decided."
    )]
    DuplicateLayerName {
        layer: String,
        first: String,
        second: String,
    },

    #[error(
        "`{}` ({}) grants `{}` {}, and `{}` ({}) does not — and `{}` declares \
         `may-widen = false`.\n\
         \n\
         This is refused rather than merged, and refused rather than quietly narrowed. \
         Narrowing silently would be the worst of the three: the build would pass, one \
         file would say the crate has it, the envelope would not, and nothing would tell \
         a reader which. Either widen `{}` — visibly, where the people who wrote it can \
         see — or drop it from `{}`.",
        .0.layer, .0.layer_origin, .0.crate_name, .0.capability,
        .0.ceiling, .0.ceiling_origin, .0.ceiling, .0.ceiling, .0.layer
    )]
    LayerWouldWiden(Box<LayerConflict>),
}

/// Why one layer could not be composed onto another.
///
/// Boxed into its error variant rather than inlined: six strings would widen every
/// `Result<_, PolicyError>` in this crate, and the overwhelmingly common case is the `Ok`
/// one. It is a named struct rather than an anonymous tuple because a reader of the
/// refusal needs to know which of the two documents is which, and `.3` does not say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerConflict {
    pub crate_name: String,
    /// What the upper layer confers that the ceiling does not.
    pub capability: String,
    /// The layer whose grant would widen.
    pub layer: String,
    pub layer_origin: String,
    /// The layer that declared `may-widen = false`.
    pub ceiling: String,
    pub ceiling_origin: String,
}

impl Policy {
    /// The policy a repository with no `buildclamp.toml` gets.
    ///
    /// Having one at all — rather than refusing to run without a file — is what makes
    /// `cargo buildclamp observe` a one-command first experience.
    pub fn empty() -> Self {
        Self {
            version: POLICY_VERSION,
            min_tool_version: None,
            enforcement: None,
            defaults: Defaults::default(),
            grants: BTreeMap::new(),
            exceptions: Vec::new(),
            layer: None,
            baseline: None,
        }
    }

    /// Parse and validate. Every error this can return is one a person can fix by
    /// editing the file, and none of them can first appear halfway through a build.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        Self::parse_as(text, TOOL_VERSION)
    }

    /// `parse`, with the running tool's version supplied — the seam the tests use, since
    /// a check against a compile-time constant cannot otherwise be exercised from both
    /// sides.
    pub fn parse_as(text: &str, running: &str) -> Result<Self, PolicyError> {
        // The version is read from a PERMISSIVE parse first, before the typed one.
        //
        // The order is the whole point. `deny_unknown_fields` is on this struct, so a
        // policy from a future buildclamp — which is to say one carrying a key this build
        // has never heard of — failed `toml::from_str` with `unknown field` and never
        // reached the version check below. The reader was told to look at a field when
        // the real answer was that the file was written for a newer binary, which sends
        // them to delete the line rather than to upgrade.
        let probe: toml::Value = toml::from_str(text)?;
        if let Some(found) = probe.get("version").and_then(toml::Value::as_integer) {
            let found = u32::try_from(found).unwrap_or(u32::MAX);
            // Only the FUTURE is refused, and the past is read. A version bump that
            // rejected every file in the field would be a migration nobody performs, and
            // the tool would be the reason a build broke on the day it was upgraded.
            if !(OLDEST_POLICY_VERSION..=POLICY_VERSION).contains(&found) {
                return Err(PolicyError::Version { found });
            }
        }
        if let Some(required) = probe
            .get("min-tool-version")
            .or_else(|| probe.get("min_tool_version"))
            .and_then(toml::Value::as_str)
            .map(str::to_string)
        {
            check_tool_floor(&required, running)?;
        }

        let mut policy: Policy = toml::from_str(text)?;
        if !(OLDEST_POLICY_VERSION..=POLICY_VERSION).contains(&policy.version) {
            return Err(PolicyError::Version {
                found: policy.version,
            });
        }
        policy.validate()?;
        // Upgraded in memory, never on disk. Nothing this tool does should rewrite a file
        // somebody is going to read in a diff without being asked — `cargo buildclamp
        // policy migrate` is the asking.
        policy.version = POLICY_VERSION;
        Ok(policy)
    }

    /// Whether this text is a policy of an older version than this build writes.
    ///
    /// Asked of the **text**, not of a parsed policy, because parsing upgrades it: after
    /// [`Policy::parse`] every policy says it is current, which is right for everything
    /// except the one question `policy migrate` needs answered.
    pub fn declared_version(text: &str) -> Option<u32> {
        toml::from_str::<toml::Value>(text)
            .ok()?
            .get("version")
            .and_then(toml::Value::as_integer)
            .and_then(|v| u32::try_from(v).ok())
    }

    /// Apply the read decision to a resolved envelope, last.
    ///
    /// With `withhold-secret-reads` off, [`Capability::FsRead`] is granted to every unit
    /// whatever else the policy says — including to a unit whose grant does not list it.
    /// That looks like the envelope ignoring the grant, and it is not: a grant replaces the
    /// defaults, and with withholding off there is no restriction for it to replace. The
    /// alternative is a report showing `fs-read` ungranted on a run where every path on the
    /// machine was readable, which is a document that says the opposite of what happened.
    ///
    /// With it on, the capability comes from the grant's own list and from nowhere else,
    /// which is the same rule every other capability follows.
    fn settle_reads(&self, mut envelope: Envelope) -> Envelope {
        if self.defaults.withhold_secret_reads {
            envelope.granted.remove(Capability::FsRead);
        } else {
            envelope.granted.insert(Capability::FsRead);
        }
        // Carried on the envelope rather than passed alongside it, so the report says which
        // rules each unit actually ran under. A reader asking "why did this crate not see
        // my variable?" should find the answer in the document rather than by inferring it
        // from a policy file that may since have changed.
        envelope.env_allowlist = self.defaults.env_allowlist;
        envelope
    }

    fn validate(&self) -> Result<(), PolicyError> {
        // A trust-root key that does not parse is a policy error, caught here rather than as
        // a silent verification miss at build time: a customer who fat-fingers a key wants to
        // hear it the moment they write it, not to discover that every signed layer quietly
        // failed to verify.
        for key in &self.defaults.trust_root {
            crate::signed_policy::TrustedKey::from_base64(key)
                .map_err(|source| PolicyError::BadTrustRootKey { source })?;
        }
        for (crate_name, grants) in &self.grants {
            for g in grants.iter() {
                if g.why.trim().is_empty() {
                    return Err(PolicyError::MissingWhy {
                        crate_name: crate_name.clone(),
                    });
                }
                if let Some(req) = &g.version {
                    semver::VersionReq::parse(req).map_err(|source| {
                        PolicyError::BadVersionReq {
                            crate_name: crate_name.clone(),
                            req: req.clone(),
                            source,
                        }
                    })?;
                }
                if !g.env_allow_secrets {
                    for name in &g.env_allow {
                        if HARD_DENY.iter().any(|d| d.eq_ignore_ascii_case(name)) {
                            return Err(PolicyError::HardDenyWithoutOptIn {
                                crate_name: crate_name.clone(),
                                name: name.clone(),
                            });
                        }
                    }
                }
                // A zone without the capability is always a mistake, and one that
                // silently does nothing. Catching it here turns a policy that quietly
                // does less than its author believed into a message they can act on.
                if !g.write_zones.is_empty() && !g.capabilities.contains(&Capability::FsWrite) {
                    return Err(PolicyError::ZoneWithoutWrite {
                        crate_name: crate_name.clone(),
                        zone: g.write_zones[0].as_str().to_string(),
                    });
                }
            }
        }
        // Everything about an exception that can be judged without knowing what day it
        // is. The rest — the seven-day bound and the active cap — is in
        // `break_glass`, because this crate has no clock and a check that invented one
        // could not be tested against a fixed string.
        for e in &self.exceptions {
            let crate_name = e.crate_name.clone();
            if crate_name.trim().is_empty() || crate_name.contains('*') {
                return Err(PolicyError::ExceptionWildcard { found: crate_name });
            }
            if e.reason.trim().is_empty() {
                return Err(PolicyError::ExceptionNoReason { crate_name });
            }
            if e.author.trim().is_empty() {
                return Err(PolicyError::ExceptionNoAuthor { crate_name });
            }
            match &e.expires {
                None => {
                    return Err(PolicyError::ExceptionNoExpiry {
                        crate_name,
                        cap: MAX_EXCEPTION_DAYS,
                    })
                }
                Some(found) if Date::parse(found).is_none() => {
                    return Err(PolicyError::ExceptionBadDate {
                        crate_name,
                        found: found.clone(),
                    })
                }
                Some(_) => {}
            }
        }
        Ok(())
    }

    /// The exceptions in force today, having refused the ones no policy may contain.
    ///
    /// Separate from [`Policy::parse`] because the two checks it makes — an expiry more
    /// than [`MAX_EXCEPTION_DAYS`] out, and more live blocks than the cap allows — are
    /// both relative to the day the build runs. A file that was legal when it was
    /// committed stays legal; a file that tries to buy three weeks never was.
    ///
    /// Callers run this **before** cargo starts, like every other policy error: an
    /// exception refused halfway through a build would leave a target directory in a
    /// state nobody chose.
    pub fn break_glass(&self, today: Date) -> Result<BreakGlass, PolicyError> {
        for e in &self.exceptions {
            // `validate` has already refused an absent or unparseable date, so anything
            // that reaches here and cannot be read is a hand-constructed value; treating
            // it as zero days out is the fail-closed reading.
            let Some(expiry) = e.expiry() else { continue };
            let days = today.days_until(expiry);
            if days > MAX_EXCEPTION_DAYS {
                return Err(PolicyError::ExceptionTooLong {
                    crate_name: e.crate_name.clone(),
                    expires: expiry.to_string(),
                    days,
                    cap: MAX_EXCEPTION_DAYS,
                });
            }
        }
        let glass = BreakGlass::split(&self.exceptions, today);
        let cap = self.defaults.max_active_exceptions;
        if glass.live().len() > cap {
            return Err(PolicyError::TooManyExceptions {
                active: glass.live().len(),
                cap,
            });
        }
        Ok(glass)
    }

    /// How many grants a human has not yet read.
    ///
    /// `init` writes every grant it generates as `reviewed = false`, and `--strict` counts
    /// these rather than looking at the report — see [`crate::Report::exit_code`] for why
    /// the distinction matters.
    pub fn unreviewed_grants(&self) -> usize {
        self.grants
            .values()
            .flat_map(|g| g.iter())
            .filter(|g| !g.reviewed)
            .count()
    }

    /// The same count, split by what is excusing each grant.
    ///
    /// `--strict` gates on [`Unreviewed::count`], which counts only the grants nothing
    /// excuses. The other two lists are not dropped, because an excused grant is still
    /// work somebody owes and a run that printed nothing about it would be a run that
    /// quietly reset the clock.
    ///
    /// With no grace window and no exceptions this returns exactly what
    /// [`Policy::unreviewed_grants`] counts, which is the case every existing caller is
    /// in.
    pub fn unreviewed(&self, grace: Option<Grace>, glass: &BreakGlass) -> Unreviewed {
        let mut out = Unreviewed::default();
        for (name, grants) in &self.grants {
            for g in grants.iter() {
                if g.reviewed {
                    continue;
                }
                // An exception is checked first and a grace window second, because the
                // exception is the louder instrument: it names a person and a date, and a
                // reader should see that rather than a grace window that would also have
                // covered it.
                if let Some(e) = glass.naming(name) {
                    out.excepted.push((
                        name.clone(),
                        e.expires.clone().unwrap_or_else(|| "?".to_string()),
                    ));
                    continue;
                }
                match grace.and_then(|w| w.covers(g.first_seen.as_deref()).map(|left| (w, left))) {
                    Some((_, days_left)) => out.in_grace.push(GraceNote {
                        crate_name: name.clone(),
                        first_seen: g.first_seen.clone().unwrap_or_default(),
                        days_left,
                    }),
                    None => out.failing.push(name.clone()),
                }
            }
        }
        out
    }

    /// The environment-deny patterns in force.
    /// Every environment name that some grant in this policy re-admits.
    ///
    /// The driver scrubs credential-shaped names out of its OWN environment before cargo
    /// inherits it, so that cargo, rustc and anything not held never see them. That is
    /// the right default and it had one fatal consequence: a name removed there is gone
    /// before any build unit exists, so no grant's `env-allow` could ever put it back.
    /// The feature was documented, parsed, validated — and impossible.
    ///
    /// This is the exception list. A name here stays in cargo's environment so that the
    /// per-unit scrub in the launcher can make the real decision, unit by unit, against
    /// each envelope. Every other unit still has it withheld.
    ///
    /// The cost is stated rather than hidden: a name on this list IS visible to cargo
    /// itself and to any process that is not held, for the whole build. That is the
    /// price of the feature working at all, it applies only to names a human wrote into
    /// a grant by hand, and for a HARD_DENY name the parser additionally demands
    /// `env-allow-secrets = true` before it will accept the policy.
    pub fn env_allow_union(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .grants
            .values()
            .flat_map(Grants::iter)
            .flat_map(|g| g.env_allow.iter().cloned())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    pub fn env_deny(&self) -> Vec<String> {
        match &self.defaults.env_deny {
            Some(v) => v.clone(),
            None => DEFAULT_ENV_DENY.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Resolve the envelope for one build unit.
    ///
    /// `is_workspace_member` comes from cargo (`CARGO_PRIMARY_PACKAGE`), not from the
    /// policy, because whether a crate is yours is a fact about the build rather than a
    /// preference.
    pub fn resolve(
        &self,
        unit: &UnitId,
        kind: UnitKind,
        is_workspace_member: bool,
    ) -> Result<Envelope, PolicyError> {
        self.resolve_with(unit, kind, is_workspace_member, &BreakGlass::none())
    }

    /// [`Policy::resolve`], with break-glass applied.
    ///
    /// # What an exception widens, and what it deliberately does not
    ///
    /// It adds the capabilities it names — or every capability, when it names none — to
    /// the envelope this unit would otherwise have had. That is what makes it an
    /// *unblock* rather than a way to make a red build exit `0` while the build script
    /// still cannot do its job: a dependency bump that added a genuine network fetch
    /// breaks the build, and an escape hatch that leaves it broken is one nobody uses
    /// twice.
    ///
    /// It does **not** widen `write_zones` or `write_paths`. Where a crate may write is
    /// the one dimension of this envelope with a shape rather than a yes or no, and an
    /// exception that could grant "anywhere" would be the off switch this format refuses
    /// to let anyone spell as an exception. So `fs-write` from an exception means the
    /// crate may write in the zones the policy already gave it, and a write outside them
    /// is still refused by the kernel — the run's verdict stands down, the syscall does
    /// not. A crate that genuinely needs a new zone needs a grant, which is a line
    /// somebody reviews.
    ///
    /// Applied **after** `settle_reads`, which is not an ordering detail: with
    /// `withhold-secret-reads` on, `settle_reads` removes [`Capability::FsRead`] from
    /// every envelope whose grant did not ask for it, and an exception applied before it
    /// would be silently taken back out.
    pub fn resolve_with(
        &self,
        unit: &UnitId,
        kind: UnitKind,
        is_workspace_member: bool,
        glass: &BreakGlass,
    ) -> Result<Envelope, PolicyError> {
        let envelope = self.resolve_without_glass(unit, kind, is_workspace_member)?;
        Ok(apply_exception(envelope, glass.naming(&unit.name)))
    }

    fn resolve_without_glass(
        &self,
        unit: &UnitId,
        kind: UnitKind,
        is_workspace_member: bool,
    ) -> Result<Envelope, PolicyError> {
        if is_workspace_member && self.defaults.trust_workspace {
            return Ok(Envelope::unheld());
        }

        let base = Envelope::default_for_kind(kind);

        let Some(grants) = self.grants.get(&unit.name) else {
            return Ok(self.settle_reads(base));
        };

        let version = semver::Version::parse(&unit.version).ok();
        let mut matched: Vec<&Grant> = Vec::new();
        for g in grants.iter() {
            match (&g.version, &version) {
                (None, _) => matched.push(g),
                (Some(req), Some(v)) => {
                    // An unparseable requirement was rejected at validate() time.
                    if semver::VersionReq::parse(req)
                        .map(|r| r.matches(v))
                        .unwrap_or(false)
                    {
                        matched.push(g);
                    }
                }
                // A version requirement cannot match a version we could not parse. A
                // grant that applied to a version it could not compare against would be
                // widening an envelope by accident.
                (Some(_), None) => {}
            }
        }

        if matched.is_empty() {
            return Ok(self.settle_reads(base));
        }

        // Most specific wins: a version-qualified grant beats an unqualified one. Ties
        // at the same specificity are ambiguous and refused.
        let qualified: Vec<&Grant> = matched
            .iter()
            .copied()
            .filter(|g| g.version.is_some())
            .collect();
        let winners = if qualified.is_empty() {
            matched
        } else {
            qualified
        };
        if winners.len() > 1 {
            return Err(PolicyError::Ambiguous {
                crate_name: unit.name.clone(),
                version: unit.version.clone(),
                count: winners.len(),
            });
        }
        let g = winners[0];

        let from_grant = Envelope {
            granted: g.capabilities.iter().copied().collect::<CapabilitySet>(),
            // The policy's zones are a closed enum — a name this build cannot honour is
            // refused at parse time rather than carried — and they widen into the wire
            // type here, at the one boundary where the envelope becomes a document.
            write_zones: g.write_zones.iter().copied().map(Forward::Known).collect(),
            write_paths: g.write_paths.clone(),
            env_allow: g.env_allow.clone(),
            env_allow_secrets: g.env_allow_secrets,
            // Set by `except_with` after `settle_reads`, never here: an exception widens
            // an envelope the policy has already finished producing.
            excepted_until: None,
            // Overwritten by `settle_reads` below, which is the one place the policy-wide
            // switches are applied so the two branches of `resolve` cannot disagree.
            env_allowlist: false,
            net_destinations: g.net_destinations.clone(),
            source: match &g.version {
                Some(req) => EnvelopeSource::GrantVersioned {
                    crate_name: unit.name.clone(),
                    req: req.clone(),
                },
                None => EnvelopeSource::Grant {
                    crate_name: unit.name.clone(),
                },
            },
            why: Some(g.why.clone()),
            reviewed: g.reviewed,
        };
        Ok(self.settle_reads(from_grant))
    }
}

/// Widen an envelope by a live exception, if one names this crate.
///
/// An exception that lists no capabilities grants all of them, which is the honest
/// default for the moment one is written: the person unblocking at 17:00 knows which
/// crate went red and often not yet which of its requests did. `cargo buildclamp except`
/// narrows it for them from the last report, so the broad form is the fallback rather
/// than the usual case.
pub(crate) fn apply_exception_pub(envelope: Envelope, exception: Option<&Exception>) -> Envelope {
    apply_exception(envelope, exception)
}

fn apply_exception(mut envelope: Envelope, exception: Option<&Exception>) -> Envelope {
    let Some(e) = exception else { return envelope };
    if e.capabilities.is_empty() {
        for c in Capability::ALL {
            envelope.granted.insert(c);
        }
    } else {
        for c in &e.capabilities {
            envelope.granted.insert(*c);
        }
    }
    envelope.excepted_until = e.expires.clone();
    envelope
}

/// Does an environment name match a deny pattern?
///
/// Patterns allow one leading and/or trailing `*`. Matching is case-insensitive because
/// environment names are conventionally uppercase but not required to be, and a policy
/// that missed `github_token` on a technicality would be a policy that missed the point.
pub fn env_name_matches(pattern: &str, name: &str) -> bool {
    let (starts, ends) = (pattern.starts_with('*'), pattern.ends_with('*'));
    let core = pattern.trim_matches('*');
    // A bare "*" denies everything, which is a legal thing to ask for.
    if core.is_empty() {
        return starts || ends;
    }
    let name_up = name.to_ascii_uppercase();
    let core_up = core.to_ascii_uppercase();
    match (starts, ends) {
        (true, true) => name_up.contains(&core_up),
        (true, false) => name_up.ends_with(&core_up),
        (false, true) => name_up.starts_with(&core_up),
        (false, false) => name_up == core_up,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_allow_union_collects_every_re_admitted_name_across_both_grant_forms() {
        // The driver uses this to decide which credential-shaped names to leave in
        // cargo's environment. Miss one and that grant's `env-allow` silently does
        // nothing, which is the bug this method exists to have fixed.
        let p = Policy::parse(
            r#"
            version = 1
            [grants."single"]
            capabilities = ["fs-write"]
            env-allow = ["OPENSSL_DIR"]
            why = "one"
            [[grants."multi"]]
            version = "<2"
            capabilities = ["fs-write"]
            env-allow = ["GITHUB_TOKEN"]
            env-allow-secrets = true
            why = "two"
            [[grants."multi"]]
            version = ">=2"
            capabilities = ["fs-write"]
            env-allow = ["OPENSSL_DIR"]
            why = "three"
            "#,
        )
        .expect("policy parses");
        // Sorted and de-duplicated: the array-of-tables form contributes both of its
        // entries, and OPENSSL_DIR appears once despite two grants naming it.
        assert_eq!(p.env_allow_union(), vec!["GITHUB_TOKEN", "OPENSSL_DIR"]);
    }

    #[test]
    fn a_policy_with_no_grants_re_admits_nothing() {
        assert!(Policy::empty().env_allow_union().is_empty());
    }

    fn unit(name: &str, version: &str) -> UnitId {
        UnitId::new(name, version)
    }

    #[test]
    fn a_grant_without_a_why_is_a_parse_error_before_anything_runs() {
        let err = Policy::parse(
            r#"
            version = 1
            [grants."sneaky"]
            capabilities = ["net"]
            why = "   "
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::MissingWhy { .. }), "{err}");
    }

    #[test]
    fn a_missing_why_field_entirely_is_also_refused() {
        // serde would default a missing String to empty; the field is required instead,
        // so the failure names the field rather than reporting an empty justification.
        let err = Policy::parse(
            r#"
            version = 1
            [grants."sneaky"]
            capabilities = ["net"]
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::Toml(_)), "{err}");
    }

    #[test]
    fn two_grants_matching_one_version_are_refused_rather_than_ordered() {
        let p = Policy::parse(
            r#"
            version = 1
            [[grants."ring"]]
            version = ">=0.16"
            capabilities = ["exec"]
            why = "a"
            [[grants."ring"]]
            version = ">=0.17"
            capabilities = ["net"]
            why = "b"
            "#,
        )
        .unwrap();
        let err = p
            .resolve(
                &unit("ring", "0.17.14"),
                UnitKind::BuildScriptCompile,
                false,
            )
            .unwrap_err();
        assert!(
            matches!(err, PolicyError::Ambiguous { count: 2, .. }),
            "{err}"
        );
    }

    #[test]
    fn a_version_qualified_grant_beats_an_unqualified_one_without_being_ambiguous() {
        let p = Policy::parse(
            r#"
            version = 1
            [[grants."ring"]]
            capabilities = ["exec"]
            why = "general"
            [[grants."ring"]]
            version = ">=0.17"
            capabilities = ["exec", "fs-write"]
            write-zones = ["out-dir"]
            why = "0.17 vendors its own asm"
            "#,
        )
        .unwrap();
        let e = p
            .resolve(
                &unit("ring", "0.17.14"),
                UnitKind::BuildScriptCompile,
                false,
            )
            .unwrap();
        assert!(e.permits(Capability::FsWrite));
        assert!(matches!(e.source, EnvelopeSource::GrantVersioned { .. }));
    }

    #[test]
    fn a_grant_replaces_the_defaults_rather_than_adding_to_them() {
        // Composition would mean a reader cannot see a unit's whole envelope in one
        // place. Granting only `net` therefore takes fs-write and exec away.
        let p = Policy::parse(
            r#"
            version = 1
            [grants."fetcher"]
            capabilities = ["net"]
            why = "downloads a pinned tarball"
            "#,
        )
        .unwrap();
        let e = p
            .resolve(
                &unit("fetcher", "1.0.0"),
                UnitKind::BuildScriptCompile,
                false,
            )
            .unwrap();
        assert!(e.permits(Capability::Net));
        assert!(!e.permits(Capability::Exec));
        assert!(!e.permits(Capability::FsWrite));
    }

    #[test]
    fn a_crate_with_no_grant_gets_the_default_for_its_kind() {
        let p = Policy::empty();
        let bs = p
            .resolve(
                &unit("anything", "1.0.0"),
                UnitKind::BuildScriptCompile,
                false,
            )
            .unwrap();
        let co = p
            .resolve(&unit("anything", "1.0.0"), UnitKind::Compile, false)
            .unwrap();
        assert!(!bs.permits(Capability::Net));
        assert!(bs.writes_to(WriteZone::OutDir));
        assert!(co.writes_to(WriteZone::Target));
    }

    #[test]
    fn a_workspace_member_is_held_unless_trust_workspace_is_on() {
        let held = Policy::empty();
        assert!(!held
            .resolve(&unit("mine", "0.1.0"), UnitKind::BuildScriptCompile, true)
            .unwrap()
            .permits(Capability::Net));

        let trusting = Policy::parse("version = 1\n[defaults]\ntrust-workspace = true\n").unwrap();
        let e = trusting
            .resolve(&unit("mine", "0.1.0"), UnitKind::BuildScriptCompile, true)
            .unwrap();
        assert_eq!(e.source, EnvelopeSource::TrustedWorkspace);
        // …and a dependency is still held even when the workspace is trusted.
        assert!(!trusting
            .resolve(
                &unit("theirs", "1.0.0"),
                UnitKind::BuildScriptCompile,
                false
            )
            .unwrap()
            .permits(Capability::Net));
    }

    #[test]
    fn re_admitting_a_credential_needs_the_loud_opt_in() {
        let err = Policy::parse(
            r#"
            version = 1
            [grants."curious"]
            capabilities = ["exec"]
            env-allow = ["GITHUB_TOKEN"]
            why = "needs it, honest"
            "#,
        )
        .unwrap_err();
        assert!(
            matches!(err, PolicyError::HardDenyWithoutOptIn { .. }),
            "{err}"
        );

        // With the opt-in it parses — the point is that it is visible in a diff, not
        // that it is impossible.
        Policy::parse(
            r#"
            version = 1
            [grants."curious"]
            capabilities = ["exec"]
            env-allow = ["GITHUB_TOKEN"]
            env-allow-secrets = true
            why = "publishes a release artefact from the build script; issue #12 to remove"
            "#,
        )
        .unwrap();
    }

    #[test]
    fn a_write_zone_without_the_write_capability_is_caught_rather_than_ignored() {
        let err = Policy::parse(
            r#"
            version = 1
            [grants."confused"]
            capabilities = ["exec"]
            write-zones = ["out-dir"]
            why = "thought this granted writing"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::ZoneWithoutWrite { .. }), "{err}");
    }

    #[test]
    fn a_future_policy_version_is_refused_rather_than_partially_understood() {
        let err = Policy::parse("version = 999\n").unwrap_err();
        assert!(matches!(err, PolicyError::Version { found: 999 }), "{err}");
    }

    #[test]
    fn a_future_policy_is_refused_by_its_version_and_not_by_whichever_key_is_new() {
        // The ordering defect. `deny_unknown_fields` is on `Policy`, so a file from a
        // newer buildclamp failed the typed parse with `unknown field` before the version
        // check was ever reached. The message sent the reader to delete a line, when the
        // real answer was that the file was written for a later binary.
        let err =
            Policy::parse("version = 3\ncentral_policy_url = \"https://example.invalid/p.toml\"\n")
                .unwrap_err();
        assert!(
            matches!(err, PolicyError::Version { found: 3 }),
            "refused, but not on the version: {err}"
        );
        let msg = err.to_string();
        assert!(!msg.contains("central_policy_url"), "{msg}");
    }

    #[test]
    fn a_version_one_policy_still_parses_and_is_upgraded_in_memory() {
        // The half of a version bump that decides whether anybody performs the migration.
        // A number that refused every file in the field would make the tool the reason a
        // build broke on the day it was upgraded, and the answer would be to pin it.
        let text = "version = 1\n[grants.\"evil\"]\ncapabilities = [\"net\"]\nwhy = \"x\"\n";
        let p = Policy::parse(text).expect("a v1 policy still parses");
        assert_eq!(
            p.version, POLICY_VERSION,
            "a parsed policy is always current; the upgrade happens in memory"
        );
        // …and the file on disk is untouched, which is what `declared_version` is for.
        assert_eq!(Policy::declared_version(text), Some(1));
        // The envelope it resolves is the same one it resolved before the bump.
        let e = p
            .resolve(&unit("evil", "0.1.3"), UnitKind::BuildScriptCompile, false)
            .unwrap();
        assert!(e.permits(Capability::Net));
    }

    #[test]
    fn a_version_older_than_this_build_reads_is_refused_rather_than_guessed_at() {
        // `0` is not "before version 1", it is a file whose version field says something
        // this build cannot interpret. Reading it as v1 would be guessing.
        let err = Policy::parse("version = 0\n").unwrap_err();
        assert!(matches!(err, PolicyError::Version { found: 0 }), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("reads back to version 1"), "{msg}");
    }

    #[test]
    fn a_policy_naming_a_tool_floor_this_build_is_below_says_which_two_versions() {
        // The case no format version can catch: the format did not change, the file just
        // relies on behaviour this binary does not have.
        let err =
            Policy::parse_as("version = 1\nmin_tool_version = \"0.4.0\"\n", "0.2.0").unwrap_err();
        let PolicyError::ToolTooOld { required, running } = &err else {
            panic!("{err}");
        };
        assert_eq!(required, "0.4.0");
        assert_eq!(running, "0.2.0");
        // Whoever hits this is holding two things and needs to know which to change.
        let msg = err.to_string();
        assert!(msg.contains("0.4.0") && msg.contains("0.2.0"), "{msg}");
    }

    #[test]
    fn a_tool_at_or_above_the_floor_parses_the_file() {
        for running in ["0.4.0", "0.4.1", "1.0.0"] {
            assert!(
                Policy::parse_as("version = 1\nmin_tool_version = \"0.4.0\"\n", running).is_ok(),
                "{running} should satisfy a 0.4.0 floor"
            );
        }
    }

    #[test]
    fn a_release_candidate_satisfies_the_floor_for_the_release_it_is_a_candidate_for() {
        // Semver orders `0.4.0-rc.1` BEFORE `0.4.0`, which is right for dependency
        // resolution and wrong for this question. The thing being asked is whether the
        // binary has the behaviour, and a candidate for 0.4.0 has 0.4.0's. Refusing it
        // would make every policy unusable on exactly the builds testing the release it
        // was written for.
        assert!(
            Policy::parse_as("version = 1\nmin_tool_version = \"0.4.0\"\n", "0.4.0-rc.1").is_ok()
        );
    }

    #[test]
    fn a_policy_with_no_floor_parses_on_any_build() {
        // A hand-written policy must not have to carry a version number to work.
        assert!(Policy::parse_as("version = 1\n", "0.0.1").is_ok());
    }

    #[test]
    fn a_floor_that_is_not_a_semantic_version_is_named_rather_than_ignored() {
        // Ignoring it would be the permissive direction: the file asked for a floor and
        // got none, and nobody would be told.
        for bad in ["0.4", "latest", ""] {
            let text = format!("version = 1\nmin_tool_version = \"{bad}\"\n");
            let err = Policy::parse_as(&text, "9.9.9").unwrap_err();
            assert!(
                matches!(err, PolicyError::BadToolFloor { .. }),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn an_unknown_field_is_refused_so_a_typo_is_never_a_silent_no_op() {
        // `capabilties = [...]` must not parse as "no capabilities".
        let err = Policy::parse(
            r#"
            version = 1
            [grants."typo"]
            capabilties = ["net"]
            why = "x"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, PolicyError::Toml(_)), "{err}");
    }

    #[test]
    fn a_generated_policy_reports_every_grant_as_unread() {
        let p = Policy::parse(
            r#"
            version = 1
            [grants."a"]
            capabilities = ["net"]
            why = "OBSERVED"
            [grants."b"]
            capabilities = ["net"]
            why = "reviewed by a person"
            reviewed = true
            "#,
        )
        .unwrap();
        assert_eq!(p.unreviewed_grants(), 1);
        assert_eq!(Policy::empty().unreviewed_grants(), 0);
    }

    #[test]
    fn env_patterns_match_the_way_the_documentation_says() {
        assert!(env_name_matches("*_TOKEN", "GITHUB_TOKEN"));
        assert!(env_name_matches("AWS_*", "AWS_SECRET_ACCESS_KEY"));
        assert!(env_name_matches("GITHUB_TOKEN", "GITHUB_TOKEN"));
        assert!(env_name_matches("*SECRET*", "MY_SECRET_THING"));
        // Case-insensitive: a lowercase spelling must not slip past.
        assert!(env_name_matches("*_TOKEN", "github_token"));
        // And the near-misses do not match.
        assert!(!env_name_matches("AWS_*", "MY_AWS_KEY"));
        assert!(!env_name_matches("*_TOKEN", "TOKEN_PATH"));
        assert!(!env_name_matches("PATH", "PATHOLOGY"));
    }

    #[test]
    fn a_grant_whose_version_requirement_cannot_match_an_unparseable_version_does_not_apply() {
        // Git and path dependencies can carry versions semver cannot parse. Applying a
        // requirement to one would be widening an envelope by accident.
        let p = Policy::parse(
            r#"
            version = 1
            [grants."odd"]
            version = ">=1"
            capabilities = ["net"]
            why = "x"
            "#,
        )
        .unwrap();
        let e = p
            .resolve(
                &unit("odd", "not-a-version"),
                UnitKind::BuildScriptCompile,
                false,
            )
            .unwrap();
        assert!(!e.permits(Capability::Net));
        assert_eq!(e.source, EnvelopeSource::Default);
    }

    // ---- break-glass ------------------------------------------------------------

    fn day(s: &str) -> Date {
        Date::parse(s).expect("test dates are well formed")
    }

    /// A policy with one exception, whose fields the caller supplies verbatim.
    fn with_exception(body: &str) -> Result<Policy, PolicyError> {
        Policy::parse(&format!("version = 1\n\n[[exception]]\n{body}\n"))
    }

    #[test]
    fn an_exception_without_an_expiry_is_refused() {
        let e = with_exception(
            r#"
            crate = "openssl-sys"
            reason = "vendored build fetches its source; INFRA-4412"
            author = "ada@example.com"
            "#,
        )
        .expect_err("an exception with no end is an off switch");
        assert!(matches!(e, PolicyError::ExceptionNoExpiry { .. }), "{e}");
        // The message has to send the reader to the honest off switch rather than leave
        // them looking for a way to spell "never".
        let text = e.to_string();
        assert!(text.contains("enforcement = \"disabled\""), "{text}");
        assert!(text.contains("7 days"), "{text}");
    }

    #[test]
    fn an_exception_needs_a_reason_and_a_name_on_it() {
        let blank_reason = with_exception(
            r#"
            crate = "openssl-sys"
            expires = "2026-09-20"
            reason = "   "
            author = "ada@example.com"
            "#,
        )
        .expect_err("whitespace is not a reason");
        assert!(
            matches!(blank_reason, PolicyError::ExceptionNoReason { .. }),
            "{blank_reason}"
        );

        let blank_author = with_exception(
            r#"
            crate = "openssl-sys"
            expires = "2026-09-20"
            reason = "a reason"
            author = ""
            "#,
        )
        .expect_err("an exception nobody's name is on is one nobody owns");
        assert!(
            matches!(blank_author, PolicyError::ExceptionNoAuthor { .. }),
            "{blank_author}"
        );
        // And the message points at the command that fills it in, because the person
        // hitting this is the one least able to go and read the documentation.
        assert!(
            blank_author.to_string().contains("cargo buildclamp except"),
            "{blank_author}"
        );

        // Missing outright is serde's to refuse, and it does.
        let missing = with_exception(
            r#"
            crate = "openssl-sys"
            expires = "2026-09-20"
            reason = "a reason"
            "#,
        )
        .expect_err("author is not optional");
        assert!(matches!(missing, PolicyError::Toml(_)), "{missing}");
    }

    #[test]
    fn an_exception_may_not_name_a_pattern() {
        let e = with_exception(
            r#"
            crate = "*"
            expires = "2026-09-20"
            reason = "everything broke"
            author = "ada@example.com"
            "#,
        )
        .expect_err("a wildcard exception is an off switch wearing another word");
        assert!(matches!(e, PolicyError::ExceptionWildcard { .. }), "{e}");
    }

    #[test]
    fn an_expiry_that_is_not_a_date_is_refused_by_name() {
        let e = with_exception(
            r#"
            crate = "openssl-sys"
            expires = "2026-9-7"
            reason = "a reason"
            author = "ada@example.com"
            "#,
        )
        .expect_err("a short date sorts wrongly, so it is not a date");
        assert!(matches!(e, PolicyError::ExceptionBadDate { .. }), "{e}");
    }

    #[test]
    fn an_exception_may_not_run_longer_than_a_week() {
        let p = with_exception(
            r#"
            crate = "openssl-sys"
            expires = "2026-10-15"
            reason = "a reason"
            author = "ada@example.com"
            "#,
        )
        .expect("it parses — the bound is relative to the day, not to the file");
        let e = p
            .break_glass(day("2026-09-15"))
            .expect_err("thirty days is not a week");
        match e {
            PolicyError::ExceptionTooLong { days, cap, .. } => {
                assert_eq!(days, 30);
                assert_eq!(cap, MAX_EXCEPTION_DAYS);
            }
            other => panic!("{other}"),
        }
        // Exactly the cap is allowed; the day after it is not.
        assert!(p.break_glass(day("2026-10-08")).is_ok());
        assert!(p.break_glass(day("2026-10-07")).is_err());
    }

    #[test]
    fn an_expired_exception_covers_nothing_and_is_still_reported() {
        let p = with_exception(
            r#"
            crate = "openssl-sys"
            expires = "2026-09-01"
            reason = "a reason"
            author = "ada@example.com"
            "#,
        )
        .unwrap();
        let glass = p
            .break_glass(day("2026-09-15"))
            .expect("an expired block is not an error, it is simply over");
        assert!(glass.covering("openssl-sys", Capability::Net).is_none());
        assert_eq!(glass.expired().len(), 1);
        assert_eq!(glass.live().len(), 0);
    }

    #[test]
    fn the_active_exception_cap_is_enforced_and_counts_only_the_live_ones() {
        let mut text = String::from("version = 1\n");
        for i in 0..4 {
            text.push_str(&format!(
                "\n[[exception]]\ncrate = \"c{i}\"\nexpires = \"2026-09-20\"\n\
                 reason = \"a reason\"\nauthor = \"ada@example.com\"\n"
            ));
        }
        let p = Policy::parse(&text).expect("four blocks parse; the cap is a run-time bound");
        match p.break_glass(day("2026-09-15")) {
            Err(PolicyError::TooManyExceptions { active, cap }) => {
                assert_eq!(active, 4);
                assert_eq!(cap, crate::breakglass::DEFAULT_ACTIVE_EXCEPTION_CAP);
            }
            other => panic!("four live exceptions must be refused, got {other:?}"),
        }
        // Raising the cap in the same file is the way past it, and the error names the
        // key so that somebody at 17:00 can find it.
        let raised = Policy::parse(&text.replace(
            "version = 1\n",
            "version = 1\n[defaults]\nmax-active-exceptions = 4\n",
        ))
        .unwrap();
        assert!(raised.break_glass(day("2026-09-15")).is_ok());
        // And an expired block does not count against it: three live plus one lapsed is
        // three, or a team would be blocked by history.
        let lapsed = Policy::parse(&text.replace(
            "crate = \"c3\"\nexpires = \"2026-09-20\"",
            "crate = \"c3\"\nexpires = \"2026-09-01\"",
        ))
        .unwrap();
        assert!(lapsed.break_glass(day("2026-09-15")).is_ok());
    }

    #[test]
    fn a_cap_of_zero_forbids_break_glass_in_this_repository() {
        let p = Policy::parse(
            r#"
            version = 1
            [defaults]
            max-active-exceptions = 0
            [[exception]]
            crate = "openssl-sys"
            expires = "2026-09-20"
            reason = "a reason"
            author = "ada@example.com"
            "#,
        )
        .unwrap();
        assert!(matches!(
            p.break_glass(day("2026-09-15")),
            Err(PolicyError::TooManyExceptions { .. })
        ));
    }

    #[test]
    fn grace_never_suppresses_a_grant_that_was_already_known() {
        // The property the milestone names. Three grants, all unreviewed: one written
        // today, one written a year ago, one from a policy that predates `first-seen`
        // entirely. A thirty-day window may excuse exactly the first.
        let p = Policy::parse(
            r#"
            version = 1
            [grants."fresh"]
            capabilities = ["net"]
            why = "observed today"
            first-seen = "2026-09-15"
            [grants."old"]
            capabilities = ["net"]
            why = "observed a year ago"
            first-seen = "2025-09-15"
            [grants."undated"]
            capabilities = ["net"]
            why = "written by hand, or by a buildclamp with no first-seen"
            "#,
        )
        .unwrap();
        assert_eq!(p.unreviewed_grants(), 3);

        let none = p.unreviewed(None, &BreakGlass::none());
        assert_eq!(none.count(), 3, "with no window, everything fails");

        let graced = p.unreviewed(
            Some(Grace {
                today: day("2026-09-15"),
                days: 30,
            }),
            &BreakGlass::none(),
        );
        assert_eq!(graced.failing, vec!["old", "undated"]);
        assert_eq!(graced.in_grace.len(), 1);
        assert_eq!(graced.in_grace[0].crate_name, "fresh");
        assert_eq!(graced.in_grace[0].days_left, 30);
        // Excused is not forgiven: the total still counts all three, which is what the
        // summary prints.
        assert_eq!(graced.total(), 3);
    }

    #[test]
    fn an_exception_excuses_an_unreviewed_grant_for_the_crate_it_names() {
        let p = Policy::parse(
            r#"
            version = 1
            [grants."openssl-sys"]
            capabilities = ["net"]
            why = "observed"
            [[exception]]
            crate = "openssl-sys"
            expires = "2026-09-20"
            reason = "a reason"
            author = "ada@example.com"
            "#,
        )
        .unwrap();
        let glass = p.break_glass(day("2026-09-15")).unwrap();
        let u = p.unreviewed(None, &glass);
        assert_eq!(
            u.count(),
            0,
            "the exception is what stands the refusal down"
        );
        assert_eq!(
            u.excepted,
            vec![("openssl-sys".to_string(), "2026-09-20".to_string())]
        );
        // The day after, the same policy fails again — closed, without an edit.
        let lapsed = p.break_glass(day("2026-09-21")).unwrap();
        assert_eq!(p.unreviewed(None, &lapsed).count(), 1);
    }

    #[test]
    fn a_policy_with_no_exceptions_resolves_to_nothing_on_any_day() {
        let p = Policy::parse("version = 1").unwrap();
        let glass = p.break_glass(day("2026-09-15")).unwrap();
        assert!(glass.is_empty());
        assert!(glass.covering("anything", Capability::Net).is_none());
    }
}
