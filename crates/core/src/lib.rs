//! `buildclamp-core` — the policy model, and nothing that touches a kernel.
//!
//! buildclamp runs every third-party `build.rs` and proc-macro inside a declared
//! capability envelope. This crate is the half that decides *what* the envelope is; the
//! half that makes a kernel enforce it is `buildclamp-sandbox`, and the two do not know
//! each other exists.
//!
//! That split is the crate's reason for being. A wrong answer here — resolving the wrong
//! envelope for a build unit, or misreading a rustc command line so a build script is
//! never held at all — is the only way a unit can run under rules nobody chose. So this
//! surface stays pure: no I/O, no `libc`, no cargo, no clock, no `unsafe`. Every policy
//! decision the tool makes is testable with `cargo test -p buildclamp-core` on any
//! machine, including one with no Landlock, no user namespaces and no seccomp — which
//! is not a hypothetical, because this project's own CI host is such a machine.
//!
//! # The four things in here
//!
//! * [`capability`] — the closed set of things a build unit can be granted, and the
//!   bitset that makes comparing two of them (drift detection) one instruction.
//! * [`unit`] — what a build unit is, and recovering one from a rustc argv.
//! * [`policy`] and [`envelope`] — `buildclamp.toml`, and resolving it to an answer.
//! * [`report`] — what happened, in a versioned JSON schema whose types make it
//!   impossible to record an outcome without recording which enforcement tier actually
//!   applied.
//!
//! Plus [`generate`], which turns a recorded run into a starting policy, and
//! [`envscrub`], which decides what a unit does not get to see in its environment.
//!
//! # Vocabulary
//!
//! The words are load-bearing, because a security tool's words about other people's code
//! end up in their issue tracker. A **build unit** is one `build.rs` execution or one
//! proc-macro expansion, named by crate and version — never "the crate", so the language
//! never implicates an author. A **capability envelope** is what a unit may do; a unit
//! running under one is **held**. A **grant** gives a unit a capability and carries a
//! required `why`. A request the envelope does not cover is an **ungranted request** —
//! not a violation, a breach or an escape. A project with fifty grants is a correctly
//! configured project.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod attest;
pub mod b64;
pub mod baseline;
pub mod breakglass;
pub mod capability;
pub mod civil;
pub mod envelope;
pub mod envscrub;
pub mod floor;
pub mod fuzzcheck;
pub mod generate;
pub mod layer;
pub mod policy;
pub mod report;
pub mod sha256;
pub mod signed_policy;
pub mod unit;
pub mod wire;
pub mod withhold;

pub use crate::attest::{
    pae, verify_statement, EnforcementProfile, Envelope as DsseEnvelope, Erratum, ErratumMatch,
    Predicate, Scope, Signature as DsseSignature, Statement, Subject, Verified, VerifyError,
    DSSE_PAYLOAD_TYPE, ERRATUM_PREDICATE_TYPE, PREDICATE_TYPE, PREDICATE_VERSION, STATEMENT_TYPE,
};
pub use crate::baseline::{Acceptance, Baseline, BaselineError, BaselineRef, BASELINE_VERSION};
pub use crate::breakglass::{
    BreakGlass, Exception, Grace, GraceNote, Unreviewed, DEFAULT_ACTIVE_EXCEPTION_CAP,
    MAX_EXCEPTION_DAYS,
};
pub use crate::capability::{Capability, CapabilitySet};
pub use crate::civil::Date;
pub use crate::envelope::{Envelope, EnvelopeSource, WriteZone};
pub use crate::envscrub::{scrub, EnvDecision};
pub use crate::floor::{Floor, FloorError, Grade};
pub use crate::generate::{
    observations, policy_from_report, policy_from_report_accepting, Observation,
};
pub use crate::layer::{Layer, LayerDecl, Stack};
pub use crate::policy::{
    Enforcement, Grant, LayerConflict, Mode, Policy, PolicyError, DEFAULT_ENV_DENY,
    OLDEST_POLICY_VERSION, POLICY_VERSION,
};
pub use crate::report::{
    rfc3339_utc, Attribution, DisableOverride, ExceptionUse, HostCapabilities, Outcome, RepoRef,
    Report, ReportError, Request, Run, Tier, UnitRecord, Verdict, ECOSYSTEM, REPORT_FORMAT_VERSION,
};
pub use crate::signed_policy::{
    check_layers, LayerSignature, PolicyProvenance, SignedPolicyError, TrustRoot, TrustRootError,
    TrustedKey,
};
pub use crate::unit::{classify, RustcInvocation, UnitId, UnitKind};
pub use crate::wire::Forward;
pub use crate::withhold::{Withheld, RESIDUAL_EXPOSURE, WITHHELD_READ_PATHS};

/// The environment variable naming the policy file, set by the driver and read by the
/// wrapper and the launcher. Its **presence is the switch**: with it unset, every role
/// passes straight through and touches nothing, so a stray `RUSTC_WRAPPER` left in a
/// shell cannot mutate a target directory on an ordinary build.
pub const ENV_POLICY: &str = "BUILDCLAMP_POLICY";

/// The run directory, where each unit writes its JSON record and the driver reads them
/// back. One directory per run rather than one shared file, because units run
/// concurrently under `cargo --jobs N` and appending to a shared file from several
/// processes is a corruption waiting for a busy build.
pub const ENV_RUN_DIR: &str = "BUILDCLAMP_RUN";

/// The trusted directory holding the proc-macro inventory.
///
/// Deliberately **not** under the run directory. The run directory lives under `target/`,
/// and a held compile unit is granted all of `target/` (rustc writes over it), so anything
/// under it — including the object→unit mapping attribution and attestation trust — can be
/// forged by the very code the sandbox is holding. The driver creates this directory outside
/// every sandbox-writable zone and passes its path here, so `read_macros` reads only what the
/// trusted wrapper wrote. Unset falls back to the run directory (no trusted plane; older
/// driver), which is why the fallback is documented rather than silent.
pub const ENV_MACRO_DIR: &str = "BUILDCLAMP_MACROS";

/// Set inside every held unit. A wrapper that sees it passes through.
///
/// Three independent reasons, any one of which is sufficient: the parent's namespaces
/// and seccomp filter are already inherited, so a second sandbox adds nothing; only one
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER` filter is permitted per task, so a second install
/// would fail; and a read-only `/proc` inside the mount namespace makes writing the
/// `uid_map` of a nested user namespace impossible.
pub const ENV_INSIDE: &str = "BUILDCLAMP_INSIDE";

/// A previous `RUSTC_WRAPPER` to chain to, such as `sccache`.
pub const ENV_INNER_WRAPPER: &str = "BUILDCLAMP_INNER_WRAPPER";

/// The mode override, so `observe` does not need a second policy file.
pub const ENV_MODE: &str = "BUILDCLAMP_MODE";

/// Path to a trusted file listing the manifest directories of the packages in the workspace
/// being built, one per line.
///
/// Set by the driver from `cargo metadata` so the wrapper and launcher can tell a
/// first-party crate from a dependency by matching `CARGO_MANIFEST_DIR`. Directories, not
/// names: two packages can share a name (a workspace member and a registry dependency of the
/// same name), and a name match would run that dependency's build script unheld under
/// `trust-workspace`, whereas a directory is unique to one crate. `CARGO_PRIMARY_PACKAGE` is
/// set only for the packages named on the command line, so a workspace member compiled as a
/// dependency of the selected one does not carry it and would resolve as third-party.
///
/// A **file path**, not the list inline: a large monorepo's member set can exceed one
/// environment entry's `MAX_ARG_STRLEN` limit (128 KiB) and fail `execve` with `E2BIG` before
/// cargo starts. The file lives outside every sandbox-writable path, so a held unit cannot
/// forge its own membership. Absent, or a file that cannot be read (an older driver, or
/// metadata that could not be produced), means the wrapper falls back to the
/// `CARGO_PRIMARY_PACKAGE` signal, which is the prior behaviour.
pub const ENV_WORKSPACE_MEMBERS: &str = "BUILDCLAMP_WORKSPACE_MEMBERS";

/// An operator-set identifier for the agent that produced a report, recorded in the run
/// header.
///
/// Opaque and never derived from the host. A fleet with more than one runner needs to tell
/// two reports apart; a fleet with one does not set it and the field stays null. Nothing
/// in this tool reads a hostname, a MAC address or a username to fill it in — see
/// `crates/cli/src/runmeta.rs`, which argues the same point about the run id.
pub const ENV_AGENT_ID: &str = "BUILDCLAMP_AGENT_ID";

/// An opaque string tying a report back to the CI job that produced it.
///
/// Recorded verbatim and never parsed. Every CI system spells its own job identity
/// differently and a schema for all of them would be a second thing to keep current, so
/// the correlation is the consumer's to make.
pub const ENV_CI_CORRELATION: &str = "BUILDCLAMP_CI_CORRELATION";

/// The day the driver started, `YYYY-MM-DD`, so every unit in one run answers the same
/// calendar question.
///
/// Passed rather than read, and that is the whole reason it exists. The launcher is a
/// separate process that re-parses `buildclamp.toml` for itself, so it could ask its own
/// clock what day it is — and then a build that crosses midnight would run half its units
/// under an exception and half without one, with nothing in the report to say why. It
/// would also let a unit be held to a day the driver never checked the seven-day bound or
/// the active cap against.
///
/// Absent or unreadable means **no exceptions apply**, which is the fail-closed reading:
/// a launcher that cannot establish the date cannot establish that a block has not
/// expired.
pub const ENV_TODAY: &str = "BUILDCLAMP_TODAY";

/// Set by `observe --deep`: record every write a held unit makes, not only the ones a
/// kernel-enforced filesystem tier would have refused.
///
/// The driver was setting this string literally and nothing read it, so `--deep` was a
/// flag with no consumer. It is a named constant here for the same reason every other
/// role-to-role variable is: the producer and the consumer must not be able to disagree
/// about the spelling.
pub const ENV_DEEP: &str = "BUILDCLAMP_DEEP";

/// Exit codes, which are part of the contract with CI.
///
/// The 0/1/2 split is what lets a pipeline tell "the tool broke" from "the tool worked
/// and the answer was no". A pipeline that treats them the same either ignores real
/// findings or blocks on unrelated breakage, and this is the same contract every sibling
/// module in this repository uses.
pub mod exit {
    /// Everything the policy asked for held.
    pub const OK: i32 = 0;
    /// buildclamp itself failed, or the underlying cargo build failed.
    pub const FAILED: i32 = 1;
    /// The policy's answer was no: an ungranted request, an unreviewed grant under
    /// `--strict`, or advisory-only enforcement under `--require-enforced`.
    pub const UNGRANTED: i32 = 2;
}
