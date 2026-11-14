//! The capability report: what every build unit asked for, and what happened.
//!
//! The report is the product's output. A person reads the one line cargo prints when a
//! unit is refused; everything else — CI gates, review tooling, drift signals built on
//! top of it — reads this JSON. It is therefore a versioned format with a
//! stated compatibility rule, not an incidental serialisation of whatever structs the
//! tool happened to have.
//!
//! # The honesty requirement, encoded in the types
//!
//! Every capability in every unit carries the [`Tier`] that actually applied **on the
//! host this ran on**. That is not decoration. Landlock is absent on some kernels, user
//! namespaces are blocked on some distributions and inside some container runtimes, and
//! seccomp user-notification decisions about paths are racy by construction. A report
//! that said "enforced" without saying how would be exactly the incomplete sandbox
//! giving a false sense of security that the Rust maintainers named as their objection
//! to this whole category. So the type makes it impossible to record an outcome without
//! recording the tier, and `--require-enforced` lets a build refuse to pass on advisory
//! enforcement alone.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::breakglass::BreakGlass;
use crate::capability::{Capability, CapabilitySet};
use crate::envelope::Envelope;
use crate::policy::Mode;
use crate::unit::{UnitId, UnitKind};
use crate::wire::Forward;

/// The report schema version. A consumer that finds a higher number must say so rather
/// than parse what it recognises.
///
/// # 2 — the run header, and `tiers` as a map
///
/// Version 1 had no place to record anything true of the *whole build*: which commit it
/// ran on, which target triple it compiled for, which CI job it belonged to. Every
/// consumer that needed one of those invented it. A cross-deployment aggregator in this
/// repository put `host.arch` — `x86_64` — into a field documented as a target triple, so
/// two deployments on the same architecture and different triples were folded together;
/// a capability difference between a `-gnu` and a `-musl` build would then have read as a
/// change in the crate. [`Run`] is that missing object.
///
/// Version 1 also spelled a unit's tiers as an array of `[capability, tier]` pairs, which
/// cannot say "one tier per capability" and cannot be indexed by a reader without a scan.
/// It is a map in version 2.
///
/// A v1 document is still read: [`Report::from_json`] migrates it. Only the *future* is
/// refused, and the pinned corpus in `crates/core/tests/golden` is what keeps that true.
pub const REPORT_FORMAT_VERSION: u32 = 2;

/// How a capability was actually constrained on this host.
///
/// The distinction between `Enforced` and `Advisory` is the single most important fact
/// in the report, so it is a variant rather than a boolean plus a note.
///
/// # A grade this build has never heard of
///
/// [`Tier::Unrecognised`] is the forward-compatibility arm, and it exists because the
/// alternative is worse than useless: a document carrying one unknown grade used to fail
/// to deserialise at the top level, taking every unit, every request and every other tier
/// in the run with it. The grade string is kept verbatim rather than collapsed to a
/// label, so a report read and written again is not quietly rewritten.
///
/// It is **not enforced**, and [`Tier::is_unenforced`] counts it with the
/// weakest thing a tier can be. That direction is not arbitrary: a reader that treated an
/// unknown grade as enforcement would let `--require-enforced` pass on a run whose
/// enforcement it could not evaluate, which is precisely the false success this schema
/// exists to prevent.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(from = "TierWire", into = "TierWire")]
pub enum Tier {
    /// The kernel refuses the operation. The build unit cannot proceed past it whatever
    /// it does, and there is no window in which it might.
    Enforced {
        /// `landlock-v7`, `netns`, `mountns-ro`, `seccomp-errno`, `scrub+userns`. Every
        /// value here is one some code path actually produces — a claim this comment has
        /// been wrong about in both directions, so it is worth re-checking against
        /// `plan_tiers` rather than trusting. `seccomp-notify-record` is deliberately NOT
        /// here: it is a notification mechanism, so it is advisory, and
        /// `crates/sandbox/tests/no_continue_is_enforced.rs` forbids it appearing as an
        /// enforced tier.
        mechanism: String,
    },
    /// The operation is observed and answered, but the decision is not atomic with the
    /// operation.
    ///
    /// This is what `SECCOMP_USER_NOTIF_FLAG_CONTINUE` buys: the supervisor reads the
    /// path or address out of the target's memory, decides, and answers — and for a
    /// `CONTINUE` the kernel then re-reads the argument, so a determined script can
    /// change it in between. Good enough to see what a build does; not good enough to
    /// call enforcement, and never described as such.
    ///
    /// Mechanisms: `seccomp-notify` (a path or address decision) and
    /// `seccomp-notify-record` (exec, which is recorded and never refused). Both are
    /// answered by the notification supervisor, which is what makes them advisory.
    Advisory {
        mechanism: String,
        /// Why it is only advisory, in a sentence, carried into the report so a reader
        /// never has to come and ask.
        limitation: String,
    },
    /// Nothing constrained this capability on this host.
    None {
        /// What was missing — `landlock: ENOSYS`, `userns: EPERM (apparmor restricted)`.
        reason: String,
    },
    /// A grade written by a newer buildclamp than the one reading it.
    ///
    /// Never produced by this build; only ever read. Treated as weaker than
    /// [`Tier::None`] wherever strength is compared, because "I cannot evaluate this"
    /// must not be allowed to answer "was this enforced?" with a yes.
    Unrecognised {
        /// The grade as it was written, kept so the document survives a round trip.
        grade: String,
    },
}

/// How a [`Tier`] is spelled on the wire.
///
/// A hand-written intermediate rather than `#[serde(tag = "grade")]` plus
/// `#[serde(other)]`, because serde's `other` attribute only accepts a **unit** variant,
/// and a unit variant would throw away the grade string — turning an unreadable document
/// into a silently altered one. The field order and the `skip_serializing_if` here
/// reproduce the tagged representation byte for byte, which the golden corpus pins.
#[derive(Serialize, Deserialize)]
struct TierWire {
    grade: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mechanism: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limitation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl From<TierWire> for Tier {
    fn from(w: TierWire) -> Self {
        match (w.grade.as_str(), w.mechanism, w.limitation, w.reason) {
            ("enforced", Some(mechanism), _, _) => Tier::Enforced { mechanism },
            ("advisory", Some(mechanism), Some(limitation), _) => Tier::Advisory {
                mechanism,
                limitation,
            },
            ("none", _, _, Some(reason)) => Tier::None { reason },
            // A known grade missing the field that gives it meaning is not a known tier.
            // Falling back here rather than defaulting the field keeps the type's central
            // promise — that no outcome can be recorded without saying how it was
            // constrained — true of documents as well as of code.
            (grade, _, _, _) => Tier::Unrecognised {
                grade: grade.to_string(),
            },
        }
    }
}

impl From<Tier> for TierWire {
    fn from(t: Tier) -> Self {
        match t {
            Tier::Enforced { mechanism } => TierWire {
                grade: "enforced".into(),
                mechanism: Some(mechanism),
                limitation: None,
                reason: None,
            },
            Tier::Advisory {
                mechanism,
                limitation,
            } => TierWire {
                grade: "advisory".into(),
                mechanism: Some(mechanism),
                limitation: Some(limitation),
                reason: None,
            },
            Tier::None { reason } => TierWire {
                grade: "none".into(),
                mechanism: None,
                limitation: None,
                reason: Some(reason),
            },
            Tier::Unrecognised { grade } => TierWire {
                grade,
                mechanism: None,
                limitation: None,
                reason: None,
            },
        }
    }
}

impl Tier {
    pub fn is_enforced(&self) -> bool {
        matches!(self, Tier::Enforced { .. })
    }

    /// Was this capability held by something, even something defeatable?
    ///
    /// The question `--require-enforced` used to ask was "is any tier advisory?", which
    /// answers *no* for [`Tier::None`] — a run where nothing constrained the capability at
    /// all passed a flag whose entire purpose is to refuse a build that could not be
    /// enforced. See [`Report::exit_code`].
    pub fn is_unenforced(&self) -> bool {
        matches!(self, Tier::None { .. } | Tier::Unrecognised { .. })
    }

    /// A short label for the terminal summary.
    pub fn label(&self) -> String {
        match self {
            Tier::Enforced { mechanism } => format!("enforced:{mechanism}"),
            Tier::Advisory { mechanism, .. } => format!("advisory:{mechanism}"),
            Tier::None { .. } => "none".to_string(),
            Tier::Unrecognised { grade } => format!("unrecognised:{grade}"),
        }
    }
}

/// One thing a build unit asked to do.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Request {
    /// Milliseconds since the unit started. Relative, not wall-clock: a report that
    /// carried absolute timestamps would differ on every run and be useless to diff,
    /// and diffing two reports is how drift is found.
    pub at_ms: u64,
    /// The thread that made the request. Present because a build script's children are
    /// held by the same filter, so a request may come from `cc` rather than the script.
    pub tid: i32,
    /// What was being asked for.
    ///
    /// Wrapped because a capability named by a newer agent must not take the whole
    /// document down with it; see [`crate::wire::Forward`]. This build never writes an
    /// unknown one.
    pub capability: Forward<Capability>,
    /// The syscall, for someone reading the report against `strace` output.
    pub syscall: String,
    /// What was asked for: `203.0.113.7:443`, `/home/ci/.config/autostart/x.desktop`,
    /// `/usr/bin/cc`. Best-effort — see [`Tier::Advisory`].
    pub target: String,
    /// What happened.
    pub outcome: Outcome,
    /// Which code inside the unit made the request, when that could be determined.
    ///
    /// Only meaningful for a compile unit, where the "unit" is a whole rustc process
    /// that may have loaded several proc-macros. For a build script the unit is already
    /// one crate's code, so this is [`Attribution::Unit`].
    #[serde(default)]
    pub attribution: Attribution,
}

/// Who inside a build unit made a request.
///
/// This exists because of the one thing every prior tool in this space gets wrong in the
/// same way: proc-macro expansion happens inside the rustc that compiles the *consumer*,
/// so a sandbox around rustc can only ever say "something in this compilation did it".
/// `cargo-acl`, the closest existing tool, states the limitation outright — one grant
/// covers every proc-macro in the build. Doing better is the strongest genuinely
/// unclaimed thing in this category, so the type records how confident the attribution
/// is rather than pretending the answer is always exact.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(from = "AttributionWire", into = "AttributionWire")]
pub enum Attribution {
    /// The unit is the answer: a build script is one crate's code.
    #[default]
    Unit,
    /// The instruction pointer at the syscall fell inside a known proc-macro's shared
    /// object. Read from `/proc/<tid>/syscall` and resolved against `/proc/<tid>/maps`.
    /// This is the good case and it names one macro.
    Exact { proc_macro: UnitId },
    /// The instruction pointer was in libc or libstd, and a scan of the stack found a
    /// return address inside this proc-macro's shared object. Lower confidence: a stack
    /// scan can find a stale frame, so it names a likely culprit rather than a certain
    /// one.
    StackScan { proc_macro: UnitId },
    /// Neither worked. The request belongs to the compilation, and these are the
    /// proc-macros that were in its closure — the same answer cargo-acl gives, which is
    /// where this degrades to rather than to nothing.
    Closure,
    /// A confidence level written by a newer buildclamp than the one reading it.
    ///
    /// Read, never produced. A reader must not upgrade it: an unrecognised confidence is
    /// not [`Attribution::Exact`], and a tool that guessed would put a named crate next
    /// to a syscall on somebody's evidence that nothing here established.
    Unrecognised {
        /// The confidence as it was written.
        confidence: String,
    },
}

/// How an [`Attribution`] is spelled on the wire. See [`TierWire`] for why this is a
/// hand-written intermediate rather than `#[serde(other)]`.
#[derive(Serialize, Deserialize)]
struct AttributionWire {
    confidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proc_macro: Option<UnitId>,
}

impl From<AttributionWire> for Attribution {
    fn from(w: AttributionWire) -> Self {
        match (w.confidence.as_str(), w.proc_macro) {
            ("unit", _) => Attribution::Unit,
            ("exact", Some(proc_macro)) => Attribution::Exact { proc_macro },
            ("stack-scan", Some(proc_macro)) => Attribution::StackScan { proc_macro },
            ("closure", _) => Attribution::Closure,
            (confidence, _) => Attribution::Unrecognised {
                confidence: confidence.to_string(),
            },
        }
    }
}

impl From<Attribution> for AttributionWire {
    fn from(a: Attribution) -> Self {
        match a {
            Attribution::Unit => AttributionWire {
                confidence: "unit".into(),
                proc_macro: None,
            },
            Attribution::Exact { proc_macro } => AttributionWire {
                confidence: "exact".into(),
                proc_macro: Some(proc_macro),
            },
            Attribution::StackScan { proc_macro } => AttributionWire {
                confidence: "stack-scan".into(),
                proc_macro: Some(proc_macro),
            },
            Attribution::Closure => AttributionWire {
                confidence: "closure".into(),
                proc_macro: None,
            },
            Attribution::Unrecognised { confidence } => AttributionWire {
                confidence,
                proc_macro: None,
            },
        }
    }
}

/// What the tool did about a request.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum Outcome {
    /// The envelope granted it.
    Granted,
    /// The envelope did not grant it and the run refused it.
    ///
    /// Named `Ungranted`, not `Denied` or `Violation`. The finding is about the policy
    /// not covering something, not about the crate having done wrong, and the words a
    /// security tool uses about other people's code end up in their issue tracker.
    Ungranted {
        /// The errno the unit saw, so a confusing build failure can be traced back.
        errno: i32,
    },
    /// Observe mode: nothing was refused, and this is what enforce mode would have done.
    WouldBeUngranted,
}

impl Outcome {
    /// Does this outcome make the run fail in enforce mode?
    pub fn is_ungranted(&self) -> bool {
        matches!(self, Outcome::Ungranted { .. } | Outcome::WouldBeUngranted)
    }
}

/// The record for one build unit.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct UnitRecord {
    pub id: UnitId,
    pub kind: Forward<UnitKind>,
    /// Where the crate came from, for a human. Not part of identity — see [`UnitId`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Which *run* of this unit this record is.
    ///
    /// One compiled build script is executed more than once per build whenever a crate is
    /// both a normal and a build dependency under `--target` — `libc`, `cfg-if`, `serde`
    /// and `proc-macro2` in practically every cross build. Measured on cargo 1.94.1: the
    /// same `build-script-build` binary runs twice, interleaved by cargo's scheduler,
    /// with identical `CARGO_PKG_NAME`, `CARGO_PKG_VERSION`, `CARGO_MANIFEST_DIR` and
    /// even `TARGET`, distinguished **only** by `OUT_DIR`.
    ///
    /// So identity by name and version alone loses one of the two records, and if the
    /// lost one is the run that made an ungranted request the report says the unit was
    /// clean. This carries the basename of `OUT_DIR`'s parent, which cargo guarantees is
    /// unique per run, and it is deterministic rather than a pid so two runs of the same
    /// build still produce comparable reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    pub envelope: Envelope,
    /// The tier that applied per capability on this host.
    ///
    /// A **map**, one tier per capability. Version 1 spelled this as an array of
    /// `[capability, tier]` pairs, which could represent two tiers for one capability —
    /// a document that says a thing was both enforced and not — and forced every reader
    /// to scan the list to answer "how was the network held?". The map makes the first
    /// unrepresentable and the second an index.
    pub tiers: BTreeMap<Forward<Capability>, Tier>,
    /// Environment names removed before the unit started.
    ///
    /// Names only, never values. A report that carried the value of a scrubbed secret
    /// would be a tool that wrote credentials to disk in the course of protecting them.
    pub env_scrubbed: Vec<String>,
    pub requests: Vec<Request>,
    /// The capability set the unit actually exercised. The observe-mode output, the
    /// input to `init`, and the unit of drift detection.
    pub observed: CapabilitySet,
    /// Proc-macros in this unit's dependency closure, for a compile unit.
    ///
    /// This is the whole of the attribution available for anything a proc-macro does:
    /// expansion happens inside the rustc compiling the consumer, so the report can name
    /// the consumer and list the macros that could have been responsible, and no more.
    /// `docs/adr/0004` argues why that is worth shipping anyway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proc_macros_in_closure: Vec<UnitId>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub duration_ms: u64,
}

impl UnitRecord {
    /// Requests this unit made that its envelope did not cover.
    pub fn ungranted(&self) -> impl Iterator<Item = &Request> {
        self.requests.iter().filter(|r| r.outcome.is_ungranted())
    }

    /// Was any capability of this unit constrained only advisorily?
    pub fn has_advisory_tier(&self) -> bool {
        self.tiers.iter().any(|(cap, tier)| {
            // An observe-only capability (exec) is advisory on every host that can record
            // at all — it is recorded, never refused, by design. Counting it here would
            // make `--require-enforced` fail on every host forever, which is not a false
            // assurance being caught, it is a floor being unsatisfiable. A capability this
            // build does not recognise is NOT skipped: an unknown name might well be one a
            // newer buildclamp does refuse, and treating it as observe-only would be the
            // permissive guess.
            let observe_only = cap.copied().is_some_and(Capability::is_observe_only);
            !observe_only && matches!(tier, Tier::Advisory { .. })
        })
    }

    /// Was any capability of this unit left unconstrained, or constrained by a grade this
    /// build cannot evaluate?
    ///
    /// Separate from [`UnitRecord::has_advisory_tier`] because the two answer different
    /// questions and only one of them used to be asked. `--require-enforced` tested for
    /// advisory tiers alone, so a unit whose every tier was [`Tier::None`] — nothing
    /// enforced, on a host that could not enforce — passed it. That is the exact shape of
    /// the failure this project names in its competitor: a control reporting success
    /// while enforcing nothing.
    ///
    /// The tier for a capability the **policy granted** is also `None`, and it must not
    /// fail the flag: "the policy grants this unit the network" is a decision, not a
    /// missing mechanism. So this asks about capabilities the envelope did *not* grant,
    /// which are the ones enforcement was supposed to hold.
    pub fn has_unenforced_tier(&self) -> bool {
        self.tiers.iter().any(|(cap, tier)| {
            let granted = cap
                .copied()
                .is_some_and(|c| self.envelope.granted.contains(c));
            !granted && tier.is_unenforced()
        })
    }

    /// Capability, unit-kind and tier-grade names in this record that this build does not
    /// know, which is how a reader says so out loud instead of under-reporting quietly.
    pub fn unknown_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Forward::Unknown(k) = &self.kind {
            out.push(format!("unit kind `{k}`"));
        }
        for cap in self.tiers.keys() {
            if let Forward::Unknown(c) = cap {
                out.push(format!("capability `{c}`"));
            }
        }
        for r in &self.requests {
            if let Forward::Unknown(c) = &r.capability {
                out.push(format!("capability `{c}`"));
            }
            if let Attribution::Unrecognised { confidence } = &r.attribution {
                out.push(format!("attribution confidence `{confidence}`"));
            }
        }
        for t in self.tiers.values() {
            if let Tier::Unrecognised { grade } = t {
                out.push(format!("tier grade `{grade}`"));
            }
        }
        for z in &self.envelope.write_zones {
            if let Forward::Unknown(z) = z {
                out.push(format!("write zone `{z}`"));
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

/// What the host could actually do, probed once per run and printed by `doctor`.
///
/// Recorded in every report because "was this enforced?" is unanswerable without it, and
/// because a report mailed from a CI runner to a reviewer has to carry its own context.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct HostCapabilities {
    pub os: String,
    pub kernel: String,
    pub arch: String,
    /// The Landlock ABI level, or `None` where the syscall is absent.
    pub landlock_abi: Option<i32>,
    pub user_namespaces: bool,
    pub seccomp_user_notif: bool,
    /// Whether `/proc` hides other processes' `environ` from the same user.
    ///
    /// Reported as a visibility signal, not as the protection — `hidepid` hides the
    /// processes of *other* users, and a build script runs as the same user as cargo, so
    /// on a host with it set cargo's environ is still readable. What closes that is the
    /// user namespace: a child user namespace fails `ptrace_may_access` against the
    /// parent's, so the open returns `EPERM`. Measured — `CLONE_NEWPID` alone leaves the
    /// read working and `CLONE_NEWUSER` alone stops it. Without the namespace a build
    /// script reads secrets from the environment of any process the user owns, whatever
    /// this field says, and scrubbing its own environment does not change that. Measured
    /// on a stock Ubuntu 24.04 kernel: a fixture build script read 7,883 bytes of its
    /// parent's environ and found both planted credentials.
    pub proc_hidepid: bool,
}

/// Where the source came from, when the run happened in a git checkout.
///
/// Every field is optional and the whole object is absent outside a checkout. A build in
/// an unpacked tarball, a vendored source tree or a container with `.git` excluded is an
/// ordinary build, not an error, and a report that refused to be written there would make
/// buildclamp the reason a release pipeline failed.
///
/// # The remote is scrubbed before it is recorded
///
/// A git remote is a URL, and a URL has a userinfo component: CI systems configure
/// `https://x-access-token:<token>@github.com/org/repo` routinely. Copying that into a
/// report would write a live credential to disk in the course of protecting one, which is
/// the failure `env_scrubbed` exists to prevent one field further up. [`RepoRef::record`]
/// drops userinfo, and the test named for it is why this paragraph can be believed.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct RepoRef {
    /// The `origin` remote, with any userinfo removed.
    pub remote: Option<String>,
    /// The resolved commit, full hex.
    pub commit: Option<String>,
    /// The symbolic ref `HEAD` pointed at — `refs/heads/main`. Absent on a detached head.
    #[serde(rename = "ref")]
    pub reference: Option<String>,
}

impl RepoRef {
    /// Build a record, dropping credentials out of the remote URL.
    ///
    /// `https://user:token@host/org/repo.git` becomes `https://host/org/repo.git`. An
    /// `ssh://` or `git@host:org/repo` remote has no password component and passes
    /// through unchanged apart from a `user@` prefix, which is a username and not a
    /// secret but is dropped anyway: it is not needed to identify the repository, and a
    /// field this small should not be the one that has to be right about which usernames
    /// are also tokens.
    pub fn record(
        remote: Option<String>,
        commit: Option<String>,
        reference: Option<String>,
    ) -> Self {
        Self {
            remote: remote.as_deref().map(sanitise_remote),
            commit,
            reference,
        }
    }
}

/// Strip the userinfo component from a remote URL.
fn sanitise_remote(url: &str) -> String {
    // Split on the LAST `@` before the first `/` of the path, so a password containing an
    // `@` cannot smuggle the rest of itself through.
    let (scheme, rest) = match url.find("://") {
        Some(i) => (&url[..i + 3], &url[i + 3..]),
        // `git@github.com:org/repo.git` — scp syntax, no scheme.
        None => ("", url),
    };
    let host_start = rest.find('/').unwrap_or(rest.len());
    match rest[..host_start].rfind('@') {
        Some(at) => format!("{scheme}{}", &rest[at + 1..]),
        None => url.to_string(),
    }
}

/// Everything true of the whole build rather than of one unit.
///
/// # Why this is a sibling of `units` and not fields on [`Report`]
///
/// Because of what it must NOT contaminate. `Request::at_ms` is deliberately relative to
/// the start of its unit so that two runs of the same build produce byte-identical
/// `units`, which is what makes a report diffable and drift detectable. Everything that
/// legitimately differs between two such runs — the clock, the run id, the CI job — is
/// gathered here instead, where a consumer can strip one object and compare the rest.
/// `crates/core/tests/schema.rs` pins that property.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Run {
    /// A fresh identifier per run. Opaque: it identifies a run to somebody correlating
    /// two documents, and it is not derived from anything about the machine or the user.
    pub run_uuid: String,
    /// When the run started, RFC 3339 in UTC.
    pub started_at: Option<String>,
    /// When the report was written.
    pub finished_at: Option<String>,
    /// The checkout, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<RepoRef>,
    /// The **target triple** this build compiled for — `x86_64-unknown-linux-gnu`.
    ///
    /// [`HostCapabilities`] carries `os`, `kernel` and `arch` and no triple, and the
    /// first consumer that needed one reached for `arch` — putting `x86_64` into a field
    /// its own documentation called a target triple, which merges `-gnu` and `-musl`
    /// deployments into one bucket. A capability difference between two libcs then reads
    /// as a change in the crate rather than as the platform difference it is.
    pub target: Option<String>,
    /// Who produced the report, for a fleet with more than one agent. Opaque and
    /// operator-set; nothing derives it from the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// An opaque string a CI system can set to tie this report back to its own job.
    ///
    /// Recorded verbatim and never parsed. Correlating a report with a pipeline is the
    /// consumer's job; inventing a schema for every CI system's identifiers would be a
    /// second thing to keep current.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci_correlation: Option<String>,
    /// Which package ecosystem this run belongs to. `cargo` today, and a coordinate
    /// rather than a constant so a store aggregating reports is not rebuilt the first
    /// time something else emits this format.
    pub ecosystem: String,

    /// Whether every distributed policy layer this run resolved was signed by a key in the
    /// repository's committed trust root.
    ///
    /// `false` when a distributed layer was unsigned or wrongly signed, and also when no
    /// trust root is in use — the honest default, since a repository that has not adopted
    /// signed policy has verified nothing. `--require-signed-policy` turns an unverified
    /// distributed layer into a refusal before the build; without it this field is how a
    /// reader sees that a layer's authority was not established. Additive: a report written
    /// before this field parses with it `false`.
    #[serde(default)]
    pub policy_signature_verified: bool,

    /// The trust-root key id(s) that verified the distributed layers, when any did — a
    /// single id, or several joined by commas across a rotation window or multiple layers.
    /// Absent when nothing was verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_signer_key_id: Option<String>,
}

/// The ecosystem this tool holds.
pub const ECOSYSTEM: &str = "cargo";

impl Default for Run {
    fn default() -> Self {
        Self {
            run_uuid: String::new(),
            started_at: None,
            finished_at: None,
            repo: None,
            target: None,
            agent_id: None,
            ci_correlation: None,
            ecosystem: ECOSYSTEM.to_string(),
            policy_signature_verified: false,
            policy_signer_key_id: None,
        }
    }
}

/// Format a Unix timestamp as RFC 3339 in UTC.
///
/// Pure arithmetic, because `crates/core` has no clock and is not getting one: a crate
/// that can be tested with no kernel features and no wall time is worth more than the
/// three lines this saves. The caller reads the clock and passes the number in.
///
/// The civil-date conversion is Howard Hinnant's `civil_from_days`, valid for any date in
/// the proleptic Gregorian calendar, which is a good deal more range than a build report
/// needs and is the version everybody has already checked.
pub fn rfc3339_utc(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60,
    )
}

/// True iff `s` is exactly the canonical UTC timestamp that [`rfc3339_utc`] emits:
/// `YYYY-MM-DDTHH:MM:SSZ` — fixed width, `Z` zone, no numeric offset, no fractional
/// seconds, a real calendar day. This is the inverse of `rfc3339_utc`, and the two are
/// bound together by `is_canonical_utc_accepts_exactly_rfc3339_utc`.
///
/// Lexical (`<`, `>=`) ordering of timestamp strings is chronological **only** for this
/// shape. An offset form such as `09:00:00-01:00` denotes `10:00:00Z` yet sorts before
/// `09:30:00Z`, so any code that orders timestamps as strings must gate on this first.
/// Pure: no clock, no allocation, no time dependency.
pub(crate) fn is_canonical_utc(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 20 || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return false;
    }
    // The date part is validated to a real calendar day by the same parser the rest of the
    // crate uses, so `is_canonical_utc` and `civil::Date` cannot disagree on what a day is.
    if crate::civil::Date::parse(&s[0..10]).is_none() {
        return false;
    }
    let two = |lo: usize| -> Option<u32> {
        let hi = (b[lo] as char).to_digit(10)?;
        let lo = (b[lo + 1] as char).to_digit(10)?;
        Some(hi * 10 + lo)
    };
    match (two(11), two(14), two(17)) {
        // rfc3339_utc never emits a leap second, so 60 is out of range here.
        (Some(h), Some(m), Some(sec)) => h <= 23 && m <= 59 && sec <= 59,
        _ => false,
    }
}

/// The whole run.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Report {
    pub format_version: u32,
    pub tool_version: String,
    pub mode: Mode,
    /// The cargo command that was wrapped, for reproducing the run.
    pub cargo_command: Vec<String>,
    /// Everything true of the whole build. Added in format version 2.
    #[serde(default)]
    pub run: Run,
    pub host: HostCapabilities,
    /// Enforcement the **operator** switched off, as opposed to enforcement this host
    /// could not provide.
    ///
    /// These are different facts and a reader must never have to guess which one they are
    /// looking at. `HostCapabilities` already says what the kernel can do; a tier of
    /// `none` on a capable host and a tier of `none` on a host without user namespaces
    /// look identical in the units, and only one of them is somebody's decision.
    ///
    /// Both switches that can produce one are settable by anyone with control of the CI
    /// environment — a much larger set than the people who can commit to
    /// `buildclamp.toml` — which is precisely why the report has to name them rather than
    /// leave them to be inferred from a tier that went quiet.
    ///
    /// `#[serde(default)]` because this is an additive field: a report written before it
    /// existed had no overrides to record, and empty is the correct reading. See
    /// `crates/core/tests/schema.rs`, which pins that rule.
    #[serde(default)]
    pub disable_overrides: Vec<DisableOverride>,
    /// Refusals a live `[[exception]]` stood down for on this run.
    ///
    /// The free half of what the roadmap sells centralised visibility of. A report that
    /// exited `0` because somebody broke the glass must say so in the document, not only
    /// on the terminal of whoever ran it — the terminal scrolls away and the report is
    /// what a fleet store, a job summary or an auditor reads.
    ///
    /// `#[serde(default)]` for the same reason `disable_overrides` is: a report written
    /// before this existed had no uses to record, and empty is the correct reading.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub break_glass: Vec<ExceptionUse>,
    pub units: Vec<UnitRecord>,
}

/// One unit that ran under a live `[[exception]]`, and what it did with it.
///
/// Keyed on the unit rather than on a refusal, which is a correction rather than a
/// choice. An earlier version listed the ungranted requests an exception excused — and an
/// exception *widens the envelope*, so the requests it covers come back `granted` and
/// this list was empty on exactly the runs that most needed it. A crate that reached the
/// network today because somebody broke the glass yesterday would have produced a report
/// saying "nothing asked for more than its envelope", which is true and, on its own, a
/// lie by omission.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExceptionUse {
    /// The unit that ran wider than the policy alone would have allowed.
    pub unit: UnitId,
    /// The day the exception stops applying, verbatim from the policy.
    pub expires: String,
    /// Who the policy says broke the glass. Self-asserted; see [`crate::Exception::author`].
    pub author: String,
    pub reason: String,
    /// What the block confers. **Empty means every capability** — the block named none —
    /// which is the broad form and is worth seeing as such.
    #[serde(default)]
    pub grants: Vec<Capability>,
    /// What this unit actually exercised while it applied. The line a reviewer reads:
    /// an exception nobody used is a block to delete, and one that was used is a grant to
    /// write.
    pub exercised: CapabilitySet,
    /// Requests the run's verdict stood down for, which the exception could not widen the
    /// envelope enough to let succeed — a write outside the zones is the case that
    /// exists. **The kernel still refused these.** The exception decides what the run
    /// exits with, not what the build script got back.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stood_down: Vec<Forward<Capability>>,
}

/// Everything outside the report that decides a run's exit code.
///
/// A struct rather than four positional arguments because three of the four are booleans
/// and counts, and `exit_code(false, 0, true)` at a call site says nothing about which
/// gate is which. Every field defaults to the permissive value, so a caller asking only
/// "was there an ungranted request?" writes `&Verdict::default()`.
#[derive(Clone, Debug, Default)]
pub struct Verdict {
    /// Refuse a run where some capability could only be held advisorily, or not at all.
    pub require_enforced: bool,
    /// Grants nothing has excused, counted from the **policy**, not from this report.
    pub unreviewed_grants: usize,
    /// Make an ungranted request fail an *observe* run — `cargo buildclamp observe --gate`.
    pub gate_observed: bool,
    /// The `[[exception]]` blocks live today.
    pub glass: BreakGlass,
}

/// One piece of enforcement an operator switched off, and how.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DisableOverride {
    /// The switch, as the operator spelled it: `BUILDCLAMP_MODE` or `BUILDCLAMP_DISABLE`.
    pub source: String,
    /// Its value, verbatim. Recorded rather than interpreted, because a value this build
    /// did not understand is itself worth seeing in a report.
    pub value: String,
    /// What it took away, in the reader's terms rather than the switch's.
    pub effect: String,
}

impl Report {
    /// Whether an operator switched any enforcement off in this run.
    ///
    /// The assertion this exists for: **no run carrying an override may be described as
    /// fully enforced.** A signed attestation over such a run would otherwise say
    /// "enforced" about a build where somebody had turned enforcement off, which is the
    /// overstatement this project exists to avoid — and it would say it in the project's
    /// own name, to an auditor.
    pub fn has_operator_override(&self) -> bool {
        !self.disable_overrides.is_empty()
    }
}

/// Everything that can be wrong with a report a consumer reads back.
///
/// Deliberately separate from [`crate::PolicyError`]: a bad policy is something the user
/// wrote and can fix, while a bad report is something a *tool* wrote, and the useful
/// message is about which tool rather than which line.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("the report is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error(
        "this report declares format version {found}, and this buildclamp understands \
         version {REPORT_FORMAT_VERSION}. It was written by a newer buildclamp than the \
         one reading it, so refusing is the only honest answer: a later version that adds \
         a capability would otherwise be read as a run that never asked for it, and a \
         report that is short reads exactly like a clean one. Upgrade the reader."
    )]
    Future { found: u32 },

    #[error(
        "a v1 report gave capability `{capability}` more than one tier. Migration refuses to \
         pick a winner by document order: a report carrying both `none` and `enforced` for \
         one capability would otherwise migrate to whichever came last, and if that is \
         `enforced` a refused capability reads as enforced and `--require-enforced` accepts \
         it. Fix the source report."
    )]
    DuplicateTier { capability: String },
}

/// Bring a version 1 document up to version 2, in place.
///
/// A reader that understands version N must understand everything version N was built to
/// read, and the pinned v1 corpus is the test of it. Two things changed:
///
/// * `tiers` went from `[[capability, tier], …]` to `{capability: tier}`;
/// * the [`Run`] header appeared, and a v1 document has nothing to put in it, so it gets
///   the default — an empty run id, null timestamps, no repo, no triple. **Null, not
///   invented.** A migration that guessed a target triple from `host.arch` would be the
///   same conflation that made the triple worth adding.
///
/// Anything that is already a map, or missing, is left exactly as it is: the function
/// must be a no-op on a v2 document, because `from_json` does not branch on the version
/// before calling it.
fn migrate_v1_to_v2(raw: &mut serde_json::Value) -> Result<(), ReportError> {
    let Some(units) = raw.get_mut("units").and_then(|u| u.as_array_mut()) else {
        return Ok(());
    };
    for unit in units {
        let Some(tiers) = unit.get_mut("tiers") else {
            continue;
        };
        let Some(pairs) = tiers.as_array() else {
            continue;
        };
        let mut map = serde_json::Map::with_capacity(pairs.len());
        for pair in pairs {
            // A pair that is not `[name, tier]` is left out rather than guessed at. The
            // document is then short a tier, and short is the honest failure: the unit
            // still parses and `unknown_names` has nothing to say about a pair that
            // carried no name.
            let (Some(name), Some(tier)) =
                (pair.get(0).and_then(serde_json::Value::as_str), pair.get(1))
            else {
                continue;
            };
            // A capability with more than one tier is contradictory evidence. Resolving it by
            // input order would let a v1 report carrying both `none` and `enforced` migrate to
            // whichever came last — and an `enforced` last would read a refused capability as
            // enforced. Refuse rather than choose.
            if map.contains_key(name) {
                return Err(ReportError::DuplicateTier {
                    capability: name.to_string(),
                });
            }
            map.insert(name.to_string(), tier.clone());
        }
        *tiers = serde_json::Value::Object(map);
    }
    if let Some(v) = raw.get_mut("format_version") {
        *v = serde_json::Value::from(REPORT_FORMAT_VERSION);
    }
    Ok(())
}

impl Report {
    /// Read a report, refusing one written by a newer buildclamp.
    ///
    /// **Every consumer must come through here rather than calling `serde_json` itself.**
    /// [`REPORT_FORMAT_VERSION`] has carried the sentence "a consumer that finds a higher
    /// number must say so rather than parse what it recognises" since the field existed,
    /// and until this function no consumer did: the version was written by
    /// [`Report::new`] and read by nobody, so a report claiming format version 9
    /// deserialised cleanly in all four readers — the two CLI commands and the two fleet
    /// ones.
    ///
    /// That is the failure this whole tool is about, one layer up. The asymmetry in
    /// `ARCHITECTURE.md` §1 is that a refusal costs a developer minutes and a false
    /// success costs them their credentials, and a reader that silently accepts a
    /// document it does not understand is the false success: serde fills absent fields
    /// from defaults, so a run whose requests this version cannot represent arrives
    /// looking like a run that made none.
    ///
    /// An *older* version is accepted, because a reader that understands version N
    /// understands everything version N was built to read. Only the future is refused.
    pub fn from_json(text: &str) -> Result<Self, ReportError> {
        // The version is read from the raw document BEFORE the report is built, so a
        // future report is refused on its version rather than on whichever field happens
        // to have changed shape first. A `serde_json::Error` from a v2 document would
        // name a field, which sends the reader to the wrong question.
        let raw: serde_json::Value = serde_json::from_str(text)?;
        if let Some(found) = raw
            .get("format_version")
            .and_then(serde_json::Value::as_u64)
        {
            if found > u64::from(REPORT_FORMAT_VERSION) {
                // Saturating rather than `as`: a truncating cast could report a version
                // smaller than this one and turn a refusal into a confusing accept.
                return Err(ReportError::Future {
                    found: u32::try_from(found).unwrap_or(u32::MAX),
                });
            }
        }
        let mut raw = raw;
        migrate_v1_to_v2(&mut raw)?;
        Ok(serde_json::from_value(raw)?)
    }

    pub fn new(tool_version: impl Into<String>, mode: Mode, cargo_command: Vec<String>) -> Self {
        Self {
            format_version: REPORT_FORMAT_VERSION,
            tool_version: tool_version.into(),
            mode,
            cargo_command,
            run: Run::default(),
            host: HostCapabilities::default(),
            disable_overrides: Vec::new(),
            break_glass: Vec::new(),
            units: Vec::new(),
        }
    }

    /// The units, with everything that legitimately differs between two runs of the same
    /// build removed — the shape a consumer diffs.
    ///
    /// # What it removes, and why each one
    ///
    /// * the whole [`Run`] header — the clock, the run id and the CI job are what it is
    ///   *for*, and they differ by construction;
    /// * `duration_ms` on each unit — a wall-clock measurement of a loaded machine;
    /// * `at_ms` and `tid` on each request — a relative timing and a thread id.
    ///
    /// `at_ms` is already relative to the start of its unit rather than absolute, which is
    /// what keeps the ordering of a request stream stable; relative is not the same as
    /// constant, and a diff that reported "this build is different" because one syscall
    /// landed a millisecond later would not be read twice.
    ///
    /// # What it does NOT remove, said plainly
    ///
    /// Everything else, including the `target` of every request — so a build script that
    /// writes a path containing its own pid still differs between two runs. Measured on
    /// this project's own benign fixture, which writes
    /// `…/out/.buildclamp-tmp/benign-probe-<pid>`: two otherwise identical runs differ in
    /// exactly those two request targets and nowhere else. That is the build script's
    /// behaviour, not the schema's, and normalising it away here would mean a tool
    /// deciding which of a build's own paths are "really" the same — which is how a diff
    /// starts hiding the changes it exists to show.
    pub fn diff_view(&self) -> serde_json::Value {
        let mut units = serde_json::to_value(&self.units).unwrap_or(serde_json::Value::Null);
        if let Some(units) = units.as_array_mut() {
            for unit in units.iter_mut() {
                let Some(unit) = unit.as_object_mut() else {
                    continue;
                };
                unit.remove("duration_ms");
                let Some(requests) = unit.get_mut("requests").and_then(|r| r.as_array_mut()) else {
                    continue;
                };
                for request in requests {
                    if let Some(request) = request.as_object_mut() {
                        request.remove("at_ms");
                        request.remove("tid");
                    }
                }
            }
        }
        units
    }

    /// Every name in this document that this build does not know, deduplicated.
    ///
    /// Empty for a report this build wrote. Non-empty means the document came from a
    /// newer buildclamp that adds vocabulary without having bumped `format_version` — the
    /// run is readable, and a consumer that aggregates it is reading less than was
    /// recorded. Printing this is how that stops being silent: a fleet store that
    /// under-reports a capability is wrong in the one direction that matters.
    pub fn unknown_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .units
            .iter()
            .flat_map(UnitRecord::unknown_names)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Units with at least one ungranted request.
    pub fn units_with_ungranted(&self) -> impl Iterator<Item = &UnitRecord> {
        self.units.iter().filter(|u| u.ungranted().next().is_some())
    }

    /// The exit code this run should produce.
    ///
    /// `0` clean, `2` a policy answer of no, `1` reserved for the tool or the build
    /// failing — which is decided by the caller, not here. The 0/1/2 split matters
    /// because CI has to tell "the tool broke" from "the tool worked and the answer was
    /// no", and a pipeline that treats them the same either ignores real findings or
    /// blocks on unrelated breakage. It is the same contract the sibling modules use.
    ///
    /// `unreviewed_grants` is counted from the **policy file**, not from this report.
    /// That distinction is load-bearing: cargo re-runs a build script only when it decides
    /// the unit is dirty, so a second `cargo buildclamp build --strict` in a row can
    /// legitimately run no units at all — and a `--strict` that only looked at units that
    /// happened to run would pass an entirely unreviewed policy on the second invocation.
    /// `gate_observed` makes an ungranted request fail an **observe** run, which is what
    /// `cargo buildclamp observe --gate` is for: watching a pipeline for capability drift
    /// before committing to enforcement. Without it an observe run never fails on a
    /// request, because refusing nothing is the whole point of the mode.
    ///
    /// It is a separate argument rather than a mode, because the mode is what the units
    /// were actually run under and must keep saying so in the report. A run that recorded
    /// without refusing is an observe run whether or not somebody gated on the result.
    pub fn exit_code(&self, v: &Verdict) -> i32 {
        let ungranted_fails = self.mode == Mode::Enforce || v.gate_observed;
        if ungranted_fails && self.unexcused_ungranted(&v.glass).next().is_some() {
            return 2;
        }
        // `--require-enforced` is NOT excusable by an exception, and that is deliberate.
        // It asks whether the kernel on this host could hold a capability at all, and an
        // exception naming a crate has nothing to say about a machine. Letting one
        // suppress it would turn a statement about the host into a statement about a
        // dependency, which is the category error this tool's whole tier ladder exists to
        // prevent.
        if v.require_enforced
            && self
                .units
                .iter()
                .any(|u| u.has_advisory_tier() || u.has_unenforced_tier())
        {
            return 2;
        }
        if v.unreviewed_grants > 0 {
            return 2;
        }
        0
    }

    /// Ungranted requests no live exception covers — what an enforcing run fails on.
    pub fn unexcused_ungranted<'a>(
        &'a self,
        glass: &'a BreakGlass,
    ) -> impl Iterator<Item = (&'a UnitRecord, &'a Request)> {
        self.units.iter().flat_map(move |u| {
            u.ungranted()
                .filter(move |r| glass.covering_forward(&u.id.name, &r.capability).is_none())
                .map(move |r| (u, r))
        })
    }

    /// Every unit that ran under a live exception, one entry each.
    ///
    /// A unit qualifies two ways, and both are break-glass: its envelope was widened (the
    /// usual case, and the one the earlier keying missed entirely), or it made a request
    /// an exception covers that the widening could not make succeed — a write outside the
    /// zones, which the kernel refuses whatever the policy says.
    ///
    /// One entry per unit, not per request: a build script that retries a connection in a
    /// loop produces one ungranted request per attempt, and forty identical entries bury
    /// the one fact a reader needs.
    pub fn break_glass_uses(&self, glass: &BreakGlass) -> Vec<ExceptionUse> {
        let mut out: Vec<ExceptionUse> = Vec::new();
        for u in &self.units {
            let Some(e) = glass.naming(&u.id.name) else {
                continue;
            };
            let mut stood_down: Vec<Forward<Capability>> = Vec::new();
            for r in u.ungranted() {
                if glass.covering_forward(&u.id.name, &r.capability).is_some()
                    && !stood_down.contains(&r.capability)
                {
                    stood_down.push(r.capability.clone());
                }
            }
            if u.envelope.excepted_until.is_none() && stood_down.is_empty() {
                continue;
            }
            out.push(ExceptionUse {
                unit: u.id.clone(),
                expires: e.expires.clone().unwrap_or_default(),
                author: e.author.clone(),
                reason: e.reason.clone(),
                grants: e.capabilities.clone(),
                exercised: u.observed,
                stood_down,
            });
        }
        out
    }

    /// Every (unit, capability-set) pair, which is the input to drift detection and the
    /// only thing the fleet telemetry envelope ever carries.
    pub fn capability_records(&self) -> Vec<(UnitId, CapabilitySet)> {
        self.units
            .iter()
            .map(|u| (u.id.clone(), u.observed))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Envelope;

    fn unit_with(requests: Vec<Request>, mode_reviewed: bool) -> UnitRecord {
        let mut envelope = Envelope::build_script_default();
        envelope.reviewed = mode_reviewed;
        UnitRecord {
            id: UnitId::new("evil", "0.1.3"),
            kind: UnitKind::BuildScriptCompile.into(),
            source: None,
            instance: None,
            envelope,
            tiers: BTreeMap::from([(
                Capability::Net.into(),
                Tier::Enforced {
                    mechanism: "netns".into(),
                },
            )]),
            env_scrubbed: vec!["GITHUB_TOKEN".into()],
            requests,
            observed: CapabilitySet::of(&[Capability::Net]),
            proc_macros_in_closure: Vec::new(),
            exit_code: Some(0),
            signal: None,
            duration_ms: 12,
        }
    }

    fn ungranted_request() -> Request {
        Request {
            at_ms: 3,
            tid: 42,
            capability: Capability::Net.into(),
            syscall: "connect".into(),
            target: "127.0.0.1:9".into(),
            outcome: Outcome::Ungranted { errno: 1 },
            attribution: Attribution::Unit,
        }
    }

    #[test]
    fn a_v1_report_with_two_tiers_for_one_capability_is_refused() {
        // Contradictory evidence — `none` and `enforced` for the same capability. Migration
        // must not pick the last by order: were `enforced` last, a refused capability would
        // read as enforced and `--require-enforced` would accept it. Only the tiers array and
        // format version matter here; migration refuses before the full deserialize runs.
        let v1 = r#"{"format_version":1,"units":[{"tiers":[
            ["net",{"grade":"none","reason":"nothing enforced"}],
            ["net",{"grade":"enforced","mechanism":"seccomp-errno"}]]}]}"#;
        match Report::from_json(v1) {
            Err(ReportError::DuplicateTier { capability }) => assert_eq!(capability, "net"),
            other => panic!("expected DuplicateTier, got {other:?}"),
        }
    }

    #[test]
    fn an_ungranted_request_in_enforce_mode_is_exit_two_not_exit_one() {
        // CI must tell "the tool broke" (1) from "the answer was no" (2).
        let mut r = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
        r.units.push(unit_with(vec![ungranted_request()], true));
        assert_eq!(r.exit_code(&Verdict::default()), 2);
    }

    #[test]
    fn observe_mode_never_fails_the_run_however_much_it_saw() {
        let mut r = Report::new("0.1.0", Mode::Observe, vec!["build".into()]);
        let mut u = unit_with(vec![ungranted_request()], true);
        u.requests[0].outcome = Outcome::WouldBeUngranted;
        r.units.push(u);
        assert_eq!(r.exit_code(&Verdict::default()), 0);
        // …and it still says what enforce mode would have done.
        assert_eq!(r.units_with_ungranted().count(), 1);
    }

    #[test]
    fn observe_with_gate_fails_on_what_enforcement_would_have_refused() {
        // `observe --gate` is how a pipeline watches for capability drift before it is
        // ready to enforce. Without the gate argument this returned 0 no matter what the
        // run recorded, so the flag was documented, wired to the CLI, and unreachable —
        // the mode test in `exit_code` short-circuited it every time.
        let mut r = Report::new("0.1.0", Mode::Observe, vec!["check".into()]);
        let mut u = unit_with(vec![ungranted_request()], true);
        u.requests[0].outcome = Outcome::WouldBeUngranted;
        r.units.push(u);

        assert_eq!(
            r.exit_code(&Verdict::default()),
            0,
            "no gate: observe never fails"
        );
        assert_eq!(
            r.exit_code(&Verdict {
                gate_observed: true,
                ..Verdict::default()
            }),
            2,
            "gate: the drift is the finding"
        );
        // The mode is what the units RAN under and must not change because somebody
        // gated on the result: a run that refused nothing is an observe run either way.
        assert_eq!(r.mode, Mode::Observe);
    }

    #[test]
    fn gate_on_a_clean_observe_run_still_passes() {
        // The flag must not turn every observe run red, or nobody leaves it on.
        let mut r = Report::new("0.1.0", Mode::Observe, vec!["check".into()]);
        r.units.push(unit_with(vec![], true));
        assert_eq!(
            r.exit_code(&Verdict {
                gate_observed: true,
                ..Verdict::default()
            }),
            0
        );
    }

    #[test]
    fn require_enforced_fails_a_clean_run_that_was_only_advisory() {
        // The point of the flag: a green build on a host where nothing could actually be
        // enforced is the false assurance this project exists to avoid.
        let mut r = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
        let mut u = unit_with(vec![], true);
        u.tiers = BTreeMap::from([(
            Capability::FsWrite.into(),
            Tier::Advisory {
                mechanism: "seccomp-notify".into(),
                limitation: "the kernel re-reads the path after we answer".into(),
            },
        )]);
        r.units.push(u);
        assert_eq!(r.exit_code(&Verdict::default()), 0);
        assert_eq!(
            r.exit_code(&Verdict {
                require_enforced: true,
                ..Verdict::default()
            }),
            2
        );
    }

    #[test]
    fn strict_counts_unreviewed_grants_in_the_policy_not_units_that_happened_to_run() {
        // Cargo re-runs a build script only when it decides the unit is dirty, so a second
        // `--strict` run in a row can legitimately run no units at all. Counting from the
        // report would pass an entirely unreviewed policy on that second invocation.
        let empty = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
        assert_eq!(empty.exit_code(&Verdict::default()), 0);
        assert_eq!(
            empty.exit_code(&Verdict {
                unreviewed_grants: 3,
                ..Verdict::default()
            }),
            2,
            "an unreviewed policy must fail --strict even when nothing rebuilt"
        );
    }

    #[test]
    fn a_tier_cannot_be_recorded_without_saying_how_it_was_achieved() {
        // Encoded in the type: every variant carries its mechanism or its reason. This
        // test exists so that adding a bare `Tier::Enforced` variant fails here first.
        let t = Tier::Enforced {
            mechanism: "netns".into(),
        };
        assert_eq!(t.label(), "enforced:netns");
        assert!(!Tier::None {
            reason: "landlock: ENOSYS".into()
        }
        .is_enforced());
    }

    #[test]
    fn the_report_round_trips_through_json() {
        let mut r = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
        r.units.push(unit_with(vec![ungranted_request()], true));
        let json = serde_json::to_string_pretty(&r).unwrap();
        let back: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn a_report_serialises_byte_identically_so_the_stored_blob_is_the_produced_blob() {
        // The property a store built on this depends on, and the one a customer audits by:
        // the bytes the tool writes are the bytes it would write again from the same run, so
        // a stored blob can be re-derived and compared. It holds only if serialisation is
        // deterministic — every map here is a `BTreeMap`, every set is ordered — and this is
        // where that stays true rather than being quietly broken by a field becoming a
        // `HashMap`. `to_vec_pretty` is the exact call `driver::write_report` makes.
        let mut r = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
        // A unit carries `tiers` (a map) and `requests`; two units so any ordering
        // non-determinism between them would show.
        r.units.push(unit_with(vec![ungranted_request()], true));
        r.units.push(unit_with(vec![ungranted_request()], false));

        let produced = serde_json::to_vec_pretty(&r).expect("serialises");
        let reparsed: Report = serde_json::from_slice(&produced).expect("parses");
        let rederived = serde_json::to_vec_pretty(&reparsed).expect("re-serialises");
        assert_eq!(
            produced, rederived,
            "the report did not serialise byte-identically after a round trip; a store that \
             keeps the blob verbatim and an auditor who re-derives it would disagree"
        );
    }

    #[test]
    fn scrubbed_environment_names_are_recorded_without_their_values() {
        // A report carrying the value of a scrubbed secret would write credentials to
        // disk in the course of protecting them. The struct has nowhere to put one.
        let u = unit_with(vec![], true);
        let json = serde_json::to_string(&u).unwrap();
        assert!(json.contains("GITHUB_TOKEN"));
        assert!(!json.contains("ghp_"));
    }

    #[test]
    fn is_canonical_utc_accepts_exactly_rfc3339_utc() {
        // Everything rfc3339_utc emits is canonical, across a wide span including the epoch,
        // the day boundary, and a far-future second still inside a four-digit year.
        for &s in &[
            0u64,
            1,
            86_399,
            86_400,
            1_600_000_000,
            1_726_390_800,
            4_102_444_800,
        ] {
            let t = rfc3339_utc(s);
            assert!(is_canonical_utc(&t), "rfc3339_utc({s}) = {t} was rejected");
        }
        // Leap day and end-of-year, which rfc3339_utc can produce.
        assert!(is_canonical_utc("2024-02-29T00:00:00Z"));
        assert!(is_canonical_utc("2026-12-31T23:59:59Z"));

        // The forms whose lexical order does not match chronological order — the whole
        // reason this check exists — are rejected.
        assert!(!is_canonical_utc("2026-09-15T09:00:00-01:00")); // numeric offset
        assert!(!is_canonical_utc("2026-09-15T09:00:00+00:00")); // even a +00:00 offset
        assert!(!is_canonical_utc("2026-09-15T09:00:00.500Z")); // fractional seconds
        assert!(!is_canonical_utc("2026-09-15 09:00:00Z")); // space instead of T
        assert!(!is_canonical_utc("2026-09-15T09:00:00z")); // lower-case zone

        // Not a real instant, so not something rfc3339_utc would ever emit.
        assert!(!is_canonical_utc("2026-13-01T00:00:00Z")); // month 13
        assert!(!is_canonical_utc("2026-02-30T00:00:00Z")); // Feb 30
        assert!(!is_canonical_utc("2023-02-29T00:00:00Z")); // not a leap year
        assert!(!is_canonical_utc("2026-09-15T24:00:00Z")); // hour 24
        assert!(!is_canonical_utc("2026-09-15T09:60:00Z")); // minute 60

        // Wrong length either way.
        assert!(!is_canonical_utc(""));
        assert!(!is_canonical_utc("2026-09-15T09:00:00Z ")); // trailing space
    }
}
