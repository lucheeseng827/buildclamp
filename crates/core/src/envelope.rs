//! The capability envelope: what one build unit may do, resolved.
//!
//! An envelope is the answer the policy gives about a unit. It is `Copy`-cheap in its
//! capability half and explicit in its filesystem half, and it carries the reason it
//! looks the way it does — because "why is `cc` allowed to run a compiler?" is a
//! question a reviewer asks of a report, and an envelope that cannot answer it sends
//! them back to the policy file to guess.

use serde::{Deserialize, Serialize};

use crate::capability::{Capability, CapabilitySet};
use crate::unit::UnitKind;
use crate::wire::Forward;

/// A named region of the filesystem a build unit may write to.
///
/// Zones are symbolic rather than literal paths because the literal path is only known
/// at run time, differs per unit, and must never be something the policy author has to
/// type. `OUT_DIR` is a different absolute path for every unit and every profile; a
/// policy file containing one would be wrong on the next machine.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum WriteZone {
    /// The unit's own `OUT_DIR`. The one write every build script must have: it is the
    /// entire supported mechanism for a build script to produce anything.
    OutDir,
    /// The system temporary directory. Many generators stage there rather than in
    /// `OUT_DIR` (`cc` does), so denying it by default would break the common case.
    Tmp,
    /// The whole target directory.
    ///
    /// Compiler units need this — rustc writes rlibs, metadata and incremental state
    /// all over it. Build-script units do **not** get it by default, and the difference
    /// matters: a build script that could write into `target/*/deps` could drop a
    /// replacement `.so` for a proc-macro another crate is about to load.
    Target,
    /// The unit's own manifest directory.
    ///
    /// Off by default. A build script writing into its own source tree is doing
    /// something cargo explicitly documents as unsupported, but a handful of crates do
    /// it and breaking them without a way to say yes would be the wrong trade.
    ManifestDir,
}

impl std::fmt::Display for WriteZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl WriteZone {
    /// Does this zone contain that one?
    ///
    /// One pair, and it is a fact about cargo's layout rather than a policy choice:
    /// `OUT_DIR` is `<target>/<profile>/build/<pkg>-<hash>/out`, so a unit that may write
    /// anywhere under [`WriteZone::Target`] may already write its own `OUT_DIR`.
    ///
    /// It exists because composition needs it. A ceiling is compared against an envelope
    /// zone by zone, and the defaults differ by unit kind — a build script gets `out-dir`
    /// and `tmp`, a compile gets `target` and `tmp` — so without containment an ordinary
    /// repository grant naming `out-dir` reads as *widening* a ceiling whose compile-unit
    /// default said `target`. That refusal would be arithmetically correct and obviously
    /// wrong, and it would fire on the first grant anybody wrote.
    ///
    /// Nothing else contains anything else. `tmp` and `manifest-dir` are disjoint from the
    /// rest and from each other, and a relation with more pairs in it than cargo's layout
    /// justifies would be a ceiling quietly permitting more than its author wrote.
    pub fn contains(self, other: WriteZone) -> bool {
        self == other || (self == WriteZone::Target && other == WriteZone::OutDir)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            WriteZone::OutDir => "out-dir",
            WriteZone::Tmp => "tmp",
            WriteZone::Target => "target",
            WriteZone::ManifestDir => "manifest-dir",
        }
    }
}

impl std::str::FromStr for WriteZone {
    type Err = UnknownZone;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "out-dir" | "out_dir" => Ok(WriteZone::OutDir),
            "tmp" | "temp" => Ok(WriteZone::Tmp),
            "target" => Ok(WriteZone::Target),
            "manifest-dir" | "manifest_dir" => Ok(WriteZone::ManifestDir),
            other => Err(UnknownZone(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown write zone `{0}` — buildclamp understands out-dir, tmp, target and manifest-dir")]
pub struct UnknownZone(pub String);

/// Why a unit's envelope is what it is.
///
/// Carried into the report so `cargo buildclamp explain <crate>` can answer without
/// re-deriving anything, and so a reviewer reading a report never has to open the
/// policy to find out which rule fired.
/// # A kind this build has never heard of
///
/// [`EnvelopeSource::Unrecognised`] is the forward-compatibility arm, and it is here for
/// the same reason [`crate::Tier::Unrecognised`] and [`crate::Attribution::Unrecognised`]
/// are: this type is embedded in every unit of every report, and a document carrying one
/// unknown kind used to fail to deserialise **at the top level** — taking every unit, every
/// request and every tier in the run down with it. The string is kept verbatim rather than
/// collapsed to a label, so a report read and written again is not quietly rewritten.
///
/// It is treated as the *weakest* answer wherever strength is compared, for the reason the
/// other two are: "I cannot evaluate this" must never answer a question with a yes.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(from = "SourceWire", into = "SourceWire")]
pub enum EnvelopeSource {
    /// No grant matched; the unit got the defaults for its kind.
    Default,
    /// A grant matched on the crate name alone.
    Grant { crate_name: String },
    /// A grant matched on crate name and a version requirement.
    GrantVersioned { crate_name: String, req: String },
    /// The unit belongs to the workspace being built and `trust_workspace` is on, so it
    /// runs unheld. Recorded explicitly rather than as an absent envelope: a report
    /// that silently omits the units it did not hold is a report that lies by omission.
    TrustedWorkspace,
    /// A layered policy produced this, and this is which layer.
    ///
    /// Not a `Grant` with an extra field, because it is not the same answer. A composed
    /// envelope is the result of one layer's grant bounded by another layer's ceiling, and
    /// calling that "the grant for `x`" would name one of the two documents that decided
    /// it. `ceiling` is the layer that bounded it, absent when nothing did.
    Layer {
        crate_name: String,
        /// The layer whose grant matched.
        layer: String,
        /// Its version requirement, when it had one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<String>,
        /// The layer whose `may-widen = false` bounded what that grant could confer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ceiling: Option<String>,
    },
    /// A kind written by a newer buildclamp than the one reading it. Read, never produced.
    Unrecognised {
        /// The kind as it was written, kept so the document survives a round trip.
        kind: String,
    },
}

/// How an [`EnvelopeSource`] is spelled on the wire.
///
/// A hand-written intermediate rather than `#[serde(tag = "kind")]` plus `#[serde(other)]`,
/// because serde's `other` attribute only accepts a **unit** variant — and a unit variant
/// would throw the kind string away, turning an unreadable document into a silently altered
/// one. The field order and the `skip_serializing_if`s reproduce the tagged representation
/// byte for byte, which the golden corpus pins.
#[derive(Serialize, Deserialize)]
struct SourceWire {
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    crate_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    req: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    layer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ceiling: Option<String>,
}

impl From<SourceWire> for EnvelopeSource {
    fn from(w: SourceWire) -> Self {
        match (w.kind.as_str(), w.crate_name, w.req, w.layer) {
            ("default", _, _, _) => EnvelopeSource::Default,
            ("trusted-workspace", _, _, _) => EnvelopeSource::TrustedWorkspace,
            ("grant-versioned", Some(crate_name), Some(req), _) => {
                EnvelopeSource::GrantVersioned { crate_name, req }
            }
            ("grant", Some(crate_name), _, _) => EnvelopeSource::Grant { crate_name },
            ("layer", Some(crate_name), req, Some(layer)) => EnvelopeSource::Layer {
                crate_name,
                layer,
                req,
                ceiling: w.ceiling,
            },
            // A known kind missing the field that gives it meaning is not that kind.
            // Falling back here rather than defaulting the field keeps this type honest
            // about documents as well as about code: an envelope whose source says `grant`
            // and names no crate is not evidence that a grant matched.
            (kind, _, _, _) => EnvelopeSource::Unrecognised {
                kind: kind.to_string(),
            },
        }
    }
}

impl From<EnvelopeSource> for SourceWire {
    fn from(s: EnvelopeSource) -> Self {
        let blank = SourceWire {
            kind: String::new(),
            crate_name: None,
            req: None,
            layer: None,
            ceiling: None,
        };
        match s {
            EnvelopeSource::Default => SourceWire {
                kind: "default".into(),
                ..blank
            },
            EnvelopeSource::TrustedWorkspace => SourceWire {
                kind: "trusted-workspace".into(),
                ..blank
            },
            EnvelopeSource::Grant { crate_name } => SourceWire {
                kind: "grant".into(),
                crate_name: Some(crate_name),
                ..blank
            },
            EnvelopeSource::GrantVersioned { crate_name, req } => SourceWire {
                kind: "grant-versioned".into(),
                crate_name: Some(crate_name),
                req: Some(req),
                ..blank
            },
            EnvelopeSource::Layer {
                crate_name,
                layer,
                req,
                ceiling,
            } => SourceWire {
                kind: "layer".into(),
                crate_name: Some(crate_name),
                req,
                layer: Some(layer),
                ceiling,
            },
            EnvelopeSource::Unrecognised { kind } => SourceWire { kind, ..blank },
        }
    }
}

impl EnvelopeSource {
    /// One phrase for the `explain` output and the refusal line.
    pub fn describe(&self) -> String {
        match self {
            EnvelopeSource::Default => "the defaults (no grant matched)".to_string(),
            EnvelopeSource::Grant { crate_name } => {
                format!("the grant for `{crate_name}`")
            }
            EnvelopeSource::GrantVersioned { crate_name, req } => {
                format!("the grant for `{crate_name}` version `{req}`")
            }
            EnvelopeSource::TrustedWorkspace => {
                "trust_workspace = true (this crate is part of the workspace being built)"
                    .to_string()
            }
            EnvelopeSource::Layer {
                crate_name,
                layer,
                req,
                ceiling,
            } => {
                let mut s = match req {
                    Some(req) => {
                        format!("the `{layer}` layer's grant for `{crate_name}` version `{req}`")
                    }
                    None => format!("the `{layer}` layer's grant for `{crate_name}`"),
                };
                if let Some(c) = ceiling {
                    s.push_str(&format!(", bounded by the `{c}` layer"));
                }
                s
            }
            EnvelopeSource::Unrecognised { kind } => {
                format!("`{kind}`, which this buildclamp does not recognise — the policy was resolved by a newer one")
            }
        }
    }
}

/// The resolved answer for one build unit.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Envelope {
    /// What the unit may do.
    pub granted: CapabilitySet,
    /// Where it may write, when it has [`Capability::FsWrite`]. Empty means it may
    /// write nowhere, which is a legal and occasionally correct envelope.
    ///
    /// Wrapped for the same reason a tier's capability is: this struct is embedded in
    /// every report, so `init` and the fleet reader parse it back out of a document a
    /// newer agent may have written. A zone name this build does not know is carried
    /// verbatim rather than taking the run down with it. The **policy**'s own
    /// `write_zones` are NOT wrapped — see `crates/core/src/policy.rs`. A zone a person
    /// typed into `buildclamp.toml` that this build cannot honour has to be an error,
    /// because silently ignoring it would grant less than the file says and the person
    /// would never find out.
    pub write_zones: Vec<Forward<WriteZone>>,
    /// Absolute paths it may additionally write to, for the vendored-toolchain cases
    /// that no zone describes. Rare on purpose: a policy full of absolute paths does
    /// not survive being moved to a CI runner.
    pub write_paths: Vec<String>,
    /// Environment names re-admitted despite matching a secret pattern.
    pub env_allow: Vec<String>,
    /// Whether this unit's grant opted in to re-admitting a HARD-DENIED name.
    ///
    /// Carried on the envelope rather than looked up again at the point of use, because
    /// the scrub happens in the launcher — a different process from the one that parsed
    /// the policy — and it had no way to ask. It passed `false` unconditionally, so
    /// `env-allow-secrets = true` could never take effect on the one kind of name it
    /// exists for. See [`crate::envscrub::decide`].
    ///
    /// `#[serde(default)]` because this field was added after reports existed in the
    /// field, and an additive field must not make a document written by an older
    /// buildclamp unreadable. Without it a v1 report — every report written before the
    /// field landed — failed with `missing field env_allow_secrets` while still
    /// declaring `format_version: 1`, so the reader blamed a field when the real answer
    /// was that the schema had moved underneath it. `false` is the correct reading of a
    /// report from before the opt-in existed: nothing could have opted in.
    #[serde(default)]
    pub env_allow_secrets: bool,

    /// A live `[[exception]]` widened this envelope, and the day it stops.
    ///
    /// Carried on the envelope rather than folded into [`Envelope::source`] for two
    /// reasons. The source says which rule produced the *base* — a grant, a version-
    /// qualified grant, the defaults — and that stays true and stays worth reading when
    /// an exception has widened it; and a new `source` variant would make every report
    /// carrying one unreadable to a buildclamp released before it, while an additive
    /// optional field does not. `env_allow_secrets` below is the same rule and the same
    /// reason.
    ///
    /// Present means this unit ran wider than the policy alone would have allowed, on
    /// somebody's say-so, until this date. A reader who sees it should go and look at the
    /// block: `crates/core/src/breakglass.rs` says what one costs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excepted_until: Option<String>,

    /// This unit saw only the base allowlist plus what its grant named, rather than
    /// everything minus the deny-list.
    ///
    /// Recorded per unit rather than looked up from the policy, so that a reader asking
    /// "why did this crate not see my variable?" finds the answer in the report. The
    /// policy file may have changed since; the report is what the run actually did.
    ///
    /// Additive, so `#[serde(default)]` and no version bump — see `env_allow_secrets`
    /// above, whose omission of exactly this was what taught the rule.
    #[serde(default)]
    pub env_allowlist: bool,
    /// Destinations recorded as expected for this unit, e.g. `crates.io:443`.
    ///
    /// **Advisory.** The supervisor sees a destination only through a
    /// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` response, and the kernel re-reads the
    /// `sockaddr` after we answer, so a determined script can change it in between.
    /// Enforcing a destination allowlist needs a proxy or firewall rules inside the
    /// network namespace, which v0 does not do. This field is therefore reported and
    /// never enforced, and both the schema docs and the README say so — shipping an
    /// advisory field that reads as enforcement is the exact trap this project exists
    /// to avoid.
    pub net_destinations: Vec<String>,
    /// Which rule produced this envelope.
    pub source: EnvelopeSource,
    /// The grant's `why`, when one applied. Required on every grant at parse time, so
    /// this is `Some` for every grant-sourced envelope.
    pub why: Option<String>,
    /// Whether a human has marked the grant reviewed. `init` writes `false`; a run with
    /// `--strict` refuses to proceed while any applicable grant is still `false`.
    pub reviewed: bool,
}

impl Envelope {
    /// The default envelope for a build script: it may write into `OUT_DIR` and the
    /// temporary directory, and it may run other programs.
    ///
    /// The exec default is the one people argue about, so the reasoning is here rather
    /// than in a commit message. `cc`, `pkg-config`, `protoc` and `git` are the
    /// ordinary business of build scripts, and a default that denies them would make
    /// the tool break the majority of real dependency graphs on the first run — the
    /// failure mode the dossier calls dead on arrival. Denying exec also buys less than
    /// it looks like it does: every child inherits the namespaces and the seccomp
    /// filter, so a spawned `curl` is held exactly as tightly as the script that
    /// spawned it. Exec is recorded on every unit regardless, so a build script that
    /// spawns something surprising is visible in the capability record even though
    /// nothing refused it.
    pub fn build_script_default() -> Self {
        Self {
            granted: CapabilitySet::of(&[Capability::FsWrite, Capability::Exec, Capability::Unix]),
            write_zones: vec![WriteZone::OutDir.into(), WriteZone::Tmp.into()],
            write_paths: Vec::new(),
            env_allow: Vec::new(),
            env_allow_secrets: false,
            excepted_until: None,
            env_allowlist: false,
            net_destinations: Vec::new(),
            source: EnvelopeSource::Default,
            why: None,
            reviewed: true,
        }
    }

    /// The default envelope for an ordinary compile, which is where proc-macros run.
    ///
    /// Wider than a build script's on the filesystem, because rustc legitimately writes
    /// all over the target directory, and narrower in nothing. The asymmetry is the
    /// price of holding proc-macro execution at all without a per-macro mechanism;
    /// `docs/adr/0004` argues why that price is worth paying.
    pub fn compile_default() -> Self {
        Self {
            granted: CapabilitySet::of(&[Capability::FsWrite, Capability::Exec, Capability::Unix]),
            write_zones: vec![WriteZone::Target.into(), WriteZone::Tmp.into()],
            write_paths: Vec::new(),
            env_allow: Vec::new(),
            env_allow_secrets: false,
            excepted_until: None,
            env_allowlist: false,
            net_destinations: Vec::new(),
            source: EnvelopeSource::Default,
            why: None,
            reviewed: true,
        }
    }

    /// The envelope for a unit that is not held at all.
    ///
    /// Used only for workspace members under `trust_workspace`. It grants everything,
    /// and it is recorded in the report so the set of units that ran unheld is a fact a
    /// reader can see rather than an absence they have to notice.
    pub fn unheld() -> Self {
        Self {
            granted: CapabilitySet::of(&Capability::ALL),
            write_zones: vec![
                WriteZone::OutDir.into(),
                WriteZone::Tmp.into(),
                WriteZone::Target.into(),
                WriteZone::ManifestDir.into(),
            ],
            write_paths: Vec::new(),
            env_allow: Vec::new(),
            env_allow_secrets: false,
            excepted_until: None,
            env_allowlist: false,
            net_destinations: Vec::new(),
            source: EnvelopeSource::TrustedWorkspace,
            why: None,
            reviewed: true,
        }
    }

    /// The envelope a unit of `kind` gets when no grant matches it.
    ///
    /// The single source of truth for "what may a unit do by default", so policy resolution
    /// ([`crate::policy::Policy::resolve`]) and `init`'s decision that a unit stayed inside
    /// those defaults ([`crate::generate`]) cannot drift apart. A build-script compile writes
    /// `OUT_DIR`; every other compile writes `target`, because rustc does.
    pub fn default_for_kind(kind: UnitKind) -> Self {
        match kind {
            UnitKind::BuildScriptCompile => Self::build_script_default(),
            _ => Self::compile_default(),
        }
    }

    /// Does this envelope permit `cap`?
    pub fn permits(&self, cap: Capability) -> bool {
        self.granted.contains(cap)
    }

    /// Does this envelope name `zone`?
    ///
    /// Asked through a method rather than by reaching into the vector, because the vector
    /// holds wire-level names and a zone this build does not know must never answer yes.
    pub fn writes_to(&self, zone: WriteZone) -> bool {
        self.write_zones.iter().any(|z| z.copied() == Some(zone))
    }

    /// The zones this build understands, in the order the envelope lists them.
    pub fn known_zones(&self) -> impl Iterator<Item = WriteZone> + '_ {
        self.write_zones.iter().filter_map(Forward::copied)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_source_kind_this_build_has_never_heard_of_survives_a_round_trip() {
        // The defect this arm exists for: one unknown kind used to fail the whole document
        // at the top level, taking every unit, every request and every tier with it.
        let doc = r#"{"kind":"policyset","crate_name":"serde","layer":"org"}"#;
        let read: EnvelopeSource = serde_json::from_str(doc).expect("an unknown kind reads");
        assert_eq!(
            read,
            EnvelopeSource::Unrecognised {
                kind: "policyset".into()
            }
        );
        // Written back as the kind it was, so reading a report and writing it again does
        // not quietly rewrite it.
        assert_eq!(
            serde_json::to_string(&read).unwrap(),
            r#"{"kind":"policyset"}"#
        );
        // And it says so rather than pretending to know.
        assert!(
            read.describe().contains("does not recognise"),
            "{}",
            read.describe()
        );
    }

    #[test]
    fn a_known_kind_missing_the_field_that_gives_it_meaning_is_not_that_kind() {
        // An envelope whose source says `grant` and names no crate is not evidence that a
        // grant matched, and defaulting the field would make it look like one.
        let read: EnvelopeSource = serde_json::from_str(r#"{"kind":"grant"}"#).unwrap();
        assert!(matches!(read, EnvelopeSource::Unrecognised { .. }));
        let read: EnvelopeSource =
            serde_json::from_str(r#"{"kind":"grant-versioned","crate_name":"serde"}"#).unwrap();
        assert!(matches!(read, EnvelopeSource::Unrecognised { .. }));
        let read: EnvelopeSource =
            serde_json::from_str(r#"{"kind":"layer","crate_name":"serde"}"#).unwrap();
        assert!(matches!(read, EnvelopeSource::Unrecognised { .. }));
    }

    #[test]
    fn every_source_spells_itself_the_way_the_tagged_representation_did() {
        // The wire shape is pinned because the golden corpus and every consumer in the
        // field read it. A hand-written intermediate that spelled one variant differently
        // would be a silent format change.
        for (source, json) in [
            (EnvelopeSource::Default, r#"{"kind":"default"}"#),
            (
                EnvelopeSource::TrustedWorkspace,
                r#"{"kind":"trusted-workspace"}"#,
            ),
            (
                EnvelopeSource::Grant {
                    crate_name: "serde".into(),
                },
                r#"{"kind":"grant","crate_name":"serde"}"#,
            ),
            (
                EnvelopeSource::GrantVersioned {
                    crate_name: "serde".into(),
                    req: ">=1".into(),
                },
                r#"{"kind":"grant-versioned","crate_name":"serde","req":">=1"}"#,
            ),
            (
                EnvelopeSource::Layer {
                    crate_name: "serde".into(),
                    layer: "repo".into(),
                    req: None,
                    ceiling: Some("org".into()),
                },
                r#"{"kind":"layer","crate_name":"serde","layer":"repo","ceiling":"org"}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&source).unwrap(), json, "{source:?}");
            assert_eq!(
                serde_json::from_str::<EnvelopeSource>(json).unwrap(),
                source,
                "{json}"
            );
        }
    }

    use super::*;

    #[test]
    fn a_build_script_may_not_reach_the_network_by_default() {
        // The single most important default in the product. If this test ever needs
        // changing, the change is a different product.
        let e = Envelope::build_script_default();
        assert!(!e.permits(Capability::Net));
        assert!(!e.permits(Capability::EnvSecret));
    }

    #[test]
    fn a_build_script_may_write_out_dir_and_tmp_and_nothing_else_by_default() {
        let e = Envelope::build_script_default();
        assert!(e.permits(Capability::FsWrite));
        assert_eq!(
            e.known_zones().collect::<Vec<_>>(),
            vec![WriteZone::OutDir, WriteZone::Tmp]
        );
        assert!(!e.writes_to(WriteZone::Target));
    }

    #[test]
    fn a_build_script_does_not_get_the_target_directory_that_a_compile_gets() {
        // A build script able to write into target/*/deps could drop a replacement .so
        // for a proc-macro another crate is about to load. The asymmetry is the point.
        assert!(!Envelope::build_script_default().writes_to(WriteZone::Target));
        assert!(Envelope::compile_default().writes_to(WriteZone::Target));
    }

    #[test]
    fn an_unheld_envelope_says_so_in_its_source_rather_than_being_absent() {
        // A report that omits the units it did not hold lies by omission.
        assert_eq!(Envelope::unheld().source, EnvelopeSource::TrustedWorkspace);
    }

    #[test]
    fn zone_names_survive_both_spellings() {
        use std::str::FromStr;
        assert_eq!(WriteZone::from_str("out-dir").unwrap(), WriteZone::OutDir);
        assert_eq!(WriteZone::from_str("out_dir").unwrap(), WriteZone::OutDir);
        assert!(WriteZone::from_str("everywhere").is_err());
    }
}
