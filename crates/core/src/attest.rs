//! The attestation predicate, in in-toto Statement v1, and the DSSE envelope around it.
//!
//! # What an attestation proves, and what it does not
//!
//! This section is the most important thing in the module, because an attestation is a
//! document people quote at auditors, and a claim it does not support is worse than no
//! document at all.
//!
//! **It proves:** that whoever holds the signing key asserts that an artefact with this
//! content hash was built while this exact policy file and this exact report were in
//! effect. Change any of the three and the signature stops verifying.
//!
//! **It does not prove:** that the enforcement was correct, that the policy was a good
//! one, that the build was reproducible, or that the artefact does what anyone hopes. It
//! is a statement about which documents accompanied a build, made by a party with a key.
//!
//! In particular, an attestation over a report whose tiers say `advisory` attests that
//! enforcement **was** advisory. It does not upgrade it.
//!
//! # Why this lives in the free plane
//!
//! Signing is not part of this tool. The predicate, the schema, the erratum type and
//! `cargo buildclamp verify` are, and cannot be otherwise: an attestation a third party
//! cannot check with this binary is worthless as evidence, which is the whole use it is
//! put to. Verification is free wherever it exists — Sigstore's public-good instance has
//! no chargeable tier and `gh attestation verify` is bundled — and a vendor-only
//! correction channel is not a correction channel, which is why [`Erratum`] is here too.
//!
//! # The shape, and why each layer
//!
//! ```text
//! DSSE Envelope          signature, and what was signed, so cosign and gh can verify it
//!   payloadType          application/vnd.in-toto+json
//!   payload (base64)
//!     in-toto Statement v1
//!       subject[0]       the artefact, by sha256 — what a policy engine matches on
//!       predicateType    an identifier, NOT a location: see below
//!       predicate        this project's own document, unchanged
//! ```
//!
//! The predicate body is the statement this tool has always produced, kept verbatim, with
//! three additions the milestone requires before any customer statement is signed:
//! [`EnforcementProfile`], [`Predicate::scope`], and the erratum mechanism.
//!
//! # The URI is an identifier and the committed schema is normative
//!
//! [`PREDICATE_TYPE`] is a URI because in-toto's format requires one. **Nothing in this
//! tool fetches it**, nothing requires it to resolve, and a verifier that fetched a schema
//! over the network to check a ten-year-old document would be building the failure mode
//! into the evidence.
//!
//! The normative definition is `schemas/` in this repository, committed under Apache-2.0
//! and versioned by directory. A customer holding ten-year CRA evidence cannot depend on a
//! domain outliving a company, and this is how that is answered rather than hoped about.
//!
//! **The domain in that URI is not registered**, and that is recorded here rather than
//! discovered: until it is, a third party could take it and serve a schema that disagrees
//! with the committed one. It is a prerequisite to relying on those URIs, recorded so that it
//! cannot be skipped by accident.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::report::{Report, Tier};

/// The in-toto Statement type URI. Fixed by in-toto, not by this project.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// The DSSE payload type for an in-toto Statement. Fixed by in-toto.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// This project's predicate type. An identifier — see the module docs.
pub const PREDICATE_TYPE: &str = "https://buildclamp.dev/attestation/v1";

/// The erratum predicate type. An identifier, on the same terms.
pub const ERRATUM_PREDICATE_TYPE: &str = "https://buildclamp.dev/erratum/v1";

/// The predicate format version, inside the predicate body.
///
/// Separate from the report's and the policy's, and from in-toto's. The four move
/// independently and a reader must never have to guess which one a number refers to.
///
/// Bumped to 2 to carry `waivers`, while the count of issued statements is near zero — the
/// cheapest moment to add a required-reading field. A verifier accepts 1 and 2; version 1 is
/// accepted until [`V1_SUNSET`], after which a v1 document is refused rather than read on
/// trust, because a format nobody re-issues is a format nobody audits.
pub const PREDICATE_VERSION: u32 = 2;

/// The oldest predicate version a verifier still reads.
///
/// A stated cutover rather than an immediate one: v1 statements were verifiable when
/// written, and pulling that out from under a holder with no notice is the behaviour this
/// project criticises in others. See [`v1_sunset`].
pub const OLDEST_PREDICATE_VERSION: u32 = 1;

/// The day a version-1 statement stops verifying: 2028-01-01, UTC.
///
/// A function rather than a `const` only because [`crate::civil::Date`] is parsed, not
/// const-constructed; the date is fixed and stated. After it, a v1 document is refused with
/// an error that names the date, so a holder knows the statement needs re-issuing as v2
/// rather than that verification is broken.
pub fn v1_sunset() -> crate::civil::Date {
    crate::civil::Date::parse("2028-01-01").expect("2028-01-01 is a valid date")
}

/// An in-toto Statement v1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub type_: String,
    /// What was built. One entry in practice; an array because in-toto says so.
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: Predicate,
}

/// One subject: a name and a digest.
///
/// The digest is what a policy engine matches on, which is why `artefact_sha256` is lifted
/// out of the predicate and into here rather than only living in the body: Kyverno,
/// policy-controller and `cosign verify-attestation` all match on `subject[].digest`, and a
/// hash that only appeared in a predicate would be invisible to every one of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    /// Keyed by algorithm, as in-toto requires: `{"sha256": "<hex>"}`.
    pub digest: BTreeMap<String, String>,
}

/// The document that gets signed, unchanged from the format this tool has always produced
/// except for the three additions the module docs name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Predicate {
    pub format_version: u32,
    /// What was built. A name and a content hash; never a path, which would be meaningless
    /// on the machine that verifies it.
    pub artefact_name: String,
    pub artefact_sha256: String,
    /// The policy in force, by content hash. Two builds under "the same policy" that hash
    /// differently were not under the same policy.
    pub policy_sha256: String,
    /// Whether the distributed policy layers verified against the repository's committed
    /// trust root. Carried from the report so a reader learns the policy's *authority* —
    /// who was allowed to write it — and not only its content hash, without opening the
    /// report. `false` when no trust root is in use or a layer was unsigned. Additive.
    #[serde(default)]
    pub policy_signature_verified: bool,
    /// The trust-root key id(s) that signed the distributed layers, when any did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_signer_key_id: Option<String>,
    /// The report, by content hash.
    pub report_sha256: String,
    /// Which enforcement tier applied per capability, carried forward so a reader does not
    /// have to open the report to learn that enforcement was advisory.
    pub enforcement_summary: BTreeMap<String, String>,
    pub units_held: usize,
    pub ungranted_requests: usize,
    /// Enforcement the operator switched off, carried forward from the report.
    ///
    /// Without this the statement cannot tell an auditor the difference between a build
    /// nobody could enforce and a build somebody chose not to enforce — and the tiers alone
    /// will not say. `BUILDCLAMP_DISABLE=ns` removes the namespace and the remaining
    /// mechanism still reports `enforced:`, so a run an operator had weakened could be
    /// signed as fully enforced. [`Predicate::is_fully_enforced`] refuses that.
    #[serde(default)]
    pub operator_overrides: Vec<String>,

    /// Every optional enforcement flag and its state for this run.
    ///
    /// **The addition that stops this being a laundering machine.** Without it, a run with
    /// `withhold-secret-reads` off and `hold-compile-units` off produces a statement whose
    /// every tier says `enforced:` — truthfully, because each capability that *was* held
    /// was held by the kernel — and an auditor reads "fully enforced" about a build where
    /// a build script could read `~/.aws/credentials` and no proc-macro was held at all.
    /// Those are exactly the gaps the README documents, and an attestation that hid them
    /// would be this project asserting, over a signature, the opposite of its own
    /// documentation.
    pub enforcement_profile: EnforcementProfile,

    /// What was **not** held, in words, mandatory.
    ///
    /// Distinct from `enforcement_profile`, which is a machine-readable list of switches.
    /// This is the sentence somebody reads. A statement is allowed to say "nothing", and
    /// saying it is a deliberate act rather than an empty field: the point is that the
    /// question was answered.
    pub scope: Scope,

    /// Gates a human waived with break-glass — exceptions a unit actually exercised.
    ///
    /// The same class of fact as `enforcement_summary`: a reader learns, without opening the
    /// report, that a build was let through by an override rather than fully enforced.
    /// `is_fully_enforced` returns false whenever there is one, so an attestation cannot say
    /// "fully enforced" about a build a person broke glass on. Added in format version 2, and
    /// optional, so a v1 document parses with none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waivers: Vec<Waiver>,

    /// RFC 3339, UTC. A string rather than a parsed timestamp because this crate is pure
    /// and has no clock, and because the wire carries a string either way — parsing it into
    /// a type and back is a round trip that can only lose.
    pub built_at: String,
    pub key_id: String,
}

/// A gate that passed only because break-glass waived it: an [`crate::Exception`] a unit
/// actually exercised during the build.
///
/// Distinct from an operator override, which switches a whole mechanism off, and from the
/// enforcement summary, which is about tiers. A waiver is a specific, dated, authored human
/// decision to let one unit exceed the policy, carried into the statement because an auditor
/// reading "the build passed" is owed the fact that it passed with a waiver on it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiver {
    /// The unit that ran wider than the policy alone would have allowed.
    pub unit: crate::unit::UnitId,
    /// The capabilities the exception let through, as exercised — not what the block named,
    /// which can be broader. An exception nobody exercised is not a waiver and is not here.
    pub capabilities: Vec<crate::capability::Capability>,
    /// Why the policy says the glass was broken, verbatim.
    pub reason: String,
    /// Who the policy says broke it. Self-asserted, like every `[[exception]]` author.
    pub author: String,
    /// The day the exception stops applying.
    pub expires: String,
}

/// Every optional enforcement flag, and its state for one run.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EnforcementProfile {
    /// `withhold-secret-reads`. With it off, every unit could read every path on the host.
    pub read_deny: bool,
    /// The digest of the withheld-path list that was in force, when `read_deny` is on.
    ///
    /// The list is a deny-list and it changes between releases, so "read_deny was on" does
    /// not by itself say which paths were withheld. Absent when `read_deny` is off, because
    /// there was no ruleset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_deny_ruleset_sha256: Option<String>,
    /// `hold-compile-units`. With it off, proc-macro expansion ran unheld — which is the
    /// half of the threat a build-script-only tool misses entirely.
    pub compile_units_held: bool,
    /// Always `true`, and always recorded, because it is always true: destinations are
    /// reported and never enforced. A field that can only hold one value looks redundant
    /// and is not — a reader of the statement must not have to know this project's
    /// documentation to find out that a destination list is not a control.
    pub net_destinations_recorded_only: bool,
    /// The Landlock ABI the run actually used, or `None` where Landlock was unavailable.
    /// ABI is a tier dimension: `landlock-v1` cannot restrict truncation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landlock_abi_used: Option<i32>,
    /// Repeated from `Predicate::operator_overrides` so the profile stands alone. A
    /// consumer reading only this object must not be able to conclude "everything on"
    /// about a run somebody had switched down.
    #[serde(default)]
    pub disable_overrides: Vec<String>,
}

/// What was not held, in words.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Scope {
    /// One line per gap. Empty means the signer asserts there were none, which is a claim
    /// rather than an absence of one.
    pub not_held: Vec<String>,
}

impl Predicate {
    /// Build the predicate from a finished run.
    ///
    /// Everything here is read from the report rather than passed in, so a signer cannot
    /// assemble a statement that disagrees with the run it is about. The three things a
    /// report cannot know — what the artefact is called, its hash, and who is signing —
    /// are the only arguments.
    #[allow(clippy::too_many_arguments)]
    pub fn from_report(
        report: &Report,
        artefact_name: impl Into<String>,
        artefact_sha256: impl Into<String>,
        policy_sha256: impl Into<String>,
        report_sha256: impl Into<String>,
        profile: EnforcementProfile,
        built_at: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        let mut enforcement_summary: BTreeMap<String, String> = BTreeMap::new();
        for unit in &report.units {
            for (cap, tier) in &unit.tiers {
                let name = cap.to_string();
                let rendered = rendered(tier);
                // The WEAKEST tier seen for a capability, across every unit, wins.
                //
                // A summary that took the strongest — or the last — would say `enforced:`
                // about a build in which one unit out of two hundred ran advisory, which is
                // the single most useful thing the document could have told an auditor and
                // the easiest to lose.
                enforcement_summary
                    .entry(name)
                    .and_modify(|held| {
                        if weakness(tier) > weakness_of_rendered(held) {
                            *held = rendered.clone();
                        }
                    })
                    .or_insert(rendered);
            }
        }
        let mut scope = Scope::default();
        if !profile.read_deny {
            scope.not_held.push(
                "Reads were unrestricted: every build unit could read every path on the \
                 host, including credential files. `withhold-secret-reads` was off."
                    .into(),
            );
        }
        if !profile.compile_units_held {
            scope.not_held.push(
                "Proc-macro expansion ran unheld: only build scripts were held. \
                 `hold-compile-units` was off."
                    .into(),
            );
        }
        scope.not_held.push(
            "Network destinations were recorded and never enforced. A destination list in \
             the policy is a record of what was expected, not a control."
                .into(),
        );

        Self {
            format_version: PREDICATE_VERSION,
            artefact_name: artefact_name.into(),
            artefact_sha256: artefact_sha256.into(),
            policy_sha256: policy_sha256.into(),
            // From the report, like everything else here: a signer cannot assert an
            // authority the run did not establish.
            policy_signature_verified: report.run.policy_signature_verified,
            policy_signer_key_id: report.run.policy_signer_key_id.clone(),
            report_sha256: report_sha256.into(),
            enforcement_summary,
            units_held: report.units.len(),
            ungranted_requests: report
                .units
                .iter()
                .map(|u| u.ungranted().count())
                .sum::<usize>(),
            operator_overrides: report
                .disable_overrides
                .iter()
                .map(|o| format!("{}={} ({})", o.source, o.value, o.effect))
                .collect(),
            enforcement_profile: profile,
            scope,
            // A waiver per exception a unit actually EXERCISED. A block that was live but
            // never used is not a waiver — it waived nothing — so it is not carried, which
            // keeps `is_fully_enforced` from turning false over an unused escape hatch.
            waivers: report
                .break_glass
                .iter()
                .filter(|e| !e.exercised.is_empty())
                .map(|e| Waiver {
                    unit: e.unit.clone(),
                    capabilities: e.exercised.iter().collect(),
                    reason: e.reason.clone(),
                    author: e.author.clone(),
                    expires: e.expires.clone(),
                })
                .collect(),
            built_at: built_at.into(),
            key_id: key_id.into(),
        }
    }

    /// The question an auditor actually asks, answered conservatively.
    ///
    /// **False unless both optional hardenings were on.** That is the rule the milestone
    /// puts first, and it is the difference between an attestation and a laundering
    /// machine: with `withhold-secret-reads` off a build script read every credential file
    /// on the host, and with `hold-compile-units` off no proc-macro was held at all. Both
    /// runs produce tiers that all say `enforced:`, truthfully, about the capabilities that
    /// were held — and "fully enforced" is not what either of them was.
    ///
    /// Also false when an operator switched anything off, and false when any capability's
    /// weakest tier is not `enforced:`. And false on an **empty** summary, because a run
    /// that recorded no tiers at all is not a run that enforced everything.
    pub fn is_fully_enforced(&self) -> bool {
        self.enforcement_profile.read_deny
            && self.enforcement_profile.compile_units_held
            && self.operator_overrides.is_empty()
            && self.enforcement_profile.disable_overrides.is_empty()
            // A build a human broke glass on is not fully enforced, whatever the tiers say:
            // the tiers can all read `enforced:` while an exception let one unit past the
            // policy, and that is exactly the fact a waiver records.
            && self.waivers.is_empty()
            && !self.enforcement_summary.is_empty()
            && self
                .enforcement_summary
                .values()
                .all(|v| v.starts_with("enforced:"))
    }

    /// One paragraph a person can put in front of an auditor without overstating it.
    pub fn plain_english(&self) -> String {
        let mut s = format!(
            "This attestation states that `{}` (sha256 {}) was built with buildclamp under \
             the policy with sha256 {}, holding {} build unit(s), with {} ungranted \
             request(s).\n",
            self.artefact_name,
            short(&self.artefact_sha256),
            short(&self.policy_sha256),
            self.units_held,
            self.ungranted_requests
        );
        s.push_str("\nEnforcement actually achieved on the build host:\n");
        for (cap, tier) in &self.enforcement_summary {
            s.push_str(&format!("  {cap:<12} {tier}\n"));
        }
        // The profile BEFORE the scope, and both, because they are different kinds of
        // fact. `enforcement_profile` is a set of flags a verifier can check; `scope` is
        // the signer's prose. A reader who only saw the prose would be trusting whoever
        // signed to have written a good paragraph — and the one statement where that
        // matters is the one written by somebody who would rather it read well.
        let p = &self.enforcement_profile;
        s.push_str("\nOptional hardening, as recorded in the statement:\n");
        s.push_str(&format!(
            "  {:<24} {}\n",
            "withhold-secret-reads",
            if p.read_deny {
                match &p.read_deny_ruleset_sha256 {
                    Some(d) => format!("on (ruleset {})", short(d)),
                    None => "on (ruleset not recorded)".to_string(),
                }
            } else {
                "OFF — every unit could read every path on this host".to_string()
            }
        ));
        s.push_str(&format!(
            "  {:<24} {}\n",
            "hold-compile-units",
            if p.compile_units_held {
                "on"
            } else {
                "OFF — proc-macro expansion ran unheld"
            }
        ));
        if let Some(abi) = p.landlock_abi_used {
            s.push_str(&format!("  {:<24} landlock-v{abi}\n", "filesystem ABI"));
        }

        if !self.scope.not_held.is_empty() {
            s.push_str("\nWhat the signer says this build did NOT hold:\n");
            for line in &self.scope.not_held {
                s.push_str(&format!("  - {line}\n"));
            }
        }
        if !self.operator_overrides.is_empty() {
            s.push_str(
                "\nAn operator switched enforcement off or down for this build. This is a \
                 decision somebody made, not a limit of the machine, and it is recorded \
                 here because the two are otherwise indistinguishable:\n",
            );
            for o in &self.operator_overrides {
                s.push_str(&format!("  - {o}\n"));
            }
        }
        if self.is_fully_enforced() {
            s.push_str(
                "\nEvery capability was held by the kernel, with both optional hardenings on \
                 and nothing switched off.\n",
            );
        } else {
            s.push_str("\nThis build was NOT fully enforced.\n");
            // Naming the capabilities rather than saying "see above". A reader who has to
            // work out which line disagreed with the verdict is a reader who will take the
            // verdict's word for it.
            let weak: Vec<&String> = self
                .enforcement_summary
                .iter()
                .filter(|(_, v)| !v.starts_with("enforced:"))
                .map(|(k, _)| k)
                .collect();
            if !weak.is_empty() {
                s.push_str(&format!(
                    "  These capabilities were not kernel-enforced: {}.\n",
                    weak.iter()
                        .map(|k| k.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !self.enforcement_profile.read_deny {
                s.push_str("  Reads were unrestricted.\n");
            }
            if !self.enforcement_profile.compile_units_held {
                s.push_str("  Proc-macro expansion ran unheld.\n");
            }
        }

        // Last, and on every statement including the clean ones. The sentence an auditor
        // most needs is the one about what a signature cannot establish, and putting it
        // only on the bad statements would be putting it where it is least read.
        s.push_str(
            "\nWhat this does NOT establish: that the enforcement was correct, that the \
             policy was adequate, or that the build was reproducible. It establishes which \
             policy and which report accompanied this artefact, asserted by the holder of \
             the signing key.\n",
        );
        s
    }
}

fn short(hash: &str) -> &str {
    // Cut on a CHARACTER boundary, not a byte one. `verify_statement` parses the digest
    // fields as free-form strings, so a statement can carry a multi-byte character straddling
    // byte 16 — and `&hash[..16]` on that aborts the process. A digest shorter than the window
    // is printed whole, and a malformed hash is somebody else's error to report rather than a
    // reason for a renderer to panic.
    match hash.char_indices().nth(16) {
        Some((end, _)) => &hash[..end],
        None => hash,
    }
}

/// A tier as the summary spells it.
///
/// [`Tier::label`] is the terminal's spelling and renders `Tier::None` as a bare `none`.
/// That is right for a table beside the reason and wrong here: an attestation is read on
/// its own, by somebody who may not have the report, and "nothing constrained this" without
/// "because the kernel has no Landlock" is the half of the sentence that cannot be guessed.
fn rendered(tier: &Tier) -> String {
    match tier {
        Tier::None { reason } => format!("none:{reason}"),
        other => other.label(),
    }
}

/// How weak a tier is, for picking the worst one seen.
fn weakness(tier: &Tier) -> u8 {
    match tier {
        Tier::Enforced { .. } => 0,
        Tier::Advisory { .. } => 1,
        Tier::None { .. } => 2,
        // Weaker than `none`, for the same reason `Floor` treats it so: "I cannot evaluate
        // this" must never answer "was this enforced?" with a yes.
        Tier::Unrecognised { .. } => 3,
    }
}

fn weakness_of_rendered(rendered: &str) -> u8 {
    if rendered.starts_with("enforced:") {
        0
    } else if rendered.starts_with("advisory:") {
        1
    } else if rendered.starts_with("none:") {
        2
    } else {
        3
    }
}

/// A signed correction to statements already in the world.
///
/// # Why this exists at all
///
/// A signed statement is immutable and long-lived: it is CRA evidence, it sits in a
/// registry, and it may be read in 2036. If this project later finds that a release
/// overstated a tier — a filter that did not refuse what it reported refusing, a Landlock
/// ABI that did not restrict what was assumed — every statement that release signed is now
/// wrong, and there is no way to unsign one.
///
/// So corrections are published as signed documents of their own, and `cargo buildclamp
/// verify` consults a locally supplied erratum file. Locally supplied rather than fetched:
/// a verifier that reached the network to decide would be unusable in the air-gapped case
/// this tool is built for, and would make the vendor's availability part of the customer's
/// verification path.
///
/// **Apache-2.0, in this tool, deliberately.** A correction channel only the vendor's
/// own customers could use would not be a correction channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Erratum {
    pub format_version: u32,
    /// A stable identifier for this correction, so a verifier can say which one applied.
    pub id: String,
    /// Which statements this corrects. Every field that is present must match.
    pub matches: ErratumMatch,
    /// The capability whose tier was overstated, or `None` for a whole-statement finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    /// What the tier should be read as instead.
    pub corrected_tier: String,
    /// The finding, in a sentence somebody can act on.
    pub finding: String,
    /// When this was published, RFC 3339.
    pub published: String,
}

/// Which statements an erratum corrects.
///
/// Every field present must match, and **an erratum matching nothing is legal**: a
/// correction published before anyone has built with the affected release corrects nothing
/// yet and must still be publishable.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ErratumMatch {
    /// Statements whose `key_id` is this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Statements built at or after this instant, RFC 3339. String comparison is correct
    /// for RFC 3339 in UTC with a fixed shape, which is what `rfc3339_utc` produces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub built_at_from: Option<String>,
    /// Statements built strictly before this instant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub built_at_before: Option<String>,
    /// Statements over this exact artefact digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artefact_sha256: Option<String>,
}

impl Erratum {
    /// Does this erratum correct that statement?
    pub fn applies_to(&self, p: &Predicate) -> bool {
        let m = &self.matches;
        // An erratum with NO criteria matches nothing rather than everything. The
        // permissive reading of an empty filter would let one malformed document
        // invalidate every attestation a customer holds.
        if m.key_id.is_none()
            && m.built_at_from.is_none()
            && m.built_at_before.is_none()
            && m.artefact_sha256.is_none()
        {
            return false;
        }
        if let Some(k) = &m.key_id {
            if &p.key_id != k {
                return false;
            }
        }
        // Lexical `<`/`>=` orders timestamps chronologically only when both operands are in
        // the canonical UTC shape `rfc3339_utc` emits (`is_canonical_utc`). A non-canonical
        // value — an offset or fractional-second form, or a hand-constructed predicate — can
        // sort the wrong way, which would exclude a statement this correction covers and
        // leave an overstated tier visible (`Verified::is_fully_enforced` is `errata.is_empty()
        // && …`). Fail closed toward applying the correction: only a comparison between two
        // canonical timestamps may exclude; an untrustworthy one never does.
        if let Some(from) = &m.built_at_from {
            if crate::report::is_canonical_utc(from)
                && crate::report::is_canonical_utc(&p.built_at)
                && p.built_at.as_str() < from.as_str()
            {
                return false;
            }
        }
        if let Some(before) = &m.built_at_before {
            if crate::report::is_canonical_utc(before)
                && crate::report::is_canonical_utc(&p.built_at)
                && p.built_at.as_str() >= before.as_str()
            {
                return false;
            }
        }
        if let Some(a) = &m.artefact_sha256 {
            if &p.artefact_sha256 != a {
                return false;
            }
        }
        true
    }
}

/// A DSSE envelope: what was signed, how it was encoded, and by whom.
///
/// Field names are DSSE's, not this project's. `payload` is base64 of the serialised
/// Statement; `payloadType` is [`DSSE_PAYLOAD_TYPE`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<Signature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    /// Base64 of the raw signature over [`pae`].
    pub sig: String,
}

/// DSSE's Pre-Authentication Encoding — what is actually signed.
///
/// `"DSSEv1" SP len(type) SP type SP len(body) SP body`, with lengths in ASCII decimal.
///
/// It exists so that a signature over one `(type, body)` pair cannot be replayed as a
/// signature over another: without the lengths, a payload type ending in digits and a body
/// beginning with them could be re-split. Implemented here rather than depended on because
/// it is six lines and because a verifier that got it wrong would accept a signature over
/// something else — see the negative vectors, which include exactly that confusion.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Everything `verify` can find wrong with a document, each naming what to do about it.
///
/// Separate variants rather than one string because a verifier that says only "invalid"
/// is one people learn to ignore: "this is an attestation about a different artefact" and
/// "this file is not an attestation" send a reader to completely different places.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("this is not a DSSE envelope or an in-toto Statement: {0}")]
    NotAnEnvelope(String),

    #[error(
        "the DSSE payloadType is `{found}`, and an in-toto Statement is \
         `{DSSE_PAYLOAD_TYPE}`. This envelope carries something else."
    )]
    WrongPayloadType { found: String },

    #[error("the DSSE payload is not valid base64: {0}")]
    BadPayload(#[from] crate::b64::Base64Error),

    #[error("the payload is not a JSON document: {0}")]
    BadJson(String),

    #[error(
        "the statement's `_type` is `{found}`, and an in-toto Statement v1 is \
         `{STATEMENT_TYPE}`."
    )]
    WrongStatementType { found: String },

    #[error(
        "the predicateType is `{found}`, and this tool verifies `{PREDICATE_TYPE}`. \
         Refusing rather than reading a document of a type it does not understand — \
         CVE-2022-35929 is what happens when a verifier returns success for an \
         attestation type that was never there."
    )]
    WrongPredicateType { found: String },

    #[error(
        "the statement has no subject. An in-toto Statement without one names no \
         artefact, so there is nothing for a policy engine to match and nothing this \
         could be about."
    )]
    NoSubject,

    #[error(
        "the statement is about an artefact with sha256 {expected}, and the file in \
         front of you is {found}. The signature may be perfectly good — over something \
         else."
    )]
    WrongArtefact { expected: String, found: String },

    #[error(
        "this statement disagrees with itself: `subject[0].digest.sha256` is {subject} and \
         the predicate's `artefact_sha256` is {predicate}. A policy engine matches on the \
         first and a person reads the second, so a document where they differ is one two \
         readers get different answers from — and it is refused here rather than passing \
         one of them."
    )]
    InconsistentDigest { subject: String, predicate: String },

    #[error(
        "the statement was made under a policy with sha256 {expected}, and the policy \
         file you gave is {found}. Two builds under `the same policy` that hash \
         differently were not under the same policy."
    )]
    WrongPolicy { expected: String, found: String },

    #[error(
        "the statement is about a report with sha256 {expected}, and the report you gave \
         is {found}."
    )]
    WrongReport { expected: String, found: String },

    #[error(
        "this statement is predicate format version {found}, and this buildclamp reads up \
         to {newest}. A higher number means it was written by a newer buildclamp — upgrade, \
         rather than let this one verify the parts it understands and ignore the rest, which \
         is the permissive direction and the wrong one for a signed statement."
    )]
    UnknownVersion { found: u32, newest: u32 },

    #[error(
        "this statement is predicate format version {version}, which stopped verifying on \
         {sunset}. It was valid when written; re-issue it as the current version. This is a \
         deliberate cutover, not a broken verifier — a format nobody re-issues is a format \
         nobody audits."
    )]
    VersionSunset { version: u32, sunset: String },
}

/// What `verify` established, and what it deliberately did not.
#[derive(Clone, Debug)]
pub struct Verified {
    pub statement: Statement,
    /// Errata that matched, in the order they were supplied.
    pub errata: Vec<Erratum>,
    /// Which of the optional checks were actually made, so the caller can print the truth
    /// rather than a summary. A verifier that said "verified" without saying what it
    /// checked would be the overstatement this whole project is organised against.
    pub checked_artefact: bool,
    pub checked_policy: bool,
    pub checked_report: bool,
}

impl Verified {
    /// Is the run this statement describes fully enforced, after errata?
    ///
    /// An erratum downgrades it. That is the whole point of the mechanism: a release later
    /// found to have overstated a tier makes every statement it signed wrong, and there is
    /// no way to unsign one.
    pub fn is_fully_enforced(&self) -> bool {
        self.errata.is_empty() && self.statement.predicate.is_fully_enforced()
    }
}

/// Check a document, without checking its signature.
///
/// # What this does and does not check, stated rather than implied
///
/// It checks, **itself**, that the document is an in-toto Statement v1, that its
/// `predicateType` is this project's — rather than trusting a `--type` flag, which is the
/// shape of CVE-2022-35929, where cosign returned success when no attestation of the
/// requested type existed at all — that the subject digest is the artefact in front of
/// you, and that the policy and report hashes are the files in front of you.
///
/// **It does not check the signature.** That is cosign's and `gh attestation verify`'s
/// job, and it is deliberate rather than an omission: this crate holds no signing key, its
/// only cryptography is `ring`'s verify-only Ed25519 for signed *policy* layers — a
/// different document from an attestation — and `ops/no-network-closure.sh` and CI assert
/// that its dependency closure contains no network client. Adding an attestation-signature
/// algorithm here would be choosing one for a signer that lives in another plane. The
/// caller is told, in the command's own output, which half it got.
///
/// The two halves are genuinely separable and the semantic half is the one that catches
/// laundering: a valid signature over a statement about a different artefact, or over a
/// run with `read_deny` off, verifies cryptographically and is still the wrong document.
#[allow(clippy::too_many_arguments)]
pub fn verify_statement(
    document: &str,
    artefact_sha256: Option<&str>,
    policy_sha256: Option<&str>,
    report_sha256: Option<&str>,
    errata: &[Erratum],
    today: crate::civil::Date,
) -> Result<Verified, VerifyError> {
    let raw: serde_json::Value =
        serde_json::from_str(document).map_err(|e| VerifyError::NotAnEnvelope(e.to_string()))?;

    // A DSSE envelope wraps a Statement; a bare Statement is also accepted, because that
    // is what `cosign verify-attestation` hands its caller after it has checked the
    // signature — and refusing it would mean nobody could chain the two.
    let statement_json = if raw.get("payload").is_some() && raw.get("payloadType").is_some() {
        let envelope: Envelope =
            serde_json::from_value(raw).map_err(|e| VerifyError::NotAnEnvelope(e.to_string()))?;
        if envelope.payload_type != DSSE_PAYLOAD_TYPE {
            return Err(VerifyError::WrongPayloadType {
                found: envelope.payload_type,
            });
        }
        let bytes = crate::b64::decode(&envelope.payload)?;
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|e| VerifyError::BadJson(e.to_string()))?
    } else {
        raw
    };

    // The two type fields are checked BEFORE the typed parse, so a document of another
    // type is refused for being another type rather than for a field that happened to
    // differ. A reader told "missing field `enforcement_profile`" about an SPDX document
    // goes looking in the wrong place.
    let type_ = statement_json
        .get("_type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if type_ != STATEMENT_TYPE {
        return Err(VerifyError::WrongStatementType {
            found: type_.to_string(),
        });
    }
    let predicate_type = statement_json
        .get("predicateType")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if predicate_type != PREDICATE_TYPE {
        return Err(VerifyError::WrongPredicateType {
            found: predicate_type.to_string(),
        });
    }

    let statement: Statement =
        serde_json::from_value(statement_json).map_err(|e| VerifyError::BadJson(e.to_string()))?;

    // Version gate. A version this build has never heard of is refused rather than read on
    // the parts it recognises — the permissive direction, and the wrong one for a security
    // statement. Version 1 is read until its stated sunset and refused after, so a holder
    // learns the statement needs re-issuing as v2 rather than that verification broke.
    let version = statement.predicate.format_version;
    if version > PREDICATE_VERSION {
        return Err(VerifyError::UnknownVersion {
            found: version,
            newest: PREDICATE_VERSION,
        });
    }
    if version < OLDEST_PREDICATE_VERSION {
        return Err(VerifyError::UnknownVersion {
            found: version,
            newest: PREDICATE_VERSION,
        });
    }
    if version == 1 && today >= v1_sunset() {
        return Err(VerifyError::VersionSunset {
            version: 1,
            sunset: "2028-01-01".to_string(),
        });
    }

    let subject = statement.subject.first().ok_or(VerifyError::NoSubject)?;
    let declared = subject.digest.get("sha256").cloned().unwrap_or_default();

    // Internal consistency first, and with NO arguments needed. The artefact hash appears
    // twice on purpose — in the subject because that is what Kyverno, policy-controller and
    // `cosign verify-attestation` match on, and in the predicate because that is what a
    // person reads — and a document where the two differ is one where those two readers
    // reach different conclusions about the same signature. Refusing it is the only answer
    // that does not pick a side.
    if !declared.eq_ignore_ascii_case(&statement.predicate.artefact_sha256) {
        return Err(VerifyError::InconsistentDigest {
            subject: declared,
            predicate: statement.predicate.artefact_sha256.clone(),
        });
    }

    let mut checked_artefact = false;
    if let Some(found) = artefact_sha256 {
        // Compared against the SUBJECT digest, not the predicate's copy. The subject is
        // what every policy engine matches on, so a document whose two copies disagreed
        // would pass here and fail in Kyverno — or the reverse, which is worse.
        if !declared.eq_ignore_ascii_case(found) {
            return Err(VerifyError::WrongArtefact {
                expected: declared,
                found: found.to_string(),
            });
        }
        checked_artefact = true;
    }

    let mut checked_policy = false;
    if let Some(found) = policy_sha256 {
        if !statement
            .predicate
            .policy_sha256
            .eq_ignore_ascii_case(found)
        {
            return Err(VerifyError::WrongPolicy {
                expected: statement.predicate.policy_sha256.clone(),
                found: found.to_string(),
            });
        }
        checked_policy = true;
    }

    let mut checked_report = false;
    if let Some(found) = report_sha256 {
        if !statement
            .predicate
            .report_sha256
            .eq_ignore_ascii_case(found)
        {
            return Err(VerifyError::WrongReport {
                expected: statement.predicate.report_sha256.clone(),
                found: found.to_string(),
            });
        }
        checked_report = true;
    }

    let matched: Vec<Erratum> = errata
        .iter()
        .filter(|e| e.applies_to(&statement.predicate))
        .cloned()
        .collect();

    Ok(Verified {
        statement,
        errata: matched,
        checked_artefact,
        checked_policy,
        checked_report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Capability, CapabilitySet};
    use crate::envelope::Envelope as Env;
    use crate::policy::Mode;
    use crate::report::{DisableOverride, UnitRecord};
    use crate::unit::{UnitId, UnitKind};

    fn unit(name: &str, tiers: &[(Capability, Tier)]) -> UnitRecord {
        UnitRecord {
            id: UnitId::new(name, "1.0.0"),
            kind: UnitKind::BuildScriptCompile.into(),
            source: None,
            instance: None,
            envelope: Env::build_script_default(),
            tiers: tiers
                .iter()
                .map(|(c, t)| ((*c).into(), t.clone()))
                .collect(),
            env_scrubbed: Vec::new(),
            requests: Vec::new(),
            observed: CapabilitySet::default(),
            proc_macros_in_closure: Vec::new(),
            exit_code: Some(0),
            signal: None,
            duration_ms: 1,
        }
    }

    fn enforced() -> Tier {
        Tier::Enforced {
            mechanism: "netns".into(),
        }
    }

    fn advisory() -> Tier {
        Tier::Advisory {
            mechanism: "seccomp-notify".into(),
            limitation: "the decision is not atomic with the operation".into(),
        }
    }

    fn report_with(units: Vec<UnitRecord>) -> Report {
        let mut r = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
        r.units = units;
        r
    }

    fn everything_on() -> EnforcementProfile {
        EnforcementProfile {
            read_deny: true,
            read_deny_ruleset_sha256: Some("sha256:aa".into()),
            compile_units_held: true,
            net_destinations_recorded_only: true,
            landlock_abi_used: Some(7),
            disable_overrides: Vec::new(),
        }
    }

    fn predicate(report: &Report, profile: EnforcementProfile) -> Predicate {
        Predicate::from_report(
            report,
            "libthing.rlib",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            profile,
            "2026-09-15T10:00:00Z",
            "key-1",
        )
    }

    #[test]
    fn short_never_panics_on_a_multibyte_boundary() {
        // A well-formed digest is 64 ASCII hex characters and truncates to 16.
        assert_eq!(short(&"a".repeat(64)), "aaaaaaaaaaaaaaaa");
        // Shorter than the window is printed whole.
        assert_eq!(short("abc"), "abc");
        assert_eq!(short(""), "");
        // A malformed digest with a multi-byte character straddling byte 16 must not abort:
        // `verify_statement` accepts the digest fields as free-form strings, so this is
        // reachable input, not a hypothetical. Fifteen ASCII bytes then a 2-byte 'é' put a
        // char boundary across offset 16; a byte slice there would panic.
        let evil = format!("{}{}", "a".repeat(15), "é".repeat(4));
        let got = short(&evil);
        assert!(evil.starts_with(got), "the prefix must be a real prefix");
        assert!(
            got.len() <= 17,
            "truncated near the window, got {}",
            got.len()
        );
    }

    #[test]
    fn a_run_with_read_deny_off_is_not_fully_enforced() {
        // The rule the milestone puts first. Every tier says `enforced:` and every one of
        // them is true — about the capabilities that were held. With reads unrestricted a
        // build script read every credential file on the host, and "fully enforced" is not
        // what that was.
        let r = report_with(vec![unit("a", &[(Capability::Net, enforced())])]);
        let p = predicate(
            &r,
            EnforcementProfile {
                read_deny: false,
                read_deny_ruleset_sha256: None,
                ..everything_on()
            },
        );
        assert!(!p.is_fully_enforced());
        // And it says so in words, not only in a boolean.
        assert!(
            p.scope
                .not_held
                .iter()
                .any(|l| l.contains("Reads were unrestricted")),
            "{:?}",
            p.scope.not_held
        );
        assert!(p.plain_english().contains("NOT fully enforced"));
    }

    #[test]
    fn a_run_with_compile_units_unheld_is_not_fully_enforced() {
        let r = report_with(vec![unit("a", &[(Capability::Net, enforced())])]);
        let p = predicate(
            &r,
            EnforcementProfile {
                compile_units_held: false,
                ..everything_on()
            },
        );
        assert!(!p.is_fully_enforced());
        assert!(p
            .scope
            .not_held
            .iter()
            .any(|l| l.contains("Proc-macro expansion ran unheld")));
    }

    #[test]
    fn a_compile_recorded_as_unheld_is_not_fully_enforced_even_with_the_flag_on() {
        // The gap this closes, at the seam that closes it. When `hold-compile-units` is on
        // but one compilation cannot be held, `cargo-buildclamp` runs it unheld and records
        // it with every non-observe-only capability at `Tier::None` — the shape built here.
        // The profile flag `compile_units_held` stays true (the option WAS on), so a report
        // that merely omitted the failed unit would read as fully enforced while a proc-macro
        // ran outside the sandbox. The per-unit `none:` tiers are what make the summary tell
        // the truth: the weakest-wins summary drops below `enforced:`, and the answer turns
        // false whatever the flag says. This is why the fix records the unit instead of
        // dropping it, and this test fails the day someone lets an omission back in.
        let reason = "the sandbox could not be applied to this compilation; it ran unheld";
        let unheld = unit(
            "couldnt-hold",
            &[
                (
                    Capability::Net,
                    Tier::None {
                        reason: reason.into(),
                    },
                ),
                (
                    Capability::FsWrite,
                    Tier::None {
                        reason: reason.into(),
                    },
                ),
            ],
        );
        let held = unit("held", &[(Capability::Net, enforced())]);
        let r = report_with(vec![held, unheld]);
        // everything_on() carries compile_units_held: true — the exact state at a runtime
        // hold failure, and the one an omitted unit would have sailed through.
        let p = predicate(&r, everything_on());
        assert!(
            p.enforcement_profile.compile_units_held,
            "the flag is on, as it is when a single unit fails to hold"
        );
        assert!(
            p.enforcement_summary["net"].starts_with("none:"),
            "the weakest tier for net must be the unheld unit's none, not the held unit's \
             enforced: {:?}",
            p.enforcement_summary
        );
        assert!(
            !p.is_fully_enforced(),
            "a unit nothing held must never read as fully enforced, whatever the flag says"
        );
    }

    #[test]
    fn one_advisory_unit_among_two_hundred_enforced_still_fails() {
        // The assertion the milestone names. The summary takes the WEAKEST tier seen for a
        // capability, so one unit out of two hundred decides the answer — which is the
        // single most useful thing the document can tell an auditor and the easiest to lose
        // to a summary that took the last value it saw.
        let mut units: Vec<UnitRecord> = (0..199)
            .map(|i| unit(&format!("u{i}"), &[(Capability::Net, enforced())]))
            .collect();
        units.push(unit("the-one", &[(Capability::Net, advisory())]));
        let r = report_with(units);
        let p = predicate(&r, everything_on());
        assert_eq!(p.units_held, 200);
        assert!(p.enforcement_summary["net"].starts_with("advisory:"));
        assert!(!p.is_fully_enforced());

        // …and the order does not matter, which is what a summary keyed on "last one wins"
        // would get wrong half the time.
        let mut reversed = r.units.clone();
        reversed.reverse();
        let q = predicate(&report_with(reversed), everything_on());
        assert_eq!(q.enforcement_summary["net"], p.enforcement_summary["net"]);
    }

    #[test]
    fn an_operator_override_vetoes_the_claim() {
        let mut r = report_with(vec![unit("a", &[(Capability::Net, enforced())])]);
        r.disable_overrides.push(DisableOverride {
            source: "BUILDCLAMP_DISABLE".into(),
            value: "ns".into(),
            effect: "no namespaces".into(),
        });
        let p = predicate(&r, everything_on());
        assert!(!p.is_fully_enforced());
        assert!(p
            .plain_english()
            .contains("An operator switched enforcement off"));
    }

    #[test]
    fn a_statement_with_no_tiers_at_all_is_not_fully_enforced() {
        // An empty summary is a run that recorded nothing, not a run that enforced
        // everything. `all()` on an empty iterator is `true`, which is the shape of bug
        // this test exists for.
        let r = report_with(Vec::new());
        let p = predicate(&r, everything_on());
        assert!(p.enforcement_summary.is_empty());
        assert!(!p.is_fully_enforced());
    }

    #[test]
    fn everything_on_and_everything_enforced_is_the_one_case_that_passes() {
        let r = report_with(vec![
            unit("a", &[(Capability::Net, enforced())]),
            unit("b", &[(Capability::FsWrite, enforced())]),
        ]);
        let p = predicate(&r, everything_on());
        assert!(p.is_fully_enforced(), "{:?}", p.enforcement_summary);
        // Even then the scope is not empty: destinations are never enforced, and a reader
        // must not have to know this project's documentation to find that out.
        assert!(p
            .scope
            .not_held
            .iter()
            .any(|l| l.contains("recorded and never enforced")));
    }

    #[test]
    fn the_predicate_round_trips_through_json_unchanged() {
        let r = report_with(vec![unit("a", &[(Capability::Net, enforced())])]);
        let p = predicate(&r, everything_on());
        let text = serde_json::to_string(&p).unwrap();
        let back: Predicate = serde_json::from_str(&text).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn the_statement_carries_the_artefact_digest_where_a_policy_engine_looks_for_it() {
        // Kyverno, policy-controller and `cosign verify-attestation` all match on
        // `subject[].digest`. A hash that lived only in the predicate would be invisible to
        // every one of them, which is the reason it is lifted rather than duplicated by
        // accident.
        let r = report_with(vec![unit("a", &[(Capability::Net, enforced())])]);
        let p = predicate(&r, everything_on());
        let s = Statement {
            type_: STATEMENT_TYPE.into(),
            subject: vec![Subject {
                name: p.artefact_name.clone(),
                digest: BTreeMap::from([("sha256".into(), p.artefact_sha256.clone())]),
            }],
            predicate_type: PREDICATE_TYPE.into(),
            predicate: p.clone(),
        };
        let v: serde_json::Value = serde_json::to_value(&s).unwrap();
        assert_eq!(v["_type"], STATEMENT_TYPE);
        assert_eq!(v["predicateType"], PREDICATE_TYPE);
        assert_eq!(v["subject"][0]["digest"]["sha256"], p.artefact_sha256);
        let back: Statement = serde_json::from_value(v).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn pae_is_the_dsse_encoding_and_cannot_be_re_split() {
        // The published vector: DSSEv1 with a type and a body, lengths in ASCII decimal.
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
        // The property the lengths exist for. Without them, a type ending in digits and a
        // body beginning with them could be re-split into a different pair with the same
        // bytes — and a signature over one would verify over the other.
        let a = pae("type1", b"23 body");
        let b = pae("type", b"123 body");
        assert_ne!(a, b);
        assert_eq!(pae("", b""), b"DSSEv1 0  0 ".to_vec());
    }

    #[test]
    fn an_erratum_with_no_criteria_matches_nothing() {
        // The permissive reading of an empty filter would let one malformed document
        // invalidate every attestation a customer holds.
        let r = report_with(vec![unit("a", &[(Capability::Net, enforced())])]);
        let p = predicate(&r, everything_on());
        let e = Erratum {
            format_version: 1,
            id: "BCE-0001".into(),
            matches: ErratumMatch::default(),
            capability: None,
            corrected_tier: "advisory:seccomp-notify".into(),
            finding: "the filter did not refuse what it reported refusing".into(),
            published: "2026-10-01T00:00:00Z".into(),
        };
        assert!(!e.applies_to(&p));
    }

    #[test]
    fn an_erratum_matches_the_window_it_names_and_nothing_outside_it() {
        let r = report_with(vec![unit("a", &[(Capability::Net, enforced())])]);
        let p = predicate(&r, everything_on()); // built_at 2026-09-15T10:00:00Z, key-1
        let window = |from: &str, before: &str| Erratum {
            format_version: 1,
            id: "BCE-0001".into(),
            matches: ErratumMatch {
                key_id: Some("key-1".into()),
                built_at_from: Some(from.into()),
                built_at_before: Some(before.into()),
                artefact_sha256: None,
            },
            capability: Some("net".into()),
            corrected_tier: "advisory:seccomp-notify".into(),
            finding: "f".into(),
            published: "2026-10-01T00:00:00Z".into(),
        };
        assert!(window("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z").applies_to(&p));
        // The bounds are half-open: `from` includes, `before` excludes.
        assert!(window("2026-09-15T10:00:00Z", "2026-10-01T00:00:00Z").applies_to(&p));
        assert!(!window("2026-09-01T00:00:00Z", "2026-09-15T10:00:00Z").applies_to(&p));
        assert!(!window("2026-09-16T00:00:00Z", "2026-10-01T00:00:00Z").applies_to(&p));

        // A different key is a different signer and is not corrected by this.
        let mut other = window("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z");
        other.matches.key_id = Some("key-2".into());
        assert!(!other.applies_to(&p));
    }

    #[test]
    fn a_non_canonical_built_at_never_excludes_a_correction() {
        // The finding, exactly: `09:00:00-01:00` is `10:00:00Z` but sorts lexically before
        // `09:30:00Z`. A build whose predicate carries such a value must not slip past a
        // correction whose window covers it and keep an overstated tier visible.
        let r = report_with(vec![unit("a", &[(Capability::Net, enforced())])]);
        let mut p = predicate(&r, everything_on());
        p.built_at = "2026-09-15T09:00:00-01:00".into(); // == 10:00:00Z, sorts as "09:00…"
        let e = Erratum {
            format_version: 1,
            id: "BCE-0002".into(),
            matches: ErratumMatch {
                key_id: Some("key-1".into()),
                built_at_from: Some("2026-09-15T09:30:00Z".into()),
                built_at_before: Some("2026-10-01T00:00:00Z".into()),
                artefact_sha256: None,
            },
            capability: Some("net".into()),
            corrected_tier: "advisory:seccomp-notify".into(),
            finding: "f".into(),
            published: "2026-10-01T00:00:00Z".into(),
        };
        // Lexically "09:00:00-01:00" < "09:30:00Z", so the pre-fix code returned false and
        // dropped the correction. Fail-closed keeps it.
        assert!(e.applies_to(&p));
    }

    #[test]
    fn a_non_canonical_window_bound_never_excludes_a_correction() {
        // A malformed bound on the erratum side is equally untrustworthy: it must not be the
        // reason a correction is skipped, but a *canonical* bound still excludes as before.
        let r = report_with(vec![unit("a", &[(Capability::Net, enforced())])]);
        let p = predicate(&r, everything_on()); // canonical built_at 2026-09-15T10:00:00Z
        let mut e = Erratum {
            format_version: 1,
            id: "BCE-0003".into(),
            matches: ErratumMatch {
                key_id: Some("key-1".into()),
                built_at_from: None,
                built_at_before: Some("2026-09-15T09:00:00-01:00".into()), // non-canonical
                artefact_sha256: None,
            },
            capability: Some("net".into()),
            corrected_tier: "advisory:seccomp-notify".into(),
            finding: "f".into(),
            published: "2026-10-01T00:00:00Z".into(),
        };
        assert!(e.applies_to(&p));
        // The ordinary path is untouched: a canonical `before` at the build instant excludes.
        e.matches.built_at_before = Some("2026-09-15T10:00:00Z".into());
        assert!(!e.applies_to(&p));
    }

    // --- format version 2: waivers, and the verifier migration --------------------------

    fn day(s: &str) -> crate::civil::Date {
        crate::civil::Date::parse(s).expect("a valid date")
    }

    /// A bare Statement document for `p`, as `verify_statement` reads.
    fn document_for(p: &Predicate) -> String {
        let s = Statement {
            type_: STATEMENT_TYPE.into(),
            subject: vec![Subject {
                name: p.artefact_name.clone(),
                digest: BTreeMap::from([("sha256".into(), p.artefact_sha256.clone())]),
            }],
            predicate_type: PREDICATE_TYPE.into(),
            predicate: p.clone(),
        };
        serde_json::to_string(&s).expect("serialises")
    }

    fn report_with_waiver() -> Report {
        let mut r = report_with(vec![unit("a", &[(Capability::Net, enforced())])]);
        r.break_glass.push(crate::report::ExceptionUse {
            unit: UnitId::new("evilcrate", "1.0.0"),
            expires: "2026-12-31".into(),
            author: "someone@example.com".into(),
            reason: "shipping under a deadline".into(),
            grants: vec![],
            exercised: CapabilitySet::of(&[Capability::Net]),
            stood_down: vec![],
        });
        r
    }

    #[test]
    fn a_build_broken_glass_on_is_not_fully_enforced_whatever_the_tiers_say() {
        // Every tier is `enforced:` and true, and an exception still let one unit past the
        // policy. "Fully enforced" is not what that was, and the waiver is why.
        let p = predicate(&report_with_waiver(), everything_on());
        assert_eq!(p.waivers.len(), 1);
        assert_eq!(p.waivers[0].unit, UnitId::new("evilcrate", "1.0.0"));
        assert!(!p.is_fully_enforced());
    }

    #[test]
    fn an_exception_nobody_exercised_is_not_a_waiver() {
        // A live block that let nothing through waived nothing, so it must not flip
        // is_fully_enforced — otherwise an unused escape hatch would taint a clean build.
        let mut r = report_with(vec![unit("a", &[(Capability::Net, enforced())])]);
        r.break_glass.push(crate::report::ExceptionUse {
            unit: UnitId::new("cautious", "1.0.0"),
            expires: "2026-12-31".into(),
            author: "someone".into(),
            reason: "just in case".into(),
            grants: vec![],
            exercised: CapabilitySet::default(),
            stood_down: vec![],
        });
        let p = predicate(&r, everything_on());
        assert!(p.waivers.is_empty());
        assert!(p.is_fully_enforced());
    }

    #[test]
    fn the_current_version_is_two_and_it_verifies() {
        let p = predicate(
            &report_with(vec![unit("a", &[(Capability::Net, enforced())])]),
            everything_on(),
        );
        assert_eq!(p.format_version, 2);
        assert_eq!(PREDICATE_VERSION, 2);
        let doc = document_for(&p);
        assert!(
            verify_statement(&doc, None, None, None, &[], day("2029-01-01")).is_ok(),
            "the current version verifies regardless of the v1 sunset"
        );
    }

    #[test]
    fn the_verifier_reads_version_one_before_its_sunset_and_refuses_it_after() {
        let mut p = predicate(
            &report_with(vec![unit("a", &[(Capability::Net, enforced())])]),
            everything_on(),
        );
        p.format_version = 1;
        let doc = document_for(&p);
        // Before the stated sunset, a v1 statement still verifies — it was valid when written.
        assert!(verify_statement(&doc, None, None, None, &[], day("2027-06-01")).is_ok());
        // On and after it, refused, and the error names the version and the date.
        let err = verify_statement(&doc, None, None, None, &[], day("2028-01-01")).unwrap_err();
        assert!(
            matches!(err, VerifyError::VersionSunset { version: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn the_verifier_refuses_a_version_from_the_future() {
        // A newer buildclamp's statement is refused rather than read on the parts this one
        // recognises — the permissive direction, wrong for a signature.
        let mut p = predicate(
            &report_with(vec![unit("a", &[(Capability::Net, enforced())])]),
            everything_on(),
        );
        p.format_version = PREDICATE_VERSION + 1;
        let doc = document_for(&p);
        let err = verify_statement(&doc, None, None, None, &[], day("2026-09-16")).unwrap_err();
        assert!(matches!(err, VerifyError::UnknownVersion { .. }), "{err:?}");
    }
}
