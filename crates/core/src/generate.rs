//! Turning a capability record into a starting `buildclamp.toml`.
//!
//! This is the adoption path and it is not a convenience feature. A default-deny policy
//! that breaks common crates on the first run is dead on arrival — the tool gets
//! uninstalled the same afternoon — so the documented first command is
//! `cargo buildclamp observe`, which refuses nothing, and the second is
//! `cargo buildclamp init`, which writes the file describing what the build actually
//! did. Enforcement is the third command, and by then it passes.
//!
//! Two properties the generated file must have, both of which are about what happens
//! next rather than about the file itself:
//!
//! * **Every generated grant is `reviewed = false`.** The tool cannot know whether a
//!   build script *should* reach the network; it only knows that it did. Marking its own
//!   output reviewed would launder an observation into an approval, and `--strict`
//!   exists so CI can refuse to pass while any of them is still unread.
//! * **The `why` says it is an observation, with the date.** A human replacing it with a
//!   real reason is the work; a `why` that read like a justification would make that
//!   work invisible.

use std::collections::{BTreeMap, BTreeSet};

use crate::baseline::{Acceptance, Baseline, BaselineRef};
use crate::capability::{Capability, CapabilitySet};
use crate::envelope::{Envelope, WriteZone};
use crate::policy::{Defaults, Grant, Grants, Mode, Policy, POLICY_VERSION};
use crate::report::Report;
use crate::unit::UnitId;

/// What one unit was observed doing, distilled from a report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub id: UnitId,
    pub used: CapabilitySet,
    /// Distinct destinations seen, for the grant's `net-destinations` field.
    pub destinations: Vec<String>,
    /// Environment names that were scrubbed and that the unit might have wanted.
    pub env_scrubbed: Vec<String>,
}

/// Collapse a report into one observation per unit.
///
/// Units are keyed by [`UnitId`], so a crate that appears as both a build script and a
/// compile unit is merged — which is right, because the policy is keyed the same way and
/// a grant applies to both.
pub fn observations(report: &Report) -> Vec<Observation> {
    let mut by_unit: BTreeMap<UnitId, Observation> = BTreeMap::new();
    for u in &report.units {
        let entry = by_unit.entry(u.id.clone()).or_insert_with(|| Observation {
            id: u.id.clone(),
            used: CapabilitySet::EMPTY,
            destinations: Vec::new(),
            env_scrubbed: Vec::new(),
        });
        for c in u.observed.iter() {
            entry.used.insert(c);
        }
        for r in &u.requests {
            // Only actual destinations. A `socket` request records the address family
            // ("AF_INET socket"), which is a fact about the call and not somewhere the
            // unit talked to — putting it in a destination list would make the generated
            // policy describe a host that does not exist.
            if r.capability.copied() == Some(Capability::Net)
                && looks_like_a_destination(&r.target)
                && !entry.destinations.contains(&r.target)
            {
                entry.destinations.push(r.target.clone());
            }
        }
        for name in &u.env_scrubbed {
            if !entry.env_scrubbed.contains(name) {
                entry.env_scrubbed.push(name.clone());
            }
        }
    }
    by_unit.into_values().collect()
}

/// Is this recorded target somewhere the unit talked to, rather than a description of the
/// call?
///
/// A destination is `host:port`, `1.2.3.4:443` or `[::1]:443`. Anything without a port is
/// a socket family or an unreadable argument.
fn looks_like_a_destination(target: &str) -> bool {
    match target.rsplit_once(':') {
        Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok(),
        None => false,
    }
}

/// Build a policy from a report.
///
/// `today` is passed in rather than read from a clock: this crate is pure, and a
/// generator that reached for the wall clock could not be tested by comparing its output
/// to a fixed string.
pub fn policy_from_report(report: &Report, today: &str) -> Policy {
    policy_from_report_accepting(report, today, None).0
}

/// `policy_from_report`, with a published baseline vouching for the grants it covers.
///
/// # What accepting may and may not do
///
/// It may mark a grant `reviewed = true` when the baseline has an entry for **that exact
/// version** and everything the grant asks for is inside what the entry allows. It then
/// pins the grant to that version — `=0.2.176` rather than the minor series `init` would
/// normally write — because a range would extend the baseline's approval to releases its
/// author never looked at. That is the same laundering `reviewed: false` exists to
/// prevent, and doing it in a published document's name would be worse than doing it
/// silently.
///
/// It may not do anything else. It cannot add a capability, widen a zone, or mark
/// anything the baseline does not cover: a crate that did something the document never
/// described comes out `reviewed = false` with its ordinary observation `why`, exactly as
/// if no baseline had been passed.
///
/// `accepted` is `(baseline, digest)`. The digest is computed by the caller, over the
/// document's bytes as they were read, because this crate does no I/O and hashing a
/// re-serialised copy would name a file nobody has.
pub fn policy_from_report_accepting(
    report: &Report,
    today: &str,
    accepted: Option<(&Baseline, &str)>,
) -> (Policy, Acceptance) {
    let mut acceptance = Acceptance::default();
    let mut grants: BTreeMap<String, PendingGrants> = BTreeMap::new();

    for obs in observations(report) {
        // The zones the observed units actually had, unioned across kinds, and — separately —
        // the zones a grantless enforcing run would hand those same kinds back. A crate seen
        // as both a build script and a compile unit needs OUT_DIR *and* `target`: `resolve`
        // replaces the default envelope with the grant's zones, so a grant hardcoded to the
        // build script's `[OutDir, Tmp]` dropped `target` from the compile unit and broke it
        // on the next enforcing run.
        let mut zone_set: BTreeSet<WriteZone> = BTreeSet::new();
        let mut default_zones: BTreeSet<WriteZone> = BTreeSet::new();
        let mut unknown_kind = false;
        for u in report.units.iter().filter(|u| u.id == obs.id) {
            zone_set.extend(u.envelope.known_zones());
            match u.kind.known() {
                Some(kind) => default_zones.extend(Envelope::default_for_kind(*kind).known_zones()),
                // A kind a newer agent wrote and this build cannot map to a default: keep the
                // grant rather than drop a zone on a guess.
                None => unknown_kind = true,
            }
        }

        // A unit needs no entry only when it stayed inside BOTH the default capabilities AND
        // the default zones for its kind — a grantless enforcing run then reconstructs exactly
        // what it had, and an entry per such crate would be a file nobody reviews. But a unit
        // that widened a zone (a build script writing `manifest-dir`, say, using only the
        // default capabilities) MUST keep a grant: `needs_no_grant` looks at capabilities
        // alone, and dropping the grant would silently lose the zone and deny that write on
        // the next enforcing run.
        let widens_zones = unknown_kind || !zone_set.is_subset(&default_zones);
        if needs_no_grant(&obs) && !widens_zones {
            continue;
        }

        let mut capabilities: Vec<Capability> = obs.used.iter().collect();
        // Whatever it used, plus what the default already allowed — otherwise generating
        // a grant for a crate that reached the network would silently take away the
        // OUT_DIR write it also needs.
        for c in [Capability::FsWrite, Capability::Exec, Capability::Unix] {
            if !capabilities.contains(&c) {
                capabilities.push(c);
            }
        }
        capabilities.sort();

        // A unit that recorded no zones still gets the build-script floor rather than an empty
        // grant, which `resolve` would read as "writes nowhere".
        if zone_set.is_empty() {
            zone_set.insert(WriteZone::OutDir);
            zone_set.insert(WriteZone::Tmp);
        }
        let zones: Vec<WriteZone> = zone_set.into_iter().collect();

        // The baseline is consulted here, where the EXACT observed version is in hand.
        // The grant that comes out of this block carries a version *requirement*, and a
        // requirement is not something a baseline can be matched against.
        let entry =
            accepted.and_then(|(baseline, _)| baseline.entry(&obs.id.name, &obs.id.version));
        let vouched =
            entry.filter(|e| e.covers(&capabilities, &zones, &[], &[], &obs.destinations));
        let who = format!("{} {}", obs.id.name, obs.id.version);
        let (version, why, reviewed) = match (vouched, accepted) {
            (Some(e), Some((_, digest))) => {
                acceptance.accepted.push(who);
                (
                    Some(format!("={}", obs.id.version)),
                    format!("{} — accepted from the baseline {}", e.why.trim(), digest),
                    true,
                )
            }
            _ => {
                if accepted.is_some() {
                    acceptance.residual.push(who);
                }
                (
                    minor_series(&obs.id.version),
                    describe_observation(&obs, today),
                    false,
                )
            }
        };

        grants.entry(obs.id.name.clone()).or_default().push(
            obs.id.version.clone(),
            Grant {
                // Pinned to the observed minor series, not to the exact version. Pinning
                // exactly would make every patch bump a fresh failure, which trains people to
                // widen the requirement until it means nothing; leaving it off entirely would
                // let a future version inherit a grant nobody looked at. The middle is where
                // drift is visible without being noise.
                version,
                capabilities,
                write_zones: zones,
                write_paths: Vec::new(),
                env_allow: Vec::new(),
                env_allow_secrets: false,
                net_destinations: obs.destinations.clone(),
                why,
                // True in exactly one case: a published baseline has an entry for this
                // crate at this exact version, and everything the grant asks for is inside
                // it. Otherwise never — see the module docs: the tool observed this, it did
                // not approve it.
                reviewed,
                // What `--grace` measures from. Written here and nowhere else: the day the
                // tool first wrote a grant for this crate is the only thing a grace window
                // can honestly count from, and a reviewer must never be able to reset it by
                // touching the file.
                first_seen: Some(today.to_string()),
            },
        );
    }

    let policy = Policy {
        version: POLICY_VERSION,
        // `init` writes a policy for the buildclamp that generated it. A file carrying
        // `net-destinations` or a zone an older agent never learned is not a file that
        // agent should read half of.
        min_tool_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        // `init` never generates an off switch. It writes what a run observed; disabling
        // enforcement is a decision a person makes, not one a recording implies.
        enforcement: None,
        defaults: Defaults {
            mode: Mode::Enforce,
            trust_workspace: false,
            env_deny: None,
            // `init` never turns withholding on. It writes what a run observed, and an
            // observe run cannot observe a read it did not restrict — so switching a
            // default-deny on from a recording would be enabling a restriction nothing
            // here has measured the cost of. That is a person's decision, made once, with
            // the break rate in front of them.
            withhold_secret_reads: false,
            // Nor an allowlist. Same reason: an observe run records which names were
            // reachable, not which were needed, so generating an allowlist from one would
            // be writing down the CI environment that happened to be present.
            env_allowlist: false,
            // And never holding compile units. An observe run does not hold them either,
            // so a recording cannot say what it would cost — and this is the switch whose
            // cost is the whole question.
            hold_compile_units: false,
            // The shipped cap. `init` writes it explicitly rather than leaving it to the
            // serde default, so that the first thing a reader learns about break-glass is
            // that there is a bound on it and where the bound is set.
            max_active_exceptions: crate::breakglass::DEFAULT_ACTIVE_EXCEPTION_CAP,
            // No trust root. `init` records what one build did; adopting signed policy is a
            // separate, deliberate act of committing the customer's own key, not something a
            // recording can infer.
            trust_root: Vec::new(),
        },
        grants: grants.into_iter().map(|(k, v)| (k, v.finish())).collect(),
        // `init` never generates an exception. An exception says a human decided to ship
        // past a refusal today; a recording cannot decide that, and a generator that
        // emitted one would be laundering an observation into an approval — the same
        // discipline `reviewed: false` above exists for.
        exceptions: Vec::new(),
        // `init` never generates a layer declaration. Which file sits on which is a fact
        // about how an organisation is arranged, and a recording of one build has no way
        // to know it — a generated `extends` would be pointing at a path nobody chose.
        layer: None,
        // The reviewer of record for every `reviewed = true` above. Written even when
        // nothing matched: "this policy was checked against that document and none of it
        // was covered" is a fact worth having in the file, and it is the one that tells
        // somebody the baseline is the wrong one rather than that they forgot to pass it.
        baseline: accepted.map(|(b, digest)| BaselineRef {
            digest: digest.to_string(),
            source: b.source.clone(),
            published: b.published.clone(),
            accepted: today.to_string(),
        }),
    };
    (policy, acceptance)
}

/// Grants accumulated for one crate name before the shape is chosen.
///
/// # The defect this type exists for
///
/// `policy_from_report` used to `insert` straight into a `BTreeMap<String, Grants>` keyed
/// on the crate NAME, while observations are keyed by name **and version**. A graph
/// holding two versions of the same crate — which is ordinary in cargo, and exactly what
/// `[patch]`, a workspace with two members on different majors, or a transitive
/// duplicate produces — generated two observations, and the second `insert` silently
/// erased the first.
///
/// Erasing is not a cosmetic loss. The surviving grant carries the OTHER version's
/// requirement, so the erased version matches no grant and falls back to the defaults on
/// the next enforcing run. `init` is the adoption path: the file it writes is supposed to
/// be one that passes. Instead the build breaks on a crate the user watched the tool
/// observe, which is the failure most likely to make somebody uninstall it.
#[derive(Default)]
struct PendingGrants(Vec<(String, Grant)>);

impl PendingGrants {
    fn push(&mut self, observed_version: String, g: Grant) {
        self.0.push((observed_version, g));
    }

    /// One grant stays `Grants::One`, so the common file is unchanged; several become
    /// `Grants::Many`, which is the shape the policy format already had for exactly this.
    fn finish(mut self) -> Grants {
        // Two observations of one crate whose version *requirements* come out identical — two
        // versions in the same minor series granted differently, both written `>=1.2, <1.3` —
        // would both match the same versions, and the resolver could not choose between them:
        // it would pick one unpredictably, or union them and over-grant. Pin each colliding
        // grant to its exact observed version so every version selects at most one grant.
        // Group by the MINOR SERIES of the observed version, not by the requirement string.
        // Two grants collide when some version matches both selectors, and that is exactly when
        // their observed versions share a minor series — whether they were written the same way
        // (two uncovered `>=1.2, <1.3`) or DIFFERENTLY: a baseline-covered `=1.2.3` and an
        // uncovered `>=1.2, <1.3` are distinct strings that both match `1.2.3`, so a check keyed
        // on the requirement string missed the overlap and the resolver could satisfy `1.2.3`
        // from either grant. Pin every grant in a colliding series to its exact observed
        // version, so each version selects at most one grant.
        let mut series_count: BTreeMap<String, usize> = BTreeMap::new();
        for (observed, _) in &self.0 {
            if let Some(series) = minor_series(observed) {
                *series_count.entry(series).or_default() += 1;
            }
        }
        for (observed, g) in &mut self.0 {
            if minor_series(observed)
                .is_some_and(|series| series_count.get(&series).copied().unwrap_or(0) > 1)
            {
                g.version = Some(format!("={observed}"));
            }
        }

        let mut grants: Vec<Grant> = self.0.into_iter().map(|(_, g)| g).collect();
        if grants.len() == 1 {
            return Grants::One(Box::new(grants.remove(0)));
        }
        // Sorted by version requirement so the file is stable across runs: a generated
        // file that reordered itself between two observations of the same graph would
        // show up as a diff in every review.
        grants.sort_by(|a, b| a.version.cmp(&b.version));
        Grants::Many(grants)
    }
}

/// Did this unit stay inside what the defaults already allow?
fn needs_no_grant(obs: &Observation) -> bool {
    let default_ok = CapabilitySet::of(&[Capability::FsWrite, Capability::Exec, Capability::Unix]);
    obs.used.added_over(default_ok).is_empty()
}

/// `1.2.3` becomes `>=1.2, <1.3`; `0.9.4` becomes `>=0.9.4, <0.10` because the whole
/// ecosystem treats a `0.x` minor as a major.
fn minor_series(version: &str) -> Option<String> {
    let v = semver::Version::parse(version).ok()?;
    if v.major == 0 {
        Some(format!(">={}.{}, <0.{}", v.major, v.minor, v.minor + 1))
    } else {
        Some(format!(
            ">={}.{}, <{}.{}",
            v.major,
            v.minor,
            v.major,
            v.minor + 1
        ))
    }
}

/// The `why` a generated grant carries.
///
/// It says what was seen and when, and it says a human has not written a reason yet.
/// Anything that read like a justification would hide the work that still has to happen.
fn describe_observation(obs: &Observation, today: &str) -> String {
    let mut what: Vec<String> = Vec::new();
    if obs.used.contains(Capability::Net) {
        if obs.destinations.is_empty() {
            what.push("opened a socket".to_string());
        } else {
            what.push(format!("connected to {}", obs.destinations.join(", ")));
        }
    }
    if obs.used.contains(Capability::EnvSecret) {
        what.push("had credential-shaped variables in its environment".to_string());
    }
    if what.is_empty() {
        what.push("used more than the defaults".to_string());
    }
    format!(
        "OBSERVED {today}: {}. Written by `cargo buildclamp init` from a recorded run — \
         replace this with the reason the crate needs it, then set reviewed = true.",
        what.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;
    use crate::envelope::Envelope;
    use crate::report::{Outcome, Report, Request, UnitRecord};
    use crate::unit::UnitKind;

    fn report_with(units: Vec<UnitRecord>) -> Report {
        let mut r = Report::new("0.1.0", Mode::Observe, vec!["build".into()]);
        r.units = units;
        r
    }

    fn unit(name: &str, version: &str, used: &[Capability], dests: &[&str]) -> UnitRecord {
        UnitRecord {
            id: UnitId::new(name, version),
            kind: UnitKind::BuildScriptCompile.into(),
            source: None,
            instance: None,
            envelope: Envelope::build_script_default(),
            tiers: std::collections::BTreeMap::new(),
            env_scrubbed: Vec::new(),
            requests: dests
                .iter()
                .map(|d| Request {
                    at_ms: 1,
                    tid: 1,
                    capability: Capability::Net.into(),
                    syscall: "connect".into(),
                    target: (*d).to_string(),
                    outcome: Outcome::WouldBeUngranted,
                    attribution: crate::report::Attribution::Unit,
                })
                .collect(),
            observed: CapabilitySet::of(used),
            proc_macros_in_closure: Vec::new(),
            exit_code: Some(0),
            signal: None,
            duration_ms: 1,
        }
    }

    #[test]
    fn a_crate_that_stayed_inside_the_defaults_gets_no_entry() {
        // The property that keeps a generated file short enough that somebody reads it.
        let r = report_with(vec![unit(
            "benign",
            "1.0.0",
            &[Capability::FsWrite, Capability::Exec],
            &[],
        )]);
        let p = policy_from_report(&r, "2026-09-01");
        assert!(p.grants.is_empty());
    }

    #[test]
    fn a_generated_grant_is_never_marked_reviewed() {
        // The tool observed this; it did not approve it. `--strict` refuses to pass
        // while any generated grant is still unread, and that is the whole mechanism.
        let r = report_with(vec![unit(
            "fetcher",
            "1.2.3",
            &[Capability::Net],
            &["crates.io:443"],
        )]);
        let p = policy_from_report(&r, "2026-09-01");
        let Grants::One(g) = &p.grants["fetcher"] else {
            panic!("expected a single grant")
        };
        assert!(!g.reviewed);
        assert!(g.why.contains("OBSERVED 2026-09-01"));
        assert!(g.why.contains("crates.io:443"));
        assert!(g.why.contains("replace this"));
    }

    #[test]
    fn a_generated_grant_keeps_the_capabilities_the_defaults_already_gave() {
        // Generating a grant because a crate reached the network must not silently take
        // away the OUT_DIR write it also needs.
        let r = report_with(vec![unit("fetcher", "1.2.3", &[Capability::Net], &[])]);
        let p = policy_from_report(&r, "2026-09-01");
        let Grants::One(g) = &p.grants["fetcher"] else {
            panic!()
        };
        assert!(g.capabilities.contains(&Capability::Net));
        assert!(g.capabilities.contains(&Capability::FsWrite));
        assert!(g.capabilities.contains(&Capability::Exec));
    }

    fn compile_unit(name: &str, version: &str, used: &[Capability]) -> UnitRecord {
        let mut u = unit(name, version, used, &[]);
        u.kind = UnitKind::Compile.into();
        u.envelope = Envelope::compile_default();
        u
    }

    #[test]
    fn a_crate_seen_as_both_build_script_and_compile_keeps_target() {
        // observations() merges the two by UnitId, and `resolve` replaces the default
        // envelope with the grant's zones. A grant carrying only the build script's
        // [OutDir, Tmp] would strip `target` from the compile unit and refuse it on the
        // next enforcing run, so the grant must union both kinds' zones.
        let r = report_with(vec![
            // The build script also reached the network, so a grant is generated at all.
            unit(
                "dual",
                "1.0.0",
                &[Capability::FsWrite, Capability::Net],
                &["crates.io:443"],
            ),
            // The same crate's compile unit, whose default envelope writes `target`.
            compile_unit("dual", "1.0.0", &[Capability::FsWrite]),
        ]);
        let p = policy_from_report(&r, "2026-09-01");
        let Grants::One(g) = &p.grants["dual"] else {
            panic!("expected a single merged grant")
        };
        assert!(
            g.write_zones.contains(&WriteZone::Target),
            "the compile unit's `target` zone was dropped: {:?}",
            g.write_zones
        );
        assert!(
            g.write_zones.contains(&WriteZone::OutDir),
            "the build script's OUT_DIR zone was dropped: {:?}",
            g.write_zones
        );
    }

    #[test]
    fn a_unit_that_widened_a_zone_keeps_its_grant_even_with_default_capabilities() {
        // The regression: a build script that writes `manifest-dir` but uses only the default
        // capabilities (fs-write, exec, unix). needs_no_grant looks at capabilities alone, so
        // it used to drop the grant — and the next enforcing run, back on the build-script
        // default of [OutDir, Tmp], then denied the manifest-dir write.
        let mut u = unit("writer", "1.0.0", &[Capability::FsWrite], &[]);
        u.envelope = {
            let mut e = Envelope::build_script_default();
            e.write_zones.push(WriteZone::ManifestDir.into());
            e
        };
        let r = report_with(vec![u]);
        let p = policy_from_report(&r, "2026-09-01");
        let Grants::One(g) = &p.grants["writer"] else {
            panic!("the widened manifest-dir grant was dropped: {:?}", p.grants)
        };
        assert!(
            g.write_zones.contains(&WriteZone::ManifestDir),
            "manifest-dir was lost: {:?}",
            g.write_zones
        );
    }

    #[test]
    fn two_versions_in_one_minor_series_get_exact_pins_not_colliding_selectors() {
        // 1.2.0 and 1.2.5 would both be written `>=1.2, <1.3`, and a resolver could not tell
        // the two grants apart — it would pick one unpredictably or union them. Each colliding
        // observation is pinned to its exact version instead.
        let r = report_with(vec![
            unit("dep", "1.2.0", &[Capability::Net], &["a:1"]),
            unit("dep", "1.2.5", &[Capability::Net], &["b:2"]),
        ]);
        let p = policy_from_report(&r, "2026-09-01");
        let Grants::Many(gs) = &p.grants["dep"] else {
            panic!("expected two grants for `dep`, got {:?}", p.grants["dep"])
        };
        let reqs: Vec<Option<&str>> = gs.iter().map(|g| g.version.as_deref()).collect();
        assert!(reqs.contains(&Some("=1.2.0")), "{reqs:?}");
        assert!(reqs.contains(&Some("=1.2.5")), "{reqs:?}");
        assert!(
            !reqs.contains(&Some(">=1.2, <1.3")),
            "a colliding minor-series selector survived: {reqs:?}"
        );
    }

    #[test]
    fn generated_policies_parse_and_then_make_the_same_build_pass() {
        // The round trip that matters: observe -> init -> enforce must be green, or the
        // adoption path does not exist.
        let r = report_with(vec![
            unit("fetcher", "1.2.3", &[Capability::Net], &["crates.io:443"]),
            unit("benign", "1.0.0", &[Capability::FsWrite], &[]),
        ]);
        let generated = policy_from_report(&r, "2026-09-01");
        let text = toml::to_string_pretty(&generated).unwrap();
        let reparsed = Policy::parse(&text).unwrap_or_else(|e| panic!("{e}\n---\n{text}"));

        let env = reparsed
            .resolve(
                &UnitId::new("fetcher", "1.2.3"),
                UnitKind::BuildScriptCompile,
                false,
            )
            .unwrap();
        assert!(
            env.permits(Capability::Net),
            "the grant must cover what was seen"
        );
        assert!(!env.reviewed, "and it must still be unreviewed");
    }

    #[test]
    fn a_socket_family_is_not_recorded_as_a_destination() {
        // `socket` records "AF_INET socket", which is a fact about the call. A generated
        // policy listing it as a destination would describe a host that does not exist.
        assert!(!looks_like_a_destination("AF_INET socket"));
        assert!(!looks_like_a_destination("<unreadable>"));
        assert!(looks_like_a_destination("127.0.0.1:9"));
        assert!(looks_like_a_destination("crates.io:443"));
        assert!(looks_like_a_destination("[::1]:443"));

        let r = report_with(vec![unit(
            "fetcher",
            "1.0.0",
            &[Capability::Net],
            &["AF_INET socket", "crates.io:443"],
        )]);
        let p = policy_from_report(&r, "2026-09-01");
        let Grants::One(g) = &p.grants["fetcher"] else {
            panic!()
        };
        assert_eq!(g.net_destinations, vec!["crates.io:443".to_string()]);
    }

    #[test]
    fn the_version_requirement_pins_a_minor_series_not_an_exact_version() {
        // Exact pinning makes every patch bump a fresh failure, which trains people to
        // widen the requirement until it means nothing. No requirement at all lets a
        // future version inherit a grant nobody looked at.
        assert_eq!(minor_series("1.2.3").unwrap(), ">=1.2, <1.3");
        // 0.x: the ecosystem treats a minor as a major, so the series is narrower.
        assert_eq!(minor_series("0.9.4").unwrap(), ">=0.9, <0.10");
        assert_eq!(minor_series("not-a-version"), None);
    }

    #[test]
    fn two_versions_of_one_crate_each_keep_their_grant() {
        // The defect: grants were keyed on the crate NAME while observations are keyed by
        // name AND version, so the second `insert` erased the first. Two versions of one
        // crate is ordinary in cargo — a `[patch]`, a workspace whose members sit on two
        // majors, a transitive duplicate — and the erased one then matched no grant and
        // fell back to the defaults on the next enforcing run. `init` exists to write a
        // file that passes; instead the build broke on a crate the user had just watched
        // the tool observe.
        let old = unit("dual", "1.2.0", &[Capability::Net], &["a.invalid:443"]);
        let new = unit("dual", "2.0.0", &[Capability::EnvSecret], &[]);
        let p = policy_from_report(&report_with(vec![old, new]), "2026-09-01");

        let Grants::Many(gs) = &p.grants["dual"] else {
            panic!(
                "two observed versions must produce two grants, got {:?}",
                p.grants["dual"]
            );
        };
        assert_eq!(gs.len(), 2);

        let reqs: Vec<&str> = gs.iter().filter_map(|g| g.version.as_deref()).collect();
        assert_eq!(reqs, vec![">=1.2, <1.3", ">=2.0, <2.1"]);

        // And each grant carries the capabilities of ITS version, not the other one's.
        let v1 = gs
            .iter()
            .find(|g| g.version.as_deref() == Some(">=1.2, <1.3"))
            .unwrap();
        let v2 = gs
            .iter()
            .find(|g| g.version.as_deref() == Some(">=2.0, <2.1"))
            .unwrap();
        assert!(v1.capabilities.contains(&Capability::Net));
        assert!(!v1.capabilities.contains(&Capability::EnvSecret));
        assert!(v2.capabilities.contains(&Capability::EnvSecret));
        assert!(!v2.capabilities.contains(&Capability::Net));
        assert_eq!(v1.net_destinations, vec!["a.invalid:443".to_string()]);
    }

    #[test]
    fn a_generated_policy_parses_back_and_resolves_both_versions() {
        // The round trip is the real assertion: a generated file that `Policy::parse`
        // rejects, or that resolves one version and not the other, would fail the user in
        // the same place the erasure did.
        let old = unit("dual", "1.2.0", &[Capability::Net], &[]);
        let new = unit("dual", "2.0.0", &[Capability::EnvSecret], &[]);
        let p = policy_from_report(&report_with(vec![old, new]), "2026-09-01");

        let text = toml::to_string_pretty(&p).expect("a generated policy serialises");
        let back = crate::policy::Policy::parse(&text).expect("and parses back");

        let a = back
            .resolve(
                &UnitId::new("dual", "1.2.3"),
                crate::unit::UnitKind::BuildScriptCompile,
                false,
            )
            .unwrap();
        let b = back
            .resolve(
                &UnitId::new("dual", "2.0.1"),
                crate::unit::UnitKind::BuildScriptCompile,
                false,
            )
            .unwrap();
        assert!(a.permits(Capability::Net));
        assert!(!a.permits(Capability::EnvSecret));
        assert!(b.permits(Capability::EnvSecret));
        assert!(!b.permits(Capability::Net));
    }

    #[test]
    fn one_crate_seen_as_two_unit_kinds_produces_one_grant() {
        let mut build = unit("dual", "1.0.0", &[Capability::Net], &[]);
        let mut compile = unit("dual", "1.0.0", &[Capability::EnvSecret], &[]);
        build.kind = UnitKind::BuildScriptCompile.into();
        compile.kind = UnitKind::Compile.into();
        let p = policy_from_report(&report_with(vec![build, compile]), "2026-09-01");
        assert_eq!(p.grants.len(), 1);
        let Grants::One(g) = &p.grants["dual"] else {
            panic!()
        };
        assert!(g.capabilities.contains(&Capability::Net));
        assert!(g.capabilities.contains(&Capability::EnvSecret));
    }

    // ---- --accept-baseline ------------------------------------------------------------

    /// A baseline covering `netty 1.2.3` doing exactly what the fixture below does.
    fn baseline(body: &str) -> Baseline {
        Baseline::parse(&format!("version = 1\nsource = \"https://example.invalid/b.toml\"\npublished = \"2026-09-01\"\n{body}")).expect("the test baseline parses")
    }

    fn netty() -> Report {
        // Uses the network, so it needs a grant at all — plus the three the generator
        // always folds in so a grant does not silently remove what the defaults gave.
        report_with(vec![unit(
            "netty",
            "1.2.3",
            &[Capability::Net],
            &["registry.example:443"],
        )])
    }

    #[test]
    fn a_baseline_entry_for_the_exact_version_marks_the_grant_reviewed_and_pins_it() {
        let b = baseline(
            "[[crate]]\nname = \"netty\"\nversion = \"1.2.3\"\n\
             capabilities = [\"net\", \"fs-write\", \"exec\", \"unix\"]\n\
             write-zones = [\"out-dir\", \"tmp\"]\n\
             net-destinations = [\"registry.example:443\"]\n\
             why = \"fetches its protocol definitions at build time\"\n",
        );
        let (p, acc) =
            policy_from_report_accepting(&netty(), "2026-09-15", Some((&b, "sha256:ab")));

        let g = match p.grants.get("netty").expect("a grant for netty") {
            Grants::One(g) => (**g).clone(),
            Grants::Many(v) => v[0].clone(),
        };
        assert!(g.reviewed, "the baseline vouched for this exact version");
        // Pinned, not the minor series `init` would otherwise write. A patch bump comes
        // back for review rather than inheriting an approval nobody made.
        assert_eq!(g.version.as_deref(), Some("=1.2.3"));
        // The `why` is the baseline's, and it names the document that vouched.
        assert!(
            g.why.starts_with("fetches its protocol definitions"),
            "{}",
            g.why
        );
        assert!(g.why.contains("sha256:ab"), "{}", g.why);
        // And the reviewer of record is in the file, not only in the grant.
        let r = p
            .baseline
            .expect("the policy records which document accepted");
        assert_eq!(r.digest, "sha256:ab");
        assert_eq!(r.source.as_deref(), Some("https://example.invalid/b.toml"));
        assert_eq!(r.published.as_deref(), Some("2026-09-01"));
        assert_eq!(r.accepted, "2026-09-15");

        assert_eq!(acc.accepted, vec!["netty 1.2.3"]);
        assert!(acc.residual.is_empty());
    }

    #[test]
    fn a_baseline_pin_and_an_uncovered_grant_in_one_series_do_not_overlap() {
        // The finding: the collision check compared requirement STRINGS, so a baseline-covered
        // `=1.2.3` and an uncovered `>=1.2, <1.3` — different strings that both match 1.2.3 —
        // were not seen as colliding, and the resolver could satisfy 1.2.3 from either grant.
        // Two observations of `netty` in one minor series, only one of them in the baseline,
        // must both come out exact-pinned so no version selects two grants.
        let r = report_with(vec![
            unit(
                "netty",
                "1.2.3",
                &[Capability::Net],
                &["registry.example:443"],
            ),
            unit(
                "netty",
                "1.2.7",
                &[Capability::Net],
                &["registry.example:443"],
            ),
        ]);
        let b = baseline(
            "[[crate]]\nname = \"netty\"\nversion = \"1.2.3\"\n\
             capabilities = [\"net\", \"fs-write\", \"exec\", \"unix\"]\n\
             write-zones = [\"out-dir\", \"tmp\"]\n\
             net-destinations = [\"registry.example:443\"]\n\
             why = \"fetches its protocol definitions at build time\"\n",
        );
        let (p, _acc) = policy_from_report_accepting(&r, "2026-09-15", Some((&b, "sha256:ab")));
        let Grants::Many(gs) = &p.grants["netty"] else {
            panic!("expected two grants for netty, got {:?}", p.grants["netty"])
        };
        let reqs: Vec<Option<&str>> = gs.iter().map(|g| g.version.as_deref()).collect();
        assert!(
            !reqs.contains(&Some(">=1.2, <1.3")),
            "an uncovered grant kept a minor-series selector that overlaps the baseline pin: \
             {reqs:?}"
        );
        assert!(
            reqs.contains(&Some("=1.2.3")),
            "the baseline pin was lost: {reqs:?}"
        );
        assert!(
            reqs.contains(&Some("=1.2.7")),
            "the uncovered grant was not pinned out of the overlap: {reqs:?}"
        );
    }

    #[test]
    fn a_baseline_never_marks_reviewed_anything_it_does_not_cover() {
        // The discipline the milestone names, in its four shapes. Each of these leaves the
        // grant exactly as a baseline-less `init` would have written it: unreviewed, on
        // the minor series, with the observation `why`.
        let cases: [(&str, &str); 4] = [
            (
                "a different version",
                "[[crate]]\nname = \"netty\"\nversion = \"1.2.4\"\n\
                 capabilities = [\"net\", \"fs-write\", \"exec\", \"unix\"]\n\
                 write-zones = [\"out-dir\", \"tmp\"]\n\
                 net-destinations = [\"registry.example:443\"]\nwhy = \"x\"\n",
            ),
            (
                "a different crate",
                "[[crate]]\nname = \"other\"\nversion = \"1.2.3\"\n\
                 capabilities = [\"net\", \"fs-write\", \"exec\", \"unix\"]\n\
                 write-zones = [\"out-dir\", \"tmp\"]\nwhy = \"x\"\n",
            ),
            (
                "one capability short of what was observed",
                "[[crate]]\nname = \"netty\"\nversion = \"1.2.3\"\n\
                 capabilities = [\"fs-write\", \"exec\", \"unix\"]\n\
                 write-zones = [\"out-dir\", \"tmp\"]\nwhy = \"x\"\n",
            ),
            (
                "a destination the document never mentioned",
                "[[crate]]\nname = \"netty\"\nversion = \"1.2.3\"\n\
                 capabilities = [\"net\", \"fs-write\", \"exec\", \"unix\"]\n\
                 write-zones = [\"out-dir\", \"tmp\"]\n\
                 net-destinations = [\"somewhere.else:443\"]\nwhy = \"x\"\n",
            ),
        ];
        for (what, body) in cases {
            let b = baseline(body);
            let (p, acc) =
                policy_from_report_accepting(&netty(), "2026-09-15", Some((&b, "sha256:ab")));
            let g = match p.grants.get("netty").expect("a grant for netty") {
                Grants::One(g) => (**g).clone(),
                Grants::Many(v) => v[0].clone(),
            };
            assert!(!g.reviewed, "{what}: accepted something it does not cover");
            assert_eq!(g.version.as_deref(), Some(">=1.2, <1.3"), "{what}");
            assert!(g.why.contains("OBSERVED"), "{what}: {}", g.why);
            assert_eq!(acc.residual, vec!["netty 1.2.3"], "{what}");
            assert!(acc.accepted.is_empty(), "{what}");
            // The digest is recorded even when nothing matched, which is what tells
            // somebody they passed the wrong baseline rather than forgot to pass one.
            assert!(p.baseline.is_some(), "{what}");
        }
    }

    #[test]
    fn a_crate_may_use_less_than_the_baseline_describes() {
        // A build script that skipped its fetch because a cache was warm is the ordinary
        // case, and refusing to accept it would make acceptance depend on the weather.
        let b = baseline(
            "[[crate]]\nname = \"netty\"\nversion = \"1.2.3\"\n\
             capabilities = [\"net\", \"fs-write\", \"exec\", \"unix\", \"env-secret\"]\n\
             write-zones = [\"out-dir\", \"tmp\", \"manifest-dir\"]\n\
             net-destinations = [\"registry.example:443\", \"mirror.example:443\"]\n\
             why = \"fetches its protocol definitions at build time\"\n",
        );
        let (_, acc) =
            policy_from_report_accepting(&netty(), "2026-09-15", Some((&b, "sha256:ab")));
        assert_eq!(acc.accepted, vec!["netty 1.2.3"]);
    }

    #[test]
    fn no_baseline_leaves_every_grant_exactly_where_it_was() {
        // `policy_from_report` is this function with `None`, and a change to the accepting
        // path must not move the ordinary one.
        let (with_none, acc) = policy_from_report_accepting(&netty(), "2026-09-15", None);
        let plain = policy_from_report(&netty(), "2026-09-15");
        assert_eq!(
            toml::to_string(&with_none).unwrap(),
            toml::to_string(&plain).unwrap()
        );
        assert!(with_none.baseline.is_none());
        // And nothing is counted: a run with no baseline has no residual to publish,
        // which is different from having a residual of zero.
        assert_eq!(acc.total(), 0);
    }
}
