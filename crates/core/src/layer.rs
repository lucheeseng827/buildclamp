//! Policy composition: an org layer, a policyset layer, a repo layer.
//!
//! # What this is for
//!
//! A single `buildclamp.toml` per repository is right for one repository and wrong for
//! forty. What a security team actually wants to say — "no build script in this
//! organisation reaches the network, and here are the nine crates that may" — has nowhere
//! to live in a flat file, so it gets said in a wiki and enforced by nobody.
//!
//! # The mechanism is free, and that is deliberate
//!
//! A proprietary policy dialect forks the tool. A customer with a hand-written org policy
//! in git gets the whole of this for nothing, exactly as a customer with a hand-written
//! rule gets Semgrep's engine for nothing. What is worth selling is *authorship and
//! distribution* — writing the org layer, keeping it current, getting it onto forty
//! machines — and none of that is the resolution algorithm.
//!
//! # The one rule that makes layering worth having
//!
//! A layer may declare itself a **ceiling**: `may-widen = false` says that no layer above
//! it may confer anything it did not. A layer above that tries is a **hard error naming
//! both files**, never a merge and never a silent narrowing.
//!
//! The declaration belongs to the layer being protected, not to the one doing the widening.
//! A layer that could be marked widenable from above would be no protection at all — the
//! repo could simply say so.
//!
//! **A ceiling bounds every crate, including ones it never mentions.** That reads strict
//! and it is the only coherent reading: the org layer's answer for a crate it does not name
//! is "the defaults", and if a repo could exceed the defaults for any crate the org had not
//! thought of, the ceiling would hold only for crates somebody had already worried about —
//! which is exactly the set that needs it least.
//!
//! # Precedence, and refusing rather than guessing
//!
//! Layers are ordered **nearest last**: the repo's own file is the last word, and each
//! `extends` entry is composed beneath it in the order written. Within one layer, the
//! existing rule stands and is unchanged — most specific wins, a tie is
//! [`crate::PolicyError::Ambiguous`] rather than last-one-wins. Across layers, the nearest
//! layer with a matching grant wins, bounded by every ceiling beneath it.
//!
//! A cycle in `extends` is refused by name. So is a file that extends nothing and is
//! extended by nothing while declaring `may-widen = false`, because a ceiling nobody is
//! under is a line that reads like a control and is not one.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::capability::Capability;
use crate::envelope::{Envelope, EnvelopeSource};
use crate::policy::{Policy, PolicyError};
use crate::unit::{UnitId, UnitKind};
use crate::wire::Forward;

/// The `[layer]` table: what this file is called, what it sits on, and whether anything
/// above it may exceed it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct LayerDecl {
    /// A name a person will read in a refusal and in `explain`. Required: "layer 2" is not
    /// a thing anybody can act on, and the whole value of the feature is that a reader can
    /// tell which document decided.
    pub name: String,

    /// Files this layer is composed **on top of**, nearest last.
    ///
    /// Relative paths, resolved against the file that names them — never against the
    /// working directory, which is wherever cargo happened to be invoked from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extends: Vec<String>,

    /// May a layer above this one confer something this one did not?
    ///
    /// Defaults to **true**, because a file that says nothing about layering must behave
    /// exactly as it did before layering existed. `false` makes this layer a ceiling.
    #[serde(default = "yes")]
    pub may_widen: bool,
}

fn yes() -> bool {
    true
}

/// A resolved stack: every layer, nearest last, with the file each came from.
///
/// Built by the caller, because loading files is I/O and this crate has none. The CLI walks
/// `extends`, reads each file, and hands the result here — which also means the cycle check
/// and the path resolution live where the paths are, and the composition rule lives where
/// the policy semantics are.
#[derive(Clone, Debug)]
pub struct Stack {
    layers: Vec<Layer>,
}

/// One layer in a stack.
#[derive(Clone, Debug)]
pub struct Layer {
    /// The `[layer] name`, or a name the caller supplied for a file that declared none.
    pub name: String,
    /// Where it came from, for a refusal that names both files.
    pub origin: String,
    pub policy: Policy,
}

impl Stack {
    /// A stack of one: what every repository with a single `buildclamp.toml` has.
    ///
    /// Not a special case in the resolution below — it goes through exactly the same path,
    /// because a composition rule that behaved differently for one layer would be a rule
    /// nobody exercised until the day they added a second.
    pub fn single(policy: Policy) -> Self {
        Self {
            layers: vec![Layer {
                name: policy
                    .layer
                    .as_ref()
                    .map(|l| l.name.clone())
                    .unwrap_or_else(|| "repo".to_string()),
                origin: "buildclamp.toml".to_string(),
                policy,
            }],
        }
    }

    /// Build a stack from layers already loaded, **nearest last**.
    pub fn new(layers: Vec<Layer>) -> Result<Self, PolicyError> {
        if layers.is_empty() {
            return Err(PolicyError::EmptyStack);
        }
        // A ceiling nobody is under is a line that reads like a control and is not one. The
        // last layer is the nearest, so nothing is above it.
        if let Some(top) = layers.last() {
            if !may_widen(&top.policy) && layers.len() == 1 {
                return Err(PolicyError::CeilingWithNothingAbove {
                    layer: top.name.clone(),
                    origin: top.origin.clone(),
                });
            }
        }
        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
        for l in &layers {
            if let Some(other) = seen.insert(&l.name, &l.origin) {
                return Err(PolicyError::DuplicateLayerName {
                    layer: l.name.clone(),
                    first: other.to_string(),
                    second: l.origin.clone(),
                });
            }
        }
        Ok(Self { layers })
    }

    pub fn layers(&self) -> &[Layer] {
        &self.layers
    }

    /// The nearest layer, which is the repository's own.
    pub fn nearest(&self) -> &Layer {
        self.layers.last().expect("a stack is never empty")
    }

    /// Unreviewed grants across **every** layer.
    ///
    /// `--strict` counts this rather than the nearest layer's, because a grant nobody has
    /// read is a grant nobody has read whichever file it is in — and the org layer is the
    /// one whose grants apply to forty repositories at once.
    pub fn unreviewed_grants(&self) -> usize {
        self.layers
            .iter()
            .map(|l| l.policy.unreviewed_grants())
            .sum()
    }

    /// Environment names re-admitted by **any** layer.
    ///
    /// A union, because the driver scrubs its own environment once before cargo starts and
    /// a name removed there is gone before any unit exists. A name only the org layer
    /// re-admits has to survive that scrub, or the org layer's `env-allow` would be a key
    /// that parses, validates and cannot take effect — which is the defect the union in
    /// [`Policy::env_allow_union`] was written for, one layer up.
    pub fn env_allow_union(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .layers
            .iter()
            .flat_map(|l| l.policy.env_allow_union())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// [`Policy::unreviewed`], summed across every layer.
    pub fn unreviewed(
        &self,
        grace: Option<crate::Grace>,
        glass: &crate::BreakGlass,
    ) -> crate::Unreviewed {
        let mut out = crate::Unreviewed::default();
        for l in &self.layers {
            let mut part = l.policy.unreviewed(grace, glass);
            out.failing.append(&mut part.failing);
            out.in_grace.append(&mut part.in_grace);
            out.excepted.append(&mut part.excepted);
        }
        out
    }

    /// Resolve every crate any layer names, so a stack that cannot compose is refused
    /// **before cargo starts**.
    ///
    /// # Why this is not left to the per-unit resolution
    ///
    /// [`Stack::resolve`] answers about one unit, so a ceiling violation would first be
    /// noticed in the launcher — a separate process, halfway through a build, with a target
    /// directory already half written. Every other policy error in this tool is caught
    /// before a single unit runs, and a composition error is the one most likely to be
    /// somebody's first encounter with layering.
    ///
    /// # Which versions it checks
    ///
    /// A grant may be version-qualified, and resolving at an arbitrary version would match
    /// nothing. So the candidates come from the requirements themselves: each comparator's
    /// own `major.minor.patch` is a version that satisfies a `>=`, `^`, `~` or `=` bound,
    /// which is every form `init` writes and every form anyone types. `0.0.0` and a
    /// deliberately high version are added so that an unqualified grant and a `<` bound are
    /// both reached.
    ///
    /// It is a **sweep, not a proof**. A requirement whose only satisfying versions are ones
    /// no candidate here happens to hit would slip through and be caught per-unit, which is
    /// where it was caught before. The sweep exists to move the common case earlier, and
    /// saying which case it does not cover is cheaper than implying it covers all of them.
    pub fn check(&self) -> Result<(), PolicyError> {
        let mut names: Vec<&String> = self
            .layers
            .iter()
            .flat_map(|l| l.policy.grants.keys())
            .collect();
        names.sort();
        names.dedup();

        for name in names {
            for version in self.candidate_versions(name) {
                let id = UnitId::new(name, &version);
                for kind in [UnitKind::BuildScriptCompile, UnitKind::Compile] {
                    for member in [false, true] {
                        self.resolve(&id, kind, member)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn candidate_versions(&self, name: &str) -> Vec<String> {
        let mut out = vec!["0.0.0".to_string(), "9999.0.0".to_string()];
        for l in &self.layers {
            let Some(grants) = l.policy.grants.get(name) else {
                continue;
            };
            for g in grants.every() {
                let Some(req) = &g.version else {
                    continue;
                };
                let Ok(parsed) = semver::VersionReq::parse(req) else {
                    continue;
                };
                for c in &parsed.comparators {
                    out.push(format!(
                        "{}.{}.{}",
                        c.major,
                        c.minor.unwrap_or(0),
                        c.patch.unwrap_or(0)
                    ));
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Resolve one unit against the whole stack.
    ///
    /// The nearest layer with a matching grant wins; every ceiling beneath it bounds what
    /// that grant may confer, and a grant that exceeds a ceiling is refused by name rather
    /// than quietly narrowed. Narrowing silently would be the worst of the three options:
    /// the build would pass, the policy file would say one thing, and the envelope would be
    /// another — with nothing to tell a reader which.
    pub fn resolve(
        &self,
        unit: &UnitId,
        kind: UnitKind,
        is_workspace_member: bool,
    ) -> Result<Envelope, PolicyError> {
        self.resolve_with(unit, kind, is_workspace_member, &crate::BreakGlass::none())
    }

    /// [`Stack::resolve`], with break-glass applied.
    ///
    /// Break-glass comes from the **nearest** layer only, and deliberately: an exception is
    /// somebody in this repository shipping past a refusal today, and an org layer that
    /// could carry one would be breaking glass on forty repositories from a file none of
    /// their engineers read.
    pub fn resolve_with(
        &self,
        unit: &UnitId,
        kind: UnitKind,
        is_workspace_member: bool,
        glass: &crate::BreakGlass,
    ) -> Result<Envelope, PolicyError> {
        // The ceilings beneath each position, computed once. A layer at index `i` is
        // bounded by every ceiling at an index below it.
        let mut winner: Option<(usize, Envelope)> = None;
        for (i, l) in self.layers.iter().enumerate() {
            let envelope = l.policy.resolve(unit, kind, is_workspace_member)?;
            // A layer that fell through to its own defaults did not decide anything, so it
            // does not displace a farther layer that did. `TrustedWorkspace` DOES decide:
            // it is an explicit answer about this unit rather than the absence of one.
            let decided = !matches!(envelope.source, EnvelopeSource::Default);
            if decided || winner.is_none() {
                winner = Some((i, envelope));
            }
        }
        let (at, mut envelope) = winner.expect("a stack is never empty");

        // Every ceiling BELOW the winning layer bounds it. Below, not above: a ceiling
        // constrains what may be conferred by the layers stacked on it, and a layer nearer
        // the repository than the winner did not confer this envelope.
        for (i, l) in self.layers.iter().enumerate() {
            if i >= at || may_widen(&l.policy) {
                continue;
            }
            let ceiling = l.policy.resolve(unit, kind, is_workspace_member)?;
            if let Some(capability) = exceeds(&envelope, &ceiling) {
                return Err(PolicyError::LayerWouldWiden(Box::new(
                    crate::policy::LayerConflict {
                        crate_name: unit.name.clone(),
                        capability,
                        layer: self.layers[at].name.clone(),
                        layer_origin: self.layers[at].origin.clone(),
                        ceiling: l.name.clone(),
                        ceiling_origin: l.origin.clone(),
                    },
                )));
            }
            envelope.source = with_ceiling(envelope.source, &self.layers[at].name, &l.name);
        }

        if self.layers.len() > 1 {
            envelope.source = as_layer(envelope.source, &self.layers[at].name);
        }

        Ok(crate::policy::apply_exception_pub(
            envelope,
            glass.naming(&unit.name),
        ))
    }
}

fn may_widen(p: &Policy) -> bool {
    p.layer.as_ref().is_none_or(|l| l.may_widen)
}

/// The first thing `envelope` confers that `ceiling` does not, if any.
///
/// Capabilities first, then zones, then paths, then re-admitted environment names — in the
/// order a reader would ask about them, so the message names the most alarming difference
/// rather than the first one alphabetically.
fn exceeds(envelope: &Envelope, ceiling: &Envelope) -> Option<String> {
    for c in Capability::ALL {
        if envelope.granted.contains(c) && !ceiling.granted.contains(c) {
            return Some(c.as_str().to_string());
        }
    }
    for z in &envelope.write_zones {
        // Containment, not equality: `OUT_DIR` lives under the target directory, and the
        // default zones differ by unit kind, so a plain `out-dir` grant would otherwise
        // read as widening a ceiling whose compile-unit default said `target`. See
        // [`WriteZone::contains`].
        //
        // A zone this build has no name for covers nothing and is covered by nothing: it
        // cannot be shown to be inside a ceiling, so it is treated as outside one. That is
        // the fail-closed direction, and the alternative is a ceiling that a newer
        // buildclamp's vocabulary could walk through.
        let covered = ceiling.write_zones.iter().any(|c| match (c, z) {
            (Forward::Known(c), Forward::Known(z)) => c.contains(*z),
            (a, b) => a == b,
        });
        if !covered {
            return Some(format!("write-zone `{z}`"));
        }
    }
    for p in &envelope.write_paths {
        if !ceiling.write_paths.contains(p) {
            return Some(format!("write-path `{p}`"));
        }
    }
    for n in &envelope.env_allow {
        if !ceiling.env_allow.iter().any(|a| a.eq_ignore_ascii_case(n)) {
            return Some(format!("environment name `{n}`"));
        }
    }
    None
}

/// Rewrite a source as a layered one, keeping what it already said.
fn as_layer(source: EnvelopeSource, layer: &str) -> EnvelopeSource {
    match source {
        EnvelopeSource::Grant { crate_name } => EnvelopeSource::Layer {
            crate_name,
            layer: layer.to_string(),
            req: None,
            ceiling: None,
        },
        EnvelopeSource::GrantVersioned { crate_name, req } => EnvelopeSource::Layer {
            crate_name,
            layer: layer.to_string(),
            req: Some(req),
            ceiling: None,
        },
        // Already layered (a ceiling was recorded first), or a source that names no grant:
        // the defaults and `trust_workspace` are answers about the whole stack rather than
        // about one layer's grant, and dressing them up as one would name a document that
        // did not decide anything.
        other => other,
    }
}

fn with_ceiling(source: EnvelopeSource, layer: &str, ceiling: &str) -> EnvelopeSource {
    match as_layer(source, layer) {
        EnvelopeSource::Layer {
            crate_name,
            layer,
            req,
            ..
        } => EnvelopeSource::Layer {
            crate_name,
            layer,
            req,
            ceiling: Some(ceiling.to_string()),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Capability;

    fn layer(name: &str, text: &str) -> Layer {
        Layer {
            name: name.to_string(),
            origin: format!("{name}/buildclamp.toml"),
            policy: Policy::parse(text)
                .unwrap_or_else(|e| panic!("the {name} layer in this test parses: {e}")),
        }
    }

    fn unit(name: &str) -> UnitId {
        UnitId::new(name, "1.0.0")
    }

    /// An org layer that is a ceiling: `openssl-sys` may reach the network, nothing else
    /// may, and nothing above may add to that.
    const ORG: &str = r#"
        version = 2
        [layer]
        name = "org"
        may-widen = false
        [grants."openssl-sys"]
        capabilities = ["net", "fs-write", "exec", "unix"]
        write-zones = ["out-dir", "tmp"]
        why = "downloads a pinned tarball when no system library is found"
        reviewed = true
    "#;

    #[test]
    fn a_repo_layer_wins_where_the_org_said_nothing() {
        // The ordinary case, and the one that has to stay cheap: a repository that adds a
        // grant for a crate its org layer never mentioned, within what the ceiling allows.
        let stack = Stack::new(vec![
            layer("org", ORG),
            layer(
                "repo",
                r#"
                version = 2
                [layer]
                name = "repo"
                [grants."cc"]
                capabilities = ["fs-write", "exec", "unix"]
                write-zones = ["out-dir", "tmp"]
                why = "compiles C"
                "#,
            ),
        ])
        .expect("a two-layer stack");

        let e = stack
            .resolve(&unit("cc"), UnitKind::BuildScriptCompile, false)
            .expect("inside the ceiling");
        assert!(e.permits(Capability::Exec));
        // And `explain` can say which layer, which is the whole point of the variant.
        match &e.source {
            EnvelopeSource::Layer { layer, ceiling, .. } => {
                assert_eq!(layer, "repo");
                assert_eq!(ceiling.as_deref(), Some("org"));
            }
            other => panic!("the source must name the layer: {other:?}"),
        }
        assert!(
            e.source.describe().contains("`repo` layer"),
            "{}",
            e.source.describe()
        );
        assert!(e.source.describe().contains("bounded by the `org` layer"));
    }

    #[test]
    fn a_repo_grant_that_exceeds_an_org_ceiling_is_a_hard_error_naming_both_files() {
        // The milestone's central assertion, and the reason the mechanism is worth having.
        // Not a merge, and not a silent narrowing: narrowing would leave the build passing,
        // one file saying the crate has the network and the envelope saying it does not,
        // with nothing to tell a reader which.
        let stack = Stack::new(vec![
            layer("org", ORG),
            layer(
                "repo",
                r#"
                version = 2
                [layer]
                name = "repo"
                [grants."telemetry-sys"]
                capabilities = ["net", "fs-write", "exec", "unix"]
                write-zones = ["out-dir", "tmp"]
                why = "phones home at build time"
                "#,
            ),
        ])
        .unwrap();

        let err = stack
            .resolve(&unit("telemetry-sys"), UnitKind::BuildScriptCompile, false)
            .expect_err("a repo may not exceed a ceiling");
        let PolicyError::LayerWouldWiden(conflict) = &err else {
            panic!("{err}");
        };
        assert_eq!(conflict.crate_name, "telemetry-sys");
        assert_eq!(conflict.capability, "net");
        assert_eq!(conflict.layer, "repo");
        assert_eq!(conflict.ceiling, "org");
        // Both files named, because a message naming one sends the reader to the wrong
        // half of the decision.
        let msg = err.to_string();
        assert!(msg.contains("repo/buildclamp.toml"), "{msg}");
        assert!(msg.contains("org/buildclamp.toml"), "{msg}");
    }

    #[test]
    fn a_ceiling_bounds_a_crate_it_never_mentions() {
        // The strict reading, and the only coherent one: the org's answer for a crate it
        // does not name is "the defaults". If a repo could exceed the defaults for any
        // crate the org had not thought of, the ceiling would hold only for the crates
        // somebody had already worried about — the set that needs it least.
        let stack = Stack::new(vec![
            layer("org", ORG),
            layer(
                "repo",
                r#"
                version = 2
                [layer]
                name = "repo"
                [grants."surprise"]
                capabilities = ["net", "fs-write", "exec", "unix"]
                write-zones = ["out-dir", "tmp"]
                why = "nobody upstairs has heard of this crate"
                "#,
            ),
        ])
        .unwrap();
        assert!(matches!(
            stack.resolve(&unit("surprise"), UnitKind::BuildScriptCompile, false),
            Err(PolicyError::LayerWouldWiden(_))
        ));
    }

    #[test]
    fn a_repo_may_always_narrow() {
        // Narrowing is never a contradiction, whatever the ceiling says. A repository that
        // wants less than its organisation allows is a repository doing the right thing.
        let stack = Stack::new(vec![
            layer("org", ORG),
            layer(
                "repo",
                r#"
                version = 2
                [layer]
                name = "repo"
                [grants."openssl-sys"]
                capabilities = ["fs-write", "exec", "unix"]
                write-zones = ["out-dir"]
                why = "our vendored copy needs no network"
                reviewed = true
                "#,
            ),
        ])
        .unwrap();
        let e = stack
            .resolve(&unit("openssl-sys"), UnitKind::BuildScriptCompile, false)
            .expect("narrowing is always allowed");
        assert!(
            !e.permits(Capability::Net),
            "the repo took the network away"
        );
        assert!(e.permits(Capability::Exec));
    }

    #[test]
    fn a_layer_that_may_widen_lets_the_one_above_exceed_it() {
        // Without `may-widen = false` the stack is composition without enforcement, which
        // is what a policyset layer nobody has locked down should be.
        let stack = Stack::new(vec![
            layer(
                "policyset",
                r#"
                version = 2
                [layer]
                name = "policyset"
                [grants."openssl-sys"]
                capabilities = ["fs-write", "exec", "unix"]
                write-zones = ["out-dir", "tmp"]
                why = "no network here"
                "#,
            ),
            layer(
                "repo",
                r#"
                version = 2
                [layer]
                name = "repo"
                [grants."openssl-sys"]
                capabilities = ["net", "fs-write", "exec", "unix"]
                write-zones = ["out-dir", "tmp"]
                why = "this repo does need it"
                "#,
            ),
        ])
        .unwrap();
        let e = stack
            .resolve(&unit("openssl-sys"), UnitKind::BuildScriptCompile, false)
            .expect("nothing declared a ceiling");
        assert!(e.permits(Capability::Net));
        match &e.source {
            EnvelopeSource::Layer { layer, ceiling, .. } => {
                assert_eq!(layer, "repo");
                assert_eq!(*ceiling, None, "nothing bounded it");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_ceiling_with_nothing_above_it_is_refused() {
        // A line that reads like a control and is not one. Either something should be
        // extending this file, or the line should go — and the tool says which rather than
        // leaving somebody to believe in it.
        let err = Stack::new(vec![layer("org", ORG)]).expect_err("a ceiling needs a stack");
        assert!(
            matches!(err, PolicyError::CeilingWithNothingAbove { .. }),
            "{err}"
        );
    }

    #[test]
    fn two_layers_with_one_name_are_refused() {
        let err = Stack::new(vec![
            layer("org", "version = 2\n[layer]\nname = \"org\"\n"),
            layer("org", "version = 2\n[layer]\nname = \"org\"\n"),
        ])
        .expect_err("a refusal naming one of two identical names sends a reader nowhere");
        assert!(
            matches!(err, PolicyError::DuplicateLayerName { .. }),
            "{err}"
        );
    }

    #[test]
    fn strict_counts_unreviewed_grants_across_every_layer() {
        // A grant nobody has read is a grant nobody has read whichever file it is in — and
        // the org layer is the one whose grants apply to forty repositories at once, so
        // counting only the nearest would be counting the least important.
        let stack = Stack::new(vec![
            layer(
                "org",
                r#"
                version = 2
                [layer]
                name = "org"
                [grants."a"]
                capabilities = ["net"]
                why = "unread"
                [grants."b"]
                capabilities = ["net"]
                why = "read"
                reviewed = true
                "#,
            ),
            layer(
                "repo",
                r#"
                version = 2
                [layer]
                name = "repo"
                [grants."c"]
                capabilities = ["net"]
                why = "unread"
                "#,
            ),
        ])
        .unwrap();
        assert_eq!(stack.unreviewed_grants(), 2);
    }

    #[test]
    fn a_stack_of_one_resolves_exactly_as_an_unlayered_policy_does() {
        // The property that keeps composition from being a second code path: a single-file
        // repository goes through the same resolution, and a rule that behaved differently
        // for one layer would be a rule nobody exercised until they added a second.
        let text = r#"
            version = 2
            [grants."openssl-sys"]
            capabilities = ["net", "fs-write", "exec", "unix"]
            write-zones = ["out-dir", "tmp"]
            why = "x"
        "#;
        let policy = Policy::parse(text).unwrap();
        let direct = policy
            .resolve(&unit("openssl-sys"), UnitKind::BuildScriptCompile, false)
            .unwrap();
        let stacked = Stack::single(policy)
            .resolve(&unit("openssl-sys"), UnitKind::BuildScriptCompile, false)
            .unwrap();
        assert_eq!(direct, stacked);
        // Including the source: a lone file is not "the `repo` layer's grant", it is the
        // grant, and dressing it up would name a layering nobody set up.
        assert!(matches!(stacked.source, EnvelopeSource::Grant { .. }));
    }

    #[test]
    fn break_glass_comes_from_the_nearest_layer_only() {
        // An exception is somebody in THIS repository shipping past a refusal today. An org
        // layer that could carry one would be breaking glass on forty repositories from a
        // file none of their engineers read.
        let today = crate::Date::parse("2026-09-16").unwrap();
        let org = layer(
            "org",
            r#"
            version = 2
            [layer]
            name = "org"
            [[exception]]
            crate = "telemetry-sys"
            expires = "2026-09-20"
            reason = "an incident somewhere else entirely"
            author = "someone@example.com"
            "#,
        );
        let repo = layer("repo", "version = 2\n[layer]\nname = \"repo\"\n");
        let stack = Stack::new(vec![org.clone(), repo.clone()]).unwrap();

        // The org's exception is not in force: the glass the stack honours is the nearest
        // layer's, and the nearest layer has none.
        let glass = repo.policy.break_glass(today).unwrap();
        let e = stack
            .resolve_with(
                &unit("telemetry-sys"),
                UnitKind::BuildScriptCompile,
                false,
                &glass,
            )
            .unwrap();
        assert!(!e.permits(Capability::Net));
        assert_eq!(e.excepted_until, None);
    }
}
