//! A published capability baseline, and what accepting one may and may not do.
//!
//! # The problem this solves
//!
//! `cargo buildclamp init` on a real dependency graph writes a couple of hundred grants,
//! every one of them `reviewed = false`, and `--strict` refuses to pass while any are.
//! That is correct and it is also, on day one, impossible: nobody reads two hundred build
//! scripts in an afternoon, so the realistic outcomes are `--strict` never being turned
//! on, or somebody setting every `reviewed` to `true` with `sed`. Both end with a gate
//! that gates nothing.
//!
//! A baseline is a published document saying what the common crates do — `libc` probes
//! the target with a compiler and writes cfg flags to `OUT_DIR`, and so on — so that the
//! grants matching it can be marked reviewed against a reviewer of record, and the
//! remaining handful is a list somebody can actually read.
//!
//! # The three rules that keep it from being a rubber stamp
//!
//! **It matches on the exact version, and pins the grant to it.** `init` normally writes
//! a grant for the observed minor series (`>=0.2.176, <0.3`), because pinning exactly
//! would make every patch bump a fresh failure and train people to widen the requirement
//! until it means nothing. An accepted grant is the one case where that trade goes the
//! other way: the baseline approved `0.2.176`, so the grant it produces says `=0.2.176`.
//! Anything else would let a version nobody has looked at inherit an approval — which is
//! precisely the laundering this whole module is supposed to prevent, and it would be
//! doing it in the name of a document that never mentioned that version.
//!
//! The cost is stated rather than hidden: a patch bump of an accepted crate goes red
//! under `--strict` until the baseline is refreshed and `init --accept-baseline` is run
//! again. That is the intended workflow. `--grace` is what stops it being a 17:00
//! problem.
//!
//! **It only ever narrows.** A grant is accepted when everything it asks for is inside
//! what the baseline entry allows. A crate that did something the baseline did not
//! describe is not accepted, and its grant stays `reviewed = false` — the acceptance
//! cannot add a capability to a grant, only vouch for one already there. This is
//! `generate.rs`'s existing rule, that an observation is never laundered into an
//! approval, applied to a second document.
//!
//! **It records which document did the vouching.** The digest goes in the policy, and
//! every accepted grant's `why` names it. A reader holding the policy and a baseline file
//! can tell whether the second is the one the first was written against.
//!
//! The digest is not a defence against an adversary: anyone who can write
//! `reviewed = true` can write a digest beside it. It answers "which document?", not "who
//! is allowed to say?" — see [`crate::sha256`].

use serde::{Deserialize, Serialize};

use crate::capability::Capability;
use crate::envelope::WriteZone;

/// The baseline format version this build understands.
pub const BASELINE_VERSION: u32 = 1;

/// A parsed baseline document.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    pub version: u32,
    /// Where this document came from, so a reader holding only a digest can go and get
    /// it. Optional: a baseline kept in the repository has no URL and needs none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// When it was published, `YYYY-MM-DD`. Recorded rather than checked — a baseline
    /// does not expire, because the versions in it do not change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    /// Singular, because that is how TOML spells an array of tables: the blocks are
    /// `[[crate]]`.
    #[serde(default, rename = "crate")]
    pub entries: Vec<Entry>,
}

/// One crate at one version, and what the baseline says it legitimately does.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Entry {
    pub name: String,
    /// The **exact** version this describes — `0.2.176`, never a requirement. A range
    /// here would be a claim about versions the document's author did not look at.
    pub version: String,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub write_zones: Vec<WriteZone>,
    #[serde(default)]
    pub write_paths: Vec<String>,
    #[serde(default)]
    pub env_allow: Vec<String>,
    #[serde(default)]
    pub net_destinations: Vec<String>,
    /// What this crate needs it for, in a sentence. This is what an accepted grant's
    /// `why` becomes, so it is the line a reviewer of the *policy* ends up reading.
    pub why: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("the baseline is not valid TOML: {0}")]
    Toml(#[from] toml::de::Error),

    #[error(
        "the baseline declares version {found}, and this buildclamp understands version \
         {BASELINE_VERSION}. Upgrade buildclamp, or use a baseline written for it."
    )]
    Version { found: u32 },

    #[error(
        "the baseline entry for `{name}` has `version = \"{version}\"`, which is a \
         requirement rather than a version. A baseline says what one release of a crate \
         does, because that is the only thing its author can have looked at; a range here \
         would vouch for versions nobody read. Write `0.2.176`."
    )]
    NotExact { name: String, version: String },

    #[error(
        "the baseline entry for `{name}` {version} has no `why`. It becomes the accepted \
         grant's `why`, so it is the sentence somebody reviewing the policy reads instead \
         of the build script."
    )]
    MissingWhy { name: String, version: String },
}

impl Baseline {
    pub fn parse(text: &str) -> Result<Self, BaselineError> {
        // Version first, from a permissive parse, for the same reason the policy does it:
        // `deny_unknown_fields` turns a document from a newer buildclamp into an
        // "unknown field" error that sends the reader to delete a line when the real
        // answer is that the file was written for a later version.
        let probe: toml::Value = toml::from_str(text)?;
        if let Some(found) = probe.get("version").and_then(toml::Value::as_integer) {
            let found = u32::try_from(found).unwrap_or(u32::MAX);
            if found != BASELINE_VERSION {
                return Err(BaselineError::Version { found });
            }
        }
        let baseline: Baseline = toml::from_str(text)?;
        if baseline.version != BASELINE_VERSION {
            return Err(BaselineError::Version {
                found: baseline.version,
            });
        }
        for e in &baseline.entries {
            if semver::Version::parse(&e.version).is_err() {
                return Err(BaselineError::NotExact {
                    name: e.name.clone(),
                    version: e.version.clone(),
                });
            }
            if e.why.trim().is_empty() {
                return Err(BaselineError::MissingWhy {
                    name: e.name.clone(),
                    version: e.version.clone(),
                });
            }
        }
        Ok(baseline)
    }

    /// The entry for exactly this crate at exactly this version.
    ///
    /// Versions are compared as parsed semver values rather than as strings, which means
    /// a version either side that is not a well-formed `major.minor.patch` matches
    /// nothing — including the short `1.0` a person might write by hand, which `semver`
    /// refuses. That is the fail-closed direction: an entry nothing matches leaves a
    /// grant unreviewed, and the cost of getting it wrong is somebody reading one more
    /// build script rather than one fewer.
    pub fn entry(&self, name: &str, version: &str) -> Option<&Entry> {
        let want = semver::Version::parse(version).ok()?;
        self.entries.iter().find(|e| {
            e.name == name
                && semver::Version::parse(&e.version)
                    .map(|v| v == want)
                    .unwrap_or(false)
        })
    }
}

impl Entry {
    /// Is everything this grant asks for inside what the baseline allows?
    ///
    /// Subset, never equality. A crate that used less than its baseline entry describes is
    /// accepted — a build script that skipped its network fetch because a cache was warm
    /// is the ordinary case — and a crate that used *more* is not, whatever else matches.
    pub fn covers(
        &self,
        capabilities: &[Capability],
        write_zones: &[WriteZone],
        write_paths: &[String],
        env_allow: &[String],
        net_destinations: &[String],
    ) -> bool {
        capabilities.iter().all(|c| self.capabilities.contains(c))
            // Semantic containment, not exact membership: `WriteZone::contains` makes a
            // baseline that allows `target` cover a grant requesting `out-dir` (a compile
            // unit's `target` already spans its `OUT_DIR`). Exact membership rejected that,
            // leaving the grant unreviewed during `--accept-baseline` and the residual larger
            // than the baseline actually vouched for.
            && write_zones
                .iter()
                .all(|z| self.write_zones.iter().any(|allowed| allowed.contains(*z)))
            && write_paths.iter().all(|p| self.write_paths.contains(p))
            && env_allow.iter().all(|n| {
                self.env_allow
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(n))
            })
            && net_destinations
                .iter()
                .all(|d| self.net_destinations.contains(d))
    }
}

/// The document a policy's grants were accepted against.
///
/// Written into `buildclamp.toml` by `init --accept-baseline`, and it is the reviewer of
/// record for every grant in that file carrying `reviewed = true` with an acceptance note
/// in its `why`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct BaselineRef {
    /// `sha256:<hex>` of the document's bytes, exactly as they were read.
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    /// The day the acceptance was made.
    pub accepted: String,
}

/// What an acceptance did, for the line `init` prints and the number the plan asks to be
/// published.
#[derive(Clone, Debug, Default)]
pub struct Acceptance {
    /// Grants marked reviewed, as `name version`.
    pub accepted: Vec<String>,
    /// Grants left unreviewed, as `name version`. **This is the number that matters**: a
    /// baseline that accepts everything is one nobody checked, and a baseline that
    /// accepts nothing has not been measured against a real graph.
    pub residual: Vec<String>,
}

impl Acceptance {
    pub fn total(&self) -> usize {
        self.accepted.len() + self.residual.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            name: "libc".into(),
            version: "0.2.176".into(),
            capabilities: vec![Capability::FsWrite, Capability::Exec],
            write_zones: vec![WriteZone::OutDir, WriteZone::Tmp],
            write_paths: Vec::new(),
            env_allow: Vec::new(),
            net_destinations: Vec::new(),
            why: "probes the target with a compiler and writes cfg flags to OUT_DIR".into(),
        }
    }

    #[test]
    fn a_grant_inside_the_entry_is_covered_and_one_outside_it_is_not() {
        let e = entry();
        assert!(e.covers(
            &[Capability::FsWrite, Capability::Exec],
            &[WriteZone::OutDir, WriteZone::Tmp],
            &[],
            &[],
            &[]
        ));
        // Less than the entry describes is still inside it.
        assert!(e.covers(&[Capability::FsWrite], &[WriteZone::OutDir], &[], &[], &[]));
        // One capability more is not, however much else matches.
        assert!(!e.covers(
            &[Capability::FsWrite, Capability::Exec, Capability::Net],
            &[WriteZone::OutDir],
            &[],
            &[],
            &[]
        ));
        // Nor one zone more.
        assert!(!e.covers(
            &[Capability::FsWrite],
            &[WriteZone::OutDir, WriteZone::ManifestDir],
            &[],
            &[],
            &[]
        ));
        // Nor a destination the entry never mentioned.
        assert!(!e.covers(
            &[Capability::Net],
            &[],
            &[],
            &[],
            &["example.com:443".into()]
        ));
    }

    #[test]
    fn a_version_requirement_in_a_baseline_is_refused() {
        let e = Baseline::parse(
            "version = 1\n[[crate]]\nname = \"libc\"\nversion = \">=0.2, <0.3\"\nwhy = \"x\"\n",
        )
        .expect_err("a range vouches for versions nobody read");
        assert!(matches!(e, BaselineError::NotExact { .. }), "{e}");
    }

    #[test]
    fn an_entry_without_a_reason_is_refused() {
        let e = Baseline::parse(
            "version = 1\n[[crate]]\nname = \"libc\"\nversion = \"0.2.176\"\nwhy = \" \"\n",
        )
        .expect_err("the why becomes the grant's why");
        assert!(matches!(e, BaselineError::MissingWhy { .. }), "{e}");
    }

    #[test]
    fn a_lookup_matches_the_exact_release_and_nothing_else() {
        let b = Baseline::parse(
            "version = 1\n[[crate]]\nname = \"libc\"\nversion = \"1.0.0\"\nwhy = \"x\"\n",
        )
        .unwrap();
        assert!(b.entry("libc", "1.0.0").is_some());
        assert!(
            b.entry("libc", "1.0.1").is_none(),
            "a patch bump is a new release"
        );
        assert!(b.entry("other", "1.0.0").is_none());
        // A version that is not a version matches nothing, which is the fail-closed
        // direction: the grant stays unreviewed and somebody reads the build script.
        assert!(b.entry("libc", "1.0").is_none());
        assert!(b.entry("libc", "").is_none());
    }

    #[test]
    fn a_baseline_from_a_newer_buildclamp_is_refused_by_version() {
        let e = Baseline::parse("version = 99\ncolour = \"blue\"\n")
            .expect_err("a future document is refused on its version");
        match e {
            BaselineError::Version { found } => assert_eq!(found, 99),
            other => panic!("the refusal must name the version, not a field: {other}"),
        }
    }
}
