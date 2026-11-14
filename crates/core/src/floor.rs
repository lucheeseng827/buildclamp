//! An enforcement floor a CI lane declares, so a misconfigured lane fails as one.
//!
//! # The failure this exists for
//!
//! `--require-enforced` is checked at the end of a build, against what actually happened.
//! That is the right place for it and it is too late for one job: telling a lane that
//! *cannot* enforce from a lane whose build genuinely found something. Both come back as
//! exit 2, twenty minutes in, and the pipeline that green-lights on "no findings" has
//! already spent its time.
//!
//! Worse is the case where nothing fails at all. A container image change that takes
//! `CAP_SYS_ADMIN` away, an Ubuntu host with
//! `kernel.apparmor_restrict_unprivileged_userns=1`, a runner whose seccomp profile
//! denies `unshare` — each turns an enforcing lane into an advisory one, and the build
//! stays green because advisory enforcement still runs the build. Nobody is told that the
//! control stopped controlling. That is the same shape as the incumbent this project is
//! measured against: a notice printed, and the build continuing unsandboxed.
//!
//! So a lane states its floor — `doctor --require net=enforced,fs-write=enforced` — and
//! the statement is checked in seconds, before a test runs, against what the host reports
//! it can do.

use std::collections::BTreeMap;
use std::fmt;

use crate::capability::Capability;
use crate::report::Tier;
use crate::wire::Forward;

/// How strongly a capability is held, ordered from weakest to strongest.
///
/// The ordering is the type's whole job: a floor is a comparison, and `Advisory` has to
/// sit strictly between "nothing" and "the kernel refuses it" or a lane asking for
/// advisory enforcement would accept none.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Grade {
    /// Nothing held it, or a grade this build cannot evaluate.
    None,
    /// Observed and answered, but not atomically with the operation.
    Advisory,
    /// The kernel refuses it.
    Enforced,
}

impl Grade {
    pub fn as_str(self) -> &'static str {
        match self {
            Grade::None => "none",
            Grade::Advisory => "advisory",
            Grade::Enforced => "enforced",
        }
    }

    /// The grade a tier achieved.
    ///
    /// [`Tier::Unrecognised`] grades as `None`, and the direction is not a detail: a
    /// reader that treated a grade it could not evaluate as enforcement would pass a floor
    /// on the strength of a word it did not understand.
    pub fn of(tier: &Tier) -> Grade {
        match tier {
            Tier::Enforced { .. } => Grade::Enforced,
            Tier::Advisory { .. } => Grade::Advisory,
            Tier::None { .. } | Tier::Unrecognised { .. } => Grade::None,
        }
    }
}

impl fmt::Display for Grade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Grade {
    type Err = FloorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Grade::None),
            "advisory" => Ok(Grade::Advisory),
            "enforced" => Ok(Grade::Enforced),
            other => Err(FloorError::UnknownGrade(other.to_string())),
        }
    }
}

/// The minimum grade a lane requires, per capability.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Floor(BTreeMap<Capability, Grade>);

/// One requirement this host does not meet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unmet {
    pub capability: Capability,
    pub required: Grade,
    pub achieved: Grade,
    /// The tier's own label, so the message names the mechanism and not only the grade.
    pub tier: String,
}

#[derive(Debug, thiserror::Error)]
pub enum FloorError {
    #[error(
        "`{0}` is not a capability a floor can name — buildclamp can enforce net, unix, \
         fs-write, fs-read and env-secret, or take a bare `enforced` / `advisory` to mean \
         all of them. `exec` is understood but observe-only, so it is not one a floor may \
         require."
    )]
    UnknownCapability(String),

    #[error("`{0}` is not an enforcement grade — write `enforced`, `advisory` or `none`")]
    UnknownGrade(String),

    #[error(
        "`{0}` is not a requirement. Write `<capability>=<grade>`, for example \
         `net=enforced`, or a bare grade to mean every capability"
    )]
    Malformed(String),

    #[error(
        "`{capability}` is required twice, as `{first}` and as `{second}`. A lane whose \
         floor contradicts itself has no floor, and picking one silently would make which \
         is honoured depend on the order they were typed in"
    )]
    Duplicate {
        capability: Capability,
        first: Grade,
        second: Grade,
    },

    #[error(
        "`{0}` is observe-only: buildclamp records it and never refuses it on any host, so \
         it cannot be part of an enforcement floor — a lane requiring it enforced would \
         fail everywhere, forever. Drop it from --require; a bare grade already skips it."
    )]
    ObserveOnly(Capability),
}

impl Floor {
    /// Parse a comma-separated floor.
    ///
    /// `net=enforced,fs-write=advisory` names two capabilities. A bare grade —
    /// `enforced` — applies to every capability, which is the common case and the one a
    /// lane should be able to write without listing five names.
    pub fn parse(s: &str) -> Result<Self, FloorError> {
        let mut out: BTreeMap<Capability, Grade> = BTreeMap::new();
        for piece in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match piece.split_once('=') {
                Some((cap, grade)) => {
                    let cap: Capability = cap
                        .trim()
                        .parse()
                        .map_err(|_| FloorError::UnknownCapability(cap.trim().to_string()))?;
                    if cap.is_observe_only() {
                        return Err(FloorError::ObserveOnly(cap));
                    }
                    let grade: Grade = grade.trim().parse()?;
                    // Duplicates are refused rather than resolved. A floor is a promise
                    // about the lane, and a promise that depends on argument order is not
                    // one; this is the same rule the policy applies to two grants matching
                    // one version.
                    if let Some(first) = out.insert(cap, grade) {
                        if first != grade {
                            return Err(FloorError::Duplicate {
                                capability: cap,
                                first,
                                second: grade,
                            });
                        }
                    }
                }
                None => {
                    let grade: Grade = piece.parse().map_err(|_| {
                        // A bare word that is neither a grade nor `cap=grade` is more
                        // likely a typo'd capability than a typo'd grade, so the message
                        // names both possibilities rather than guessing.
                        FloorError::Malformed(piece.to_string())
                    })?;
                    // Every capability buildclamp can actually refuse. Observe-only ones
                    // (exec) are skipped, because a bare `enforced` floor that demanded exec
                    // be enforced would be unsatisfiable on every host.
                    for cap in Capability::ALL.into_iter().filter(|c| !c.is_observe_only()) {
                        // The same contradiction rule as the explicit arm above, and for the
                        // same reason: `net=advisory,enforced` and `net=enforced,none` must
                        // not silently overwrite or downgrade the named grade. A floor whose
                        // meaning depends on the order its pieces were written is not a floor.
                        if let Some(first) = out.insert(cap, grade) {
                            if first != grade {
                                return Err(FloorError::Duplicate {
                                    capability: cap,
                                    first,
                                    second: grade,
                                });
                            }
                        }
                    }
                }
            }
        }
        Ok(Self(out))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Capability, Grade)> + '_ {
        self.0.iter().map(|(c, g)| (*c, *g))
    }

    /// Which requirements the given tiers fail to meet.
    ///
    /// A capability the tiers do not mention at all counts as [`Grade::None`], not as
    /// "not applicable". A lane that required `net=enforced` and got a tier map with no
    /// `net` in it has not been told anything reassuring — and a missing tier is exactly
    /// the defect `unix` had.
    pub fn unmet(&self, tiers: &BTreeMap<Forward<Capability>, Tier>) -> Vec<Unmet> {
        let mut out = Vec::new();
        for (capability, required) in self.iter() {
            let tier = tiers.get(&Forward::Known(capability));
            let achieved = tier.map_or(Grade::None, Grade::of);
            if achieved < required {
                out.push(Unmet {
                    capability,
                    required,
                    achieved,
                    tier: tier.map_or_else(|| "absent".to_string(), Tier::label),
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiers(pairs: &[(Capability, Tier)]) -> BTreeMap<Forward<Capability>, Tier> {
        pairs
            .iter()
            .map(|(c, t)| (Forward::Known(*c), t.clone()))
            .collect()
    }

    fn enforced(m: &str) -> Tier {
        Tier::Enforced {
            mechanism: m.to_string(),
        }
    }

    fn advisory() -> Tier {
        Tier::Advisory {
            mechanism: "seccomp-notify".into(),
            limitation: "the kernel re-reads the path after we answer".into(),
        }
    }

    #[test]
    fn a_bare_grade_means_every_capability_buildclamp_can_refuse() {
        let f = Floor::parse("enforced").unwrap();
        // Every capability except the observe-only ones, which cannot be enforced anywhere.
        let refusable = Capability::ALL
            .iter()
            .filter(|c| !c.is_observe_only())
            .count();
        assert_eq!(f.iter().count(), refusable);
        assert!(f.iter().all(|(_, g)| g == Grade::Enforced));
        assert!(
            f.iter().all(|(c, _)| !c.is_observe_only()),
            "a bare floor must not require an observe-only capability"
        );
    }

    #[test]
    fn an_observe_only_capability_cannot_be_named_in_a_floor() {
        // Requiring exec enforced would fail on every host forever — that is a floor that
        // is unsatisfiable rather than a host that fell short, and the two must not look
        // the same. Refused at parse time, by name.
        let err = Floor::parse("exec=enforced").expect_err("exec cannot be required");
        assert!(
            matches!(err, FloorError::ObserveOnly(Capability::Exec)),
            "{err}"
        );
        // Even asking for it advisory is refused: a floor is about enforcement, and exec
        // offers none, so it has no place in one whatever grade is named.
        assert!(matches!(
            Floor::parse("exec=advisory"),
            Err(FloorError::ObserveOnly(_))
        ));
    }

    #[test]
    fn a_per_capability_floor_names_only_what_it_names() {
        let f = Floor::parse("net=enforced, fs-write=advisory").unwrap();
        let got: Vec<(Capability, Grade)> = f.iter().collect();
        assert_eq!(
            got,
            vec![
                (Capability::Net, Grade::Enforced),
                (Capability::FsWrite, Grade::Advisory),
            ]
        );
    }

    #[test]
    fn advisory_sits_strictly_between_none_and_enforced() {
        // The ordering is the type's whole job. If `Advisory` ever compared equal to
        // `None`, a lane asking for advisory enforcement would accept a host that enforced
        // nothing at all.
        assert!(Grade::None < Grade::Advisory);
        assert!(Grade::Advisory < Grade::Enforced);

        let f = Floor::parse("fs-write=advisory").unwrap();
        assert!(f
            .unmet(&tiers(&[(Capability::FsWrite, advisory())]))
            .is_empty());
        assert_eq!(
            f.unmet(&tiers(&[(
                Capability::FsWrite,
                Tier::None {
                    reason: "landlock: ENOSYS".into()
                }
            )]))
            .len(),
            1
        );
    }

    #[test]
    fn an_unmet_requirement_names_the_mechanism_and_not_only_the_grade() {
        // Whoever reads this is deciding whether to change the runner or the floor, and
        // "advisory" alone does not tell them which mechanism went missing.
        let f = Floor::parse("fs-write=enforced").unwrap();
        let unmet = f.unmet(&tiers(&[(Capability::FsWrite, advisory())]));
        assert_eq!(unmet.len(), 1);
        assert_eq!(unmet[0].capability, Capability::FsWrite);
        assert_eq!(unmet[0].required, Grade::Enforced);
        assert_eq!(unmet[0].achieved, Grade::Advisory);
        assert_eq!(unmet[0].tier, "advisory:seccomp-notify");
    }

    #[test]
    fn a_capability_with_no_tier_at_all_fails_a_floor_rather_than_being_skipped() {
        // `unix` shipped for months with no tier on any enforcing run, and a floor that
        // read an absent tier as "not applicable" would have reported that host as
        // meeting a floor it was never measured against.
        let f = Floor::parse("unix=enforced").unwrap();
        let unmet = f.unmet(&tiers(&[(Capability::Net, enforced("netns"))]));
        assert_eq!(unmet.len(), 1);
        assert_eq!(unmet[0].achieved, Grade::None);
        assert_eq!(unmet[0].tier, "absent");
    }

    #[test]
    fn a_tier_grade_this_build_cannot_evaluate_never_satisfies_a_floor() {
        let f = Floor::parse("net=advisory").unwrap();
        let unmet = f.unmet(&tiers(&[(
            Capability::Net,
            Tier::Unrecognised {
                grade: "partial".into(),
            },
        )]));
        assert_eq!(unmet.len(), 1, "an unknown grade must not pass a floor");
        assert_eq!(unmet[0].tier, "unrecognised:partial");
    }

    #[test]
    fn a_floor_that_contradicts_itself_is_refused() {
        let err = Floor::parse("net=enforced,net=none").unwrap_err();
        assert!(matches!(err, FloorError::Duplicate { .. }), "{err}");
        // Saying the same thing twice is not a contradiction and is allowed.
        assert!(Floor::parse("net=enforced,net=enforced").is_ok());
    }

    #[test]
    fn a_bare_grade_contradicting_a_named_one_is_refused_in_either_order() {
        // The bare-grade arm applies the same contradiction rule as the explicit arm, so a
        // floor's meaning cannot depend on the order its pieces were written in. Before this,
        // `net=advisory,enforced` silently overwrote `net`, and `net=enforced,none` silently
        // downgraded it — a weaker floor than the lane asked for, with nothing said.
        for floor in [
            "net=advisory,enforced",
            "enforced,net=advisory",
            "net=enforced,none",
            "none,net=enforced",
        ] {
            assert!(
                matches!(Floor::parse(floor), Err(FloorError::Duplicate { .. })),
                "`{floor}` should be a contradiction"
            );
        }
        // A bare grade that agrees with the named one is not a contradiction.
        assert!(Floor::parse("net=enforced,enforced").is_ok());
        assert!(Floor::parse("enforced,net=enforced").is_ok());
    }

    #[test]
    fn a_typo_is_named_rather_than_ignored() {
        // Ignoring an unparseable requirement would give the lane a weaker floor than it
        // asked for, silently — which is the failure the whole flag exists to prevent.
        assert!(matches!(
            Floor::parse("network=enforced").unwrap_err(),
            FloorError::UnknownCapability(_)
        ));
        assert!(matches!(
            Floor::parse("net=strict").unwrap_err(),
            FloorError::UnknownGrade(_)
        ));
        assert!(matches!(
            Floor::parse("net").unwrap_err(),
            FloorError::Malformed(_)
        ));
    }

    #[test]
    fn an_empty_floor_requires_nothing() {
        let f = Floor::parse("").unwrap();
        assert!(f.is_empty());
        assert!(f.unmet(&tiers(&[])).is_empty());
    }
}
