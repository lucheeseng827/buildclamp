//! Break-glass: the unblock path that does not need a security person.
//!
//! # The failure this exists for
//!
//! A transitive dependency bump adds a capability. The build goes red at 17:00. Whoever
//! is standing there has three options: understand and approve a third-party build
//! script's new behaviour under time pressure, find somebody who can, or uninstall the
//! tool. Every gate that offers only the first two gets the third, and the tool is gone
//! inside two sprints — usually with a plugin routing around it, which is worse than
//! never having had it.
//!
//! So there is an unblock path, it is in the free tool, and it works with no account, no
//! network and no server. What it is not is quiet: every use is a block in a file that
//! shows up in a diff, carries a name, carries a reason, and stops working by itself.
//!
//! # The two instruments, and why they are two
//!
//! **An exception** ([`Exception`]) names a crate and says the build does not fail on it
//! until a date. It covers both halves of a red build — an ungranted request and an
//! unreviewed grant — because at 17:00 nobody should have to work out which of two
//! mechanisms their failure needs.
//!
//! **Grace** ([`Grace`]) is not about a crate at all. It says that a grant *first seen*
//! within the last N days warns instead of failing `--strict`, so the ordinary flow —
//! bump, red build, `cargo buildclamp init`, commit, file a ticket — is not blocked on
//! the review happening the same afternoon. It has no effect on a grant that was already
//! there, which is the property that stops it becoming a way to never review anything:
//! `--grace 30` on a year-old unreviewed policy excuses nothing.
//!
//! Both are bounded, and the bounds are the design:
//!
//! | | exception | grace |
//! |---|---|---|
//! | bound | [`MAX_EXCEPTION_DAYS`] days, refused above it | the run's own `--grace N` |
//! | how many | [`DEFAULT_ACTIVE_EXCEPTION_CAP`], configurable, refused above it | n/a |
//! | names a person | yes, mandatory | no |
//! | covers | one crate | any grant younger than N days |
//! | silent | never — the summary says so on every run | never |
//!
//! # What is deliberately absent
//!
//! There is no exception that never expires, and no `crate = "*"`. Both exist already
//! under a name that says what they are: `enforcement = "disabled"` at the top of the
//! policy, or `BUILDCLAMP_DISABLE` in the environment, each recorded in the report's
//! `disable_overrides`. An escape hatch that can be spelled two ways, one of which reads
//! like a narrow exception and behaves like an off switch, is how a control ends up
//! disabled in a repository where everyone believes it is on.
//!
//! There is also nothing here that tooling outside this repository can take away.
//! Centralised *visibility* of who is breaking glass, and the ability to shorten or
//! forbid it org-wide, may live elsewhere. The ability to unblock at all may not: a tool
//! that can block and cannot unblock is one that gets unhooked.

use serde::{Deserialize, Serialize};

use crate::capability::Capability;
use crate::civil::Date;
use crate::wire::Forward;

/// The longest an exception may run, in days from the day the run happens.
///
/// Seven, and the number is doing work. It is long enough to cover a weekend and a
/// Monday morning triage, which is the actual span of the incident this serves, and
/// short enough that nobody can treat an exception as a decision. It is checked against
/// **today**, not against the day the block was written, so an exception cannot be
/// backdated into a long one and cannot quietly outlive its week by being committed
/// early.
pub const MAX_EXCEPTION_DAYS: i64 = 7;

/// How many exceptions may be live at once before the policy is refused.
///
/// Three, configurable with `max-active-exceptions` in `[defaults]`. An incident is one
/// or two crates; a repository holding ten live exceptions does not have an incident, it
/// has a policy that no longer describes its build, and the right answer there is to fix
/// the policy rather than to add an eleventh block. The cap is raisable in the same edit
/// that hits it — the error names the key — so nobody is ever trapped at 17:00 by a
/// number this file chose.
pub const DEFAULT_ACTIVE_EXCEPTION_CAP: usize = 3;

/// One `[[exception]]` block.
///
/// ```toml
/// [[exception]]
/// crate = "openssl-sys"
/// capabilities = ["net"]
/// expires = "2026-09-20"
/// reason = "vendored build fetches its own source; INFRA-4412 tracks pinning it"
/// author = "ada@example.com"
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Exception {
    /// The crate this covers. One name, never a pattern — see the module docs.
    #[serde(rename = "crate")]
    pub crate_name: String,

    /// Narrow it to specific capabilities. Empty means every capability that crate asks
    /// for, which is the honest default for the case this serves: at 17:00 the person
    /// unblocking knows which crate broke, and often does not yet know which of its
    /// requests did.
    #[serde(default)]
    pub capabilities: Vec<Capability>,

    /// The day this stops applying, `YYYY-MM-DD`. Mandatory.
    ///
    /// # Why this is an `Option` when it is mandatory
    ///
    /// So that leaving it out produces *this* file's error rather than serde's. A
    /// missing `expires` is the one omission that reads, to somebody skimming the block,
    /// like a deliberate "no expiry" — and a permanent exception is precisely what this
    /// format must make unwritable. The error says that, in those words. The other two
    /// mandatory fields are plain `String`s and lean on serde for absence, because a
    /// block with no `reason` at all does not read like anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// Why the glass was broken. Required, non-empty.
    ///
    /// Not "what the crate does" — the `why` on a grant is for that. This is what
    /// happened that made refusing unacceptable today, and it is what the person reading
    /// the ticket in a week needs.
    pub reason: String,

    /// Who broke the glass. Required, non-empty, and written from the checkout's git
    /// identity by `cargo buildclamp except`.
    ///
    /// **It is self-asserted and this file does not pretend otherwise.** `git config
    /// user.email` is whatever the person set it to, so the name here is a courtesy, not
    /// an attestation. What actually makes an exception accountable is that it is a block
    /// in a committed file: the commit that added it has an author the forge verified, it
    /// appeared in a diff somebody could have reviewed, and it stops working by itself.
    /// The field exists so that the common case — reading the policy, not the history —
    /// answers "who?" without a `git blame`.
    pub author: String,
}

impl Exception {
    /// The parsed expiry, or `None` if it is absent or unparseable.
    ///
    /// Both of those are refused by [`crate::Policy::parse`] before any run reaches this,
    /// so a `None` here means a hand-constructed value rather than a policy from disk.
    pub fn expiry(&self) -> Option<Date> {
        Date::parse(self.expires.as_deref()?)
    }

    /// Does this block cover a request by `crate_name` for `capability`?
    ///
    /// Version is deliberately not part of the question. An exception exists because a
    /// version bump changed what a crate does, so scoping it to the version that broke
    /// would mean a second bump during the same week silently re-breaks the build — and
    /// the whole span is a week.
    pub fn covers(&self, crate_name: &str, capability: Capability) -> bool {
        self.crate_name == crate_name
            && (self.capabilities.is_empty() || self.capabilities.contains(&capability))
    }

    /// Does this block cover `crate_name` at all, whatever it asked for?
    pub fn names(&self, crate_name: &str) -> bool {
        self.crate_name == crate_name
    }

    /// [`Exception::covers`], for a capability as it appears in a report.
    ///
    /// A report can carry a capability name this build has never heard of — written by a
    /// newer buildclamp, read by this one, preserved rather than dropped. An exception
    /// that listed capabilities cannot be *shown* to cover such a request, so it does
    /// not; one that listed none says "whatever this crate asked for", and that includes
    /// a request whose name only a later version can spell.
    pub fn covers_forward(&self, crate_name: &str, capability: &Forward<Capability>) -> bool {
        match capability {
            Forward::Known(c) => self.covers(crate_name, *c),
            Forward::Unknown(_) => self.names(crate_name) && self.capabilities.is_empty(),
        }
    }
}

/// The exceptions in a policy, split by whether they still apply today.
///
/// Expired blocks are carried rather than dropped. A run whose build just went red
/// because an exception lapsed should be told that, by name and date — the alternative is
/// a failure that looks identical to the one the exception was written for, which is how
/// somebody ends up writing the same block twice.
#[derive(Clone, Debug, Default)]
pub struct BreakGlass {
    live: Vec<Exception>,
    expired: Vec<Exception>,
}

impl BreakGlass {
    /// No exceptions — what a policy with no `[[exception]]` block resolves to, and what
    /// every code path that does not have a date to compare against must use.
    pub fn none() -> Self {
        Self::default()
    }

    pub(crate) fn split(exceptions: &[Exception], today: Date) -> Self {
        let mut live = Vec::new();
        let mut expired = Vec::new();
        for e in exceptions {
            // An expiry of today is still live: "expires 2026-09-20" means the twentieth
            // is covered and the twenty-first is not. A reader writing a date expects the
            // day they wrote to work.
            match e.expiry() {
                Some(d) if d >= today => live.push(e.clone()),
                // Unparseable is treated as expired rather than live. It cannot happen
                // through `Policy::parse`, which refuses the file, and if it ever did the
                // safe reading of a date nobody can read is that it has passed.
                _ => expired.push(e.clone()),
            }
        }
        Self { live, expired }
    }

    /// The block covering this request, if one does.
    pub fn covering(&self, crate_name: &str, capability: Capability) -> Option<&Exception> {
        self.live.iter().find(|e| e.covers(crate_name, capability))
    }

    /// The block naming this crate at all, if one does. What excuses an unreviewed grant.
    pub fn naming(&self, crate_name: &str) -> Option<&Exception> {
        self.live.iter().find(|e| e.names(crate_name))
    }

    /// [`BreakGlass::covering`], for a capability as it appears in a report.
    pub fn covering_forward(
        &self,
        crate_name: &str,
        capability: &Forward<Capability>,
    ) -> Option<&Exception> {
        self.live
            .iter()
            .find(|e| e.covers_forward(crate_name, capability))
    }

    pub fn live(&self) -> &[Exception] {
        &self.live
    }

    pub fn expired(&self) -> &[Exception] {
        &self.expired
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty() && self.expired.is_empty()
    }
}

/// The `--grace <days>` window, and the day it is measured from.
#[derive(Clone, Copy, Debug)]
pub struct Grace {
    pub today: Date,
    pub days: i64,
}

impl Grace {
    /// Is a grant first seen on `first_seen` still inside the window?
    ///
    /// `None` — a grant with no `first-seen` — is **never** in grace. That is the rule
    /// the milestone's test names: grace must not suppress a grant that was already
    /// known, and a grant carrying no date is one this tool has no evidence is new. It is
    /// also the fail-closed direction, which is the one to pick when the evidence is
    /// missing rather than merely old.
    pub fn covers(&self, first_seen: Option<&str>) -> Option<i64> {
        let seen = Date::parse(first_seen?)?;
        let age = seen.days_until(self.today);
        // A `first-seen` in the future is not in grace either. It is a clock-skewed CI
        // host or a hand-edited date, and neither is evidence of newness.
        if (0..self.days).contains(&age) {
            Some(self.days - age)
        } else {
            None
        }
    }
}

/// What `--strict` found, split by what is excusing each grant.
#[derive(Clone, Debug, Default)]
pub struct Unreviewed {
    /// Grants that fail the run. Crate names, in policy order, one entry per grant.
    pub failing: Vec<String>,
    /// Grants a `--grace` window is currently excusing.
    pub in_grace: Vec<GraceNote>,
    /// Grants a live exception is currently excusing, with the crate and the expiry.
    pub excepted: Vec<(String, String)>,
}

impl Unreviewed {
    /// The count `--strict` gates on: excused grants are not in it.
    pub fn count(&self) -> usize {
        self.failing.len()
    }

    /// Anything at all still unreviewed, excused or not — what the summary reports, since
    /// an excused grant is still work somebody owes.
    pub fn total(&self) -> usize {
        self.failing.len() + self.in_grace.len() + self.excepted.len()
    }
}

/// One grant a grace window is excusing, and for how much longer.
#[derive(Clone, Debug)]
pub struct GraceNote {
    pub crate_name: String,
    pub first_seen: String,
    /// Days remaining, counting today. `1` means this is the last run it is excused on.
    pub days_left: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(name: &str, expires: &str, caps: &[Capability]) -> Exception {
        Exception {
            crate_name: name.into(),
            capabilities: caps.to_vec(),
            expires: Some(expires.into()),
            reason: "an incident".into(),
            author: "ada@example.com".into(),
        }
    }

    fn day(s: &str) -> Date {
        Date::parse(s).expect("test dates are well formed")
    }

    #[test]
    fn an_exception_is_live_on_the_day_it_names_and_not_the_day_after() {
        let e = [ex("openssl-sys", "2026-09-20", &[])];
        assert_eq!(BreakGlass::split(&e, day("2026-09-20")).live().len(), 1);
        assert_eq!(BreakGlass::split(&e, day("2026-09-21")).live().len(), 0);
        assert_eq!(BreakGlass::split(&e, day("2026-09-21")).expired().len(), 1);
    }

    #[test]
    fn an_expired_exception_covers_nothing() {
        let glass = BreakGlass::split(&[ex("openssl-sys", "2026-09-01", &[])], day("2026-09-15"));
        assert!(glass.covering("openssl-sys", Capability::Net).is_none());
        assert!(glass.naming("openssl-sys").is_none());
        // …and is still reported, so the run can say why it just went red.
        assert_eq!(glass.expired().len(), 1);
    }

    #[test]
    fn narrowing_to_capabilities_narrows_what_is_covered() {
        let glass = BreakGlass::split(
            &[ex("openssl-sys", "2026-09-20", &[Capability::Net])],
            day("2026-09-15"),
        );
        assert!(glass.covering("openssl-sys", Capability::Net).is_some());
        assert!(glass.covering("openssl-sys", Capability::FsWrite).is_none());
        // But naming the crate is what excuses an unreviewed grant, and that is not
        // per-capability: a grant is not a request.
        assert!(glass.naming("openssl-sys").is_some());
    }

    #[test]
    fn an_empty_capability_list_covers_every_capability() {
        let glass = BreakGlass::split(&[ex("openssl-sys", "2026-09-20", &[])], day("2026-09-15"));
        for c in Capability::ALL {
            assert!(glass.covering("openssl-sys", c).is_some(), "{c:?}");
        }
        assert!(glass
            .covering("some-other-crate", Capability::Net)
            .is_none());
    }

    #[test]
    fn grace_never_covers_a_grant_that_carries_no_date() {
        // The property the milestone names: grace must not suppress a grant that was
        // already known, and a grant with no `first-seen` is one nothing here can show is
        // new. A policy written before `first-seen` existed is entirely in this case.
        let g = Grace {
            today: day("2026-09-15"),
            days: 30,
        };
        assert_eq!(g.covers(None), None);
    }

    #[test]
    fn grace_covers_a_new_grant_and_stops_at_the_window() {
        let g = Grace {
            today: day("2026-09-15"),
            days: 7,
        };
        assert_eq!(g.covers(Some("2026-09-15")), Some(7)); // today
        assert_eq!(g.covers(Some("2026-09-09")), Some(1)); // six days old, last run
        assert_eq!(g.covers(Some("2026-09-08")), None); // seven days old, over
        assert_eq!(g.covers(Some("2026-01-01")), None); // long known
        assert_eq!(g.covers(Some("2026-09-16")), None); // skewed clock, not evidence
        assert_eq!(g.covers(Some("whenever")), None); // unparseable
    }

    #[test]
    fn a_zero_day_grace_window_excuses_nothing() {
        // `--grace 0` has to mean "no grace", including for a grant written today.
        let g = Grace {
            today: day("2026-09-15"),
            days: 0,
        };
        assert_eq!(g.covers(Some("2026-09-15")), None);
    }
}
