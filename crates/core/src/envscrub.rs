//! Deciding which environment names a build unit does not get to see.
//!
//! # The honest limit, stated first
//!
//! **There is no syscall for `getenv`.** A process's environment is copied into its
//! memory at `execve` and read from there, so nothing can observe a read. What this tool
//! controls is therefore **exposure**: whether the name is in the unit's environment at
//! all. Observe mode reports which credential-shaped names *were reachable*, never which
//! were read, and the documentation says so in those words.
//!
//! # The second limit, which is worse and was measured
//!
//! Removing a name from a build script's own environment does not remove it from the
//! environment of the cargo process that spawned it, or of the shell that spawned cargo.
//! With no `hidepid` on `/proc` — the default on stock Ubuntu 24.04 — any process of the
//! same user can read `/proc/<pid>/environ`. A fixture build script in this repository
//! reads **7,883 bytes** of its parent's environment and finds both planted credentials.
//!
//! So scrubbing is one of three layers, and only the third is complete:
//!
//! 1. the driver scrubs its **own** environment before executing cargo, which removes
//!    every process in the build tree from the exposure set;
//! 2. the unit's environment is scrubbed here;
//! 3. a **user namespace** puts every other process out of the unit's reach, which is
//!    the only one of the three that closes the hole rather than narrowing it: a child
//!    user namespace fails `ptrace_may_access` against the parent's, so
//!    `/proc/<pid>/environ` is `EPERM` before a byte is read. Measured against the
//!    obvious guess — `CLONE_NEWPID` alone leaves the read working. It is part of the
//!    namespace tier, and the report says whether it applied.
//!
//! A README that described (2) alone as protecting secrets would be wrong, and this
//! module's existence is not a licence to say otherwise.

use std::ffi::OsString;

use crate::envelope::Envelope;
use crate::policy::{env_name_matches, HARD_DENY};

/// The decision for one environment variable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EnvDecision {
    /// Passed through untouched.
    Keep,
    /// Removed before the unit starts.
    Scrub,
}

/// What to do with `name` for a unit holding `envelope`, under `deny_patterns`.
///
/// The order is deliberate and each step exists for a reason a test names:
///
/// 1. A name the unit's grant explicitly re-admits is kept — but a name in
///    [`HARD_DENY`] is only re-admitted when the grant also set `env_allow_secrets`,
///    which the policy parser has already checked.
/// 2. A name matching any deny pattern is scrubbed.
/// 3. With `env-allowlist` on, a name outside [`crate::policy::ENV_ALLOWLIST_BASE`] is
///    scrubbed even though no deny pattern named it. The two combine and the order is what
///    makes that safe: the deny-list has already run, so the allowlist can only take
///    further names away and never hand one back. `CARGO_*` is in the base set and
///    `CARGO_REGISTRY_TOKEN` starts with it — a base set consulted first would re-admit
///    exactly the credential the deny-list exists to remove.
/// 4. Everything else is kept. Build scripts need `PATH`, `HOME`, `CC`, `PKG_CONFIG_*`,
///    every `CARGO_*`, `RUSTC`, `TARGET`, `OUT_DIR` and `NUM_JOBS`, which is why the
///    allowlist is opt-in and ships with a base set rather than being the default.
pub fn decide(
    name: &str,
    envelope: &Envelope,
    deny_patterns: &[String],
    env_allow_secrets: bool,
) -> EnvDecision {
    let re_admitted = envelope
        .env_allow
        .iter()
        .any(|a| a.eq_ignore_ascii_case(name));

    if re_admitted {
        let is_hard = HARD_DENY.iter().any(|d| d.eq_ignore_ascii_case(name));
        if !is_hard || env_allow_secrets {
            return EnvDecision::Keep;
        }
        // A hard-denied name without the opt-in. The policy parser rejects this
        // combination, so reaching here means a caller built an envelope by hand; scrub
        // rather than trust it. A security decision that depends on an earlier
        // validation having run is a security decision waiting to be bypassed.
        return EnvDecision::Scrub;
    }

    if deny_patterns.iter().any(|p| env_name_matches(p, name)) {
        return EnvDecision::Scrub;
    }

    // The allowlist, AFTER the deny-list and never before it. See the numbered rule 3 in
    // this function's documentation: `CARGO_*` is in the base set and
    // `CARGO_REGISTRY_TOKEN` starts with it, so consulting the base set first would hand
    // back the credential the line above just removed.
    if envelope.env_allowlist
        && !crate::policy::ENV_ALLOWLIST_BASE
            .iter()
            .any(|p| env_name_matches(p, name))
    {
        return EnvDecision::Scrub;
    }

    EnvDecision::Keep
}

/// Apply [`decide`] across a whole environment, returning the names removed.
///
/// Names and values are `OsString`, so the caller reads `std::env::vars_os` rather than
/// `std::env::vars`. `vars` panics when any inherited name **or value** is not valid
/// Unicode, and since the compiler-child scrub runs once per rustc that would abort every
/// compile in a build over a single non-Unicode variable anywhere in the host environment.
/// Only the name is ever matched, and a name that is not Unicode cannot match a deny pattern
/// or an allowlist entry (both are `&str`). Under a **deny-list** that means it is not a
/// secret this policy can name, so it is kept verbatim rather than dropped — dropping it would
/// silently change the environment the child sees. Under an **allowlist** the rule is the
/// opposite: only names on the list survive, and a name that cannot be on the list must be
/// removed, or the allowlist would leak every non-Unicode variable straight to the child.
///
/// The returned removal list is **names only**. A removed non-Unicode name is reported by its
/// lossy form (it decoded to nothing, so there is no exact text to give); a removed decodable
/// name is exact. A report that carried the value of a scrubbed secret would write credentials
/// to disk in the course of protecting them, so values never appear here.
pub fn scrub<I, K, V>(
    env: I,
    envelope: &Envelope,
    deny_patterns: &[String],
    env_allow_secrets: bool,
) -> (Vec<(OsString, OsString)>, Vec<String>)
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<OsString>,
    V: Into<OsString>,
{
    let mut kept = Vec::new();
    let mut removed = Vec::new();
    for (k, v) in env {
        let key: OsString = k.into();
        let value: OsString = v.into();
        // Decode the name only to make the decision; the value is preserved verbatim. The
        // decision is computed as an owned value so `key` is no longer borrowed when the match
        // below moves it.
        let decision = match key.to_str() {
            Some(name) => decide(name, envelope, deny_patterns, env_allow_secrets),
            // A non-Unicode name cannot match a deny pattern or an allowlist entry. Keep it
            // under a deny-list (it is nothing this policy can name); scrub it under an
            // allowlist (it cannot be on the list, and "only listed names survive").
            None if envelope.env_allowlist => EnvDecision::Scrub,
            None => EnvDecision::Keep,
        };
        match decision {
            EnvDecision::Keep => kept.push((key, value)),
            // `to_string_lossy` is exact for a decodable name and best-effort for a
            // non-Unicode one; either way the removal list records that the name was scrubbed.
            EnvDecision::Scrub => removed.push(key.to_string_lossy().into_owned()),
        }
    }
    removed.sort();
    (kept, removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::DEFAULT_ENV_DENY;

    fn patterns() -> Vec<String> {
        DEFAULT_ENV_DENY.iter().map(|s| s.to_string()).collect()
    }

    /// The default envelope, with the allowlist switched on the way `resolve` would.
    fn allowlisted() -> Envelope {
        let mut e = Envelope::build_script_default();
        e.env_allowlist = true;
        e
    }

    #[test]
    fn the_allowlist_cannot_hand_back_what_the_deny_list_removed() {
        // The ordering bug this whole feature could have shipped with. `CARGO_*` is in the
        // base set and `CARGO_REGISTRY_TOKEN` starts with it, so an allowlist consulted
        // before the deny-list would re-admit the exact credential the deny-list exists to
        // remove — turning a feature sold as *stronger* into a hole.
        let e = allowlisted();
        for name in [
            "CARGO_REGISTRY_TOKEN",
            "CARGO_REGISTRIES_MYCORP_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
        ] {
            assert_eq!(
                decide(name, &e, &patterns(), false),
                EnvDecision::Scrub,
                "{name} must stay scrubbed under an allowlist"
            );
        }
    }

    #[test]
    fn an_ordinary_variable_survives_a_deny_list_and_does_not_survive_an_allowlist() {
        // The whole difference between the two models, in one assertion. A deny-list
        // cannot know about a credential variable nobody has thought of; an allowlist does
        // not have to, and that is why cargo-acl's allowlist is the stronger model.
        let deny_only = Envelope::build_script_default();
        let allow = allowlisted();
        for name in ["GITHUB_RUN_ID", "CI", "ACME_INTERNAL_ENDPOINT", "EDITOR"] {
            assert_eq!(
                decide(name, &deny_only, &patterns(), false),
                EnvDecision::Keep,
                "{name} is not credential-shaped, so a deny-list keeps it"
            );
            assert_eq!(
                decide(name, &allow, &patterns(), false),
                EnvDecision::Scrub,
                "{name} is not on the base list, so an allowlist removes it"
            );
        }
    }

    #[test]
    fn the_base_set_keeps_a_build_script_working_under_an_allowlist() {
        // The adoption question, and the reason the base set exists at all. Cargo talks to
        // a build script almost entirely through these; without them the script fails with
        // a missing-variable panic from inside a dependency, which nobody would connect to
        // this tool.
        let e = allowlisted();
        for name in [
            "PATH",
            "HOME",
            "OUT_DIR",
            "TARGET",
            "HOST",
            "NUM_JOBS",
            "OPT_LEVEL",
            "PROFILE",
            "RUSTC",
            "CARGO",
            "CARGO_MANIFEST_DIR",
            "CARGO_PKG_NAME",
            "CARGO_FEATURE_DEFAULT",
            "CARGO_CFG_TARGET_OS",
            "DEP_OPENSSL_INCLUDE",
            "TMPDIR",
            "LC_ALL",
            "BUILDCLAMP_POLICY",
        ] {
            assert_eq!(
                decide(name, &e, &patterns(), false),
                EnvDecision::Keep,
                "{name} must survive the allowlist or nothing builds"
            );
        }
    }

    #[test]
    fn a_grant_adds_to_the_base_set_rather_than_replacing_it() {
        // The escape hatch. A build script that genuinely needs `ACME_SDK_ROOT` names it,
        // and still gets PATH and OUT_DIR — an allowlist that made a grant replace the base
        // would mean every grant had to re-list eighteen cargo variables to work.
        let mut e = allowlisted();
        e.env_allow = vec!["ACME_SDK_ROOT".to_string()];
        assert_eq!(
            decide("ACME_SDK_ROOT", &e, &patterns(), false),
            EnvDecision::Keep
        );
        assert_eq!(decide("PATH", &e, &patterns(), false), EnvDecision::Keep);
        assert_eq!(
            decide("ACME_OTHER", &e, &patterns(), false),
            EnvDecision::Scrub
        );
    }

    #[test]
    fn a_hard_denied_name_still_needs_the_loud_opt_in_under_an_allowlist() {
        // The allowlist must not become a second, quieter way to re-admit a credential.
        let mut e = allowlisted();
        e.env_allow = vec!["AWS_SECRET_ACCESS_KEY".to_string()];
        assert_eq!(
            decide("AWS_SECRET_ACCESS_KEY", &e, &patterns(), false),
            EnvDecision::Scrub,
            "without env-allow-secrets it stays out"
        );
        assert_eq!(
            decide("AWS_SECRET_ACCESS_KEY", &e, &patterns(), true),
            EnvDecision::Keep,
            "with the loud opt-in it comes back, the same as under a deny-list"
        );
    }

    #[test]
    fn the_variables_every_build_script_needs_survive_the_default_patterns() {
        // The false-positive gate for the environment. Scrubbing any of these breaks
        // essentially every -sys crate in the ecosystem on the first run.
        let e = Envelope::build_script_default();
        for name in [
            "PATH",
            "HOME",
            "OUT_DIR",
            "TARGET",
            "HOST",
            "NUM_JOBS",
            "OPT_LEVEL",
            "PROFILE",
            "RUSTC",
            "CARGO",
            "CARGO_MANIFEST_DIR",
            "CARGO_PKG_NAME",
            "CARGO_CFG_TARGET_OS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CC",
            "CXX",
            "AR",
            "PKG_CONFIG_PATH",
            "PKG_CONFIG_SYSROOT_DIR",
            "OPENSSL_DIR",
            "LD_LIBRARY_PATH",
            "TMPDIR",
            "DEP_OPENSSL_INCLUDE",
        ] {
            assert_eq!(
                decide(name, &e, &patterns(), false),
                EnvDecision::Keep,
                "{name} must survive the default patterns"
            );
        }
    }

    #[test]
    fn the_credentials_the_incident_was_about_are_removed() {
        let e = Envelope::build_script_default();
        for name in [
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_ACCESS_KEY_ID",
            "CARGO_REGISTRY_TOKEN",
            "NPM_TOKEN",
            "MY_SERVICE_API_KEY",
            "DATABASE_PASSWORD",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "SSH_AUTH_SOCK",
            "ANTHROPIC_API_KEY",
        ] {
            assert_eq!(
                decide(name, &e, &patterns(), false),
                EnvDecision::Scrub,
                "{name} must be removed"
            );
        }
    }

    #[test]
    fn a_grant_can_re_admit_an_ordinary_name() {
        let mut e = Envelope::build_script_default();
        e.env_allow = vec!["MY_SERVICE_API_KEY".into()];
        assert_eq!(
            decide("MY_SERVICE_API_KEY", &e, &patterns(), false),
            EnvDecision::Keep
        );
    }

    #[test]
    fn re_admitting_a_hard_denied_name_needs_the_opt_in_even_here() {
        // Defence in depth: the policy parser already rejects this, and this layer does
        // not trust that it ran. A security decision that depends on an earlier
        // validation having happened is one waiting to be bypassed.
        let mut e = Envelope::build_script_default();
        e.env_allow = vec!["GITHUB_TOKEN".into()];
        assert_eq!(
            decide("GITHUB_TOKEN", &e, &patterns(), false),
            EnvDecision::Scrub
        );
        assert_eq!(
            decide("GITHUB_TOKEN", &e, &patterns(), true),
            EnvDecision::Keep
        );
    }

    #[test]
    fn scrubbing_reports_names_and_never_values() {
        let e = Envelope::build_script_default();
        let (kept, removed) = scrub(
            [
                ("PATH", "/usr/bin"),
                ("GITHUB_TOKEN", "ghp_supersecret"),
                ("OUT_DIR", "/t/out"),
            ],
            &e,
            &patterns(),
            false,
        );
        assert_eq!(removed, vec!["GITHUB_TOKEN".to_string()]);
        assert!(kept.iter().any(|(k, _)| k.to_str() == Some("PATH")));
        assert!(!kept.iter().any(|(k, _)| k.to_str() == Some("GITHUB_TOKEN")));
        // The removal list carries no values at all — there is nowhere to put one.
        assert!(!format!("{removed:?}").contains("ghp_"));
    }

    #[test]
    #[cfg(unix)]
    fn a_non_unicode_name_is_kept_and_a_non_unicode_value_is_preserved() {
        // `std::env::vars` panics on a name OR value that is not valid Unicode; reading
        // `vars_os` and matching only decodable names is what keeps a single such variable in
        // the host environment from aborting every compile in the build.
        use std::os::unix::ffi::OsStringExt;

        let e = Envelope::build_script_default();
        let bad_name = OsString::from_vec(vec![0xff, 0xfe]);
        let bad_value = OsString::from_vec(vec![0xff]);
        let (kept, removed) = scrub(
            vec![
                (bad_name.clone(), OsString::from("v")), // undecodable NAME
                (OsString::from("PATH"), bad_value.clone()), // undecodable VALUE
                (OsString::from("GITHUB_TOKEN"), OsString::from("ghp_x")), // a real secret
            ],
            &e,
            &patterns(),
            false,
        );

        // The secret is still removed; non-Unicode noise beside it weakened nothing.
        assert_eq!(removed, vec!["GITHUB_TOKEN".to_string()]);
        // The undecodable NAME is kept verbatim, not dropped: a name that cannot be matched
        // cannot be a secret this policy knows how to scrub, and dropping it would change the
        // child's environment.
        assert!(kept.iter().any(|(k, _)| k == &bad_name));
        // The undecodable VALUE on an otherwise-kept name survives untouched.
        let path_value = kept
            .iter()
            .find(|(k, _)| k.to_str() == Some("PATH"))
            .map(|(_, v)| v.clone());
        assert_eq!(path_value, Some(bad_value));
    }

    #[test]
    #[cfg(unix)]
    fn a_non_unicode_name_is_scrubbed_under_an_allowlist() {
        // Under an allowlist only listed names survive, and a non-Unicode name cannot be on
        // the list. Keeping it (the deny-list behaviour) would leak an arbitrary variable
        // past the allowlist straight to the child.
        use std::os::unix::ffi::OsStringExt;

        let e = allowlisted();
        let bad_name = OsString::from_vec(vec![0xff, 0xfe]);
        let (kept, removed) = scrub(
            vec![
                (bad_name.clone(), OsString::from("v")), // undecodable name, not on the list
                (OsString::from("PATH"), OsString::from("/usr/bin")), // a base name, allowed
            ],
            &e,
            &patterns(),
            false,
        );

        // The undecodable name did not survive the allowlist.
        assert!(
            !kept.iter().any(|(k, _)| k == &bad_name),
            "a non-Unicode name leaked past the allowlist"
        );
        assert!(removed.iter().any(|n| n.contains('\u{fffd}')));
        // The base name still passes, so the allowlist did not over-scrub.
        assert!(kept.iter().any(|(k, _)| k.to_str() == Some("PATH")));
    }

    #[test]
    fn a_replaced_deny_list_replaces_rather_than_extends() {
        // `defaults.env-deny` is documented as replacing the built-in list. A policy
        // author who narrows it must actually get the narrower behaviour, or the
        // documentation is a lie and their build still breaks.
        let e = Envelope::build_script_default();
        let only_aws = vec!["AWS_*".to_string()];
        assert_eq!(
            decide("AWS_SECRET_ACCESS_KEY", &e, &only_aws, false),
            EnvDecision::Scrub
        );
        assert_eq!(
            decide("GITHUB_TOKEN", &e, &only_aws, false),
            EnvDecision::Keep
        );
    }
}
