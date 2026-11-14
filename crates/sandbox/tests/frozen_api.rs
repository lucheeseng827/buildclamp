//! The frozen surface of `buildclamp-sandbox`, pinned by the compiler.
//!
//! # Why a test and not a promise in a README
//!
//! This crate is meant to be cut out and published on its own: "run this command under a
//! capability envelope and tell me which tier held it" is useful to anyone building a
//! CI runner, a package manager or a plugin host, and none of them want a cargo
//! subcommand. A crate nobody can depend on without the surface moving under them is not
//! one anybody will, so the surface is frozen before the cut rather than after the first
//! complaint.
//!
//! A sentence in a document does not survive a refactor. This does: every item below is
//! *used* at its exact type, so removing one, renaming it, changing an argument, or
//! changing what it returns fails to compile. The message it fails with names the item.
//!
//! # What is frozen, and what is not
//!
//! Frozen: [`Plan`] and its fields, [`Plan::hold`], [`Held`] and its fields, [`HoldError`]
//! and its variants, [`projected_tiers`], and [`probe::host`]. That is the whole arrow the
//! crate exists for — describe an envelope, run a command inside it, find out which tier
//! held each capability — and it is deliberately small.
//!
//! Not frozen, and said so where it lives: `bpf` and `bpfcheck`. They are published
//! because a reviewer who does not trust us should be able to read and execute the filter
//! rather than take its behaviour on faith, and because the fuzz targets are a separate
//! crate. A syscall added to the tables changes `bpf`'s surface, and freezing it would
//! make the filter harder to correct — which is the wrong trade for the part of the crate
//! most likely to need correcting.
//!
//! # Additions
//!
//! A compiler cannot see a *new* public item, so this file cannot catch one. `api.rs` is
//! the other half: it snapshots the declared surface and fails when it changes in either
//! direction.
//!
//! # The compatibility suite
//!
//! `docs/MATRIX.md` is what "compatible" means here. A frozen signature says the calls
//! still typecheck; the matrix says what they still *do* on a given host, which is the
//! half a type system cannot express and the half that decides whether a green build
//! means anything. A consumer regenerates it with `ops/matrix-row.sh`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use buildclamp_core::{Capability, Forward, HostCapabilities, Request, Tier, UnitId};
use buildclamp_sandbox::{probe, Held, HoldError, Plan};

/// Free functions, pinned as function pointers.
///
/// A function-pointer coercion checks the **whole** signature: a changed argument type, a
/// changed return type, or an added parameter all fail here, where a call with inferred
/// types would silently keep compiling.
const _PROJECTED_TIERS: fn(&HostCapabilities) -> BTreeMap<Forward<Capability>, Tier> =
    buildclamp_sandbox::projected_tiers;
const _HOST: fn() -> HostCapabilities = probe::host;
const _HOLD: fn(&Plan, Command) -> Result<Held, HoldError> = Plan::hold;

#[test]
fn plan_carries_exactly_these_fields_at_exactly_these_types() {
    // Constructed field by field with NO `..Default::default()`, which is the point: a
    // struct-literal without it is exhaustive, so an added field fails to compile here
    // and a removed one does too. With the shorthand, both would pass.
    let plan = Plan {
        allow_net: false,
        allow_unix: false,
        writable: Vec::<PathBuf>::new(),
        withheld_reads: Vec::<PathBuf>::new(),
        private_tmp: None::<PathBuf>,
        env: Vec::<(OsString, OsString)>::new(),
        observe_writes: false,
        observe_only: false,
        proc_macro_objects: Vec::<(PathBuf, UnitId)>::new(),
        skip_exec_target: None::<PathBuf>,
    };

    // `Default` is part of the surface: a consumer writing `Plan { allow_net: true,
    // ..Default::default() }` is the ordinary case, and losing the impl would break every
    // one of them without changing a single signature.
    let from_default = Plan::default();
    assert!(!from_default.allow_net);
    assert!(!from_default.observe_only);
    assert!(from_default.writable.is_empty());

    // And `Clone` and `Debug`, which cost nothing to keep and break callers to remove.
    let cloned: Plan = plan.clone();
    let _: String = format!("{cloned:?}");
}

#[test]
fn held_carries_exactly_these_fields_at_exactly_these_types() {
    let held = Held {
        tiers: BTreeMap::<Forward<Capability>, Tier>::new(),
        requests: Vec::<Request>::new(),
        exit_code: None::<i32>,
        signal: None::<i32>,
        duration_ms: 0u64,
    };
    let cloned: Held = held.clone();
    let _: String = format!("{cloned:?}");
    assert!(cloned.tiers.is_empty());
}

#[test]
fn hold_error_has_exactly_these_variants() {
    // An exhaustive match with no wildcard arm: adding a variant fails to compile here,
    // which is the point. A consumer matching on this enum is doing the same thing, and a
    // new variant is a breaking change however harmless it looks from inside.
    let errors = [
        HoldError::NothingAvailable("no mechanism".into()),
        HoldError::Setup("mount failed".into()),
        HoldError::Spawn(std::io::Error::other("no such file")),
        HoldError::UnsupportedPlatform("macos".into()),
    ];
    for e in &errors {
        let described = match e {
            HoldError::NothingAvailable(what) => what.clone(),
            HoldError::Setup(what) => what.clone(),
            HoldError::Spawn(source) => source.to_string(),
            HoldError::UnsupportedPlatform(os) => os.clone(),
        };
        assert!(!described.is_empty());
        // `std::error::Error` and `Display`, which is how every caller reports one.
        let _: &dyn std::error::Error = e;
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn the_crate_refuses_rather_than_running_unheld_on_a_host_it_cannot_hold() {
    // Not a signature — a promise. Every `HoldError` variant is a refusal to run rather
    // than a reason to run unheld, and a consumer depending on that is depending on the
    // one thing this crate is for. A future variant meaning "ran it anyway" would pass
    // the exhaustive match above and break this.
    //
    // Asserted through the non-Linux stub's own words, which is the only branch reachable
    // from a test on any host: it names the platform and says it will not run unheld.
    let e = HoldError::UnsupportedPlatform("some-os".into());
    let text = e.to_string();
    assert!(text.contains("some-os"), "{text}");
    assert!(
        text.contains("not something buildclamp will do"),
        "the refusal must say it will not run unheld: {text}"
    );

    let e = HoldError::NothingAvailable("no user namespaces, no seccomp".into());
    assert!(
        e.to_string().contains("Refusing to run"),
        "{}",
        e.to_string()
    );
}

#[test]
fn projected_tiers_answers_for_a_host_with_nothing() {
    // The shape a consumer builds a gate on: every capability present, and the ones that
    // cannot be held saying `none` with a reason rather than being absent. A map that
    // omitted them would read as "no requirement" to anything checking a floor.
    let nothing = HostCapabilities {
        os: "linux".into(),
        kernel: "0.0".into(),
        arch: "x86_64".into(),
        landlock_abi: None,
        user_namespaces: false,
        seccomp_user_notif: false,
        proc_hidepid: false,
    };
    let tiers = buildclamp_sandbox::projected_tiers(&nothing);
    if cfg!(target_os = "linux") {
        for c in Capability::ALL {
            let tier = tiers
                .get(&Forward::Known(c))
                .unwrap_or_else(|| panic!("`{}` has no tier on a host with nothing", c.as_str()));
            assert!(
                !tier.is_enforced(),
                "`{}` claims enforcement on a host with no mechanism: {tier:?}",
                c.as_str()
            );
        }
    } else {
        // Off Linux the projection is empty, and `Floor::unmet` reads a missing tier as
        // `none` — so every requirement fails, which is the correct answer for a platform
        // with no enforcement.
        assert!(tiers.is_empty());
    }
}
