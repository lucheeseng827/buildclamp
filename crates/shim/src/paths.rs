//! Turning a unit's symbolic write zones into the absolute paths this run uses.
//!
//! A policy says `write-zones = ["out-dir", "tmp"]`. A kernel needs
//! `/home/ci/proj/target/debug/build/serde-c0f05d/out`. This module is that translation,
//! and it is separate from both the policy (which must never contain a machine-specific
//! path) and the sandbox (which must never know what cargo is).
//!
//! # Where the paths come from
//!
//! Cargo tells the build script, in its environment, at run time. Nothing here is
//! derived from the path the binary was compiled into, because the two hashes differ —
//! measured on cargo 1.94.1, the shim lives in `build/<pkg>-<hashA>/` while `OUT_DIR` is
//! `build/<pkg>-<hashB>/out`. A tool that inferred one from the other would grant the
//! wrong directory and break every build script that writes anything.
//!
//! # The temporary directory is ours, not the system's
//!
//! The unit gets a **private** temporary directory and `TMPDIR` pointing at it, rather
//! than write access to `/tmp`. Two reasons, one measured:
//!
//! * A tmpfs mounted over `/tmp` hides whatever was already there — including, in the
//!   spike that found this, the build's own files when the target directory happened to
//!   live under `/tmp`.
//! * Granting the shared `/tmp` lets one unit read and overwrite another's temporaries,
//!   which is a channel between two units that are otherwise isolated.
//!
//! `cc` needs a writable temporary directory and fails hard without one — measured:
//! *"Cannot create temporary file in ./: Read-only file system"*, then abort. So this is
//! not optional, only private.

use std::path::{Path, PathBuf};

use buildclamp_core::{Envelope, WriteZone};

/// The absolute paths one held unit is allowed to write to, plus the environment
/// overrides that make the unit use them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitPaths {
    /// Directories the unit may write to, absolute and de-duplicated.
    pub writable: Vec<PathBuf>,
    /// The private temporary directory, to be created by the caller and exported as
    /// `TMPDIR`. `None` when the unit was not granted the `tmp` zone.
    pub private_tmp: Option<PathBuf>,
}

/// Where a unit's run-time context puts things. Assembled from cargo's environment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnitContext {
    /// `OUT_DIR`, as cargo set it for this unit.
    pub out_dir: Option<PathBuf>,
    /// `CARGO_MANIFEST_DIR`.
    pub manifest_dir: Option<PathBuf>,
    /// The target directory for this build.
    pub target_dir: Option<PathBuf>,
    /// The run directory, which is always writable: every held unit writes its own
    /// record there, and a unit that could not would leave the report silently short.
    pub run_dir: Option<PathBuf>,
}

/// Resolve an envelope's zones and explicit paths against this unit's context.
///
/// Zones that have no path in this context are dropped rather than guessed. A build
/// script with no `OUT_DIR` is not a thing cargo produces, but a `cargo buildclamp
/// explain` run has no context at all, and inventing a path there would print a lie.
pub fn resolve_zones(envelope: &Envelope, ctx: &UnitContext) -> UnitPaths {
    let mut writable: Vec<PathBuf> = Vec::new();
    let mut private_tmp = None;

    // `known_zones` rather than the raw list: an envelope read back out of a report a
    // newer agent wrote can name a zone this build has never heard of, and the rule for
    // one of those is the same as for the `_` arm below — resolve it to nothing, so the
    // unit fails closed with a write refusal rather than being handed a path nobody here
    // could have meant.
    for zone in envelope.known_zones() {
        match zone {
            WriteZone::OutDir => push(&mut writable, ctx.out_dir.as_deref()),
            WriteZone::ManifestDir => push(&mut writable, ctx.manifest_dir.as_deref()),
            WriteZone::Target => push(&mut writable, ctx.target_dir.as_deref()),
            WriteZone::Tmp => {
                // A private directory rather than the shared /tmp. See the module docs.
                if let Some(out) = ctx.out_dir.as_deref() {
                    let t = out.join(".buildclamp-tmp");
                    push(&mut writable, Some(t.as_path()));
                    private_tmp = Some(t);
                } else if let Some(run) = ctx.run_dir.as_deref() {
                    let t = run.join("tmp");
                    push(&mut writable, Some(t.as_path()));
                    private_tmp = Some(t);
                }
            }
            // `WriteZone` is `#[non_exhaustive]`, so a zone added in a newer core than
            // this crate was built against lands here. Resolving to nothing is the same
            // rule as a zone with no path in this context: drop it rather than guess.
            // The consequence is a build that fails closed with a clear write refusal,
            // which is the right direction for the mistake to point.
            _ => {}
        }
    }

    for p in &envelope.write_paths {
        push(&mut writable, Some(Path::new(p)));
    }

    // The unit must always be able to write its own record, whatever the policy says.
    // A policy that could switch this off would produce a report missing exactly the
    // units someone wanted hidden.
    push(&mut writable, ctx.run_dir.as_deref());

    UnitPaths {
        writable,
        private_tmp,
    }
}

fn push(into: &mut Vec<PathBuf>, p: Option<&Path>) {
    if let Some(p) = p {
        let p = p.to_path_buf();
        if !into.contains(&p) {
            into.push(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buildclamp_core::Capability;

    fn ctx() -> UnitContext {
        UnitContext {
            out_dir: Some(PathBuf::from("/proj/target/debug/build/serde-b1/out")),
            manifest_dir: Some(PathBuf::from("/reg/serde-1.0.229")),
            target_dir: Some(PathBuf::from("/proj/target")),
            run_dir: Some(PathBuf::from("/proj/target/buildclamp/run")),
        }
    }

    #[test]
    fn the_default_build_script_envelope_resolves_to_out_dir_and_a_private_tmp() {
        let p = resolve_zones(&Envelope::build_script_default(), &ctx());
        assert!(p
            .writable
            .contains(&PathBuf::from("/proj/target/debug/build/serde-b1/out")));
        assert_eq!(
            p.private_tmp,
            Some(PathBuf::from(
                "/proj/target/debug/build/serde-b1/out/.buildclamp-tmp"
            ))
        );
        // Not the whole target directory, and not the manifest directory.
        assert!(!p.writable.contains(&PathBuf::from("/proj/target")));
        assert!(!p.writable.contains(&PathBuf::from("/reg/serde-1.0.229")));
    }

    #[test]
    fn the_temporary_directory_is_private_rather_than_the_shared_tmp() {
        // Granting /tmp would let one unit read and overwrite another's temporaries,
        // which is a channel between units that are otherwise isolated.
        let p = resolve_zones(&Envelope::build_script_default(), &ctx());
        assert!(!p.writable.iter().any(|w| w == Path::new("/tmp")));
        assert!(p.private_tmp.as_ref().unwrap().starts_with("/proj/target"));
    }

    #[test]
    fn a_compile_unit_gets_the_target_directory_because_rustc_writes_all_over_it() {
        let p = resolve_zones(&Envelope::compile_default(), &ctx());
        assert!(p.writable.contains(&PathBuf::from("/proj/target")));
    }

    #[test]
    fn the_run_directory_is_always_writable_whatever_the_policy_says() {
        // A policy that could switch this off would produce a report missing exactly the
        // units someone wanted hidden.
        let mut e = Envelope::build_script_default();
        e.write_zones.clear();
        e.granted.remove(Capability::FsWrite);
        let p = resolve_zones(&e, &ctx());
        assert!(p
            .writable
            .contains(&PathBuf::from("/proj/target/buildclamp/run")));
    }

    #[test]
    fn a_zone_with_no_path_in_this_context_is_dropped_rather_than_guessed() {
        let e = Envelope::build_script_default();
        let empty = UnitContext::default();
        let p = resolve_zones(&e, &empty);
        assert!(p.writable.is_empty());
        assert_eq!(p.private_tmp, None);
    }

    #[test]
    fn explicit_write_paths_are_added_and_duplicates_collapse() {
        let mut e = Envelope::build_script_default();
        e.write_paths = vec![
            "/opt/vendored".into(),
            // The same directory a zone already resolved to.
            "/proj/target/debug/build/serde-b1/out".into(),
        ];
        let p = resolve_zones(&e, &ctx());
        assert!(p.writable.contains(&PathBuf::from("/opt/vendored")));
        assert_eq!(
            p.writable
                .iter()
                .filter(|w| *w == Path::new("/proj/target/debug/build/serde-b1/out"))
                .count(),
            1
        );
    }
}
