//! The pre-exec sweep: shimming build scripts cargo will never recompile.
//!
//! # The bug this exists for
//!
//! An earlier design assumed that setting `RUSTC_WRAPPER` dirties every unit's
//! fingerprint, so turning buildclamp on would force a rebuild and every build script
//! would pass through the wrapper and get shimmed.
//!
//! **That is false, and an adversarial review reproduced it on cargo 1.94.1.** Cargo
//! deliberately excludes the wrapper from fingerprints and metadata hashes, so that a
//! build cache stays shareable between people who use `sccache` and people who do not.
//! Measured: a plain `cargo build`, then `RUSTC_WRAPPER=wrap.sh cargo build -v`, reports
//! `Fresh` for everything and invokes the wrapper only for `-vV` and the `--print`
//! probe. The build-script compile never happens again.
//!
//! The consequence is the worst failure this tool can have. Any target directory that was
//! ever populated by a plain `cargo build` — a CI cache restore, a colleague's build,
//! rust-analyzer compiling build scripts in the background the moment a dependency was
//! added — keeps its compiled build scripts **un-shimmed forever**. Cargo re-*runs* them
//! whenever it decides the run is dirty (a `rerun-if-changed` file moved, a feature
//! changed, a path dependency with no `rerun-if` directives, which re-runs on every
//! source edit). Those runs execute the plain binary: no sandbox, no environment scrub,
//! no record. And `cargo buildclamp build` reports zero ungranted requests, because from
//! its point of view nothing happened.
//!
//! A tool that reports success while enforcing nothing is worse than no tool. So before
//! exec'ing cargo, the driver walks the build directories and shims anything the wrapper
//! will not get a chance to.
//!
//! # Why this is an improvement, not just a patch
//!
//! Because the wrapper is not in the fingerprint, alternating between `cargo build` and
//! `cargo buildclamp build` costs **no rebuild at all** — which is much better than the
//! rebuild storm the original design assumed and accepted. The sweep is what makes that
//! safe rather than dangerous.
//!
//! # The second half: cargo will not re-link either
//!
//! Cargo hard-links `build_script_build-<hash>` to `build-script-build` and executes the
//! latter. For a Fresh unit it does not re-create that link, so replacing the hashed file
//! alone would leave cargo executing the old inode. The sweep therefore unlinks and
//! re-creates the link itself, falling back to a copy on filesystems that refuse hard
//! links.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::swap::{self, REAL_SUFFIX};

/// What one sweep did, for the report's `swept` count and for `unhook`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SweepResult {
    /// Build scripts that were compiled before buildclamp was involved and are now
    /// shimmed.
    pub shimmed: Vec<PathBuf>,
    /// Already shimmed, left alone.
    pub already: usize,
    /// Paths that looked like build scripts but could not be shimmed, with the reason.
    ///
    /// Never silently dropped: a build script the sweep could not reach is a build script
    /// that will run unheld, and the report has to say so.
    pub failed: Vec<(PathBuf, String)>,
}

impl SweepResult {
    pub fn is_empty(&self) -> bool {
        self.shimmed.is_empty() && self.failed.is_empty()
    }
}

/// The name cargo hard-links a compiled build script to and then executes.
const EXECUTED_NAME: &str = "build-script-build";

/// Shim every already-compiled build script under `build_root` that is not shimmed yet.
///
/// `build_root` is a target directory. Both layouts are walked: `<target>/<profile>/build/`
/// and `<target>/<triple>/<profile>/build/`, because a cross build has host build scripts
/// in the first and target ones in the second, and only sweeping one would leave half the
/// graph unheld.
pub fn sweep(build_root: &Path, launcher: &Path) -> io::Result<SweepResult> {
    let mut result = SweepResult::default();
    for dir in build_dirs(build_root) {
        sweep_one_build_dir(&dir, launcher, &mut result)?;
    }
    Ok(result)
}

/// Every `.../build/` directory under a target directory.
///
/// Walked rather than constructed, because the profile names are arbitrary (`debug`,
/// `release`, and any custom profile a workspace defines) and the triple directories
/// depend on what has been cross-compiled.
fn build_dirs(target_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(level1) = fs::read_dir(target_dir) else {
        return out;
    };
    for a in level1.flatten() {
        if !a.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let p = a.path();
        // <target>/<profile>/build
        let direct = p.join("build");
        if direct.is_dir() {
            out.push(direct);
        }
        // <target>/<triple>/<profile>/build
        if let Ok(level2) = fs::read_dir(&p) {
            for b in level2.flatten() {
                if b.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let nested = b.path().join("build");
                    if nested.is_dir() {
                        out.push(nested);
                    }
                }
            }
        }
    }
    out
}

fn sweep_one_build_dir(
    build_dir: &Path,
    launcher: &Path,
    result: &mut SweepResult,
) -> io::Result<()> {
    let entries = match fs::read_dir(build_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };

    for dir in unit_dirs(entries) {
        let Some(hashed) = find_compiled_build_script(&dir) else {
            continue;
        };

        if swap::is_shim(&hashed) {
            result.already += 1;
            // Even when the hashed file is already a shim, the executed hard link may
            // predate it — an interrupted earlier run, or a swap performed by the wrapper
            // in a build cargo then abandoned. Re-pointing it is cheap and idempotent.
            if let Err(e) = relink(&dir, &hashed) {
                result.failed.push((dir.join(EXECUTED_NAME), e.to_string()));
            }
            continue;
        }

        match swap::swap(&hashed, launcher).and_then(|s| relink(&dir, &s.shim)) {
            Ok(()) => result.shimmed.push(hashed),
            Err(e) => result.failed.push((hashed, e.to_string())),
        }
    }
    Ok(())
}

/// The directories under a `build/` directory that may hold a compiled build script.
///
/// Before cargo 1.100 that is `build/<pkg>-<hash>/`, beside the `build-script-build` link.
/// From 1.100 it is `build/<pkg>/<hash>/out/`, and cargo executes the file there itself,
/// so there is no link: `relink` finds none and does nothing.
fn unit_dirs(entries: fs::ReadDir) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in entries.flatten() {
        if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let dir = e.path();
        if let Ok(hashes) = fs::read_dir(&dir) {
            for h in hashes.flatten() {
                let o = h.path().join("out");
                if o.is_dir() {
                    out.push(o);
                }
            }
        }
        out.push(dir);
    }
    out
}

/// The `build_script_*-<hash>` file in a unit directory, if there is a real one.
///
/// Requires an ELF magic or a shim header, because the directory also holds
/// `build_script_build-<hash>.d` (a dep-info text file), the `.real` we may have written,
/// and on some cargo versions other artefacts. Matching on the name alone would try to
/// swap a dep-info file and corrupt the unit.
fn find_compiled_build_script(dir: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("build_script_") {
            continue;
        }
        if name.ends_with(".d") || name.ends_with(REAL_SUFFIX) {
            continue;
        }
        let p = e.path();
        if is_executable_artefact(&p) {
            return Some(p);
        }
    }
    None
}

fn is_executable_artefact(p: &Path) -> bool {
    let Ok(bytes) = fs::read(p) else { return false };
    bytes.starts_with(b"\x7fELF") || bytes.starts_with(b"#!/bin/sh\n# Written by buildclamp.")
}

/// Point `build-script-build` at `target`, replacing whatever link is there.
///
/// Cargo will not re-link a Fresh unit, so replacing the hashed file alone would leave
/// cargo executing the old inode — the build script that is not shimmed. Unlink first
/// because a hard link cannot be created over an existing name; fall back to a copy on
/// filesystems that refuse hard links (some overlay and network mounts do).
fn relink(dir: &Path, target: &Path) -> io::Result<()> {
    let executed = dir.join(EXECUTED_NAME);
    if !executed.exists() {
        // Cargo has not run this unit yet, so it will create the link itself from
        // whatever the hashed file is by then — which is our shim.
        return Ok(());
    }
    fs::remove_file(&executed)?;
    match fs::hard_link(target, &executed) {
        Ok(()) => Ok(()),
        Err(_) => {
            fs::copy(target, &executed)?;
            let perms = fs::metadata(target)?.permissions();
            fs::set_permissions(&executed, perms)
        }
    }
}

/// Undo every swap under a target directory, restoring the real build scripts.
pub fn unsweep(build_root: &Path) -> io::Result<usize> {
    let mut n = 0;
    for build_dir in build_dirs(build_root) {
        let Ok(entries) = fs::read_dir(&build_dir) else {
            continue;
        };
        for dir in unit_dirs(entries) {
            let Some(hashed) = find_compiled_build_script(&dir) else {
                continue;
            };
            if !swap::is_shim(&hashed) {
                continue;
            }
            swap::unswap(&hashed)?;
            let _ = relink(&dir, &hashed);
            n += 1;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A target directory shaped like cargo's, holding one already-compiled build script
    /// and the hard link cargo executes — the state left by a plain `cargo build`.
    fn target_dir_from_a_plain_build(profile: &str) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let unit = d.path().join(profile).join("build").join("dep-8fec19e1");
        fs::create_dir_all(&unit).unwrap();
        let hashed = unit.join("build_script_build-8fec19e1");
        fs::write(&hashed, b"\x7fELF pretend build script").unwrap();
        fs::set_permissions(&hashed, fs::Permissions::from_mode(0o755)).unwrap();
        fs::hard_link(&hashed, unit.join(EXECUTED_NAME)).unwrap();
        // The dep-info file cargo writes beside it, which must not be touched.
        fs::write(
            unit.join("build_script_build-8fec19e1.d"),
            b"deps: build.rs\n",
        )
        .unwrap();
        (d, hashed)
    }

    fn launcher() -> &'static Path {
        Path::new("/usr/local/bin/cargo-buildclamp")
    }

    #[test]
    fn a_build_script_compiled_before_buildclamp_existed_gets_shimmed() {
        // The whole reason this module exists. Without it, this build script runs unheld
        // and the report says the build was clean.
        let (d, hashed) = target_dir_from_a_plain_build("debug");
        let r = sweep(d.path(), launcher()).unwrap();
        assert_eq!(r.shimmed, vec![hashed.clone()]);
        assert!(swap::is_shim(&hashed));
        assert!(hashed
            .with_file_name("build_script_build-8fec19e1.real")
            .exists());
    }

    #[test]
    fn the_executed_hard_link_is_re_pointed_because_cargo_will_not_re_link_a_fresh_unit() {
        // Replacing the hashed file alone leaves cargo executing the old inode — the
        // unshimmed build script. This is the half of the fix that is easy to miss.
        let (d, hashed) = target_dir_from_a_plain_build("debug");
        let executed = hashed.with_file_name(EXECUTED_NAME);
        sweep(d.path(), launcher()).unwrap();
        assert!(
            swap::is_shim(&executed),
            "cargo would still run the old binary"
        );
        assert_eq!(fs::read(&executed).unwrap(), fs::read(&hashed).unwrap());
    }

    #[test]
    fn sweeping_twice_changes_nothing_and_does_not_lose_the_real_binary() {
        let (d, hashed) = target_dir_from_a_plain_build("debug");
        sweep(d.path(), launcher()).unwrap();
        let real = hashed.with_file_name("build_script_build-8fec19e1.real");
        let before = fs::read(&real).unwrap();

        let second = sweep(d.path(), launcher()).unwrap();
        assert!(second.shimmed.is_empty());
        assert_eq!(second.already, 1);
        // The critical property: a second sweep must not shim the shim and lose the real
        // build script behind two layers.
        assert_eq!(fs::read(&real).unwrap(), before);
        assert_eq!(before, b"\x7fELF pretend build script");
    }

    #[test]
    fn both_the_host_and_the_cross_target_build_directories_are_swept() {
        // A cross build puts host build scripts in <target>/<profile>/build and target
        // ones in <target>/<triple>/<profile>/build. Sweeping one would leave half the
        // graph unheld.
        let d = tempfile::tempdir().unwrap();
        for rel in [
            "debug/build/host-1",
            "x86_64-unknown-linux-musl/debug/build/cross-1",
        ] {
            let unit = d.path().join(rel);
            fs::create_dir_all(&unit).unwrap();
            let f = unit.join("build_script_build-abc");
            fs::write(&f, b"\x7fELF").unwrap();
            fs::hard_link(&f, unit.join(EXECUTED_NAME)).unwrap();
        }
        let r = sweep(d.path(), launcher()).unwrap();
        assert_eq!(r.shimmed.len(), 2, "both layouts must be swept: {r:?}");
    }

    #[test]
    fn cargo_1_100s_layout_is_swept_and_unswept() {
        // Measured on cargo 1.100.0: `build/<pkg>/<hash>/out/build_script_build`, no hash
        // in the name and no `build-script-build` link; cargo executes this file.
        let d = tempfile::tempdir().unwrap();
        let out = d.path().join("debug/build/bs/333cbacb469d7be5/out");
        fs::create_dir_all(&out).unwrap();
        let bin = out.join("build_script_build");
        fs::write(&bin, b"\x7fELF pretend build script").unwrap();
        fs::write(out.join("build_script_build.d"), b"deps: build.rs\n").unwrap();
        let r = sweep(d.path(), launcher()).unwrap();
        assert_eq!(r.shimmed, vec![bin.clone()], "{r:?}");
        assert!(swap::is_shim(&bin));
        assert!(!out.join(EXECUTED_NAME).exists(), "no link in this layout");
        assert_eq!(unsweep(d.path()).unwrap(), 1);
        assert_eq!(fs::read(&bin).unwrap(), b"\x7fELF pretend build script");
    }

    #[test]
    fn the_dep_info_file_beside_the_build_script_is_never_touched() {
        // Matching on the name alone would try to swap `build_script_build-<hash>.d`,
        // which is a text file cargo needs, and corrupt the unit.
        let (d, hashed) = target_dir_from_a_plain_build("debug");
        let dep_info = hashed.with_file_name("build_script_build-8fec19e1.d");
        sweep(d.path(), launcher()).unwrap();
        assert_eq!(fs::read(&dep_info).unwrap(), b"deps: build.rs\n");
    }

    #[test]
    fn a_unit_cargo_has_not_run_yet_needs_no_link_and_is_not_an_error() {
        let d = tempfile::tempdir().unwrap();
        let unit = d.path().join("debug/build/fresh-1");
        fs::create_dir_all(&unit).unwrap();
        fs::write(unit.join("build_script_build-1"), b"\x7fELF").unwrap();
        let r = sweep(d.path(), launcher()).unwrap();
        assert_eq!(r.shimmed.len(), 1);
        assert!(r.failed.is_empty(), "{r:?}");
    }

    #[test]
    fn an_empty_or_missing_target_directory_sweeps_to_nothing() {
        let d = tempfile::tempdir().unwrap();
        assert!(sweep(d.path(), launcher()).unwrap().is_empty());
        assert!(sweep(&d.path().join("never-built"), launcher())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn unsweep_restores_every_real_build_script_and_the_link_cargo_runs() {
        let (d, hashed) = target_dir_from_a_plain_build("debug");
        sweep(d.path(), launcher()).unwrap();
        assert_eq!(unsweep(d.path()).unwrap(), 1);
        assert_eq!(fs::read(&hashed).unwrap(), b"\x7fELF pretend build script");
        assert_eq!(
            fs::read(hashed.with_file_name(EXECUTED_NAME)).unwrap(),
            b"\x7fELF pretend build script"
        );
    }
}
