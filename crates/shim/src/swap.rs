//! Swapping a compiled build script for a shim that re-enters buildclamp.
//!
//! # The mechanism, and why it is a shell script
//!
//! When cargo compiles a build script it invokes rustc through `RUSTC_WRAPPER`, so
//! buildclamp sees the command line and knows where the output will land. After rustc
//! succeeds, buildclamp renames that output to `<name>.real` and writes a three-line
//! `/bin/sh` script in its place. Cargo then hard-links the shim to
//! `build-script-build` and executes it, and the shim execs buildclamp's launcher with
//! the real binary's path.
//!
//! A shell script rather than a symlink or a hard link to the buildclamp binary, for two
//! reasons that a measurement changed:
//!
//! * **A later plain `cargo build` costs nothing.** The shim tests one environment
//!   variable and execs the real binary. Nothing is copied, nothing is sandboxed, no
//!   process of ours starts.
//! * **A moved or uninstalled buildclamp degrades to transparent, never to a broken
//!   build.** The shim checks the binary is executable before exec'ing it. A tool that
//!   breaks every build in the repository after someone runs `cargo uninstall` is a tool
//!   that gets remembered for that.
//!
//! An earlier draft justified this with "a truncating linker must not clobber our
//! executable". **That premise is false and the comment is corrected rather than
//! deleted**, because the true behaviour is load-bearing: measured with `strace` on GNU
//! ld 2.42 and rustc 1.94, the linker does `unlink(out)` then writes a temp with
//! `O_EXCL` then `rename`s — the ETXTBSY dance. The output therefore always gets a
//! **fresh inode**, which means cargo's `build-script-build` hard link would point at
//! stale bytes unless cargo re-links it after every rebuild. It does, verified by
//! comparing inodes across a rebuild. So the design depends on that cargo behaviour, and
//! saying so is the difference between a documented dependency and a coincidence.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The suffix given to the real build-script binary once the shim takes its place.
pub const REAL_SUFFIX: &str = ".real";

/// Where a swap put things, so the caller can record it and the tests can assert on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Swapped {
    /// The path cargo will hard-link and execute — now the shim.
    pub shim: PathBuf,
    /// The build script rustc actually produced.
    pub real: PathBuf,
}

/// Replace a compiled build script with a shim that re-enters `launcher`.
///
/// `launcher` must be an absolute path to the buildclamp binary. `output` is the path
/// rustc wrote, recovered from the command line by
/// [`buildclamp_core::RustcInvocation::build_script_output`].
///
/// Idempotent in the way that matters: if a `.real` already exists from a previous run
/// it is overwritten, because rustc has just produced a fresh binary and the old one is
/// stale by definition.
pub fn swap(output: &Path, launcher: &Path) -> io::Result<Swapped> {
    let real = with_suffix(output, REAL_SUFFIX);

    // Rename rather than copy: a copy would double the size of every build directory,
    // and rename within one directory is atomic, so there is no window in which the
    // path cargo is about to hard-link does not exist.
    fs::rename(output, &real)?;

    let script = shim_script(launcher, &real);
    fs::write(output, script)?;
    fs::set_permissions(output, fs::Permissions::from_mode(0o755))?;

    Ok(Swapped {
        shim: output.to_path_buf(),
        real,
    })
}

/// The shim's text.
///
/// Kept to three effective lines so a reviewer who does not trust buildclamp can read
/// the whole of what cargo executes. That readability is not decoration: this file is
/// the thing standing between cargo and a third party's code, and a reviewer who cannot
/// audit it in ten seconds has to take the rest on faith.
///
/// `$0` is passed explicitly. Cargo executes the script with `argv[0]` set to the
/// absolute path of `build-script-build` and no arguments, and a shim forwarding only
/// `"$@"` would drop it — measured, and the launcher needs it to tell which of the two
/// hashed directories it was invoked through.
fn shim_script(launcher: &Path, real: &Path) -> String {
    format!(
        "#!/bin/sh\n\
         # Written by buildclamp. The build script rustc produced is beside this file,\n\
         # with a {REAL_SUFFIX} suffix. If buildclamp is not installed or no policy is\n\
         # active, this runs it directly and does nothing else.\n\
         [ -n \"${policy}\" ] && [ -x '{launcher}' ] && \\\n\
         \x20 exec '{launcher}' __launch --real '{real}' --argv0 \"$0\" -- \"$@\"\n\
         exec '{real}' \"$@\"\n",
        policy = buildclamp_core::ENV_POLICY,
        launcher = launcher.display(),
        real = real.display(),
    )
}

/// `foo` becomes `foo.real`. A plain string append rather than `set_extension`, which
/// would turn `build_script_build-8fec19e1` into `build_script_build-8fec19e1.real` only
/// by luck and `foo.bar` into `foo.real` by design.
fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Is this path a shim buildclamp wrote?
///
/// Used by `unhook` and by the tests. Reads the first bytes rather than checking for a
/// sibling `.real`, because the question being asked is "did we write this file", and a
/// leftover `.real` from an interrupted run would answer it wrongly.
pub fn is_shim(p: &Path) -> bool {
    let Ok(head) = fs::read(p) else { return false };
    head.starts_with(b"#!/bin/sh\n# Written by buildclamp.")
}

/// Undo a swap, restoring the real build script.
///
/// `cargo buildclamp unhook` exists because someone will want their target directory
/// back without a full rebuild, and because a tool that can only be added is a tool
/// people are reluctant to try.
pub fn unswap(shim: &Path) -> io::Result<()> {
    if !is_shim(shim) {
        return Ok(());
    }
    let real = with_suffix(shim, REAL_SUFFIX);
    if real.exists() {
        fs::rename(&real, shim)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().expect("a scratch directory")
    }

    #[test]
    fn a_swap_leaves_the_real_binary_beside_a_readable_shim() {
        let d = scratch();
        let out = d.path().join("build_script_build-8fec19e1");
        fs::write(&out, b"\x7fELF pretend binary").unwrap();
        fs::set_permissions(&out, fs::Permissions::from_mode(0o755)).unwrap();

        let s = swap(&out, Path::new("/usr/local/bin/cargo-buildclamp")).unwrap();

        assert_eq!(s.real, d.path().join("build_script_build-8fec19e1.real"));
        assert_eq!(fs::read(&s.real).unwrap(), b"\x7fELF pretend binary");
        assert!(is_shim(&s.shim));
        // Executable, or cargo cannot run it and every build in the repository breaks.
        assert_eq!(
            fs::metadata(&s.shim).unwrap().permissions().mode() & 0o111,
            0o111
        );
    }

    #[test]
    fn the_shim_passes_argv0_through_because_cargo_supplies_no_other_arguments() {
        // Cargo runs the script with argv[0] = <abs>/build-script-build and nothing
        // else. A shim forwarding only "$@" drops the one piece of information the
        // launcher has about which hashed directory it came through.
        let d = scratch();
        let out = d.path().join("bs");
        fs::write(&out, b"x").unwrap();
        let s = swap(&out, Path::new("/opt/cargo-buildclamp")).unwrap();
        let text = fs::read_to_string(&s.shim).unwrap();
        assert!(text.contains("--argv0 \"$0\""), "{text}");
        assert!(text.contains("-- \"$@\""), "{text}");
    }

    #[test]
    fn the_shim_falls_back_to_the_real_binary_when_no_policy_is_active() {
        let d = scratch();
        let out = d.path().join("bs");
        fs::write(&out, b"x").unwrap();
        let s = swap(&out, Path::new("/opt/cargo-buildclamp")).unwrap();
        let text = fs::read_to_string(&s.shim).unwrap();
        let last = text.lines().last().unwrap();
        assert!(
            last.starts_with("exec '"),
            "the last line must exec the real binary: {last}"
        );
        assert!(last.contains(".real"), "{last}");
        assert!(text.contains(buildclamp_core::ENV_POLICY));
    }

    #[test]
    fn the_shim_checks_buildclamp_is_executable_so_an_uninstall_does_not_break_builds() {
        let d = scratch();
        let out = d.path().join("bs");
        fs::write(&out, b"x").unwrap();
        let s = swap(&out, Path::new("/opt/cargo-buildclamp")).unwrap();
        assert!(fs::read_to_string(&s.shim)
            .unwrap()
            .contains("-x '/opt/cargo-buildclamp'"));
    }

    /// The behaviour the fallback promises, executed rather than asserted about.
    #[test]
    fn the_shim_actually_runs_the_real_binary_when_the_launcher_is_missing() {
        let d = scratch();
        let out = d.path().join("bs");
        fs::write(&out, "#!/bin/sh\necho i-am-the-real-build-script\n").unwrap();
        fs::set_permissions(&out, fs::Permissions::from_mode(0o755)).unwrap();
        let s = swap(&out, Path::new("/nonexistent/cargo-buildclamp")).unwrap();

        let o = std::process::Command::new(&s.shim)
            .env(buildclamp_core::ENV_POLICY, "/some/policy.toml")
            .output()
            .expect("the shim runs");
        assert!(
            o.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&o.stdout).trim(),
            "i-am-the-real-build-script"
        );
    }

    #[test]
    fn a_suffix_is_appended_rather_than_replacing_a_dotted_component() {
        // `set_extension` would turn `build_script_build-8fec.1` into
        // `build_script_build-8fec.real` and lose the real binary.
        assert_eq!(
            with_suffix(Path::new("/t/build_script_build-8fec.1"), ".real"),
            PathBuf::from("/t/build_script_build-8fec.1.real")
        );
    }

    #[test]
    fn unswap_restores_the_real_binary_and_ignores_anything_it_did_not_write() {
        let d = scratch();
        let out = d.path().join("bs");
        fs::write(&out, b"original").unwrap();
        let s = swap(&out, Path::new("/opt/cargo-buildclamp")).unwrap();
        unswap(&s.shim).unwrap();
        assert_eq!(fs::read(&s.shim).unwrap(), b"original");
        assert!(!s.real.exists());

        // A file we did not write is left alone, even if a stray `.real` sits beside it.
        let other = d.path().join("someone-elses-binary");
        fs::write(&other, b"not ours").unwrap();
        fs::write(with_suffix(&other, REAL_SUFFIX), b"decoy").unwrap();
        unswap(&other).unwrap();
        assert_eq!(fs::read(&other).unwrap(), b"not ours");
    }
}
