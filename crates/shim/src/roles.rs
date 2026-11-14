//! The three process roles cargo puts buildclamp in, and how it tells them apart.
//!
//! One executable, three jobs:
//!
//! | role | how it is entered | what it does |
//! |---|---|---|
//! | driver | a person types `cargo buildclamp build` | sets the environment, runs cargo, reads the run directory back |
//! | wrapper | cargo runs `$RUSTC_WRAPPER <compiler> <args…>` | classifies, runs the compile, swaps a build script for a shim |
//! | launcher | a shim execs `buildclamp __launch --real … -- …` | resolves the envelope and holds the build script |
//!
//! It has to be one executable because the shim needs an absolute path to something that
//! will still be there when cargo runs it, and because a second binary would be a second
//! thing to install, find on `PATH` and keep in version lockstep with the first.
//!
//! # The passthrough rules, which are the safety net
//!
//! The wrapper does nothing at all unless a policy is active. Three environment
//! variables decide, and each check exists for a failure someone would otherwise hit:
//!
//! * **No `BUILDCLAMP_POLICY`** → pass through. A stray `RUSTC_WRAPPER` left in a shell
//!   must not mutate target directories on an ordinary build. Nothing is lost by this:
//!   changing `RUSTC_WRAPPER` already changes every unit's fingerprint and forces a
//!   rebuild, so keeping shims around for a later policied run would buy nothing back.
//! * **`BUILDCLAMP_INSIDE` set** → pass through. We are already inside a held unit, and
//!   there are three independent reasons a second sandbox would be wrong: the namespaces
//!   and seccomp filter are inherited already; only one `NEW_LISTENER` seccomp filter is
//!   permitted per task, so installing a second fails; and the read-only `/proc` inside
//!   the mount namespace makes writing a nested user namespace's `uid_map` impossible.
//! * **A probe** (`--print`, `-vV`, rustc reading stdin) → pass through. There is no
//!   crate, no output and nothing to hold, and cargo issues several per build.

use std::ffi::OsString;
use std::path::PathBuf;

use buildclamp_core::{RustcInvocation, UnitKind, ENV_INSIDE, ENV_MODE, ENV_POLICY};

/// Which job this process was started to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// `cargo buildclamp <subcommand> …`, or the bare binary with no recognised role.
    Driver(Vec<OsString>),
    /// `RUSTC_WRAPPER` — `argv[1..]` is the compiler and its arguments.
    Wrapper { command: Vec<OsString> },
    /// `__launch --real <path> --argv0 <path> -- <args…>`, from a shim.
    Launcher {
        real: PathBuf,
        argv0: Option<OsString>,
        args: Vec<OsString>,
    },
}

/// The hidden subcommand a shim uses. Underscored so it does not appear in help output
/// and cannot be confused with something a person is meant to type.
pub const LAUNCH_SUBCOMMAND: &str = "__launch";

/// Work out which role this invocation is.
///
/// `argv` is the whole command line including `argv[0]`.
///
/// # Distinguishing a wrapper call from a driver call
///
/// Cargo invokes the wrapper as `<self> <compiler> <args…>`, and a person invokes the
/// driver as `cargo-buildclamp buildclamp build …` (cargo inserts the subcommand name)
/// or `cargo-buildclamp build …`. The discriminator is that a wrapper's first argument
/// is a path to an executable and never one of our subcommand names. Keying on "is it a
/// known subcommand" rather than "does it look like a path" is deliberate: a compiler
/// can live anywhere and be called anything (`clippy-driver`, a wrapper script, an
/// sccache shim), so the closed set to test against is ours, not theirs.
pub fn detect(argv: &[OsString]) -> Role {
    if argv.len() >= 2 && argv[1] == LAUNCH_SUBCOMMAND {
        return parse_launch(&argv[2..]);
    }

    // Cargo passes the subcommand name as the first argument when it dispatches
    // `cargo buildclamp …`; strip it so both spellings reach the same parser.
    let rest: Vec<OsString> = if argv.len() >= 2 && argv[1] == "buildclamp" {
        argv[2..].to_vec()
    } else {
        argv[1..].to_vec()
    };

    let first = rest.first().and_then(|s| s.to_str()).unwrap_or("");
    if first.is_empty() || DRIVER_SUBCOMMANDS.contains(&first) || first.starts_with('-') {
        return Role::Driver(rest);
    }

    // Anything else in that position is a compiler path from cargo.
    Role::Wrapper {
        command: argv[1..].to_vec(),
    }
}

/// The subcommands a person can type. Also the set that tells a driver call from a
/// wrapper call, so adding one here without adding it to the CLI is a bug the tests
/// catch.
pub const DRIVER_SUBCOMMANDS: &[&str] = &[
    "build", "check", "test", "bench", "doc", "install", "publish", "run", "clippy", "observe",
    "init", "explain", "report", "doctor", "selftest", "except", "verify", "policy", "unhook",
    "help",
];

fn parse_launch(args: &[OsString]) -> Role {
    let mut real = PathBuf::new();
    let mut argv0 = None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].to_str() {
            Some("--real") => {
                if let Some(v) = args.get(i + 1) {
                    real = PathBuf::from(v);
                }
                i += 2;
            }
            Some("--argv0") => {
                argv0 = args.get(i + 1).cloned();
                i += 2;
            }
            Some("--") => {
                rest = args[i + 1..].to_vec();
                break;
            }
            _ => i += 1,
        }
    }
    Role::Launcher {
        real,
        argv0,
        args: rest,
    }
}

/// Should the wrapper hold this unit, or hand it straight to the compiler?
///
/// Returns the reason for a passthrough so the caller can record it; a wrapper that
/// silently did nothing would be indistinguishable from a wrapper that was never called.
pub fn wrapper_action(invocation: &RustcInvocation, env: &dyn EnvLookup) -> WrapperAction {
    if env.get(ENV_POLICY).is_none() {
        return WrapperAction::PassThrough(PassReason::NoPolicy);
    }
    if env.get(ENV_INSIDE).is_some() {
        return WrapperAction::PassThrough(PassReason::AlreadyHeld);
    }
    // Before anything is classified. The kill switch outranks every other decision here,
    // including the ones that would hold a unit, because its whole purpose is that a
    // person under pressure does not have to reason about which of them applies.
    if env.get(ENV_MODE).as_deref() == Some("off") {
        return WrapperAction::PassThrough(PassReason::KillSwitch);
    }
    match invocation.kind {
        UnitKind::Probe => WrapperAction::PassThrough(PassReason::Probe),
        UnitKind::BuildScriptCompile => match invocation.build_script_output() {
            Some(_) => WrapperAction::CompileThenSwap,
            // A build-script compile whose output path we could not recover. Passing
            // through is the only safe answer: failing the build because we did not
            // recognise a command line is how a wrapper gets uninstalled, and guessing a
            // path is how a target directory gets corrupted.
            None => WrapperAction::PassThrough(PassReason::UnrecognisedOutput),
        },
        UnitKind::ProcMacroCompile => WrapperAction::CompileAndRecordMacro,
        UnitKind::Compile => WrapperAction::HoldCompile,
    }
}

/// What the wrapper decided to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapperAction {
    /// Run the compiler unchanged.
    PassThrough(PassReason),
    /// Run the compiler, then replace the build script it produced with a shim.
    CompileThenSwap,
    /// Run the compiler under the compile envelope, and record the proc-macro shared
    /// object it produced so later attribution can name it.
    CompileAndRecordMacro,
    /// Run the compiler under the compile envelope. This is where proc-macros execute.
    HoldCompile,
}

/// Why a unit was not held. Recorded, never silent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassReason {
    NoPolicy,
    AlreadyHeld,
    Probe,
    UnrecognisedOutput,
    /// `BUILDCLAMP_MODE=off` — the operator's emergency exit.
    ///
    /// Checked here as well as in the driver, deliberately. The driver is the ordinary way
    /// in, but a wrapper can be reached without it: a `RUSTC_WRAPPER` left in a shell, a
    /// CI job that exports the variable itself, a build resumed from a target directory
    /// still carrying shims. Somebody reaching for the emergency exit is having a bad
    /// enough day already; it has to work from wherever they set it.
    KillSwitch,
}

/// The environment, behind a trait so the decision logic is testable without touching
/// the process's real environment — which tests cannot do safely in parallel.
pub trait EnvLookup {
    fn get(&self, name: &str) -> Option<String>;
}

/// The real process environment.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessEnv;

impl EnvLookup for ProcessEnv {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

impl EnvLookup for std::collections::BTreeMap<String, String> {
    fn get(&self, name: &str) -> Option<String> {
        self.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn argv(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn the_wrapper_honours_the_kill_switch_on_its_own() {
        // The wrapper is one of three roles that can hold a unit, and each checks the
        // switch independently. Mutation testing found this one untested: disabling the
        // check here left the end-to-end suite green, because the launcher caught it
        // first. Defence in depth that only one layer is tested for is not depth.
        //
        // It matters because a wrapper can be reached without the driver — a
        // `RUSTC_WRAPPER` left in a shell, a CI job exporting the variable itself, a
        // build resumed from a target directory still carrying shims. Somebody reaching
        // for the emergency exit is having a bad enough day; it has to work from wherever
        // they set it.
        let held = wrapper_action(&build_script(), &env(&[(ENV_POLICY, "/p.toml")]));
        assert!(
            matches!(held, WrapperAction::CompileThenSwap),
            "without the switch this unit is held: {held:?}"
        );

        let off = wrapper_action(
            &build_script(),
            &env(&[(ENV_POLICY, "/p.toml"), (ENV_MODE, "off")]),
        );
        assert_eq!(
            off,
            WrapperAction::PassThrough(PassReason::KillSwitch),
            "the wrapper must pass through on its own, without relying on another role"
        );
    }

    #[test]
    fn only_the_exact_word_off_is_the_kill_switch() {
        // A near miss must not disable enforcement. `BUILDCLAMP_MODE=Off` or `=0` or
        // `=false` are the kinds of thing a person types under pressure, and quietly
        // treating one of them as the switch would be worse than ignoring it: the build
        // would pass, look held, and hold nothing.
        for near in ["Off", "OFF", "0", "false", "no", "disabled", ""] {
            let a = wrapper_action(
                &build_script(),
                &env(&[(ENV_POLICY, "/p.toml"), (ENV_MODE, near)]),
            );
            assert!(
                matches!(a, WrapperAction::CompileThenSwap),
                "`{near}` must not be read as the kill switch, got {a:?}"
            );
        }
    }

    fn build_script() -> RustcInvocation {
        buildclamp_core::classify(
            &[
                "--crate-name",
                "build_script_build",
                "--out-dir",
                "/t/build/x-1",
                "-C",
                "extra-filename=-1",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn cargo_calling_the_wrapper_is_told_apart_from_a_person_typing_a_subcommand() {
        assert!(matches!(
            detect(&argv(&[
                "cargo-buildclamp",
                "/usr/bin/rustc",
                "--crate-name",
                "x"
            ])),
            Role::Wrapper { .. }
        ));
        // Cargo inserts the subcommand name when dispatching `cargo buildclamp build`.
        assert!(matches!(
            detect(&argv(&["cargo-buildclamp", "buildclamp", "build"])),
            Role::Driver(_)
        ));
        assert!(matches!(
            detect(&argv(&["cargo-buildclamp", "build"])),
            Role::Driver(_)
        ));
        assert!(matches!(
            detect(&argv(&["cargo-buildclamp"])),
            Role::Driver(_)
        ));
        assert!(matches!(
            detect(&argv(&["cargo-buildclamp", "--version"])),
            Role::Driver(_)
        ));
    }

    #[test]
    fn a_compiler_that_is_not_called_rustc_is_still_recognised_as_a_wrapper_call() {
        // Under `cargo clippy` the workspace's own units arrive with clippy-driver in
        // front. Keying on the compiler's name would skip exactly the unit a developer
        // most wants held.
        assert!(matches!(
            detect(&argv(&[
                "cargo-buildclamp",
                "clippy-driver",
                "/usr/bin/rustc",
                "--crate-name",
                "x"
            ])),
            Role::Wrapper { .. }
        ));
        assert!(matches!(
            detect(&argv(&[
                "cargo-buildclamp",
                "/usr/local/bin/sccache",
                "rustc"
            ])),
            Role::Wrapper { .. }
        ));
    }

    #[test]
    fn a_launch_call_carries_the_real_binary_the_argv0_and_the_arguments() {
        let r = detect(&argv(&[
            "cargo-buildclamp",
            "__launch",
            "--real",
            "/t/bs.real",
            "--argv0",
            "/t/build-script-build",
            "--",
            "extra",
        ]));
        match r {
            Role::Launcher { real, argv0, args } => {
                assert_eq!(real, PathBuf::from("/t/bs.real"));
                assert_eq!(argv0, Some(OsString::from("/t/build-script-build")));
                assert_eq!(args, argv(&["extra"]));
            }
            other => panic!("expected a launcher, got {other:?}"),
        }
    }

    #[test]
    fn with_no_policy_active_the_wrapper_touches_nothing() {
        // A stray RUSTC_WRAPPER in a shell must not mutate target directories.
        assert_eq!(
            wrapper_action(&build_script(), &env(&[])),
            WrapperAction::PassThrough(PassReason::NoPolicy)
        );
    }

    #[test]
    fn a_nested_wrapper_call_inside_a_held_unit_passes_through() {
        // Three independent reasons, any one sufficient: the filter and namespaces are
        // inherited; only one NEW_LISTENER filter is allowed per task; and a read-only
        // /proc makes a nested user namespace's uid_map unwritable.
        assert_eq!(
            wrapper_action(
                &build_script(),
                &env(&[(ENV_POLICY, "/p.toml"), (ENV_INSIDE, "1")])
            ),
            WrapperAction::PassThrough(PassReason::AlreadyHeld)
        );
    }

    #[test]
    fn a_probe_passes_through_even_with_a_policy_active() {
        let probe = buildclamp_core::classify(&["-".to_string(), "--print=cfg".to_string()]);
        assert_eq!(
            wrapper_action(&probe, &env(&[(ENV_POLICY, "/p.toml")])),
            WrapperAction::PassThrough(PassReason::Probe)
        );
    }

    #[test]
    fn a_build_script_compile_with_a_policy_is_swapped() {
        assert_eq!(
            wrapper_action(&build_script(), &env(&[(ENV_POLICY, "/p.toml")])),
            WrapperAction::CompileThenSwap
        );
    }

    #[test]
    fn a_build_script_compile_we_cannot_locate_passes_through_rather_than_failing() {
        // Failing the build because we did not recognise a command line is how a wrapper
        // gets uninstalled; guessing a path is how a target directory gets corrupted.
        let odd = buildclamp_core::classify(&["--crate-name".into(), "build_script_build".into()]);
        assert_eq!(
            wrapper_action(&odd, &env(&[(ENV_POLICY, "/p.toml")])),
            WrapperAction::PassThrough(PassReason::UnrecognisedOutput)
        );
    }

    #[test]
    fn every_driver_subcommand_is_recognised_as_a_driver_call() {
        // Adding a subcommand to the CLI without adding it here would make cargo's
        // invocation of it look like a compiler path.
        for sub in DRIVER_SUBCOMMANDS {
            assert!(
                matches!(detect(&argv(&["cargo-buildclamp", sub])), Role::Driver(_)),
                "`{sub}` was not recognised as a driver subcommand"
            );
        }
    }
}
