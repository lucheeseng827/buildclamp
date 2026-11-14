//! `cargo-buildclamp` — one binary, three jobs.
//!
//! A person types `cargo buildclamp build`. Cargo runs this binary as `RUSTC_WRAPPER`.
//! A shimmed build script execs it as a launcher. Which job this process is doing is
//! decided by its command line, before clap ever sees it — see [`buildclamp_shim::roles`].
//!
//! It has to be one executable because the shim embeds an absolute path to something that
//! must still be there when cargo runs it, and because a second binary would be a second
//! thing to install, find on `PATH` and keep in version lockstep with the first.

// Every `unsafe` block in this project lives in `buildclamp-sandbox`, where it can be
// audited as one bounded surface. That confinement is worth a compiler check rather than a
// sentence in a README, so every other crate forbids it outright.
#![forbid(unsafe_code)]

mod args;
mod driver;
mod render;
mod runmeta;
mod unitrun;

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode};

use buildclamp_core::{exit, Capability, Forward, Mode, Policy, Tier, UnitKind};
use buildclamp_shim::roles::{self, Role, WrapperAction};

use clap::Parser;

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let code = match roles::detect(&argv) {
        Role::Launcher { real, args, .. } => run_launcher(&real, &args),
        Role::Wrapper { command } => run_wrapper(&command),
        Role::Driver(rest) => run_driver(rest),
    };
    ExitCode::from(code as u8)
}

// --- the launcher --------------------------------------------------------------------

fn run_launcher(real: &Path, args: &[OsString]) -> i32 {
    match unitrun::LaunchContext::from_env() {
        Some(ctx) => unitrun::launch(ctx, real, args),
        // No run directory or no policy: the shim's own fallback should have caught this,
        // so reaching here means the environment changed mid-build. Run the real build
        // script rather than break the build — but say so, because an unheld unit that
        // nobody knows about is the failure this tool exists to prevent.
        None => {
            eprintln!(
                "buildclamp: no policy or run directory in the environment; running \
                 `{}` unheld",
                real.display()
            );
            passthrough(Command::new(real).args(args))
        }
    }
}

// --- the rustc wrapper ---------------------------------------------------------------

fn run_wrapper(command: &[OsString]) -> i32 {
    if command.is_empty() {
        eprintln!("buildclamp: called as a rustc wrapper with no compiler");
        return exit::FAILED;
    }

    // The compiler and its arguments. `argv[1]` is not always rustc — under `cargo
    // clippy` the workspace's own units arrive with `clippy-driver` in front — so the
    // classifier scans the whole argv rather than keying on this.
    let compiler = &command[0];
    let rest: Vec<String> = command[1..]
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    let invocation = buildclamp_core::classify(&rest);
    let action = roles::wrapper_action(&invocation, &roles::ProcessEnv);

    let mut cmd = Command::new(compiler);
    cmd.args(&command[1..]);
    // Chain to a previous wrapper, so `sccache` keeps working.
    if let Some(inner) = std::env::var_os(buildclamp_core::ENV_INNER_WRAPPER) {
        if !inner.is_empty() {
            cmd = Command::new(inner);
            cmd.arg(compiler).args(&command[1..]);
        }
    }

    // After the chain is resolved, so the inner wrapper is scrubbed too — it is another
    // process that sees the compiler's environment, and `sccache` in particular puts that
    // environment into a cache key. The driver leaves `env-allow`ed names in place for the
    // launcher's sake; nothing rebuilds the environment on this path, so the wrapper has to
    // take them back out. See `driver::compiler_child_secret_names`.
    driver::scrub_compiler_environment(&mut cmd);

    match action {
        WrapperAction::PassThrough(_) => passthrough(&mut cmd),
        WrapperAction::CompileThenSwap => {
            let code = passthrough_status(&mut cmd);
            if code == 0 {
                if let (Some(out), Ok(me)) = (invocation.build_script_output(), driver::self_path())
                {
                    // A swap that fails is reported and does not fail the build: the unit
                    // then runs unheld, which the sweep will catch on the next run, and
                    // breaking a build over it would be worse.
                    if let Err(e) = buildclamp_shim::swap(Path::new(&out), &me) {
                        eprintln!(
                            "buildclamp: could not hold the build script for this crate: {e}"
                        );
                    }
                }
            }
            code
        }
        WrapperAction::CompileAndRecordMacro => {
            let code = passthrough_status(&mut cmd);
            if code == 0 {
                record_macro(&invocation);
            }
            code
        }
        // Where proc-macro expansion is caught. Off unless the policy asks for it: this is
        // every rustc in the graph rather than one process per crate with a build script,
        // and rustc opens thousands of files, so it changes what a build costs rather than
        // adding to it.
        WrapperAction::HoldCompile => {
            let policy = driver::wrapper_policy();
            if policy.defaults.hold_compile_units {
                hold_compile(&invocation, cmd, &policy)
            } else {
                passthrough(&mut cmd)
            }
        }
    }
}

/// The identity cargo gives the crate being compiled.
///
/// From the environment rather than from the argv `--crate-name`, because they are not the
/// same string: rustc's crate name is underscored (`serde_derive`) and the policy is keyed
/// by the package name (`serde-derive`). Keying the inventory or an envelope on the
/// underscored form would silently miss every grant written for a hyphenated crate.
fn unit_identity(invocation: &buildclamp_core::RustcInvocation) -> Option<buildclamp_core::UnitId> {
    let name = std::env::var("CARGO_PKG_NAME")
        .ok()
        .or_else(|| invocation.crate_name.clone())?;
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    Some(buildclamp_core::UnitId::new(name, version))
}

/// Open the run directory, honouring the trusted macro directory the driver provided.
///
/// The macro inventory is written and read here, in the wrapper, outside the sandbox — but a
/// held compile is granted all of `target/`, so the inventory cannot live under the run
/// directory (which is under `target/`) without being forgeable by the code being held. The
/// driver puts it outside every writable zone and names it in `ENV_MACRO_DIR`. Falling back
/// to the run directory keeps an older driver working, at the cost of the pre-inventory
/// attribution the docs already describe as the graceful-degradation case.
fn open_run_dir(
    run_dir: impl Into<std::path::PathBuf>,
) -> std::io::Result<buildclamp_shim::RunDir> {
    let run_dir = run_dir.into();
    match std::env::var_os(buildclamp_core::ENV_MACRO_DIR) {
        Some(macros) => buildclamp_shim::RunDir::open_with_macro_dir(run_dir, macros),
        None => buildclamp_shim::RunDir::open(run_dir),
    }
}

/// Record the proc-macro shared object this compile produced.
///
/// Best effort throughout, and deliberately: every failure here costs precision in a later
/// attribution, and none of them is worth failing a compile that succeeded over. A missing
/// entry means one refusal names the compilation instead of the macro — which is the answer
/// the tool gave for everything before this inventory existed.
fn record_macro(invocation: &buildclamp_core::RustcInvocation) {
    let (Some(object), Some(id), Some(run_dir)) = (
        invocation.proc_macro_output(),
        unit_identity(invocation),
        std::env::var_os(buildclamp_core::ENV_RUN_DIR),
    ) else {
        return;
    };
    if let Ok(run) = open_run_dir(run_dir) {
        let _ = run.write_macro(Path::new(&object), &id);
    }
}

/// Run one rustc under the compile envelope.
///
/// # What this holds, and what it cannot
///
/// Proc-macro expansion happens inside the rustc compiling the **consumer**, which has
/// already loaded every proc-macro in its closure by the time any of them runs. So this is
/// one shared policy per compilation, not per macro: a refusal names the compilation and
/// the macros that could have been responsible. `cargo-acl` holds rustc the same way and
/// says so; `docs/adr/0004` argues why it is worth shipping anyway.
///
/// # Failing open is not an option here, and failing closed is not either
///
/// A build script that cannot be held is refused, because the alternative is running
/// somebody else's code unheld. A **compile** that cannot be held is different: refusing it
/// fails a build over a sandbox that could not start, on every crate in the graph, and a
/// tool that does that gets switched off within the hour. So the plan failing to apply
/// prints and passes through — but it records that unit with every capability at
/// [`Tier::None`], so it reads as a unit nothing held, not one that looks clean.
///
/// The record is the point, and an omission would be a hole. `is_fully_enforced` keys on the
/// `hold-compile-units` *flag*, which is still on when a single unit fails to hold, so a
/// report that simply left this unit out could be signed "fully enforced" while a proc-macro
/// ran outside the sandbox. A `none:` unit drops the enforcement summary for those
/// capabilities below `enforced:`, which turns `is_fully_enforced` false and fails
/// `--require-enforced` — the honest reading of a compilation nothing constrained.
fn hold_compile(
    invocation: &buildclamp_core::RustcInvocation,
    mut cmd: Command,
    policy: &Policy,
) -> i32 {
    let (Some(id), Some(run_dir)) = (
        unit_identity(invocation),
        std::env::var_os(buildclamp_core::ENV_RUN_DIR),
    ) else {
        return passthrough(&mut cmd);
    };

    let is_workspace_member = driver::is_workspace_member();
    let Ok(envelope) = policy.resolve(&id, UnitKind::Compile, is_workspace_member) else {
        // An ambiguous or invalid policy stopped the driver long before this; reaching
        // here means the file changed mid-build, and a compile is not the place to
        // adjudicate it.
        return passthrough(&mut cmd);
    };

    let Ok(run) = open_run_dir(&run_dir) else {
        return passthrough(&mut cmd);
    };

    let unit_ctx = buildclamp_shim::UnitContext {
        out_dir: None,
        manifest_dir: std::env::var_os("CARGO_MANIFEST_DIR").map(Into::into),
        // rustc writes its artefacts under `--out-dir`, which is inside the target
        // directory. Granting that directory rather than the profile directory would deny
        // the incremental and dep-info files rustc writes beside it.
        target_dir: invocation.profile_dir(),
        run_dir: Some(std::path::PathBuf::from(&run_dir)),
    };
    let paths = buildclamp_shim::resolve_zones(&envelope, &unit_ctx);
    for d in paths.writable.iter().chain(paths.private_tmp.iter()) {
        let _ = std::fs::create_dir_all(d);
    }

    let (kept, scrubbed) = buildclamp_core::scrub(
        std::env::vars_os(),
        &envelope,
        &policy.env_deny(),
        envelope.env_allow_secrets,
    );
    cmd.env_clear();

    // The working directory, explicitly, because `pivot_root` does not preserve one and
    // `Prepared` restores only what the command asks for. Cargo invokes rustc with the
    // cwd it chose and passes source paths RELATIVE to it — `src/lib.rs`, not an absolute
    // path — so a held compile that lost the cwd fails with "couldn't read src/lib.rs: No
    // such file or directory". Measured exactly that way before this line existed, and it
    // is the kind of failure that reads as a missing file rather than as a sandbox.
    if let Ok(cwd) = std::env::current_dir() {
        cmd.current_dir(cwd);
    }

    let proc_macros = run.read_macros();
    let plan = buildclamp_sandbox::Plan {
        allow_net: envelope.permits(buildclamp_core::Capability::Net),
        allow_unix: envelope.permits(buildclamp_core::Capability::Unix),
        writable: paths.writable.clone(),
        // A held compile unit is where a proc-macro runs, so `withhold-secret-reads` has to
        // reach it too — an empty list here let a held proc-macro read the withheld
        // credential paths even on a Landlock host. Same resolution as the build path.
        withheld_reads: crate::unitrun::withheld_reads(policy, &envelope),
        private_tmp: paths.private_tmp.clone(),
        env: kept,
        observe_writes: false,
        observe_only: policy.defaults.mode == Mode::Observe,
        proc_macro_objects: proc_macros.clone(),
        skip_exec_target: None,
    };

    // `plan.hold` consumes `cmd`, and the contract above is that a compile which cannot be
    // held passes through rather than failing the build. Rebuild the equivalent command
    // first — program, args and working directory — so it can still run on failure. Its
    // environment is left inherited, matching the other passthrough paths in this function: a
    // passthrough runs the compile unheld, as cargo intended, not under the scrubbed set.
    let mut fallback = Command::new(cmd.get_program());
    fallback.args(cmd.get_args());
    if let Some(dir) = cmd.get_current_dir() {
        fallback.current_dir(dir);
    }

    let started = std::time::Instant::now();
    let held = match plan.hold(cmd) {
        Ok(h) => h,
        Err(e) => {
            // hold-compile-units is on, but the sandbox could not be applied to this unit.
            // The build must not fail over a sandbox that could not start (see the contract
            // above), so the compilation runs unheld — via `passthrough_status`, which waits
            // rather than `exec`ing, so control returns here to write the record. That record
            // is what keeps the report honest: an omitted unit is invisible to
            // `is_fully_enforced`, which keys on the flag and would still read "fully
            // enforced" with a proc-macro having run outside the sandbox. Recording every
            // non-observe-only capability at `Tier::None` makes the unit visible, drops its
            // enforcement summary to `none:`, and so turns `is_fully_enforced` false and
            // fails `--require-enforced` — the honest reading of a unit nothing held. `exec`
            // is left out because it is observe-only: it is advisory on every host by design,
            // so a `none:` for it would say nothing this scan does not already know.
            eprintln!(
                "buildclamp: could not hold this compilation ({e}); running it unheld and \
                 recording it as unheld, so the report cannot read as fully enforced"
            );
            let reason = format!(
                "hold-compile-units was on, but the sandbox could not be applied to this \
                 compilation ({e}); it ran unheld"
            );
            let unheld_tiers: std::collections::BTreeMap<Forward<Capability>, Tier> =
                Capability::ALL
                    .into_iter()
                    .filter(|c| !c.is_observe_only())
                    .map(|c| {
                        (
                            Forward::Known(c),
                            Tier::None {
                                reason: reason.clone(),
                            },
                        )
                    })
                    .collect();
            // Run it unheld, keeping the real ExitStatus. `passthrough_status` returns only a
            // numeric code, but a compile the sandbox could not hold can still die by signal
            // (an OOM kill, a segfault in rustc), and the record must say so rather than
            // flatten it to `exit::FAILED`, exactly as the held path preserves `held.signal`.
            use std::os::unix::process::ExitStatusExt;
            let (exit_code, signal, code) = match fallback.status() {
                Ok(s) => (s.code(), s.signal(), s.code().unwrap_or(exit::FAILED)),
                Err(e) => {
                    eprintln!("buildclamp: could not run the compiler: {e}");
                    (Some(exit::FAILED), None, exit::FAILED)
                }
            };
            let record = buildclamp_core::UnitRecord {
                id,
                kind: UnitKind::Compile.into(),
                source: None,
                instance: None,
                envelope,
                tiers: unheld_tiers,
                // The unheld compile inherited the FULL parent environment: `fallback` is built
                // without the scrubbed set, matching this function's other passthrough paths, so
                // nothing was removed from it. Recording `scrubbed` here would be the same class
                // of overclaim this record exists to prevent — a report saying credential names
                // were stripped from a process that in fact received them.
                env_scrubbed: Vec::new(),
                // Nothing was observed because nothing was held to observe it. The list of
                // proc-macros that could have run is kept, though — it is the whole of the
                // attribution available for what an unheld expansion might have done.
                observed: std::iter::empty::<Capability>().collect(),
                requests: Vec::new(),
                proc_macros_in_closure: proc_macros.into_iter().map(|(_, id)| id).collect(),
                exit_code,
                signal,
                duration_ms: started.elapsed().as_millis() as u64,
            };
            if let Err(e) = run.write_unit(&record) {
                eprintln!("buildclamp: could not record that this compilation ran unheld: {e}");
                return exit::FAILED;
            }
            return code;
        }
    };

    let record = buildclamp_core::UnitRecord {
        id,
        kind: UnitKind::Compile.into(),
        source: None,
        instance: None,
        envelope,
        tiers: held.tiers.clone(),
        env_scrubbed: scrubbed,
        observed: held
            .requests
            .iter()
            .filter_map(|r| r.capability.copied())
            .collect(),
        requests: held.requests.clone(),
        // The macros that could have been responsible for anything this compilation did.
        // Not a claim about which one: see this function's own documentation.
        proc_macros_in_closure: proc_macros.into_iter().map(|(_, id)| id).collect(),
        exit_code: held.exit_code,
        signal: held.signal,
        duration_ms: started.elapsed().as_millis() as u64,
    };
    if let Err(e) = run.write_unit(&record) {
        eprintln!("buildclamp: could not record what this compilation did: {e}");
        return exit::FAILED;
    }
    held.exit_code.unwrap_or(exit::FAILED)
}

/// Replace this process with the command. Never returns on success.
fn passthrough(cmd: &mut Command) -> i32 {
    use std::os::unix::process::CommandExt;
    let err = cmd.exec();
    eprintln!("buildclamp: could not run the compiler: {err}");
    exit::FAILED
}

/// Run the command to completion and return its status.
fn passthrough_status(cmd: &mut Command) -> i32 {
    match cmd.status() {
        Ok(s) => s.code().unwrap_or(exit::FAILED),
        Err(e) => {
            eprintln!("buildclamp: could not run the compiler: {e}");
            exit::FAILED
        }
    }
}

// --- the driver ----------------------------------------------------------------------

fn run_driver(rest: Vec<OsString>) -> i32 {
    let mut argv = vec![OsString::from("cargo buildclamp")];
    argv.extend(rest);
    let cli = match args::Cli::try_parse_from(&argv) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() {
                exit::FAILED
            } else {
                exit::OK
            };
        }
    };

    match cli.command {
        args::Command::Doctor(a) => doctor(a),
        args::Command::Selftest(a) => selftest(a),
        args::Command::Unhook(a) => {
            let layout = driver::Layout::resolve(None, None);
            let dir = a.target_dir.unwrap_or(layout.target_dir);
            match buildclamp_shim::unsweep(&dir) {
                Ok(n) => {
                    println!(
                        "buildclamp: restored {n} build script(s) in {}",
                        dir.display()
                    );
                    exit::OK
                }
                Err(e) => {
                    eprintln!("buildclamp: {e}");
                    exit::FAILED
                }
            }
        }
        args::Command::Explain(a) => explain(a),
        args::Command::Report(a) => report(a),
        args::Command::Init(a) => init(a),
        args::Command::Except(a) => except(a),
        args::Command::Verify(a) => verify(a),
        args::Command::Policy(a) => match a.what {
            args::PolicyAction::Migrate(m) => policy_migrate(m),
        },
        ref c @ (args::Command::Build(_)
        | args::Command::Check(_)
        | args::Command::Test(_)
        | args::Command::Bench(_)
        | args::Command::Doc(_)
        | args::Command::Install(_)
        | args::Command::Publish(_)
        | args::Command::Clippy(_)
        | args::Command::Observe(_)) => {
            let sub = c.cargo_subcommand().expect("these all run cargo");
            let common = c.cargo_args().expect("these all take cargo args").clone();
            let (mode, gate) = match c {
                args::Command::Observe(o) => (Mode::Observe, o.gate),
                _ => (Mode::Enforce, false),
            };
            // The kill switch outranks the subcommand. `cargo buildclamp build` with
            // `BUILDCLAMP_MODE=off` in the environment is somebody disabling the tool
            // without editing their pipeline, which is the situation it exists for; making
            // them also change the command would defeat it.
            let mode = match std::env::var(buildclamp_core::ENV_MODE).as_deref() {
                Ok("off") => Mode::Off,
                _ => mode,
            };
            // Publishing is the one verb here with an outward, irreversible effect, so
            // what it costs on this host is said before cargo starts and
            // `--require-enforced` is answered before the upload rather than after it.
            if sub == "publish" && !driver::warn_before_publishing(common.require_enforced) {
                return exit::UNGRANTED;
            }
            let deep = common.deep;
            build(sub, common, mode, deep, gate)
        }
    }
}

/// Load a policy and everything it extends.
///
/// Every error — an unreadable extends, a cycle, a layer that contradicts a ceiling's
/// declaration, a bad grant — is caught here, before a single unit runs. A policy problem
/// discovered halfway through a build would leave a target directory in a state nobody
/// chose.
fn load_policy(
    path: &Path,
    require_signed: bool,
) -> Result<(buildclamp_core::Stack, buildclamp_core::PolicyProvenance), i32> {
    if !path.exists() {
        // No policy is a legitimate state: it is what `observe` runs against on the first
        // day in a repository that has never seen this tool. Nothing to verify, so the
        // provenance is the empty default (signature not verified, because there is no
        // policy whose authority could have been).
        return Ok((
            buildclamp_core::Stack::single(Policy::empty()),
            buildclamp_core::PolicyProvenance::default(),
        ));
    }
    let (stack, sources) = driver::load_stack_sources(path).map_err(|e| {
        eprintln!("buildclamp: {e}");
        exit::FAILED
    })?;
    // Composed here, before anything else happens. Per-unit resolution would first notice a
    // ceiling violation inside the launcher — a separate process, halfway through a build,
    // with a target directory already half written — and every other policy error in this
    // tool is caught before a single unit runs.
    stack.check().map_err(|e| {
        eprintln!("buildclamp: {e}");
        exit::FAILED
    })?;
    // Signature verification is the same class of pre-build check: a distributed layer whose
    // authority is not established under `--require-signed-policy` fails here, before cargo,
    // not after a target directory is half written.
    let provenance =
        driver::verify_policy_signatures(&stack, &sources, require_signed).map_err(|e| {
            eprintln!("buildclamp: {e}");
            exit::FAILED
        })?;
    Ok((stack, provenance))
}

/// `cargo buildclamp doctor`, with an optional declared enforcement floor.
///
/// Three exit codes, and which one a lane gets is the point of the command:
///
/// * `0` — the host meets the floor, or none was declared;
/// * `1` — the floor itself could not be understood. A typo is the tool failing to do its
///   job, not an answer about the machine, and treating it as `2` would make a
///   misspelled requirement look like a host that fell short;
/// * `2` — the host does not reach what the lane said it needed.
fn doctor(a: args::DoctorArgs) -> i32 {
    let host = buildclamp_sandbox::probe::host();

    // Parsed BEFORE the host is reported on, so a lane with a typo in its floor is told
    // so immediately rather than after a page of output it is not going to act on.
    let floor = match a.require.as_deref().map(buildclamp_core::Floor::parse) {
        Some(Ok(f)) => Some(f),
        Some(Err(e)) => {
            eprintln!("buildclamp: {e}");
            return exit::FAILED;
        }
        None => None,
    };

    if a.json {
        // The same `HostCapabilities` that goes into `report.json`, so a consumer that
        // already parses a report needs no second schema for the host — plus the tiers
        // those capabilities project to.
        //
        // The tiers are ADDED beside the host fields rather than nesting them under a
        // `host` key, and that is a compatibility decision rather than a stylistic one:
        // every existing reader of this output, including this project's own end-to-end
        // guard, indexes `user_namespaces` at the top level, and a reshuffle would make
        // each of them silently stop finding it. An additive key cannot.
        //
        // They belong here at all because the tier ladder is this tool's central claim and
        // `doctor` is where somebody goes to check it before trusting a green build. A
        // consumer that had to run the enforcement to find out what it would reach would
        // be measuring a build rather than a host.
        let mut doc = serde_json::to_value(&host)
            .expect("HostCapabilities is a plain struct of owned scalars");
        if let Some(map) = doc.as_object_mut() {
            let tiers: std::collections::BTreeMap<String, buildclamp_core::Tier> =
                buildclamp_sandbox::projected_tiers(&host)
                    .into_iter()
                    .map(|(c, t)| (c.to_string(), t))
                    .collect();
            map.insert(
                "tiers".into(),
                serde_json::to_value(tiers).expect("a tier is a plain enum of owned strings"),
            );
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).expect("the document was just built from values")
        );
    } else {
        print!("{}", render::doctor(&host));
    }

    let Some(floor) = floor else {
        return exit::OK;
    };
    let unmet = floor.unmet(&buildclamp_sandbox::projected_tiers(&host));
    if unmet.is_empty() {
        return exit::OK;
    }
    // To stderr even under `--json`, so a lane that pipes stdout into a parser still sees
    // why it failed rather than only an exit code.
    eprint!("{}", render::unmet_floor(&unmet));
    exit::UNGRANTED
}

/// `cargo buildclamp selftest --no-network`.
///
/// Runs a command inside the same envelope a build script gets, with the network denied,
/// and fails if anything in it asked for the network. The default command is this binary,
/// so the check is about the artefact in front of you rather than about a dependency
/// graph — `ops/no-network-closure.sh` is the one that reads the graph, and the two prove
/// different halves of the same claim.
///
/// Exit codes are the usual three: `0` clean, `2` the network was asked for, `1` the check
/// could not be carried out — a host with no enforcement, or a command that would not
/// start. **A host that cannot enforce is a `1` and never a `0`.** A selftest that passed
/// because nothing was watching would be the false assurance this whole tool exists to
/// prevent, inside its own self-check.
fn selftest(a: args::SelftestArgs) -> i32 {
    if !a.no_network {
        eprintln!(
            "buildclamp: selftest needs a check to run. Today there is one: \
             `cargo buildclamp selftest --no-network`."
        );
        return exit::FAILED;
    }

    let command: Vec<String> = if a.command.is_empty() {
        let me = match driver::self_path() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("buildclamp: cannot find my own binary: {e}");
                return exit::FAILED;
            }
        };
        vec![
            me.display().to_string(),
            "buildclamp".into(),
            "doctor".into(),
            "--json".into(),
        ]
    } else {
        a.command.clone()
    };

    let host = buildclamp_sandbox::probe::host();
    if !host.user_namespaces && !host.seccomp_user_notif {
        eprintln!(
            "buildclamp: this host can neither create a network namespace nor answer a \
             seccomp notification, so nothing here could refuse a connection and a pass \
             would mean nothing. Run `cargo buildclamp doctor` to see what is missing."
        );
        return exit::FAILED;
    }

    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    // Scrubbed like a real held unit. The check is about the network, but a self-check
    // that handed the command a set of credentials a build script would never see would
    // be testing something other than the envelope it claims to test.
    let envelope = buildclamp_core::Envelope::build_script_default();
    let (kept, _) = buildclamp_core::scrub(
        std::env::vars_os(),
        &envelope,
        &buildclamp_core::DEFAULT_ENV_DENY
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>(),
        false,
    );
    cmd.env_clear();

    let plan = buildclamp_sandbox::Plan {
        allow_net: false,
        // Unix sockets too. A check that denied `AF_INET` and left `AF_UNIX` open would
        // pass a binary talking to the docker socket, which is the credential surface the
        // two capabilities were split apart to keep visible.
        allow_unix: false,
        writable: Vec::new(),
        withheld_reads: Vec::new(),
        private_tmp: None,
        env: kept,
        observe_writes: false,
        observe_only: false,
        proc_macro_objects: Vec::new(),
        skip_exec_target: None,
    };

    // The command keeps its own stdout rather than having it captured, so a user-supplied
    // one can be debugged — but it is announced first, or the default command's `doctor
    // --json` reads as this command's output and says `user_namespaces: false` two lines
    // above a tier of `enforced:netns`. Both are true: the inner report describes the
    // held child, which is inside a namespace it cannot nest another one in.
    println!("selftest --no-network: holding `{}`", command.join(" "));
    println!("--- the command's own output follows ---");

    let held = match plan.hold(cmd) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("buildclamp: could not hold the command for the selftest: {e}");
            return exit::FAILED;
        }
    };
    println!("--- end of the command's output ---\n");

    let net: Vec<&buildclamp_core::Request> = held
        .requests
        .iter()
        .filter(|r| {
            matches!(
                r.capability.copied(),
                Some(buildclamp_core::Capability::Net | buildclamp_core::Capability::Unix)
            )
        })
        .collect();

    // The tier is printed with the result, never separately. A pass under `none` is not a
    // pass, and the number that says so has to travel with the claim — the same rule the
    // report follows for every capability.
    let tier = held
        .tiers
        .get(&buildclamp_core::Forward::Known(
            buildclamp_core::Capability::Net,
        ))
        .map_or_else(|| "absent".to_string(), buildclamp_core::Tier::label);

    println!("  network tier {tier}");
    println!("  exit code    {:?}", held.exit_code);

    if !net.is_empty() {
        println!("  ! {} network request(s):", net.len());
        for r in &net {
            println!("      {} {} {}", r.capability, r.syscall, r.target);
        }
        println!(
            "\n  This binary asked for the network while doing its ordinary work. \
             \n  If that is buildclamp itself, the artefact boundary in ADR-0005 is broken."
        );
        return exit::UNGRANTED;
    }

    // The claim below is specifically that the *network* was kernel-enforced, so the evidence
    // must be the network tiers — both of them. `values().any(is_enforced)` accepted any
    // enforced tier, so an enforced filesystem tier on a host whose net/unix were only
    // advisory would let the self-test report the network as kernel-enforced. Check Net AND
    // Unix directly.
    let enforced = |cap| {
        held.tiers
            .get(&buildclamp_core::Forward::Known(cap))
            .is_some_and(buildclamp_core::Tier::is_enforced)
    };
    if !(enforced(buildclamp_core::Capability::Net) && enforced(buildclamp_core::Capability::Unix))
    {
        eprintln!(
            "  ! the network was not kernel-enforced on this host — `net` and `unix` must both \
             be `enforced` — so the absence of a network request is not evidence. Refusing to \
             report a pass."
        );
        return exit::FAILED;
    }

    if held.exit_code != Some(0) {
        eprintln!(
            "  ! the command did not succeed, so it may simply not have got as far as \
             the network. Refusing to report a pass."
        );
        return exit::FAILED;
    }

    println!("\n  no network request, enforced by the kernel on this host.");
    exit::OK
}

fn build(sub: &str, common: args::CargoArgs, mode: Mode, deep: bool, gate: bool) -> i32 {
    let layout = driver::Layout::resolve(common.policy.as_deref(), common.report.as_deref());
    let (stack, provenance) = match load_policy(&layout.policy, common.require_signed_policy) {
        Ok(s) => s,
        Err(code) => return code,
    };
    // The nearest layer is the last word on everything that is a decision about THIS run
    // rather than about a crate: the mode, the off switch, and break-glass. An org layer
    // that could carry an exception would be breaking glass on forty repositories from a
    // file none of their engineers read.
    let policy = &stack.nearest().policy;

    // A policy that disables enforcement outranks the subcommand, exactly as the
    // environment switch does. Same effect, same record in the report, different set of
    // people able to reach it: this one needs commit access.
    let mode = match policy.enforcement {
        Some(buildclamp_core::Enforcement::Disabled) => Mode::Off,
        None => mode,
    };
    // Resolved BEFORE cargo starts, like every other policy error. The two checks it
    // makes — an expiry more than a week out, and more live blocks than the cap allows —
    // are relative to today, so they cannot live in `parse`; but a run refused halfway
    // through a build would leave a target directory in a state nobody chose, so they
    // happen here rather than when the exit code is worked out.
    let today = buildclamp_core::Date::parse(&today()).expect("`today` is YYYY-MM-DD");
    let glass = match policy.break_glass(today) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("buildclamp: {}: {e}", layout.policy.display());
            return exit::FAILED;
        }
    };

    let mut outcome = match driver::run(
        sub,
        &common.cargo_args,
        &stack,
        &provenance,
        &layout,
        mode,
        deep,
        today,
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("buildclamp: {e}");
            return exit::FAILED;
        }
    };

    // Written into the document, not only onto the terminal. A run that exited 0 because
    // somebody broke the glass has to say so where a job summary, a fleet store or an
    // auditor reads, and the terminal scrolls away.
    outcome.report.break_glass = outcome.report.break_glass_uses(&glass);

    if let Err(e) = driver::write_report(&outcome.report, &layout.report) {
        eprintln!("buildclamp: could not write the report: {e}");
        return exit::FAILED;
    }

    let mut out = std::io::stdout().lock();
    let _ = write!(out, "{}", render::summary(&outcome.report, false));
    if outcome.swept > 0 {
        // Said out loud because it means those units were compiled before buildclamp was
        // involved, and a reader should know the tool had to catch up rather than
        // intercept.
        let _ = writeln!(
            out,
            "  {} build script(s) were already compiled and have been held retroactively",
            outcome.swept
        );
    }
    let _ = writeln!(out, "  report: {}", layout.report.display());

    // Printed BEFORE the cargo-status check, and this ordering is the whole value of the
    // block. A build whose units were refused is one cargo fails, so the early return
    // below used to swallow every break-glass line — including "the exception for `x`
    // expired on <date>", which is exactly what the person whose build just went red
    // needs and is worthless once the run has exited.
    let grace = common.grace.map(|days| buildclamp_core::Grace {
        today,
        days: i64::from(days),
    });
    // Across EVERY layer. A grant nobody has read is a grant nobody has read whichever
    // file it is in, and the org layer's grants apply to forty repositories at once.
    let unreviewed = stack.unreviewed(grace, &glass);
    let _ = write!(
        out,
        "{}",
        render::break_glass(
            &glass,
            &outcome.report.break_glass,
            &unreviewed,
            &layout.policy
        )
    );

    // Cargo's own failure comes first: a build that did not compile is not a policy
    // answer, and reporting it as one would send someone looking in the wrong place.
    match outcome.cargo_status {
        Some(0) => {}
        Some(_) | None => {
            // …unless the reason cargo failed was a unit we refused, which the launcher
            // reported with exit code 2 and one line of stderr cargo has already printed.
            //
            // An exception does not un-fail this. The kernel already refused the syscall
            // and the unit already died: break-glass decides what the *run* exits with,
            // not what a build script got back, and a cargo that failed for any reason is
            // still a build that did not compile. Saying otherwise would make `except` a
            // flag that appears to work and produces no artefact.
            if outcome.report.unexcused_ungranted(&glass).next().is_some() {
                return exit::UNGRANTED;
            }
            return exit::FAILED;
        }
    }

    if outcome.report.units.is_empty() {
        // Cargo found everything fresh, so no build unit ran and the policy was not
        // exercised. Saying so matters: an empty report reads exactly like a clean one,
        // and someone checking a gate deserves to know it measured nothing.
        let _ = writeln!(
            out,
            "  note: no build units ran — cargo found everything fresh. The policy was \n             \x20       not exercised by this run."
        );
    }

    // `gate` is passed through rather than short-circuited here: an observe run with
    // --gate must fail on a request enforcement would have refused, and that decision
    // belongs with the rest of the exit-code contract in `Report::exit_code`.
    let policy_code = outcome.report.exit_code(&buildclamp_core::Verdict {
        require_enforced: common.require_enforced,
        unreviewed_grants: if common.strict { unreviewed.count() } else { 0 },
        gate_observed: gate,
        glass,
    });
    if mode == Mode::Observe && !gate {
        return exit::OK;
    }
    policy_code
}

fn explain(a: args::ExplainArgs) -> i32 {
    let layout = driver::Layout::resolve(a.policy.as_deref(), None);
    // `explain` answers "what envelope would this crate get"; it runs no build and refuses
    // nothing, so it never requires a signature and ignores the provenance.
    let (stack, _provenance) = match load_policy(&layout.policy, false) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let policy = &stack.nearest().policy;
    let id = buildclamp_core::UnitId::new(
        &a.crate_name,
        a.version.clone().unwrap_or_else(|| "0.0.0".into()),
    );
    // With break-glass applied, because `explain` answers "what envelope would this crate
    // get", and an answer that left out a live exception would be wrong in the permissive
    // direction on exactly the days somebody is most likely to ask.
    let today = buildclamp_core::Date::parse(&today()).expect("`today` is YYYY-MM-DD");
    let glass = match policy.break_glass(today) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("buildclamp: {}: {e}", layout.policy.display());
            return exit::FAILED;
        }
    };
    let envelope = match stack.resolve_with(
        &id,
        buildclamp_core::UnitKind::BuildScriptCompile,
        false,
        &glass,
    ) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("buildclamp: {e}");
            return exit::FAILED;
        }
    };
    let withheld = if a.env {
        let patterns = policy.env_deny();
        // `vars_os`, not `vars`: the latter panics on a non-Unicode name or value, and a name
        // that is not Unicode cannot match a `&str` deny pattern anyway, so dropping the
        // undecodable ones loses nothing this list could have reported.
        std::env::vars_os()
            .filter_map(|(k, _)| k.into_string().ok())
            .filter(|k| {
                patterns
                    .iter()
                    .any(|p| buildclamp_core::policy::env_name_matches(p, k))
            })
            .filter(|k| !envelope.env_allow.iter().any(|a| a.eq_ignore_ascii_case(k)))
            .collect()
    } else {
        Vec::new()
    };
    print!(
        "{}",
        render::explain(&a.crate_name, a.version.as_deref(), &envelope, &withheld)
    );
    if let Some(e) = glass.naming(&a.crate_name) {
        print!("{}", render::explain_exception(e));
    }
    exit::OK
}

fn report(a: args::ReportArgs) -> i32 {
    let layout = driver::Layout::resolve(None, a.from.as_deref());
    let text = match std::fs::read_to_string(&layout.report) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "buildclamp: no report at {} ({e}). Run `cargo buildclamp observe` first.",
                layout.report.display()
            );
            return exit::FAILED;
        }
    };
    if a.json {
        print!("{text}");
        return exit::OK;
    }
    match buildclamp_core::Report::from_json(&text) {
        Ok(r) => {
            if a.markdown {
                print!("{}", render::markdown(&r, &layout.report));
            } else {
                print!("{}", render::summary(&r, a.all));
            }
            exit::OK
        }
        Err(e) => {
            eprintln!(
                "buildclamp: the report at {} did not parse: {e}",
                layout.report.display()
            );
            exit::FAILED
        }
    }
}

fn init(a: args::InitArgs) -> i32 {
    let layout = driver::Layout::resolve(None, a.from.as_deref());
    let out = a.out.clone().unwrap_or_else(|| layout.policy.clone());

    let text = match std::fs::read_to_string(&layout.report) {
        Ok(t) => t,
        Err(_) => {
            eprintln!(
                "buildclamp: no report at {}. Run `cargo buildclamp observe` first — it \
                 records what your build does without refusing anything.",
                layout.report.display()
            );
            return exit::FAILED;
        }
    };
    let report: buildclamp_core::Report = match buildclamp_core::Report::from_json(&text) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("buildclamp: the report did not parse: {e}");
            return exit::FAILED;
        }
    };

    if out.exists() && !a.force && !a.stdout {
        // Overwriting a reviewed policy with generated grants — every one of them
        // `reviewed = false` — would undo exactly the work the file exists to record.
        eprintln!(
            "buildclamp: {} already exists. Pass --force to overwrite it, or --stdout to \
             see what would be written. Overwriting replaces reviewed grants with \
             unreviewed ones.",
            out.display()
        );
        return exit::FAILED;
    }

    // Read before anything is generated, so a baseline that does not exist or does not
    // parse stops the command rather than producing a policy in which nothing happens to
    // have been accepted — which is what "nothing matched" also looks like.
    let baseline = match a.accept_baseline.as_deref() {
        None => None,
        Some(path) => match read_baseline(path) {
            Ok(b) => Some(b),
            Err(code) => return code,
        },
    };
    let (generated, acceptance) = buildclamp_core::policy_from_report_accepting(
        &report,
        &today(),
        baseline.as_ref().map(|(b, digest)| (b, digest.as_str())),
    );
    let toml = match toml::to_string_pretty(&generated) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("buildclamp: could not render the policy: {e}");
            return exit::FAILED;
        }
    };
    let body = format!(
        "# Written by `cargo buildclamp init` from {report}.\n\
         #\n\
         # Every grant below says what was OBSERVED, not why it is acceptable. Replace\n\
         # each `why` with the real reason and set `reviewed = true`. Until then,\n\
         # `cargo buildclamp build --strict` will refuse to pass.\n\
         #\n\
         # A project with many grants is a correctly configured project.\n\n{toml}",
        report = layout.report.display()
    );

    if a.stdout {
        print!("{body}");
        return exit::OK;
    }
    match std::fs::write(&out, body) {
        Ok(()) => {
            print!(
                "{}",
                render::init_summary(&out, generated.grants.len(), &acceptance)
            );
            exit::OK
        }
        Err(e) => {
            eprintln!("buildclamp: could not write {}: {e}", out.display());
            exit::FAILED
        }
    }
}

/// `cargo buildclamp policy migrate` — rewrite a policy at the current format version.
///
/// # What it does and does not change
///
/// The version number, and nothing else. There is no semantic difference between a version
/// 1 policy and the version 2 this writes: composition is opt-in through a `[layer]` table,
/// and a migration that invented one would be choosing an organisation's file layout on its
/// behalf. So this is a one-line edit somebody could make by hand, and it exists so that
/// nobody has to wonder whether it is.
///
/// It **checks** that, rather than asserting it. The migrated text is parsed back and every
/// grant is re-resolved against the original, and a difference is a refusal rather than a
/// file somebody has to notice. A migration that silently changed an envelope would be the
/// worst thing this command could do, because the whole reason to run it is to stop
/// thinking about the format.
fn policy_migrate(a: args::MigrateArgs) -> i32 {
    let layout = driver::Layout::resolve(a.policy.as_deref(), None);
    let path = layout.policy;
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("buildclamp: could not read {}: {e}", path.display());
            return exit::FAILED;
        }
    };
    let before = match Policy::parse(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("buildclamp: {}: {e}", path.display());
            return exit::FAILED;
        }
    };

    let declared = Policy::declared_version(&text);
    if declared == Some(buildclamp_core::POLICY_VERSION) {
        println!(
            "buildclamp: {} is already version {}. Nothing to do.",
            path.display(),
            buildclamp_core::POLICY_VERSION
        );
        return exit::OK;
    }

    let rendered = match toml::to_string_pretty(&before) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("buildclamp: could not render the migrated policy: {e}");
            return exit::FAILED;
        }
    };

    // Parsed back and compared, before anything is written. A migration that changed an
    // envelope would break a build for a reason the diff does not show, on the one command
    // somebody runs precisely so they can stop thinking about the format.
    match Policy::parse(&rendered) {
        Ok(after) => {
            if let Some(difference) = first_envelope_difference(&before, &after) {
                eprintln!(
                    "buildclamp: refusing to migrate {}: the rewritten policy resolves a \
                     different envelope for `{difference}`.\n  \
                     This is a bug in buildclamp, not in your file. Nothing has been \
                     written. Please report it with the policy attached.",
                    path.display()
                );
                return exit::FAILED;
            }
        }
        Err(e) => {
            eprintln!(
                "buildclamp: refusing to migrate {}: the rewritten policy does not parse \
                 ({e}). This is a bug in buildclamp, not in your file. Nothing has been \
                 written.",
                path.display()
            );
            return exit::FAILED;
        }
    }

    if a.stdout {
        print!("{rendered}");
        return exit::OK;
    }
    if let Err(e) = std::fs::write(&path, &rendered) {
        eprintln!("buildclamp: could not write {}: {e}", path.display());
        return exit::FAILED;
    }
    println!(
        "buildclamp: {} migrated from version {} to {}.\n\
         \n  Read the diff before committing. The rewrite goes through the parser and the\n  \
         serialiser, so comments and key order do not survive it — which is why this is a\n  \
         command you run once rather than something a build does for you.\n\
         \n  Nothing about your policy's meaning changed, and buildclamp checked that\n  \
         before writing: every grant resolves the same envelope it did.\n",
        path.display(),
        declared
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unversioned".into()),
        buildclamp_core::POLICY_VERSION
    );
    exit::OK
}

/// The first crate whose envelope differs between two policies, if any.
///
/// Over every crate either policy names, under both unit kinds, workspace member and not.
/// It cannot cover a crate neither file mentions — those resolve to the defaults on both
/// sides by construction — and it does not need to.
fn first_envelope_difference(before: &Policy, after: &Policy) -> Option<String> {
    let mut names: Vec<&String> = before.grants.keys().chain(after.grants.keys()).collect();
    names.sort();
    names.dedup();
    for name in names {
        for version in ["0.0.0", "0.1.3", "1.0.0", "2.5.9"] {
            let id = buildclamp_core::UnitId::new(name, version);
            for kind in [UnitKind::BuildScriptCompile, UnitKind::Compile] {
                for member in [false, true] {
                    let a = before.resolve(&id, kind, member);
                    let b = after.resolve(&id, kind, member);
                    match (a, b) {
                        (Ok(a), Ok(b)) if a == b => {}
                        (Err(_), Err(_)) => {}
                        _ => return Some(name.clone()),
                    }
                }
            }
        }
    }
    None
}

/// `cargo buildclamp verify` — check an attestation, and say which half was checked.
///
/// The signature is not checked here and the output says so on every run, pass or fail. A
/// verifier that printed "verified" for half a verification would be the overstatement this
/// project is organised against, and it would be making it about the one document people
/// quote at auditors.
fn verify(a: args::VerifyArgs) -> i32 {
    let document = match std::fs::read_to_string(&a.file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("buildclamp: could not read {}: {e}", a.file.display());
            return exit::FAILED;
        }
    };

    // Hashed here rather than taken as hex on the command line: a flag carrying a digest is
    // a flag somebody pastes the wrong value into, and the whole question is whether the
    // file in front of you is the one the statement is about.
    let digest = |path: &Path| -> Result<String, i32> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(buildclamp_core::sha256::hex(&bytes)),
            Err(e) => {
                eprintln!("buildclamp: could not read {}: {e}", path.display());
                Err(exit::FAILED)
            }
        }
    };
    let artefact = match a.artefact.as_deref().map(digest).transpose() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let policy = match a.policy.as_deref().map(digest).transpose() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let report = match a.report.as_deref().map(digest).transpose() {
        Ok(v) => v,
        Err(code) => return code,
    };

    let mut errata = Vec::new();
    for path in &a.errata {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("buildclamp: could not read {}: {e}", path.display());
                return exit::FAILED;
            }
        };
        // An erratum that does not parse is a hard failure, never a skip. A verifier that
        // quietly ignored a correction it could not read would report a statement as good
        // on the strength of a file saying it is not.
        match serde_json::from_str::<buildclamp_core::Erratum>(&text) {
            Ok(e) => errata.push(e),
            Err(e) => {
                eprintln!(
                    "buildclamp: {} is not an erratum: {e}\n  \
                     Refusing to continue: an erratum this could not read is a correction \
                     it would have ignored.",
                    path.display()
                );
                return exit::FAILED;
            }
        }
    }

    let verified = match buildclamp_core::verify_statement(
        &document,
        artefact.as_deref(),
        policy.as_deref(),
        report.as_deref(),
        &errata,
        // Today, for the format-version sunset: a v1 statement stops verifying on its stated
        // date, and this is the one place with a clock to compare against.
        buildclamp_core::Date::parse(&today()).expect("`today` is YYYY-MM-DD"),
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("buildclamp: {e}");
            return exit::UNGRANTED;
        }
    };

    print!("{}", render::verified(&verified, &a));

    if a.require_fully_enforced && !verified.is_fully_enforced() {
        return exit::UNGRANTED;
    }
    exit::OK
}

/// A baseline document and the digest of the bytes it was read as.
///
/// The digest is over the file exactly as it sits on disk, not over a re-serialised copy:
/// what it has to identify is the document a reader can go and fetch.
fn read_baseline(path: &Path) -> Result<(buildclamp_core::Baseline, String), i32> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("buildclamp: could not read {}: {e}", path.display());
            return Err(exit::FAILED);
        }
    };
    let text = match String::from_utf8(bytes.clone()) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("buildclamp: {} is not UTF-8 text", path.display());
            return Err(exit::FAILED);
        }
    };
    match buildclamp_core::Baseline::parse(&text) {
        Ok(b) => Ok((b, buildclamp_core::sha256::tagged(&bytes))),
        Err(e) => {
            eprintln!("buildclamp: {}: {e}", path.display());
            Err(exit::FAILED)
        }
    }
}

/// `cargo buildclamp except` — the 17:00 unblock.
///
/// Appends a validated `[[exception]]` block. Appends, rather than round-tripping the
/// policy through the TOML serialiser, and that is not laziness: `buildclamp.toml` is a
/// file people write by hand and comment, and a re-serialise would return it with every
/// comment gone and every table reordered. The one command somebody runs under pressure
/// must not be the one that mangles the file they were about to commit.
///
/// It refuses rather than writes whenever the result would not parse — no reason, no
/// identity, a capability that is not a capability, an expiry past the cap, or one
/// exception too many. A command that wrote a block the next build would reject would
/// have turned one red build into two.
fn except(a: args::ExceptArgs) -> i32 {
    let layout = driver::Layout::resolve(a.policy.as_deref(), None);
    let today = buildclamp_core::Date::parse(&today()).expect("`today` is YYYY-MM-DD");

    if a.reason.trim().is_empty() {
        eprintln!(
            "buildclamp: --reason is required, and it is the one field this command \
             cannot fill in for you. Not what the crate does — the grant's `why` is for \
             that — but what happened today, and where the work went."
        );
        return exit::FAILED;
    }

    let days = i64::from(a.days);
    if !(1..=buildclamp_core::MAX_EXCEPTION_DAYS).contains(&days) {
        eprintln!(
            "buildclamp: --days must be between 1 and {}. A week covers an incident; \
             anything longer is a decision, and a decision belongs in a grant somebody \
             reviewed.",
            buildclamp_core::MAX_EXCEPTION_DAYS
        );
        return exit::FAILED;
    }

    // Parsed here rather than left to the policy parser, so a typo is caught before the
    // file is touched and is named next to the list of what it could have been.
    let mut capabilities = Vec::new();
    for name in &a.capabilities {
        match name.parse::<buildclamp_core::Capability>() {
            Ok(c) => capabilities.push(c),
            Err(_) => {
                eprintln!(
                    "buildclamp: `{name}` is not a capability. They are: {}.",
                    buildclamp_core::Capability::ALL
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                return exit::FAILED;
            }
        }
    }

    // Narrowed from the run that just went red, when there is one. This is what keeps the
    // broad form — an exception naming no capabilities, which grants all of them — as the
    // fallback rather than the usual case: the report sitting in the target directory
    // already says which requests were refused, and the person at 17:00 should not have to
    // read it to find out.
    if capabilities.is_empty() {
        capabilities = refused_capabilities(&layout.report, &a.crate_name);
        if !capabilities.is_empty() {
            println!(
                "buildclamp: narrowing this exception to {} — what `{}` was actually \
                 refused in the last run. Pass --capability to override.",
                capabilities
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                a.crate_name
            );
        }
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let author = match a.author.clone().or_else(|| runmeta::git_identity(&cwd)) {
        Some(who) => who,
        None => {
            eprintln!(
                "buildclamp: git has no identity configured here, so there is no name to \
                 put on this exception. Set one (`git config user.email you@example.com`) \
                 or pass --author. It is not verified and does not pretend to be — what \
                 makes an exception accountable is that it is a committed block with a \
                 diff and an expiry — but one with nobody's name on it is one nobody owns."
            );
            return exit::FAILED;
        }
    };

    let block = render_exception(
        &a.crate_name,
        &capabilities,
        today.plus_days(days),
        &a.reason,
        &author,
    );

    // Checked by parsing the WHOLE file as it would be after the write, rather than by
    // checking the block alone. The cap on how many may be live is a property of the
    // file, and the only honest way to know whether this write crosses it is to try it.
    let existing = std::fs::read_to_string(&layout.policy).unwrap_or_default();
    let candidate = if existing.trim().is_empty() {
        format!("{NEW_POLICY_HEADER}{block}")
    } else {
        format!("{}\n{block}", existing.trim_end())
    };
    match Policy::parse(&candidate).and_then(|p| p.break_glass(today).map(|_| ())) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("buildclamp: this exception would not be accepted: {e}");
            return exit::FAILED;
        }
    }

    if a.stdout {
        print!("{block}");
        return exit::OK;
    }
    if let Err(e) = std::fs::write(&layout.policy, &candidate) {
        eprintln!(
            "buildclamp: could not write {}: {e}",
            layout.policy.display()
        );
        return exit::FAILED;
    }
    println!(
        "buildclamp: `{}` is excused until {} — appended to {}.\n\
         \n  Commit it: the diff is what makes this visible, and it is the only thing \
         that does.\n  It stops applying on {}, with no edit and no reminder.\n",
        a.crate_name,
        today.plus_days(days),
        layout.policy.display(),
        today.plus_days(days).plus_days(1)
    );
    exit::OK
}

/// What the last run refused this crate, so an exception can be as narrow as the incident.
///
/// Empty when there is no report, when it does not parse, or when that crate had no
/// refusal in it — all three of which are ordinary. An exception written from an empty
/// answer names no capabilities and therefore grants all of them, which is the honest
/// reading: nothing here knows what broke, so nothing here may claim to have narrowed it.
///
/// A capability the report carries that this build has no name for is skipped rather than
/// guessed at. It cannot be written into a policy — the file's capability list is a closed
/// enum — and an exception that quietly dropped it while claiming to be narrow would be
/// narrower than the incident.
fn refused_capabilities(report_path: &Path, crate_name: &str) -> Vec<buildclamp_core::Capability> {
    let Ok(text) = std::fs::read_to_string(report_path) else {
        return Vec::new();
    };
    let Ok(report) = buildclamp_core::Report::from_json(&text) else {
        return Vec::new();
    };
    let mut out: Vec<buildclamp_core::Capability> = Vec::new();
    for u in report.units.iter().filter(|u| u.id.name == crate_name) {
        for r in u.ungranted() {
            if let buildclamp_core::Forward::Known(c) = r.capability {
                if !out.contains(&c) {
                    out.push(c);
                }
            }
        }
    }
    out.sort();
    out
}

/// The header a policy gets when `except` is the first thing to create one.
///
/// Break-glass before a policy exists is an ordinary case rather than a strange one: the
/// default envelope refuses the network to every crate, so a repository with no
/// `buildclamp.toml` at all can go red on the first enforcing run.
const NEW_POLICY_HEADER: &str = "\
# Written by `cargo buildclamp except`, which found no policy to append to.
#
# An exception stands a refusal down for one crate until a date. It is not a grant and
# it is not a review: when it lapses, this build goes red again for the same reason it
# went red today. `cargo buildclamp observe` then `init` is what writes the grant.
version = 1

";

fn render_exception(
    crate_name: &str,
    capabilities: &[buildclamp_core::Capability],
    expires: buildclamp_core::Date,
    reason: &str,
    author: &str,
) -> String {
    let mut out = String::from("\n[[exception]]\n");
    out.push_str(&format!("crate = {}\n", toml_string(crate_name)));
    if !capabilities.is_empty() {
        let names: Vec<String> = capabilities
            .iter()
            .map(|c| toml_string(c.as_str()))
            .collect();
        out.push_str(&format!("capabilities = [{}]\n", names.join(", ")));
    }
    out.push_str(&format!("expires = \"{expires}\"\n"));
    out.push_str(&format!("reason = {}\n", toml_string(reason)));
    out.push_str(&format!("author = {}\n", toml_string(author)));
    out
}

/// One TOML basic string, escaped.
///
/// `toml::Value::to_string` would do this, and it is two lines to do it here without
/// constructing a value whose rendering has to be trusted to match what the parser will
/// read back. The candidate file is re-parsed before it is written, so an escape this got
/// wrong is caught rather than committed — but getting it right first is cheaper than
/// explaining the refusal.
fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Today, as `YYYY-MM-DD`.
///
/// Computed here rather than in `buildclamp-core`, which is pure and has no clock: a
/// generator that reached for the wall clock could not be tested by comparing its output
/// to a fixed string.
fn today() -> String {
    // Civil-date arithmetic from the epoch, rather than a `chrono` dependency for one
    // line. This is Howard Hinnant's `civil_from_days`.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let z = secs / 86_400 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_date_helper_agrees_with_known_epoch_values() {
        // A wrong date in a generated `why` is a small thing that makes every other claim
        // in the file look sloppy, so the arithmetic is pinned rather than trusted.
        fn civil(secs: i64) -> String {
            let z = secs / 86_400 + 719_468;
            let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
            let doe = z - era * 146_097;
            let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
            let y = yoe + era * 400;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let d = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            let y = if m <= 2 { y + 1 } else { y };
            format!("{y:04}-{m:02}-{d:02}")
        }
        assert_eq!(civil(0), "1970-01-01");
        assert_eq!(civil(1_000_000_000), "2001-09-09");
        // A leap day, which is where this arithmetic usually goes wrong.
        assert_eq!(civil(1_709_164_800), "2024-02-29");
    }

    #[test]
    fn todays_date_is_well_formed() {
        let t = today();
        assert_eq!(t.len(), 10, "{t}");
        assert!(t.chars().filter(|c| *c == '-').count() == 2, "{t}");
    }
}
