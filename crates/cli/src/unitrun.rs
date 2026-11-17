//! The launcher: what runs when a shimmed build script is executed.
//!
//! This is where the three crates meet. `buildclamp-core` says what the unit may do,
//! `buildclamp-shim` turns that into paths, and `buildclamp-sandbox` makes a kernel
//! enforce it. Everything this module does is arrange for that meeting and write down
//! what happened.
//!
//! # Cargo hides this process's stderr unless it fails
//!
//! Cargo captures a build script's stderr and shows it **only** when the unit exits
//! non-zero. So there are exactly two channels out of here:
//!
//! * the JSON record, written to the run directory, which the driver reads afterwards;
//! * on the failure path only, **one** well-formed message on stderr — which cargo then
//!   prints, and which is the entire developer experience of a refusal.
//!
//! Nothing else is printed. A launcher that chattered on the success path would put its
//! own noise inside what cargo shows as the crate's output the next time something broke.

use std::path::PathBuf;
use std::process::Command;

use buildclamp_core::{envscrub, Capability, Mode, Policy, UnitId, UnitKind, UnitRecord};
use buildclamp_sandbox::Plan;
use buildclamp_shim::paths::UnitContext;
use buildclamp_shim::RunDir;

use crate::render;

/// Everything the launcher recovers from its environment.
///
/// All of it comes from cargo at **run** time. None of it is derived from where the
/// binary sits: the shim lives in `build/<pkg>-<hashA>/` while `OUT_DIR` is
/// `build/<pkg>-<hashB>/out`, and inferring one from the other would grant the wrong
/// directory to every unit.
#[derive(Debug)]
pub struct LaunchContext {
    pub id: UnitId,
    pub manifest_dir: Option<PathBuf>,
    pub out_dir: Option<PathBuf>,
    pub run_dir: PathBuf,
    pub policy_path: PathBuf,
    pub is_workspace_member: bool,
    /// The basename of `OUT_DIR`'s parent, which cargo guarantees unique per run of a
    /// build script. Without it, the same script running twice under `--target` produces
    /// one record instead of two.
    pub instance: Option<String>,
    pub mode_override: Option<Mode>,
    /// `observe --deep`: record granted writes too, not only refused ones.
    pub deep: bool,
    /// The day the *driver* started, so every unit in one run answers the same calendar
    /// question about an exception's expiry. `None` means no exception can apply — see
    /// [`buildclamp_core::ENV_TODAY`] for why that is the fail-closed reading.
    pub today: Option<buildclamp_core::Date>,
}

impl LaunchContext {
    pub fn from_env() -> Option<Self> {
        let out_dir = std::env::var_os("OUT_DIR").map(PathBuf::from);
        let name = std::env::var("CARGO_PKG_NAME").ok()?;
        let is_workspace_member = crate::driver::is_workspace_member();
        Some(Self {
            id: UnitId::new(
                name,
                std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into()),
            ),
            manifest_dir: std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from),
            instance: out_dir
                .as_ref()
                .and_then(|p| p.parent())
                .and_then(|p| p.file_name())
                .map(|s| s.to_string_lossy().into_owned()),
            out_dir,
            run_dir: std::env::var_os(buildclamp_core::ENV_RUN_DIR).map(PathBuf::from)?,
            policy_path: std::env::var_os(buildclamp_core::ENV_POLICY).map(PathBuf::from)?,
            is_workspace_member,
            mode_override: match std::env::var(buildclamp_core::ENV_MODE).as_deref() {
                Ok("observe") => Some(Mode::Observe),
                Ok("enforce") => Some(Mode::Enforce),
                Ok("off") => Some(Mode::Off),
                _ => None,
            },
            deep: std::env::var_os(buildclamp_core::ENV_DEEP).is_some(),
            today: std::env::var(buildclamp_core::ENV_TODAY)
                .ok()
                .as_deref()
                .and_then(buildclamp_core::Date::parse),
        })
    }
}

/// Run the real build script with nothing held, for `BUILDCLAMP_MODE=off`.
///
/// Deliberately not `env_clear()` and not a `Plan`: the point of the kill switch is that
/// the unit runs exactly as it would if buildclamp were not installed at all. A
/// "passthrough" that still scrubbed the environment would be a fourth enforcement mode
/// wearing the word off, and the person who reached for it at 3am would find their build
/// still failing for a reason the switch promised to remove.
///
/// No record is written here. The launcher is one process among many and the run is not
/// its to describe; the driver writes the report that says enforcement was off, and it
/// writes it whether or not any unit reached this function.
fn passthrough_unheld(real: &std::path::Path, args: &[std::ffi::OsString]) -> i32 {
    match Command::new(real).args(args).status() {
        Ok(st) => st.code().unwrap_or(buildclamp_core::exit::FAILED),
        Err(e) => {
            eprintln!(
                "buildclamp: could not run {} with enforcement off: {e}",
                real.display()
            );
            buildclamp_core::exit::FAILED
        }
    }
}

/// Run one build script under its envelope. Returns the exit code this process should use.
pub fn launch(ctx: LaunchContext, real: &std::path::Path, args: &[std::ffi::OsString]) -> i32 {
    // The kill switch, in the third and last role that could hold anything. Checked
    // before the policy is even read: a person reaching for the emergency exit may be
    // reaching for it *because* the policy is what broke, and making the exit depend on
    // parsing that policy would be the cruellest possible ordering.
    if ctx.mode_override == Some(Mode::Off) {
        return passthrough_unheld(real, args);
    }
    // The whole STACK, not just the file the environment names. A launcher that resolved
    // against the nearest layer alone would hold every unit to the repository's grants and
    // silently ignore the ceiling the organisation set — which is the one failure mode
    // layering exists to prevent, arriving in the one process that does the holding.
    let stack = if ctx.policy_path.exists() {
        match crate::driver::load_stack(&ctx.policy_path) {
            Ok(s) => s,
            // A policy that does not compose must have stopped the driver long before any
            // unit ran. Reaching here means something replaced a file mid-build, and the
            // only safe reading of that is the strictest one.
            Err(e) => {
                eprintln!("buildclamp: the policy became unreadable during the build: {e}");
                return buildclamp_core::exit::FAILED;
            }
        }
    } else {
        buildclamp_core::Stack::single(Policy::empty())
    };
    let policy = stack.nearest().policy.clone();

    let mode = ctx.mode_override.unwrap_or(policy.defaults.mode);
    // Re-derived here rather than passed as a resolved set, because this process re-parses
    // the policy anyway and a second encoding of the same blocks is a second thing that
    // can disagree with the file. The driver has already refused the file if a block runs
    // past the bound or the cap, so anything that survives to here is one it accepted;
    // with no date in the environment nothing applies at all.
    let glass = ctx
        .today
        .and_then(|today| policy.break_glass(today).ok())
        .unwrap_or_default();
    let envelope = match stack.resolve_with(
        &ctx.id,
        UnitKind::BuildScriptCompile,
        ctx.is_workspace_member,
        &glass,
    ) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("buildclamp: {e}");
            return buildclamp_core::exit::FAILED;
        }
    };

    let run = match RunDir::open(&ctx.run_dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("buildclamp: could not open the run directory: {e}");
            return buildclamp_core::exit::FAILED;
        }
    };

    let unit_ctx = UnitContext {
        out_dir: ctx.out_dir.clone(),
        manifest_dir: ctx.manifest_dir.clone(),
        target_dir: None,
        run_dir: Some(ctx.run_dir.clone()),
    };
    let paths = buildclamp_shim::resolve_zones(&envelope, &unit_ctx);
    for d in paths.writable.iter().chain(paths.private_tmp.iter()) {
        // Created here rather than left to the unit: a directory that does not exist
        // cannot be granted to a mount namespace, and a build script that had to create
        // its own temp directory before it could use one would fail on the first write.
        let _ = std::fs::create_dir_all(d);
    }

    // The fourth argument used to be a literal `false`, which made
    // `env-allow-secrets = true` unable to do the one thing it exists for: re-admit a
    // HARD_DENY name. The envelope carries the grant's opt-in now, so the decision is
    // made where the policy said it should be.
    let (kept, scrubbed) = envscrub::scrub(
        std::env::vars_os(),
        &envelope,
        &policy.env_deny(),
        envelope.env_allow_secrets,
    );

    let mut command = Command::new(real);
    command.args(args);
    command.env_clear();
    if let Some(dir) = &ctx.manifest_dir {
        // Cargo runs a build script with cwd set to its manifest directory, and a script
        // that reads a relative path — most code generators do — breaks without it.
        command.current_dir(dir);
    }

    let dests = destinations(&envelope);
    let plan = Plan {
        allow_net: dests.allow_net,
        allow_unix: envelope.permits(Capability::Unix),
        writable: paths.writable.clone(),
        withheld_reads: withheld_reads(&policy, &envelope),
        read_allowed: read_allowed(
            &envelope,
            ctx.manifest_dir.as_deref(),
            ctx.out_dir.as_deref().and_then(profile_dir_of).as_deref(),
        ),
        private_tmp: paths.private_tmp.clone(),
        env: kept,
        // `observe --deep`. Without it, writes are notified only when there is no
        // kernel-enforced filesystem tier to fall back on — see the `observe_writes`
        // expression in buildclamp_sandbox's linux::hold, which ORs this with
        // `observe_only` and "no namespace". So on a host with a mount namespace this is
        // the only way to see the writes a unit made that the policy already permitted.
        observe_writes: ctx.deep,
        observe_only: mode == Mode::Observe,
        proc_macro_objects: Vec::new(),
        skip_exec_target: Some(real.to_path_buf()),
        // Write xor execute: nothing the unit can write may be run, except from the zones
        // its grant named in `exec-zones`. A grant without `exec` refuses every exec.
        deny_exec: !envelope.permits(Capability::Exec),
        no_exec: paths.writable.clone(),
        exec_allowed: buildclamp_shim::resolve_exec_zones(&envelope, &unit_ctx),
        // A build script loads nothing it wrote: no exemption from the noexec mount.
        load_allowed: Vec::new(),
        net_allowed: dests.allowed,
        hosts: dests.hosts,
    };

    let started = std::time::Instant::now();
    let held = plan.hold(command);
    let held = match held {
        Ok(h) => h,
        Err(e) => {
            // Refusing to run rather than running unheld. This is the property that
            // distinguishes buildclamp from a sandbox that quietly disables itself, so it
            // fails the unit loudly instead of producing a clean report.
            eprintln!("buildclamp: {e}");
            return buildclamp_core::exit::FAILED;
        }
    };

    let record = UnitRecord {
        id: ctx.id.clone(),
        kind: UnitKind::BuildScriptCompile.into(),
        source: None,
        instance: ctx.instance.clone(),
        envelope: envelope.clone(),
        tiers: held.tiers.clone(),
        env_scrubbed: scrubbed,
        observed: observed_from(&held.requests),
        requests: held.requests.clone(),
        proc_macros_in_closure: Vec::new(),
        exit_code: held.exit_code,
        signal: held.signal,
        duration_ms: started.elapsed().as_millis() as u64,
    };

    if let Err(e) = run.write_unit(&record) {
        // A record that could not be written would make the report silently short, and a
        // missing unit reads exactly like a clean one. Fail rather than hide it.
        eprintln!("buildclamp: could not record what `{}` did: {e}", ctx.id);
        return buildclamp_core::exit::FAILED;
    }

    let ungranted = record.ungranted().count();
    if mode == Mode::Enforce && ungranted > 0 {
        // The one message cargo will show. It has to answer "which dependency, and what
        // did it try to do" without any other context being visible.
        eprint!("{}", render::refusal_line(&record));
        // Non-zero even when the script itself exited 0. A build script that swallowed the
        // refusal — caught the error, carried on, exited cleanly — must not be reported as
        // clean, because swallowing it is exactly what a deliberately malicious one does.
        return buildclamp_core::exit::UNGRANTED;
    }

    held.exit_code.unwrap_or(buildclamp_core::exit::FAILED)
}

/// The credential paths this unit may not read.
///
/// Empty in two cases, and they are not the same one. The policy may not be withholding
/// anything — the default, and the behaviour every version of this tool has had. Or the
/// unit's grant may carry `fs-read`, which re-admits the whole withheld set for that crate
/// and is the escape hatch for a build script that genuinely needs a credential, such as
/// one authenticating to a private registry. Either way the read bits are not handled by
/// the ruleset, so the kernel restricts nothing and a build that has not asked for this
/// pays nothing.
///
/// `HOME` is read here rather than in `buildclamp-core` because core has no environment
/// and is not getting one. A unit with no `HOME` gets an empty set: every entry in the
/// default list is home-relative, so there is nothing to withhold — and the tier then says
/// the policy withheld no reads, which is true rather than reassuring.
pub(crate) fn withheld_reads(
    policy: &buildclamp_core::Policy,
    envelope: &buildclamp_core::Envelope,
) -> Vec<std::path::PathBuf> {
    // The read allowlist withholds these too: a `read-paths` entry over part of the home
    // directory can contain one, and an allowlist that handed it back would be weaker than
    // the deny-list it is meant to improve on. These are home-relative paths: a credential
    // file inside the workspace is not among them, and the README says so.
    if !(policy.defaults.withhold_secret_reads || envelope.read_allowlist)
        || envelope.permits(Capability::FsRead)
    {
        return Vec::new();
    }
    let Some(home) = std::env::var_os("HOME") else {
        return Vec::new();
    };
    // `Path::new(&home)`, not `home.to_string_lossy()`: a non-Unicode HOME must reach
    // `expand` byte-for-byte, or the withheld paths would name a different directory and leave
    // the real credential files readable.
    buildclamp_core::withhold::expand(std::path::Path::new(&home))
        .into_iter()
        .map(|(p, _)| p)
        .collect()
}

/// The roots a unit may read beneath under `read-allowlist`, or none when it is off or the
/// unit's grant lists `fs-read` (which reads everything).
///
/// `profile_dir` is the target profile directory (`target/debug`): build scripts read the
/// `OUT_DIR`s of the crates they depend on (`DEP_*_INCLUDE`), and rustc reads `deps/`.
/// Writable zones need no entry here — a write zone is readable by construction.
pub(crate) fn read_allowed(
    envelope: &buildclamp_core::Envelope,
    manifest_dir: Option<&std::path::Path>,
    profile_dir: Option<&std::path::Path>,
) -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    if !envelope.read_allowlist || envelope.permits(Capability::FsRead) {
        return Vec::new();
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut roots: Vec<PathBuf> = [
        "/usr",
        "/lib",
        "/lib32",
        "/lib64",
        "/libx32",
        "/bin",
        "/sbin",
        "/etc",
        "/proc",
        "/sys",
        "/dev",
        "/nix/store",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    // The cargo home's dependency sources and binaries, never the cargo home itself: it
    // holds `credentials.toml`, the token that publishes as you.
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".cargo")));
    if let Some(c) = cargo_home {
        roots.extend(["registry", "git", "bin"].iter().map(|s| c.join(s)));
    }
    roots.extend(
        std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|h| h.join(".rustup"))),
    );
    roots.extend(crate::driver::workspace_member_dirs_from_env());
    roots.extend(manifest_dir.map(std::path::Path::to_path_buf));
    roots.extend(profile_dir.map(std::path::Path::to_path_buf));
    for p in &envelope.read_paths {
        match (p.strip_prefix("~/"), &home) {
            (Some(rest), Some(h)) => roots.push(h.join(rest)),
            (Some(_), None) => {} // no home to resolve against: grant nothing, fail closed
            (None, _) => roots.push(PathBuf::from(p)),
        }
    }
    roots
}

/// The target profile directory an `OUT_DIR` sits in: the parent of its `build` ancestor,
/// in both cargo layouts (`build/<pkg>-<hash>/out` and, from 1.100, `build/<pkg>/<hash>/out`).
pub(crate) fn profile_dir_of(out_dir: &std::path::Path) -> Option<std::path::PathBuf> {
    // `build` sits at a fixed depth in each layout, told apart by whether the unit directory
    // is a bare 16-hex hash. Searching upward for the first `build` would stop at a package
    // that is itself named `build` (`build/build/<hash>/out`).
    if out_dir.file_name()? != "out" {
        return None;
    }
    let unit = out_dir.parent()?;
    let bare_hash = unit
        .file_name()?
        .to_str()
        .is_some_and(|n| n.len() == 16 && n.bytes().all(|b| b.is_ascii_hexdigit()));
    let build = if bare_hash {
        unit.parent()?.parent()?
    } else {
        unit.parent()?
    };
    if build.file_name()? != "build" {
        return None;
    }
    build.parent().map(std::path::Path::to_path_buf)
}

/// What a grant's `net-destinations` becomes for the sandbox.
pub(crate) struct Destinations {
    /// May the unit have the whole network? False when it has a destination list.
    pub allow_net: bool,
    /// The resolved addresses the supervisor may connect to for it.
    pub allowed: Vec<std::net::SocketAddr>,
    /// The hosts file contents that make the listed names resolve inside the namespace.
    pub hosts: Option<String>,
}

/// Resolve a grant's `net-destinations` here, on the host's network, at the moment the unit
/// starts: the unit's own namespace has no resolver, and a name resolved now is not a CDN
/// address written into a policy months ago.
///
/// `net` without destinations is the whole network, as it always was. `net` with them is
/// those destinations and nothing else. A destination that does not resolve is reported and
/// left out, which fails closed: connections to it are refused.
pub(crate) fn destinations(envelope: &buildclamp_core::Envelope) -> Destinations {
    use std::net::{SocketAddr, ToSocketAddrs};
    let allow_net = envelope.permits(Capability::Net);
    if !allow_net || envelope.net_destinations.is_empty() {
        return Destinations {
            allow_net,
            allowed: Vec::new(),
            hosts: None,
        };
    }
    let mut allowed: Vec<SocketAddr> = Vec::new();
    // Only the listed names, at the addresses they resolved to here, and the loopback name.
    // A name the unit could resolve to an address it may not reach would only turn its first
    // connection attempt into a refusal.
    let mut hosts = String::from("127.0.0.1 localhost\n");
    for d in &envelope.net_destinations {
        if let Ok(a) = d.parse::<SocketAddr>() {
            allowed.push(a);
            continue;
        }
        let resolved: Vec<SocketAddr> = d
            .rsplit_once(':')
            .and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?)))
            .and_then(|hp| hp.to_socket_addrs().ok())
            .map(Iterator::collect)
            .unwrap_or_default();
        if resolved.is_empty() {
            eprintln!(
                "buildclamp: net-destination `{d}` did not resolve; connections to it will be refused"
            );
            continue;
        }
        let host = d.rsplit_once(':').map(|(h, _)| h).unwrap_or(d);
        for a in &resolved {
            hosts.push_str(&format!("{} {host}\n", a.ip()));
        }
        allowed.extend(resolved);
    }
    allowed.sort();
    allowed.dedup();
    // Contents, not a file: the sandbox makes it unnamed, out of every unit's reach.
    Destinations {
        allow_net: false,
        allowed,
        hosts: Some(hosts),
    }
}

/// The capability set a unit actually exercised, for observe mode and drift.
fn observed_from(requests: &[buildclamp_core::Request]) -> buildclamp_core::CapabilitySet {
    // A capability this build does not recognise cannot enter the bitmask — there is no
    // bit for it — so it is left out here and remains visible in the request stream and in
    // `Report::unknown_names`, which is what keeps the omission from being silent.
    requests
        .iter()
        .filter_map(|r| r.capability.copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profile_directory_is_found_in_both_layouts_even_for_a_package_named_build() {
        use std::path::{Path, PathBuf};
        for (out, want) in [
            ("/t/debug/build/serde-1a2b3c4d5e6f7a8b/out", "/t/debug"),
            ("/t/debug/build/serde/1a2b3c4d5e6f7a8b/out", "/t/debug"),
            ("/t/debug/build/build/1a2b3c4d5e6f7a8b/out", "/t/debug"),
            ("/t/release/build/build-1a2b3c4d5e6f7a8b/out", "/t/release"),
        ] {
            assert_eq!(
                profile_dir_of(Path::new(out)),
                Some(PathBuf::from(want)),
                "{out}"
            );
        }
        assert_eq!(profile_dir_of(Path::new("/t/debug/deps")), None);
    }

    #[test]
    fn the_instance_discriminator_comes_from_out_dirs_parent() {
        // Cargo guarantees `build/<pkg>-<hash>/out` is unique per run of a build script,
        // and that hash is the only thing distinguishing the two runs of one script under
        // --target. Deriving it from anything else loses one of the records.
        let out = PathBuf::from("/proj/target/debug/build/libc-b8458491/out");
        let instance = out
            .parent()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().into_owned());
        assert_eq!(instance.as_deref(), Some("libc-b8458491"));
    }

    #[test]
    fn the_observed_set_is_what_the_unit_asked_for_not_what_it_was_granted() {
        // `init` generates a policy from this, so folding in the envelope would make the
        // generated grants describe the defaults rather than the build.
        let reqs = vec![
            buildclamp_core::Request {
                at_ms: 1,
                tid: 1,
                capability: Capability::Net.into(),
                syscall: "connect".into(),
                target: "x".into(),
                outcome: buildclamp_core::Outcome::Ungranted { errno: 1 },
                attribution: buildclamp_core::Attribution::Unit,
            },
            buildclamp_core::Request {
                at_ms: 2,
                tid: 1,
                capability: Capability::Exec.into(),
                syscall: "execve".into(),
                target: "/usr/bin/cc".into(),
                outcome: buildclamp_core::Outcome::Granted,
                attribution: buildclamp_core::Attribution::Unit,
            },
        ];
        let set = observed_from(&reqs);
        assert!(set.contains(Capability::Net));
        assert!(set.contains(Capability::Exec));
        assert!(!set.contains(Capability::FsWrite));
    }
}
