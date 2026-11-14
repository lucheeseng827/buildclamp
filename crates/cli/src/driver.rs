//! The driver: what happens when a person types `cargo buildclamp build`.
//!
//! Four steps, and the second one is the reason this module is not three lines:
//!
//! 1. **Scrub this process's own environment.** Removing a secret from a build script's
//!    environment does nothing about the copy in the environment of the cargo process
//!    that spawned it, which any process of the same user can read through `/proc`. So
//!    the driver drops them before exec'ing cargo, which takes every process in the build
//!    tree out of the exposure set. The developer's shell is still readable, and only a
//!    user namespace closes that — measured: `CLONE_NEWPID` alone leaves the read
//!    working, `CLONE_NEWUSER` alone makes it `EPERM`. `doctor` says which you have.
//! 2. **Sweep the target directory.** Cargo does not put `RUSTC_WRAPPER` in a
//!    fingerprint, so a target directory ever populated by a plain build keeps its
//!    compiled build scripts un-shimmed forever and the wrapper never sees them. Without
//!    this step the tool reports success while enforcing nothing on most real
//!    repositories.
//! 3. Run cargo with the wrapper and the run directory set.
//! 4. Read the run directory back and assemble the report.

use std::path::{Path, PathBuf};
use std::process::Command;

use buildclamp_core::{Mode, Policy, Report};
use buildclamp_shim::RunDir;

/// Where a run's files live, all under the target directory so `cargo clean` removes them.
#[derive(Clone, Debug)]
pub struct Layout {
    pub target_dir: PathBuf,
    pub run_dir: PathBuf,
    pub report: PathBuf,
    pub policy: PathBuf,
}

impl Layout {
    pub fn resolve(explicit_policy: Option<&Path>, explicit_report: Option<&Path>) -> Self {
        let root = workspace_root();
        let target_dir = target_dir(root.as_deref());
        Self {
            run_dir: target_dir.join("buildclamp").join("run"),
            report: explicit_report
                .map(Path::to_path_buf)
                .unwrap_or_else(|| target_dir.join("buildclamp").join("report.json")),
            // With no workspace there is no `buildclamp.toml` to find, and the path named
            // here is one that will not exist — which `load_policy` reads as the empty
            // policy, so an install outside a project runs on the defaults. That is the
            // right answer: default-deny is what you want holding a crate you have not
            // read, and there is no repository here whose policy could have said otherwise.
            policy: explicit_policy
                .map(Path::to_path_buf)
                .unwrap_or_else(|| root.unwrap_or_else(scratch_root).join("buildclamp.toml")),
            target_dir,
        }
    }
}

/// The workspace root, from `cargo locate-project`.
///
/// Asked of cargo rather than guessed by walking upwards for a `Cargo.toml`, because a
/// workspace member has one too and the policy belongs beside the workspace's.
///
/// `None` when there is no workspace here at all. That is not an error and not a rare
/// case: `cargo buildclamp install ripgrep` is run from wherever you happen to be
/// standing, and installing a tool from the registry is the reason that subcommand
/// exists. See [`scratch_root`] for where a run with no workspace puts its files.
fn workspace_root() -> Option<PathBuf> {
    let out = Command::new(cargo())
        .args(["locate-project", "--workspace", "--message-format", "plain"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let p = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
    p.parent().map(Path::to_path_buf)
}

/// Where a run with no workspace around it puts its run directory and report.
///
/// A temporary directory, and **not** `./target`, which is what this used to fall back to.
/// The fallback was invisible while every subcommand needed a workspace to do anything;
/// `install` does not, and `cargo buildclamp install ripgrep` run from a home directory
/// would have created `~/target/buildclamp/` there. A build tool that leaves a `target`
/// directory in someone's home is a build tool they uninstall.
///
/// It is not `$CARGO_HOME` either, tempting as that is for a global act like an install:
/// reports would accumulate there forever with nothing to clean them up, and the rule this
/// layout is built on — everything under a directory `cargo clean` removes — has no
/// equivalent there. A temporary directory is honest about the lifetime, and the driver
/// prints the report's path on every run, so it is findable while it matters.
fn scratch_root() -> PathBuf {
    // One directory per process, created once and returned the same on every call within a
    // run (both the policy-path fallback and `target_dir` reach for it). The old fixed
    // `$TMPDIR/buildclamp-scratch` was predictable and world-reachable, and three things
    // followed on a shared or CI host: another user could pre-create and own it, failing the
    // run for a reason nobody could see; a group- or world-readable one held the report,
    // which carries the repository URL, run identifiers and scrubbed variable names; and two
    // concurrent no-workspace runs shared one run directory, so one read the other's records.
    // A fresh, owner-only directory per process closes all three.
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(create_scratch_root).clone()
}

fn create_scratch_root() -> PathBuf {
    create_owner_only_temp_dir("buildclamp-scratch")
}

/// A fresh, owner-only directory in the system temp, named unpredictably.
///
/// pid *and* the wall-clock nanosecond, so the name is not one another user can predict and
/// pre-create — and `0700` means even a lucky guess is a directory they cannot read. Shared
/// by the no-workspace scratch root (which holds the report) and the trusted macro inventory
/// (which must sit outside every sandbox-writable zone).
fn create_owner_only_temp_dir(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    dir
}

fn target_dir(root: Option<&Path>) -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(d) => PathBuf::from(d),
        None => match root {
            Some(r) => r.join("target"),
            None => scratch_root(),
        },
    }
}

pub fn cargo() -> PathBuf {
    std::env::var_os("CARGO")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cargo"))
}

/// Whether the crate cargo is currently building belongs to the workspace being built.
///
/// Identity is the crate's **manifest directory** (`CARGO_MANIFEST_DIR`), matched against the
/// member directories the driver wrote to the trusted file named by
/// [`buildclamp_core::ENV_WORKSPACE_MEMBERS`] — not the package name. Two packages can share a
/// name (a workspace member and a registry dependency of the same name), and a name match would
/// classify that dependency as first-party under `trust-workspace` and run its build script
/// unheld. A directory is unique: a registry dependency lives under `~/.cargo/registry`, never
/// inside the workspace, so a colliding name cannot fool this. The driver exports the set
/// because `CARGO_PRIMARY_PACKAGE` marks only the command-line-selected packages — an unselected
/// member compiled as a dependency of the selected one does not carry it and would otherwise
/// resolve as third-party.
///
/// The list is passed by **file path**, not inline, because a large monorepo's member set can
/// exceed a single environment entry's `MAX_ARG_STRLEN` limit (128 KiB) and fail `execve` with
/// `E2BIG` before cargo starts. The file sits outside every sandbox-writable path, so a held
/// unit cannot forge its own membership. An absent variable or an unreadable file both mean "no
/// reliable member list" and fall back to the primary-package signal — the prior behaviour that
/// never breaks a build. When the list is present but `CARGO_MANIFEST_DIR` is not, membership
/// cannot be confirmed, so this answers non-member: `trust-workspace` must never widen trust to
/// a crate it cannot place.
pub(crate) fn is_workspace_member() -> bool {
    let list = std::env::var_os(buildclamp_core::ENV_WORKSPACE_MEMBERS)
        .and_then(|p| std::fs::read_to_string(p).ok());
    let Some(list) = list else {
        return std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some();
    };
    match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => member_listed(&list, &dir),
        Err(_) => false,
    }
}

/// The membership decision itself, split from the environment so it is testable without
/// setting a process variable — which needs `unsafe` in the 2024 edition and races every
/// sibling test that reads `environ`. `manifest_dir` is one entry to test against the
/// newline-separated member directories, matched whole so `/w/a` never matches `/w/ab`.
fn member_listed(list: &str, manifest_dir: &str) -> bool {
    list.split('\n').any(|m| !m.is_empty() && m == manifest_dir)
}

/// The manifest directories of the packages in the workspace being built, one per line, from
/// `cargo metadata` — or `None` when it cannot be produced.
///
/// Directories, not names, because the wrapper matches them against `CARGO_MANIFEST_DIR` to
/// tell a first-party crate from a same-named dependency (see [`is_workspace_member`]).
/// `--no-deps` so it resolves only the workspace and makes no network request, and the
/// `--manifest-path` the run itself was given (if any) so metadata resolves the SAME workspace
/// cargo is about to build. Without it a `cargo buildclamp build --manifest-path other/` would
/// classify against the current directory's workspace instead — marking that build's own members
/// third-party. Best-effort: a failure returns `None` and the wrappers fall back to
/// `CARGO_PRIMARY_PACKAGE`, so a metadata error never fails the build it was only trying to
/// classify.
fn workspace_member_dirs(manifest_path: Option<&str>) -> Option<String> {
    let mut cmd = Command::new(cargo());
    cmd.args(["metadata", "--no-deps", "--format-version", "1"]);
    if let Some(path) = manifest_path {
        cmd.args(["--manifest-path", path]);
    }
    let out = cmd.stderr(std::process::Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_member_dirs(&out.stdout)
}

/// The value of `--manifest-path` in a cargo argument list, in either the `--manifest-path X` or
/// the `--manifest-path=X` form, so workspace-member discovery can resolve the manifest the run
/// is actually building rather than whichever one sits in the current directory.
fn manifest_path_from(cargo_args: &[String]) -> Option<&str> {
    let mut it = cargo_args.iter();
    while let Some(a) = it.next() {
        if a == "--manifest-path" {
            return it.next().map(String::as_str);
        }
        if let Some(rest) = a.strip_prefix("--manifest-path=") {
            return Some(rest);
        }
    }
    None
}

/// The manifest directories of the workspace members out of `cargo metadata`'s JSON, split
/// from the subprocess so the parse is testable against a fixture.
///
/// A package is a member when its `id` is one of `workspace_members`; the two are matched as
/// whole strings, so the exact spelling of a package id (which has changed across cargo
/// versions) never matters — both sides come from the same document. Each member's directory is
/// the parent of its `manifest_path`, which is what cargo also exports as `CARGO_MANIFEST_DIR`
/// when it builds that crate, so the two compare byte-for-byte on either side.
fn parse_member_dirs(metadata_json: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(metadata_json).ok()?;
    let members: std::collections::BTreeSet<&str> = v
        .get("workspace_members")?
        .as_array()?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let dirs: Vec<&str> = v
        .get("packages")?
        .as_array()?
        .iter()
        .filter(|p| {
            p.get("id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|id| members.contains(id))
        })
        .filter_map(|p| {
            p.get("manifest_path")
                .and_then(serde_json::Value::as_str)
                .and_then(manifest_dir_of)
        })
        .collect();
    if dirs.is_empty() {
        None
    } else {
        Some(dirs.join("\n"))
    }
}

/// The directory of a `Cargo.toml` path — a crate's manifest directory. Trimmed at the last
/// `/` rather than via `Path::parent` so the value stays byte-identical to the `manifest_path`
/// cargo wrote and thus to the `CARGO_MANIFEST_DIR` it exports for the same crate.
fn manifest_dir_of(manifest_path: &str) -> Option<&str> {
    manifest_path.rfind('/').map(|i| &manifest_path[..i])
}

/// This executable, as an absolute path.
///
/// The shim embeds it, and cargo will run that shim from a different working directory
/// later, so a relative path would break the moment anything changed directory.
pub fn self_path() -> std::io::Result<PathBuf> {
    std::env::current_exe()
}

/// What a run produced.
#[derive(Debug)]
pub struct RunOutcome {
    pub report: Report,
    /// Cargo's own exit status, kept separate from the policy's answer so a build failure
    /// and a refusal are never confused.
    pub cargo_status: Option<i32>,
    pub swept: usize,
}

/// Load a policy and everything it extends, nearest last.
///
/// # Why the walking happens here and the composing happens in core
///
/// `buildclamp-core` is pure: no I/O, no clock, no cargo. So the paths, the cycle check and
/// the reading live here, where the filesystem is, and the composition rule lives there,
/// where the policy semantics are and where it can be tested with no files at all.
///
/// A relative `extends` resolves against **the file that names it**, never against the
/// working directory. The working directory is wherever cargo happened to be invoked from,
/// and a policy that meant different things depending on which subdirectory you ran the
/// build in would be a policy nobody could reason about.
pub fn load_stack(path: &Path) -> Result<buildclamp_core::Stack, StackError> {
    Ok(load_stack_sources(path)?.0)
}

/// The bytes and location of one loaded layer, kept so its detached signature can be checked
/// against the trust root without re-reading the file (which a concurrent edit could change
/// between the two reads).
pub struct LayerSource {
    /// The layer's name, aligned with the [`buildclamp_core::Layer`] at the same index.
    pub name: String,
    /// The canonical path the layer was read from — where its `<path>.sig` sidecar lives.
    pub path: PathBuf,
    /// The exact bytes a signature would be over.
    pub bytes: Vec<u8>,
}

/// Load a stack and keep each layer's bytes and path, so signatures can be verified.
///
/// The sources are in the same order as the stack's layers — nearest (the committed anchor)
/// last — so `sources.last()` is the anchor, the one layer that is never signature-checked.
pub fn load_stack_sources(
    path: &Path,
) -> Result<(buildclamp_core::Stack, Vec<LayerSource>), StackError> {
    let mut layers = Vec::new();
    let mut sources = Vec::new();
    let mut seen = Vec::new();
    load_into(path, &mut layers, &mut sources, &mut seen)?;
    let stack = buildclamp_core::Stack::new(layers).map_err(StackError::Policy)?;
    Ok((stack, sources))
}

/// Verify each distributed layer's detached signature against the committed anchor's trust
/// root, and under `require` refuse a build whose distributed policy is not signed.
///
/// The signature for a layer at `<path>` is a base64 sidecar at `<path>.sig`. The anchor —
/// the repository's own committed policy, `sources.last()` — is trusted because it is
/// committed and is never checked here; it is also where the trust root is read from. No
/// network request is made: every byte verified was already on disk when the stack loaded.
pub fn verify_policy_signatures(
    stack: &buildclamp_core::Stack,
    sources: &[LayerSource],
    require: bool,
) -> Result<buildclamp_core::PolicyProvenance, buildclamp_core::SignedPolicyError> {
    let root =
        buildclamp_core::TrustRoot::from_base64_keys(&stack.nearest().policy.defaults.trust_root)
            .unwrap_or_default();
    // Read each sidecar once, into owned bytes the LayerSignature list can borrow.
    let sigs: Vec<Option<Vec<u8>>> = sources
        .iter()
        .map(|s| read_detached_signature(&s.path))
        .collect();
    let anchor_index = sources.len().saturating_sub(1);
    let layers: Vec<buildclamp_core::LayerSignature> = sources
        .iter()
        .zip(&sigs)
        .enumerate()
        .map(|(i, (src, sig))| buildclamp_core::LayerSignature {
            name: &src.name,
            is_anchor: i == anchor_index,
            bytes: &src.bytes,
            signature: sig.as_deref(),
        })
        .collect();
    buildclamp_core::check_layers(&layers, &root, require)
}

/// Read and decode a `<path>.sig` sidecar, if one exists and is a well-formed signature.
///
/// A missing sidecar is `None` — an unsigned layer, which is only fatal under
/// `--require-signed-policy`. A malformed sidecar is also `None`: a signature that does not
/// decode cannot verify, so it is the same outcome as no signature, surfaced by the layer
/// failing to verify rather than by a parse error that would read as a different problem.
fn read_detached_signature(path: &Path) -> Option<Vec<u8>> {
    // The sidecar is the layer's full path plus `.sig` — `buildclamp.toml.sig` beside
    // `buildclamp.toml` — built by appending rather than replacing the extension, so a file
    // with two dots or none is handled the same way.
    let mut sig_path = path.as_os_str().to_os_string();
    sig_path.push(".sig");
    let text = std::fs::read_to_string(PathBuf::from(sig_path)).ok()?;
    buildclamp_core::signed_policy::decode_signature(&text).ok()
}

/// Everything that can go wrong before a stack exists.
#[derive(Debug, thiserror::Error)]
pub enum StackError {
    #[error("could not read {0}: {1}")]
    Read(String, std::io::Error),

    #[error("the policy layers do not compose: {0}")]
    Policy(#[source] buildclamp_core::PolicyError),

    #[error("{path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: buildclamp_core::PolicyError,
    },

    #[error(
        "the policy layers form a cycle: {}. \n\
         \n\
         A cycle has no nearest layer, so there is no answer to `which file is the last \
         word` — and a resolver that picked one would be picking whichever file it happened \
         to read first.",
        .chain.join(" -> ")
    )]
    Cycle { chain: Vec<String> },
}

fn load_into(
    path: &Path,
    layers: &mut Vec<buildclamp_core::Layer>,
    sources: &mut Vec<LayerSource>,
    seen: &mut Vec<PathBuf>,
) -> Result<(), StackError> {
    // Canonicalised so that `../org/buildclamp.toml` and `org/buildclamp.toml` reached by
    // two routes are recognised as one file. A cycle check on the spelling rather than on
    // the file would miss the cycle that actually happens, which is two layers reaching a
    // third by different relative paths.
    let key = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if seen.contains(&key) {
        let mut chain: Vec<String> = seen.iter().map(|p| p.display().to_string()).collect();
        chain.push(key.display().to_string());
        return Err(StackError::Cycle { chain });
    }
    seen.push(key.clone());

    let text = std::fs::read_to_string(path)
        .map_err(|e| StackError::Read(path.display().to_string(), e))?;
    let policy = buildclamp_core::Policy::parse(&text).map_err(|source| StackError::Parse {
        path: path.display().to_string(),
        source,
    })?;

    // Depth first, and the extends BEFORE this file, so the result is nearest last.
    let here = path.parent().unwrap_or(Path::new("."));
    if let Some(decl) = &policy.layer {
        for extend in &decl.extends {
            load_into(&here.join(extend), layers, sources, seen)?;
        }
    }

    let name = policy
        .layer
        .as_ref()
        .map(|l| l.name.clone())
        // A file with no `[layer]` is the repository's own, which is what every
        // unlayered policy has always been. Naming it rather than leaving it blank
        // means a refusal reads the same whether or not somebody set up layering.
        .unwrap_or_else(|| "repo".to_string());
    // Captured for signature verification: the exact bytes a `<path>.sig` would be over, and
    // the canonical path the sidecar sits beside. Pushed in the same order as the layer, so
    // the two Vecs stay aligned and `sources.last()` is the anchor.
    sources.push(LayerSource {
        name: name.clone(),
        path: key,
        bytes: text.into_bytes(),
    });
    layers.push(buildclamp_core::Layer {
        name,
        origin: path.display().to_string(),
        policy,
    });
    // Off the current recursion path on the way out: `seen` is a DFS path stack, not a
    // visited set. Two branches of a diamond — repo -> org -> base and repo -> team -> base —
    // both reach `base`, and that is a duplicate for `buildclamp_core` to name, not a cycle.
    // A real cycle is still caught above, because the repeated node is still on the path when
    // it is reached the second time.
    seen.pop();
    Ok(())
}

/// Run cargo under a policy.
#[allow(clippy::too_many_arguments)]
pub fn run(
    subcommand: &str,
    cargo_args: &[String],
    stack: &buildclamp_core::Stack,
    provenance: &buildclamp_core::PolicyProvenance,
    layout: &Layout,
    mode: Mode,
    deep: bool,
    today: buildclamp_core::Date,
) -> std::io::Result<RunOutcome> {
    // A fresh run directory each time: records from a previous run would be read back as
    // part of this one, and a report describing two different builds is worse than no
    // report.
    let _ = std::fs::remove_dir_all(&layout.run_dir);
    // The proc-macro inventory lives OUTSIDE `target/`. A held compile is granted all of
    // `target/` (rustc writes across it), and the run directory is under `target/`, so an
    // inventory kept there could be forged by the very code the sandbox is holding — and
    // attribution and attestation would trust the forgery. This directory is on no
    // sandbox-writable path, so only the trusted wrapper processes write it; they are told
    // where it is by ENV_MACRO_DIR below.
    let macro_dir = create_owner_only_temp_dir("buildclamp-macros");
    let run = RunDir::open_with_macro_dir(&layout.run_dir, &macro_dir)?;

    let me = self_path()?;
    let swept = buildclamp_shim::sweep(&layout.target_dir, &me)?;
    if !swept.failed.is_empty() {
        // Never silent: a build script the sweep could not reach will run unheld, and the
        // person needs to know before they read a clean report.
        for (path, why) in &swept.failed {
            eprintln!(
                "buildclamp: could not hold the already-compiled build script at {}: {why}",
                path.display()
            );
        }
    }

    let mut cmd = Command::new(cargo());
    cmd.arg(subcommand).args(cargo_args);

    // Scrub our own environment before cargo inherits it. Step 1 in the module docs.
    // The nearest layer decides what a credential LOOKS like — `env-deny` is a policy-wide
    // switch and the repository is the last word on it — while the names re-admitted are
    // the union across every layer, because a name only the org layer allows still has to
    // survive this one scrub to reach any unit at all.
    let policy = &stack.nearest().policy;
    for name in secret_names_in_environment(policy, &stack.env_allow_union()) {
        if cargo_itself_needs(subcommand, &name) {
            continue;
        }
        cmd.env_remove(name);
    }

    cmd.env("RUSTC_WRAPPER", &me);
    cmd.env(buildclamp_core::ENV_POLICY, &layout.policy);
    // One calendar for the whole run. See `ENV_TODAY`: a launcher that asked its own
    // clock would split a build that crosses midnight, and could honour a block against a
    // day the driver never checked the bounds on.
    cmd.env(buildclamp_core::ENV_TODAY, today.to_string());
    cmd.env(buildclamp_core::ENV_RUN_DIR, &layout.run_dir);
    cmd.env(buildclamp_core::ENV_MACRO_DIR, &macro_dir);
    cmd.env(buildclamp_core::ENV_MODE, mode.as_str());
    // The workspace members by manifest directory, so a wrapper can tell a first-party crate
    // from a dependency — even one sharing a member's name — by matching CARGO_MANIFEST_DIR,
    // and even when cargo did not select the member on the command line. Written to a trusted
    // file (owner-only, outside every sandbox-writable path so a held unit cannot forge its own
    // membership, removed after cargo below) and passed by PATH, not inline: a large monorepo's
    // member list can exceed one environment entry's MAX_ARG_STRLEN limit (128 KiB) and fail
    // execve with E2BIG before cargo even starts. Best-effort throughout: on any failure the
    // wrapper falls back to CARGO_PRIMARY_PACKAGE.
    let members_dir = workspace_member_dirs(manifest_path_from(cargo_args)).and_then(|members| {
        let dir = create_owner_only_temp_dir("buildclamp-members");
        let file = dir.join("members");
        if std::fs::write(&file, members).is_ok() {
            Some((dir, file))
        } else {
            let _ = std::fs::remove_dir_all(&dir);
            None
        }
    });
    if let Some((_, file)) = &members_dir {
        cmd.env(buildclamp_core::ENV_WORKSPACE_MEMBERS, file);
    }
    if deep {
        cmd.env(buildclamp_core::ENV_DEEP, "1");
    }
    // Chain to whatever wrapper was already configured, so `sccache` keeps working.
    match std::env::var_os("RUSTC_WRAPPER") {
        Some(prev) if !prev.is_empty() && Path::new(&prev) != me => {
            cmd.env(buildclamp_core::ENV_INNER_WRAPPER, prev);
        }
        // Nothing in the environment. A wrapper configured in a `config.toml` instead is
        // NOT chained, and this is where that stops being silent.
        _ => warn_about_a_wrapper_only_cargo_can_see(),
    }

    // Begun before cargo starts, so `started_at` is the build's start rather than the
    // moment the report happened to be assembled.
    let mut run_header = crate::runmeta::begin(cargo_args);
    // Record which distributed policy layers were signed, and by whom, so the report and any
    // attestation carry the policy's authority and not only its content hash.
    crate::runmeta::stamp_policy_provenance(&mut run_header, provenance);

    let status = cmd.status()?;

    // Cargo has exited, so every wrapper has too and the inventory has served its purpose:
    // it only ever carried object→unit mappings between wrapper processes during the build,
    // and those are already folded into each report record. Remove it rather than leave a
    // per-run directory in the system temp.
    let _ = std::fs::remove_dir_all(&macro_dir);
    // The member list has done its job too — every wrapper that consulted it has exited with
    // cargo. Remove its trusted directory rather than leave it in the system temp.
    if let Some((dir, _)) = &members_dir {
        let _ = std::fs::remove_dir_all(dir);
    }

    crate::runmeta::end(&mut run_header);

    let mut report = Report::new(
        env!("CARGO_PKG_VERSION"),
        mode,
        std::iter::once(subcommand.to_string())
            .chain(cargo_args.iter().cloned())
            .collect(),
    );
    report.run = run_header;
    report.host = buildclamp_sandbox::probe::host();
    report.disable_overrides = operator_overrides(mode, policy);
    report.units = run.read_units()?;

    Ok(RunOutcome {
        report,
        cargo_status: status.code(),
        swept: swept.shimmed.len(),
    })
}

/// Say so when a `rustc-wrapper` is configured in a `config.toml` this run will override.
///
/// # The silence this replaces
///
/// Chaining reads `RUSTC_WRAPPER` from the environment, and cargo lets that variable be
/// set a second way: `[build] rustc-wrapper` in a `config.toml`. The environment wins over
/// the config, so a project whose `.cargo/config.toml` configures `sccache` — which is how
/// a team configures it, because a committed file is how you configure a team — gets
/// buildclamp's own path in that slot and sccache never runs.
///
/// Measured on cargo 1.94.1 with a wrapper that logs each invocation: `RUSTC_WRAPPER` in
/// the environment produced 7 inner invocations under `cargo buildclamp check`, and the
/// same wrapper in `.cargo/config.toml` produced **0** — while a plain `cargo check`
/// with that config produced 7. The build still succeeds and is simply no longer cached,
/// which is the worst shape a regression can have: it costs time, it produces no error,
/// and the tool that caused it is the last thing anyone suspects.
///
/// # Why this warns rather than chaining it
///
/// Chaining it would mean resolving cargo's config hierarchy — every ancestor
/// `.cargo/config.toml`, `$CARGO_HOME`, the `.cargo/config` spelling, `--config`
/// arguments, and the precedence between them. Getting that subtly wrong would run the
/// WRONG wrapper, silently, which is worse than running none. So this looks only for the
/// key, says where it found it, and tells the person the one-line fix. It cannot claim to
/// have found every config cargo would read, and the message does not claim to.
fn warn_about_a_wrapper_only_cargo_can_see() {
    let Some((file, value)) = configured_rustc_wrapper() else {
        return;
    };
    eprintln!(
        "buildclamp: {} sets `build.rustc-wrapper = {value}`, and buildclamp has to put \n\
         \x20 itself in that slot — the RUSTC_WRAPPER environment variable overrides the \n\
         \x20 config, so that wrapper will NOT run and your builds will not be cached.\n\
         \x20 Export it instead and buildclamp will chain to it:\n\
         \x20   RUSTC_WRAPPER={value} cargo buildclamp build",
        file.display()
    );
}

/// Find a `build.rustc-wrapper` in the config files closest to this build.
///
/// Ancestor `.cargo/config.toml` first, then `$CARGO_HOME`, in cargo's own order of
/// preference. Both the `.toml` and the extensionless spelling, because cargo reads both
/// and a project that has not migrated is exactly the kind that also has an old sccache
/// setup.
fn configured_rustc_wrapper() -> Option<(PathBuf, String)> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        dirs.extend(cwd.ancestors().map(|d| d.join(".cargo")));
    }
    // Skip only the home candidate when neither variable is set — not the whole search.
    // A `?` here returned `None` from the function and abandoned the ancestor `.cargo`
    // directories already collected above, so a `build.rustc-wrapper` in a project's own
    // `.cargo/config.toml` went unwarned on a runner with neither `CARGO_HOME` nor `HOME`
    // — the exact silence this warning exists to break.
    if let Some(home) = std::env::var_os("CARGO_HOME") {
        dirs.push(PathBuf::from(home));
    } else if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".cargo"));
    }

    find_wrapper_in(&dirs)
}

/// The file-reading half, separated so it can be tested without touching the environment.
fn find_wrapper_in(dirs: &[PathBuf]) -> Option<(PathBuf, String)> {
    for dir in dirs {
        for name in ["config.toml", "config"] {
            let path = dir.join(name);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            // Parsed rather than grepped: `rustc-wrapper` appears in comments in plenty of
            // real config files, and a warning that fired on a comment would be trained
            // away within a week.
            let Ok(value) = text.parse::<toml::Value>() else {
                continue;
            };
            if let Some(w) = value
                .get("build")
                .and_then(|b| b.get("rustc-wrapper"))
                .and_then(toml::Value::as_str)
            {
                return Some((path, w.to_string()));
            }
        }
    }
    None
}

/// What the operator switched off, read from the environment this run actually saw.
///
/// The report has to distinguish "somebody turned this off" from "this kernel cannot do
/// it", and only the first is a decision. Two switches can produce one:
///
/// * `BUILDCLAMP_MODE=off` — the kill switch, which takes everything.
/// * `BUILDCLAMP_DISABLE` — the per-mechanism knob, which exists so the fallback tiers
///   are testable on a host that has everything, and which is therefore *also* a way to
///   quietly weaken a build.
///
/// Both are settable by anyone with control of the CI environment, which is a far larger
/// set of people than those who can commit to `buildclamp.toml`. That asymmetry is the
/// reason this function exists: without it, the difference between a build nobody could
/// enforce and a build somebody chose not to enforce is invisible in the artefact a
/// reviewer reads.
///
/// The value is recorded verbatim rather than parsed into meaning, because a value this
/// build did not recognise is itself worth seeing.
fn operator_overrides(mode: Mode, policy: &Policy) -> Vec<buildclamp_core::DisableOverride> {
    let mut out = Vec::new();
    if mode == Mode::Off {
        // Which switch produced it matters to a reader: one needs commit access to the
        // policy, the other only control of the CI environment, and a reviewer deciding
        // how much to worry needs to know which.
        let (source, value) = match policy.enforcement {
            Some(buildclamp_core::Enforcement::Disabled) => {
                ("buildclamp.toml", "enforcement = \"disabled\"")
            }
            None => ("BUILDCLAMP_MODE", "off"),
        };
        out.push(buildclamp_core::DisableOverride {
            source: source.into(),
            value: value.into(),
            effect: "all enforcement; every build unit ran unheld".into(),
        });
    }
    if let Ok(v) = std::env::var("BUILDCLAMP_DISABLE") {
        if !v.trim().is_empty() {
            out.push(buildclamp_core::DisableOverride {
                source: "BUILDCLAMP_DISABLE".into(),
                value: v.clone(),
                effect: format!("the mechanism(s) named in `{v}` were not used"),
            });
        }
    }
    out
}

/// Is this a credential the cargo verb being run cannot do its job without?
///
/// Exactly one verb has any, and the exception is narrow on purpose.
///
/// # Why `publish` needs one
///
/// Step 1 of this module drops credential-shaped names before cargo inherits them, so
/// that no process in the build tree holds a secret a build script could read out of
/// `/proc`. `CARGO_REGISTRY_TOKEN` is in [`buildclamp_core::DEFAULT_ENV_DENY`] by name,
/// along with `CARGO_REGISTRIES_*` for alternative registries — which is correct for every
/// other verb and fatal for this one, because the token IS how `cargo publish`
/// authenticates. Scrubbing it would leave a subcommand that cannot do the thing it is
/// named after, failing at the upload with an authentication error that points nowhere
/// near buildclamp.
///
/// # What is given up, said plainly
///
/// Cargo holds the token while third-party build scripts run in the verification build.
/// That is not a new exposure created here — it is what a plain `cargo publish` does, and
/// publishing is one of the few moments a developer's registry token and somebody else's
/// build-time code are alive in the same process tree. buildclamp narrows it in the two
/// places it can: every held unit's own environment is scrubbed separately by the
/// launcher, so no unit is handed the token; and where the environment tier is
/// `enforced:scrub+userns`, a unit cannot read cargo's environment either. Where the tier
/// is only `advisory:scrub`, it can, and [`warn_before_publishing`] says so before cargo
/// starts rather than in a report written afterwards.
///
/// The list is exact names and prefixes rather than a pattern language: this is a
/// security exception, and a wildcard here would be a way to widen it without noticing.
fn cargo_itself_needs(subcommand: &str, name: &str) -> bool {
    if subcommand != "publish" {
        return false;
    }
    name == "CARGO_REGISTRY_TOKEN" || name.starts_with("CARGO_REGISTRIES_")
}

/// Say what publishing costs on this host, before anything is uploaded.
///
/// Returns `false` when the caller asked for enforcement and this host cannot provide it,
/// which for this verb has to be answered **before** cargo runs. Everywhere else
/// `--require-enforced` reads the finished report, and that is the right place for it; an
/// upload cannot be taken back, so a verdict delivered after one would not be a verdict.
pub fn warn_before_publishing(require_enforced: bool) -> bool {
    let host = buildclamp_sandbox::probe::host();
    let tiers = buildclamp_sandbox::projected_tiers(&host);
    let env_tier = tiers.get(&buildclamp_core::Forward::Known(
        buildclamp_core::Capability::EnvSecret,
    ));
    if env_tier.is_some_and(buildclamp_core::Tier::is_enforced) {
        return true;
    }

    let label = env_tier.map_or_else(|| "absent".to_string(), buildclamp_core::Tier::label);
    let message = format!(
        "publishing needs your registry token in cargo's own environment, and the \n\
         \x20 environment tier on this host is `{label}`. A held build script cannot be \n\
         \x20 handed the token — each unit's environment is scrubbed separately — but \n\
         \x20 without a user namespace it can still read it out of /proc/<pid>/environ of \n\
         \x20 the cargo that is publishing. Run `cargo buildclamp doctor` to see what is \n\
         \x20 missing."
    );

    if require_enforced {
        eprintln!("buildclamp: {message}");
        eprintln!(
            "buildclamp: refusing to publish, because --require-enforced was asked for and \n\
             \x20 this host cannot provide it. This is checked before the upload rather \n\
             \x20 than after it: an upload cannot be taken back."
        );
        return false;
    }
    eprintln!("buildclamp: {message}");
    true
}

/// The names in *our* environment that the policy treats as credentials.
///
/// Computed rather than hard-coded so `defaults.env-deny` governs both the driver's own
/// scrub and each unit's, and a policy author changing one changes both.
///
/// `re_admitted` is the escape hatch, and the two callers pass opposite things on purpose.
/// The driver passes [`Policy::env_allow_union`]: a name some grant re-admits has to
/// survive into cargo's environment, because the launcher inherits from cargo and cannot
/// hand a build script a variable that is no longer there. The wrapper passes nothing —
/// see [`compiler_child_secret_names`].
fn secret_names_in_environment(policy: &Policy, re_admitted: &[String]) -> Vec<String> {
    // `vars_os`, not `vars`: the latter panics on a name **or a value** that is not valid
    // Unicode, and since the compiler-child scrub landed this runs once per rustc rather
    // than once per build. A single non-Unicode variable anywhere in the inherited
    // environment would abort every compile in the build — a crash on the host's contents
    // rather than on anything this policy says.
    //
    // Only the name is ever matched, so the value's encoding stops mattering the moment it
    // is dropped here. A name that is not Unicode cannot match an `env-deny` pattern (they
    // are `&str`), so filtering it out removes nothing that could have been scrubbed.
    secret_names_in(unicode_names(std::env::vars_os()), policy, re_admitted)
}

/// Keep the names that are valid Unicode, drop the rest.
///
/// Its own function so the dropping is testable without touching the process environment.
/// Planting a non-Unicode variable would need `unsafe` in the 2024 edition, would race every
/// sibling test that reads `environ`, and would put an `unsafe` block outside
/// `crates/sandbox` — which this project's CI rejects as an architecture invariant. Feeding
/// the decode a written-down list tests the same step without any of that.
fn unicode_names<I>(names: I) -> impl Iterator<Item = String>
where
    I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
{
    names.into_iter().filter_map(|(k, _)| k.into_string().ok())
}

/// The decision itself, over any set of names.
///
/// Split from the process environment so it can be tested against a written-down one. The
/// alternative was setting a variable and putting it back, which needs `unsafe` in the
/// 2024 edition, races every sibling test that reads `environ`, and would put an `unsafe`
/// block outside `crates/sandbox` — which this project's CI rejects as an architecture
/// invariant, correctly.
fn secret_names_in<I>(names: I, policy: &Policy, re_admitted: &[String]) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let patterns = policy.env_deny();
    names
        .into_iter()
        .filter(|k| {
            !re_admitted.iter().any(|a| a.eq_ignore_ascii_case(k))
                && patterns
                    .iter()
                    .any(|p| buildclamp_core::policy::env_name_matches(p, k))
        })
        .collect()
}

/// The names to drop before exec'ing the compiler. **No re-admission, ever.**
///
/// The driver leaves every `env-allow`ed name in cargo's environment so the launcher can
/// make the real per-unit decision, and for a build script it does: `unitrun::launch`
/// clears the environment and rebuilds it from the unit's own envelope. Nothing does that
/// for rustc. `run_wrapper` execs the compiler with whatever it inherited, so without this
/// every name any one grant re-admitted is visible to *every* compile in the build — and a
/// proc-macro expands inside rustc, so a macro with no grant of its own could read a
/// credential that was re-admitted for some unrelated crate.
///
/// A compile unit has no envelope to consult, which settles what the answer has to be: the
/// strict one. `env-allow` is a statement about one named build script, and a re-admission
/// that leaked to the compiler would make it a statement about the whole build.
///
/// This is not the same thing as holding rustc, which remains unbuilt and documented as
/// such. It is the narrower guarantee that the driver's own scrub is not undone one process
/// later.
fn compiler_child_secret_names(policy: &Policy) -> Vec<String> {
    secret_names_in_environment(policy, &[])
}

/// The compiler-side answer over a written-down environment, for tests.
#[cfg(test)]
fn compiler_child_secret_names_in<I>(names: I, policy: &Policy) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    secret_names_in(names, policy, &[])
}

/// The policy the wrapper was told to use, or the strictest reading if it cannot be had.
///
/// The wrapper runs as a child of cargo with no arguments of its own, so the path arrives
/// through the environment. A policy that has gone missing or stopped parsing since the
/// driver read it cannot be recovered here and must not silently widen anything:
/// [`Policy::empty`] still answers `env_deny` with the built-in defaults, so the compiler
/// is scrubbed either way.
pub fn wrapper_policy() -> Policy {
    std::env::var_os(buildclamp_core::ENV_POLICY)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| Policy::parse(&t).ok())
        .unwrap_or_else(Policy::empty)
}

/// Drop the credentials a compiler child must not see. See [`compiler_child_secret_names`].
pub fn scrub_compiler_environment(cmd: &mut Command) {
    for name in compiler_child_secret_names(&wrapper_policy()) {
        cmd.env_remove(name);
    }
}

/// Write the report, creating its directory.
pub fn write_report(report: &Report, path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_vec_pretty(report)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_member_dirs_keeps_members_and_drops_dependencies() {
        // A package is a member when its id is in `workspace_members`; a dependency (here
        // `libc`) is listed under `packages` but is not a member. Each member contributes its
        // manifest DIRECTORY — the parent of its Cargo.toml — which is what CARGO_MANIFEST_DIR
        // holds when cargo builds it.
        let json = br#"{
            "packages": [
                {"id": "path+file:///w/a#a@0.1.0", "name": "a", "manifest_path": "/w/a/Cargo.toml"},
                {"id": "path+file:///w/b#b@0.1.0", "name": "b", "manifest_path": "/w/b/Cargo.toml"},
                {"id": "registry+https://x#libc@0.2.0", "name": "libc", "manifest_path": "/home/u/.cargo/registry/src/x/libc-0.2.0/Cargo.toml"}
            ],
            "workspace_members": ["path+file:///w/a#a@0.1.0", "path+file:///w/b#b@0.1.0"]
        }"#;
        let dirs = parse_member_dirs(json).unwrap();
        let set: Vec<&str> = dirs.split('\n').collect();
        assert!(set.contains(&"/w/a") && set.contains(&"/w/b"), "{dirs:?}");
        assert!(
            !set.iter().any(|d| d.contains("libc")),
            "a dependency must not count as a workspace member: {dirs:?}"
        );
    }

    #[test]
    fn parse_member_dirs_is_none_when_empty_or_unparseable() {
        // None makes the caller fall back to CARGO_PRIMARY_PACKAGE rather than break a build.
        assert!(parse_member_dirs(br#"{"packages": [], "workspace_members": []}"#).is_none());
        assert!(parse_member_dirs(b"not json").is_none());
    }

    #[test]
    fn manifest_path_from_reads_both_arg_forms() {
        // Both cargo spellings, so metadata resolves the manifest the run is building rather
        // than whichever workspace sits in the current directory.
        let split = vec![
            "build".to_string(),
            "--manifest-path".to_string(),
            "/w/Cargo.toml".to_string(),
        ];
        assert_eq!(manifest_path_from(&split), Some("/w/Cargo.toml"));
        let joined = vec![
            "build".to_string(),
            "--manifest-path=/w/Cargo.toml".to_string(),
        ];
        assert_eq!(manifest_path_from(&joined), Some("/w/Cargo.toml"));
        // Absent: None, and the caller resolves the current-directory workspace as before.
        assert_eq!(manifest_path_from(&["build".to_string()]), None);
    }

    #[test]
    fn member_listed_matches_a_whole_directory_only() {
        let list = "/w/app\n/w/util\n/w/util-macros";
        assert!(member_listed(list, "/w/app"));
        assert!(member_listed(list, "/w/util"));
        assert!(member_listed(list, "/w/util-macros"));
        assert!(!member_listed(list, "/w/uti")); // not a prefix or substring match
        assert!(!member_listed(list, "/w/util/src")); // a subdirectory is not the member dir
        assert!(!member_listed(list, "")); // empty never matches an entry
        assert!(!member_listed("", "/w/app")); // empty list matches nothing
    }

    #[test]
    fn a_dependency_sharing_a_member_name_is_not_a_member() {
        // The trust-escalation this identity closes. `util` is a workspace member at /w/util; a
        // registry dependency ALSO named `util` builds from ~/.cargo/registry. Identity by name
        // would have called that dependency first-party and run its build script unheld under
        // trust-workspace. Identity by directory keeps them apart: the member matches its own
        // directory, the same-named dependency does not.
        let members = "/w/app\n/w/util";
        assert!(
            member_listed(members, "/w/util"),
            "the real member matches its own manifest directory"
        );
        assert!(
            !member_listed(
                members,
                "/home/u/.cargo/registry/src/index.crates.io-6f17d22bba15001f/util-1.4.0"
            ),
            "a same-named registry dependency, in a different directory, is not a member"
        );
    }

    /// The exact composition `run` performs: decide what the policy calls a credential,
    /// then keep back the ones the verb cannot work without.
    fn scrubbed_for(subcommand: &str, names: &[&str]) -> Vec<String> {
        let policy = Policy::empty();
        secret_names_in(names.iter().map(|s| (*s).to_string()), &policy, &[])
            .into_iter()
            .filter(|n| !cargo_itself_needs(subcommand, n))
            .collect()
    }

    #[test]
    fn publish_keeps_the_registry_token_that_every_other_verb_drops() {
        // `CARGO_REGISTRY_TOKEN` is in the default deny list BY NAME, which is correct for
        // every verb except the one that authenticates with it. Scrubbing it here would
        // leave a subcommand that cannot do the thing it is named after, failing at the
        // upload with an authentication error pointing nowhere near buildclamp.
        let names = &[
            "CARGO_REGISTRY_TOKEN",
            "CARGO_REGISTRIES_MYCORP_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "PATH",
        ];

        let on_publish = scrubbed_for("publish", names);
        assert!(!on_publish.contains(&"CARGO_REGISTRY_TOKEN".to_string()));
        assert!(!on_publish.contains(&"CARGO_REGISTRIES_MYCORP_TOKEN".to_string()));

        // And the exception is narrow: it buys the registry token and nothing else. A
        // publish still takes every other credential out of cargo's environment.
        assert!(on_publish.contains(&"AWS_SECRET_ACCESS_KEY".to_string()));
        assert!(on_publish.contains(&"GITHUB_TOKEN".to_string()));
        assert!(
            !on_publish.contains(&"PATH".to_string()),
            "PATH is not a credential"
        );
    }

    #[test]
    fn every_other_verb_still_drops_the_registry_token() {
        // The exception is keyed on the subcommand, so a `build` that happens to run with
        // a registry token in the environment still takes it out of the build tree. If
        // this ever passes for `build`, the exception has stopped being an exception.
        for verb in ["build", "check", "test", "bench", "doc", "install"] {
            let scrubbed = scrubbed_for(verb, &["CARGO_REGISTRY_TOKEN"]);
            assert_eq!(
                scrubbed,
                vec!["CARGO_REGISTRY_TOKEN".to_string()],
                "`{verb}` must still scrub the registry token"
            );
        }
    }

    #[test]
    fn a_wrapper_configured_in_a_config_file_is_found_so_it_can_be_warned_about() {
        // Measured on cargo 1.94.1 with a wrapper that logs each invocation: exported in
        // the environment it ran 7 times under `cargo buildclamp check`; set in
        // `.cargo/config.toml` it ran 0 times, while a plain `cargo check` with the same
        // config ran it 7. The environment beats the config and buildclamp has to own that
        // slot, so sccache silently stops caching. This test is what keeps the warning
        // wired to the thing it warns about.
        let d = tempfile::tempdir().unwrap();
        let cargo_dir = d.path().join(".cargo");
        std::fs::create_dir_all(&cargo_dir).unwrap();
        std::fs::write(
            cargo_dir.join("config.toml"),
            "[build]\nrustc-wrapper = \"/usr/bin/sccache\"\n",
        )
        .unwrap();

        let found = find_wrapper_in(std::slice::from_ref(&cargo_dir)).expect("the key is there");
        assert_eq!(found.1, "/usr/bin/sccache");
        assert_eq!(found.0, cargo_dir.join("config.toml"));
    }

    #[test]
    fn the_extensionless_config_spelling_is_read_too() {
        // Cargo reads both, and a project that never migrated off `.cargo/config` is
        // exactly the kind that also has an sccache setup nobody has looked at in years.
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("config"),
            "[build]\nrustc-wrapper = \"cachetool\"\n",
        )
        .unwrap();
        assert_eq!(
            find_wrapper_in(&[d.path().to_path_buf()]).map(|(_, v)| v),
            Some("cachetool".to_string())
        );
    }

    #[test]
    fn a_commented_out_wrapper_does_not_produce_a_warning() {
        // The config is PARSED rather than grepped. `rustc-wrapper` appears in comments in
        // plenty of real config files, and a warning that fired on a comment would be
        // trained away inside a week — after which the real one would go unread too.
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("config.toml"),
            "[build]\n# rustc-wrapper = \"sccache\"\njobs = 4\n",
        )
        .unwrap();
        assert_eq!(find_wrapper_in(&[d.path().to_path_buf()]), None);
    }

    #[test]
    fn a_directory_with_no_config_at_all_is_silent() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(find_wrapper_in(&[d.path().to_path_buf()]), None);
    }

    #[test]
    fn the_nearest_config_wins_the_way_cargo_orders_them() {
        // The caller passes ancestors first and `$CARGO_HOME` last, so the first hit is
        // the one closest to the build. Naming a file the user is not looking at would
        // send them to edit the wrong one.
        let d = tempfile::tempdir().unwrap();
        let near = d.path().join("near");
        let far = d.path().join("far");
        std::fs::create_dir_all(&near).unwrap();
        std::fs::create_dir_all(&far).unwrap();
        std::fs::write(
            near.join("config.toml"),
            "[build]\nrustc-wrapper = \"near\"\n",
        )
        .unwrap();
        std::fs::write(
            far.join("config.toml"),
            "[build]\nrustc-wrapper = \"far\"\n",
        )
        .unwrap();
        assert_eq!(
            find_wrapper_in(&[near, far]).map(|(_, v)| v),
            Some("near".to_string())
        );
    }

    #[test]
    fn the_run_directory_and_the_report_live_under_the_target_directory() {
        // So `cargo clean` removes them. A report that survived a clean would be read back
        // as describing a build that no longer exists.
        let l = Layout::resolve(None, None);
        assert!(l.run_dir.starts_with(&l.target_dir));
        assert!(l.report.starts_with(&l.target_dir));
    }

    #[test]
    fn the_policy_defaults_beside_the_workspace_manifest_not_the_target_directory() {
        let l = Layout::resolve(None, None);
        assert_eq!(l.policy.file_name().unwrap(), "buildclamp.toml");
        assert!(!l.policy.starts_with(&l.target_dir));
    }

    #[test]
    fn an_explicit_policy_path_is_used_verbatim() {
        let l = Layout::resolve(Some(Path::new("/etc/shared-policy.toml")), None);
        assert_eq!(l.policy, PathBuf::from("/etc/shared-policy.toml"));
    }

    #[test]
    fn a_non_unicode_environment_name_is_dropped_rather_than_fatal() {
        // `std::env::vars()` panics on a name OR a value that is not valid Unicode, and the
        // compiler-child scrub made this run once per rustc rather than once per build — so
        // one such variable anywhere in the inherited environment aborted every compile in
        // the build. Nothing about the policy was involved; it was a crash on the host's
        // contents.
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        // Invalid UTF-8 in the name, and separately in the value. Neither may reach the
        // matcher, and neither may stop the good names beside them from being scrubbed.
        let names = vec![
            (OsString::from_vec(vec![0xff, 0xfe]), OsString::from("x")),
            (
                OsString::from("GITHUB_TOKEN"),
                OsString::from_vec(vec![0xff]),
            ),
            (OsString::from("AWS_SECRET_ACCESS_KEY"), OsString::from("s")),
        ];
        let kept: Vec<String> = unicode_names(names).collect();
        assert_eq!(
            kept,
            vec!["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"],
            "a non-Unicode NAME is dropped; a non-Unicode VALUE never mattered, because only \
             the name is matched"
        );

        // And the survivors still scrub, so dropping the undecodable one costs nothing: a
        // name that is not Unicode cannot match an `env-deny` pattern anyway.
        let p = Policy::empty();
        assert_eq!(
            compiler_child_secret_names_in(kept, &p),
            vec!["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"]
        );
    }

    #[test]
    fn the_drivers_own_scrub_uses_the_same_patterns_the_units_do() {
        // A policy author who narrows `env-deny` must get the narrower behaviour in both
        // places, or the documentation is a lie in one of them.
        let narrow =
            Policy::parse("version = 1\n[defaults]\nenv-deny = [\"NOTHING_MATCHES_*\"]\n").unwrap();
        assert!(secret_names_in(planted(), &narrow, &narrow.env_allow_union()).is_empty());
    }

    /// The policy for the two tests below: one grant re-admits one credential.
    fn re_admitting_policy() -> Policy {
        Policy::parse(
            "version = 1\n\
             [defaults]\n\
             env-deny = [\"BUILDCLAMP_TEST_TOKEN\", \"AWS_SECRET_ACCESS_KEY\"]\n\
             [grants.somecrate]\n\
             version = \"1\"\n\
             reviewed = true\n\
             why = \"needs the token\"\n\
             env-allow = [\"BUILDCLAMP_TEST_TOKEN\"]\n",
        )
        .unwrap()
    }

    /// The environment these tests reason about. Written down rather than set, so nothing
    /// here touches `environ` — see `secret_names_in`.
    fn planted() -> Vec<String> {
        ["PATH", "BUILDCLAMP_TEST_TOKEN", "AWS_SECRET_ACCESS_KEY"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    #[test]
    fn a_re_admitted_credential_survives_the_drivers_scrub() {
        // Not an oversight, and the reason the compiler-side scrub below has to exist.
        // The launcher inherits cargo's environment and cannot hand a build script a
        // variable that is no longer in it, so `env-allow` only works if the driver
        // leaves the name alone.
        let p = re_admitting_policy();
        let dropped = secret_names_in(planted(), &p, &p.env_allow_union());
        assert!(
            !dropped.iter().any(|n| n == "BUILDCLAMP_TEST_TOKEN"),
            "the driver dropped a name a grant re-admits, which makes env-allow a no-op"
        );
        // And the one no grant names is still dropped, or the exemption is a blanket.
        assert!(
            dropped.iter().any(|n| n == "AWS_SECRET_ACCESS_KEY"),
            "re-admitting one name exempted another, so env-allow widened past its grant"
        );
    }

    #[test]
    fn the_compiler_never_inherits_a_credential_re_admitted_for_some_other_crate() {
        // The hole this closes: `run_wrapper` execs rustc with whatever it inherited, and
        // proc-macro expansion happens inside that rustc. A macro with no grant of its own
        // would otherwise read a credential `env-allow`ed for an unrelated build script.
        // A compile unit has no envelope, so the answer is the strict one.
        let p = re_admitting_policy();
        assert!(
            compiler_child_secret_names_in(planted(), &p)
                .iter()
                .any(|n| n == "BUILDCLAMP_TEST_TOKEN"),
            "a re-admitted credential reached the compiler, so every proc-macro in the \
             build can read it"
        );
    }

    #[test]
    fn a_policy_that_cannot_be_read_still_scrubs_the_compiler() {
        // `wrapper_policy` falls back to `Policy::empty`, whose `env_deny` is the built-in
        // default list rather than nothing. A missing policy must not be the widest one.
        assert!(
            compiler_child_secret_names_in(planted(), &Policy::empty())
                .iter()
                .any(|n| n == "AWS_SECRET_ACCESS_KEY"),
            "an unreadable policy scrubbed nothing from the compiler, so a build whose \
             policy went missing mid-run exposes every credential to every macro"
        );
    }
}
