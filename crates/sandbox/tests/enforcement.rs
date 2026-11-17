//! Does the sandbox actually stop anything?
//!
//! Every other test in this crate checks a decision, a filter shape or a decoder. These
//! run a real process and look at what it managed to do, which is the only kind of test
//! that can catch a filter that installs cleanly and enforces nothing.
//!
//! They need privileges the ordinary `cargo test` run may not have — user namespaces, or
//! at minimum seccomp — so each one **skips with a printed reason** rather than failing
//! when the host cannot support it. A red test on a laptop that simply lacks the
//! mechanism teaches nothing and gets ignored; a skip that says which mechanism was
//! missing is actionable.
//!
//! Run them with output: `cargo test -p buildclamp-sandbox --test enforcement -- --nocapture`.

use std::process::Command;

use buildclamp_core::{Capability, Outcome, Tier};
use buildclamp_sandbox::{probe, Plan};

/// Skip with a reason, rather than fail, when the host cannot run a check.
macro_rules! require {
    ($cond:expr, $why:expr) => {
        if !$cond {
            eprintln!("SKIP: {}", $why);
            return;
        }
    };
}

fn sh(script: &str) -> Command {
    let mut c = Command::new("/bin/sh");
    c.arg("-c").arg(script);
    c.env_clear();
    c
}

#[test]
fn a_held_command_still_runs_and_its_exit_status_reaches_the_caller() {
    let host = probe::host();
    require!(
        host.user_namespaces || host.seccomp_user_notif,
        "neither user namespaces nor seccomp notification on this host"
    );
    let plan = Plan {
        allow_net: true,
        allow_unix: true,
        ..Default::default()
    };
    let _lock = exclusive();
    let held = plan.hold(sh("exit 7")).expect("holding a trivial command");
    assert_eq!(
        held.exit_code,
        Some(7),
        "the unit's own status must reach the caller"
    );
}

#[test]
fn a_unit_denied_the_network_cannot_open_an_internet_socket() {
    let host = probe::host();
    require!(
        host.user_namespaces || host.seccomp_user_notif,
        "no mechanism to deny the network on this host"
    );

    // `exec 3<>/dev/tcp/...` is bash-only, so use a tiny python if it is there, and fall
    // back to reporting the skip rather than passing vacuously.
    let has_python = Command::new("/bin/sh")
        .arg("-c")
        .arg("command -v python3")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    require!(has_python, "no python3 to attempt a connection with");

    let plan = Plan {
        allow_net: false,
        allow_unix: true,
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        ..Default::default()
    };
    let script = "python3 -c \"
import socket,sys
try:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    s.connect(('127.0.0.1', 9))
    print('CONNECTED')
except Exception as e:
    print('REFUSED', type(e).__name__)
\"";
    let _lock = exclusive();
    let out = plan
        .hold({
            let mut c = sh(script);
            c.env("PATH", "/usr/bin:/bin");
            c.stdout(std::process::Stdio::piped());
            c
        })
        .expect("holding the unit");

    // The unit must not have connected. Either the socket call was refused or the empty
    // network namespace made the address unreachable — both are the sandbox working, and
    // the report says which mechanism applied.
    let net_tier = out
        .tiers
        .get(&Capability::Net.into())
        .map(Tier::label)
        .unwrap_or_default();
    eprintln!("network tier on this host: {net_tier}");
    assert!(
        net_tier.starts_with("enforced:"),
        "the network must be enforced, not {net_tier}"
    );

    // And if the supervisor saw the attempt, it must be recorded as ungranted rather than
    // quietly allowed.
    for r in out
        .requests
        .iter()
        .filter(|r| r.capability.copied() == Some(Capability::Net))
    {
        assert!(
            matches!(r.outcome, Outcome::Ungranted { .. }),
            "a network request was recorded as granted under a deny policy: {r:?}"
        );
    }
}

#[test]
fn a_unit_may_write_inside_its_allowed_directory_and_not_outside_it() {
    let host = probe::host();
    require!(
        host.user_namespaces,
        "no user namespaces, so there is no read-only root to test"
    );

    let scratch = tempfile::tempdir().expect("a scratch directory");
    let allowed = scratch.path().join("out");
    std::fs::create_dir_all(&allowed).unwrap();
    let forbidden = scratch.path().join("forbidden");
    std::fs::create_dir_all(&forbidden).unwrap();

    let plan = Plan {
        allow_net: false,
        allow_unix: true,
        writable: vec![allowed.clone()],
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        ..Default::default()
    };

    let script = format!(
        "echo inside > {allowed}/ok 2>/dev/null && echo WROTE_INSIDE; \
         echo outside > {forbidden}/bad 2>/dev/null && echo WROTE_OUTSIDE",
        allowed = allowed.display(),
        forbidden = forbidden.display(),
    );
    let _lock = exclusive();
    let held = plan.hold(sh(&script)).expect("holding the unit");
    eprintln!(
        "filesystem tier on this host: {}",
        held.tiers
            .get(&Capability::FsWrite.into())
            .map(Tier::label)
            .unwrap_or_default()
    );

    // The legitimate write must have succeeded — a sandbox that blocks OUT_DIR breaks
    // every build script there is.
    assert!(
        allowed.join("ok").exists(),
        "the unit could not write to the directory it was granted"
    );
    // And the write outside must not have landed.
    assert!(
        !forbidden.join("bad").exists(),
        "a write outside the granted directories succeeded"
    );
}

#[test]
fn a_unit_cannot_rename_or_link_out_of_its_allowed_directory() {
    // The two-path escape: a file created inside the granted directory, then moved or
    // hard-linked OUT of it. A supervisor that authorised renameat/linkat on the source
    // alone let the destination write land in an ungranted directory, and the permitted
    // source laundered it. Whatever tier this host enforces at — landlock, a read-only
    // mount, or the seccomp-notify supervisor whose destination check this exercises — the
    // destination must be refused.
    let host = probe::host();
    require!(
        host.user_namespaces,
        "no user namespaces, so there is no write boundary to test"
    );

    let scratch = tempfile::tempdir().expect("a scratch directory");
    let allowed = scratch.path().join("out");
    std::fs::create_dir_all(&allowed).unwrap();
    let forbidden = scratch.path().join("forbidden");
    std::fs::create_dir_all(&forbidden).unwrap();

    let plan = Plan {
        allow_net: false,
        allow_unix: true,
        writable: vec![allowed.clone()],
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        ..Default::default()
    };

    // `mv` renames (renameat) and only falls back to copy+unlink across filesystems; both
    // directories are in one tmpfs, so it is a rename. `ln` hard-links (linkat). Both target
    // the forbidden directory from a source inside the allowed one.
    let script = format!(
        "echo payload > {allowed}/src && cp {allowed}/src {allowed}/src2 2>/dev/null; \
         mv {allowed}/src2 {forbidden}/moved 2>/dev/null; \
         ln {allowed}/src {forbidden}/linked 2>/dev/null; true",
        allowed = allowed.display(),
        forbidden = forbidden.display(),
    );
    let _lock = exclusive();
    let held = plan.hold(sh(&script)).expect("holding the unit");
    eprintln!(
        "filesystem tier on this host: {}",
        held.tiers
            .get(&Capability::FsWrite.into())
            .map(Tier::label)
            .unwrap_or_default()
    );

    assert!(
        !forbidden.join("moved").exists(),
        "a rename into an ungranted directory landed"
    );
    assert!(
        !forbidden.join("linked").exists(),
        "a hard link into an ungranted directory landed"
    );
}

/// Observe mode's whole value is that the build it records is the build that normally
/// runs. A namespace changes that build: a connection fails with a different errno, the
/// process list is shorter, a temporary file lands somewhere else. So the check is not
/// "did it refuse anything" but "is this the same machine the build would have seen".
///
/// It is also the cheap proof for the bug that made the base namespaces unconditional:
/// with `CLONE_NEWUSER` always in the flag set, this fails here with two different
/// namespace inodes, and on a host without user namespaces it fails much louder, as
/// `unshare` returning EPERM and `spawn` reporting `Permission denied`.
#[test]
fn observe_mode_leaves_the_build_in_the_namespace_it_would_normally_run_in() {
    let host = probe::host();
    require!(
        host.seccomp_user_notif,
        "no seccomp notification on this host"
    );

    let parent = std::fs::read_link("/proc/self/ns/user").expect("reading our own userns");
    let scratch = tempfile::tempdir().unwrap();
    let out = scratch.path().join("ns.txt");
    let plan = Plan {
        allow_net: false,
        observe_only: true,
        observe_writes: true,
        writable: vec![scratch.path().to_path_buf()],
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        ..Default::default()
    };
    let _lock = exclusive();
    plan.hold(sh(&format!(
        "readlink /proc/self/ns/user > {}",
        out.display()
    )))
    .expect("holding the unit");

    let child = std::fs::read_to_string(&out).expect("the unit wrote its namespace");
    assert_eq!(
        child.trim(),
        parent.to_string_lossy(),
        "observe mode moved the build into a different user namespace"
    );
}

#[test]
fn observe_mode_records_without_refusing_anything() {
    let host = probe::host();
    require!(
        host.seccomp_user_notif,
        "no seccomp notification on this host"
    );

    let scratch = tempfile::tempdir().unwrap();
    let plan = Plan {
        allow_net: false,
        observe_only: true,
        observe_writes: true,
        writable: vec![scratch.path().to_path_buf()],
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        ..Default::default()
    };
    let marker = scratch.path().join("written-anyway");
    let _lock = exclusive();
    let held = plan
        .hold(sh(&format!("echo x > {}", marker.display())))
        .expect("holding the unit");

    // Observe mode must never be the reason a build broke: nobody could tell its failures
    // from real ones, and the tool would be uninstalled the first time it happened.
    assert_eq!(held.exit_code, Some(0), "observe mode refused something");
    assert!(marker.exists(), "observe mode prevented a write");
    for r in &held.requests {
        assert!(
            matches!(r.outcome, Outcome::Granted),
            "observe mode recorded a refusal: {r:?}"
        );
    }
}

#[test]
fn holding_a_unit_costs_a_few_milliseconds_not_a_few_hundred() {
    let host = probe::host();
    require!(
        host.user_namespaces || host.seccomp_user_notif,
        "nothing to measure on this host"
    );

    let plan = Plan {
        allow_net: true,
        allow_unix: true,
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        ..Default::default()
    };

    let n = 10;
    let _lock = exclusive();
    let start = std::time::Instant::now();
    for _ in 0..n {
        plan.hold(sh("exit 0")).expect("holding");
    }
    let per_unit = start.elapsed().as_micros() as f64 / n as f64 / 1000.0;
    eprintln!("held-unit overhead: {per_unit:.1} ms per unit");

    // The published figure is 3-4 ms of seccomp setup plus 2.4 ms of namespaces. A
    // generous bound here catches an order-of-magnitude regression — a supervisor that
    // stopped exiting promptly, a probe moved inside the loop — without failing on a busy
    // CI machine.
    assert!(
        per_unit < 250.0,
        "holding a trivial unit took {per_unit:.1} ms, which is far above the measured 6 ms"
    );
}

/// The Landlock rung, on a host that has it.
///
/// This is the test the tier was implemented for, and it is written to be the thing that
/// catches the two ways the rung can be wrong in the direction that matters.
///
/// The first is a ruleset that denies too much. The handled-access mask deliberately
/// leaves reads and exec alone, so a build script must still be able to read its manifest
/// directory and run `cc` — and a mask with a stray bit in it would break every real build
/// while looking like tighter security.
///
/// The second is a tier that names Landlock over enforcement the mount namespace actually
/// did. `BUILDCLAMP_DISABLE=ns` removes the namespace, so what is left is Landlock or
/// nothing: if the write outside still lands with the namespace gone, the label was
/// crediting the wrong mechanism.
#[test]
fn landlock_enforces_the_write_boundary_without_a_mount_namespace() {
    let host = probe::host();
    let abi = match host.landlock_abi {
        Some(v) => v,
        None => {
            eprintln!("SKIP: this kernel has no Landlock (CONFIG_SECURITY_LANDLOCK unset)");
            return;
        }
    };
    require!(
        host.seccomp_user_notif,
        "no seccomp notification, so `hold` refuses the unit before Landlock is reached"
    );
    eprintln!("Landlock ABI on this host: v{abi}");

    let scratch = tempfile::tempdir().expect("a scratch directory");
    let allowed = scratch.path().join("out");
    std::fs::create_dir_all(&allowed).unwrap();
    let forbidden = scratch.path().join("forbidden");
    std::fs::create_dir_all(&forbidden).unwrap();
    // Something to read from outside the write zone. Reads are unrestricted by design and
    // the mask must not have quietly changed that.
    let readable = scratch.path().join("readable.txt");
    std::fs::write(&readable, b"buildclamp\n").unwrap();

    // Outside the scratch directory on purpose: /dev/shm is mode 1777, so DAC lets an
    // unprivileged unit create files there, and the tmpfs is shared with every other
    // process on the host. It is the concrete escape the `/dev` allowance used to permit
    // — the list was once `["/dev"]` and the write decider matches by prefix — and the
    // one place in this test where a leak would outlive the test itself.
    let shm =
        std::path::PathBuf::from(format!("/dev/shm/buildclamp-escape-{}", std::process::id()));
    let _ = std::fs::remove_file(&shm);

    let plan = Plan {
        allow_net: false,
        allow_unix: true,
        writable: vec![allowed.clone()],
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        ..Default::default()
    };

    // Every step leaves a filesystem effect rather than a printed marker, because `Held`
    // does not carry the child's output and an effect is the stronger claim anyway.
    //
    // `2>/dev/null` is load-bearing rather than noise. The first run of this test on CI
    // failed with `/bin/sh: 1: cannot create /dev/null: Permission denied` — a device node
    // is outside every write zone, and Landlock, unlike the mount namespace where /dev is
    // a separate mount that stays writable, has no notion of a mount to inherit that from.
    // A shell redirect is what every configure-shaped probe does, so keeping it here is
    // what keeps that regression caught.
    let script = format!(
        // First, and without any redirect of its own, so the answer cannot be confused
        // with a redirect failing: can the unit write to /dev/null at all? Two CI rounds
        // were spent inferring this from `cannot create /dev/null` lines attached to other
        // commands, and a marker file says it directly.
        "echo x > /dev/null && touch {allowed}/devnull_ok; \
         echo first > {allowed}/ok 2>/dev/null; \
         mkdir {allowed}/sub 2>/dev/null; \
         echo second > {allowed}/ok 2>/dev/null; \
         cat {readable} > {allowed}/readback 2>/dev/null; \
         echo escaped > {shm} 2>/dev/null; \
         echo outside > {forbidden}/bad 2>/dev/null",
        allowed = allowed.display(),
        forbidden = forbidden.display(),
        readable = readable.display(),
        shm = shm.display(),
    );

    // Without the mount namespace, so nothing but Landlock can be doing the refusing.
    let held = {
        let _guard = DisableNs::set();
        plan.hold(sh(&script)).expect("holding the unit")
    };

    let tier = held
        .tiers
        .get(&Capability::FsWrite.into())
        .map(Tier::label)
        .unwrap_or_default();
    eprintln!("filesystem tier with BUILDCLAMP_DISABLE=ns: {tier}");
    assert_eq!(
        tier,
        format!("enforced:landlock-v{abi}"),
        "the filesystem tier should name Landlock when the namespace is gone"
    );

    // Asserted first because everything below depends on it: a redirect to /dev/null that
    // is refused aborts its whole command, so a failure here produces a cascade of
    // confusing failures further down. This is the regression the first CI run found.
    assert!(
        allowed.join("devnull_ok").exists(),
        "the unit could not write to /dev/null, so every `2>/dev/null` in a real build \
         script would abort its command. The /dev grant in linux::landlock is wrong."
    );
    assert!(
        allowed.join("ok").exists(),
        "the unit could not write to the directory Landlock granted it"
    );
    // Rewriting an existing file is `O_TRUNC`, so this is the TRUNCATE right on ABI 3+.
    // Handled but not granted would break the second build of any crate and not the first.
    assert_eq!(
        std::fs::read_to_string(allowed.join("ok")).unwrap(),
        "second\n",
        "rewriting an existing file failed: TRUNCATE is handled but not granted"
    );
    assert!(
        allowed.join("sub").is_dir(),
        "MAKE_DIR was not granted inside the write zone"
    );
    // Reads are unrestricted by design and the README says so twice. A failure here means
    // the handled mask has grown a READ_* bit and the tool has quietly started doing
    // something its own documentation denies.
    assert_eq!(
        std::fs::read_to_string(allowed.join("readback")).unwrap_or_default(),
        "buildclamp\n",
        "a read from outside the write zone was refused"
    );
    assert!(
        !forbidden.join("bad").exists(),
        "Landlock did not stop a write outside the granted directories, and the tier \
         said it had — this is the false assurance the whole tool exists to prevent"
    );
    let escaped = shm.exists();
    let _ = std::fs::remove_file(&shm);
    assert!(
        !escaped,
        "the unit created a file in /dev/shm, which is outside every zone in \
         Plan::writable. The always-writable allowance has widened back to the whole of \
         /dev, and with it a durable side effect and a channel to every other process on \
         the host — reported, as ever, as fully enforced"
    );
    assert_eq!(
        std::fs::read_to_string(&readable).unwrap(),
        "buildclamp\n",
        "the readable file outside the zone was modified"
    );
}

/// Serialises every test that calls `hold`.
///
/// `hold` reads `BUILDCLAMP_DISABLE` from the environment, and the environment is
/// process-wide while `cargo test` runs these on threads of a single process. One test
/// setting it would otherwise be seen by any sibling holding a unit at that moment, which
/// would not fail loudly — it would make the sibling assert against a tier it never asked
/// for, on some runs and not others.
///
/// This used to be a `--test-threads=1` in the CI files and a paragraph asking the reader
/// to remember. Both CI files still pass the flag, but the correctness of a plain
/// `cargo test` cannot rest on a flag the person running it did not type.
static HOLD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take the lock for the duration of a test that holds a unit.
///
/// Poisoning is stepped over rather than propagated: it means some earlier test panicked,
/// and turning that into a cascade of failures in every other test hides the one that
/// actually broke.
fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    HOLD_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Sets `BUILDCLAMP_DISABLE=ns`, holding [`HOLD_LOCK`] for as long as it is set.
///
/// The lock is the point: without it, restoring the variable on drop closes the window
/// only for this test's own use of it and leaves it wide open for every sibling.
struct DisableNs(
    Option<String>,
    // Held, never read: the lock is the point and `Drop` is what uses it.
    #[allow(dead_code)] std::sync::MutexGuard<'static, ()>,
);

impl DisableNs {
    fn set() -> Self {
        Self::set_to("ns")
    }

    /// The same, with any value `BUILDCLAMP_DISABLE` accepts, e.g. `notify`.
    fn set_to(value: &str) -> Self {
        let guard = exclusive();
        let prev = std::env::var("BUILDCLAMP_DISABLE").ok();
        // SAFETY: `guard` is held for this value's whole lifetime and every other test
        // that reads the variable through `hold` takes the same lock, so no other thread
        // in this process is reading the environment while it is being written.
        unsafe { std::env::set_var("BUILDCLAMP_DISABLE", value) };
        DisableNs(prev, guard)
    }
}

impl Drop for DisableNs {
    fn drop(&mut self) {
        // SAFETY: the lock is still held — this field is dropped after the body runs.
        unsafe {
            match &self.0 {
                Some(v) => std::env::set_var("BUILDCLAMP_DISABLE", v),
                None => std::env::remove_var("BUILDCLAMP_DISABLE"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Exec: write xor execute, and deny-all.
// ---------------------------------------------------------------------------

/// A scratch directory the unit may write, canonical so the paths in the report and the
/// paths the plan names are the same string.
fn writable_scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let out = std::fs::canonicalize(scratch.path()).unwrap().join("out");
    std::fs::create_dir_all(&out).unwrap();
    (scratch, out)
}

/// Copy a real program into `out` and try to run it from there.
fn drop_and_run(out: &std::path::Path) -> Command {
    let mut c = sh(&format!(
        "cp /bin/true {0}/dropped && {0}/dropped",
        out.display()
    ));
    c.env("PATH", "/usr/bin:/bin");
    c
}

#[test]
fn a_program_written_into_a_no_exec_directory_cannot_be_run() {
    let host = probe::host();
    require!(
        host.landlock_abi.is_some() || host.seccomp_user_notif,
        "neither Landlock nor seccomp notification, so exec cannot be restricted here"
    );
    let (_scratch, out) = writable_scratch();
    let plan = Plan {
        allow_unix: true,
        writable: vec![out.clone()],
        no_exec: vec![out.clone()],
        ..Default::default()
    };
    let _lock = exclusive();
    let held = plan.hold(drop_and_run(&out)).expect("holding the unit");
    assert_ne!(held.exit_code, Some(0), "the dropped program ran");
    assert!(
        out.join("dropped").exists(),
        "the copy itself must succeed: this is write-xor-execute, not a write refusal"
    );
    let exec = held
        .tiers
        .get(&Capability::Exec.into())
        .map(Tier::label)
        .unwrap_or_default();
    eprintln!("exec tier on this host: {exec}");
    if let Some(abi) = host.landlock_abi {
        assert_eq!(exec, format!("enforced:landlock-v{abi}"));
    }
    if host.seccomp_user_notif {
        let dropped = format!("{}/dropped", out.display());
        assert!(
            held.requests
                .iter()
                .any(|r| r.capability.copied() == Some(Capability::Exec)
                    && r.target == dropped
                    && matches!(r.outcome, Outcome::Ungranted { .. })),
            "the refused exec must be in the record as ungranted: {:?}",
            held.requests
        );
    }
}

#[test]
fn landlock_alone_refuses_the_dropped_program() {
    // The supervisor's refusal is authoritative but its allow is a CONTINUE a unit can
    // race, so the guarantee has to hold with the supervisor out of the picture — and with
    // the noexec mount out of it too, or this would pass on the mount alone. So the program
    // is placed beforehand in a no-exec directory that is NOT a writable bind: it sits on
    // the read-only root, which is mounted executable, and only Landlock can refuse it.
    let host = probe::host();
    require!(host.landlock_abi.is_some(), "no Landlock on this host");
    require!(
        host.user_namespaces,
        "with notify off, nothing else could hold the unit"
    );
    let (_scratch, planted) = writable_scratch();
    std::fs::copy("/bin/true", planted.join("dropped")).unwrap();
    let plan = Plan {
        allow_unix: true,
        no_exec: vec![planted.clone()],
        ..Default::default()
    };
    let _off = DisableNs::set_to("notify");
    let held = plan
        .hold(sh(&format!("{}/dropped", planted.display())))
        .expect("holding the unit");
    let exec = held
        .tiers
        .get(&Capability::Exec.into())
        .map(Tier::label)
        .unwrap_or_default();
    assert!(exec.starts_with("enforced:landlock"), "exec tier: {exec}");
    assert_ne!(
        held.exit_code,
        Some(0),
        "Landlock let the dropped program run"
    );
}

#[test]
fn an_exec_zone_re_allows_running_what_the_unit_built() {
    let host = probe::host();
    require!(
        host.landlock_abi.is_some() || host.seccomp_user_notif,
        "exec is not restricted on this host, so there is nothing to re-allow"
    );
    let (_scratch, out) = writable_scratch();
    let plan = Plan {
        allow_unix: true,
        writable: vec![out.clone()],
        no_exec: vec![out.clone()],
        exec_allowed: vec![out.clone()],
        ..Default::default()
    };
    let _lock = exclusive();
    let held = plan.hold(drop_and_run(&out)).expect("holding the unit");
    assert_eq!(
        held.exit_code,
        Some(0),
        "an exec zone must allow what it names"
    );
}

#[test]
fn deny_exec_still_starts_the_program_and_refuses_everything_it_spawns() {
    let host = probe::host();
    require!(
        host.landlock_abi.is_some(),
        "no Landlock, so deny-all is advisory here"
    );
    let plan = Plan {
        allow_unix: true,
        deny_exec: true,
        ..Default::default()
    };
    let _lock = exclusive();
    // `exit 3` proves the shell itself ran; `/bin/true` is what it must not be able to run.
    let held = plan
        .hold(sh("/bin/true || exit 3"))
        .expect("the program itself, and its ELF interpreter, must be executable");
    assert_eq!(
        held.exit_code,
        Some(3),
        "the shell ran, and could not exec /bin/true"
    );
}

/// The dynamic loader for this architecture, if it is where the usual distributions put it.
fn loader() -> Option<&'static str> {
    ["/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
}

#[test]
fn the_loader_cannot_run_a_dropped_program_where_the_mount_namespace_applies() {
    // `ld.so ./written` execs only the loader, which lives outside every no-exec directory,
    // and the loader then maps the written file PROT_EXEC — which Landlock's EXECUTE right
    // does not see. The noexec mount does: the kernel refuses PROT_EXEC on it.
    let host = probe::host();
    require!(
        host.user_namespaces,
        "no user namespaces, so no noexec mount"
    );
    let Some(ld) = loader() else {
        eprintln!("SKIP: no dynamic loader at a known path");
        return;
    };
    let (_scratch, out) = writable_scratch();
    let plan = Plan {
        allow_unix: true,
        writable: vec![out.clone()],
        no_exec: vec![out.clone()],
        ..Default::default()
    };
    let _lock = exclusive();
    let held = plan
        .hold({
            let mut c = sh(&format!(
                "cp /bin/true {o}/dropped && {ld} {o}/dropped",
                o = out.display()
            ));
            c.env("PATH", "/usr/bin:/bin");
            c
        })
        .expect("holding the unit");
    assert!(out.join("dropped").exists(), "the copy must succeed");
    assert_ne!(
        held.exit_code,
        Some(0),
        "the loader ran a program written into a no-exec directory"
    );
}

#[test]
fn a_held_program_inside_a_no_exec_directory_still_starts() {
    // The supervisor always allows the held program; Landlock must too, or a unit whose
    // program lives where it can write (a grant writing `target`) starts on one host and
    // not another.
    let host = probe::host();
    require!(host.landlock_abi.is_some(), "no Landlock on this host");
    let (_scratch, out) = writable_scratch();
    std::fs::copy("/bin/true", out.join("prog")).unwrap();
    let plan = Plan {
        allow_unix: true,
        writable: vec![out.clone()],
        no_exec: vec![out.clone()],
        ..Default::default()
    };
    // With namespaces ON: the noexec bind is what refused it before the fix.
    let _lock = exclusive();
    let held = plan
        .hold(Command::new(out.join("prog")))
        .expect("the held program itself must be allowed to start");
    assert_eq!(held.exit_code, Some(0));
}

#[test]
fn a_program_run_from_a_memfd_is_a_known_limit() {
    // Stated in the README, the CHANGELOG and the claim's context, and pinned here so the
    // statement cannot go stale in either direction: a memfd is on no path, so neither the
    // Landlock rule nor the noexec mount covers it. If this starts failing, something now
    // stops it — update the docs, then this test.
    let host = probe::host();
    require!(
        host.landlock_abi.is_some() || host.user_namespaces,
        "nothing restricts exec here"
    );
    let has_python = Command::new("/bin/sh")
        .args(["-c", "command -v python3"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    require!(has_python, "no python3 to create a memfd with");
    // A host whose kernel refuses executable memfds itself (`vm.memfd_noexec`, 6.3+) closes
    // the hole without us, and that must not read as "buildclamp now stops it".
    let memfd_noexec = std::fs::read_to_string("/proc/sys/vm/memfd_noexec")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
    require!(
        memfd_noexec == 0,
        "the kernel already refuses executable memfds here"
    );
    let (_scratch, out) = writable_scratch();
    let plan = Plan {
        allow_unix: true,
        writable: vec![out.clone()],
        no_exec: vec![out.clone()],
        ..Default::default()
    };
    let _lock = exclusive();
    let held = plan
        .hold({
            let mut c = sh("python3 -c \"import os;fd=os.memfd_create('x');\
                            os.write(fd,open('/bin/true','rb').read());\
                            os.execve(fd,['t'],{})\"");
            c.env("PATH", "/usr/bin:/bin");
            c
        })
        .expect("holding the unit");
    assert_eq!(
        held.exit_code,
        Some(0),
        "a memfd exec is now refused — update the docs"
    );
}

// ---------------------------------------------------------------------------
// Reads: the allowlist.
// ---------------------------------------------------------------------------

#[test]
fn a_read_allowlist_leaves_only_the_allowed_roots_readable_minus_what_is_withheld() {
    let host = probe::host();
    require!(
        host.landlock_abi.is_some(),
        "no Landlock, so reads cannot be restricted here"
    );
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let base = std::fs::canonicalize(scratch.path()).unwrap();
    let allowed = base.join("allowed");
    let other = base.join("other");
    std::fs::create_dir_all(&allowed).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(allowed.join("ok.txt"), "fine\n").unwrap();
    std::fs::write(allowed.join(".netrc"), "machine x password PLACEHOLDER\n").unwrap();
    std::fs::write(other.join("token"), "PLACEHOLDER\n").unwrap();

    // The shell, `cat` and their libraries must stay readable, as they would for a real
    // build script under the allowlist.
    let mut roots: Vec<std::path::PathBuf> = ["/usr", "/lib", "/lib64", "/bin", "/etc"]
        .iter()
        .map(std::path::PathBuf::from)
        .collect();
    roots.push(allowed.clone());
    let plan = Plan {
        allow_unix: true,
        read_allowed: roots,
        withheld_reads: vec![allowed.join(".netrc")],
        ..Default::default()
    };
    let script = format!(
        "cat {a}/ok.txt >/dev/null || exit 2; \
         cat {o}/token >/dev/null 2>&1 && exit 3; \
         cat {a}/.netrc >/dev/null 2>&1 && exit 4; \
         exit 0",
        a = allowed.display(),
        o = other.display()
    );
    let _lock = exclusive();
    let held = plan
        .hold({
            let mut c = sh(&script);
            c.env("PATH", "/usr/bin:/bin");
            c
        })
        .expect("holding the unit");
    assert_eq!(
        held.exit_code,
        Some(0),
        "2 = an allowed file was unreadable, 3 = a file outside every root was read, \
         4 = a withheld file inside an allowed root was read"
    );
    let tier = held
        .tiers
        .get(&Capability::FsRead.into())
        .map(Tier::label)
        .unwrap_or_default();
    assert!(
        tier.starts_with("enforced:landlock"),
        "fs-read tier: {tier}"
    );
}

// ---------------------------------------------------------------------------
// Network destinations.
// ---------------------------------------------------------------------------

/// Linux 5.9+, for SECCOMP_IOCTL_NOTIF_ADDFD with SETFD — what destination mode needs.
fn kernel_has_addfd(host: &buildclamp_core::HostCapabilities) -> bool {
    let mut v = host
        .kernel
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .map(|p| p.parse::<u32>().unwrap_or(0));
    matches!((v.next(), v.next()), (Some(a), Some(b)) if (a, b) >= (5, 9))
}

#[test]
fn a_listed_destination_is_reachable_by_name_and_nothing_else_is() {
    let host = probe::host();
    require!(
        host.user_namespaces && host.seccomp_user_notif && kernel_has_addfd(&host),
        "destinations need an empty network namespace, the supervisor and Linux 5.9+"
    );
    let has_python = Command::new("/bin/sh")
        .args(["-c", "command -v python3"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    require!(has_python, "no python3 to make connections with");

    // A listener in THIS namespace, which the unit's empty one cannot reach on its own.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let allowed = listener.local_addr().unwrap();
    let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let denied = other.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            use std::io::Write;
            let mut s = s;
            let _ = s.write_all(b"HELLO\n");
        }
    });

    let plan = Plan {
        allow_unix: true,
        net_allowed: vec![allowed],
        hosts: Some("127.0.0.1 localhost\n127.0.0.1 allowed.test\n".into()),
        ..Default::default()
    };
    let script = format!(
        "python3 -c \"
import socket, sys
s = socket.create_connection(('allowed.test', {ap}), timeout=5)
if s.recv(16) != b'HELLO\\n': sys.exit(2)
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
# The proxied socket lives in the host's namespace. Disconnecting it (AF_UNSPEC) would let
# it be re-aimed, so that must be refused; and io_uring, which never passes the filter.
if libc.connect(s.fileno(), (ctypes.c_char * 16)(), 16) == 0: sys.exit(5)
if libc.syscall(425, 1, (ctypes.c_char * 120)()) >= 0: sys.exit(6)
# glibc's ranking probe: answered without CONTINUE, so it cannot be raced into a re-aim.
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if u.connect_ex(('127.0.0.1', 0)) != 101: sys.exit(7)
try:
    socket.create_connection(('127.0.0.1', {dp}), timeout=5)
    sys.exit(3)
except PermissionError:
    sys.exit(0)
except Exception as e:
    print(type(e).__name__); sys.exit(4)
\"",
        ap = allowed.port(),
        dp = denied.port()
    );
    let _lock = exclusive();
    let held = plan
        .hold({
            let mut c = sh(&script);
            c.env("PATH", "/usr/bin:/bin");
            c
        })
        .expect("holding the unit");
    assert_eq!(
        held.exit_code,
        Some(0),
        "2 = the listed destination did not answer, 3 = an unlisted one was reached, \
         4 = it failed some other way, 5 = the proxied socket could be disconnected and \
         re-aimed, 6 = io_uring was available, 7 = a datagram probe was not refused \
         with ENETUNREACH"
    );
    assert!(
        !held.requests.iter().any(|r| r.target.ends_with(":0")),
        "datagram probes are not recorded: {:?}",
        held.requests
    );
    let net = held
        .tiers
        .get(&Capability::Net.into())
        .map(Tier::label)
        .unwrap_or_default();
    assert_eq!(net, "enforced:netns+connect-proxy");
    assert!(
        held.requests
            .iter()
            .any(|r| r.target == allowed.to_string() && matches!(r.outcome, Outcome::Granted)),
        "the proxied connect is in the record as granted: {:?}",
        held.requests
    );
}

#[test]
fn observe_records_a_listed_destination_as_granted_and_an_unlisted_one_as_would_be_refused() {
    // Observe refuses nothing and runs on the real network, but what it records is what
    // `init` and drift read: a crate with a list must not have its listed connects recorded
    // as refused, nor glibc's datagram address-ranking probes recorded at all.
    let host = probe::host();
    require!(
        host.seccomp_user_notif,
        "observe records through the supervisor"
    );
    let has_python = Command::new("/bin/sh")
        .args(["-c", "command -v python3"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    require!(has_python, "no python3 to make connections with");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let allowed = listener.local_addr().unwrap();
    let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unlisted = other.local_addr().unwrap();
    std::thread::spawn(move || for _ in listener.incoming() {});
    std::thread::spawn(move || for _ in other.incoming() {});
    let plan = Plan {
        allow_unix: true,
        observe_only: true,
        net_allowed: vec![allowed],
        ..Default::default()
    };
    let script = format!(
        "python3 -c \"
import socket
socket.create_connection(('127.0.0.1', {a}), timeout=5)
socket.create_connection(('127.0.0.1', {u}), timeout=5)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.connect(('127.0.0.1', 0))
\"",
        a = allowed.port(),
        u = unlisted.port()
    );
    let _lock = exclusive();
    let held = plan
        .hold({
            let mut c = sh(&script);
            c.env("PATH", "/usr/bin:/bin");
            c
        })
        .expect("holding the unit");
    assert_eq!(held.exit_code, Some(0), "observe refuses nothing");
    let outcome = |t: String| {
        held.requests
            .iter()
            .find(|r| r.syscall == "connect" && r.target == t)
            .map(|r| r.outcome.clone())
    };
    assert!(matches!(
        outcome(allowed.to_string()),
        Some(Outcome::Granted)
    ));
    assert!(matches!(
        outcome(unlisted.to_string()),
        Some(Outcome::WouldBeUngranted)
    ));
    assert!(
        outcome("127.0.0.1:0".to_string()).is_none(),
        "a datagram connect is not network use and is not recorded"
    );
}
