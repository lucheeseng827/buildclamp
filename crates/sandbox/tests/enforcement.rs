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
        let guard = exclusive();
        let prev = std::env::var("BUILDCLAMP_DISABLE").ok();
        // SAFETY: `guard` is held for this value's whole lifetime and every other test
        // that reads the variable through `hold` takes the same lock, so no other thread
        // in this process is reading the environment while it is being written.
        unsafe { std::env::set_var("BUILDCLAMP_DISABLE", "ns") };
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
