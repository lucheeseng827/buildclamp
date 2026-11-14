//! The whole tool, driving a real cargo build of deliberately hostile crates.
//!
//! Every other test in this repository checks one decision. These check the claim: that
//! `cargo buildclamp build` stops what the August 2026 `arrayref` build script did, while
//! leaving an ordinary `cc`-shaped build script working.
//!
//! They compile the fixtures under `tests/fixtures/` with the real `cargo`, through the
//! real binary, in a scratch workspace. Nothing is mocked, because the thing under test
//! *is* the interception, and a mocked cargo would test the mock.
//!
//! # They skip rather than fail where the host cannot enforce
//!
//! A machine with no user namespaces and no seccomp cannot demonstrate enforcement, and a
//! red test there teaches nothing. Each check prints the mechanism it needed and returns.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The binary as cargo built it.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cargo-buildclamp"))
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/cli is two levels below the module root")
        .join("tests/fixtures")
}

/// Whether this host can demonstrate enforcement at all.
///
/// Asked of the tool itself, so the suite and the tool agree about the host — but asked
/// through `doctor --json`, so the answer does not depend on the width of a rendered
/// column.
///
/// **This function is why the suite is worth running.** An earlier version matched the
/// human-readable table with a fixed-width string, `"user namespaces               yes"`.
/// The rendered column is one space narrower than that, so the match failed on *every*
/// host: all seven tests below skipped everywhere, always, and the suite reported
/// `7 passed` having asserted nothing. A green gate that never ran is the exact false
/// assurance this tool exists to prevent, and it had it in its own tests.
///
/// So the rule is now explicit, and it is the same asymmetry the whole design follows
/// from: **"this host cannot enforce" and "I could not tell whether this host can
/// enforce" are different answers, and only the first may skip.** A guard that cannot
/// get an answer panics, because a suite that cannot establish its own preconditions
/// must not report success.
fn host_can_enforce() -> bool {
    let out = Command::new(bin())
        .args(["buildclamp", "doctor", "--json"])
        .output()
        .expect("doctor runs");

    assert!(
        out.status.success(),
        "`doctor --json` exited {:?}, so this suite cannot establish whether the host \
         can enforce. Refusing to skip: a skip here would report success having \
         asserted nothing.\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let host: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "`doctor --json` did not emit the HostCapabilities object this guard reads \
             ({e}). The guard must fail rather than skip, or a change to the output \
             silently disables every test below.\nstdout:\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });

    host.get("user_namespaces")
        .and_then(serde_json::Value::as_bool)
        .expect(
            "`user_namespaces` must be a bool in `doctor --json`; this guard depends on \
             it and must fail rather than skip if the field moves or is renamed",
        )
}

/// A scratch workspace depending on the named fixtures.
struct Victim {
    dir: tempfile::TempDir,
}

impl Victim {
    fn new(deps: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("a scratch workspace");
        let f = fixtures();
        let mut manifest = String::from(
            "[workspace]\n[package]\nname = \"victim\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
        );
        for d in deps {
            manifest.push_str(&format!("{d} = {{ path = \"{}\" }}\n", f.join(d).display()));
        }
        std::fs::write(dir.path().join("Cargo.toml"), manifest).unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "// nothing\n").unwrap();
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Run a buildclamp subcommand in this workspace, with credentials planted in the
    /// environment so the scrub has something to remove.
    fn run(&self, args: &[&str]) -> Output {
        Command::new(bin())
            .arg("buildclamp")
            .args(args)
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path().join("home"))
            .env("GITHUB_TOKEN", "ghp_planted_for_the_test")
            .env("AWS_SECRET_ACCESS_KEY", "planted_for_the_test")
            .output()
            .expect("the binary runs")
    }

    fn report(&self) -> serde_json::Value {
        let p = self.dir.path().join("target/buildclamp/report.json");
        let text = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("no report at {}: {e}", p.display()));
        serde_json::from_str(&text).expect("the report is valid JSON")
    }

    fn persistence_file(&self) -> PathBuf {
        self.dir.path().join("home/.config/autostart/evil.desktop")
    }
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn the_replica_of_the_arrayref_build_script_is_stopped_and_named() {
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["evil"]);
    let out = v.run(&["build"]);

    // Exit 2, not 1: CI has to tell "the tool broke" from "the policy said no".
    assert_eq!(code(&out), 2, "stderr:\n{}", stderr(&out));

    // The one message cargo shows must name the crate and what it tried to do. This is
    // the entire developer experience of a refusal.
    let err = stderr(&out);
    assert!(err.contains("evil@0.1.3"), "{err}");
    assert!(err.contains("reach the network"), "{err}");
    assert!(err.contains("[grants.\"evil\"]"), "{err}");

    // The build script's own step markers are the ground truth for what was stopped.
    // Compare against tests/fixtures/README.md, which records the unsandboxed baseline.
    assert!(
        err.contains("evil-step:2:connect:err:"),
        "the connection was not refused:\n{err}"
    );
    assert!(
        err.contains("evil-step:5:persist-outside-out-dir:err:"),
        "the persistence write outside OUT_DIR succeeded:\n{err}"
    );
    assert!(
        err.contains("evil-note:env-visible=\n") || err.contains("evil-note:env-visible=\r\n"),
        "credentials were still visible in the unit's environment:\n{err}"
    );
    assert!(
        err.contains("evil-step:4:read-parent-environ:err:"),
        "the unit read its parent's environment through /proc:\n{err}"
    );

    // And the legitimate half still worked, or the tool is useless.
    assert!(
        err.contains("evil-step:6:write-out-dir:ok"),
        "OUT_DIR was not writable:\n{err}"
    );

    // The persistence file must not exist on disk.
    assert!(
        !v.persistence_file().exists(),
        "the build script achieved persistence at {}",
        v.persistence_file().display()
    );
}

#[test]
fn a_held_build_script_can_create_threads() {
    // The regression this test exists for, and it is not a capability question: the
    // sandbox used to `unshare(CLONE_NEWPID)` without forking before `execve`, which sets
    // `pid_for_children` without moving the caller. The kernel refuses `CLONE_THREAD`
    // while those differ, so every held unit was single-threaded and any that tried to
    // create a thread died with EINVAL.
    //
    // Nothing caught it: every fixture here was single-threaded and no compile unit had
    // ever been held. It surfaced when rustc went under the sandbox and panicked at
    // startup, because `install_ctrlc_handler` spawns a thread.
    //
    // `cc` compiles in parallel with threads and `bindgen` uses them, so the blast radius
    // was most `-sys` crates in the ecosystem — builds broken by buildclamp, for a reason
    // nothing in the report would have explained.
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["threaded"]);
    let out = v.run(&["build"]);
    assert_eq!(
        code(&out),
        0,
        "a held build script could not create a thread:\n{}",
        stderr(&out)
    );

    let report = v.report();
    let units = report["units"].as_array().expect("units");
    assert!(
        units.iter().any(|u| u["id"]["name"] == "threaded"),
        "the threaded fixture must actually have been held, or this proves nothing"
    );
}

#[test]
fn an_ordinary_build_script_still_builds_under_an_environment_allowlist() {
    // The adoption question for `env-allowlist`, asked the same way as for the deny-list:
    // a hardening option that breaks `cc`-shaped build scripts is one nobody leaves on, so
    // the base set is only defensible if the benign fixture passes under it.
    //
    // The fixture spawns a compiler and reads its own manifest directory, which is exactly
    // the path that needs PATH, HOME, OUT_DIR, CARGO_MANIFEST_DIR and the rest to survive.
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["benign"]);
    std::fs::write(
        v.path().join("buildclamp.toml"),
        "version = 1\n\n[defaults]\nenv-allowlist = true\n",
    )
    .unwrap();

    let out = v.run(&["build"]);
    assert_eq!(
        code(&out),
        0,
        "the benign fixture broke under the allowlist, so the base set is missing \
         something every build script needs:\n{}",
        stderr(&out)
    );

    let report = v.report();
    let units = report["units"].as_array().expect("units");
    assert!(!units.is_empty(), "no units were recorded at all");
    // And the report says which rules the unit ran under, so a later "why did my variable
    // disappear?" is answerable from the document rather than from a policy file that may
    // have changed since.
    assert!(
        units
            .iter()
            .any(|u| u["envelope"]["env_allowlist"] == serde_json::Value::Bool(true)),
        "the report must record that the allowlist applied"
    );
}

#[test]
fn an_ordinary_build_script_produces_no_ungranted_requests() {
    // The false-positive gate. A default-deny policy that breaks `cc`, `bindgen` and
    // `pkg-config` on the first run is dead on arrival, so this failing is as serious as
    // the malicious fixture getting through.
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["benign"]);
    // `--deep` on purpose. Without it the filesystem tier is Landlock, the kernel permits
    // every write inside OUT_DIR without the supervisor seeing one, and this gate would
    // pass over a build where the supervisor's own path handling was wrong — which is
    // exactly the defect the fixture's `remove_dir_all` was added for. `--deep` is what
    // makes the supervisor judge each write, so the judgement is what is under test.
    let out = v.run(&["build", "--deep"]);
    assert_eq!(
        code(&out),
        0,
        "the benign fixture was refused:\n{}",
        stderr(&out)
    );

    let report = v.report();
    let units = report["units"].as_array().expect("units");
    assert!(!units.is_empty(), "no units were recorded at all");
    for u in units {
        let ungranted: Vec<_> = u["requests"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["outcome"]["outcome"] != "granted")
            .collect();
        assert!(
            ungranted.is_empty(),
            "the benign fixture had ungranted requests: {ungranted:#?}"
        );
    }
}

#[test]
fn observe_records_what_enforcement_would_refuse_without_refusing_it() {
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["evil"]);
    let out = v.run(&["observe"]);

    // Observe mode must never be the reason a build broke.
    assert_eq!(
        code(&out),
        0,
        "observe refused something:\n{}",
        stderr(&out)
    );
    // …which means the build script really did everything, including the persistence
    // write. Observe mode observes; it does not protect, and the docs say so.
    assert!(
        v.persistence_file().exists(),
        "observe mode prevented a write, so it is not observing what the build does"
    );

    // And it recorded what enforcement would have refused, or `init` has nothing to work
    // from and the operator is told a build is clean that enforcing would break.
    let report = v.report();
    let would: Vec<_> = report["units"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|u| u["requests"].as_array().unwrap())
        .filter(|r| r["outcome"]["outcome"] == "would-be-ungranted")
        .collect();
    assert!(
        !would.is_empty(),
        "observe mode recorded nothing that enforcement would refuse: {report:#?}"
    );
}

#[test]
fn observe_then_init_then_build_is_a_green_build() {
    // The adoption path, end to end. If this fails the tool cannot be adopted by a real
    // repository, whatever else it does.
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["evil", "benign"]);

    assert_eq!(code(&v.run(&["observe"])), 0);
    let init = v.run(&["init"]);
    assert_eq!(code(&init), 0, "{}", stderr(&init));

    let policy = std::fs::read_to_string(v.path().join("buildclamp.toml")).expect("a policy");
    assert!(policy.contains("[grants.evil]"), "{policy}");
    assert!(
        policy.contains("OBSERVED"),
        "the why must say it is an observation:\n{policy}"
    );
    assert!(
        policy.contains("reviewed = false"),
        "a generated grant must never be marked reviewed:\n{policy}"
    );
    // The destination list must hold destinations, not descriptions of the call.
    assert!(
        !policy.contains("AF_INET socket"),
        "a socket family leaked into net-destinations:\n{policy}"
    );

    // Clean, so cargo actually re-runs the build scripts against the new policy.
    std::fs::remove_dir_all(v.path().join("target")).ok();
    let built = v.run(&["build"]);
    assert_eq!(
        code(&built),
        0,
        "the generated policy did not make the build pass:\n{}",
        stderr(&built)
    );
}

#[test]
fn strict_refuses_an_unreviewed_policy_even_when_nothing_rebuilt() {
    // Cargo re-runs a build script only when it decides the unit is dirty, so a second
    // `--strict` in a row can run no units at all. A `--strict` that counted units rather
    // than grants would pass an entirely unreviewed policy on that second invocation.
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["evil"]);
    assert_eq!(code(&v.run(&["observe"])), 0);
    assert_eq!(code(&v.run(&["init"])), 0);

    let first = v.run(&["build", "--strict"]);
    assert_eq!(code(&first), 2, "{}", stderr(&first));
    // Again, with nothing to rebuild.
    let second = v.run(&["build", "--strict"]);
    assert_eq!(
        code(&second),
        2,
        "--strict passed on a second run because nothing rebuilt:\n{}",
        String::from_utf8_lossy(&second.stdout)
    );

    // Marking the grants read makes it pass, which is the whole mechanism.
    let p = v.path().join("buildclamp.toml");
    let text = std::fs::read_to_string(&p)
        .unwrap()
        .replace("reviewed = false", "reviewed = true");
    std::fs::write(&p, text).unwrap();
    assert_eq!(code(&v.run(&["build", "--strict"])), 0);
}

#[test]
fn require_enforced_fails_where_the_host_can_only_be_advisory() {
    // A green build on a machine that could not enforce anything is the false assurance
    // this tool exists to avoid, so CI can refuse to accept one. `BUILDCLAMP_DISABLE`
    // makes that path testable on a host that has everything.
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["benign"]);
    assert_eq!(code(&v.run(&["build", "--require-enforced"])), 0);

    std::fs::remove_dir_all(v.path().join("target")).ok();
    let degraded = Command::new(bin())
        .args(["buildclamp", "build", "--require-enforced"])
        .current_dir(v.path())
        .env("HOME", v.path().join("home"))
        .env("BUILDCLAMP_DISABLE", "ns")
        .output()
        .expect("the binary runs");
    assert_eq!(
        code(&degraded),
        2,
        "a run with only advisory enforcement passed --require-enforced:\n{}",
        String::from_utf8_lossy(&degraded.stdout)
    );
}

#[test]
fn a_build_script_compiled_before_buildclamp_was_involved_is_still_held() {
    // The blocker an adversarial review found: cargo does not put RUSTC_WRAPPER in a
    // fingerprint, so a target directory populated by a plain `cargo build` keeps its
    // build scripts un-shimmed and the wrapper never sees them. Without the pre-exec
    // sweep this test passes with exit 0 and an empty report — the tool reporting success
    // while enforcing nothing.
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["evil"]);

    // A plain build first, exactly as a CI cache restore or a colleague would leave it.
    let plain = Command::new("cargo")
        .arg("build")
        .current_dir(v.path())
        .env("HOME", v.path().join("home"))
        .output()
        .expect("cargo runs");
    assert!(
        plain.status.success(),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );
    assert!(
        v.persistence_file().exists(),
        "the plain build should have let the fixture persist; the test proves nothing otherwise"
    );
    std::fs::remove_file(v.persistence_file()).unwrap();

    // Now make cargo consider the unit dirty without recompiling the script, which is what
    // a `rerun-if-changed` file moving does in a real repository.
    let out = v.run(&["build"]);
    let combined = format!("{}{}", stderr(&out), String::from_utf8_lossy(&out.stdout));

    // Either the unit was re-run and refused, or it was not re-run at all — but it must
    // never have run unheld and achieved persistence.
    assert!(
        !v.persistence_file().exists(),
        "a build script compiled before buildclamp was involved ran unheld:\n{combined}"
    );
}
