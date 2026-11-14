//! Proc-macro expansion, held.
//!
//! # Why these two fixtures existed for months and were referenced by no test
//!
//! `evilmacro` and `macrouser` were written for this and then stranded: the wrapper passed
//! `HoldCompile` and `CompileAndRecordMacro` straight to `passthrough`, so there was
//! nothing to point them at. The README meanwhile said every proc-macro runs inside a
//! capability envelope. It did not, and this suite is what makes the sentence true in the
//! present tense rather than in intent.
//!
//! # The baseline is the interesting half
//!
//! Expansion happens inside the rustc compiling the **consumer**, so a tool that holds only
//! build scripts does not see it at all. The baseline test below shows exactly that: with
//! compile units unheld, the fixture macro writes a persistence file into `$HOME` from
//! inside rustc and nothing stops it or records it. That is the gap, demonstrated, before
//! anything claims to close it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

fn host_can_enforce() -> bool {
    let out = Command::new(bin())
        .args(["buildclamp", "doctor", "--json"])
        .output()
        .expect("doctor runs");
    assert!(
        out.status.success(),
        "`doctor --json` exited {:?}; refusing to skip on an answer this suite could not \
         establish",
        out.status.code()
    );
    let host: serde_json::Value = serde_json::from_slice(&out.stdout).expect("HostCapabilities");
    host["user_namespaces"].as_bool().expect("a bool")
}

/// A workspace whose compilation expands the hostile fixture macro.
struct Consumer {
    dir: tempfile::TempDir,
}

impl Consumer {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a scratch workspace");
        std::fs::write(
            dir.path().join("Cargo.toml"),
            format!(
                "[workspace]\n[package]\nname = \"consumer\"\nversion = \"0.1.0\"\n\
                 edition = \"2021\"\n\n[dependencies]\nmacrouser = {{ path = \"{}\" }}\n",
                fixtures().join("macrouser").display()
            ),
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub use macrouser::Thing;\n").unwrap();
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        Self { dir }
    }

    fn policy(&self, hold: bool) {
        let text = if hold {
            "version = 1\n\n[defaults]\nhold-compile-units = true\n"
        } else {
            "version = 1\n"
        };
        std::fs::write(self.dir.path().join("buildclamp.toml"), text).unwrap();
    }

    fn check(&self) -> Output {
        let _ = std::fs::remove_dir_all(self.dir.path().join("target"));
        let _ = std::fs::remove_dir_all(self.dir.path().join("home/.config"));
        Command::new(bin())
            .args(["buildclamp", "check"])
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path().join("home"))
            .output()
            .expect("the binary runs")
    }

    /// Did the macro's persistence write land? This is the one the sandbox can actually
    /// stop, and the one whose success is the whole point of the baseline.
    fn persisted(&self) -> bool {
        self.dir
            .path()
            .join("home/.config/autostart/evilmacro.desktop")
            .exists()
    }

    fn report(&self) -> serde_json::Value {
        let text =
            std::fs::read_to_string(self.dir.path().join("target/buildclamp/report.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }
}

#[test]
fn an_unheld_compile_lets_a_proc_macro_persist_to_the_home_directory() {
    // The gap, demonstrated. Expansion runs inside the rustc compiling the consumer, so a
    // tool that holds only build scripts never sees it — and this fixture writes a
    // `.desktop` autostart entry from inside rustc, which is a machine that stays
    // compromised after the build.
    //
    // Asserted rather than assumed, because the refusal below means nothing without it.
    let c = Consumer::new();
    c.policy(false);
    let out = c.check();
    assert_eq!(
        out.status.code(),
        Some(0),
        "the baseline build must succeed\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        c.persisted(),
        "the fixture must actually reach the home directory when nothing holds it, or the \
         enforced test below is asserting against a macro that never ran"
    );
}

#[test]
fn a_held_compile_refuses_what_the_proc_macro_does_at_expansion_time() {
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let c = Consumer::new();
    c.policy(true);
    let out = c.check();
    // Exit 2, not 0, and the distinction is the 0/1/2 contract this tool is built on: the
    // compilation SUCCEEDED and the policy's answer was no. A proc-macro reaching for the
    // network is a finding, so an enforcing run fails on it — 1 would mean the tool or the
    // build broke, which is a different thing and would send somebody to the wrong place.
    assert_eq!(
        out.status.code(),
        Some(2),
        "an ungranted request inside a held compile must fail the run as a policy answer\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !c.persisted(),
        "the proc-macro wrote its persistence file from inside a held rustc"
    );

    // The macro's own log lines say which way each step went. `PermissionDenied` on the
    // connect is the sandbox refusing it; `ConnectionRefused` would mean nothing was
    // listening and the sandbox never came into it, which is what the baseline sees.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let log = format!("{stdout}{stderr}");
    assert!(
        log.contains("evilmacro-step:1:connect:err:PermissionDenied"),
        "the network reach must be refused by the sandbox, not merely fail to \
         connect:\n{log}"
    );
}

#[test]
fn a_refusal_inside_a_compile_names_the_macros_that_could_have_been_responsible() {
    // The attribution this buys, and the limit on it, in one assertion. Expansion happens
    // inside a rustc that has already loaded every proc-macro in the closure, so the
    // report names the compilation and the macros that could have done it — not which one
    // did. `docs/adr/0004` argues why that is worth shipping; `cargo-acl` gives the same
    // answer and says so.
    //
    // This also pins the inventory itself: `proc_macros_in_closure` was `Vec::new()` at
    // its only call site until the run directory learned to carry macro objects between
    // the rustc that compiled one and the rustc that loaded it.
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let c = Consumer::new();
    c.policy(true);
    // 2: the compilation succeeded and the policy's answer was no. See the test above.
    assert_eq!(c.check().status.code(), Some(2));

    let report = c.report();
    let units = report["units"].as_array().expect("units");
    let offender = units
        .iter()
        .find(|u| {
            u["requests"]
                .as_array()
                .is_some_and(|rs| rs.iter().any(|r| r["outcome"]["outcome"] != "granted"))
        })
        .expect("some unit made an ungranted request");

    assert_eq!(
        offender["id"]["name"], "macrouser",
        "the unit is the crate being COMPILED, which is where expansion happened"
    );
    let closure: Vec<&str> = offender["proc_macros_in_closure"]
        .as_array()
        .expect("a closure list")
        .iter()
        .filter_map(|m| m["name"].as_str())
        .collect();
    assert!(
        closure.contains(&"evilmacro"),
        "the macro that could have been responsible must be named: {closure:?}"
    );
}

#[test]
fn an_ordinary_build_survives_having_its_compile_units_held() {
    // The adoption question, and the one that decides whether this can ever be default.
    // The graph here spawns a compiler from a build script and creates threads from
    // another, which between them cover what broke the first time rustc went under the
    // sandbox.
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let f = fixtures();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        format!(
            "[workspace]\n[package]\nname = \"ordinary\"\nversion = \"0.1.0\"\n\
             edition = \"2021\"\n\n[dependencies]\nbenign = {{ path = \"{}\" }}\n\
             threaded = {{ path = \"{}\" }}\n",
            f.join("benign").display(),
            f.join("threaded").display()
        ),
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src/lib.rs"),
        "pub fn n() -> usize { benign::entries().len() + threaded::THREAD_SUM as usize }\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("buildclamp.toml"),
        "version = 1\n\n[defaults]\nhold-compile-units = true\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("home")).unwrap();

    let out = Command::new(bin())
        .args(["buildclamp", "build"])
        .current_dir(dir.path())
        .env("HOME", dir.path().join("home"))
        .output()
        .expect("the binary runs");
    assert_eq!(
        out.status.code(),
        Some(0),
        "an ordinary build broke under compile holding\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = std::fs::read_to_string(dir.path().join("target/buildclamp/report.json")).unwrap();
    let report: serde_json::Value = serde_json::from_str(&text).unwrap();
    let units = report["units"].as_array().unwrap();
    assert!(
        units.iter().any(|u| u["kind"] == "compile"),
        "compile units must actually have been held, or this proves nothing"
    );
    let ungranted: usize = units
        .iter()
        .filter_map(|u| u["requests"].as_array())
        .flatten()
        .filter(|r| r["outcome"]["outcome"] != "granted")
        .count();
    assert_eq!(ungranted, 0, "an ordinary graph must ask for nothing extra");
}

/// A workspace whose compilation expands BOTH a probe macro that issues a syscall from its
/// own code and a quiet one that does nothing — so `exact` attribution can be shown to name
/// the culprit and only the culprit.
fn exact_consumer() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a scratch workspace");
    let f = fixtures();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        format!(
            "[workspace]\n[package]\nname = \"probeconsumer\"\nversion = \"0.1.0\"\n\
             edition = \"2021\"\n\n[dependencies]\nprobemacro = {{ path = \"{}\" }}\n\
             quietmacro = {{ path = \"{}\" }}\n",
            f.join("probemacro").display(),
            f.join("quietmacro").display()
        ),
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src/lib.rs"),
        "#[derive(probemacro::Probe)]\npub struct A;\n\
         #[derive(quietmacro::Quiet)]\npub struct B;\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("buildclamp.toml"),
        "version = 1\n\n[defaults]\nhold-compile-units = true\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("home")).unwrap();
    dir
}

#[test]
fn a_held_compile_names_the_exact_proc_macro_that_reached_out() {
    // The differentiator, proven by an executing test rather than a unit test over
    // fabricated `/proc` maps. `probemacro` issues `socket` with an inline `syscall`
    // instruction compiled into its own shared object, so the instruction pointer the kernel
    // records falls inside `libprobemacro-*.so` and the supervisor names it at `exact` — not
    // `closure`, which is all a tool holding only the compilation could ever say.
    //
    // `quietmacro` is in the same closure and does nothing. The precision half is the sharp
    // one: `exact` must name the culprit and NOT the innocent macro beside it, because a
    // false attribution at `exact` is an accusation made on the user's behalf.
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let dir = exact_consumer();
    let _ = std::fs::remove_dir_all(dir.path().join("target"));
    let out = Command::new(bin())
        .args(["buildclamp", "check"])
        .current_dir(dir.path())
        .env("HOME", dir.path().join("home"))
        .output()
        .expect("the binary runs");
    // The socket is ungranted, so a held run fails on it as a policy answer: exit 2.
    assert_eq!(
        out.status.code(),
        Some(2),
        "the probe's socket must be refused as a policy answer\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = std::fs::read_to_string(dir.path().join("target/buildclamp/report.json")).unwrap();
    let report: serde_json::Value = serde_json::from_str(&text).unwrap();
    let units = report["units"].as_array().expect("units");
    let requests: Vec<&serde_json::Value> = units
        .iter()
        .filter_map(|u| u["requests"].as_array())
        .flatten()
        .collect();

    // The exact one: a `socket` request attributed to probemacro with `exact` confidence.
    let exact = requests
        .iter()
        .find(|r| r["attribution"]["confidence"] == "exact")
        .unwrap_or_else(|| {
            panic!(
                "no request was attributed at `exact`; attributions seen: {:?}",
                requests
                    .iter()
                    .map(|r| &r["attribution"])
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        exact["attribution"]["proc_macro"]["name"], "probemacro",
        "the exact attribution must name the macro whose own code made the syscall"
    );
    assert_eq!(
        exact["syscall"], "socket",
        "the probe issues a socket(2), the notified call its .so traps on"
    );

    // Precision: quietmacro is in the closure but must never be the NAMED culprit of
    // anything. It did nothing; naming it would be a false accusation at `exact`.
    for r in &requests {
        assert_ne!(
            r["attribution"]["proc_macro"]["name"], "quietmacro",
            "the innocent macro in the closure was named as a culprit: {r}"
        );
    }

    // The closure — the incumbent's answer — still carries BOTH macros, which is exactly
    // what `exact` improves on: the set names everyone who COULD have done it; `exact` names
    // the one that did.
    let offender = units
        .iter()
        .find(|u| {
            u["requests"]
                .as_array()
                .is_some_and(|rs| rs.iter().any(|r| r["attribution"]["confidence"] == "exact"))
        })
        .expect("the unit that made the exact request");
    let closure: Vec<&str> = offender["proc_macros_in_closure"]
        .as_array()
        .expect("a closure list")
        .iter()
        .filter_map(|m| m["name"].as_str())
        .collect();
    assert!(
        closure.contains(&"probemacro") && closure.contains(&"quietmacro"),
        "the closure set must name every proc-macro the compilation loaded: {closure:?}"
    );
}
