//! The kill switch, and the rule that it can never be silent.
//!
//! A vendor binary that sits in every build needs an emergency off, and a platform team
//! asks for it before they ask what the tool does. `BUILDCLAMP_DISABLE` is not that
//! switch: it removes one mechanism at a time, it exists so the fallback tiers are
//! testable on a host that has everything, and its name tells a reader nothing useful.
//!
//! The property that makes an off switch safe to ship is the one these tests pin: **a run
//! with enforcement switched off still says so, in both places a person looks.** An
//! emergency exit that leaves no trace is indistinguishable from a tool that was never
//! installed, and six months later nobody can tell which builds were held.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test binary has a path");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("cargo-buildclamp")
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/cli is two levels below the module root")
        .join("tests/fixtures")
}

/// A scratch workspace depending on the hostile fixture, with a policy that grants nothing.
struct Victim {
    dir: tempfile::TempDir,
}

impl Victim {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("scratch dir");
        let root = dir.path();
        copy_dir(&fixtures().join("evil"), &root.join("evil"));
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"victim\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nevil = { path = \"evil\" }\n[workspace]\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        std::fs::write(root.join("buildclamp.toml"), "version = 1\n").unwrap();
        Self { dir }
    }

    fn run(&self, env: &[(&str, &str)]) -> (i32, String) {
        // Each run starts from a clean target directory. Cargo marks a unit fresh only
        // when it SUCCEEDED, so the freshness trap springs on exactly the green path a
        // test is trusted to have measured.
        let _ = std::fs::remove_dir_all(self.dir.path().join("target"));
        let mut c = Command::new(bin());
        c.args(["buildclamp", "build"]).current_dir(self.dir.path());
        for (k, v) in env {
            c.env(k, v);
        }
        let out = c.output().expect("buildclamp runs");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned()
                + &String::from_utf8_lossy(&out.stderr),
        )
    }

    fn report(&self) -> serde_json::Value {
        let text = std::fs::read_to_string(self.dir.path().join("target/buildclamp/report.json"))
            .expect("a report must exist even with enforcement off — that is the point");
        serde_json::from_str(&text).expect("the report parses")
    }

    fn set_policy(&self, text: &str) {
        std::fs::write(self.dir.path().join("buildclamp.toml"), text).unwrap();
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let p = e.path();
        let dest = to.join(p.file_name().unwrap());
        if p.is_dir() {
            copy_dir(&p, &dest);
        } else {
            std::fs::copy(&p, &dest).unwrap();
        }
    }
}

fn host_can_enforce() -> bool {
    let out = Command::new(bin())
        .args(["buildclamp", "doctor", "--json"])
        .output()
        .expect("doctor runs");
    assert!(out.status.success(), "doctor --json failed");
    let host: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("doctor --json parses");
    host.get("user_namespaces")
        .and_then(serde_json::Value::as_bool)
        .expect("`user_namespaces` is a bool")
}

#[test]
fn without_the_switch_the_hostile_fixture_is_still_refused() {
    // The control. Every assertion below is about a build that would otherwise fail, so
    // this establishes that it does — a kill-switch test against a build that passes
    // anyway would prove nothing about the switch.
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new();
    let (code, _) = v.run(&[]);
    assert_eq!(
        code, 2,
        "the evil fixture must be refused without the switch"
    );
}

#[test]
fn the_environment_switch_lets_the_build_through_and_says_so() {
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new();
    let (code, stdout) = v.run(&[("BUILDCLAMP_MODE", "off")]);
    assert_ne!(code, 2, "with enforcement off nothing may be refused");

    let r = v.report();
    assert_eq!(r["mode"], "off");
    let o = &r["disable_overrides"][0];
    assert_eq!(o["source"], "BUILDCLAMP_MODE");
    assert_eq!(o["value"], "off");

    // Both places a person looks. The report was faithful before the terminal was, and a
    // switch that is honest only in a JSON file somebody has to go and open is a silent
    // switch.
    assert!(
        stdout.contains("ENFORCEMENT WAS SWITCHED OFF"),
        "the terminal must say so too:\n{stdout}"
    );
}

#[test]
fn the_policy_switch_works_and_is_attributed_to_the_policy() {
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new();
    v.set_policy("version = 1\nenforcement = \"disabled\"\n");
    let (code, _) = v.run(&[]);
    assert_ne!(code, 2);

    let r = v.report();
    assert_eq!(r["mode"], "off");
    // Which switch it was matters: this one needs commit access to the policy, the
    // environment one only needs control of CI. A reviewer deciding how much to worry
    // needs to be able to tell them apart.
    assert_eq!(r["disable_overrides"][0]["source"], "buildclamp.toml");
}

#[test]
fn the_per_mechanism_knob_is_recorded_even_though_it_still_enforces() {
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new();
    let (_, _) = v.run(&[("BUILDCLAMP_DISABLE", "ns")]);
    let r = v.report();

    // Still enforce mode — this knob takes a mechanism, not the whole tool. That is
    // exactly why it needs recording: the tiers will still read `enforced:` from whatever
    // mechanism remains, so nothing else in the report would show that somebody had
    // reached in and weakened it.
    assert_eq!(r["mode"], "enforce");
    let sources: Vec<&str> = r["disable_overrides"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|o| o["source"].as_str().unwrap())
        .collect();
    assert!(
        sources.contains(&"BUILDCLAMP_DISABLE"),
        "the per-mechanism knob must be recorded: {sources:?}"
    );
}

#[test]
fn a_policy_that_disables_enforcement_still_parses_on_a_release_that_ignores_it() {
    // Forward compatibility, which is why the key is reserved now rather than when the
    // bundle mechanism lands. `Policy` carries `deny_unknown_fields`, so a release that
    // had never heard of this key would reject the whole bundle carrying it — making an
    // org-wide off switch undeployable at exactly the moment it is wanted.
    let p = buildclamp_core::Policy::parse("version = 1\nenforcement = \"disabled\"\n")
        .expect("the reserved key must parse");
    assert_eq!(p.enforcement, Some(buildclamp_core::Enforcement::Disabled));

    let absent = buildclamp_core::Policy::parse("version = 1\n").expect("parses");
    assert_eq!(absent.enforcement, None, "absent means enforcing");
}
