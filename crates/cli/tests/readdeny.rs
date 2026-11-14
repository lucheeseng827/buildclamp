//! Withheld reads, driven against a real cargo and a real Landlock ruleset.
//!
//! # The baseline is half the test
//!
//! Every assertion here comes in a pair: the same fixture, the same planted credentials,
//! once with `withhold-secret-reads` off and once with it on. A refusal on its own proves
//! nothing — a fixture that could not find the file, a `HOME` the test forgot to set, a
//! typo in a path, all look exactly like enforcement working. The baseline run has to
//! **succeed at reading every one of them** before the enforced run's refusal means
//! anything, so the baseline is asserted rather than assumed.
//!
//! # The tier is named, not merely present
//!
//! The refusal is asserted against `enforced:landlock-vN` specifically. A silent regression
//! to a weaker mechanism — a mount namespace, which cannot express a read restriction at
//! all — would still produce a report and still produce a green build, and naming the tier
//! is what makes that fail here instead of shipping.

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

/// Whether this host can demonstrate a Landlock read restriction.
///
/// A guard that cannot get an answer panics rather than skipping, the same rule
/// `endtoend.rs` follows: "this host cannot enforce" and "I could not tell" are different
/// answers and only the first may skip.
fn landlock_abi() -> Option<i64> {
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
    let host: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("doctor --json emits HostCapabilities");
    host["landlock_abi"].as_i64()
}

/// A workspace whose dependency's build script reads credentials out of a planted `HOME`.
struct Victim {
    dir: tempfile::TempDir,
}

impl Victim {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a scratch workspace");
        let f = fixtures();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            format!(
                "[workspace]\n[package]\nname = \"victim\"\nversion = \"0.1.0\"\n\
                 edition = \"2021\"\n\n[dependencies]\ncredreader = {{ path = \"{}\" }}\n",
                f.join("credreader").display()
            ),
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "// nothing\n").unwrap();

        // The planted credentials. Obvious placeholders: a fixture carrying anything that
        // looked like a live key would be a liability in a public repository, and the test
        // only needs the paths to exist with known contents.
        let home = dir.path().join("home");
        for (rel, body) in [
            (
                ".aws/credentials",
                "[default]\naws_access_key_id = PLACEHOLDER\n",
            ),
            (".ssh/id_ed25519", "PLACEHOLDER-NOT-A-KEY\n"),
            (
                ".config/gh/hosts.yml",
                "github.com:\n  oauth_token: PLACEHOLDER\n",
            ),
            (
                ".cargo/credentials.toml",
                "[registry]\ntoken = \"PLACEHOLDER\"\n",
            ),
        ] {
            let p = home.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        Self { dir }
    }

    fn policy(&self, withhold: bool) {
        let text = if withhold {
            "version = 1\n\n[defaults]\nwithhold-secret-reads = true\n"
        } else {
            "version = 1\n"
        };
        std::fs::write(self.dir.path().join("buildclamp.toml"), text).unwrap();
    }

    fn check(&self) -> Output {
        // A fresh target each time: cargo would otherwise consider the build script fresh
        // and not run it, and a test whose subject never executed passes for the wrong
        // reason — the same trap the `install` verb has.
        let _ = std::fs::remove_dir_all(self.dir.path().join("target"));
        Command::new(bin())
            .args(["buildclamp", "check"])
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path().join("home"))
            .output()
            .expect("the binary runs")
    }

    /// What the build script recorded about itself, out of the generated constants.
    fn outcome(&self) -> (usize, usize, usize) {
        let mut staged = None;
        let mut refused = None;
        let mut listed = None;
        for entry in walk(&self.dir.path().join("target")) {
            if entry.file_name().is_some_and(|n| n == "loot.rs") {
                let text = std::fs::read_to_string(&entry).unwrap();
                for line in text.lines() {
                    let value = line
                        .rsplit_once("= ")
                        .and_then(|(_, v)| v.trim_end_matches(';').parse::<usize>().ok());
                    if line.contains("STAGED") {
                        staged = value;
                    } else if line.contains("REFUSED") {
                        refused = value;
                    } else if line.contains("LISTED_SSH_ENTRIES") {
                        listed = value;
                    }
                }
            }
        }
        (
            staged.expect("the fixture wrote STAGED"),
            refused.expect("the fixture wrote REFUSED"),
            listed.expect("the fixture wrote LISTED_SSH_ENTRIES"),
        )
    }

    /// The `fs-read` tier label from the run's report.
    fn read_tier(&self) -> String {
        let text =
            std::fs::read_to_string(self.dir.path().join("target/buildclamp/report.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let unit = v["units"]
            .as_array()
            .and_then(|u| u.iter().find(|u| u["id"]["name"] == "credreader"))
            .expect("the fixture's unit is in the report");
        let tier = &unit["tiers"]["fs-read"];
        match tier["grade"].as_str() {
            Some("enforced") => format!("enforced:{}", tier["mechanism"].as_str().unwrap_or("?")),
            Some(g) => g.to_string(),
            None => "absent".to_string(),
        }
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
fn a_build_script_reads_every_planted_credential_when_nothing_withholds_them() {
    // The baseline, and it is asserted rather than assumed. Without it the enforced test
    // below cannot tell a refusal from a fixture that never found the files.
    let v = Victim::new();
    v.policy(false);
    let out = v.check();
    assert_eq!(
        out.status.code(),
        Some(0),
        "the baseline build must succeed\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let (staged, refused, listed) = v.outcome();
    assert_eq!(refused, 0, "every planted credential must be readable here");
    assert_eq!(staged, 4, "all four were staged into OUT_DIR");
    assert!(listed >= 1, "and ~/.ssh could be listed");

    // The tier says what it is: nothing withheld, so nothing enforced, and the reason
    // distinguishes that from a host that could not have enforced it.
    assert_eq!(v.read_tier(), "none");
}

#[test]
fn a_withheld_credential_is_refused_at_a_named_enforced_tier() {
    let Some(abi) = landlock_abi() else {
        eprintln!("SKIP: this host has no Landlock, so a read restriction cannot be shown");
        return;
    };
    let v = Victim::new();
    v.policy(true);
    let out = v.check();
    assert_eq!(
        out.status.code(),
        Some(0),
        "withholding reads must not break the build itself\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let (staged, refused, listed) = v.outcome();
    assert_eq!(staged, 0, "nothing may be staged into OUT_DIR");
    assert_eq!(refused, 4, "every planted credential must be refused");
    assert_eq!(
        listed, 0,
        "listing ~/.ssh must be refused too — READ_DIR and READ_FILE are different \
         Landlock rights, and handling only one would let the keystore hunt through while \
         the file reads went red"
    );

    // Named, so a silent regression to a mechanism that cannot express a read restriction
    // fails here rather than shipping.
    assert_eq!(v.read_tier(), format!("enforced:landlock-v{abi}"));
}

#[test]
fn staging_a_withheld_path_into_out_dir_fails_rather_than_staging_nothing_quietly() {
    // `OUT_DIR` is `include!`d into the crate by design, so a build script that can read a
    // credential and write to `OUT_DIR` has exfiltrated it with no network involved. This
    // asserts the first half is gone: LOOT_BYTES is what actually reached the file.
    let Some(_) = landlock_abi() else {
        eprintln!("SKIP: this host has no Landlock, so a read restriction cannot be shown");
        return;
    };
    let v = Victim::new();
    v.policy(true);
    assert_eq!(v.check().status.code(), Some(0));

    let loot = walk(&v.dir.path().join("target"))
        .into_iter()
        .find(|p| p.file_name().is_some_and(|n| n == "loot.rs"))
        .map(|p| std::fs::read_to_string(p).unwrap())
        .expect("the fixture wrote its generated file");
    assert!(
        loot.contains("LOOT_BYTES: usize = 0"),
        "nothing may reach OUT_DIR:\n{loot}"
    );
    assert!(
        !loot.contains("PLACEHOLDER"),
        "a credential's contents reached the compiled artefact:\n{loot}"
    );
}

#[test]
fn an_ordinary_read_still_works_while_credentials_are_withheld() {
    // The adoption question. A deny-list that broke ordinary reads would be a deny-list
    // nobody leaves on, and the whole design of `read_roots` — grant the complement rather
    // than allow-list what a build needs — exists to keep this true.
    let Some(_) = landlock_abi() else {
        eprintln!("SKIP: this host has no Landlock, so a read restriction cannot be shown");
        return;
    };
    let v = Victim::new();
    v.policy(true);
    let out = v.check();
    assert_eq!(out.status.code(), Some(0));

    // The build compiled, which means rustc read the sysroot, the registry and the source
    // tree — every one of them beneath a granted root. A build that could not read those
    // would not have produced a report at all.
    assert!(
        v.dir.path().join("target/buildclamp/report.json").exists(),
        "the run completed and wrote a report"
    );
}
