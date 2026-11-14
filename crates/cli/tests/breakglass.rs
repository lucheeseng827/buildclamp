//! Break-glass, end to end, against a real cargo build of the hostile fixture.
//!
//! The claim under test is the one the roadmap put a test next to: **the free tool can
//! gate and ungate a build with no account, no network and no plane.** Nothing here
//! contacts anything. The whole mechanism is a block in a file the build reads.
//!
//! The order matters and is the point. Every check asserts the **red** state first and
//! then the green one, because a test that only asserts green passes just as well when
//! the gate never fired — which is the failure this project found in its own end-to-end
//! suite once already, where seven tests skipped on every host and reported `7 passed`.

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

/// Whether this host can demonstrate enforcement at all.
///
/// Asked through `doctor --json`, and a guard that cannot get an answer **panics** rather
/// than skipping: "this host cannot enforce" and "I could not tell" are different
/// answers, and only the first may skip.
fn host_can_enforce() -> bool {
    let out = Command::new(bin())
        .args(["buildclamp", "doctor", "--json"])
        .output()
        .expect("doctor runs");
    assert!(
        out.status.success(),
        "`doctor --json` exited {:?}; refusing to skip on an answer this suite could not \
         establish.\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let host: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("doctor --json emits HostCapabilities");
    host.get("user_namespaces")
        .and_then(serde_json::Value::as_bool)
        .expect("`user_namespaces` must be a bool in doctor --json")
}

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

    fn policy(&self) -> PathBuf {
        self.dir.path().join("buildclamp.toml")
    }

    /// Run a buildclamp subcommand in this workspace.
    ///
    /// `HOME` points inside the scratch directory and the git identity is supplied
    /// through the environment, so nothing here reads or writes the developer's own git
    /// configuration — and `except` has an author to use on a CI runner that has none.
    fn run(&self, args: &[&str]) -> Output {
        Command::new(bin())
            .arg("buildclamp")
            .args(args)
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path().join("home"))
            .env("GIT_AUTHOR_EMAIL", "ada@example.com")
            .env("GITHUB_TOKEN", "ghp_planted_for_the_test")
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

    /// Throw away the target directory so the next build actually runs the build script.
    ///
    /// Necessary because editing `buildclamp.toml` does not change any cargo fingerprint,
    /// so a build script that **succeeded** is reused and the policy is not exercised at
    /// all — the tool says exactly that ("no build units ran"). In the situation this
    /// feature is for the script has failed, so cargo re-runs it and nobody has to do
    /// this; but `tests/fixtures/evil` deliberately never fails the build, because a
    /// fixture that exited non-zero on a denied syscall would let a broken sandbox pass.
    /// So the fixture's virtue is what makes this call necessary, and a test that skipped
    /// it would assert a green build that ran nothing.
    fn clean(&self) {
        let _ = std::fs::remove_dir_all(self.dir.path().join("target"));
    }
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Today, the same way the binary computes it, so a test written on one day still asserts
/// the right dates on another.
fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs() as i64;
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

// --- the claim -------------------------------------------------------------------------

#[test]
fn the_free_tool_can_gate_a_build_and_then_ungate_it_with_no_account_and_no_network() {
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["evil"]);

    // Gate. The default envelope refuses the network to every crate, and the fixture's
    // build script reaches for it, so this is red before any policy file exists at all.
    let red = v.run(&["build"]);
    assert_eq!(code(&red), 2, "stderr:\n{}", stderr(&red));
    assert!(!v.policy().exists(), "no policy was needed to gate");

    // Ungate. One command, no account, no network, no server: the whole mechanism is a
    // block appended to a file in the repository.
    let broke = v.run(&[
        "except",
        "evil",
        "--reason",
        "release blocked at 17:00; INFRA-4412 tracks the real grant",
    ]);
    assert_eq!(code(&broke), 0, "stderr:\n{}", stderr(&broke));
    let policy = std::fs::read_to_string(v.policy()).expect("except wrote the policy");
    assert!(policy.contains("[[exception]]"), "{policy}");
    assert!(policy.contains("crate = \"evil\""), "{policy}");
    assert!(policy.contains("ada@example.com"), "{policy}");
    // Narrowed to what the run that just went red was actually refused, rather than
    // granting everything — the report on disk is what makes that possible.
    assert!(
        policy.contains("capabilities = [\"net\"]"),
        "the exception should be narrowed from the report:\n{policy}"
    );
    // A week is the ceiling and one day is the default: an exception that outlives its
    // incident is one nobody deletes.
    assert!(
        policy.contains(&format!("expires = \"{}\"", tomorrow())),
        "expected a one-day expiry in:\n{policy}"
    );

    v.clean();
    // `-vv` because cargo hides a build script's output unless it fails, and the whole
    // point of the assertion below is that this one now *succeeds*. Without it the
    // strongest evidence the test could offer would be an exit code, which a run that
    // exercised nothing also produces.
    let green = v.run(&["build", "--", "-vv"]);
    assert!(
        !stdout(&green).contains("no build units ran"),
        "the build script was reused, so nothing was exercised:\n{}",
        stdout(&green)
    );
    assert_eq!(
        code(&green),
        0,
        "the exception did not ungate the build:\nstdout:\n{}\nstderr:\n{}",
        stdout(&green),
        stderr(&green)
    );

    // The build script actually got the network this time: the exception widened the
    // envelope, it did not merely make a refused run exit zero. The fixture's own step
    // marker is the ground truth — `err:ConnectionRefused` is the connection reaching a
    // closed port on loopback, which is what success looks like for a fixture that must
    // never put traffic on anyone's network. `err:PermissionDenied` is the sandbox.
    let both = format!("{}{}", stdout(&green), stderr(&green));
    assert!(
        both.contains("evil-step:2:connect:err:ConnectionRefused"),
        "the exception did not actually grant the network:\n{both}"
    );
    // And the report agrees, without anybody having to read a build script's stderr: the
    // request is recorded, it is `granted`, and the tier for the network says why it was
    // not held rather than going quiet.
    let report = v.report();
    let unit = report["units"]
        .as_array()
        .expect("units")
        .iter()
        .find(|u| u["id"]["name"] == "evil")
        .expect("the evil unit ran");
    assert_eq!(unit["envelope"]["excepted_until"], tomorrow());
    assert!(
        unit["observed"]
            .as_array()
            .expect("observed")
            .contains(&serde_json::Value::String("net".into())),
        "the network was not exercised:\n{unit}"
    );
    assert_eq!(unit["tiers"]["net"]["grade"], "none");

    // Loud, and in the document as well as on the terminal. A run that passed because
    // somebody broke the glass must not read like a clean one.
    let out = stdout(&green);
    assert!(out.contains("BREAK-GLASS"), "{out}");
    assert!(out.contains("ada@example.com"), "{out}");
    assert!(out.contains("INFRA-4412"), "{out}");
    assert!(
        out.contains("None of this is approval"),
        "the summary must say what an exception is not:\n{out}"
    );

    // What it did NOT buy: the write outside OUT_DIR. `write-zones` is the one dimension
    // an exception cannot widen, and the kernel still refused it.
    assert!(
        !v.persistence_file().exists(),
        "an exception widened write-zones, which it must never do: {}",
        v.persistence_file().display()
    );
}

/// The day after today, which is what `--days 1` produces.
fn tomorrow() -> String {
    let out = Command::new(bin())
        .args(["buildclamp", "--version"])
        .output()
        .expect("the binary runs");
    assert!(out.status.success());
    // Computed from the same civil arithmetic as `today()` rather than parsed back out of
    // the tool, so this assertion is independent of the code it checks.
    let t = today();
    let (y, m, d): (i64, i64, i64) = (
        t[0..4].parse().unwrap(),
        t[5..7].parse().unwrap(),
        t[8..10].parse().unwrap(),
    );
    let yy = if m <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468 + 1;

    let z = days + 719_468;
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

#[test]
fn an_expired_exception_fails_closed_and_says_which_block_ran_out() {
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["evil"]);
    std::fs::write(
        v.policy(),
        "version = 1\n\n[[exception]]\ncrate = \"evil\"\ncapabilities = [\"net\"]\n\
         expires = \"2020-01-01\"\nreason = \"an incident that is long over\"\n\
         author = \"ada@example.com\"\n",
    )
    .unwrap();

    let out = v.run(&["build"]);
    // Closed, by itself, with nobody having edited anything.
    assert_eq!(
        code(&out),
        2,
        "an expired exception must not excuse anything:\nstdout:\n{}\nstderr:\n{}",
        stdout(&out),
        stderr(&out)
    );
    // And named, so the person whose build just went red does not write the same block a
    // second time wondering why the first one stopped working.
    let text = stdout(&out);
    assert!(
        text.contains("expired on 2020-01-01"),
        "the lapse must be named:\n{text}"
    );
    // The kernel refused the syscall too, not merely the verdict.
    assert!(
        stderr(&out).contains("evil-step:2:connect:err:PermissionDenied"),
        "the network was not refused:\n{}",
        stderr(&out)
    );
}

#[test]
fn an_exception_is_recorded_in_the_report_and_not_only_on_the_terminal() {
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["evil"]);
    // Narrowed to fs-write, which an exception can stand the verdict down for and cannot
    // widen a zone for — so the report carries a use, the run passes, and the write still
    // does not happen.
    std::fs::write(
        v.policy(),
        format!(
            "version = 1\n\n[[exception]]\ncrate = \"evil\"\n\
             expires = \"{}\"\nreason = \"INFRA-4412\"\nauthor = \"ada@example.com\"\n",
            tomorrow()
        ),
    )
    .unwrap();

    let out = v.run(&["build"]);
    assert_eq!(code(&out), 0, "stderr:\n{}", stderr(&out));

    let report = v.report();
    let uses = report
        .get("break_glass")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| {
            panic!(
                "the report must record what break-glass stood down:\n{}",
                serde_json::to_string_pretty(&report).unwrap()
            )
        });
    assert!(!uses.is_empty(), "a use was expected");
    let first = &uses[0];
    assert_eq!(first["unit"]["name"], "evil");
    assert_eq!(first["author"], "ada@example.com");
    assert_eq!(first["reason"], "INFRA-4412");
    assert_eq!(first["expires"], tomorrow());
    // The block named no capabilities, so it grants all of them and the record says so by
    // carrying none rather than by listing six.
    assert_eq!(first["grants"], serde_json::json!([]));
    // And what the unit actually did with it, which is the line that turns a block into a
    // grant somebody writes or a block somebody deletes.
    assert!(
        first["exercised"]
            .as_array()
            .expect("exercised is a capability set")
            .contains(&serde_json::Value::String("net".into())),
        "{first}"
    );

    // And the envelope says it ran wider than the policy alone would have allowed.
    let unit = report["units"]
        .as_array()
        .expect("units")
        .iter()
        .find(|u| u["id"]["name"] == "evil" && u["envelope"]["excepted_until"].is_string())
        .expect("some unit's envelope should carry excepted_until");
    assert_eq!(unit["envelope"]["excepted_until"], tomorrow());
}

#[test]
fn except_refuses_rather_than_writing_a_block_the_next_build_would_reject() {
    let v = Victim::new(&[]);

    // Past the seven-day bound.
    let long = v.run(&["except", "evil", "--reason", "r", "--days", "30"]);
    assert_eq!(code(&long), 1, "{}", stderr(&long));
    assert!(
        stderr(&long).contains("between 1 and 7"),
        "{}",
        stderr(&long)
    );
    assert!(!v.policy().exists(), "nothing should have been written");

    // No reason.
    let mute = v.run(&["except", "evil", "--reason", "  "]);
    assert_eq!(code(&mute), 1, "{}", stderr(&mute));
    assert!(!v.policy().exists());

    // A capability that is not one, named next to the list of what it could have been.
    let typo = v.run(&["except", "evil", "--reason", "r", "--capability", "nett"]);
    assert_eq!(code(&typo), 1, "{}", stderr(&typo));
    assert!(stderr(&typo).contains("fs-write"), "{}", stderr(&typo));
    assert!(!v.policy().exists());

    // And the cap, which is a property of the whole file rather than of one block: the
    // fourth write is refused because the file it would produce is one no build accepts.
    for i in 0..3 {
        let ok = v.run(&["except", &format!("c{i}"), "--reason", "r"]);
        assert_eq!(code(&ok), 0, "{}", stderr(&ok));
    }
    let over = v.run(&["except", "c3", "--reason", "r"]);
    assert_eq!(code(&over), 1, "{}", stderr(&over));
    assert!(
        stderr(&over).contains("max-active-exceptions"),
        "the refusal must name the way past it:\n{}",
        stderr(&over)
    );
    let policy = std::fs::read_to_string(v.policy()).unwrap();
    assert!(
        !policy.contains("c3"),
        "the refused block was written:\n{policy}"
    );
    assert_eq!(policy.matches("[[exception]]").count(), 3);
}

#[test]
fn except_keeps_the_comments_in_a_policy_somebody_wrote_by_hand() {
    // The one command run under pressure must not be the one that mangles the file the
    // person was about to commit, which is what a round trip through the TOML serialiser
    // would do.
    let v = Victim::new(&[]);
    let original = "# A comment somebody wrote and wants to keep.\nversion = 1\n\n\
                    [grants.\"openssl-sys\"]\n# and this one\ncapabilities = [\"exec\"]\n\
                    why = \"runs its own configure\"\nreviewed = true\n";
    std::fs::write(v.policy(), original).unwrap();

    let out = v.run(&["except", "evil", "--reason", "INFRA-4412"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let after = std::fs::read_to_string(v.policy()).unwrap();
    assert!(after.starts_with(original.trim_end()), "{after}");
    assert!(after.contains("# and this one"), "{after}");
    assert!(after.contains("[[exception]]"), "{after}");
}

#[test]
fn grace_warns_on_a_new_grant_and_fails_on_one_that_was_already_known() {
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let v = Victim::new(&["benign"]);

    // A grant written today, unreviewed. Without a window, `--strict` is red.
    let policy = format!(
        "version = 1\n\n[grants.\"benign\"]\ncapabilities = [\"fs-write\", \"exec\"]\n\
         write-zones = [\"out-dir\", \"tmp\"]\nwhy = \"observed\"\nfirst-seen = \"{}\"\n",
        today()
    );
    std::fs::write(v.policy(), &policy).unwrap();
    let red = v.run(&["build", "--strict"]);
    assert_eq!(code(&red), 2, "stdout:\n{}", stdout(&red));

    // With one, it warns and passes. `--strict` reads the policy rather than the report,
    // so this answer does not depend on a unit having run — which is the distinction that
    // makes `--strict` survive a second `cargo buildclamp build` in a row.
    let amber = v.run(&["build", "--strict", "--grace", "30"]);
    assert_eq!(
        code(&amber),
        0,
        "a grant first seen today is inside a thirty-day window:\nstdout:\n{}",
        stdout(&amber)
    );
    let text = stdout(&amber);
    assert!(text.contains("--grace"), "{text}");
    assert!(text.contains("benign"), "{text}");

    // The property the milestone names: a grant that was already known is not excused,
    // whatever window is asked for. Same file, one date changed.
    std::fs::write(
        v.policy(),
        policy.replace(
            &format!("first-seen = \"{}\"", today()),
            "first-seen = \"2020-01-01\"",
        ),
    )
    .unwrap();
    let still_red = v.run(&["build", "--strict", "--grace", "30"]);
    assert_eq!(
        code(&still_red),
        2,
        "grace suppressed a grant that was already known:\nstdout:\n{}",
        stdout(&still_red)
    );

    // And so is one carrying no date at all, which is every policy written before
    // `first-seen` existed.
    std::fs::write(
        v.policy(),
        policy.replace(&format!("first-seen = \"{}\"\n", today()), ""),
    )
    .unwrap();
    let undated = v.run(&["build", "--strict", "--grace", "3650"]);
    assert_eq!(
        code(&undated),
        2,
        "an undated grant is not evidence of newness:\nstdout:\n{}",
        stdout(&undated)
    );
}

// --- --accept-baseline -------------------------------------------------------------

#[test]
fn accept_baseline_marks_what_the_document_covers_and_nothing_else() {
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    // Two crates, one of which the baseline will vouch for. `netlegit` reaches the
    // network and `evil` does a good deal more, so exactly one of them can be accepted by
    // a document that describes a network fetch.
    let v = Victim::new(&["netlegit", "evil"]);
    let observed = v.run(&["observe"]);
    assert_eq!(code(&observed), 0, "stderr:\n{}", stderr(&observed));

    // What the run actually saw, so the baseline below describes the real thing rather
    // than what this test hopes happened.
    let report = v.report();
    let units: Vec<String> = report["units"]
        .as_array()
        .expect("units")
        .iter()
        .map(|u| format!("{}@{}", u["id"]["name"], u["id"]["version"]))
        .collect();
    assert!(
        units.iter().any(|u| u.contains("netlegit")),
        "the observe run did not reach netlegit: {units:?}"
    );

    let version = report["units"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"]["name"] == "netlegit")
        .map(|u| u["id"]["version"].as_str().expect("a version").to_string())
        .expect("netlegit ran");

    let baseline = v.dir.path().join("baseline.toml");
    std::fs::write(
        &baseline,
        format!(
            "version = 1\nsource = \"https://example.invalid/b.toml\"\npublished = \"2026-09-01\"\n\n\
             [[crate]]\nname = \"netlegit\"\nversion = \"{version}\"\n\
             capabilities = [\"net\", \"fs-write\", \"exec\", \"unix\", \"env-secret\", \"fs-read\"]\n\
             write-zones = [\"out-dir\", \"tmp\"]\n\
             net-destinations = [\"127.0.0.1:9\", \"localhost:9\"]\n\
             why = \"resolves a pinned dependency at build time\"\n"
        ),
    )
    .unwrap();

    let init = v.run(&[
        "init",
        "--accept-baseline",
        baseline.to_str().expect("a utf-8 path"),
    ]);
    assert_eq!(code(&init), 0, "stderr:\n{}", stderr(&init));

    let policy = std::fs::read_to_string(v.policy()).expect("init wrote the policy");

    // The reviewer of record is in the file, with the digest of the bytes on disk.
    let digest = sha256_hex(&std::fs::read(&baseline).unwrap());
    assert!(
        policy.contains(&format!("digest = \"sha256:{digest}\"")),
        "the policy must record which document vouched:\n{policy}"
    );

    let parsed: toml::Value = toml::from_str(&policy).expect("the generated policy parses");
    let grants = parsed["grants"].as_table().expect("grants");

    // Accepted: reviewed, pinned to the exact version, and carrying the baseline's own
    // reason rather than an observation.
    let accepted = grant_of(&grants["netlegit"]);
    assert_eq!(accepted["reviewed"].as_bool(), Some(true), "{accepted}");
    assert_eq!(accepted["version"].as_str(), Some(&*format!("={version}")));
    assert!(
        accepted["why"]
            .as_str()
            .expect("a why")
            .starts_with("resolves a pinned dependency"),
        "{accepted}"
    );

    // Not accepted: the document says nothing about this crate, so nothing changed.
    let untouched = grant_of(&grants["evil"]);
    assert_eq!(untouched["reviewed"].as_bool(), Some(false), "{untouched}");
    assert!(
        untouched["why"]
            .as_str()
            .expect("a why")
            .contains("OBSERVED"),
        "{untouched}"
    );

    // And the residual is printed, because a command that reported only what it accepted
    // would be reporting its own success rate.
    let said = stdout(&init);
    assert!(said.contains("accepted from the baseline"), "{said}");
    assert!(said.contains("still unreviewed"), "{said}");
    assert!(
        said.contains("evil"),
        "the residual must name what is left:\n{said}"
    );

    // `--strict` is now down to the residual rather than everything.
    let strict = v.run(&["build", "--strict"]);
    assert_eq!(
        code(&strict),
        2,
        "evil is still unreviewed:\n{}",
        stdout(&strict)
    );
    assert!(
        stdout(&strict).contains("1 grant(s)"),
        "exactly one grant should remain:\n{}",
        stdout(&strict)
    );
}

/// The one grant under a `[grants."x"]` key, whichever shape the policy used.
fn grant_of(value: &toml::Value) -> toml::Value {
    match value {
        toml::Value::Array(v) => v[0].clone(),
        other => other.clone(),
    }
}

/// SHA-256 of some bytes, as hex — computed here rather than taken from the library under
/// test, so the assertion above is independent of the code it checks.
fn sha256_hex(bytes: &[u8]) -> String {
    let out = std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.take().expect("stdin").write_all(bytes)?;
            c.wait_with_output()
        })
        .expect("sha256sum is in coreutils and present on every host this suite runs on");
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .expect("sha256sum prints the digest first")
        .to_string()
}
