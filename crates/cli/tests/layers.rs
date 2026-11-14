//! Composed policies, end to end, through the real binary and a real cargo build.
//!
//! The unit tests in `buildclamp-core::layer` cover the composition rule with no files at
//! all. These cover the half that only exists once files do: `extends` resolved against the
//! file that names it, a cycle refused, the ceiling enforced by the process that actually
//! holds a build unit, and `--strict` counting across layers.

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
    host.get("user_namespaces")
        .and_then(serde_json::Value::as_bool)
        .expect("`user_namespaces` must be a bool")
}

/// A workspace with an `org/` directory beside it, so `extends = "../org/buildclamp.toml"`
/// is a real relative path resolved against a real file.
struct Estate {
    dir: tempfile::TempDir,
}

impl Estate {
    fn new(deps: &[&str]) -> Self {
        let dir = tempfile::tempdir().expect("a scratch estate");
        let f = fixtures();
        std::fs::create_dir_all(dir.path().join("org")).unwrap();
        std::fs::create_dir_all(dir.path().join("repo/src")).unwrap();
        std::fs::create_dir_all(dir.path().join("repo/home")).unwrap();

        let mut manifest = String::from(
            "[workspace]\n[package]\nname = \"victim\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
        );
        for d in deps {
            manifest.push_str(&format!("{d} = {{ path = \"{}\" }}\n", f.join(d).display()));
        }
        std::fs::write(dir.path().join("repo/Cargo.toml"), manifest).unwrap();
        std::fs::write(dir.path().join("repo/src/lib.rs"), "// nothing\n").unwrap();
        Self { dir }
    }

    fn write(&self, rel: &str, text: &str) {
        std::fs::write(self.dir.path().join(rel), text).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(bin())
            .arg("buildclamp")
            .args(args)
            .current_dir(self.dir.path().join("repo"))
            .env("HOME", self.dir.path().join("repo/home"))
            .env("GITHUB_TOKEN", "ghp_planted_for_the_test")
            .output()
            .expect("the binary runs")
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

/// An org layer that is a ceiling and grants nothing beyond the defaults.
const ORG_CEILING: &str = r#"
version = 2

[layer]
name = "org"
may-widen = false
"#;

const REPO_EXTENDS_ORG: &str = r#"
version = 2

[layer]
name = "repo"
extends = ["../org/buildclamp.toml"]
"#;

#[test]
fn a_repo_grant_that_exceeds_the_org_ceiling_refuses_before_cargo_starts() {
    let e = Estate::new(&["benign"]);
    e.write("org/buildclamp.toml", ORG_CEILING);
    e.write(
        "repo/buildclamp.toml",
        &format!(
            "{REPO_EXTENDS_ORG}\n[grants.\"benign\"]\ncapabilities = [\"net\", \"fs-write\", \
             \"exec\", \"unix\"]\nwrite-zones = [\"out-dir\", \"tmp\"]\nwhy = \"it does not, \
             but the org has not said so\"\n"
        ),
    );

    let out = e.run(&["build"]);
    assert_eq!(
        code(&out),
        1,
        "a policy that does not compose is the tool failing, not a policy answer:\n{}",
        stderr(&out)
    );

    // Both files named. A message naming one sends the reader to the wrong half of the
    // decision, and the whole value of layering is that a reader can tell which document
    // decided.
    let err = stderr(&out);
    assert!(err.contains("repo/buildclamp.toml"), "{err}");
    assert!(err.contains("org/buildclamp.toml"), "{err}");
    assert!(err.contains("may-widen = false"), "{err}");
    assert!(err.contains("`net`") || err.contains(" net"), "{err}");

    // And cargo never ran: a policy problem discovered halfway through a build would leave
    // a target directory in a state nobody chose.
    assert!(
        !e.dir.path().join("repo/target/buildclamp").exists(),
        "the run got far enough to write a report"
    );
}

#[test]
fn the_org_ceiling_holds_in_the_process_that_does_the_holding() {
    // The half the unit tests cannot reach. The launcher is a separate process that
    // re-reads the policy from disk, and one that resolved against the nearest file alone
    // would hold every unit to the repository's grants and silently ignore the ceiling —
    // the one failure layering exists to prevent, arriving where the holding happens.
    if !host_can_enforce() {
        eprintln!("SKIP: this host has no user namespaces");
        return;
    }
    let e = Estate::new(&["evil"]);
    // The org permits the network for nothing, and says nothing may widen that.
    e.write("org/buildclamp.toml", ORG_CEILING);
    // The repo grants `evil` only what the defaults already allow, so the stack composes.
    e.write(
        "repo/buildclamp.toml",
        &format!(
            "{REPO_EXTENDS_ORG}\n[grants.\"evil\"]\ncapabilities = [\"fs-write\", \"exec\", \
             \"unix\"]\nwrite-zones = [\"out-dir\", \"tmp\"]\nwhy = \"within the ceiling\"\n\
             reviewed = true\n"
        ),
    );

    let out = e.run(&["build"]);
    assert_eq!(
        code(&out),
        2,
        "the network is still refused:\n{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("evil-step:2:connect:err:PermissionDenied"),
        "the kernel did not refuse the network:\n{}",
        stderr(&out)
    );

    // The report names the layer that produced the envelope, which is what `explain` reads.
    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(e.dir.path().join("repo/target/buildclamp/report.json"))
            .expect("a report"),
    )
    .expect("valid JSON");
    let unit = report["units"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"]["name"] == "evil")
        .expect("the evil unit ran");
    assert_eq!(unit["envelope"]["source"]["kind"], "layer");
    assert_eq!(unit["envelope"]["source"]["layer"], "repo");
    assert_eq!(unit["envelope"]["source"]["ceiling"], "org");
}

#[test]
fn explain_names_the_layer_that_produced_each_answer() {
    let e = Estate::new(&[]);
    e.write(
        "org/buildclamp.toml",
        &format!(
            "{ORG_CEILING}\n[grants.\"openssl-sys\"]\ncapabilities = [\"net\", \"fs-write\", \
             \"exec\", \"unix\"]\nwrite-zones = [\"out-dir\", \"tmp\"]\nwhy = \"a pinned \
             tarball\"\nreviewed = true\n"
        ),
    );
    e.write("repo/buildclamp.toml", REPO_EXTENDS_ORG);

    let out = e.run(&["explain", "openssl-sys", "--version", "0.9.117"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("`org` layer"), "{text}");
    // NOT "bounded by the `org` layer": the org layer is the one that decided, and a layer
    // is not bounded by itself. A source that said otherwise would name two documents where
    // one made the decision.
    assert!(!text.contains("bounded by"), "{text}");
}

#[test]
fn a_repo_grant_inside_the_ceiling_names_both_the_layer_and_the_bound() {
    // The other half: the repo decided, and the org bounded what it could decide. Both
    // documents are named because both took part.
    let e = Estate::new(&[]);
    e.write(
        "org/buildclamp.toml",
        &format!(
            "{ORG_CEILING}{}",
            r#"
[grants."cc"]
capabilities = ["fs-write", "exec", "unix"]
write-zones = ["out-dir", "tmp"]
why = "compiles C"
reviewed = true
"#
        ),
    );
    e.write(
        "repo/buildclamp.toml",
        &format!(
            "{REPO_EXTENDS_ORG}{}",
            r#"
[grants."cc"]
capabilities = ["fs-write", "exec", "unix"]
write-zones = ["out-dir"]
why = "we do not need TMPDIR"
reviewed = true
"#
        ),
    );

    let out = e.run(&["explain", "cc"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("`repo` layer"), "{text}");
    assert!(text.contains("bounded by the `org` layer"), "{text}");
}

#[test]
fn strict_counts_unreviewed_grants_in_every_layer() {
    let e = Estate::new(&["benign"]);
    e.write(
        "org/buildclamp.toml",
        &format!(
            "{ORG_CEILING}\n[grants.\"somebody-else\"]\ncapabilities = [\"fs-write\", \"exec\", \
             \"unix\"]\nwrite-zones = [\"out-dir\", \"tmp\"]\nwhy = \"nobody has read this\"\n"
        ),
    );
    e.write("repo/buildclamp.toml", REPO_EXTENDS_ORG);

    let out = e.run(&["build", "--strict"]);
    assert_eq!(
        code(&out),
        2,
        "an unreviewed grant in the ORG layer must still fail --strict:\n{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("1 grant(s)"), "{}", stdout(&out));
}

#[test]
fn a_cycle_in_extends_is_refused_by_name() {
    let e = Estate::new(&[]);
    e.write(
        "org/buildclamp.toml",
        "version = 2\n\n[layer]\nname = \"org\"\nextends = [\"../repo/buildclamp.toml\"]\n",
    );
    e.write("repo/buildclamp.toml", REPO_EXTENDS_ORG);

    let out = e.run(&["explain", "anything"]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    let err = stderr(&out);
    assert!(err.contains("cycle"), "{err}");
    // The chain, so a reader can see which edge to cut rather than which file to open.
    assert!(err.contains("->"), "{err}");
}

#[test]
fn a_diamond_is_named_as_a_duplicate_not_a_cycle() {
    // repo extends org-a and org-b; both extend base. `base` is reached by two branches — a
    // diamond, not a cycle. The loader's `seen` list used to never pop, so the second visit
    // to `base` looked like a cycle and printed a chain that was every file seen so far. Now
    // `seen` is a recursion path: the second visit is off it, so `buildclamp_core` names the
    // real problem — `base` appears twice — instead of a cycle that is not there.
    let e = Estate::new(&[]);
    e.write("org/base.toml", "version = 2\n\n[layer]\nname = \"base\"\n");
    e.write(
        "org/a.toml",
        "version = 2\n\n[layer]\nname = \"org-a\"\nextends = [\"base.toml\"]\n",
    );
    e.write(
        "org/b.toml",
        "version = 2\n\n[layer]\nname = \"org-b\"\nextends = [\"base.toml\"]\n",
    );
    e.write(
        "repo/buildclamp.toml",
        "version = 2\n\n[layer]\nname = \"repo\"\nextends = [\"../org/a.toml\", \"../org/b.toml\"]\n",
    );

    let out = e.run(&["explain", "anything"]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    let err = stderr(&out);
    assert!(!err.contains("cycle"), "a diamond is not a cycle:\n{err}");
    assert!(
        err.contains("base"),
        "the duplicated layer should be named:\n{err}"
    );
}

#[test]
fn an_extends_that_points_at_nothing_names_the_file() {
    let e = Estate::new(&[]);
    e.write(
        "repo/buildclamp.toml",
        "version = 2\n\n[layer]\nname = \"repo\"\nextends = [\"../org/absent.toml\"]\n",
    );
    let out = e.run(&["explain", "anything"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("absent.toml"), "{}", stderr(&out));
}

#[test]
fn a_ceiling_with_nothing_above_it_is_refused_rather_than_believed_in() {
    let e = Estate::new(&[]);
    // The org file alone, used directly as the repository's policy: `may-widen = false`
    // with nothing stacked on it is a line that reads like a control and is not one.
    e.write("repo/buildclamp.toml", ORG_CEILING);
    let out = e.run(&["explain", "anything"]);
    assert_eq!(code(&out), 1, "{}", stdout(&out));
    assert!(
        stderr(&out).contains("nothing is stacked on top"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_version_one_policy_still_builds_and_migrate_changes_only_the_number() {
    // The compatibility promise a version bump lives or dies on. A v1 file keeps working,
    // and `policy migrate` is how you stop seeing the version rather than how you keep
    // your build running.
    let e = Estate::new(&["benign"]);
    let v1 = "version = 1\n\n[grants.\"benign\"]\ncapabilities = [\"fs-write\", \"exec\", \
              \"unix\"]\nwrite-zones = [\"out-dir\", \"tmp\"]\nwhy = \"written before the \
              bump\"\nreviewed = true\n";
    e.write("repo/buildclamp.toml", v1);

    let before = e.run(&["explain", "benign"]);
    assert_eq!(
        code(&before),
        0,
        "a v1 policy still parses:\n{}",
        stderr(&before)
    );

    let migrated = e.run(&["policy", "migrate"]);
    assert_eq!(code(&migrated), 0, "{}", stderr(&migrated));
    let text = std::fs::read_to_string(e.dir.path().join("repo/buildclamp.toml")).unwrap();
    assert!(text.starts_with("version = 2"), "{text}");

    // The envelope is identical, which is the property `migrate` checks before it writes
    // and this checks after. A migration that changed one would break a build for a reason
    // the diff does not show.
    let after = e.run(&["explain", "benign"]);
    assert_eq!(stdout(&after), stdout(&before));
}
