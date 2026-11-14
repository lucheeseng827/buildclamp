//! The cargo verbs beyond `build` / `check` / `test`, each driving a real cargo.
//!
//! `bench`, `doc` and `install` all compile and run build scripts, and each one was a hole
//! in the coverage table before it was a subcommand. `doc` is the one that surprises
//! people: a pipeline that holds `build` and then publishes documentation from an unheld
//! `cargo doc` has run the same third-party code twice and held it once.
//!
//! Each test builds its own throwaway package depending on `tests/fixtures/benign`, so the
//! assertion is that a build script **ran and was recorded**, not that some cached
//! artefact was reused. That distinction is the whole subject of the `install` test below.

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

/// A throwaway package with a binary, its own build script, and the benign fixture as a
/// dependency.
///
/// A binary and not just a library, because `cargo install` refuses a package with nothing
/// to install and would then never reach the build it is being tested for.
///
/// **Its own build script as well as a dependency's**, because those two arrive by
/// different routes and only one of them is the easy case. Under `cargo clippy` a
/// dependency's build script is compiled by `<buildclamp> <rustc> …` and the workspace's
/// own by `<buildclamp> clippy-driver <rustc> …`; a classifier that keyed on the
/// compiler's basename would hold the first and silently skip the second, which is the one
/// a developer most wants held.
struct Package {
    dir: tempfile::TempDir,
}

impl Package {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a scratch package");
        let benign = fixtures().join("benign");
        std::fs::write(
            dir.path().join("Cargo.toml"),
            format!(
                "[workspace]\n[package]\nname = \"subject\"\nversion = \"0.1.0\"\n\
                 edition = \"2021\"\n\n[dependencies]\nbenign = {{ path = \"{}\" }}\n",
                benign.display()
            ),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("build.rs"),
            "fn main() {\n    let out = std::env::var(\"OUT_DIR\").unwrap();\n             \x20   std::fs::write(std::path::Path::new(&out).join(\"own.rs\"), \"pub const OWN: usize = 1;\")\n             \x20       .unwrap();\n}\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("src/bin")).unwrap();
        std::fs::write(
            dir.path().join("src/lib.rs"),
            "include!(concat!(env!(\"OUT_DIR\"), \"/own.rs\"));\n             pub fn count() -> usize { OWN + benign::entries().len() }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("src/bin/subject.rs"),
            "fn main() { println!(\"{}\", subject::count()); }\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(bin())
            .arg("buildclamp")
            .args(args)
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path().join("home"))
            .output()
            .expect("the binary runs")
    }

    /// The crate names the last run recorded, read from the report it wrote.
    fn units_in_report(&self) -> Vec<String> {
        let text = std::fs::read_to_string(self.path().join("target/buildclamp/report.json"))
            .expect("the run wrote a report");
        let v: serde_json::Value = serde_json::from_str(&text).expect("valid report json");
        v["units"]
            .as_array()
            .map(|us| {
                us.iter()
                    .filter_map(|u| u["id"]["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn assert_held(out: &Output, pkg: &Package, verb: &str) {
    assert_eq!(
        out.status.code(),
        Some(0),
        "`{verb}` failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !pkg.units_in_report().is_empty(),
        "`{verb}` recorded no build units, so nothing was held and the clean report \
         proves nothing\nstdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn bench_holds_the_build_scripts_it_compiles() {
    let pkg = Package::new();
    let out = pkg.run(&["bench"]);
    assert_held(&out, &pkg, "bench");
}

#[test]
fn doc_holds_the_build_scripts_it_compiles() {
    // The one people do not expect. Building documentation compiles and runs every build
    // script in the graph, so a docs job is a full execution of third-party build-time
    // code — and it is usually the job nobody hardened.
    let pkg = Package::new();
    let out = pkg.run(&["doc"]);
    assert_held(&out, &pkg, "doc");
}

#[test]
fn install_holds_the_build_scripts_of_what_it_is_installing() {
    let pkg = Package::new();
    let root = tempfile::tempdir().unwrap();
    let out = pkg.run(&[
        "install",
        "--path",
        ".",
        "--root",
        root.path().to_str().unwrap(),
        "--offline",
    ]);
    assert_held(&out, &pkg, "install");
    assert!(
        root.path().join("bin/subject").exists(),
        "the install must still have installed something"
    );
}

/// A publishable package: no dependencies, its own build script, and the manifest fields
/// `cargo publish` insists on. Separate from [`Package`] because a path dependency makes a
/// crate unpublishable, and the point here is the verification build.
fn publishable() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a scratch package");
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[workspace]\n[package]\nname = \"pubsubject\"\nversion = \"0.1.0\"\n         edition = \"2021\"\nlicense = \"Apache-2.0\"\ndescription = \"a fixture\"\n         build = \"build.rs\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("build.rs"),
        "fn main() {\n    let out = std::env::var(\"OUT_DIR\").unwrap();\n         \x20   std::fs::write(std::path::Path::new(&out).join(\"g.rs\"), \"pub const N: usize = 1;\")\n         \x20       .unwrap();\n}\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src/lib.rs"),
        "include!(concat!(env!(\"OUT_DIR\"), \"/g.rs\"));\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("home")).unwrap();
    dir
}

#[test]
fn clippy_holds_the_workspaces_own_build_script_and_not_only_its_dependencies() {
    // The trap `crates/core/src/unit.rs` is written around, driven end to end against real
    // clippy rather than against a recorded command line.
    //
    // `cargo clippy` sets `RUSTC_WORKSPACE_WRAPPER=clippy-driver` and leaves
    // `RUSTC_WRAPPER` to buildclamp, so the two build scripts in this package arrive by
    // different routes: the dependency's as `<buildclamp> <rustc> …` and the workspace's
    // own as `<buildclamp> clippy-driver <rustc> …`. Keying on the compiler's basename
    // would hold the first and skip the second — and the second is the developer's own
    // code, on the job that runs for every pull request including one from a fork.
    //
    // So asserting "at least one unit" would pass while the interesting half was missing.
    // Both are named.
    let pkg = Package::new();
    let out = pkg.run(&["clippy"]);
    assert_held(&out, &pkg, "clippy");

    let units = pkg.units_in_report();
    assert!(
        units.iter().any(|u| u == "benign"),
        "the dependency's build script, which arrives with rustc in front, was not \
         held: {units:?}"
    );
    assert!(
        units.iter().any(|u| u == "subject"),
        "the workspace's OWN build script, which arrives with clippy-driver in front, \
         was not held: {units:?}"
    );
}

#[test]
fn publish_refuses_before_the_upload_when_it_cannot_enforce() {
    // The property that makes `publish` different from every other verb here.
    // `--require-enforced` normally reads the finished report, which is the right place
    // for it — and it would be useless here, because by then the crate is on the registry
    // and an upload cannot be taken back. So it is answered first.
    //
    // No network is involved and none should be: the whole point is that cargo never runs.
    // `BUILDCLAMP_DISABLE=ns` removes the user namespace, which is what the environment
    // tier depends on, so this is deterministic on a host that has one and on a host that
    // never did.
    let dir = publishable();
    let out = Command::new(bin())
        .args(["buildclamp", "publish", "--require-enforced", "--dry-run"])
        .current_dir(dir.path())
        .env("HOME", dir.path().join("home"))
        .env("BUILDCLAMP_DISABLE", "ns")
        .output()
        .expect("the binary runs");

    assert_eq!(
        out.status.code(),
        Some(2),
        "a publish that cannot be enforced must be refused, not reported on afterwards"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to publish"),
        "the refusal must say what it refused:\n{stderr}"
    );
    assert!(
        stderr.contains("cannot be taken back"),
        "and why it is checked first:\n{stderr}"
    );

    // Cargo must not have run. `cargo publish` packages into `target/package` before it
    // uploads, so the absence of that directory is the evidence that nothing was
    // packaged, verified or sent.
    assert!(
        !dir.path().join("target/package").exists(),
        "cargo ran despite the refusal"
    );
}

#[test]
fn publish_says_what_it_costs_on_a_host_that_cannot_hold_the_token_out_of_reach() {
    // Without `--require-enforced` the publish proceeds — refusing outright would make
    // buildclamp the reason a release did not go out — but it is never silent about it.
    // Publishing is one of the few moments a registry token and third-party build-time
    // code are alive in the same process tree, and on this host a held unit could read the
    // token out of cargo's `/proc/<pid>/environ`.
    //
    // Asserted on the message alone, so no registry is contacted: `--dry-run` with no
    // network still reaches the warning, which is printed before cargo starts.
    let dir = publishable();
    let out = Command::new(bin())
        .args(["buildclamp", "publish", "--dry-run", "--offline"])
        .current_dir(dir.path())
        .env("HOME", dir.path().join("home"))
        .env("BUILDCLAMP_DISABLE", "ns")
        .output()
        .expect("the binary runs");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("advisory:scrub"),
        "the warning must name the tier it is about:\n{stderr}"
    );
    assert!(
        stderr.contains("/proc/<pid>/environ"),
        "and the exact exposure:\n{stderr}"
    );
    // The command itself is expected to fail here — `cargo publish` cannot run `--offline`
    // at all, measured — and that is not what this test is about. The warning is printed
    // before cargo is spawned, which is the property being pinned.
}

#[test]
fn an_install_that_reuses_an_existing_build_says_it_held_nothing() {
    // Measured, and the reason this test exists rather than a comment: `cargo install
    // --path <dir>` builds into `<dir>/target`, so installing a package that has already
    // been built there runs no build script at all. The report is then empty and looks
    // exactly like a clean one.
    //
    // The run has to say so. "Nothing asked for more than its envelope" over a build that
    // never happened is the false assurance this whole tool exists to prevent, and it
    // would be the easiest one here to ship by accident.
    let pkg = Package::new();
    let root = tempfile::tempdir().unwrap();
    let args = [
        "install",
        "--path",
        ".",
        "--root",
        root.path().to_str().unwrap(),
        "--offline",
        "--force",
    ];

    let first = pkg.run(&args);
    assert_held(&first, &pkg, "install");

    let second = pkg.run(&args);
    assert_eq!(second.status.code(), Some(0));
    assert!(
        pkg.units_in_report().is_empty(),
        "cargo should have reused the first build; if this starts failing, cargo's \
         install caching changed and the note below is no longer needed"
    );
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        stdout.contains("no build units ran"),
        "a run that held nothing must say so rather than reporting a clean \
         build\nstdout:\n{stdout}"
    );
}
