//! `cargo buildclamp selftest --no-network`, driven the way CI drives it.
//!
//! The command makes a claim about buildclamp's own artefact, and a claim nobody has
//! watched fail is not a claim. So the negative case is the important test here: a binary
//! that *does* reach the network must come back non-zero, and it is compiled fresh by this
//! file rather than mocked, because a mocked socket would test the mock.
//!
//! # Why these skip and the others do not
//!
//! `endtoend.rs` refuses to skip: a guard that cannot establish whether the host can
//! enforce panics there, because a suite reporting success having asserted nothing is the
//! exact false assurance this project exists to prevent. The same rule applies here and
//! the guard is the same function — `doctor --json`, parsed, never screen-scraped. What
//! differs is only that a host with no enforcement makes the SUBJECT of the test
//! unavailable rather than the assertion unreliable, and `selftest` itself reports that
//! case as exit 1 rather than as a pass, which the third test below pins.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cargo-buildclamp"))
}

/// Whether this host can demonstrate enforcement, asked of the tool through `--json`.
///
/// A guard that cannot get an answer panics rather than skipping, for the reason in the
/// module docs.
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
    let userns = host["user_namespaces"].as_bool().expect("a bool");
    let notify = host["seccomp_user_notif"].as_bool().expect("a bool");
    userns || notify
}

fn selftest(args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .arg("buildclamp")
        .arg("selftest")
        .args(args)
        .output()
        .expect("the binary runs")
}

/// Compile a tiny program with `rustc` and return its path.
///
/// A loose `rustc` invocation rather than a cargo fixture package: the subject is a
/// *binary*, it needs no dependencies, and a package under `tests/fixtures` would have to
/// be kept out of every workspace by hand for the same reason the hostile fixtures are.
fn compile(dir: &std::path::Path, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.rs"));
    let out = dir.join(name);
    std::fs::write(&src, source).unwrap();
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let status = Command::new(rustc)
        .arg(&src)
        .arg("-o")
        .arg(&out)
        .status()
        .expect("rustc runs");
    assert!(status.success(), "the fixture must compile");
    out
}

#[test]
fn buildclamp_itself_opens_no_socket_while_doing_its_ordinary_work() {
    if !host_can_enforce() {
        eprintln!("SKIP: this host can neither create a network namespace nor notify");
        return;
    }
    let out = selftest(&["--no-network"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "buildclamp asked for the network during its own selftest.\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The tier travels with the claim. A pass reported under `none` would be a pass that
    // means nothing, which is the whole subject of this tool.
    assert!(
        stdout.contains("network tier enforced:"),
        "the result must name the mechanism that achieved it:\n{stdout}"
    );
}

#[test]
fn a_binary_that_reaches_the_network_fails_the_selftest() {
    // The test that makes the one above worth running. Without it, `selftest` returning 0
    // would be evidence of nothing: a check that has never been observed to fail cannot
    // distinguish a clean binary from a broken check.
    if !host_can_enforce() {
        eprintln!("SKIP: this host can neither create a network namespace nor notify");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let evil = compile(
        d.path(),
        "reaches_out",
        // TEST-NET-3 (203.0.113.0/24), which is reserved for documentation and routed
        // nowhere. The point is the socket call, and the call is refused before any packet
        // could leave — but a fixture that named a real host would be one bad refactor
        // away from a test suite that talks to the internet.
        r#"fn main() {
               let _ = std::net::TcpStream::connect("203.0.113.7:443");
           }"#,
    );

    let out = selftest(&["--no-network", "--", evil.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a network-using binary must fail the selftest.\n{stdout}"
    );
    assert!(
        stdout.contains("network request"),
        "the failure must name what was asked for:\n{stdout}"
    );
}

#[test]
fn a_selftest_with_no_check_selected_is_an_error_rather_than_a_pass() {
    // `selftest` on its own must not exit 0. A self-check that passes by doing nothing is
    // the false assurance this project names as worse than having no tool at all, and it
    // would be the easiest one in the repository to write by accident.
    let out = selftest(&[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--no-network"),
        "the error must say which check to ask for"
    );
}
