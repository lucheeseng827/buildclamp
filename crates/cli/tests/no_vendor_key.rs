//! Two architecture invariants for signed policy, enforced by scanning the free binary's
//! own source so that breaking either is a deliberate, reviewable act rather than a slip.
//!
//! 1. **No vendor trust root is compiled in.** The trust root is always the customer's,
//!    read from their committed policy. A key baked into `cargo-buildclamp` would make a
//!    vendor's key rotation or lapse a customer's build outage, and would make the vendor an
//!    authority over what the customer's builds may do. So no Ed25519 public key may appear
//!    as a literal in shipped source.
//! 2. **The verification path makes no network request.** Signature verification reads bytes
//!    that are already on disk; it never fetches a policy, a key, or a revocation list. A
//!    build whose outcome depended on a remote response would fail the moment that response
//!    did, which is the failure mode signed policy exists to avoid.
//!
//! Source-scanning is the right shape here for the same reason `no_continue_is_enforced.rs`
//! is: the property is about what the code is ALLOWED to contain, and the cheapest place to
//! assert that is over the text, in CI, on every commit.

use std::fs;
use std::path::{Path, PathBuf};

/// Every non-test `.rs` under the two Apache-2.0 crates that make up the free binary.
///
/// Test modules are `#[cfg(test)]` and never ship, so a key or a socket in one is not in the
/// binary — but rather than parse cfg boundaries, the key check below keys on a *real* key's
/// length, which test code never has as a literal, and the network check is scoped to the
/// verification module, whose tests generate keys and open no sockets.
fn oss_source() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                if let Ok(t) = fs::read_to_string(&p) {
                    out.push((p, t));
                }
            }
        }
    }
    let root = module_root();
    let mut out = Vec::new();
    walk(&root.join("crates/core/src"), &mut out);
    walk(&root.join("crates/cli/src"), &mut out);
    assert!(
        out.iter().map(|(_, t)| t.len()).sum::<usize>() > 20_000,
        "the source walk read almost nothing; it is looking in the wrong place"
    );
    out
}

fn module_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/cli is two levels below the module root")
        .to_path_buf()
}

/// The quoted string literals on a line, roughly — enough to find a base64 key, which
/// contains no escapes.
fn string_literals(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            if let Some(end) = line[i + 1..].find('"') {
                out.push(&line[i + 1..i + 1 + end]);
                i = i + 1 + end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// A literal that could be a 32-byte Ed25519 public key: base64, and long enough that test
/// garbage ("not base64!!!") and short markers never reach it. A real key base64-encodes to
/// 44 characters; 40 is a safe floor that no incidental string in this codebase hits.
fn could_be_a_key(s: &str) -> bool {
    s.len() >= 40
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
}

#[test]
fn no_ed25519_key_is_hardcoded_in_the_free_binary() {
    let mut findings = Vec::new();
    for (path, text) in oss_source() {
        for (n, line) in text.lines().enumerate() {
            // A key gets into a binary two ways: parsed from a literal, or held in a
            // constant. Anything else — a key read from a policy field — is data, not a
            // vendor key, and is exactly what is allowed.
            let upper = line.to_uppercase();
            let key_context = line.contains("from_base64")
                || ((line.contains("const ") || line.contains("static "))
                    && ["KEY", "ROOT", "TRUST", "SIGNER", "VENDOR", "PUBLIC"]
                        .iter()
                        .any(|w| upper.contains(w)));
            if key_context {
                for lit in string_literals(line) {
                    if could_be_a_key(lit) {
                        findings.push(format!(
                            "{}:{}: a base64 key literal `{}…`",
                            path.display(),
                            n + 1,
                            &lit[..12]
                        ));
                    }
                }
            }
        }
    }
    assert!(
        findings.is_empty(),
        "a hardcoded Ed25519 key is a vendor trust root, and there must be none — the trust \
         root is always the customer's, read from their committed policy:\n  {}",
        findings.join("\n  ")
    );
}

#[test]
fn the_verification_path_reads_from_disk_and_never_the_network() {
    // Scoped to the module that does the verifying. If a fetch ever appears here — reqwest,
    // ureq, a raw TcpStream, an http client — it is a live network dependency in the build
    // path, which the module's own documentation forbids.
    let src = fs::read_to_string(module_root().join("crates/core/src/signed_policy.rs"))
        .expect("signed_policy.rs exists");
    for needle in [
        "reqwest",
        "ureq",
        "TcpStream",
        "http::",
        "hyper",
        "std::net",
    ] {
        assert!(
            !src.contains(needle),
            "signed_policy.rs contains `{needle}`: verification must read bytes already on \
             disk, never fetch them"
        );
    }
}

#[test]
fn the_trust_root_is_built_from_customer_policy_data() {
    // The positive control: the one construction of a trust root in shipped code reads the
    // customer's `trust-root` policy field. Without this, the scan above could pass simply
    // because the feature was deleted.
    let driver = fs::read_to_string(module_root().join("crates/cli/src/driver.rs"))
        .expect("driver.rs exists");
    assert!(
        driver.contains("defaults.trust_root"),
        "the trust root must be built from the customer's policy `trust-root`, and the code \
         that does so has gone missing"
    );
}
