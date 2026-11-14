//! Signed policy, end to end through the binary.
//!
//! The verification logic is unit-tested in `buildclamp-core::signed_policy`; this proves the
//! wiring around it: that the loader captures each layer's bytes, finds its `<layer>.sig`
//! sidecar, verifies it against the committed anchor's `trust-root`, refuses an unsigned
//! distributed layer under `--require-signed-policy`, and records the outcome in the report.
//!
//! It signs a layer with `ring` — a test-only capability. The shipped binary verifies and
//! never signs, which `no_vendor_key.rs` and the crate layout keep true.

use std::path::PathBuf;
use std::process::{Command, Output};

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cargo-buildclamp"))
}

/// A workspace with a committed anchor that trusts one key and extends one org layer.
struct Repo {
    dir: tempfile::TempDir,
    pair: Ed25519KeyPair,
}

impl Repo {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let dir = tempfile::tempdir().unwrap();

        // A minimal crate so `cargo check` has something to compile.
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\n[package]\nname = \"signed\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn n() -> u8 { 0 }\n").unwrap();
        std::fs::create_dir_all(dir.path().join("home")).unwrap();

        // The distributed org layer, and the committed anchor that trusts the key and pulls
        // the org layer in.
        std::fs::write(
            dir.path().join("org.toml"),
            "version = 1\n[layer]\nname = \"org\"\n",
        )
        .unwrap();
        let pubkey = base64(pair.public_key().as_ref());
        std::fs::write(
            dir.path().join("buildclamp.toml"),
            format!(
                "version = 1\n[layer]\nname = \"repo\"\nextends = [\"org.toml\"]\n\n\
                 [defaults]\ntrust-root = [\"{pubkey}\"]\n"
            ),
        )
        .unwrap();

        Repo { dir, pair }
    }

    /// Write a valid detached signature for the org layer.
    fn sign_org(&self) {
        let bytes = std::fs::read(self.dir.path().join("org.toml")).unwrap();
        let sig = self.pair.sign(&bytes);
        std::fs::write(self.dir.path().join("org.toml.sig"), base64(sig.as_ref())).unwrap();
    }

    fn check(&self, extra: &[&str]) -> Output {
        let _ = std::fs::remove_dir_all(self.dir.path().join("target"));
        let mut args = vec!["buildclamp", "check"];
        args.extend_from_slice(extra);
        Command::new(bin())
            .args(&args)
            .current_dir(self.dir.path())
            .env("HOME", self.dir.path().join("home"))
            .output()
            .expect("the binary runs")
    }

    fn report(&self) -> serde_json::Value {
        let text =
            std::fs::read_to_string(self.dir.path().join("target/buildclamp/report.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }
}

#[test]
fn a_signed_distributed_layer_verifies_and_the_report_names_the_signer() {
    let repo = Repo::new();
    repo.sign_org();
    let out = repo.check(&[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a signed policy build must succeed\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = repo.report();
    assert_eq!(
        report["run"]["policy_signature_verified"], true,
        "the report must record that the org layer verified: {}",
        report["run"]
    );
    assert!(
        report["run"]["policy_signer_key_id"].is_string(),
        "the report must name the key that signed the layer: {}",
        report["run"]
    );
}

#[test]
fn an_unsigned_distributed_layer_is_refused_under_require_signed_policy() {
    // No `sign_org()`, so org.toml has no sidecar. The refusal happens at policy load, before
    // cargo runs, like every other policy error.
    let repo = Repo::new();
    let out = repo.check(&["--require-signed-policy"]);
    assert_ne!(
        out.status.code(),
        Some(0),
        "an unsigned distributed layer must be refused when signatures are required"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not signed") && stderr.contains("org"),
        "the refusal must name the unsigned layer:\n{stderr}"
    );
}

#[test]
fn an_unsigned_layer_runs_without_the_switch_and_the_report_says_it_was_unverified() {
    // Without `--require-signed-policy` an unsigned layer is not fatal: the build proceeds and
    // the report shows the authority was not established, which is visible rather than a
    // surprise.
    let repo = Repo::new();
    let out = repo.check(&[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "an unsigned layer without the switch must not fail the build\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        repo.report()["run"]["policy_signature_verified"],
        false,
        "an unverified layer must read as unverified in the report"
    );
}

#[test]
fn a_layer_signed_by_an_untrusted_key_is_refused() {
    let repo = Repo::new();
    // Sign with a DIFFERENT key than the trust root names.
    let rng = SystemRandom::new();
    let attacker =
        Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
    let bytes = std::fs::read(repo.dir.path().join("org.toml")).unwrap();
    std::fs::write(
        repo.dir.path().join("org.toml.sig"),
        base64(attacker.sign(&bytes).as_ref()),
    )
    .unwrap();

    let out = repo.check(&["--require-signed-policy"]);
    assert_ne!(
        out.status.code(),
        Some(0),
        "a layer signed by an untrusted key must not satisfy --require-signed-policy"
    );
}

/// Standard base64, matching what `buildclamp-core::b64` decodes.
fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            A[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
