//! A synthetic credential reader, shaped like the two 2026 incidents this project cites.
//!
//! **Synthetic, never a real payload.** It reaches for the same *paths* the incidents
//! reached for and does the same *thing with them* — stage the contents into `OUT_DIR`,
//! which `src/lib.rs` then `include!`s into the compiled artefact — and it has none of
//! their code. Reimplementing the behaviour is what makes the test meaningful; copying a
//! dropper into a repository is how a test fixture becomes an incident of its own.
//!
//! The two shapes, both reduced to their primitive:
//!
//! * **an exfiltrator** reading a cloud credential directory from the developer's machine,
//!   as the June 2026 one did;
//! * **a keystore hunter** walking a home directory for key material, as the TrapDoor
//!   family did against Sui and Move keystores.
//!
//! Neither sends anything. The network is denied by default and a fixture that tried to
//! prove the read by phoning somewhere would be testing the network tier instead of this
//! one. The proof that the read succeeded is `OUT_DIR`: the staged file is the exfiltration
//! path that matters anyway, because `OUT_DIR` is `include!`d into the binary by design.
//!
//! It reports through `cargo:warning=` rather than by failing, so a run where the reads
//! SUCCEED is visible as a baseline rather than as a broken build. That is the half of the
//! test that is easy to omit and useless to omit: a refusal proves nothing unless the same
//! fixture is known to succeed when nothing is holding it.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Where the credentials live, relative to `HOME`. These are the paths, not the contents.
const TARGETS: &[&str] = &[
    ".aws/credentials",
    ".ssh/id_ed25519",
    ".config/gh/hosts.yml",
    ".cargo/credentials.toml",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let home = std::env::var("HOME").unwrap_or_default();
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets this"));

    let mut staged = 0usize;
    let mut refused = 0usize;
    let mut loot = String::new();

    for target in TARGETS {
        let path = Path::new(&home).join(target);
        match std::fs::read_to_string(&path) {
            Ok(body) => {
                println!("cargo:warning=credreader: READ {target} ({} bytes)", body.len());
                loot.push_str(&format!("// {target}\n{body}\n"));
                staged += 1;
            }
            Err(e) => {
                println!("cargo:warning=credreader: REFUSED {target} ({:?})", e.kind());
                refused += 1;
            }
        }
    }

    // The keystore hunt: a directory listing rather than a file read, because the two are
    // different Landlock rights and a ruleset that handled only one would let this half
    // through while the test above went green.
    let listed = std::fs::read_dir(Path::new(&home).join(".ssh"))
        .map(|d| d.flatten().count())
        .unwrap_or_else(|e| {
            println!("cargo:warning=credreader: REFUSED listing .ssh ({:?})", e.kind());
            0
        });

    // Staging into OUT_DIR is the exfiltration that needs no network: OUT_DIR is
    // `include!`d into the crate, so whatever lands here is compiled into the artefact.
    let mut f = std::fs::File::create(out.join("loot.rs")).expect("OUT_DIR is writable");
    writeln!(f, "/// Bytes this build script managed to read. Empty means it was stopped.").unwrap();
    writeln!(f, "pub const STAGED: usize = {staged};").unwrap();
    writeln!(f, "pub const REFUSED: usize = {refused};").unwrap();
    writeln!(f, "pub const LISTED_SSH_ENTRIES: usize = {listed};").unwrap();
    writeln!(f, "pub const LOOT_BYTES: usize = {};", loot.len()).unwrap();
}
