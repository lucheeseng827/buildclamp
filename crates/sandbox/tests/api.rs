//! The other half of the freeze: a snapshot of the declared surface.
//!
//! `frozen_api.rs` is the compiler's half — every frozen item is used at its exact type,
//! so a removal or a signature change fails to build. What a compiler cannot see is an
//! **addition**: a new `pub fn` compiles perfectly and quietly enlarges what this crate
//! promises to keep working forever.
//!
//! So the surface is written down, in `API.txt`, and this compares the source against it.
//! The point is not that additions are forbidden — the point is that adding one is a line
//! in a diff somebody looked at, rather than something that happened.
//!
//! # It parses with a regular expression, and that is a deliberate limit
//!
//! The correct tool is rustdoc's JSON output, which is nightly-only; this project pins a
//! stable toolchain and a gate that only ran on nightly would be a gate that ran nowhere.
//! So this reads declarations out of the text, which means:
//!
//!   * it lists items declared `pub` inside a **private** module, which are not reachable
//!     by a consumer at all. They are in the snapshot anyway, prefixed by their module, and
//!     that is the safe direction: an item that becomes reachable later is already listed
//!     and the change shows up where it matters — in `lib.rs`'s `pub use` lines, which are
//!     also snapshotted;
//!   * it does not see re-exports' resolved paths, trait impls, or blanket impls.
//!
//! What it does catch is the thing that actually happens: somebody adds `pub fn` to a file
//! in this crate without deciding whether it is part of the promise.

use std::fs;
use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `pub` declaration in the crate's source, as `<module path>::<item>`.
fn declared_surface() -> Vec<String> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
            .flatten()
            .collect();
        entries.sort_by_key(std::fs::DirEntry::path);
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                let inner = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}::{name}")
                };
                walk(&path, &inner, out);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
            // `mod.rs` and `lib.rs` are the module itself rather than a child of it.
            let module = match (prefix.is_empty(), stem.as_str()) {
                (true, "lib") => String::new(),
                (_, "mod") => prefix.to_string(),
                (true, s) => s.to_string(),
                (false, s) => format!("{prefix}::{s}"),
            };
            let text = fs::read_to_string(&path).unwrap_or_default();
            let mut in_test_module = false;
            for line in text.lines() {
                // Everything under `#[cfg(test)]` is not surface. Crude — it stops at the
                // next unindented `}` — and sufficient, because this crate puts its test
                // modules last in every file.
                if line.trim_start().starts_with("#[cfg(test)]") {
                    in_test_module = true;
                }
                if in_test_module {
                    continue;
                }
                let t = line.trim_start();
                let Some(rest) = t.strip_prefix("pub ") else {
                    continue;
                };
                // `pub(crate)` and `pub(super)` are not surface.
                if rest.starts_with('(') {
                    continue;
                }
                let Some(name) = item_name(rest) else {
                    continue;
                };
                let entry = if module.is_empty() {
                    name
                } else {
                    format!("{module}::{name}")
                };
                if !out.contains(&entry) {
                    out.push(entry);
                }
            }
        }
    }

    let mut out = Vec::new();
    walk(&crate_root().join("src"), "", &mut out);
    out.sort();
    out
}

/// `fn hold(&self, …) -> …` becomes `fn hold`; `struct Plan {` becomes `struct Plan`.
///
/// The kind is kept because `struct Held` becoming `enum Held` is a breaking change that a
/// name alone would hide.
fn item_name(rest: &str) -> Option<String> {
    for kind in [
        "fn ",
        "struct ",
        "enum ",
        "trait ",
        "const ",
        "static ",
        "type ",
        "mod ",
        "use ",
        "unsafe fn ",
        "extern ",
    ] {
        let Some(after) = rest.strip_prefix(kind) else {
            continue;
        };
        let name: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':' || *c == ' ')
            .collect();
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        return Some(format!(
            "{}{name}",
            kind.trim_end_matches(' ').to_owned() + " "
        ));
    }
    None
}

#[test]
fn the_public_surface_matches_the_snapshot() {
    let snapshot_path = crate_root().join("API.txt");
    let declared = declared_surface();
    assert!(
        declared.len() > 10,
        "the surface scan found only {} items, so it is reading nothing and this gate is \
         asserting nothing",
        declared.len()
    );

    let snapshot = fs::read_to_string(&snapshot_path).unwrap_or_else(|e| {
        panic!(
            "cannot read {} ({e}). It is committed: it is what makes enlarging this \
             crate's promise a line in a diff rather than something that happened.",
            snapshot_path.display()
        )
    });
    let expected: Vec<String> = snapshot
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();

    let added: Vec<&String> = declared.iter().filter(|d| !expected.contains(d)).collect();
    let removed: Vec<&String> = expected.iter().filter(|e| !declared.contains(e)).collect();

    assert!(
        added.is_empty() && removed.is_empty(),
        "the public surface of buildclamp-sandbox has changed.\n\n\
         added (this crate now promises to keep these working):\n{}\n\
         removed (a consumer depending on these no longer builds):\n{}\n\n\
         This crate is meant to be cut out and published on its own, so its surface is \n\
         frozen — see crates/sandbox/API.md. If the change is intended, update \n\
         crates/sandbox/API.txt in the same commit and say in the message why the promise \n\
         moved. If it is not, the addition probably wants `pub(crate)`.",
        added
            .iter()
            .map(|s| format!("  + {s}"))
            .collect::<Vec<_>>()
            .join("\n"),
        removed
            .iter()
            .map(|s| format!("  - {s}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
