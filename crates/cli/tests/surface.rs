//! The mechanical sweep: everything the tool declares must be read by something.
//!
//! # The defect class this exists for
//!
//! Twice in one week this project shipped a switch that was declared, documented, wired
//! into the command line — and read by nobody.
//!
//! * `--deep` set `BUILDCLAMP_DEEP` in the environment and no code ever looked it up, so
//!   the flag documented for recording every write recorded nothing.
//! * `REPORT_FORMAT_VERSION` was written into every report and compared by no consumer,
//!   so its own doc comment — "a consumer that finds a higher number must say so rather
//!   than parse what it recognises" — described a contract that did not exist.
//!
//! Both were found by hand, one of them by accident. Neither is exotic: a flag is added,
//! the plumbing lands in one commit and the code that consumes it in another, and the
//! second commit does not arrive. Nothing fails, because nothing was asserting. That is
//! the same shape as the end-to-end suite reporting `7 passed` while every test skipped,
//! and it has the same cause — a thing that only ever *looks* present.
//!
//! So this file asserts the property mechanically, over the source, and it will keep
//! finding the next one without anybody being clever.
//!
//! # What it does NOT catch, stated plainly
//!
//! A value that is written AND read but never **acted on**. `format_version` would pass
//! this sweep today if `Report::from_json` did not compare it, because the field is read
//! when the struct is built. Detecting "read but not used in a decision" is a dataflow
//! question a grep cannot answer, and pretending otherwise would make this file the same
//! kind of decorative check it exists to prevent. That class needs a test that exercises
//! the behaviour, which is what `crates/core/tests/schema.rs` is.
//!
//! It also only reads **production** source: each file is cut at its first `#[cfg(test)]`,
//! so a switch read only from a test module counts as unread — which is the answer we
//! want, since a flag exercised only by its own tests is still dead in the field.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

mod overlay;

/// The module root — two levels above `crates/cli`, the same walk `endtoend.rs` makes.
fn module_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/cli is two levels below the module root")
        .to_path_buf()
}

/// Every `.rs` file under the Apache-2.0 crates, cut at its first `#[cfg(test)]`.
///
/// The cut is why this is honest about test-only readers. It assumes test modules sit at
/// the end of a file, which is this repository's consistent shape; a `#[cfg(test)]` in
/// the middle would hide production code after it from the sweep, which fails safe —
/// toward reporting a reader missing, never toward inventing one.
fn production_sources() -> BTreeMap<String, String> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                // Integration tests live in `crates/*/tests/`, and a file there carries no
                // `#[cfg(test)]` marker — the whole file is the test — so the cut below
                // does not exclude them. Without this, a `.field` or `ENV_` reference in a
                // test would satisfy a check that promises production code, and the sweep
                // would certify a switch that only its own tests read. Found by review;
                // no current flag was passing for this reason, but the gate could not have
                // told the difference.
                let skip = p.file_name().is_some_and(|n| {
                    matches!(
                        n.to_str(),
                        Some("tests" | "benches" | "examples" | "target")
                    )
                });
                if !skip {
                    walk(&p, out);
                }
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let root = module_root();
    let mut files = Vec::new();
    walk(&root.join("crates"), &mut files);

    let mut map = BTreeMap::new();
    for f in files {
        let Ok(text) = fs::read_to_string(&f) else {
            continue;
        };
        let prod = match text.find("#[cfg(test)]") {
            Some(i) => text[..i].to_string(),
            None => text,
        };
        let rel = f
            .strip_prefix(&root)
            .unwrap_or(&f)
            .to_string_lossy()
            .into_owned();
        map.insert(rel, prod);
    }
    assert!(
        map.len() >= 15,
        "the source walk found only {} files; it is looking in the wrong place, and a \
         sweep that scans nothing passes everything",
        map.len()
    );
    map
}

/// Environment variables the tool reads via a literal rather than a const.
///
/// `BUILDCLAMP_DISABLE` is one: `crates/sandbox` looks it up with a string, because it is
/// a test and diagnostic affordance rather than part of the wrapper protocol the `ENV_`
/// consts describe. Such a variable needs no read-site check — it was *found* at its read
/// site — but the documentation checks below must still know it exists, or they report a
/// variable that plainly works as missing. Found this way on the sweep's first run, which
/// is the checker being corrected by the source rather than the other way round.
fn literal_env_vars(src: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for text in src.values() {
        for line in text.lines() {
            if !(line.contains("env::var(\"") || line.contains("env::var_os(\"")) {
                continue;
            }
            for piece in line.split('"') {
                if piece.starts_with("BUILDCLAMP_") && !out.contains(&piece.to_string()) {
                    out.push(piece.to_string());
                }
            }
        }
    }
    out
}

/// `pub const ENV_X: &str = "BUILDCLAMP_Y";` → `(ENV_X, BUILDCLAMP_Y, file)`.
fn declared_env_consts(src: &BTreeMap<String, String>) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (file, text) in src {
        for line in text.lines() {
            let t = line.trim();
            let Some(rest) = t.strip_prefix("pub const ") else {
                continue;
            };
            let Some((name, tail)) = rest.split_once(':') else {
                continue;
            };
            if !name.starts_with("ENV_") {
                continue;
            }
            let Some(v) = tail.split('"').nth(1) else {
                continue;
            };
            if v.starts_with("BUILDCLAMP_") {
                out.push((name.trim().to_string(), v.to_string(), file.clone()));
            }
        }
    }
    out
}

/// Whether `line` uses `name` to *write* the environment rather than read it.
fn is_env_write(line: &str, name: &str) -> bool {
    line.contains(&format!(".env({name}"))
        || line.contains(&format!("env_remove({name}"))
        || line.contains(&format!(".env({}", format_args!("buildclamp_core::{name}")))
        || line.contains(&format!(
            "env_remove({}",
            format_args!("buildclamp_core::{name}")
        ))
}

#[test]
fn every_environment_variable_the_tool_sets_is_read_by_something() {
    let src = production_sources();
    let consts = declared_env_consts(&src);
    assert!(
        consts.len() >= 5,
        "found only {} ENV_ consts; the parser has drifted from the source",
        consts.len()
    );

    let mut dead = Vec::new();
    for (name, value, decl_file) in &consts {
        let mut readers = Vec::new();
        for (file, text) in &src {
            for (n, line) in text.lines().enumerate() {
                // The declaration itself is not a reader, nor is the `use` that imports it.
                if file == decl_file && line.contains("pub const") && line.contains(name) {
                    continue;
                }
                if line.trim_start().starts_with("use ") {
                    continue;
                }
                if !line.contains(name) {
                    continue;
                }
                if is_env_write(line, name) {
                    continue;
                }
                readers.push(format!("{file}:{}", n + 1));
            }
        }
        if readers.is_empty() {
            dead.push(format!("  {name} (\"{value}\") declared in {decl_file}"));
        }
    }

    assert!(
        dead.is_empty(),
        "these environment variables are set or declared and read by NOTHING in \
         production code:\n{}\n\nEither wire the read site or delete the variable. A \
         switch that is documented and never consulted is the defect that made `--deep` \
         record nothing: it looks present in every place a reader would check.",
        dead.join("\n")
    );
}

#[test]
fn every_command_line_flag_is_read_outside_the_place_it_is_declared() {
    let src = production_sources();
    let args = src
        .get("crates/cli/src/args.rs")
        .expect("crates/cli/src/args.rs is where the command line is declared");

    // `#[arg(long...)]` on the line(s) before `pub <field>:`.
    let lines: Vec<&str> = args.lines().collect();
    let mut flags: Vec<String> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains("#[arg(long") {
            continue;
        }
        for probe in lines.iter().skip(i + 1).take(4) {
            let t = probe.trim();
            if let Some(rest) = t.strip_prefix("pub ") {
                if let Some((field, _)) = rest.split_once(':') {
                    flags.push(field.trim().to_string());
                    break;
                }
            }
        }
    }
    flags.sort();
    flags.dedup();
    assert!(
        flags.len() >= 10,
        "found only {} long flags; the parser has drifted from args.rs",
        flags.len()
    );

    let mut dead = Vec::new();
    for f in &flags {
        let needle = format!(".{f}");
        let read = src.iter().any(|(file, text)| {
            file != "crates/cli/src/args.rs"
                && text.lines().any(|l| {
                    l.contains(&needle)
                        && !l.trim_start().starts_with("//")
                        && !l.trim_start().starts_with("///")
                })
        });
        if !read {
            dead.push(f.clone());
        }
    }

    assert!(
        dead.is_empty(),
        "these command-line flags are declared in args.rs and read NOWHERE else in \
         production code: {dead:?}\n\nThe flag parses, `--help` documents it, and it \
         changes nothing. Wire it or delete it.",
        dead = dead
    );
}

#[test]
fn every_environment_variable_is_documented_and_every_documented_one_exists() {
    let root = module_root();
    let src = production_sources();
    let consts = declared_env_consts(&src);

    let docs: String = ["docs/CONFIG.md", "docs/OPERATIONS.md", "README.md"]
        .iter()
        .filter_map(|p| fs::read_to_string(root.join(p)).ok())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !docs.is_empty(),
        "no documentation was read; the paths have moved"
    );

    // Code → docs. A variable the tool honours and nobody wrote down is undocumented
    // surface, which is how a switch survives long enough to rot.
    let literals = literal_env_vars(&src);
    let mut known: Vec<String> = consts.iter().map(|(_, v, _)| v.clone()).collect();
    known.extend(literals);
    known.sort();
    known.dedup();

    let undocumented: Vec<&str> = known
        .iter()
        .map(String::as_str)
        .filter(|v| !docs.contains(*v))
        .collect();
    assert!(
        undocumented.is_empty(),
        "these environment variables are honoured by the tool and appear in no \
         documentation: {undocumented:?}"
    );

    // Docs → code. A variable named in the documentation and absent from the source is a
    // reader following an instruction that does nothing.
    let declared: Vec<&str> = known.iter().map(String::as_str).collect();
    let mut orphaned = Vec::new();
    for word in docs.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if word.starts_with("BUILDCLAMP_")
            && !declared.contains(&word)
            && !orphaned.contains(&word.to_string())
        {
            orphaned.push(word.to_string());
        }
    }
    assert!(
        orphaned.is_empty(),
        "the documentation names environment variables that do not exist in the source: \
         {orphaned:?}\n\nA reader who sets one of these gets silence."
    );
}

/// Every crate but `buildclamp-sandbox` forbids `unsafe`, so the confinement is a
/// compiler check rather than a claim in a document.
///
/// `crates/sandbox/INTERNALS.md` opens by telling a new engineer that the entire
/// `unsafe` surface of the project is one bounded crate, and an auditor scopes an
/// engagement on that sentence — the Y2 audit line names exactly those files. A sentence
/// load-bearing enough to price an audit against should not be true by coincidence.
///
/// This checks the *attribute*, not the absence of the token, and the difference is the
/// whole point: absence today is luck, and the lint is what makes it hold tomorrow. The
/// lint was watched to fail — adding `unsafe { libc::getpid() }` to `crates/cli` gives
/// `error: usage of an unsafe block`, so this is a gate observed to bite rather than one
/// assumed to.
#[test]
fn every_crate_outside_the_sandbox_forbids_unsafe_code() {
    let root = module_root();
    let mut roots: Vec<PathBuf> = Vec::new();
    // The overlay's second tree (overlay/mod.rs) is scanned when a checkout has it and
    // skipped silently when it does not. A test that named its paths unconditionally would
    // fail in the tree it most needs to pass in.
    let mut crates_dirs = vec![root.join("crates")];
    if let Some(dir) = overlay::load().and_then(|o| o.closed_tree_dir(&root)) {
        crates_dirs.push(dir.join("crates"));
    }
    for crates_dir in crates_dirs {
        let Ok(entries) = fs::read_dir(&crates_dir) else {
            continue;
        };
        for e in entries.flatten() {
            for name in ["lib.rs", "main.rs"] {
                let p = e.path().join("src").join(name);
                if p.is_file() {
                    roots.push(p);
                }
            }
        }
    }

    assert!(
        roots.len() >= 4,
        "found only {} crate roots; the walk is looking in the wrong place, and a sweep \
         that scans nothing passes everything",
        roots.len()
    );

    // Line-exact, and NOT `contains`: `crates/sandbox/src/lib.rs` names the attribute in
    // its own module docs to explain the confinement, so a substring search reads that
    // prose as the lint. The first version of this test did exactly that and reported the
    // sandbox as forbidding unsafe — a checker satisfied by a sentence describing the
    // thing it is meant to verify.
    fn forbids_unsafe(text: &str) -> bool {
        text.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]")
    }

    let mut missing = Vec::new();
    for p in &roots {
        let rel = p.strip_prefix(&root).unwrap_or(p).to_string_lossy();
        // The one crate that cannot forbid it is the one that exists to contain it.
        if rel.starts_with("crates/sandbox/") {
            continue;
        }
        if !forbids_unsafe(&fs::read_to_string(p).unwrap_or_default()) {
            missing.push(rel.into_owned());
        }
    }

    assert!(
        missing.is_empty(),
        "these crate roots do not forbid `unsafe`, so the claim that every unsafe block \
         in the project lives in `crates/sandbox` is unenforced: {missing:?}"
    );

    // And the containment is only meaningful if the sandbox is genuinely the exception:
    // a run where every crate forbade it would pass the loop above while proving nothing.
    let sandbox = fs::read_to_string(root.join("crates/sandbox/src/lib.rs")).unwrap();
    assert!(
        !forbids_unsafe(&sandbox),
        "if the sandbox forbids unsafe too, this test is asserting a property of an empty \
         set and the exception it documents is stale"
    );
}
