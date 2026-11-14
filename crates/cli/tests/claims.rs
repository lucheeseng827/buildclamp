//! The claim registry gate: every present-tense claim resolves to evidence.
//!
//! `CLAIMS.toml` is the join between what this project says and what it can show. This
//! file is what makes the join real, because a registry nothing checks is just a longer
//! README.
//!
//! # Why this exists rather than a forbidden-words list
//!
//! The obvious version is a banned-vocabulary grep — "first", "only", "audited", "secure".
//! It was tried here first and it does not survive contact with the documents: "a
//! default-deny policy that breaks common crates on **the first** run", "resolved to **the
//! only** non-yanked modern release", "embeds an **SBOM** after the build" in a competitor
//! table. Ten hits, zero of them claims. A gate whose output is almost entirely false
//! positives gets an allowlist, then the allowlist gets entries added without much thought,
//! and then it is decoration — which is the exact failure mode this project keeps finding
//! in itself.
//!
//! So the gate targets the class that actually rots: **absence claims**. "Nobody has
//! shipped this" is true when written and false the moment a competitor ships, and nothing
//! tells you. It is also the class this project got wrong: its positioning said nobody
//! had shipped per-proc-macro handling when `cargo-acl` sandboxes rustc and holds every
//! proc-macro coarsely but really.
//!
//! Every absence claim must therefore be registered with the search that supports it, its
//! sources, and a date — and it goes stale on a clock, because an unrepeated search is not
//! evidence four months later.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

mod overlay;

fn module_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/cli is two levels below the module root")
        .to_path_buf()
}

fn registry() -> toml::Value {
    let text = fs::read_to_string(module_root().join("CLAIMS.toml"))
        .expect("CLAIMS.toml is the claim registry and must exist");
    let mut reg = text
        .parse::<toml::Value>()
        .expect("CLAIMS.toml must be valid TOML");
    // Claims whose evidence is not in this tree, where a checkout has them (overlay/mod.rs).
    if let Some(o) = overlay::load() {
        if let Some(all) = reg.get_mut("claim").and_then(toml::Value::as_array_mut) {
            all.extend(o.claims);
        }
    }
    reg
}

fn claims(reg: &toml::Value) -> Vec<&toml::Value> {
    reg.get("claim")
        .and_then(toml::Value::as_array)
        .expect("CLAIMS.toml has a [[claim]] array")
        .iter()
        .collect()
}

fn s<'a>(v: &'a toml::Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(toml::Value::as_str)
}

/// Every `.rs` file in the repository, tests included — evidence usually IS a test.
fn all_rust_source() -> String {
    fn walk(dir: &Path, out: &mut String) {
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
                    out.push_str(&t);
                    out.push('\n');
                }
            }
        }
    }
    let root = module_root();
    let mut out = String::new();
    walk(&root.join("crates"), &mut out);
    if let Some(dir) = overlay::load().and_then(|o| o.closed_tree_dir(&root)) {
        walk(&dir, &mut out);
    }
    assert!(
        out.len() > 10_000,
        "the source walk collected {} bytes; it is looking in the wrong place, and a gate \
         that reads nothing passes everything",
        out.len()
    );
    out
}

/// Whether a claim belongs to a tree this checkout does not have.
///
/// A path rule on `where` handled documents. It did not handle EVIDENCE: a claim whose test
/// lives in the overlay's second tree has no test when that tree is absent, and the gate was
/// right to fail — the registry was wrong to point at it unconditionally. A claim marked
/// `plane = "closed"` therefore applies only where that tree is present.
///
/// The lesson generalises: a registry that is read in more than one tree has to say which
/// tree each entry applies to, and a per-field prefix rule was always going to miss one.
fn claim_is_out_of_scope(c: &toml::Value, root: &Path) -> bool {
    s(c, "plane") == Some("closed")
        && overlay::load()
            .and_then(|o| o.closed_tree_dir(root))
            .is_none()
}

#[test]
fn every_claim_is_well_formed() {
    let reg = registry();
    let cs = claims(&reg);
    assert!(cs.len() >= 5, "the registry has only {} claims", cs.len());

    let mut ids = BTreeSet::new();
    for c in &cs {
        let id = s(c, "id").expect("every claim has an id");
        assert!(ids.insert(id.to_string()), "duplicate claim id: {id}");
        assert!(
            s(c, "text").is_some_and(|t| t.len() > 20),
            "{id}: text too short"
        );
        assert!(
            c.get("where")
                .and_then(toml::Value::as_array)
                .is_some_and(|w| !w.is_empty()),
            "{id}: `where` must name at least one file that makes the claim"
        );
        let kind = s(c, "kind").expect("every claim has a kind");
        assert!(
            kind == "capability" || kind == "absence",
            "{id}: kind must be capability or absence, got {kind}"
        );
        assert!(s(c, "checked").is_some(), "{id}: needs a `checked` date");
    }
}

/// Whether `rel` lies in the overlay's second tree while this checkout does not have it.
///
/// That tree is absent wherever only this tree exists, and a claim is allowed to name a
/// document that only ships beside it. The first version of this gate fell straight into
/// that hole: it asserted every `where` path exists, a claim named a document in the other
/// tree, and the run without it went red. The fix is not to stop checking. Such a path is
/// optional ONLY when its tree is absent; with it present the path must exist like any
/// other, so a typo is still caught wherever there is something to catch it against.
fn in_absent_tree(root: &Path, rel: &str) -> bool {
    overlay::load().is_some_and(|o| o.is_in_absent_tree(root, rel))
}

#[test]
fn every_file_a_claim_points_at_exists() {
    let root = module_root();
    let reg = registry();
    let mut missing = Vec::new();
    for c in claims(&reg) {
        let id = s(c, "id").unwrap_or("?").to_string();
        for w in c
            .get("where")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(rel) = w.as_str() else { continue };
            if in_absent_tree(&root, rel) {
                continue;
            }
            if !root.join(rel).exists() {
                missing.push(format!("{id} -> {rel}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "claims point at files that do not exist, so the registry has drifted from the \
         repository: {missing:?}"
    );
}

#[test]
fn every_capability_claim_names_a_test_that_exists() {
    let root = module_root();
    let reg = registry();
    let src = all_rust_source();
    let mut dangling = Vec::new();

    for c in claims(&reg) {
        if claim_is_out_of_scope(c, &root) {
            continue;
        }
        let id = s(c, "id").unwrap_or("?").to_string();
        if s(c, "kind") != Some("capability") {
            continue;
        }
        let ev = c
            .get("evidence")
            .and_then(toml::Value::as_array)
            .unwrap_or_else(|| panic!("{id}: a capability claim needs `evidence`"));
        assert!(!ev.is_empty(), "{id}: `evidence` is empty");

        for e in ev {
            let Some(item) = e.as_str() else { continue };
            // Two forms. Most evidence is a Rust test; some properties are asserted by a
            // shell gate instead, because they are about the resolved dependency graph
            // rather than about code this crate can call. Both are checked for existence,
            // and neither is allowed to be a bare sentence.
            if let Some(name) = item.strip_prefix("test:") {
                if !src.contains(&format!("fn {name}(")) {
                    dangling.push(format!("{id} -> test {name}"));
                }
            } else if let Some(rel) = item.strip_prefix("script:") {
                let path = module_root().join(rel);
                if !path.exists() {
                    dangling.push(format!("{id} -> script {rel} (missing)"));
                } else {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = fs::metadata(&path).expect("stat").permissions().mode();
                        if mode & 0o111 == 0 {
                            dangling.push(format!("{id} -> script {rel} (not executable)"));
                        }
                    }
                }
            } else {
                panic!("{id}: evidence `{item}` must be `test:<fn name>` or `script:<path>`");
            }
        }
    }

    assert!(
        dangling.is_empty(),
        "these claims cite tests that do not exist:\n  {}\n\nA claim whose evidence was \
         renamed or deleted is a claim with no evidence, and it reads exactly like one \
         that still has some.",
        dangling.join("\n  ")
    );
}

/// Days since 1970-01-01 for a `YYYY-MM-DD` string, by Howard Hinnant's days-from-civil.
///
/// No `chrono`: this crate does not depend on it, and a date comparison is not worth a
/// dependency in a binary sold to people who read `cargo tree`.
fn epoch_days(date: &str) -> Option<i64> {
    let mut it = date.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn today_epoch_days() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs();
    (secs / 86_400) as i64
}

#[test]
fn an_absence_claim_goes_stale_on_the_clock() {
    // The finding that produced this test, and it is the sharp one: `CLAIMS.toml` declared
    // `absence_max_age_days = 120` with a comment saying an older claim "fails the gate",
    // and nothing read the key. A registry whose freshness rule is itself unenforced is
    // the same defect as a flag nothing reads — shipped in the very change that added a
    // gate for flags nothing reads. `surface.rs` covers environment variables and
    // command-line flags, not TOML keys, so it could not catch this one.
    //
    // This test fails with the passage of time and that is deliberate. An absence claim
    // is a search somebody ran on a date; four months later it describes a search nobody
    // has repeated, and the competitor it is about has had four months to ship. Repeating
    // the search and moving the date is the work, not a chore to route around.
    let reg = registry();
    let max_age = reg
        .get("absence_max_age_days")
        .and_then(toml::Value::as_integer)
        .expect("CLAIMS.toml declares absence_max_age_days, and this test is what reads it");

    let today = today_epoch_days();
    let mut stale = Vec::new();

    for c in claims(&reg) {
        if s(c, "kind") != Some("absence") {
            continue;
        }
        let id = s(c, "id").unwrap_or("?").to_string();
        let checked = s(c, "checked").unwrap_or_else(|| panic!("{id}: needs `checked`"));
        let days = epoch_days(checked)
            .unwrap_or_else(|| panic!("{id}: `checked` must be YYYY-MM-DD, got {checked:?}"));
        let age = today - days;
        if age > max_age {
            stale.push(format!(
                "{id}: checked {checked}, {age} days ago (limit {max_age})"
            ));
        }
    }

    assert!(
        stale.is_empty(),
        "these absence claims are past their freshness window:\n  {}\n\nRepeat the \
         search named in the entry, then either move `checked` forward or soften the \
         claim. Raising `absence_max_age_days` to make this pass is the one fix that is \
         not a fix.",
        stale.join("\n  ")
    );
}

#[test]
fn every_absence_claim_carries_a_dated_search() {
    let reg = registry();
    let mut bad = Vec::new();
    for c in claims(&reg) {
        if s(c, "kind") != Some("absence") {
            continue;
        }
        let id = s(c, "id").unwrap_or("?").to_string();
        if s(c, "search").is_none_or(str::is_empty) {
            bad.push(format!("{id}: no `search` — what was looked at?"));
        }
        if c.get("sources")
            .and_then(toml::Value::as_array)
            .is_none_or(|v| v.is_empty())
        {
            bad.push(format!("{id}: no `sources`"));
        }
    }
    assert!(
        bad.is_empty(),
        "absence claims without a repeatable search:\n  {}\n\n\"Nobody has shipped this\" \
         is true when written and false the moment somebody ships. Without the search \
         written down, nobody can tell which state it is in.",
        bad.join("\n  ")
    );
}

/// Whitespace collapsed to single spaces, so a marker matches across a wrapped line.
///
/// The first version of this gate matched line by line and failed on both of the
/// repository's real claims, because prose wraps: "What nobody has shipped is per-macro
/// granularity" is split across two lines and neither carries enough of it. The second
/// version counted phrases per document instead, which review correctly called a gate
/// that cannot fail for the case it exists for — swapping one absence claim for a
/// different one keeps the count at two. Normalising first is what makes exact matching
/// possible, and exact matching is what ties an entry to the sentence it backs.
fn normalised(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

const ABSENCE_PHRASES: [&str; 6] = [
    "nobody has shipped",
    "no competitor",
    "no one else",
    "nobody ships",
    "no existing tool",
    "the only tool",
];

#[test]
fn every_absence_claim_appears_in_every_document_it_names() {
    let root = module_root();
    let reg = registry();
    let mut missing = Vec::new();

    for c in claims(&reg) {
        if s(c, "kind") != Some("absence") {
            continue;
        }
        let id = s(c, "id").unwrap_or("?").to_string();
        let marker = s(c, "marker").unwrap_or_else(|| {
            panic!(
                "{id}: an absence claim needs a `marker` — the exact \
                                       sentence in the prose it backs"
            )
        });
        let marker_n = normalised(marker);

        for w in c
            .get("where")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(rel) = w.as_str() else { continue };
            // Same rule: a document that only ships beside the other tree is not a
            // missing marker in a checkout that legitimately lacks that tree.
            if in_absent_tree(&root, rel) {
                continue;
            }
            let Ok(text) = fs::read_to_string(root.join(rel)) else {
                missing.push(format!("{id}: {rel} could not be read"));
                continue;
            };
            if !normalised(&text).contains(&marker_n) {
                missing.push(format!("{id}: marker not found in {rel}"));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "these absence claims name a document that no longer contains them:\n  {}\n\n\
         Either the prose was reworded and the marker needs updating, or the claim was \
         removed and the entry should go with it. A registry that has drifted from the \
         documents certifies whatever it used to say.",
        missing.join("\n  ")
    );
}

#[test]
fn no_absence_claim_in_the_documents_is_unregistered() {
    // The other direction, and the one that catches a NEW claim. Every registered marker
    // is deleted from the text first; anything matching an absence phrase in what remains
    // is a claim nobody wrote a search for.
    let root = module_root();
    let reg = registry();

    let markers: Vec<String> = claims(&reg)
        .iter()
        .filter(|c| s(c, "kind") == Some("absence"))
        .filter_map(|c| s(c, "marker").map(normalised))
        .collect();
    // No registered absence claim is a valid state, not a vacuous one: every absence phrase
    // in the documents is then unregistered, the strictest form of this gate. What it must
    // not do is read nothing, so it insists below that the documents were found.

    let mut docs: Vec<String> = ["README.md", "ARCHITECTURE.md", "CHANGELOG.md"]
        .map(String::from)
        .to_vec();
    if let Some(o) = overlay::load() {
        docs.extend(o.documents);
    }

    let mut unregistered = Vec::new();
    let mut read = 0;
    for d in &docs {
        let Ok(text) = fs::read_to_string(root.join(d)) else {
            continue;
        };
        read += 1;
        let mut remaining = normalised(&text);
        for m in &markers {
            remaining = remaining.replace(m.as_str(), " ");
        }
        let low = remaining.to_lowercase();
        for p in ABSENCE_PHRASES {
            if low.contains(p) {
                unregistered.push(format!("{d}: {p:?}"));
            }
        }
    }

    assert!(
        read >= 3,
        "the absence-claim gate read {read} documents; it is looking in the wrong place"
    );
    assert!(
        unregistered.is_empty(),
        "these absence claims appear in the documents and are not in CLAIMS.toml:\n  {}\n\n\
         An absence claim is true when written and false the moment somebody ships, and \
         nothing tells you. Add an entry with its `marker`, the search that supports it, \
         its sources and a date — or soften the sentence. This project has already got \
         this class wrong once, in its own positioning, about per-proc-macro handling.",
        unregistered.join("\n  ")
    );
}
