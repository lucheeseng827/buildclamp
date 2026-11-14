//! The properties the fuzz targets assert, and a deterministic sweep that runs them here.
//!
//! # Why the properties live in the library
//!
//! `cargo-fuzz` needs a nightly toolchain and libFuzzer, so a target that only exists
//! under `fuzz/` is a check that runs where somebody has set that up and nowhere else.
//! These are the same functions, called from `cargo test` over a seeded corpus on every
//! commit and from libFuzzer over an unbounded one when it is available. The fuzzer finds
//! the inputs; the property decides what "wrong" means, and it must not live only where
//! the fuzzer does.
//!
//! # The properties
//!
//! **A parse is never more permissive than the text.** `Policy::parse` either fails, or
//! every capability it hands a unit is one the file named or one the defaults already
//! gave. This is the fails-open class: a `#[serde(default)]` that defaults the wrong way,
//! a version requirement that matches a unit it should not, a merge that unions where it
//! should replace. Each of those produces a policy that parses, reads correctly to a
//! human, and grants something nobody wrote down.
//!
//! The oracle is deliberately built from a **generic** TOML parse rather than from the
//! typed structs: it collects every whole string anywhere in the document and asserts the
//! envelope is inside the capabilities and zones among them. It therefore knows nothing
//! about `Grant`, `Grants`, `Defaults` or the resolution order, which is what makes it a
//! second opinion rather than a restatement.
//!
//! **A report survives being read.** `Report::from_json` either fails or produces a
//! document that serialises and reads back to the same value — including the v1 migration,
//! which is the path a real consumer takes. And **a migration never strengthens a tier**:
//! a v1 document whose network tier was advisory must not come back enforced, because a
//! reader acting on that difference is acting on something no run measured.
//!
//! # What is not here
//!
//! The drift-envelope deserializer, which is an untrusted input boundary outside this
//! tool. It lives with the code it is about.

use crate::capability::Capability;
use crate::policy::Policy;
use crate::report::Report;
use crate::unit::{UnitId, UnitKind};

/// The units a parsed policy is interrogated about.
///
/// Fixed rather than generated: the property is about what the *document* can produce, and
/// the interesting variation is in the text. Two names — one that a generated grant is
/// likely to match and one nothing should — and three versions including one that is not a
/// version, because a grant that applied to a version it could not compare against would
/// be widening an envelope by accident.
fn probe_units() -> Vec<(UnitId, UnitKind)> {
    let mut out = Vec::new();
    for name in ["evil", "libc", "a-crate-no-policy-mentions"] {
        for version in ["0.1.3", "1.2.3", "not-a-version"] {
            for kind in [UnitKind::BuildScriptCompile, UnitKind::Compile] {
                out.push((UnitId::new(name, version), kind));
            }
        }
    }
    out
}

/// Every whole string in the document, however deeply nested.
///
/// A generic walk, not a typed read: it knows nothing about `Grant`, `Grants`, `Defaults`
/// or the resolution order, which is what makes it a second opinion rather than a
/// restatement of the code under test.
///
/// It over-approximates in exactly one way, and it is worth being precise about which:
/// a string is counted **wherever it appears**, so `why = "net"` puts `net` in the set
/// even though a `why` grants nothing. It does *not* match substrings — `why = "it does
/// not use net"` contributes nothing — so the bound is over whole values, not over the
/// file's bytes. Both directions are deliberate. An over-approximation makes the property
/// weaker and never makes it wrong; matching substrings would make almost any document
/// vacuously pass, because a `why` sentence mentioning what a crate does *not* do would
/// license the capability it names.
fn strings_in(text: &str) -> Vec<String> {
    fn walk(v: &toml::Value, out: &mut Vec<String>) {
        match v {
            toml::Value::String(s) => {
                if !out.contains(s) {
                    out.push(s.clone());
                }
            }
            toml::Value::Array(a) => a.iter().for_each(|v| walk(v, out)),
            toml::Value::Table(t) => t.values().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Ok(v) = toml::from_str::<toml::Value>(text) {
        walk(&v, &mut out);
    }
    out
}

/// The capabilities [`strings_in`] finds.
fn capabilities_named(text: &str) -> Vec<Capability> {
    let mut out = Vec::new();
    for s in strings_in(text) {
        if let Ok(c) = s.parse::<Capability>() {
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out
}

/// The grade a report's raw JSON gave the unit at array position `index` for `cap`, if it can
/// be found.
///
/// Indexed by position, not by `(name, version)`. A report can carry several records with the
/// same `UnitId`, distinguished only by `instance` or `kind` — one build script is executed
/// more than once per build — and matching by name and version could compare a strengthened
/// later record against an honest earlier one and so miss the strengthening this check exists
/// to catch. `report` was parsed from this same `text` and the migration keeps units in order,
/// so `units[index]` here is the very record `report.units[index]` is comparing.
///
/// A second opinion over generic JSON, so the tier check does not have to trust the typed
/// read it is testing. It handles both the v2 map spelling `{cap: {grade}}` and the v1
/// array-of-pairs `[[cap, {grade}]]`. It returns `None` when the shape is not what either
/// version writes — the caller then falls back to the sound document-wide check rather than
/// fail a valid migration over a structure it did not recognise (the input is fuzzed, so
/// "unrecognised" is common and must never be an error).
fn raw_tier_grade(text: &str, index: usize, cap: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let u = v.get("units")?.as_array()?.get(index)?;
    let tiers = u.get("tiers")?;
    // v2: a map from capability to its tier object.
    if let Some(map) = tiers.as_object() {
        return map
            .get(cap)
            .and_then(|t| t.get("grade"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
    }
    // v1: an array of `[capability, tier]` pairs.
    if let Some(pairs) = tiers.as_array() {
        for pair in pairs {
            let pair = pair.as_array()?;
            if pair.first().and_then(serde_json::Value::as_str) == Some(cap) {
                return pair
                    .get(1)
                    .and_then(|t| t.get("grade"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string);
            }
        }
    }
    None
}

/// The property: a parse is never more permissive than the text.
///
/// `Err` carries enough to reproduce: the document, the unit, and the capability that
/// appeared from nowhere.
pub fn policy_is_no_more_permissive_than_its_text(text: &str) -> Result<(), String> {
    let Ok(policy) = Policy::parse(text) else {
        // A refused document is the other half of the property. Nothing was granted.
        return Ok(());
    };
    let named = capabilities_named(text);

    for (id, kind) in probe_units() {
        // Resolved WITHOUT break-glass. An exception naming no capabilities grants all of
        // them by design, so including it would make the property either vacuous or a
        // restatement of the exception rule. `breakglass.rs` tests that rule directly.
        let Ok(envelope) = policy.resolve(&id, kind, false) else {
            continue;
        };
        // The defaults are permitted whatever the text says: they are what a unit gets
        // when no grant matches, and a document that mentions nothing still produces them.
        let default_envelope = match kind {
            UnitKind::BuildScriptCompile => crate::Envelope::build_script_default(),
            _ => crate::Envelope::compile_default(),
        };
        for c in envelope.granted.iter() {
            // `fs-read` is the default allowance ONLY while withholding is off — the literal
            // truth on a host where nothing withholds a read, argued at length in
            // `Policy::settle_reads`. With `withhold-secret-reads` on it is not a default, so a
            // granted `fs-read` the document does not name is the strongest read-control
            // regression there is; it is then checked like any other capability rather than
            // skipped.
            if c == Capability::FsRead && !policy.defaults.withhold_secret_reads {
                continue;
            }
            if default_envelope.permits(c) || named.contains(&c) {
                continue;
            }
            return Err(format!(
                "`{}` was granted `{}` and nothing in the document names it\n\
                 --- the document ---\n{text}\n--- unit: {} {} as {:?} ---",
                id.name,
                c.as_str(),
                id.name,
                id.version,
                kind
            ));
        }

        // The same bound on where it may write. A zone is a *shape* rather than a yes or
        // no, so a parse that widened one is the more dangerous of the two. Compared as
        // whole strings for the same reason capabilities are: `text.contains("out-dir")`
        // would be satisfied by a `why` sentence and the bound would mean nothing.
        let named_strings = strings_in(text);
        for z in &envelope.write_zones {
            let name = z.to_string();
            let is_default = default_envelope
                .write_zones
                .iter()
                .any(|d| d.to_string() == name);
            if is_default || named_strings.contains(&name) {
                continue;
            }
            return Err(format!(
                "`{}` may write in `{name}` and nothing in the document names it\n\
                 --- the document ---\n{text}",
                id.name
            ));
        }

        // The same bound on explicit write PATHS. The loop above checks `write-zones`; an
        // invented or mis-inherited `write-paths` entry widens filesystem access just as much
        // and was going unchecked entirely. Defaults carry no write paths, so any resolved
        // path must appear as a whole string in the document.
        for p in &envelope.write_paths {
            if named_strings.contains(p) {
                continue;
            }
            return Err(format!(
                "`{}` may write the path `{p}` and nothing in the document names it\n\
                 --- the document ---\n{text}",
                id.name
            ));
        }
    }
    Ok(())
}

/// The property: a report either fails to parse or survives being read and written.
///
/// Round-tripping through the *typed* value rather than comparing strings, because
/// `from_json` migrates a v1 document on the way in and the migrated form is legitimately
/// a different string. What must not change is the meaning.
pub fn report_survives_being_read(text: &str) -> Result<(), String> {
    let Ok(report) = Report::from_json(text) else {
        return Ok(());
    };
    let written = serde_json::to_string(&report)
        .map_err(|e| format!("a parsed report would not serialise: {e}"))?;
    let again = Report::from_json(&written).map_err(|e| {
        format!("a report this build wrote would not read back: {e}\n--- it wrote ---\n{written}")
    })?;
    if serde_json::to_string(&again).ok().as_deref() != Some(written.as_str()) {
        return Err(format!(
            "reading a report changed it\n--- first ---\n{written}\n--- second ---\n{}",
            serde_json::to_string(&again).unwrap_or_default()
        ));
    }

    // And the direction that matters: reading a document must never strengthen a tier.
    // A v1 report whose network tier was advisory coming back enforced would be a reader
    // asserting something no run measured — the exact overstatement the tier ladder is
    // there to prevent, arriving through a migration nobody looks at.
    //
    // Checked per `(unit, capability)`, not with `text.contains("enforced")`: one legitimately
    // enforced tier anywhere in the document would otherwise license every other tier to come
    // back enforced, so a migration that strengthened a *different* capability would pass.
    for (index, unit) in report.units.iter().enumerate() {
        for (cap, tier) in &unit.tiers {
            if !tier.is_enforced() {
                continue;
            }
            let cap = cap.to_string();
            match raw_tier_grade(text, index, &cap) {
                // The document graded this exact `(unit, cap)`: it has to have been enforced
                // too, or the migration strengthened it.
                Some(grade) => {
                    if grade != "enforced" {
                        return Err(format!(
                            "reading this report produced an `enforced` tier for `{cap}` on \
                             `{}` but the document graded it `{grade}`\n--- the document ---\n{text}",
                            unit.id.name
                        ));
                    }
                }
                // The raw grade could not be located (a shape the fuzzer mangled): fall back to
                // the sound document-wide check — an `enforced` that appears nowhere in the
                // text is a fabrication no matter how the document is spelled.
                None => {
                    if !text.contains("enforced") {
                        return Err(format!(
                            "reading this report produced an `enforced` tier for `{cap}` and the \
                             document never said `enforced`\n--- the document ---\n{text}"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny xorshift, so the sweep is a fixed corpus rather than a different one on
    /// every run. A test that mutated randomly would fail on somebody else's machine for
    /// an input nobody could reproduce, which is the worst property a property test can
    /// have.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// The committed corpus for one fuzz target.
    ///
    /// **The same files libFuzzer seeds from**, which is what makes a crash committed there
    /// a permanent regression test on the stable toolchain — see `fuzz/corpus/README.md`.
    /// A property that only ran against seeds written inline here would leave every crash
    /// the fuzzer ever found guarded by nothing but a corpus file nobody reads.
    ///
    /// A missing or empty directory **panics**. It is committed, and the alternative is a
    /// sweep that silently covers nothing — which is the shape of green test this project
    /// has already had once, in its own end-to-end suite, where seven tests skipped on
    /// every host and reported success.
    fn corpus(target: &str) -> Vec<String> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("../../fuzz/corpus/{target}"));
        let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
            panic!(
                "no corpus at {} ({e}). It is committed, and a sweep with no inputs asserts \
                 nothing while reporting success.",
                dir.display()
            )
        });
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "md") {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                out.push(text);
            }
        }
        assert!(
            !out.is_empty(),
            "the corpus at {} is empty; seeds are committed so that both the fuzzer and \
             this sweep start from something",
            dir.display()
        );
        out
    }

    /// Byte-level mutations of a seed. Crude on purpose: the interesting failures are
    /// documents that still parse, and a mutator that only produced valid TOML would never
    /// reach the error paths this is also asserting do not grant anything.
    fn mutate(seed: &str, rng: &mut Rng) -> String {
        let mut b = seed.as_bytes().to_vec();
        if b.is_empty() {
            return seed.to_string();
        }
        let ops = 1 + rng.below(3);
        for _ in 0..ops {
            let at = rng.below(b.len());
            match rng.below(4) {
                0 => b[at] = b"abcdefghijklmnopqrstuvwxyz-_\"[]{}=,.0123456789\n"[rng.below(46)],
                1 => {
                    b.remove(at);
                    if b.is_empty() {
                        return String::new();
                    }
                }
                2 => b.insert(at, b"\"[]{}=,\n "[rng.below(9)]),
                // Splice in a capability name, which is how a mutation reaches the branch
                // that matters: a document that grants something is more interesting than
                // one that is merely malformed.
                _ => {
                    let word =
                        ["net", "fs-write", "env-secret", "exec", "unix", "fs-read"][rng.below(6)];
                    for (i, c) in word.bytes().enumerate() {
                        b.insert(at + i, c);
                    }
                }
            }
        }
        String::from_utf8_lossy(&b).into_owned()
    }

    #[test]
    fn a_parse_is_never_more_permissive_than_its_text() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let seeds = corpus("policy_no_more_permissive");
        for seed in &seeds {
            policy_is_no_more_permissive_than_its_text(seed).unwrap_or_else(|e| panic!("{e}"));
        }
        let mut parsed = 0usize;
        for _ in 0..20_000 {
            let text = mutate(&seeds[rng.below(seeds.len())], &mut rng);
            policy_is_no_more_permissive_than_its_text(&text).unwrap_or_else(|e| panic!("{e}"));
            if Policy::parse(&text).is_ok() {
                parsed += 1;
            }
        }
        // A sweep where every document was rejected would be asserting the property about
        // nothing — the shape of green test this project has already had once, and the
        // reason every guard here counts what it covered.
        assert!(
            parsed > 200,
            "only {parsed} of 20000 mutations produced a policy that parsed; the mutator \
             is producing garbage rather than documents"
        );
    }

    #[test]
    fn the_property_fails_on_a_policy_that_grants_what_the_text_does_not_name() {
        // A gate never observed to fail is not a gate. This constructs the finding
        // directly — a document naming only `exec` whose envelope somehow includes `net` —
        // by checking the oracle against a hand-built claim rather than by breaking the
        // parser.
        let text = "version = 1\n[grants.\"evil\"]\ncapabilities = [\"exec\"]\nwhy = \"x\"\n";
        let named = capabilities_named(text);
        assert!(named.contains(&Capability::Exec));
        assert!(
            !named.contains(&Capability::Net),
            "the oracle must not find a capability the document never names, or the \
             property is vacuous"
        );
        // The over-approximation is over whole values, not over bytes, and the difference
        // is what keeps the property from being vacuous. A `why` whose entire text is a
        // capability name counts; a `why` that merely mentions one in a sentence — which
        // is what almost every real `why` does, often to say the crate does NOT do it —
        // does not.
        let sentence = "version = 1\n[grants.\"evil\"]\ncapabilities = [\"exec\"]\n\
                        why = \"it does not use net\"\n";
        assert!(
            !capabilities_named(sentence).contains(&Capability::Net),
            "a substring match here would let any `why` license the capability it names"
        );
        let whole = "version = 1\n[grants.\"evil\"]\ncapabilities = [\"exec\"]\n\
                     why = \"net\"\n";
        assert!(capabilities_named(whole).contains(&Capability::Net));
    }

    #[test]
    fn a_report_either_fails_to_parse_or_survives_being_read() {
        let seeds = corpus("report_round_trip");
        let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
        for seed in &seeds {
            report_survives_being_read(seed).unwrap_or_else(|e| panic!("{e}"));
        }
        let mut parsed = 0usize;
        for _ in 0..5_000 {
            let text = mutate(&seeds[rng.below(seeds.len())], &mut rng);
            report_survives_being_read(&text).unwrap_or_else(|e| panic!("{e}"));
            if Report::from_json(&text).is_ok() {
                parsed += 1;
            }
        }
        assert!(
            parsed > 50,
            "only {parsed} of 5000 mutations produced a report that parsed"
        );
    }

    #[test]
    fn raw_tier_grade_reads_both_the_v2_map_and_the_v1_pairs() {
        // The per-(unit, cap) second opinion behind the "migration never strengthens a tier"
        // check. It must read a grade out of both report spellings, and return None — so the
        // caller falls back to the sound document-wide check — for anything it cannot locate.
        let v2 = r#"{"units":[{"id":{"name":"libc","version":"0.2.0"},"tiers":{
            "net":{"grade":"enforced","mechanism":"seccomp-errno"},
            "fs-write":{"grade":"advisory","mechanism":"seccomp-notify","limitation":"x"}}}]}"#;
        assert_eq!(raw_tier_grade(v2, 0, "net").as_deref(), Some("enforced"));
        assert_eq!(
            raw_tier_grade(v2, 0, "fs-write").as_deref(),
            Some("advisory")
        );
        assert_eq!(raw_tier_grade(v2, 0, "exec"), None); // capability not present
        let v1 = r#"{"units":[{"id":{"name":"libc","version":"0.2.0"},"tiers":[
            ["net",{"grade":"enforced","mechanism":"seccomp-errno"}],
            ["fs-write",{"grade":"advisory","mechanism":"seccomp-notify","limitation":"x"}]]}]}"#;
        assert_eq!(raw_tier_grade(v1, 0, "net").as_deref(), Some("enforced"));
        assert_eq!(
            raw_tier_grade(v1, 0, "fs-write").as_deref(),
            Some("advisory")
        );
        // An index the document does not carry: None, so the check stays sound rather than
        // failing a valid migration over a shape it could not read.
        assert_eq!(raw_tier_grade(v2, 5, "net"), None);
    }

    #[test]
    fn raw_tier_grade_distinguishes_records_that_share_a_unit_id() {
        // Why it is indexed and not matched by (name, version): a report can hold two records
        // with the identical UnitId — one enforced, one advisory — because a build script runs
        // more than once per build. Matched by name+version, the second record's grade would be
        // read from the first, and a migration that strengthened the second advisory tier to
        // enforced would pass this check unseen. By index, each record is read as itself.
        let doc = r#"{"units":[
            {"id":{"name":"dup","version":"1.0.0"},"tiers":{"net":{"grade":"enforced","mechanism":"seccomp-errno"}}},
            {"id":{"name":"dup","version":"1.0.0"},"tiers":{"net":{"grade":"advisory","mechanism":"seccomp-notify","limitation":"x"}}}
        ]}"#;
        assert_eq!(raw_tier_grade(doc, 0, "net").as_deref(), Some("enforced"));
        assert_eq!(
            raw_tier_grade(doc, 1, "net").as_deref(),
            Some("advisory"),
            "the second record must be read as itself, not aliased to the first by UnitId"
        );
    }

    #[test]
    fn the_policy_property_accepts_a_grant_that_names_its_write_path() {
        // Guards the write-paths check: a resolved path the document DOES name must pass, or
        // the property would false-positive on every policy that uses `write-paths`.
        let text = "version = 1\n[grants.\"libc\"]\ncapabilities = [\"fs-write\"]\n\
                    write-paths = [\"/opt/vendored\"]\nwhy = \"vendored headers\"\n";
        policy_is_no_more_permissive_than_its_text(text).unwrap();
    }

    #[test]
    fn the_policy_property_accepts_a_withholding_policy_that_names_fs_read() {
        // With `withhold-secret-reads` on, `fs-read` is no longer a default and is checked
        // like any other capability. A policy that turns withholding on must still pass the
        // property — the point of the change is to catch a regression that grants `fs-read`
        // WITHOUT naming it, not to fail a policy that names it.
        let text = "version = 1\n[defaults]\nwithhold-secret-reads = true\n\
                    [grants.\"libc\"]\ncapabilities = [\"fs-read\", \"fs-write\"]\n\
                    why = \"reads a vendored file\"\n";
        policy_is_no_more_permissive_than_its_text(text).unwrap();
    }
}
