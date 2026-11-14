//! The tool's output never claims a compliance status it cannot back, and never describes
//! its own report as an SBOM.
//!
//! The capability report is a per-crate record of what a build asked for and what happened
//! to it. It is testing evidence — one of the four routes CRA Article 13(5) names — and it
//! is emphatically **not** a software bill of materials: it is not CycloneDX, not SPDX, and
//! carries none of the NTIA minimum elements. Nor is it a conformity assessment. A build
//! tool that let those words into its output would be handing a reader a claim the document
//! cannot support, which is the exact failure this project exists not to commit — and it is
//! the one a demand for CRA evidence makes tempting.
//!
//! So this gate scans the OUTPUT PATHS — the modules that produce what the tool prints and
//! writes — for those words as string literals. It deliberately does not scan the prose
//! docs: `docs/SSDF.md` and the like discuss CRA, SBOMs and conformity in order to say what
//! buildclamp is NOT, and banning the words there would ban the honesty. The line is
//! output, not discussion.

use std::fs;
use std::path::{Path, PathBuf};

fn module_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/cli is two levels below the module root")
        .to_path_buf()
}

/// The modules that produce what the tool emits: the human-readable render, and the
/// machine documents (report, attestation) whose field names and fixed strings are the only
/// non-data text in the output.
fn output_path_sources() -> Vec<(PathBuf, String)> {
    let root = module_root();
    [
        "crates/cli/src/render.rs",
        "crates/core/src/report.rs",
        "crates/core/src/attest.rs",
    ]
    .iter()
    .map(|rel| {
        let p = root.join(rel);
        let t =
            fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {} ({e})", p.display()));
        (p, t)
    })
    .collect()
}

/// The string literals on a line — a claim reaches output as a literal, and this keeps a
/// word in a doc-comment (which never prints) from tripping the gate.
fn string_literals(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    let bytes = line.as_bytes();
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

/// Whether a line is inside a doc or ordinary comment. Comments never reach output, and the
/// module docs above talk about SBOMs on purpose.
fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

#[test]
fn no_output_path_emits_a_compliance_or_sbom_claim() {
    // Whole tokens and specific phrases, so "conformity" catches a conformity CLAIM but the
    // substring hunt that would flag "ntia" inside "differential" is avoided.
    const FORBIDDEN: [&str; 7] = [
        "sbom",
        "cyclonedx",
        "spdx",
        "conformity",
        "cra compliant",
        "cra-compliant",
        "ntia",
    ];
    let mut findings = Vec::new();
    for (path, text) in output_path_sources() {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for lit in string_literals(line) {
                let low = lit.to_lowercase();
                for term in FORBIDDEN {
                    if low.contains(term) {
                        findings.push(format!(
                            "{}:{}: output literal contains `{}`: {:?}",
                            path.display(),
                            n + 1,
                            term,
                            &lit[..lit.len().min(60)]
                        ));
                    }
                }
            }
        }
    }
    assert!(
        findings.is_empty(),
        "the tool's output must not claim conformity or call its report an SBOM — the report \
         is testing evidence, not CycloneDX/SPDX and not a conformity assessment:\n  {}",
        findings.join("\n  ")
    );
}

#[test]
fn a_serialized_report_and_predicate_carry_no_such_claim() {
    // The runtime half: not only the literals, but the actual JSON a consumer reads. Field
    // names and values together, serialised, must contain none of the terms.
    use buildclamp_core::attest::{EnforcementProfile, Predicate};
    use buildclamp_core::{Mode, Report};

    let report = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
    let predicate = Predicate::from_report(
        &report,
        "libthing.rlib",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        EnforcementProfile::default(),
        "2026-09-16T00:00:00Z",
        "key-1",
    );
    let report_json = serde_json::to_string(&report).unwrap().to_lowercase();
    let predicate_json = serde_json::to_string(&predicate).unwrap().to_lowercase();
    for term in ["sbom", "cyclonedx", "spdx", "conformity", "cra compliant"] {
        assert!(
            !report_json.contains(term),
            "the report JSON contains `{term}`"
        );
        assert!(
            !predicate_json.contains(term),
            "the predicate JSON contains `{term}`"
        );
    }
}
