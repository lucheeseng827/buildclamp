//! The negative vectors, run against this project's own verifier.
//!
//! The file they live in is published — `schemas/v1/negative/` — so that a customer can run
//! it against *their* verification path rather than trusting ours. This is the half that
//! keeps ours honest.
//!
//! # Why each vector carries a reason
//!
//! **A verifier that rejects everything passes a naive negative suite.** So each vector
//! names the class of rejection it must produce, and a verifier that refuses the right
//! documents for the wrong reasons fails here as surely as one that accepts them. The
//! positive control in the same directory is the other half of that: a suite with no
//! acceptance in it cannot tell a correct verifier from a broken one.

use std::collections::BTreeSet;

use buildclamp_core::attest::{verify_statement, VerifyError};
use buildclamp_core::Date;

/// A day comfortably before the v1 sunset, so these vectors exercise the checks they are
/// about rather than the version cutover.
fn now() -> Date {
    Date::parse("2026-09-16").unwrap()
}
use serde_json::Value;

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/v1/negative")
}

fn vectors() -> Value {
    let path = dir().join("vectors.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {} ({e}). It is committed and it is published: customers are told \
             to run it against their own verifier.",
            path.display()
        )
    });
    serde_json::from_str(&text).expect("vectors.json is valid JSON")
}

/// The class of rejection, as `vectors.json` spells it.
fn class(e: &VerifyError) -> &'static str {
    match e {
        VerifyError::NotAnEnvelope(_) => "NotAnEnvelope",
        VerifyError::WrongPayloadType { .. } => "WrongPayloadType",
        VerifyError::BadPayload(_) => "BadPayload",
        VerifyError::BadJson(_) => "BadJson",
        VerifyError::WrongStatementType { .. } => "WrongStatementType",
        VerifyError::WrongPredicateType { .. } => "WrongPredicateType",
        VerifyError::NoSubject => "NoSubject",
        VerifyError::WrongArtefact { .. } => "WrongArtefact",
        VerifyError::InconsistentDigest { .. } => "InconsistentDigest",
        VerifyError::WrongPolicy { .. } => "WrongPolicy",
        VerifyError::WrongReport { .. } => "WrongReport",
        VerifyError::UnknownVersion { .. } => "UnknownVersion",
        VerifyError::VersionSunset { .. } => "VersionSunset",
    }
}

#[test]
fn every_vector_is_rejected_for_the_reason_it_names() {
    let v = vectors();
    let entries = v["vectors"].as_array().expect("vectors is an array");
    assert!(
        entries.len() >= 15,
        "only {} vectors; the published file is smaller than the suite it is meant to be",
        entries.len()
    );

    let mut accepted = 0usize;
    for entry in entries {
        let name = entry["file"].as_str().expect("a file name");
        let expect = entry["expect"].as_str().expect("an expectation");
        let why = entry["why"].as_str().unwrap_or("");
        assert!(
            !why.is_empty(),
            "{name} has no `why`. A vector nobody can explain is one nobody maintains."
        );

        let path = dir().join(name);
        let document = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

        // `given` names the digests this vector should be verified against. A policy or
        // report hash appears once in a statement, so nothing internal contradicts it and
        // the rejection needs the file it should have matched — which is a fact a customer
        // running the published file needs too, so it is in the file rather than here.
        let given = &entry["given"];
        let digest = |k: &str| given.get(k).and_then(Value::as_str).map(str::to_string);
        let (artefact, policy, report) = (
            digest("artefact_sha256"),
            digest("policy_sha256"),
            digest("report_sha256"),
        );

        match verify_statement(
            &document,
            artefact.as_deref(),
            policy.as_deref(),
            report.as_deref(),
            &[],
            now(),
        ) {
            Err(e) => {
                assert_eq!(
                    class(&e),
                    expect,
                    "{name} was rejected as {} and the published file says {expect}.\n  \
                     A verifier that refuses the right documents for the wrong reasons is \n  \
                     one nobody can debug against.\n  message: {e}",
                    class(&e)
                );
            }
            Ok(verified) => {
                // Two vectors verify and must still not be reported as fully enforced.
                // That distinction is the whole reason `enforcement_profile` exists.
                match expect {
                    "accept" => {
                        assert!(
                            verified.is_fully_enforced(),
                            "{name} is the positive control and must describe a fully \
                             enforced run"
                        );
                        accepted += 1;
                    }
                    "not-fully-enforced" => assert!(
                        !verified.is_fully_enforced(),
                        "{name} verified AND reported a fully enforced run. {why}"
                    ),
                    other => panic!(
                        "{name} was accepted, and the published file says it should be \
                         rejected as {other}"
                    ),
                }
            }
        }
    }
    assert!(
        accepted > 0,
        "no vector was accepted. A negative suite with no positive control cannot tell a \
         correct verifier from one that rejects everything — which is the sentence the \
         published README leads with."
    );
}

#[test]
fn every_file_in_the_directory_is_in_the_index() {
    // A vector added to the directory and not to `vectors.json` is one the suite never
    // runs, and it is published, so somebody else's suite never runs it either.
    let listed: BTreeSet<String> = vectors()["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["file"].as_str().unwrap().to_string())
        .collect();
    let present: BTreeSet<String> = std::fs::read_dir(dir())
        .expect("the vector directory is committed")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json") && n != "vectors.json")
        .collect();
    assert_eq!(
        listed, present,
        "the published index and the directory disagree. A vector in one and not the other \
         is a check nobody runs."
    );
}

#[test]
fn the_positive_control_fails_once_a_digest_is_checked_against_the_wrong_file() {
    // The control verifies with no file arguments; the point of the artefact, policy and
    // report flags is that they can turn a valid statement into a rejection, and a suite
    // that never passed one would not be testing them.
    let document = std::fs::read_to_string(dir().join("VALID-control.json")).unwrap();
    let right = "a".repeat(64);
    let wrong = "9".repeat(64);

    assert!(verify_statement(&document, Some(&right), None, None, &[], now()).is_ok());
    assert!(matches!(
        verify_statement(&document, Some(&wrong), None, None, &[], now()),
        Err(VerifyError::WrongArtefact { .. })
    ));
    assert!(matches!(
        verify_statement(&document, None, Some(&wrong), None, &[], now()),
        Err(VerifyError::WrongPolicy { .. })
    ));
    assert!(matches!(
        verify_statement(&document, None, None, Some(&wrong), &[], now()),
        Err(VerifyError::WrongReport { .. })
    ));
}

#[test]
fn an_erratum_downgrades_the_control() {
    // The milestone's erratum test: a signed statement cannot be unsigned, so a tier this
    // project later finds to be overstated is corrected by a document of its own — and the
    // correction has to change the answer, not merely be printed.
    let document = std::fs::read_to_string(dir().join("VALID-control.json")).unwrap();
    let clean =
        verify_statement(&document, None, None, None, &[], now()).expect("the control verifies");
    assert!(clean.is_fully_enforced());

    let erratum: buildclamp_core::Erratum = serde_json::from_str(
        r#"{
            "format_version": 1,
            "id": "BCE-0001",
            "matches": { "key_id": "key-1" },
            "capability": "net",
            "corrected_tier": "advisory:seccomp-notify",
            "finding": "the filter did not refuse what it reported refusing",
            "published": "2026-10-01T00:00:00Z"
        }"#,
    )
    .expect("the erratum parses");

    let corrected = verify_statement(
        &document,
        None,
        None,
        None,
        std::slice::from_ref(&erratum),
        now(),
    )
    .expect("an erratum does not make the document unreadable");
    assert_eq!(corrected.errata.len(), 1);
    assert!(
        !corrected.is_fully_enforced(),
        "an erratum must downgrade the answer, not merely be reported alongside it"
    );

    // And one naming a different signer leaves it alone: an erratum that corrected
    // everything would be a way to invalidate every attestation a customer holds.
    let mut other = erratum;
    other.matches.key_id = Some("key-2".into());
    let untouched = verify_statement(&document, None, None, None, &[other], now()).unwrap();
    assert!(untouched.errata.is_empty());
    assert!(untouched.is_fully_enforced());
}
