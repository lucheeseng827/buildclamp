//! The committed schema is normative, so it has to agree with the code.
//!
//! `schemas/README.md` says the file in `schemas/v1/`, not the URI, defines the format —
//! because a customer holding ten-year evidence cannot depend on a domain outliving a
//! company. That promise is worth nothing if the schema and the struct drift apart, and
//! they drift silently: adding a field to the Rust type compiles, serialises and ships,
//! and the schema still describes the document the tool stopped producing.
//!
//! So this compares them in **both** directions. A field the code emits and the schema does
//! not describe fails here; a field the schema requires and the code does not emit fails
//! here. It is not a JSON Schema validator — writing or depending on one would be a large
//! surface for a check this narrow — and it does not need to be: the two failures above are
//! the ones that actually happen.

use std::collections::BTreeSet;

use buildclamp_core::attest::{
    EnforcementProfile, Erratum, ErratumMatch, Predicate, Statement, Subject,
    ERRATUM_PREDICATE_TYPE, PREDICATE_TYPE, STATEMENT_TYPE,
};
use buildclamp_core::{Mode, Report};
use serde_json::Value;

fn schema(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/v1")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {} ({e}). It is committed and it is normative — see schemas/README.md.",
            path.display()
        )
    });
    serde_json::from_str(&text).expect("the committed schema is valid JSON")
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object().expect("an object").keys().cloned().collect()
}

fn described(schema: &Value) -> BTreeSet<String> {
    schema["properties"]
        .as_object()
        .expect("the schema has properties")
        .keys()
        .cloned()
        .collect()
}

fn required(schema: &Value) -> BTreeSet<String> {
    schema["required"]
        .as_array()
        .expect("the schema names its required fields")
        .iter()
        .map(|v| v.as_str().expect("a name").to_string())
        .collect()
}

/// A predicate with every optional field populated, so nothing is skipped by
/// `skip_serializing_if` and the comparison sees the whole surface.
fn full_predicate() -> Predicate {
    let mut report = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
    // A break-glass an exception exercised, so `waivers` is populated and the schema is
    // checked to describe it — otherwise the "every optional field" fixture would skip it.
    report
        .break_glass
        .push(buildclamp_core::report::ExceptionUse {
            unit: buildclamp_core::UnitId::new("evilcrate", "1.0.0"),
            expires: "2026-12-31".into(),
            author: "someone@example.com".into(),
            reason: "shipping under a deadline".into(),
            grants: vec![],
            exercised: buildclamp_core::CapabilitySet::of(&[buildclamp_core::Capability::Net]),
            stood_down: vec![],
        });
    // Both policy-signature fields set, so the emitted document carries `policy_signer_key_id`
    // rather than skipping it via `skip_serializing_if`. An optional field the comparison never
    // sees is one the committed schema can drift away from without this gate noticing.
    report.run.policy_signature_verified = true;
    report.run.policy_signer_key_id = Some("bc-2026-k1".into());
    Predicate::from_report(
        &report,
        "libthing.rlib",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
        EnforcementProfile {
            read_deny: true,
            read_deny_ruleset_sha256: Some("d".repeat(64)),
            compile_units_held: true,
            net_destinations_recorded_only: true,
            landlock_abi_used: Some(7),
            disable_overrides: vec!["BUILDCLAMP_DISABLE=ns".into()],
        },
        "2026-09-15T10:00:00Z",
        "key-1",
    )
}

#[test]
fn every_field_the_predicate_emits_is_described_by_the_committed_schema() {
    let s = schema("attestation.schema.json");
    let emitted = keys(&serde_json::to_value(full_predicate()).unwrap());
    let known = described(&s);
    let undescribed: Vec<&String> = emitted.difference(&known).collect();
    assert!(
        undescribed.is_empty(),
        "the predicate emits fields the normative schema does not describe: {undescribed:?}\n\n\
         schemas/v1/attestation.schema.json is what a ten-year-old document is read \n\
         against. Add them there in the same commit, with the sentence that says why the \n\
         field exists — that sentence is the reason the schema is worth committing."
    );
}

#[test]
fn every_field_the_schema_requires_is_one_the_predicate_emits() {
    let s = schema("attestation.schema.json");
    let emitted = keys(&serde_json::to_value(full_predicate()).unwrap());
    let needed = required(&s);
    let missing: Vec<&String> = needed.difference(&emitted).collect();
    assert!(
        missing.is_empty(),
        "the normative schema requires fields the predicate does not emit: {missing:?}\n\n\
         Every document this tool produces would be invalid against its own schema."
    );
}

#[test]
fn the_nested_objects_agree_too() {
    // `enforcement_profile` and `scope` are where the new surface is, and a top-level
    // comparison would not look inside either.
    let s = schema("attestation.schema.json");
    let doc = serde_json::to_value(full_predicate()).unwrap();

    for (field, def) in [
        ("enforcement_profile", "enforcementProfile"),
        ("scope", "scope"),
    ] {
        let sub = &s["$defs"][def];
        let emitted = keys(&doc[field]);
        let known = described(sub);
        let undescribed: Vec<&String> = emitted.difference(&known).collect();
        assert!(
            undescribed.is_empty(),
            "{field} emits fields $defs/{def} does not describe: {undescribed:?}"
        );
        let needed = required(sub);
        let missing: Vec<&String> = needed.difference(&emitted).collect();
        assert!(
            missing.is_empty(),
            "$defs/{def} requires fields {field} does not emit: {missing:?}"
        );
    }
}

#[test]
fn the_erratum_and_its_schema_agree() {
    let s = schema("erratum.schema.json");
    let e = Erratum {
        format_version: 1,
        id: "BCE-0001".into(),
        matches: ErratumMatch {
            key_id: Some("key-1".into()),
            built_at_from: Some("2026-09-01T00:00:00Z".into()),
            built_at_before: Some("2026-10-01T00:00:00Z".into()),
            artefact_sha256: Some("a".repeat(64)),
        },
        capability: Some("net".into()),
        corrected_tier: "advisory:seccomp-notify".into(),
        finding: "the filter did not refuse what it reported refusing".into(),
        published: "2026-10-01T00:00:00Z".into(),
    };
    let doc = serde_json::to_value(&e).unwrap();
    let emitted = keys(&doc);
    let known = described(&s);
    let undescribed: Vec<&String> = emitted.difference(&known).collect();
    assert!(
        undescribed.is_empty(),
        "the erratum emits fields the schema does not describe: {undescribed:?}"
    );
    let needed = required(&s);
    let missing: Vec<&String> = needed.difference(&emitted).collect();
    assert!(
        missing.is_empty(),
        "the schema requires fields the erratum does not emit: {missing:?}"
    );
    let nested = keys(&doc["matches"]);
    let nested_known = described(&s["$defs"]["matches"]);
    let nested_undescribed: Vec<&String> = nested.difference(&nested_known).collect();
    assert!(
        nested_undescribed.is_empty(),
        "matches emits fields $defs/matches does not describe: {nested_undescribed:?}"
    );
}

#[test]
fn the_schema_ids_are_the_predicate_types_the_code_emits() {
    // The URI is an identifier rather than a location, and the one thing that must be true
    // of an identifier is that both places spell it the same way. A schema whose `$id` did
    // not match the `predicateType` would describe a format nothing produces.
    assert_eq!(schema("attestation.schema.json")["$id"], PREDICATE_TYPE);
    assert_eq!(schema("erratum.schema.json")["$id"], ERRATUM_PREDICATE_TYPE);
}

#[test]
fn a_statement_is_shaped_the_way_in_toto_and_the_policy_engines_expect() {
    // Not our format: `_type`, `subject`, `predicateType` and `predicate` are in-toto's
    // spelling, and cosign, gh, Kyverno and policy-controller all read them directly. A
    // rename here is not a refactor, it is a document nothing consumes.
    let p = full_predicate();
    let s = Statement {
        type_: STATEMENT_TYPE.into(),
        subject: vec![Subject {
            name: p.artefact_name.clone(),
            digest: std::collections::BTreeMap::from([(
                "sha256".to_string(),
                p.artefact_sha256.clone(),
            )]),
        }],
        predicate_type: PREDICATE_TYPE.into(),
        predicate: p.clone(),
    };
    let v = serde_json::to_value(&s).unwrap();
    assert_eq!(
        keys(&v),
        BTreeSet::from_iter([
            "_type".to_string(),
            "predicateType".to_string(),
            "predicate".to_string(),
            "subject".to_string(),
        ])
    );
    assert_eq!(v["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(v["subject"][0]["digest"]["sha256"], p.artefact_sha256);
    assert_eq!(
        keys(&v["subject"][0]),
        BTreeSet::from_iter(["digest".to_string(), "name".to_string(),])
    );
}
