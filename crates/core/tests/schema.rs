//! The report is a wire format, and this file is the contract.
//!
//! Everything here is an *integration* test rather than a unit test, deliberately: it
//! reaches the schema the way a consumer does, through the crate's public surface, so a
//! change that keeps the internals consistent but breaks a reader still fails.
//!
//! # Why a pinned corpus rather than a round-trip
//!
//! A round-trip test — serialise a `Report`, read it back, compare — passes forever no
//! matter how the schema changes, because both halves change together. It proves the code
//! agrees with itself. What a consumer needs is that *this* build still reads a document
//! *an older build wrote*, and the only way to test that is to keep a document an older
//! build wrote.
//!
//! `golden/report-v1.json` is a real report, produced by `cargo buildclamp observe` over
//! `tests/fixtures/benign` on Linux 6.18, with the scratch directory rewritten to `/w` and
//! the kernel string pinned so the file does not change per machine. Nothing else was
//! touched. **When this test fails, the schema changed in a way that breaks every reader
//! in the field, and the fix is a version bump plus a new corpus entry — not an edit to
//! this file.**

use buildclamp_core::{Capability, Mode, Report, ReportError, Tier, REPORT_FORMAT_VERSION};

const GOLDEN_V1: &str = include_str!("golden/report-v1.json");

/// The version 2 corpus: a real `cargo buildclamp observe` over `tests/fixtures/benign`,
/// run inside a git checkout with an `origin` remote so the run header is populated rather
/// than null. Normalised the same way v1 was — the scratch directory rewritten to `/w`,
/// the kernel string pinned — plus the four fields that are a fresh value on every run:
/// the run id, the two timestamps and the commit. The fixture writes a temporary file
/// named after its own pid, and that pid is pinned too; see `Report::diff_view`, which
/// explains why that one is the build script's business and not the schema's.
const GOLDEN_V2: &str = include_str!("golden/report-v2.json");

#[test]
fn the_pinned_v1_report_still_parses() {
    // What "parses" means changed with version 2 and is worth stating: the document is
    // migrated on the way in, so a v1 file read by this build yields a v2 report. That is
    // the promise `REPORT_FORMAT_VERSION` makes — a reader that understands version N
    // understands everything version N was built to read — and it is stronger than
    // "deserialises", which a `tiers` array would no longer do.
    let r = Report::from_json(GOLDEN_V1).expect("the v1 corpus must parse forever");
    assert_eq!(r.format_version, REPORT_FORMAT_VERSION);
    assert_eq!(r.mode, Mode::Observe);
    assert_eq!(r.units.len(), 1);
    assert_eq!(r.units[0].id.name, "benign");
}

#[test]
fn the_pinned_v2_report_still_parses_and_carries_its_run_header() {
    let r = Report::from_json(GOLDEN_V2).expect("the v2 corpus must parse forever");
    assert_eq!(r.format_version, 2);
    assert_eq!(r.run.ecosystem, "cargo");
    assert_eq!(
        r.run.target.as_deref(),
        Some("x86_64-unknown-linux-gnu"),
        "the triple, not the architecture: `x86_64` alone merges -gnu and -musl into one          drift bucket, which is the confusion this field was added to end"
    );
    let repo = r
        .run
        .repo
        .as_ref()
        .expect("the corpus was produced in a checkout");
    assert_eq!(repo.reference.as_deref(), Some("refs/heads/main"));
    assert_eq!(repo.commit.as_deref().map(str::len), Some(40));
}

#[test]
fn migrating_a_v1_document_changes_its_shape_and_not_its_content() {
    // The migration's whole job. If it ever starts inventing a value — a target triple
    // guessed from `host.arch` was the tempting one — this is where that shows up.
    let v1 = Report::from_json(GOLDEN_V1).unwrap();
    assert_eq!(
        v1.run.run_uuid, "",
        "a v1 document has no run id to migrate"
    );
    assert!(v1.run.started_at.is_none());
    assert!(v1.run.repo.is_none());
    assert!(
        v1.run.target.is_none(),
        "null, not `host.arch`: a migration that guessed the triple would write a fact          nobody measured into a field consumers bucket on"
    );

    let u = &v1.units[0];
    assert_eq!(u.requests.len(), 8, "every request survived the migration");
    assert_eq!(u.tiers.len(), 5, "every tier survived, one per capability");
}

#[test]
fn two_runs_of_the_same_build_diff_to_nothing_once_the_run_header_is_stripped() {
    // The property that makes a report diffable, and therefore drift detectable. It is
    // asserted through `diff_view` rather than by comparing the raw `units`, because
    // `duration_ms`, `at_ms` and `tid` legitimately differ between two runs and pretending
    // otherwise would be a test that had to be weakened the first time it was believed.
    let a = Report::from_json(GOLDEN_V2).unwrap();
    let mut b = Report::from_json(GOLDEN_V2).unwrap();

    b.run.run_uuid = "ffffffff-ffff-4fff-bfff-ffffffffffff".into();
    b.run.started_at = Some("2027-01-01T00:00:00Z".into());
    b.run.finished_at = Some("2027-01-01T00:00:09Z".into());
    b.run.ci_correlation = Some("a different job".into());
    b.units[0].duration_ms += 41;
    b.units[0].requests[0].at_ms += 7;
    b.units[0].requests[0].tid += 1;

    assert_eq!(
        a.diff_view(),
        b.diff_view(),
        "two runs of the same build must compare equal once the run header and the          timings are stripped, or every diff is noise and no drift is visible in it"
    );
    assert_ne!(
        serde_json::to_value(&a.units).unwrap(),
        serde_json::to_value(&b.units).unwrap(),
        "the raw units DO differ — which is why `diff_view` exists rather than a          comparison of the units themselves"
    );
}

#[test]
fn a_capability_this_build_has_never_heard_of_does_not_take_the_run_down_with_it() {
    // Measured before it was fixed: `"fs-read"` anywhere in a report failed the whole
    // document with serde's `unknown variant`, so one unimplemented capability made eight
    // units, their request streams and their tiers unreadable. A report that fails to load
    // sends a person looking for a bug in the tool; a report short by one field reads
    // exactly like a clean one. Neither is acceptable, so the name is kept and said aloud.
    // `fs-read` was this test's example until it shipped as a real capability. The name
    // has to be one this build genuinely does not know, or the test asserts nothing.
    let newer = GOLDEN_V2.replacen("\"net\": {", "\"fs-append\": {", 1);
    assert_ne!(newer, GOLDEN_V2, "the substitution must actually apply");

    let r = Report::from_json(&newer).expect("an unknown capability must not drop the run");
    assert_eq!(r.units[0].requests.len(), 8, "the request stream survived");
    assert_eq!(
        r.units[0].tiers.len(),
        5,
        "the tier survived under its own name"
    );
    assert!(
        r.unknown_names().iter().any(|n| n.contains("fs-append")),
        "the unknown must be REPORTED, not merely tolerated: a consumer aggregating this          run is reading less than was recorded, and silence there under-reports. Got {:?}",
        r.unknown_names()
    );

    // And it round-trips verbatim rather than being rewritten as something this build
    // does understand, which would corrupt the document in the course of reading it.
    let out = serde_json::to_string(&r).unwrap();
    assert!(out.contains("fs-append"), "{out}");
}

#[test]
fn a_tier_grade_this_build_cannot_evaluate_is_never_treated_as_enforcement() {
    // The direction matters more than the tolerance. A reader that met an unfamiliar grade
    // and shrugged would let `--require-enforced` pass on a run whose enforcement it could
    // not evaluate — a control reporting success while enforcing nothing, which is the
    // exact failure this project names in its competitor.
    let newer = GOLDEN_V2.replacen("\"grade\": \"none\"", "\"grade\": \"partial\"", 1);
    assert_ne!(newer, GOLDEN_V2);
    let r = Report::from_json(&newer).expect("an unknown grade must not drop the run");

    let unrecognised: Vec<&Tier> = r.units[0]
        .tiers
        .values()
        .filter(|t| matches!(t, Tier::Unrecognised { .. }))
        .collect();
    assert_eq!(unrecognised.len(), 1, "{:?}", r.units[0].tiers);
    assert!(!unrecognised[0].is_enforced());
    assert!(unrecognised[0].is_unenforced());
    assert_eq!(unrecognised[0].label(), "unrecognised:partial");
    assert!(r.unknown_names().iter().any(|n| n.contains("partial")));
}

#[test]
fn the_run_header_carries_exactly_these_fields_and_no_identity() {
    // The same discipline as `scrubbed_environment_names_are_recorded_without_their_values`
    // one level up, and as drift's `the_envelope_has_nowhere_to_put_a_path_or_a_secret`.
    // This object is new, it is the first thing in the report that describes the *machine*
    // rather than the build, and adding a field to it must be a deliberate act somebody
    // justifies in review rather than a line that slips in.
    let v: serde_json::Value = serde_json::from_str(GOLDEN_V2).unwrap();
    let mut keys: Vec<&str> = v["run"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "agent_id",
            "ci_correlation",
            "ecosystem",
            "finished_at",
            "repo",
            "run_uuid",
            "started_at",
            "target",
        ]
    );

    // No identity anywhere in the document: not a tenant, not an actor, not a user. The
    // report is mailed from a CI runner to a reviewer, and whose build it was is not a
    // fact it needs to carry.
    let whole = GOLDEN_V2.to_lowercase();
    for forbidden in ["\"tenant\"", "\"actor\"", "\"user\"", "\"username\""] {
        assert!(!whole.contains(forbidden), "the report names {forbidden}");
    }
}

#[test]
fn a_remote_url_never_carries_the_credential_that_was_in_it() {
    // CI configures `https://x-access-token:<token>@github.com/org/repo` routinely, and a
    // report is a file written to disk and mailed to reviewers. Copying the URL verbatim
    // would write a live credential in the course of protecting one — the same failure
    // `env_scrubbed` exists to prevent one field up.
    use buildclamp_core::RepoRef;
    let r = RepoRef::record(
        Some("https://someone:ghp_notarealtoken@github.invalid/org/repo.git".into()),
        None,
        None,
    );
    let remote = r.remote.unwrap();
    assert_eq!(remote, "https://github.invalid/org/repo.git");
    assert!(!remote.contains("ghp_"), "{remote}");
    assert!(!remote.contains('@'), "{remote}");

    // An `@` inside the password cannot smuggle the rest of it through.
    let r = RepoRef::record(
        Some("https://u:p@ss@github.invalid/org/repo.git".into()),
        None,
        None,
    );
    assert_eq!(r.remote.unwrap(), "https://github.invalid/org/repo.git");

    // A remote with no userinfo is left exactly as it is.
    let r = RepoRef::record(Some("git@github.invalid:org/repo.git".into()), None, None);
    assert_eq!(r.remote.unwrap(), "github.invalid:org/repo.git");
}

#[test]
fn the_violation_stream_survives_the_round_trip() {
    // This is the differentiator that is actually shipped: a per-request record with syscall, target, capability and outcome, where
    // the nearest tool emits a permission summary. `exec` in particular is something it
    // has no path for at all. A schema change that flattened these into a summary would
    // still parse, still look like a report, and quietly destroy the substrate the
    // attestation predicate and the drift feed are both built on — so it is pinned.
    let r = Report::from_json(GOLDEN_V1).unwrap();
    let u = &r.units[0];

    assert_eq!(
        u.requests.len(),
        8,
        "the stream is per-request, not per-capability"
    );

    let execs: Vec<_> = u
        .requests
        .iter()
        .filter(|q| q.capability.copied() == Some(Capability::Exec))
        .collect();
    assert_eq!(
        execs.len(),
        1,
        "the exec record is the part no competitor has"
    );
    assert_eq!(execs[0].syscall, "execve");
    assert_eq!(execs[0].target, "/usr/bin/cc");

    // Every capability carries a tier, including `unix`, which is granted by default and
    // is the one most likely to be dropped by accident.
    for cap in [
        Capability::Net,
        Capability::Unix,
        Capability::FsWrite,
        Capability::EnvSecret,
        Capability::Exec,
    ] {
        assert!(
            u.tiers.contains_key(&cap.into()),
            "{cap:?} has no tier: a capability without one is an outcome recorded without \
             saying how it was constrained, which is the one thing this schema exists to \
             make impossible"
        );
    }
}

#[test]
fn a_report_from_a_newer_buildclamp_is_refused_by_version_and_named() {
    // The defect this test exists for: `REPORT_FORMAT_VERSION` has always carried the
    // sentence "a consumer that finds a higher number must say so rather than parse what
    // it recognises", and until `Report::from_json` no consumer did. A report claiming
    // format version 9 deserialised cleanly in all five readers.
    let future = GOLDEN_V1.replacen("\"format_version\": 1", "\"format_version\": 9", 1);
    assert_ne!(future, GOLDEN_V1, "the substitution must actually apply");

    match Report::from_json(&future) {
        Err(ReportError::Future { found }) => assert_eq!(found, 9),
        Err(e) => panic!("refused, but not on the version: {e}"),
        Ok(_) => panic!(
            "a report from a newer buildclamp parsed. Serde fills absent fields from \
             defaults, so a run whose requests this version cannot represent now arrives \
             looking like a run that made none."
        ),
    }
}

#[test]
fn the_refusal_says_which_version_it_understands() {
    // The message is the product here: whoever hits this is holding two binaries and
    // needs to know which one to upgrade.
    let next = REPORT_FORMAT_VERSION + 1;
    let future = GOLDEN_V1.replacen(
        "\"format_version\": 1",
        &format!("\"format_version\": {next}"),
        1,
    );
    let msg = Report::from_json(&future).unwrap_err().to_string();
    assert!(msg.contains(&next.to_string()), "{msg}");
    assert!(msg.contains(&REPORT_FORMAT_VERSION.to_string()), "{msg}");
    assert!(msg.contains("Upgrade the reader"), "{msg}");
}

#[test]
fn the_current_version_is_accepted_and_so_is_an_older_one() {
    // Only the future is refused. A reader that understands version N understands
    // everything version N was built to read, so gating both directions would make every
    // schema bump a flag day across a fleet for no safety gained.
    let current = GOLDEN_V1.replacen(
        "\"format_version\": 1",
        &format!("\"format_version\": {REPORT_FORMAT_VERSION}"),
        1,
    );
    assert!(Report::from_json(&current).is_ok());

    let older = GOLDEN_V1.replacen("\"format_version\": 1", "\"format_version\": 0", 1);
    assert!(
        Report::from_json(&older).is_ok(),
        "an older report must still read"
    );
}

/// The version 1 policy corpus. See the header comment in the file itself for why it is
/// hand-written rather than generated.
const GOLDEN_POLICY_V1: &str = include_str!("golden/policy-v1.toml");

#[test]
fn the_pinned_v1_policy_still_parses_and_resolves_the_way_it_did() {
    // A policy is the artefact with the longest life in this system: a report is
    // regenerated every build, and `buildclamp.toml` is committed and then edited twice a
    // year. Breaking it breaks every repository at once, silently at first, because the
    // failure appears on the next build rather than on the change that caused it.
    use buildclamp_core::{Policy, UnitId, UnitKind};

    let p = Policy::parse(GOLDEN_POLICY_V1).expect("the v1 policy corpus must parse forever");

    // The corpus still SAYS version 1 on disk, and the parse upgraded it in memory. Both
    // halves matter: a version bump that rewrote files would be a tool editing something
    // somebody is about to read in a diff, and one that refused them would be a migration
    // nobody performs.
    assert_eq!(Policy::declared_version(GOLDEN_POLICY_V1), Some(1));
    assert_eq!(p.version, buildclamp_core::POLICY_VERSION);

    // A policy written before `min_tool_version` existed has no floor, and absent must
    // mean "no floor" rather than "floor of 0" or an error.
    assert!(p.min_tool_version.is_none());

    // `Grants::Many` — two versions of one crate under one key — resolves to the grant
    // for the version in hand and not to whichever came first in the file.
    let one = p
        .resolve(
            &UnitId::new("vendored-thing", "1.4.0"),
            UnitKind::BuildScriptCompile,
            false,
        )
        .unwrap();
    let two = p
        .resolve(
            &UnitId::new("vendored-thing", "2.1.0"),
            UnitKind::BuildScriptCompile,
            false,
        )
        .unwrap();
    assert!(
        one.permits(Capability::Net),
        "1.x fetches and the grant says so"
    );
    assert!(
        !two.permits(Capability::Net),
        "2.x vendors, and must not inherit 1.x's net"
    );

    // The loud opt-in still re-admits a hard-denied name, and only where it was asked for.
    let signer = p
        .resolve(
            &UnitId::new("secret-reader", "0.1.0"),
            UnitKind::BuildScriptCompile,
            false,
        )
        .unwrap();
    assert!(signer.env_allow_secrets);
    assert!(signer
        .env_allow
        .iter()
        .any(|n| n == "AWS_SECRET_ACCESS_KEY"));

    // An explicit write path outside any zone survives.
    let ring = p
        .resolve(
            &UnitId::new("ring", "0.17.8"),
            UnitKind::BuildScriptCompile,
            false,
        )
        .unwrap();
    assert_eq!(ring.write_paths, vec!["/opt/toolchain/scratch".to_string()]);
}

#[test]
fn a_malformed_report_is_an_error_rather_than_a_panic() {
    assert!(matches!(
        Report::from_json("{not json"),
        Err(ReportError::Json(_))
    ));
}

#[test]
fn a_report_with_no_version_field_is_not_silently_treated_as_current() {
    // A document with no `format_version` cannot have been written by any buildclamp, so
    // it is malformed rather than ancient: `Report` requires the field, and serde says so.
    let stripped = GOLDEN_V1.replacen("\"format_version\": 1,", "", 1);
    assert!(matches!(
        Report::from_json(&stripped),
        Err(ReportError::Json(_))
    ));
}

#[test]
fn an_additive_field_does_not_make_an_older_report_unreadable() {
    // The regression this test exists for, caught by the corpus above on its first real
    // outing. `Envelope::env_allow_secrets` was added to fix `env-allow-secrets = true`,
    // which had never worked. It arrived as a required field with no serde default and no
    // change to `format_version`, so every report written before it — all of them —
    // stopped parsing with `missing field env_allow_secrets` while still declaring
    // version 1. The reader was told to look at a field when the real answer was that the
    // schema had moved underneath it.
    //
    // The rule this pins: an ADDITIVE field takes `#[serde(default)]` and does not bump
    // the version, because old documents stay readable and their absent value is
    // meaningful — nothing could have opted in before the opt-in existed. A field that
    // CANNOT be defaulted is a breaking change and takes a version bump instead, which
    // the gate above then refuses by name rather than by field.
    let r = Report::from_json(GOLDEN_V1).expect("a v1 report predates env_allow_secrets");
    assert!(
        !r.units[0].envelope.env_allow_secrets,
        "a report from before the opt-in existed must read as not opted in"
    );
}
