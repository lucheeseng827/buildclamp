# buildclamp and the NIST SSDF

This maps what buildclamp does to three practices of the NIST Secure Software Development
Framework ([SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)). It exists because
"which SSDF practices does this help with?" is a question in nearly every enterprise
security review, and answering it once, honestly, is cheaper than answering it in prose each
time.

## What this is, and is not

- It is a **mapping**, not a certification. buildclamp is a tool a team uses toward these
  practices; a practice is satisfied by what an organisation does, not by a tool it runs.
- It makes **no compliance claim**. It does not say "CRA compliant", it maps to no clause
  number, and it is not a conformity assessment. No harmonised CRA standard has been cited
  in the Official Journal, so a tool claiming conformity to one would be claiming conformity
  to something that does not yet exist.
- The capability report is **testing evidence**, not a bill of materials. It records, per
  build unit, which capabilities a build script or proc-macro asked for and what happened to
  each. It is not CycloneDX, not SPDX, and carries none of the NTIA minimum SBOM elements —
  use an SBOM tool for an SBOM. `crates/cli/tests/no_compliance_overclaim.rs` is the gate
  that keeps the tool's own output from blurring that line.
- Rows are marked **not-yet** where the capability is real but not yet the default, so the
  table stays honest as the tool changes rather than describing an aspiration.

## The mapping

| SSDF practice | What buildclamp provides | Status |
|---|---|---|
| **PO.5** — Implement and maintain secure environments for software development | Build scripts and (opt-in) proc-macro expansion run under a capability sandbox: network, filesystem writes and Unix sockets are constrained per crate, process execution is recorded (never refused — `exec` is observe-only), and the report names the enforcement **tier** actually achieved on the host (`enforced` / `advisory` / `none`) rather than asserting one. The build environment is the environment SSDF PO.5 is about, and a build script is the part of it that runs third-party code. | **partial** — enforced for build scripts by default; proc-macro holding is opt-in (`hold-compile-units`), and read-withholding is opt-in (`withhold-secret-reads`). The report says which applied. |
| **PW.4** — Verify third-party components (and reuse well-secured software) | A per-crate capability record is exactly what "verify third-party components ... through testing" asks for: it is a test of what each dependency's build-time code actually did, not a declaration of what it claims. Per-build-script attribution is shipped; `exact` per-proc-macro attribution is demonstrated (`docs/adr/0004`). | **partial** — build-time behaviour only; buildclamp does not analyse or verify runtime behaviour of a dependency, and says so. |
| **PS.3** — Archive and protect each software release | Each build can produce a report. A signer outside this tool binds it, the artefact hash and the policy hash into a signed in-toto/DSSE **attestation**, with the enforcement tier and any waivers carried in the predicate. A third party checks the statement against the artefact, policy and report with this binary (`cargo buildclamp verify`) and the signature with `cosign verify-attestation` or `gh attestation verify`; the schema is committed and normative for ten-year retention. | **partial** — the attestation format, verifier and schema are shipped here; signing is an air-gapped capability outside this tool, and no production signing key is issued until the enforcement engine's external audit completes. |

## Reading the status column

**partial** everywhere is deliberate and is the honest state: buildclamp is one control in a
build pipeline, it constrains build-time third-party code specifically, and several of its
strongest settings are opt-in while their cost on real dependency graphs is measured. A row
will move to a plainer word when the thing it describes is the default and the measurement
behind it is published — not before.
