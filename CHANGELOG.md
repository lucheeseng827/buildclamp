# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Two numbers appear beside every measurement here: the **host** it was measured on and the
**enforcement tier** that applied. A cost or a refusal is only comparable against another
figure from the same two, because a build script denied the network by an empty namespace
and one denied it by a seccomp errno are being stopped by different machinery at different
prices. When `cargo buildclamp doctor` reports a different tier on your host, the numbers
below describe something else.

## [Unreleased]

### Fixed

- **Cargo 1.100's build directory layout: build scripts were silently not held.** Cargo
  1.100 gives each unit its own directory (`<profile>/build/<pkg>/<hash>/out/`), passes no
  `-C extra-filename` to a build-script compile, and executes `out/build_script_build`
  directly, with no `build-script-build` link. 0.1.0 read the missing suffix as a command
  line it did not understand and passed the compile through, so no build script was held,
  and the sweep looked one directory too shallow to catch them. The build succeeded and
  the report listed no held units, with nothing saying why. The path is now
  `<out-dir>/<crate-name>` when there is no suffix, and the sweep and unhook walk both
  layouts. A held compile is granted the profile directory, not the out-dir's parent,
  which in the new layout is the unit's own directory and denied rustc its
  `incremental/` directory. Measured on cargo 1.100.0 and 1.99.1 (the full suite with user
  namespaces, landlock ABI v8, seccomp notification).

## [0.1.0] - 2026-11-15

### Added

- **A byte-identical report round-trip guarantee** — the foundation any store of
  these reports would rest on, shipped in this tool and testable now with no server: the
    report the tool writes serialises byte-identically across a round trip (using the exact
    `to_vec_pretty` the writer calls), so a store that keeps the blob verbatim and an auditor
    who re-derives it agree. It holds only because serialisation is deterministic, and the
    test fails if a field quietly becomes a `HashMap`. Test:
    `a_report_serialises_byte_identically_so_the_stored_blob_is_the_produced_blob`.

- **SSDF mapping and a no-overclaim gate (Y2 Q3, the CRA milestone's non-speculative half).**
  The CRA Annex VII evidence bundle stays unbuilt — it is defined by what
  a named compliance owner will accept, so building it speculatively would be evidence in the
  wrong shape. What ships now is the honest half that needs no such owner. `docs/SSDF.md`
  maps buildclamp to NIST SSDF practices PO.5 (secure build environment), PW.4 (verify
  third-party components through testing), and PS.3 (archive and protect each release), every
  row marked `partial` because that is the true state, and the doc says plainly it is a
  mapping and not a certification: no "CRA compliant", no clause numbers, and the capability
  report is testing evidence, not an SBOM.

  A gate keeps the tool's own OUTPUT from blurring that line: `no_compliance_overclaim.rs`
  scans the output paths (render, report, attestation) and a serialized report and predicate
  for `SBOM`, `CycloneDX`, `SPDX`, `conformity` and `CRA compliant`, and fails if any reaches
  output. It deliberately does not scan the prose docs — `docs/SSDF.md` discusses those words
  to say what buildclamp is not, and banning them there would ban the honesty. The line is
  output, not discussion. Verified the gate bites by injecting an SBOM claim into the render
  path and watching it fail.

- **Waivers in the signed statement, and a dated v1/v2 verifier migration (Y2 Q3).** The
  attestation predicate gains a `waivers` field: the break-glass exceptions a build actually
  exercised, carried so an auditor reading "the build passed" learns it passed with a human
  override on it. `is_fully_enforced()` now returns false whenever there is a waiver — every
  tier can read `enforced:` and be true while an exception let one unit past the policy, and
  that is exactly the fact a waiver records. An exception nobody exercised is not a waiver and
  does not taint a clean build.

  This bumps the predicate format to version 2, done now while the count of issued statements
  is near zero, and ships the verifier-migration story with it: the verifier accepts versions
  1 and 2, refuses a version from the future rather than reading the parts it recognises (the
  permissive direction, wrong for a signature), and refuses a version-1 statement after a
  stated sunset (2028-01-01) with an error that names the date — a v1 statement was valid when
  written, and a format nobody re-issues is a format nobody audits. `verify_statement` takes
  `today` as an argument, so the cutover is testable at any date and the pure core keeps its
  no-clock property. The committed v1 attestation schema describes both versions and the
  `waivers` shape. Tests: the `attest` version-migration and waiver cases, and the schema
  agreement test with a waiver populated.

  NOT in scope, stated so: this is the format and the verifier, not a signer.

- **Signed policy layers with a customer-owned trust root (Y2 Q3).** `policy_sha256` proves a
  distributed policy layer is byte-identical to what was recorded; it cannot prove the layer
  came from someone allowed to write it, because a curl'd bundle hashes the same as a
  committed one. This adds the authority half. A repository's committed `buildclamp.toml`
  declares `[defaults] trust-root = [<base64 Ed25519 keys>]` (under CODEOWNERS, so changing it
  is reviewed); a distributed layer it pulls in through `extends` carries a detached
  `<layer>.sig`; and `--require-signed-policy` refuses, before cargo starts, any distributed
  layer no trusted key verifies. The committed anchor is never itself signature-checked — its
  authority is that it is committed — so this verifies the layers beneath it. The report and
  attestation carry `policy_signature_verified` and the `policy_signer_key_id` that verified,
  alongside `policy_sha256`; the attestation schema (`schemas/v1`) describes both.

  Two properties hold by construction and each has a test that fails if it stops. **No vendor
  key**: the trust root is always the customer's, and `cargo-buildclamp` compiles in none, so
  a vendor's key rotation or lapse can never be a customer's build outage
  (`no_ed25519_key_is_hardcoded_in_the_free_binary`). **No live fetch**: verification reads
  bytes already on disk and makes no network request, so a build's outcome never depends on a
  remote response (`the_verification_path_reads_from_disk_and_never_the_network`). Verify-only:
  the free binary checks a signature and cannot create one — signing stays with the
  signer, air-gapped and outside this repository.

  Cryptography is Ed25519 verification from `ring`, verify-only — the same implementation a
  signer uses, so a review counts one asymmetric library and not two,
  and `ed25519-dalek` is still declined. This is the free binary's first crypto dependency,
  and it resolves the conflict the internal review flagged as major: `SECURITY.md`'s
  cryptography answer is now stated **per artefact** — `cargo-buildclamp` verifies with ring
  and names documents with the hand-written SHA-256 in `sha256.rs`; a signer outside this
  repository signs with ring — rather than as one sentence that was only ever true of one
  artefact. Tests:
  `a_signed_distributed_layer_verifies_and_the_report_names_the_signer` and the
  `signed_policy` / `no_vendor_key` suites end to end, plus fifteen unit tests over the
  verification core. NOT in scope, and stated so: distributing the signed layers is coordination that happens
  outside the enforcing binary.

- **`exact` per-proc-macro attribution, demonstrated by an executing test and claimed no
  further than measured.** The strongest differentiating claim in the project was the one
  least backed. The attribution engine (`crates/sandbox/src/linux/attribution.rs`) resolves
  a syscall's instruction pointer to the proc-macro shared object it fell inside, but it had
  only ever run against fabricated `/proc` maps in unit tests — never against a proc-macro
  that actually reached a syscall, so `exact` was real code proving nothing. It does now.
  `tests/fixtures/probemacro` issues `socket(AF_INET, …)` with an inline `syscall`
  instruction compiled into its own `.so`, so the instruction pointer the kernel records
  falls inside `libprobemacro-*.so`, and a held compile attributes the request `exact` to
  `probemacro` by name. `tests/fixtures/quietmacro` sits in the same closure doing nothing
  and is never named — the precision half, and the sharp one: a false attribution at `exact`
  is an accusation made on a user's behalf.

  Accuracy is published before it is claimed. On that one-probe corpus, precision at `exact`
  is 1.0 — one attribution, correct, zero false — and the test is the release gate: it fails
  the build if `exact` ever names the wrong macro or the innocent one, which is how "precision
  at exact must be 1.0 or the release blocks" is realised as a gate rather than a promise.
  What is NOT measured is stated beside it in `docs/adr/0004`: the synthetic sweep over
  closure size, depth and expansion order; `stack-scan`'s precision — so `stack-scan` is
  emitted labelled but is NOT a claimed confidence level, and the shipped measured claim is
  `exact` only; and the closure-size distribution, which is the precision bound of the
  `closure` fallback. That fallback — the incumbent's answer — is demonstrated by the same
  suite naming the whole set. Tests: `a_held_compile_names_the_exact_proc_macro_that_reached_out`,
  and the existing closure and baseline cases in `crates/cli/tests/procmacro.rs`.

- **Developer-machine coverage spike: a dated non-goal, measured, not a maybe.** The plan
  asked whether interactive and IDE-triggered builds could be routed through the shim by the
  cheapest mechanism — a `RUSTC_WRAPPER` line in `.cargo/config.toml` — without editor
  changes. Measured answer: no. A bare `RUSTC_WRAPPER` with a plain `cargo build` produces no
  report and holds nothing, because the wrapper passes a unit through whenever the driver's
  policy switch is absent (by design, so a stray wrapper cannot mutate a target directory);
  the manual four-variable path does hold units but gets no sweep and no report, and the
  editor sets none of the four. So laptop-side / editor enforcement stays a **documented
  non-goal**, recorded in `CLAIMS.toml` (`laptop-side-enforcement-is-not-claimed`, evidenced
  by `with_no_policy_active_the_wrapper_touches_nothing`) and in the README coverage table,
  and it may not be claimed in positioning until it ships. The blocking reason is named: the
  wrapper is inert without the driver, and rust-analyzer expands proc-macros through its own
  server rather than rustc, which a rustc wrapper never sees.

- **Corrected the per-proc-macro positioning now that `exact` is demonstrated.** Proving
  `exact` attribution (above) made an older honesty caveat false in the other direction:
  Its positioning and an absence claim said buildclamp "has not
  shipped it either — `main.rs` passes `HoldCompile` straight through … a design, not a
  capability." Compile units are held and the attribution fires, so that self-assessment was
  obsolete. The absence claim is now scoped to the incumbents (who still hold every macro
  under one shared grant), and buildclamp's side of it points at the capability claim and its
  test. The competitive absence itself is unchanged; only buildclamp's status moved. The
  automated gate could not catch this — a stale assumption is not a stale date — so it is
  logged here as a self-audit the `exact` work surfaced.

- **Exec is advisory, not enforced — and a CI invariant now forbids the mislabel.** Building
  an advisory-race harness surfaced it: `Capability::Exec` was reported
  `enforced:seccomp-notify-record`, while the sandbox's own decider allows every exec by
  construction (`_ => Decision::Allow`) and the test three functions below the label is named
  *a notification decision is not enforcement*. Exec is recorded through the notification
  supervisor and never refused; the kernel re-reads the path after the CONTINUE answer, so
  the binary that runs can differ from the one recorded. That is advisory by this project's
  own definition, and calling it enforced was promoting a CONTINUE observation to a
  guarantee.

  The relabel exposed that exec is **observe-only**: buildclamp offers exec-refusal on no
  host, by design, so `--require-enforced` and a `doctor --require` floor now exclude it
  rather than becoming unsatisfiable everywhere — and a floor that names `exec` explicitly is
  refused by name, because a lane requiring it enforced would fail forever, which must not
  look like a host that fell short. `Capability::is_observe_only` is the seam.

  `crates/sandbox/tests/no_continue_is_enforced.rs` is the architecture invariant the
  milestone asks for: a source scan that flags any `enforced("…notify…")`, verified by
  reintroducing the mislabel and watching it fire, and careful to leave `enforced("seccomp-errno")`
  alone because an errno is atomic. And `doctor` now quotes `seccomp_unotify(2)` verbatim —
  "must not be used to make security policy decisions about the system call, which would be
  inherently race-prone" — wherever a capability falls to that tier, because a tool calling
  its own enforcement weak is easy to discount and the kernel's manual is not.

- **Policy composition: `[layer]`, ceilings, and policy format version 2.** The policy type
  was one flat `BTreeMap` parsed from one file, with no `include`, `extends`, `inherit` or
  `import` anywhere. A security team's actual sentence — "no build script in this
  organisation reaches the network, and here are the nine crates that may" — had nowhere to
  live, so it got said in a wiki and enforced by nobody.

  A layer may declare itself a **ceiling** with `may-widen = false`, and then no layer above
  it may confer what it did not. The declaration belongs to the layer being *protected*: a
  layer that could be marked widenable from above would be no protection, because the
  repository could simply say so. A ceiling bounds every crate **including ones it never
  mentions** — its answer for an unnamed crate is "the defaults", and a ceiling that held
  only for crates somebody had already worried about would hold for the set that needs it
  least.

  Exceeding a ceiling is a **hard error naming both files**, and it is caught before cargo
  starts rather than per-unit: per-unit resolution would first notice it inside the
  launcher, halfway through a build, with a target directory already half written. Not a
  merge and not a silent narrowing — narrowing would leave the build passing, one file
  saying the crate has the capability, the envelope saying it does not, and nothing to tell
  a reader which. Narrowing *upward* is always allowed: a repository that wants less than
  its organisation permits needs no permission for it.

  Three more refusals, each for a reason: a cycle in `extends`, with the chain printed,
  because a cycle has no nearest layer and a resolver that picked one would be picking
  whichever file it read first; two layers with one name, because a refusal naming one of
  them sends a reader to the wrong file; and a ceiling with nothing above it, because a
  `may-widen = false` nobody is under is a line that reads like a control and is not one.

  `EnvelopeSource::Layer` names the layer that decided and the layer that bounded it, so
  `explain` and every report say which document produced each answer. That variant landed
  with the **forward-compatibility arm `EnvelopeSource` was missing** — this type is
  embedded in every unit of every report, and one unknown kind used to fail the whole
  document at the top level, taking every unit, request and tier with it. It is now the
  third enum in this crate to keep the unknown string verbatim, after `Tier` and
  `Attribution`, so no version bump was needed for the report.

  Two things the nearest layer keeps alone: the mode and the off switch, which are decisions
  about *this run*; and `[[exception]]`, because break-glass is somebody in this repository
  shipping past a refusal today, and an org layer that could carry one would be breaking
  glass on forty repositories from a file none of their engineers read. `--strict` counts
  unreviewed grants across every layer, because the org layer's grants apply to forty
  repositories at once.

  **`POLICY_VERSION` is 2, and a version 1 policy still parses.** That is the half a version
  bump lives or dies on: a number that refused every file in the field would be a migration
  nobody performs, and the tool would be the reason a build broke on the day it was
  upgraded. The rule is the report's, which has worked since report format 2 — only the
  future is refused. A v1 file is read and upgraded **in memory**; the file on disk is
  untouched until somebody runs `cargo buildclamp policy migrate`, which changes the number
  and nothing else — and re-resolves every grant against the original before writing, so a
  migration that moved an envelope is a refusal rather than a file somebody has to notice.
  The pinned v1 golden corpus asserts both halves.

  One fact about cargo's layout had to be written down for any of this to work:
  `WriteZone::Target` **contains** `WriteZone::OutDir`, because `OUT_DIR` lives under the
  target directory. Without it, a ceiling compared zone-by-zone refuses an ordinary
  `out-dir` grant for a compile unit, whose default zone is `target` — a refusal that is
  arithmetically correct, obviously wrong, and would fire on the first grant anybody wrote.
  The end-to-end suite found it on the first run.

  **Not measured, and the documentation says so where it would matter most:** whether one
  central policy actually applies across a real forty-repo estate, or whether every
  repository ends up with bespoke grants anyway. The mechanism ships because a customer with
  a hand-written org policy in git should not wait for that answer; the claim that it
  *scales* does not ship, because nothing here has earned it.

- **The attestation predicate in in-toto Statement v1, its normative schema, an erratum
  type, and `cargo buildclamp verify`.** The envelope this project emitted was
  `BCA1.<b64>.<b64>` with no `_type`, no subject, no `predicateType` and no DSSE — a format
  nothing in the ecosystem consumes, at a moment when slsa-verifier is explicitly
  unmaintained. The statement is kept verbatim as the predicate body, the artefact hash is
  lifted into `subject[0].digest.sha256` where cosign, Kyverno and policy-controller
  actually look for it, and the whole is an in-toto Statement v1 in a DSSE envelope.

  **`enforcement_profile` is the addition that stops this being a laundering machine.**
  Without it, a run with `withhold-secret-reads` off and `hold-compile-units` off produces a
  statement whose every tier says `enforced:` — truthfully, about the capabilities that were
  held — and an auditor reads "fully enforced" about a build where a build script could read
  `~/.aws/credentials` and no proc-macro was held at all. Those are exactly the gaps the
  README documents, and an attestation that hid them would be this project asserting, over a
  signature, the opposite of its own documentation. `is_fully_enforced()` is now false unless
  both hardenings were on, nothing was switched off, and every capability's **weakest** tier
  across the whole run is `enforced:` — weakest, so one advisory unit among two hundred
  decides it, whatever order the units appear in.

  A mandatory `scope` says what was not held in words, and `verify` prints the machine-
  readable profile **as well as** that prose: a reader who only saw the prose would be
  trusting whoever signed to have written a good paragraph, and the one statement where that
  matters is the one written by somebody who would rather it read well.

  **The committed schema is normative, not the URI.** `schemas/v1/` carries both schemas
  under Apache-2.0, versioned by directory, because a customer holding ten-year CRA evidence
  cannot depend on a domain outliving a company — and nothing in this tool fetches the URI. A
  test compares the schema against the Rust type in both directions, so a field added to one
  and not the other fails CI rather than shipping. The domain in those URIs is **not
  registered**, and that is recorded in `schemas/README.md` as a precondition rather than
  discovered later.

  An **erratum** predicate, also Apache-2.0 and also free: a signed statement is immutable
  and may be read in 2036, so a release later found to have overstated a tier is corrected by
  a document of its own, and `verify --erratum <file>` downgrades the answer. Errata are
  supplied locally and never fetched — a verifier that reached the network would be unusable
  in the air-gapped case this tool is built for. A vendor-only correction channel is not a
  correction channel.

  `cargo buildclamp verify` reads `predicateType` **out of the document** rather than from a
  `--type` flag: that flag is the shape of CVE-2022-35929, where cosign returned success when
  no attestation of the requested type existed at all. It also refuses a statement that
  disagrees with itself — a subject digest differing from the predicate's copy is a document
  two readers reach different conclusions from, and refusing it is the only answer that does
  not pick a side.

  **It does not check the signature and says so on every run, pass or fail**, in its own
  output rather than in a footnote. This command verifies no attestation signature; the free
  binary's only cryptography is `ring` verifying signed *policy* layers, and its closure has
  no network client, both of which CI asserts. Adding an attestation-signature algorithm here
  would be choosing one for a signer in another plane. The half it does is the one that catches laundering: a
  cryptographically perfect signature over a statement about a different artefact verifies.

  Sixteen **negative vectors** are published under `schemas/v1/negative/`, each naming the
  reason it must be rejected *for* — because a verifier that rejects everything passes a
  naive negative suite — with a positive control, because a suite with no acceptance in it
  cannot tell a correct verifier from a broken one. Customers are told to run them against
  their own verification path.

  Two more things written by hand rather than taken as dependencies, for the reason
  `Cargo.toml` gives about every dependency this tool does not have: standard base64 (RFC
  4648 §4, strict — a lenient decoder reads two strings as one payload, and a signature
  covers bytes) and DSSE's PAE encoding, whose length prefixes are the thing that stops a
  signature over one `(type, body)` pair being replayed as a signature over another.

  The signer is wired onto it in the same release and **emits DSSE**, so there is one
  definition of the document rather than two. The signing crate outside this repository
  no longer defines a statement type: it signs this tool's predicate, derives the
  enforcement profile from
  the policy that was in force and the report's own host record rather than from an argument
  — a signer able to pass `read_deny: true` for a run that had it off could sign the one
  claim the field exists to make unsignable — and delegates every non-cryptographic check to
  `verify_statement`, so a licensee and a third party reach the same verdict about the same
  document.

  It signs the **PAE** of `(payloadType, payload)` rather than the payload, and there is a
  test that a signature over the payload alone is rejected. The tamper test was rewritten:
  the old one split the attestation on `.` and mangled a field, which passed because the
  result was no longer JSON — a tamper test the parser catches is not a test of the
  signature. It now edits an `advisory:` tier into an `enforced:` one inside the envelope and
  asserts the failure is `BadSignature`, with an `assert_ne!` so that a replacement matching
  nothing cannot make it pass by verifying an unmodified document.

  Three of the signing crate's own tests failed on the new rule and were right to: their
  fixture policy
  was `version = 1`, which has both hardenings off. The fixture turns them on, which is what
  makes the other tests about the *other* reasons a run is not fully enforced.

  `BCA1` is refused by name, with a message telling a holder what they have rather than that
  their file is invalid. Nothing emits it.

  Not done: the cosign and `gh attestation verify` round-trip in CI, which needs both tools
  installed on a runner.

- **A first-run guide, a policy-authoring guide, and a troubleshooting page with measured
  numbers in it.** Three years of milestones contained no user documentation, and the single
  most likely support ticket — "this broke my build" — was answerable only by reading the
  source.

  `docs/FIRST-RUN.md` is fifteen minutes on a repository that has never seen the tool.
  `docs/POLICY.md` is the reasoning behind a grant, as distinct from `docs/CONFIG.md`, which
  is the reference: one answers "what does this key do" and the other "what do I do".

  The troubleshooting page leads with a measurement rather than advice. Run on 2026-09-15
  against `libc`, `cc` via `libz-sys`, `pkg-config` via `openssl-sys`, `openssl-sys` with
  the `vendored` feature — which compiles the whole of OpenSSL from source and made 32,762
  file operations — `bindgen`, `ring`, `zstd-sys`, `lz4-sys`, `brotli-sys`, `blake3`,
  `proc-macro2`, `quote`, `prettyplease` and `clang-sys`: **fourteen crates, zero grants.**
  `init` writes an empty `[grants]` table for that whole graph. The page says which named
  offender was *not* measured (`prost-build`, which needs a `protoc` the machine did not
  have) rather than describing it, and says that fourteen crates chosen for being common is
  not a sample of anything — the 200-crate sweep has not been run.

  `RELEASING.md` now requires upgrade notes on every release, as four questions answered
  whether or not the answer is "nothing": does an existing policy still mean the same thing,
  does an existing report still read, can a build that passed now fail, and can a build that
  failed now pass. A fixed false positive is a behaviour change too.

  `docs/CONFIG.md` catches up with the surface this release added: the `except` command,
  `--grace`, `--accept-baseline`, `max-active-exceptions`, `first-seen`, and the
  `[[exception]]` and `[baseline]` tables.

  Not done, and outside the code: support tiers and response times.

- **`buildclamp-sandbox`'s public API is frozen, with the matrix as its compatibility
  suite.** The crate is meant to be cut out and published on its own — "run this command
  under a capability envelope and tell me which tier held it" is useful to anyone building
  a CI runner, a package manager or a plugin host, and none of them want a cargo
  subcommand. A crate whose API moves under its consumers is one nobody depends on twice,
  so the freeze happens before the cut.

  `crates/sandbox/API.md` states what is frozen: `Plan` and its fields, `Plan::hold`,
  `Held`, `HoldError` and its variants, `projected_tiers` and `probe::host`. That is the
  whole arrow and nothing else. `tests/frozen_api.rs` pins each at its exact type — every
  item is *used*, so a removal, a rename, a changed argument or a changed return type fails
  to compile, because a promise written only in a document does not survive a refactor. The
  struct literals carry no `..Default::default()`, which is what makes an added field fail
  there too.

  One promise in that file is not a signature and is asserted anyway: **every `HoldError`
  variant is a refusal to run, never a reason to run unheld.** A future variant meaning
  "could not hold it, ran it anyway" would satisfy every type in the document and break the
  only thing the crate is for.

  `bpf` and `bpfcheck` are deliberately **not** frozen, and the document says why: they are
  public so a reviewer who does not trust us can read and execute the filter, and a syscall
  added to the tables changes that surface. Freezing it would make the filter harder to
  correct, which is the wrong trade for the part most likely to need correcting.

  A compiler cannot see an addition, so `API.txt` snapshots the declared surface and
  `tests/api.rs` compares the source against it in both directions. Verified by breaking
  it: an unconsidered `pub fn` fails the gate and is named in the output. Additions are not
  forbidden — unconsidered ones are.

  `docs/MATRIX.md` is named as the behavioural half of the same promise. A frozen signature
  says the calls still typecheck; `Plan::hold` returning `Ok` with every tier at `none` is a
  correctly-typed call that enforced nothing.

- **A reference interpreter for the seccomp filter, three fuzz properties, and a committed
  corpus.** `bpf::build` emits a classic-BPF program whose control flow is relative jump
  offsets resolved from forward labels. That is the part nobody can read, and a unit test
  asserting instruction 14 is `JEQ 41, +9, +0` is a test of what somebody typed rather than
  of where the jump lands. The class fails **open**: a jump that skips the notify return and
  falls into the trailing ALLOW is a hole in the tier the whole product is a claim about,
  and the process runs, the build passes and the report says `enforced`.

  So the program is executed rather than inspected. `bpfcheck::run` is a classic-BPF
  interpreter over the four instruction classes the builder emits — refusing anything else
  rather than guessing, because an interpreter that treated an unknown class as a no-op
  would report agreement about a program it did not model. `bpfcheck::expected` states the
  answer from the syscall tables, in the order the specification reads rather than the order
  the builder emits, so a reordering that changed behaviour shows up as a disagreement
  instead of being mirrored. The sweep covers every number either table names, **both
  neighbours of each** — an off-by-one lands on the next comparison, so a sweep of only the
  interesting numbers agrees with a filter whose arms are all shifted by one — six flag
  combinations, and all four option combinations on both architectures.

  Verified by breaking it, twice: swapping the `jset` arms on `openat`'s flag test and
  dropping `io_uring_setup` from the denied list each make the property fail and name the
  record that found it. What a differential of this shape cannot catch is a shared
  misunderstanding, and the module says so.

  Two more properties, in `buildclamp_core::fuzzcheck`. **A parse is never more permissive
  than the text**: `Policy::parse` either fails, or every capability and zone it hands a
  unit is one the document named or one the defaults already gave — checked against an
  oracle built from a *generic* TOML walk that knows nothing about `Grant`, `Defaults` or
  the resolution order. Verified by breaking it: a `resolve` that unions the defaults into a
  grant instead of replacing them fails within a second. **A report survives being read**:
  `from_json` either fails or round-trips through the typed value, and a migration never
  turns an advisory tier into an enforced one.

  All three live in the library, not under `fuzz/`. `cargo-fuzz` needs nightly and
  libFuzzer, so a property that lived only in a fuzz target would run where somebody had set
  that up and nowhere else. `cargo test` runs them on every commit against **the same
  committed corpus the fuzzer seeds from**, which is what makes a crash committed there a
  permanent regression test on the stable toolchain. The corpus directories are excluded
  from `.gitignore` deliberately — `cargo fuzz init` hides them, and that is the opposite of
  what this project wants from one. CI type-checks the targets on stable, which is how a
  target rots: the property moves, the target stops compiling, and nobody notices.

  Not done: OSS-Fuzz enrolment, which is an external registration rather than code, and the
  drift-envelope target, which belongs with the code it is about.

- **The enforcement matrix, its generator, and the container seccomp delta.** The tier
  ladder is this project's central claim, and a claim like that is worth what its evidence
  is worth. `docs/MATRIX.md` publishes the rows — one measured so far, and the rest listed
  as *not measured* with what each would take, rather than reasoned about from kernel
  version numbers. `ops/matrix-row.sh` is the generator: one command, from the released
  binary, on any host you can get a shell on, and the document says that a row disagreeing
  with ours is the true one.

  The `selftest` column is the one that matters, because it is the only outcome rather than
  a projection: a host can report `net: enforced:netns` and still fail to hold a process,
  and a cell where `doctor` says enforced and the selftest does not say held is a release
  blocker. `doctor --json` now carries the projected tiers alongside the host fields —
  additively, beside them rather than nested under a new key, because every existing reader
  indexes `user_namespaces` at the top level and a reshuffle would make each of them
  silently stop finding it.

  `ops/seccomp-additions.json` is the delta a container profile needs, every entry naming
  the file in `crates/sandbox/src` that issues the syscall, and
  `ops/make-seccomp-profile.sh` merges it into the operator's own default rather than
  vendoring a copy of a three-hundred-name allowlist that would go stale every time the
  runtime updated its own. `--check` verifies the list against the sandbox source and now
  runs in CI: a syscall the sandbox issues and the file does not name is a container that
  reports a weaker tier than its kernel offers, and the symptom is indistinguishable from
  an old kernel. That last case is called out by name, because it is the single most common
  way a container under-reports: a profile whose default action is `SCMP_ACT_ERRNO` refuses
  the three Landlock syscalls for being newer than itself, and Landlock then reads as
  absent on a kernel that has it.

- **Break-glass: `[[exception]]`, `--grace <days>`, and `init --accept-baseline`.** The
  failure that removes a gate like this from a CI in two sprints is a transitive dependency
  bump adding a capability, a red build at 17:00, and no unblock path that does not involve
  a security person. There is one now, it is in the free tool, and it works with no
  account, no network and no server — a block in a committed file, nothing else.

  `cargo buildclamp except <crate> --reason "…"` appends it. Mandatory `expires`, capped at
  **seven days from the day the build runs** rather than from the day the block was
  written, so it cannot be backdated into a long one. Mandatory non-empty `reason`.
  Mandatory `author`, filled in from the checkout's git identity and documented as
  self-asserted: what makes an exception accountable is a committed diff and an expiry, not
  a string. At most three live at once (`max-active-exceptions`), and the refusal names
  that key so whoever hits the cap can see their way past it. The block is narrowed from
  the report the red run just wrote, so it covers the capability that actually broke rather
  than all of them.

  **It widens capabilities and not `write-zones`.** A write outside the zones is still
  refused by the kernel; only the run's verdict stands down. An exception that could grant
  "anywhere" would be an off switch wearing the word `exception`, and there is already an
  honest way to spell that — `enforcement = "disabled"`, recorded as an operator override.
  `crate = "*"` is refused for the same reason, and `--require-enforced` is never
  excusable: it asks what this *host* can hold, and a block naming a crate has nothing to
  say about a machine.

  Measured end to end against the hostile fixture, red state asserted before green: with
  the block live the fixture reaches loopback (`err:ConnectionRefused`, the sandbox out of
  the way) and still cannot write outside `OUT_DIR`.

  `--grace <days>` is the other half. A grant whose `first-seen` is inside the window warns
  rather than failing `--strict`, so bump → red → `init` → commit → ticket is not also
  blocked on the review happening that afternoon. A grant with **no** `first-seen` is never
  in grace — the fail-closed direction, and what stops `--grace 3650` on a year-old policy
  excusing anything.

  `init --accept-baseline <file>` marks grants reviewed where a published document vouches
  for that **exact** crate version, and pins the grant it writes to that version, so a
  patch bump comes back for review instead of inheriting an approval nobody made. It only
  ever narrows: a crate that did something the document does not describe stays unreviewed.
  The document's SHA-256 goes into the policy as the reviewer of record — which answers
  "which document?", not "who may say?", and the file says so. `init` prints the residual,
  because a command reporting only what it accepted would be reporting its own success
  rate. **How large that residual is on a real estate is not measured yet**; until it is,
  your own run's number is the only evidence about it.

  Everything is loud. The summary prints what was excused, what it was used for and what is
  still owed on every run with a block in the policy, live or lapsed — and it prints it
  *before* the cargo-status check, because a build whose units were refused is one cargo
  fails and the early return used to swallow the line that says why. The report carries
  `break_glass`, keyed on the units that ran under an exception rather than on the refusals
  it excused: an exception widens the envelope, so the requests it covers come back
  `granted`, and a record keyed on refusals was empty on exactly the runs that needed it.

  Two additions this change makes without taking a dependency, for the reason `Cargo.toml`
  gives about every dependency this tool does not have: the civil-date arithmetic the
  expiries compare against (Hinnant's `days_from_civil` pair, checked in both directions
  across every day from 1970 to 2070) and SHA-256 (FIPS 180-4, checked against NIST's
  vectors including the million-`a` case that catches a broken length encoding).

- **Proc-macro expansion is held, with `hold-compile-units = true`.** The wrapper passed
  `HoldCompile` and `CompileAndRecordMacro` straight to `passthrough`, so the compile unit
  a proc-macro expands inside ran unheld and the two fixtures written for it — `evilmacro`
  and `macrouser` — were referenced by no test. Both are now real.

  The baseline is the interesting half and it is asserted: with compile units unheld, the
  fixture macro writes a `.desktop` autostart entry into `$HOME` **from inside rustc**, and
  nothing stops it or records it. That is the gap a build-script-only tool has, shown
  before anything claims to close it. Held, the same macro's network reach comes back
  `PermissionDenied` — the sandbox refusing it, not merely nothing listening — and the
  persistence file never appears.

  **The inventory `docs/adr/0004` asserted exists, now exists.** `proc_macros_in_closure`
  was `Vec::new()` at its only call site, so every attribution fell back to naming the
  compilation. The run directory carries proc-macro objects between the rustc that
  compiled one and the rustc that loads it — one file per macro, for the reason the unit
  records use one file per unit: cargo runs these concurrently and appending to a shared
  file from several processes is a corruption waiting for a busy build.

  **One shared policy per compilation, not per macro.** Expansion happens inside a rustc
  that has already loaded every proc-macro in its closure, so a refusal names the
  compilation and the macros that could have been responsible — never which one was.
  `cargo-acl` gives the same answer and says so.

  Opt-in, and this is the switch whose default costs the most to get wrong: a build script
  is one process per crate that has one, a compile unit is every rustc in the graph, and
  rustc opens thousands of files. The overhead regime the roadmap asks for — cachegrind
  instruction counts, criterion baselines on a pinned instance, a 300-crate graph with a
  confidence interval, and a README cost table generated from benchmark output — is **not
  in this change**, and it is the gate for making this default rather than the gate for
  shipping it. A 3-crate fixture graph showed no difference outside run-to-run noise,
  which is not evidence about a real one and is not published as though it were.

  A compile that cannot be held passes through rather than failing. A build script that
  cannot be held is refused, because the alternative is running somebody else's code
  unheld; a compile is different, because refusing it fails the build on every crate in
  the graph over a sandbox that would not start, and a tool that does that is switched off
  within the hour.

- **A GitHub Action, and `report --markdown` to feed it.** `action.yml` runs
  doctor → `doctor --require` → the held build → a markdown job summary, and is **free and
  unlimited on public repositories, permanently** — stated in the action file rather than
  on a page elsewhere, because a file in the repository is harder to quietly edit.

  The summary is generated by `cargo buildclamp report --markdown` rather than by shell in
  YAML, which is what makes it testable. It is **bounded and says so**: a first `init` on a
  real estate produces a couple of hundred findings and GitHub surfaces roughly ten
  annotations out of about fifty, so a summary that listed everything would be cut off by
  the platform wherever it happened to reach. It lists at most twenty units, prints how
  many it left out, and links to the report. A test builds a 200-unit report and asserts
  exactly that.

  Three ordering decisions, each with a reason. The runner's enforcement tiers are printed
  on **every** run, because a green build on a runner that enforced nothing is the failure
  this tool exists to prevent. `require-tier` is checked **before** the build, so a runner
  image change that removes user namespaces fails as a misconfigured lane rather than
  passing a build that enforced less than anyone thinks. And the summary is written
  **whether the build passed or failed** — a reviewer looking at a red job is the one who
  most needs the per-unit detail, and a step that died first would leave an exit code and
  nothing else.

  Not in this change, and the milestone asks for them: the crates.io publish, the launch
  post, the measured achievable tier per GitHub runner image, and the cargo-acl
  side-by-side. Each needs something this session does not have — a registry, a trademark
  result, real runners, or a competitor installed.

- **`env-allowlist`, the stronger of the two environment models, opt-in.** The default is
  a deny-list: a unit gets everything except names matching `env-deny`. That cannot know
  about a credential variable nobody has thought of, which is why
  `cargo-acl`'s `--clearenv` allowlist is the stronger model, and why buildclamp adopts one.

  `env-allowlist = true` gives a unit the base set in `ENV_ALLOWLIST_BASE` — what cargo and
  the toolchain tell a build script, plus the few system variables a compiler needs — and
  whatever its own grant lists. Everything else is gone: every variable CI exported, every
  one in the shell.

  **The two combine, and the allowlist never widens.** The deny-list runs first and
  independently, so a name it removes stays removed. The ordering is load-bearing rather
  than tidy: `CARGO_*` is in the base set and `CARGO_REGISTRY_TOKEN` starts with it, so an
  allowlist consulted first would hand back the exact credential the deny-list exists to
  take away, turning a feature sold as stronger into a hole. There is a test named for it.

  A grant **adds** to the base set rather than replacing it, or every grant would have to
  re-list eighteen cargo variables to work. A hard-denied name still needs the loud
  `env-allow-secrets = true`, so this does not become a second, quieter re-admission path.
  And the benign fixture — a `cc`-shaped build script that spawns a compiler and reads its
  manifest directory — is asserted to still build under it, because a hardening option that
  breaks ordinary build scripts is one nobody leaves on.

  The report records `env_allowlist` on each unit's envelope, so "why did my variable
  disappear?" is answerable from the run rather than from a policy file that may have
  changed since.

- **Withheld credential reads, opt-in, enforced by Landlock.** `withhold-secret-reads =
  true` in `[defaults]` makes a named set of credential paths unreadable to build units —
  `~/.aws`, `~/.ssh`, `~/.gnupg`, `~/.config/gcloud`, `~/.config/gh`,
  `~/.cargo/credentials.toml`, `~/.netrc`, `~/.kube`, `~/.docker/config.json`, browser
  profiles and a few more, all of them in `crates/core/src/withhold.rs` where they can be
  read rather than guessed at. A crate that genuinely needs one asks for the new `fs-read`
  capability in its grant, with a reason, like any other.

  Measured on `tests/fixtures/credreader`, a synthetic reader shaped like the two 2026
  incidents — it reads four credential paths and stages them into `OUT_DIR`, which is
  `include!`d into the crate, so the read is the whole attack and no network is needed:

  | | off | on |
  |---|---|---|
  | credential files read | 4 of 4 | 0 of 4 |
  | `~/.ssh` listable | yes | no |
  | bytes reaching `OUT_DIR` | 230 | 0 |
  | `fs-read` tier | `none` | `enforced:landlock-v7` |

  The baseline row is asserted, not assumed. A refusal on its own proves nothing — a
  fixture that never found the file looks identical — so the same fixture has to be shown
  reading all four before the zero means anything.

  **How a deny-list is expressed in a mechanism that only allows.** Landlock has no deny
  rule, so `read_roots` computes the complement: walk down from `/`, and at every directory
  with something withheld beneath it, grant the siblings one at a time instead of the
  directory. That is a handful of rules rather than one, and it buys a property granting the
  parent would not — a withheld directory that **does not exist yet** is still excluded, so
  creating `~/.aws` mid-build does not place it inside a granted region.

  Three limits, each stated next to the feature rather than in a footnote. It is a
  **deny-list**: everything not named stays readable, and this project must never describe
  it as an allow-list. It needs **Landlock**: a mount namespace cannot express a read
  restriction, and seccomp could only do it advisorily at 10–40 µs on every file rustc
  opens, so on a host without it the tier is `none` with that reason and
  `--require-enforced` fails. And **a withheld read leaves no trace in the report** — the
  kernel refuses with no supervisor in the loop, which is what makes it enforcement and
  equally what makes it unobservable, so the report names the tier but cannot name the
  crate that reached for your keys. `observe` cannot preview the breakage either, because
  observe enforces nothing.

  It ships **off**. Reads have been unrestricted since this tool existed and the README said
  so; switching a default-deny on underneath existing users would break builds they did not
  change. Making it default is a separate decision with a measured break rate behind it.

- **`clippy` is a subcommand, and it is the one that could have been covered wrongly.**
  Linting compiles and runs build scripts exactly as `check` does, so a pipeline that holds
  `build` and lints unheld has run the same third-party build-time code twice and held it
  once — on the job that runs for every pull request, including one from a fork.

  It is the only verb with two wrappers in play. `cargo clippy` sets
  `RUSTC_WORKSPACE_WRAPPER=clippy-driver` and leaves `RUSTC_WRAPPER` to buildclamp, and the
  two reach different units. Measured on cargo 1.94.1 by putting a logging script in the
  wrapper position: a **dependency's** build-script compile arrives as
  `<buildclamp> rustc --crate-name build_script_build …`, and the **workspace's own**
  arrives as `<buildclamp> clippy-driver rustc --crate-name build_script_build …`. Deciding
  what a unit is from the compiler's basename would hold the first and skip the second —
  the developer's own build script.

  `crates/core/src/unit.rs` already scanned the whole argv for that reason, with a table
  test over recorded command lines. What was missing was an end-to-end check against real
  clippy, so the new test drives it over a package with a build script of its own and names
  both units rather than counting them — "at least one unit" would have passed while the
  interesting half was missing.

  Worth recording for whoever checks this next: `cargo -vv` does **not** show it. Its
  `Running` lines print the resolved rustc command without the workspace wrapper, so a
  build log reads as though nothing goes through `clippy-driver` at all. The table above was
  measured from the wrapper position instead.

- **`publish` is a subcommand, and it is the one that cost something.** `cargo publish`
  compiles the packaged crate before uploading it — measured, in
  `target/package/<name>-<version>/` — so every build script in the graph runs and the
  wrapper reaches them like any other build.

  It is also the only verb where **cargo itself must keep a credential**. Everywhere else
  the driver drops credential-shaped names before cargo inherits them, so no process in the
  build tree holds a secret a build script could read out of `/proc`.
  `CARGO_REGISTRY_TOKEN` is in the default deny list by name, and dropping it here would
  break the upload with an authentication error pointing nowhere near buildclamp — so for
  this verb, and only this verb, it survives. The exception is exactly that narrow: an
  `AWS_SECRET_ACCESS_KEY` or a `GITHUB_TOKEN` is still taken out of the build tree, and a
  test pins it for every other verb too.

  Covering `publish` therefore meant naming an exposure rather than closing one. Held units
  never receive the token — each unit's environment is scrubbed separately — but where the
  environment tier is only `advisory:scrub`, a held build script can read it out of the
  publishing cargo's `/proc/<pid>/environ`. Publishing is one of the few moments a
  developer's registry token and somebody else's build-time code are alive in the same
  process tree, and the run now says so before cargo starts.

  **`--require-enforced` is answered before the upload for this verb**, not after it.
  Everywhere else the flag reads the finished report, which is the right place for it; here
  the report is written once the crate is already on the registry, and a verdict delivered
  then is not a verdict. A test asserts that cargo never ran.

- **`bench`, `doc` and `install` are subcommands.** All three compile and run build
  scripts, and all three sat in the README's coverage table as "partial, manual" — covered
  in principle by a mechanism that applies to any cargo verb, and in practice by nobody,
  because it took four environment variables and knowing in advance that it would work.

  `doc` is the one that surprises people: building documentation compiles and runs every
  build script in the graph, so a pipeline that holds `build` and then publishes docs from
  an unheld `cargo doc` has run the same third-party code twice and held it once.

  `install` is the one worth the change. Every other command here is about your own
  project; `cargo buildclamp install ripgrep` is about somebody else's dependency graph
  executing on your machine with your credentials in the environment, which is the shape of
  both large 2026 Rust incidents. It takes the crate name with no `--` in front, because
  requiring one would make the common case the awkward one.

  **One case holds nothing, and the run says so.** Measured: `cargo install --path <dir>`
  builds into `<dir>/target`, so installing a package already built there reuses it and no
  build script runs at all. The summary prints `no build units ran` for exactly that — a
  clean report over a build that never happened is the false assurance this whole tool
  exists to prevent, and it is pinned by a test. Installing from a registry does not have
  the problem, which is the case that matters.

  **Where an install's report goes when there is no workspace.** Running outside a project
  is the ordinary way to install a tool, and the layout used to fall back to `./target` —
  invisible while every subcommand needed a workspace to do anything, and a directory
  appearing in someone's home the moment one did not. It goes to
  `<tmp>/buildclamp-scratch/buildclamp/` instead, and the run prints the path. Deliberately
  not `$CARGO_HOME`: reports would accumulate there with nothing to clean them, and the
  rule the rest of this layout follows — everything under a directory `cargo clean` removes
  — has no equivalent there.

- **Report format version 2: a `run` header, and `tiers` as a map.** Version 1 had nowhere
  to record anything true of the whole build, so each consumer invented one — `drift
  ingest` put `host.arch`, `x86_64`, into a field its own documentation calls a target
  triple, which merges `-gnu` and `-musl` deployments into a single bucket and would have
  reported a libc difference as capability drift. The header carries a run id, start and
  finish times, the git remote / commit / ref, the target triple, an agent id, a CI
  correlation string and an ecosystem coordinate, and every field degrades to null: a
  build in an unpacked tarball or a container with no `.git` is an ordinary build. The
  remote has its userinfo stripped, because CI configures
  `https://x-access-token:<token>@host/org/repo` routinely and copying that into a report
  would write a live credential to disk in the course of protecting one.

  A v1 document is migrated on read rather than refused; the pinned v1 corpus is what
  keeps that true, and a v2 corpus is pinned beside it.

- **Names a newer buildclamp writes no longer take the run down with them.** Measured
  before the fix: `["net","fs-read"]` anywhere in a report failed the whole document with
  serde's `unknown variant`, so one unimplemented capability made every unit, request and
  tier unreadable. An unrecognised capability, write zone, unit kind, tier grade or
  attribution confidence is now carried **verbatim** — a reader that re-emits a document
  does not quietly rewrite `fs-read` as `unknown` — and `cargo buildclamp report` prints
  what it did not recognise, because tolerance without that line is a quieter way to
  under-report. An unrecognised tier grade counts as *not enforced*.

- **`cargo buildclamp doctor --require <tier-set>`**, so a CI lane declares the
  enforcement floor it needs and fails as a misconfigured lane if the host cannot reach
  it — in seconds, before a test runs. `--require-enforced` is checked at the end of a
  build against what happened, which is the right place for it and the wrong place to
  learn that the lane itself cannot enforce. A runner image that loses user namespaces
  leaves every gate green, because advisory enforcement still runs the build. `doctor`
  also now prints the tier each capability would reach on this host, computed by the same
  function that labels a real run and honouring `BUILDCLAMP_DISABLE`.

- **`cargo buildclamp selftest --no-network`**, which runs a command inside a build
  script's envelope with the network denied and fails if anything in it asked for the
  network. It proves that *this invocation of this binary, on this machine, opened no
  socket*, and it says plainly that it does not prove the binary cannot — that is
  `ops/no-network-closure.sh`, which reads the linking graph. It refuses to report a pass
  it did not earn: a host that can enforce nothing exits 1, and so does a command that did
  not succeed, since it may simply not have got as far as the network.

- **`min-tool-version` in `buildclamp.toml`**, the oldest buildclamp that can honour the
  file. The policy `version` moves when the format changes shape, which is rare, and it
  cannot express the common case: a file whose shape is unchanged and which relies on
  behaviour a given binary does not have. A release candidate satisfies the floor for its
  own release.

- **"What the RubyGems campaign settled, and what it did not" in the README.** The argument
  for holding build-time execution used to rest on inference plus one Rust incident. A
  campaign disclosed 2026-09-11 — an autonomous agent swarm publishing ~2,000 malicious
  packages, **a subset of which** obtained code execution on a registry's own
  documentation-build workers through a build-honoured file — makes the primitive an
  observed, automated, cross-ecosystem fact rather than an extrapolation. The upload count
  and the execution subset are separate numbers and only the second is evidence about
  build-time execution; conflating them would overstate the very finding this section
  exists to report carefully. The section says what it settles
  (the primitive is execution during build; the scale is not the attacker's ceiling; no
  sandbox appeared anywhere in the chain) and, at equal length, what it does not: it
  happened in another ecosystem and is not a measured claim about cargo. It also records
  that the exposed party was the **registry operator** — a deployment shape this tool does
  not serve, stated as a record rather than as a roadmap entry.

- **`crates/sandbox/INTERNALS.md`** — a guide to the enforcement crate for someone who did
  not write it. Documents what the code cannot show: the eleven orderings in `hold()` and
  `apply_in_child()` that are load-bearing, with the symptom each produces when violated;
  the multi-threaded-fork constraint that shapes every function reachable from `pre_exec`;
  the measured table showing that `CLONE_NEWUSER` and not `CLONE_NEWPID` is what refuses a
  read of another process's environment; and an explicit list of changes that are not safe
  to make. Written because a project whose security value lives in one `unsafe` crate
  should not need one particular person to change it.
- **`#![forbid(unsafe_code)]` on every crate except `buildclamp-sandbox`**, with
  `every_crate_outside_the_sandbox_forbids_unsafe_code` failing the build if one drops it.
  `cargo-buildclamp` contained no `unsafe` but did not forbid it, so "every unsafe block
  lives in one crate" was true by coincidence. It is a sentence an audit scope gets priced
  against; it should not depend on nobody having typed the keyword.

### Fixed

- **`trust-workspace` identified members by package name, so a registry dependency sharing a
  member's name ran its build script unheld.** Cargo can build a workspace member and a
  registry dependency with the same `name`; membership was matched on `CARGO_PKG_NAME` against
  the exported member list, so that dependency was classified first-party and, under
  `trust-workspace`, its build script ran outside the sandbox. Membership is now keyed on the
  crate's **manifest directory** (`CARGO_MANIFEST_DIR` matched against the members' manifest
  dirs, both from cargo): a directory is unique to one crate — a registry dependency lives
  under `~/.cargo/registry`, never inside the workspace — so a colliding name can no longer be
  mistaken for a member. `driver::a_dependency_sharing_a_member_name_is_not_a_member` is the
  guard. The `BUILDCLAMP_WORKSPACE_MEMBERS` handoff now carries directories rather than names,
  and passes them by the path of a trusted file rather than inline — a large monorepo's member
  list can exceed one environment entry's `MAX_ARG_STRLEN` (128 KiB) and fail `execve` with
  `E2BIG` before cargo starts, and the file sits outside every sandbox-writable path so a held
  unit cannot forge its own membership.

- **A symlink beside a withheld path could be granted read access to the withheld target under
  Landlock.** `read_roots` computes the readable complement of the withheld set by matching
  each candidate's own path, but the grant that follows resolves symlinks (`is_dir()` and the
  `O_PATH` open), so a read root like `~/link -> ~/.aws/credentials` — whose own path is not in
  the withheld set — was keyed on the resolved secret and handed `READ_FILE` on it, defeating
  `withhold-secret-reads`. Each read root is now opened **once** with `O_PATH | O_NOFOLLOW` and
  that single descriptor is both type-checked (via `fstat`) and keyed for the rule: a symlink
  root yields the link's own descriptor, which is identified as `S_IFLNK` and rejected, never
  granted. The single open also closes the check-to-use race a separate lstat-then-open would
  leave, in which the final component could be swapped for a symlink between the check and the
  grant. Fails closed like every other skip in the ruleset builder — one fewer readable region,
  never one more. Write zones are unchanged: those are directories the policy names for the
  unit, not siblings of a withheld path. `landlock::a_symlink_read_root_is_never_granted` is
  the guard.

- **A compilation that could not be held was omitted from the report, so an attestation
  could read "fully enforced" while a proc-macro ran unheld.** When `hold-compile-units`
  was on but the sandbox could not be applied to a specific compile unit, the compiler ran
  unheld — the documented pass-through, so a sandbox that cannot start does not fail every
  build in the graph — but nothing was recorded for that unit. `Verified::is_fully_enforced`
  keys the compile half on the `hold-compile-units` *flag*, which was still on, so the
  omitted unit was invisible and the run could be signed fully enforced with a proc-macro
  having expanded outside the sandbox.

  The pass-through stays, because failing a build over a sandbox that could not start is the
  behaviour that gets a tool switched off within the hour. What changes is that the unit is
  now recorded, with every non-observe-only capability at `none:`. The weakest-tier-wins
  summary then drops below `enforced:` and `is_fully_enforced` turns false — the honest
  reading of a compilation nothing constrained, and the same principle by which `off` mode
  refuses to "leave no trace". `attest::a_compile_recorded_as_unheld_is_not_fully_enforced_even_with_the_flag_on`
  is the guard.

- **A held build script could not create a thread.** The sandbox unshared `CLONE_NEWPID`
  in the child without forking before `execve`, which sets `pid_for_children` without
  moving the caller. The kernel refuses `CLONE_THREAD` while those two namespaces differ —
  `copy_process` returns `-EINVAL` — so every held unit was single-threaded, and any that
  tried to create a thread died on it.

  Measured with a C probe that unshares and then calls `pthread_create`:

  | state | `pthread_create` |
  |---|---|
  | before any unshare | ok |
  | after `unshare(CLONE_NEWUSER)` | ok |
  | after `unshare(CLONE_NEWPID)` | `EINVAL` |

  The blast radius is most `-sys` crates in the ecosystem: `cc` compiles in parallel with
  threads and `bindgen` uses them. These were builds broken by buildclamp, for a reason
  nothing in the report explained.

  Nothing caught it because every fixture here was single-threaded and no compile unit had
  ever been held. It surfaced the first time rustc went under the sandbox, which panics at
  startup — `install_ctrlc_handler` spawns a thread. `tests/fixtures/threaded` is the
  regression guard.

  **What removing it gives up**, stated rather than waved through: processes the unit
  *spawns* are no longer in a private PID namespace and can enumerate the host's processes.
  The unit itself always could — it was never in that namespace — so the restriction only
  ever applied to children of untrusted code that the untrusted code could lift by doing
  the work itself. No tier claimed it; the environment tier names `scrub+userns`, and the
  user namespace is what actually returns `EPERM` on `/proc/<pid>/environ`. Making the unit
  genuinely pid 1 needs a fork between the unshare and the exec, with this process relaying
  the grandchild's exit status and re-raising its signal — a design rather than a flag.

- **An `sccache` configured in `.cargo/config.toml` silently stopped running.** buildclamp
  has to occupy `RUSTC_WRAPPER`, cargo lets that be set two ways, and the environment beats
  the config — so a wrapper buildclamp never saw was displaced by it. Measured with a
  wrapper that logs each invocation: exported in the environment it ran 7 times under one
  `cargo buildclamp check` and the unit was still held; set in `.cargo/config.toml` it ran
  **0** times, while a plain `cargo check` with the same config ran it 7. The build still
  succeeded and was merely no longer cached, which is the worst shape a regression can
  take: it costs time, produces no error, and the tool that caused it is the last thing
  anyone suspects.

  buildclamp now **warns**, names the file the key is in, and prints the one-line fix. It
  warns rather than chaining the configured value itself, and the limit is deliberate:
  chaining would mean resolving cargo's whole config hierarchy, and getting that subtly
  wrong would run the *wrong* wrapper silently, which is worse than running none.

- **`unix` had no tier on any enforcing run.** `plan_tiers` emitted `net`, `fs-write`,
  `env-secret` and `exec`, and the one capability granted by default was the one recorded
  without saying how it was constrained — the single thing the schema exists to make
  impossible. It went unnoticed because the default is "allowed", so the missing row was
  the one nobody looks at, and a unit test excused it by name. The tier is
  `enforced:seccomp-errno` and deliberately not `netns`: an empty network namespace
  isolates the *abstract* unix namespace but not path-bound sockets, and the docker socket
  and the ssh agent are path-bound.

- **`--require-enforced` passed a run where nothing was enforced at all.** It tested for
  advisory tiers only, so a unit whose every tier was `none` — on a host that cannot
  enforce — satisfied the flag whose entire purpose is to refuse that build. A `none` tier
  on a capability the policy *granted* is a decision rather than a missing mechanism, and
  still passes.

- **`init` dropped a grant when a crate appeared at two versions.** Grants were keyed on
  the crate name while observations are keyed by name and version, so the second write
  erased the first; the erased version then matched no grant and fell back to the defaults
  on the next enforcing run. `init` is the adoption path, and this broke the build on a
  crate the user had just watched the tool observe.

- **A policy from a newer buildclamp was refused by whichever key was new**, not by its
  version: `deny_unknown_fields` failed the typed parse before the version check ran, so
  the message sent the reader to delete a line when the answer was to upgrade.

### Changed

- **The README's coverage table was re-measured, and two rows did not survive it.** Both
  were wrong in the same direction — towards claiming more coverage than the tool had.
  `sccache` was one row reading "yes", carrying the note that no fixture exercised it; it
  is two rows now, because the more common way to configure sccache is the way that
  silently stopped working. And a row that did not exist at all: a target directory
  buildclamp has already swept looks as though it should stay covered, and does not — the
  shim run without `BUILDCLAMP_POLICY` executes the real build script unheld and exits 0,
  by the same design that stops a stray `RUSTC_WRAPPER` mutating a target directory. An
  editor sharing a target directory with your buildclamp builds is not covered by
  proximity to them.

  Rows that were reasoned rather than run — `docker build`, `cross`, Bazel, Buck2 — now say
  so individually, instead of sitting in a table whose header says "measured".

- **Two cells of `ARCHITECTURE.md` §4 corrected against the code at the same time.** The
  environment fallback read "scrubbed only"; `plan_tiers()` emits `advisory:scrub`, and the
  distinction is the whole point of a tier — "scrubbed only" sounds like a weaker version of
  the same guarantee, while `advisory:` is the label that says a same-uid process can still
  read the environ. The `exec` row read "recorded" in all three columns; the code emits
  `advisory:seccomp-notify-record`, degrading to `none` where seccomp notification is
  absent, because without it exec cannot be recorded at all — a CONTINUE decision observes,
  it does not refuse, so the tier is `advisory:` and the source scan rejects `enforced:` on it. A table about which tier
  applied should not be the document that is vague about it.


- **`buildclamp` — capability-gated execution of build scripts and proc-macros for
  Cargo.** `cargo buildclamp build` runs every third-party `build.rs` inside a declared
  capability envelope: no network, no writes outside `OUT_DIR`, no credential-shaped
  environment variables, unless `buildclamp.toml` grants them.

- **The tier ladder, and the report that names it.** Per capability, per unit, the report
  records *how* it was constrained on that host — `enforced:netns`, `enforced:mountns-ro`,
  `advisory:seccomp-notify`, or `none` with a reason. `--require-enforced` fails a run that
  could only be advisory. This is the property the whole design turns on: the nearest
  existing tool prints a notice and continues **unsandboxed** when its helper binary is
  missing, and a green build that enforced nothing is worse than no tool.

- **Observe first.** `cargo buildclamp observe` runs the build, refuses nothing, and
  records what enforcement *would* have refused. `init` writes the policy from that, with
  every grant `reviewed = false` and a `why` that says it is an observation with a date.
  `--strict` refuses to pass while any grant is still unread.

- **Per-proc-macro attribution**, with a stated confidence — `exact` from the instruction
  pointer, `stack-scan` from a stack walk, or `closure`, which is what every other tool
  gives. It degrades to the incumbent's answer, never to nothing.

- **Signed build attestation** — a signer outside this repository signs the report
  with an offline Ed25519 key; this tool verifies the statement and holds no key.

### Measured

On a 4-vCPU Linux 6.18 host with **no Landlock**, where the filesystem tier is therefore a
mount namespace rather than Landlock:

| | |
|---|---|
| holding one build unit | 2.5 ms |
| per notified syscall | 10–40 µs |
| clean build of a serde-plus-derive graph, unhooked | 5.06 s |
| the same build, hooked | 4.86 s |

Hooked and unhooked builds are within measurement noise of each other.

Against `tests/fixtures/evil`, a replica of the August 2026 `arrayref` build script:

| what it tried | unheld | held |
|---|---|---|
| connect to its C2 address | reached the syscall | `PermissionDenied` |
| read credentials from its own environment | both visible | none visible |
| read its parent's `/proc` environment | 7,883 bytes | `PermissionDenied` |
| persist to `~/.config/autostart` | succeeded | `ReadOnlyFilesystem` |
| write `OUT_DIR` | ok | ok |

### Known limits

Stated here as well as in the README, because a changelog is where people look for what
changed and not for what was never there.

- **Linux only.** macOS and Windows get nothing.
- **Reads are unrestricted**, so a build script can read `~/.aws/credentials` and stage
  them into `OUT_DIR`, which is `include!`d into your binary by design. A read-deny list is
  the most valuable single thing absent from this version.
- **Proc-macro expansion is not yet held.** The interception, the policy and the
  attribution machinery are in place; wiring rustc itself through the sandbox needs the
  proc-macro inventory threaded through the wrapper first. Documented as unbuilt rather
  than half-done, because a compile unit that looked held and was not would be exactly the
  false assurance this tool is about.
- **`net-destinations` is recorded, never enforced.**
- **The advisory tier is defeatable**, by construction, and says so.
