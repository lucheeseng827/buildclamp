# Seed corpora, and where crashes go

Two jobs, and they are the same files.

**libFuzzer starts here.** A fuzzer given no seeds spends its first minutes discovering
that a policy file is TOML; these documents hand it that for free and let it spend the time
on the branches that matter.

**`cargo test` reads the same directory.** The deterministic sweeps in
`buildclamp_core::fuzzcheck` and `buildclamp_sandbox::bpfcheck` load every file here and
assert the property over each one, then mutate them. So **a crash committed here is a
permanent regression test**, on the stable toolchain, on every commit — without anybody
needing nightly or libFuzzer installed. That is the whole reason the properties are library
functions rather than code inside `fuzz_targets/`.

When a fuzzer finds something: commit the input here with a name that says what it is
(`grant-version-matches-unparseable.toml`, not `crash-3f2a…`), fix the defect, and the
sweep keeps it fixed.

## `bpf_differential` has no files, and that is not an oversight

Its input is an `Arbitrary`-derived struct rather than a document, so a seed would be an
opaque byte string nobody could read or maintain. The filter's input space is small enough
to sweep exactly instead: `bpfcheck`'s tests cover every syscall number either table names,
both neighbours of each — an off-by-one in a jump lands on the *next* comparison, so a
sweep of only the interesting numbers agrees with a filter whose arms are all shifted by one
— a spread of numbers no table mentions, six flag combinations, and all four option
combinations on both architectures. A crash found by the fuzzer there belongs in
`bpfcheck`'s tests as a named case, not here as bytes.
