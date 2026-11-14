# First run

Fifteen minutes, on a repository that has never seen this tool. Nothing here can break your
build: the first two commands refuse nothing.

## Before anything: what can this machine enforce?

```console
$ cargo buildclamp doctor
```

Run this first, because it decides what the rest of the page means. It prints one line per
mechanism and says what each buys. `no` on user namespaces is the common answer on a
hardened distribution or inside a container, and it is not a reason to stop — it changes
which tier you reach, and buildclamp will say which tier it reached on every run rather
than claiming one it did not.

If it is `no` and you expected `yes`, [docs/MATRIX.md](MATRIX.md) has the container and
Kubernetes fixes, including the one that surprises people: a runtime seccomp profile
refuses the three Landlock syscalls for being newer than itself, and Landlock then reads as
absent on a kernel that has it.

## 1. Watch, refuse nothing

```console
$ cargo buildclamp observe
```

This runs `cargo check` with every build script held in a recording sandbox. Nothing is
denied. It prints one block per build unit: what it was allowed, which tier held each
capability on this host, and everything it asked for.

The first run rebuilds the world, because changing the compiler wrapper changes every
fingerprint. The second is normal speed — and may run no build units at all, because cargo
found everything fresh. buildclamp says "no build units ran" rather than reporting a clean
run, which is a distinction worth noticing the first time you see it.

**Read the output.** This is the part people skip and it is the part worth the fifteen
minutes: it is probably the first time anyone has looked at what your build scripts
actually do.

## 2. Write the policy from what was seen

```console
$ cargo buildclamp init
buildclamp: wrote buildclamp.toml with 4 grant(s), all unreviewed.
```

`init` writes a grant for every unit that needed more than the defaults, and **only** for
those. A crate that wrote `OUT_DIR`, spawned a compiler and did nothing else gets no entry
at all, which is what keeps the file short enough to read.

Measured on 2026-09-15, against a graph of `libc`, `libz-sys`, `openssl-sys` (including the
`vendored` feature, which compiles the whole of OpenSSL from source), `bindgen`, `ring`,
`zstd-sys`, `lz4-sys`, `brotli-sys`, `blake3`, `proc-macro2`, `quote`, `prettyplease` and
`clang-sys`: **zero grants.** Every one of them stays inside the default envelope. If your
first `init` writes a large file, the interesting question is which crates are in it.

Every grant it writes says `reviewed = false` and its `why` records what was *observed*,
with a date. That is deliberate and it is the whole mechanism: the tool watched this, it
did not approve it. Replacing each `why` with a real reason and setting `reviewed = true`
is the work, and it is what `--strict` refuses to pass without.

If the file is long, you have two ways to make it tractable without pretending — see
[Policy authoring](POLICY.md#making-strict-reachable-on-a-real-repository).

## 3. Enforce it

```console
$ cargo buildclamp build
```

Same build, with the policy in force. An ungranted request now fails the unit, cargo fails
the build, and buildclamp prints one line naming the crate, what it tried to do, and the
exact grant to add.

Exit codes, and the distinction matters in CI: **0** clean, **1** the tool or the build
broke, **2** the tool worked and the answer was no. A pipeline that treats 1 and 2 the same
either ignores real findings or blocks on unrelated breakage.

## 4. Put it in CI

```yaml
- run: cargo buildclamp doctor --require enforced   # fail the lane, not the build
- run: cargo buildclamp build --strict --grace 14
```

Two flags and a separate step, each earning its place:

`doctor --require` declares the floor **the lane** needs, and fails early when the machine
cannot reach it. Without it a runner that lost user namespaces silently downgrades to
advisory enforcement, the build stays green, and nobody is told the control stopped
controlling.

`--strict` refuses to pass while any grant is still `reviewed = false`, which is what stops
`init`'s output from quietly becoming permanent.

`--grace 14` makes a grant written in the last fortnight warn instead of failing, so a
dependency bump becomes a warning and a ticket rather than a red build at 17:00. It never
excuses a grant that was already there.

There is also a composite action, if you would rather not write the steps:
[`action.yml`](../action.yml).

## When it blocks you

```console
$ cargo buildclamp except <crate> --reason "release blocked; TICKET-123 tracks the real grant"
```

One command, no account, no network, no server. It appends an `[[exception]]` naming you,
your reason and an expiry at most a week out, and every run says loudly that it is there.
[Troubleshooting](OPERATIONS.md#it-is-1700-a-dependency-bump-went-red-and-the-release-has-to-go)
has the bounds and how to get past each one.

## What to read next

| you want | read |
|---|---|
| to write or widen a grant | [Policy authoring](POLICY.md) |
| every flag and every key | [Configuration reference](CONFIG.md) |
| something broke | [Troubleshooting](OPERATIONS.md#troubleshooting) |
| what this reaches on your fleet | [The enforcement matrix](MATRIX.md) |
| whether to trust any of it | [`CLAIMS.toml`](../CLAIMS.toml) — every claim, and the test that holds it up |
