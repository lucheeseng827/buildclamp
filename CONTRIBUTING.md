# Contributing

## The short version

```console
$ cargo test --workspace                                    # everything
$ cargo test -p buildclamp-core                              # every policy decision, no kernel needed
$ cargo test -p cargo-buildclamp --test endtoend -- --nocapture   # the two gates that matter
$ cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
```

All four have to pass. The third is the one people forget and the one that catches the
mistakes that matter.

## Sign your commits off (DCO, not a CLA)

Every commit needs a `Signed-off-by` line. `git commit -s` adds it.

```
Signed-off-by: Your Name <you@example.com>
```

It is the [Developer Certificate of Origin](https://developercertificate.org/): you are
saying you have the right to contribute the code, not assigning anything to anyone. CI
checks for the line.

**Deliberately not a CLA.** A contributor licence agreement reads as a rights grab
however it is worded — you would be signing over the ability to relicense your work
into a part you cannot see. The DCO asks for the thing that actually matters and
nothing else.

## How an external pull request reaches the code

Worth explaining, because this repository is a **one-way mirror** and that is unusual
enough to be worth stating rather than discovering.

The code is developed in a private monorepo and published here by a sync that only ever
copies out. Nothing merges back automatically. So:

1. **Open your pull request here, against the mirror.** This is the right place; there is
   no other repository you should be looking for.
2. A maintainer **replays it into the monorepo preserving your authorship** — your commits,
   your name, your sign-off, `git am` of the patch series rather than a retyped version.
3. It goes through the same gates as everything else, and lands back here in the next sync.
4. **The pull request is closed with a link to the commit that carries it.** A closed pull
   request whose work shipped anyway looks exactly like a rejected one, so it will always
   say which it was.

This means your change appears in the mirror as a commit rather than as a merge, and there
is a delay between "accepted" and "visible". Both are consequences of the mirror, neither
is a comment on the contribution, and if either is going to be a problem for you, say so
in the pull request and it will be handled differently.

**Triage.** The maintainer named in [`SECURITY.md`](SECURITY.md) triages inbound pull
requests. Expect a first response within **five working days** — a response, not
necessarily a decision. If that lapses, the honest reading is that this project is
under-resourced rather than that your change was unwelcome, and a ping is fair.

## The two gates

Every change is measured against two fixtures that fail in opposite directions:

* **`tests/fixtures/evil`** must be stopped, and named in the report. If a change lets it
  through, the tool does not work.
* **`tests/fixtures/benign`** must produce **zero** ungranted requests. If a change makes
  it fail, the tool is unadoptable — a default-deny policy that breaks `cc`, `bindgen` and
  `pkg-config` on the first run gets uninstalled the same afternoon.

A change that fixes one usually breaks the other. That is why they are in one suite.

## If you touch the sandbox

**Read [`crates/sandbox/INTERNALS.md`](crates/sandbox/INTERNALS.md) first.** It is the
guide to what is not visible from the code: the eleven orderings that are load-bearing and
the symptom each produces when violated, why the environment tier names the user namespace
and not the PID namespace, why Landlock is raw syscalls, and an explicit list of changes
that are not safe to make. The three rules below are its summary, not a substitute for it.

`crates/sandbox` is the only crate allowed `unsafe` — every other crate carries
`#![forbid(unsafe_code)]`, and `every_crate_outside_the_sandbox_forbids_unsafe_code` fails
the build if one stops. Every block carries a comment stating the invariant that makes it
sound. Three rules, each of which cost a spike to learn:

1. **The `pre_exec` closure allocates nothing, takes no locks and cannot panic.** It runs
   between fork and exec in a process that has a supervisor thread, where the allocator may
   be held by a thread that no longer exists. Build every buffer before the fork.
2. **The supervisor thread starts before `Command::spawn`.** The child's own first `execve`
   is notified and `spawn` blocks until exec completes, so the other order deadlocks on the
   first unit. It did.
3. **Never report a tier you did not achieve.** `Tier::Advisory` carries a sentence saying
   why it is not enforcement, and there is no way to construct one without it. If a
   mechanism is missing, the answer is `Tier::None` with a reason and a refusal to run —
   never a quiet fallback to running unheld.

`BUILDCLAMP_DISABLE=ns,notify` makes the fallback tiers reachable on a host that has
everything, so a change to them is testable rather than hopeful.

## Style

Match what is there. Concretely:

- **Comments say why, not what.** If a constant has a number in it, the comment says how
  the number was chosen and what happens if it moves.
- **Record the bug in the code that fixes it.** Several comments here name a specific
  failure: the fingerprint that is not a fingerprint, the deadlock on the listener
  handover, the linker that does not truncate in place, the cross-build collision. They are
  there so nobody re-introduces them while tidying, and deleting one should feel wrong.
- **Test names are sentences.** `a_build_script_may_not_reach_the_network_by_default`, not
  `test_net`. A failing name should say which property broke without opening the file.
- **The vocabulary is not decoration.** A **build unit**, a **capability envelope**, a unit
  is **held**, a **grant** carries a required `why`, and a request the envelope does not
  cover is an **ungranted request**. Never violation, breach, denied, blocked, malicious or
  suspicious. There is a test asserting no output uses those words, because the words a
  security tool uses about other people's code end up in their issue tracker.
- No new dependency without an argument in the pull request. The workspace manifest argues
  for each *absence* too; read it before adding one.

## If you change what the report contains

The report is an audit artefact. A field added is a field a consumer may come to rely on,
and a field removed breaks them silently. Bump `REPORT_FORMAT_VERSION` for anything an
older reader would misread, and say so in the changelog.

If you change what a telemetry envelope over the report carries, there is a test
asserting its exact field set. That test failing is the point: adding a field is a
change to what leaves a reader's network and should be deliberate.
