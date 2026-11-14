# Test fixtures

Real cargo packages, compiled by a real `cargo` invocation inside the integration
tests. Nothing about cargo is mocked: the thing under test *is* the interception,
so the tests have to drive the actual build.

| fixture | what it is | what the suite asserts |
|---|---|---|
| `evil` | a replica of the `proc-macro1` build script — base64 C2 reconstruction, TCP connect, secret reads from its own and its parent's environment, a persistence write to `$HOME/.config/autostart`, a legitimate `OUT_DIR` write, and a subprocess | every capability is denied and *named* in the report, while the `OUT_DIR` write still succeeds so the crate compiles |
| `benign` | the shape shared by `cc`, `bindgen`, `pkg-config`, `prost-build` — read the manifest dir, generate into `OUT_DIR`, create a subdirectory, rename within `OUT_DIR`, spawn `cc --version`, emit `cargo:` directives | **zero violations** under the default policy. This is the false-positive gate |
| `netlegit` | a build script with a genuine need for the network, pointed at a listener the harness starts on loopback | denied by default; clean with an `[[allow]]` that carries a justification; a policy-parse failure when the justification is missing |
| `evilmacro` + `macrouser` | a proc-macro whose payload runs at **expansion** time, inside the `rustc` compiling the consumer | the compiler-unit sandbox catches it, and attribution names the consumer plus the proc-macros in its closure — no more precision than the design actually has |

## Rules every fixture follows

**Loopback only, never the internet.** The C2 address is `127.0.0.1:9`,
reconstructed from base64 exactly the way the real sample reconstructed its own.
The capability exercised is identical, because the sandbox refuses `socket` and
`connect` before a packet exists — and the suite never depends on DNS or puts
traffic on anyone else's network.

**A fixture never fails its own build.** Each step reports
`<fixture>-step:<n>:<name>:<ok|err:...>` on stderr and continues. The *tool* must
be what fails the build: a fixture that exited non-zero on a denied syscall would
let a broken sandbox pass, because the harness could not tell "we blocked it" from
"the script crashed on its own". It also makes a partial defence visible — if the
network is denied but the persistence write is not, the suite sees step 2 fail and
step 5 succeed instead of stopping at the first refusal.

**The legitimate half must keep working.** `evil` and `benign` both `include!` the
file their build script generates, so a wrongly-denied `OUT_DIR` write is a compile
error rather than a quietly different constant.

## Measured baseline, unsandboxed (2026-09-01)

Run with `GITHUB_TOKEN` and `AWS_SECRET_ACCESS_KEY` set and `HOME` pointed at a
scratch directory. Every line below must flip under the default policy, except the
two marked *must stay*.

```
evil-step:1:decode-c2:ok
evil-step:2:connect:err:ConnectionRefused        <- reached the syscall
evil-step:3:read-env-secrets:err:leaked:GITHUB_TOKEN,AWS_SECRET_ACCESS_KEY
evil-note:parent-environ-bytes=7883 secret=true  <- read the PARENT's environment
evil-step:4:read-parent-environ:err:leaked-via-proc
evil-step:5:persist-outside-out-dir:ok           <- persistence achieved
evil-step:6:write-out-dir:ok                     <- must stay ok
evil-step:7:exec-subprocess:ok                   <- must stay ok (recorded, not denied)
evilmacro-step:2:persist:ok                      <- from inside rustc
evilmacro-step:3:env:GITHUB_TOKEN,AWS_SECRET_ACCESS_KEY
```

Step 4 is the one worth staring at. Scrubbing a build script's own environment does
nothing about the copy in its parent's `/proc/<pid>/environ`, which is readable by
any process of the same user when there is no `hidepid` and no user namespace. That
measurement is why the user namespace is part of the first cut and not the roadmap.

## Where cargo puts the output

Cargo captures a build script's stderr to
`<target>/<profile>/build/<pkg>-<hash>/stderr` and shows it only when the unit
exits non-zero (or under `cargo build -vv`). The assertions read that file
directly rather than the terminal.
