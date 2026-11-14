# ADR-0005: The no-network rule is about artefacts, not about the project

**Status:** accepted · **Date:** 2026-09

## Context

This project tells people, in two places, that it cannot phone home and that they need not
take its word for it:

> A tool that denies build scripts the network must not itself be able to reach it, and a
> customer must be able to establish that from `cargo tree` rather than from a promise.

The rule as documented is stronger than the rule as enforced, and the enforcement is
weaker than it looks. `ops/ci.yml` greps `Cargo.toml` files for six line-anchored
dependency names. Measured against that regex, on this repository, four ways of acquiring
an HTTP client:

| how it arrives | caught? |
|---|---|
| `reqwest = "0.12"` | yes |
| `reqwest.workspace = true` | **no** — no `=` directly after the name |
| `  reqwest = "0.12"` under a target table | **no** — the `^` anchor |
| a wrapper crate that pulls `hyper` transitively | **no** — a grep cannot see a graph |

Three of four forms pass a check whose promise is `cargo tree`. That is the same shape as
every other defect this project has found in itself lately: a control that looks present
everywhere a reader would check, and is not.

There is also a problem the grep cannot have, because it is a problem with the sentence.
"Nothing in either plane can phone home" is a claim about a *project*, and a project is not
a thing you can point `cargo tree` at. It also forecloses something the plan needs: a
server that stores reports is a server, and a server has a network stack. Left as
written, the rule
would either be quietly broken later or would be cited as a reason not to build one.

## Decision

**The rule is narrowed to artefacts, and asserted over resolved closures.**

> No artefact that runs on a machine where a third-party build script also runs may
> contain a network client, asserted over the transitive dependency closure of each
> **published binary**.

Four artefacts, three of which never link one:

1. **the free binary** — Apache-2.0, sits in the build path. Zero network closure, forever.
2. **a second binary that runs *beside* a build** — not part of this tool, reading
   files and standard input and writing files and standard output. Zero network
   closure, forever.
3. **transport** — the customer's own CI configuration, or a small separately-versioned
   uploader. Never a subcommand of either binary above, never invocable from the build path.
4. **a report-storing server**, if one is ever built — a separate repository with its
   own workspace and lockfile, never installed on a build machine, which obviously
   has a network stack.

`ops/no-network-closure.sh` asserts 1 and 2 with `cargo tree -e normal` per binary, and
**adds to the grep rather than replacing it.** The grep is fast, needs no resolver, and
catches a library crate gaining a client before anything reachable depends on it. The
closure check sees the graph. Neither is the other's superset.

## What this gives up, stated rather than discovered later

**It is a claim about linking, not about behaviour.** The free binary spawns `cargo`, and
`cargo` downloads crates. At the process level buildclamp is one `exec` away from the
network and always has been. What the closure proves is narrower and still worth having:
the binary carries no client of its own, so there is no code path *in the artefact* that
opens a socket, and the tool cannot exfiltrate what it observes. Anyone who reads
"buildclamp cannot reach the network" as a statement about the process tree has been
misled, so this document says it in the other direction first.

**Development and build dependencies are out of the closure check.** `-e normal` excludes
both. Neither ships inside the artefact, which is what the rule is about; build-time code
on a maintainer's machine is a different question and the repo-wide grep is what covers
it. Two checks with two different scopes is only useful if each says which is which.

**A report-storing server is now permitted.** That is the point of the narrowing and
it is the part a reader is entitled to be suspicious of, because it is a rule being
relaxed by the people it constrains. Two things make it less convenient than it
sounds. The relaxation landed *before* any such server exists, so it cannot be a
rationalisation written to permit something already built. And the server it permits
is one that can never be in
the build path: read-after-the-fact only, unable to serve policy or make an enforcement
decision, and able to be entirely down while builds pass.

**It does not prove a binary makes no network call at runtime.** A binary can shell out.
The closure bounds what it links, and a run-time demonstration — the tool executing
normally inside a network namespace with no interfaces — is a separate and stronger
artefact. It is not built yet, and is named here as absent rather than implied.

## Consequences

**`cargo-deny` was considered and not adopted.** A `deny.toml` per workspace would express
the same ban a second time, and require installing a tool in CI to enforce a property the
closure script already enforces with `cargo tree` alone. This repository has just finished
adding a gate that fails the build on any declared thing nothing reads; shipping a second
mechanism for one property, where only one of them runs, would be the first thing that gate
should catch. If `cargo-deny` is adopted later for licences and advisories — which are jobs
nothing here does — the network ban can move into it and this script can go.

**The scan the mirror runs stayed a bright line.** This document had to describe
binaries outside this tool, whose names and licences are forbidden markers in
the publish scan. A scoped exception was the obvious move and was rejected: an allowlist
with one entry acquires a second, and the marker list is worth more as a rule with no
exceptions than as a rule with a short list of them. So the document is written
without that vocabulary, names nothing the scan bans, and mirrors unmodified.
