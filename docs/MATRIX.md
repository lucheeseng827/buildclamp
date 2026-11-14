# The enforcement matrix

What buildclamp actually reaches, on which hosts, measured rather than reasoned.

This document exists because the tier ladder is this project's central claim — every
capability in every report carries the tier that applied on the host it ran on — and a
claim like that is worth exactly as much as the evidence behind it. So the rows below are
recorded `doctor` and `selftest` runs, the bad ones are published alongside the good ones,
and the generator is shipped so that you do not have to take any of it on trust:

```console
$ ops/matrix-row.sh --label "GKE 1.31 default node image"
```

One command, from the released binary, on any host you can get a shell on. Run it on your
own fleet and compare. If your row disagrees with one below, your row is the true one.

## How to read a cell

`enforced` means the kernel refuses the operation and there is no window in which it might
not. `advisory` means it is observed and answered but the decision is not atomic with the
operation. `none` means nothing constrained that capability on that host — and buildclamp
says so rather than reporting enforcement it did not achieve.

The `selftest` column is the one that matters most, because it is the only one that is an
*outcome* rather than a projection. It runs a real process inside the same envelope a build
script gets, with the network denied, and fails if anything in it opened a socket. A host
can report `net: enforced:netns` and still fail to hold a process — a runtime that permits
`unshare` but not `pivot_root`, a profile that lets the filter install and blocks the
notification ioctl — and **a cell where `doctor` says `enforced` and the selftest does not
say `held` is a release blocker**, not a footnote.

## Measured

| host | kernel | Landlock ABI | net | fs-write | env-secret | selftest | measured |
|---|---|---|---|---|---|---|---|
| the development container this was built in | 6.18.44 | 7 | enforced | enforced | enforced | held (enforced:netns) | 2026-09-15 |

**One row. That is the whole of what has been measured, and the table says so rather than
implying a matrix that does not exist yet.** The rows below are the ones the plan calls
for, and each is listed with what is missing rather than with a guess, because a matrix
whose cells are reasoned is a document that tells you what we expect a kernel to do — which
you could have worked out yourself, and which is wrong precisely where it matters.

## Not measured yet

| host | why not, and what it would take |
|---|---|
| pre-Landlock kernel (5.10) | needs a VM. `virtme-ng` or `vmtest` booting a pinned kernel; this environment has no `/dev/kvm` and QEMU without it is too slow for CI |
| Landlock ABI 1–4 | same. ABI is a tier dimension — `landlock-v1` cannot restrict `TRUNCATE`, and the report names the ABI for that reason — so this row is not a formality |
| stock `docker run`, no `--security-opt` | needs a container runtime. This is the row most likely to read `none`, and the most important one to publish: see [Reaching an enforced tier in a container](#reaching-an-enforced-tier-in-a-container) |
| EKS or GKE default node image | needs a managed cluster |
| GitHub Actions `ubuntu-24.04` | the CI job to record it is not written; the runners have user namespaces, so this row is expected to be green and is therefore the least urgent and the least informative |
| static-musl container image | the image does not exist. `Cargo.toml` calls the static binary "a tested artefact" and nothing tests it — the `x86_64-unknown-linux-musl` target is not in this project's CI |

Two of those cells have an oracle the plan asks for and this document does not yet have:
**upstream's own seccomp and Landlock selftests, run first.** A row where the kernel's
selftests pass and buildclamp reports `none` is buildclamp's bug, and a row where both fail
is the kernel's — and without the oracle the two are indistinguishable. Until the VM rows
exist there is nothing to run it against.

## This is a decaying measurement

Re-run it on a schedule and expect the answers to get **worse**, not better. Hosts are
increasingly restricting exactly the primitives this depends on: distributions disabling
unprivileged user namespaces, container runtimes tightening default profiles, managed node
images shipping policies nobody in your organisation chose. Over three years more
environments will report `none`, not fewer.

That is not an argument against the tier ladder. It is the argument for it: a tool that
answered "protected" on all of those hosts would be lying on an increasing fraction of
them, and would have no way to tell you when it started.

## Reaching an enforced tier in a container

A container reporting `none` is usually a policy decision made by the runtime, not a
property of the kernel underneath it — and it is fixable. Run `ops/matrix-row.sh` inside
the container first: that tells you which of the two you have.

### The blunt answer

```console
$ docker run --security-opt seccomp=unconfined --security-opt apparmor=unconfined …
```

It works and it costs something real: the container's own syscall filter is gone for
everything in the image, not only for buildclamp. That is a worse trade than it sounds if
the image runs anything else you did not write. Use it to find out whether seccomp is what
is in the way, then use the narrow answer.

### The narrow answer

```console
$ ops/make-seccomp-profile.sh /usr/share/containers/seccomp.json > buildclamp-seccomp.json
$ docker run --security-opt seccomp=buildclamp-seccomp.json …
```

The profile is produced from **your runtime's own default** plus the syscalls buildclamp
issues. It is generated rather than vendored, and `ops/seccomp-additions.json` explains why
at length: a copy of a three-hundred-name allowlist maintained by hand in this repository
would go stale every time the runtime updated its own, and would be wrong in the direction
that breaks containers.

What it adds, and each entry names the file in `crates/sandbox/src` that issues it:
`unshare`, `clone`, `clone3`, `mount`, `umount2`, `pivot_root`, `seccomp`, `prctl`,
`ioctl`, `capset`, and the three Landlock syscalls (444–446 on x86-64).

The Landlock three are worth singling out. They are newer than most published profiles, and
a profile whose default action is `SCMP_ACT_ERRNO` refuses every syscall it has never heard
of — so on such a host Landlock reports **absent when the kernel has it**, and the symptom
is indistinguishable from an old kernel. If `doctor` says `landlock (filesystem): no` on a
6.x kernel, this is why.

`ops/make-seccomp-profile.sh --check` verifies the additions list against the sandbox source
rather than merging anything: a syscall the sandbox issues and the file does not name is a
container that silently reports a weaker tier, so it fails CI instead.

### Kubernetes

```yaml
spec:
  containers:
    - name: build
      securityContext:
        # Unprivileged user namespaces are what buildclamp uses; it never needs and never
        # asks for privilege. `privileged: true` would also work and is the wrong answer —
        # it hands the container the host's devices and capabilities to solve a problem
        # that is entirely about a seccomp filter.
        privileged: false
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
        seccompProfile:
          # The profile produced above, placed under the kubelet's seccomp root — by
          # default /var/lib/kubelet/seccomp/, so this path is
          # /var/lib/kubelet/seccomp/buildclamp-seccomp.json on the node.
          type: Localhost
          localhostProfile: buildclamp-seccomp.json
```

Two things a cluster operator will ask about, answered here rather than by trial:

* **`RuntimeDefault` is not enough**, for the Landlock reason above: the runtime default
  refuses syscalls it predates. `Unconfined` is enough and is the blunt answer.
* **The kubelet needs the file on the node.** `Localhost` resolves against the node's
  seccomp root, not against a ConfigMap; getting it there is a node-image or DaemonSet
  question, and it is the reason a lot of clusters end up on `Unconfined`.

A pod also needs whatever its cluster's Pod Security admission level permits. The
`baseline` level allows the securityContext above; `restricted` additionally requires
`runAsNonRoot`, which buildclamp is fine with — it needs no privilege and no root.
