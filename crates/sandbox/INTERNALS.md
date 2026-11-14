# `buildclamp-sandbox` internals

A guide for the second engineer. It exists because, until it did, one person could read
this crate and nobody else could, and a project whose entire security value lives in
3,900 lines of `unsafe` cannot have a bus factor of one.

It is not a tour of the API — `cargo doc` does that better. It is the set of things that
are **not visible from the code**: which orderings are load-bearing, what breaks when you
change them, and which of the comments are recording a bug that has already happened once.

Read [`src/lib.rs`]'s module docs first for what the crate promises. This document is
about how it keeps that promise.

---

## 1. The one property

> **A missing mechanism can never result in an unheld run that reports success.**

Everything below is downstream of that sentence. When you are deciding what to do about a
host that lacks something, the question is never "how do we keep the build working" — it
is "how do we keep the build working *while saying accurately what we enforced*", and if
those cannot both be had, the run is refused.

Three structural consequences, all of which you will trip over:

* **`HoldError` has no "ran anyway" variant.** Every variant is a refusal. If you find
  yourself wanting to add one, you are about to reintroduce the failure mode this crate
  was written to avoid.
* **Tiers are computed from mechanisms that were *used*,** never from what the policy
  asked for. `plan_tiers` takes booleans describing what the host gave us, not the
  `Plan`'s wishes. Wiring a policy field into a tier is always a bug.
* **A tier may understate enforcement; it may never overstate it.** The filesystem row
  reports Landlock when both Landlock and the mount namespace applied, because the
  effective policy is their intersection and naming the stronger one understates. That
  direction is fine. The other direction is the thing we criticise competitors for.

---

## 2. Read this before you touch anything: the fork constraint

The supervisor thread must be blocked in `recvmsg` **before** `Command::spawn` is called.
This is because the child's own first `execve` is notified by our own filter, and `spawn`
blocks reading std's close-on-exec pipe until that exec completes. Start the supervisor
after `spawn` and the process pair deadlocks on the very first unit. This was found by
deadlocking a spike; reversing the two statements in `linux::hold` deadlocks again.

That single requirement is what makes this crate hard, because it means **the fork happens
from a multi-threaded process.** Between `fork` and `execve` in a process that had more
than one thread, only async-signal-safe operations are sound: the allocator may be held by
a thread that does not exist on this side of the fork, a `Mutex` may be locked forever, a
panic would unwind through a destroyed runtime.

So everything reachable from the `pre_exec` closure — all of `linux::ns`,
`landlock::restrict_self`, `seccomp::install`, `seccomp::send_listener` — is

* **allocation-free** (no `String`, no `Vec`, no `format!`, no `CString::new`),
* **lock-free** (no `Mutex`, no `OnceLock`, no `lazy_static`, and note that `std::env::var`
  takes a lock),
* **panic-free** (no `unwrap`, no `expect`, no indexing that could be out of range, no
  arithmetic that could overflow in debug),

and issues only raw syscalls against buffers built **before** the fork. `ns::Prepared` is
that pre-built state; `landlock::Ruleset` is the same idea for Landlock; `seccomp::CmsgBuffer`
is the same idea for the control message.

**The review question for any change under `pre_exec` is: does this allocate?** If you
cannot answer no with certainty, it does not go there. Move the work into `Prepared::new`
or into `hold` and pass the result down as a plain integer, a `CString`, or a fixed array.

This is also why `landlock::Ruleset` is not itself captured by the closure — only its raw
fd is. `Ruleset` has a `Drop` that closes the descriptor, and a captured `Ruleset` would be
dropped in whichever process ran the closure last, closing an fd the other one still needs.
The `Ruleset` stays alive in `hold`'s scope until after `spawn` has forked; the closure
captures a `Copy` integer.

---

## 3. File map

| file | lines | `unsafe` blocks / fns | what it is |
|---|---:|---:|---|
| `src/lib.rs` | 440 | 0 / 0 | `Plan`, `Held`, `HoldError`, the tier constructors, the `Decider` the supervisor applies. Knows nothing about cargo, and must not: the translation from policy to `Plan` lives in `buildclamp-shim`, the only crate that knows both. |
| `src/probe.rs` | 327 | 9 / 0 | What this host can actually do, found out by trying. |
| `src/linux/mod.rs` | 552 | 4 / 0 | `hold()` — the one order that works — and `plan_tiers()`. |
| `src/linux/ns.rs` | 505 | 3 / 6 | Everything that runs in the forked child: namespaces, read-only root, the capability lock. |
| `src/linux/landlock.rs` | 474 | 6 / 1 | The preferred filesystem rung. Ruleset built in the parent, one syscall in the child. |
| `src/linux/seccomp.rs` | 651 | 9 / 3 | Filter installation, listener hand-off, and the supervisor loop. |
| `src/linux/bpf.rs` | 742 | 0 / 0 | The classic-BPF program, written out by hand. Pure, and therefore heavily unit-tested (13 tests). |
| `src/linux/attribution.rs` | 255 | 0 / 0 | Which proc-macro made a request, and how confident we are. |

Every `unsafe` block in the project is in this crate. Every other crate — `buildclamp-core`,
`buildclamp-shim`, `cargo-buildclamp` — carries `#![forbid(unsafe_code)]`, so the
confinement is checked by the compiler rather than asserted in a README.

Note the shape of the table: **the two files with no `unsafe` have the most tests.** That is
not an accident of effort, it is the tractability gradient. `bpf::build` is a pure function
from options to instructions, so its behaviour can be asserted exhaustively; `ns::apply_in_child`
can only really be tested by running it. Where you can move logic into the pure half, do.

---

## 4. The `hold()` sequence, and why each step is where it is

Reading `linux::hold` top to bottom, the steps are:

1. **Probe the host.** Never `uname`. See §8.
2. **Decide the ladder before doing anything**, so the tiers reported are the ones actually
   attempted rather than a guess reconstructed afterwards.
3. **Refuse if nothing is available.** No user namespaces *and* no seccomp notification is
   `HoldError::NothingAvailable`. This is the branch the whole crate exists for.
4. **Build the Landlock ruleset** — in the parent, where allocating is safe. Attempted
   whenever the run is enforcing at all, because Landlock does not need a user namespace;
   on a host with Landlock but no user namespaces this is the difference between a
   kernel-enforced filesystem tier and `advisory:seccomp-notify`. A ruleset that cannot be
   built is reported to stderr and then ignored, because the mount namespace is still there.
5. **Compute the tiers** from what steps 1–4 actually yielded.
6. **Build `ns::Prepared`** — every path as a `CString`, both maps pre-formatted, the uid
   and gid captured. See §5 for why the capture must happen here.
7. **Build the BPF program.**
8. **Create the socketpair** that will carry the listener descriptor out of the child, and
   the `CmsgBuffer` the child will write four bytes into.
9. **Install `pre_exec`** — see §5 for the ordering *inside* it, which is also load-bearing.
10. **Set the environment**, including removing `BUILDCLAMP_POLICY` and setting the
    inside-marker so a nested invocation can tell.
11. **Start the supervisor thread**, and only then
12. **`spawn`.** Steps 11 and 12 cannot be swapped (§2).
13. **`wait`, stop the supervisor, collect the requests.**

Observe mode short-circuits most of this: it applies **no** enforcement — no empty network
namespace, no read-only root, no PID namespace — only the notification filter, which
refuses nothing. That is deliberate and it is not a shortcut. A build behaves differently
inside a namespace: a connection fails with a different errno, a temporary file lands
somewhere else. Observe mode's answer has to describe the build as it runs on the machine
it normally runs on, or the policy generated from it describes a build nobody has.

---

## 5. The orderings that cost a spike each

This is the section to re-read before changing `ns.rs` or the `pre_exec` closure. Each row
is a bug that has already happened once.

| # | the rule | what happens if you violate it |
|---|---|---|
| 1 | Supervisor thread receiving **before** `spawn` | Deadlock on the first unit, every time. |
| 2 | uid/gid captured **before** the fork | After `unshare(CLONE_NEWUSER)` and before the map is written, `getuid()` returns the overflow uid 65534, and mapping *that* fails `EPERM`. |
| 3 | `setgroups`/`uid_map`/`gid_map` written **before** any mount change | procfs writes take `mnt_want_write`, so once `/proc` is inside a read-only tree this is `EROFS`. And an unmapped process cannot create a file on a filesystem it just mounted — `EOVERFLOW`, because its fsuid has no mapping in the superblock's user namespace. Both were observed. |
| 4 | Writable directories `open_tree`-cloned **before** the root is marked read-only | After the root is read-only there is nothing writable left to clone from. |
| 5 | `no_new_privs` set on **every** path that returns `Ok` from `apply_in_child` | `SECCOMP_SET_MODE_FILTER` returns `EACCES` for a caller with neither `CAP_SYS_ADMIN` nor `no_new_privs`. An earlier version returned plain `Ok(())` on the no-namespace path, so every observe run on every host — and every run on a host without user namespaces, the exact case that branch exists to serve — failed at `spawn` with `Permission denied` before the unit started. |
| 6 | `landlock_restrict_self` **after** `apply_in_child`, **before** the seccomp filter | It needs `no_new_privs` and returns `EPERM` without it; and putting it before the filter means the filter can never be the thing that refuses it on some future host with a stricter allowlist. |
| 7 | `chdir` restored **after** `pivot_root` | `pivot_root` rewrites cwd only for processes whose cwd *was* the old root. Cargo runs build scripts with cwd set to the manifest directory, so without this every unit keeps a handle into the detached, still-writable old tree. This is every unit, not a corner case. |
| 8 | `drop_all_capabilities` **last**, and never optional | Without it the read-only root is **decorative**: a spike child ran `mount -o remount,bind,rw /` and wrote to `/root`. There is deliberately no option to switch it off. |
| 9 | The architecture gate **first** in the BPF program, and it kills | A filter that checked `SYS_connect` without pinning the architecture would, under a 32-bit compat call, be testing an unrelated syscall. That is the classic seccomp bypass. On x86-64 the gate also kills the x32 ABI, which reports the same `arch` but renumbers syscalls with bit `0x40000000` set. |
| 10 | The notification buffer re-zeroed **every** iteration | The kernel rejects a buffer that is not zeroed, the previous notification's bytes are still in it, and the resulting `EINVAL` is silent. |
| 11 | The stop channel checked **only** in the `TimedOut` branch | `NOTIF_RECV` blocks forever when there is nothing to receive, so treating a timeout as readable hangs the build. It did, once. |

### Failure inside `pre_exec` fails the unit, deliberately

Every other fallback in this crate happens in the parent, where there is still a decision to
make and a tier to record. By the time the child is running, the tier has already been
reported — so a Landlock failure there would mean a report naming a mechanism that did not
apply. That is the one thing a report must never do, so the unit dies instead.

The two survivable exceptions inside the child are both cases where the report still
reflects reality: a writable directory that does not exist yet is skipped (the report shows
what was granted), and a cwd that does not exist inside the new tree falls back to `/`.

### `make_root_read_only` is Recipe B, on purpose

Clone the whole tree with `open_tree(OPEN_TREE_CLONE|AT_RECURSIVE)`, mark it read-only
atomically with `mount_setattr`, `move_mount` it to a scratch point on a fresh tmpfs,
`pivot_root(".", ".")`, `fchdir` to the old root and `umount2(MNT_DETACH)` it.

The alternative — walking `/proc/self/mountinfo` and remounting each entry read-only — was
rejected for two reasons. It needs flag archaeology, because a remount inside a user
namespace must preserve each mount's existing locked flags or fail `EPERM`. And cloning the
whole tree also handles hidden duplicate mounts, which a mountinfo walk leaves writable and
unreachable. `pivot_root(".", ".")` stacks the old root on the new one, so detaching it
leaves no `put_old` directory behind and nothing of the host tree reachable.

### The environment tier names the **user** namespace, and the obvious answer is wrong

This used to report `scrub+pidns`, reasoning that a PID namespace hides the processes whose
`/proc/<pid>/environ` a unit would read. It does not, for two separate reasons.
`unshare(CLONE_NEWPID)` does not move the caller into the new namespace — it sets
`pid_for_children`, so the first process forked *afterwards* becomes pid 1 there, and
`apply_in_child` unshares and then `execve`s with no fork in between. And measured on its
own, `CLONE_NEWPID` does not stop the read at all.

What stops it is `CLONE_NEWUSER`: a process in a child user namespace cannot pass
`ptrace_may_access` against a process in the parent one, so the open returns `EPERM` before
a byte is read.

| unshared | read of a same-uid process's environ |
|---|---|
| nothing | 4096 bytes |
| `CLONE_NEWPID` | 4096 bytes |
| `CLONE_NEWUSER` | `EPERM` |

**`CLONE_NEWPID` is no longer requested at all**, and the reason is a second measurement
rather than the first. Unsharing it sets `pid_for_children` without moving the caller, so
the caller's pid namespace and its children's differ from that point — and the kernel
refuses `CLONE_THREAD` in that state, `copy_process` returning `-EINVAL`. A held unit
therefore could not create a thread:

| state | `pthread_create` |
|---|---|
| before any unshare | ok |
| after `unshare(CLONE_NEWUSER)` | ok |
| after `unshare(CLONE_NEWPID)` | `EINVAL` |

`cc` compiles in parallel with threads, `bindgen` uses them, and rustc panics at startup
because `install_ctrlc_handler` spawns one — which is how this was found, while putting
rustc under the sandbox for the first time. What it bought was a private PID namespace for
whatever the unit *spawns*; the unit itself was never in it, so the restriction only ever
applied to children of untrusted code that the untrusted code could sidestep by doing the
work itself. `tests/fixtures/threaded` is the regression guard.

Anyone tempted to drop `CLONE_NEWUSER` for a host that dislikes it should read the environ
table above first: it is load-bearing for a row of the report. Making the unit itself pid 1
would need a second fork between the unshare and the exec, with this process relaying the
grandchild's exit status and re-raising its signal, and the listener installed on the far
side of that fork.

---

## 6. The filter and the supervisor

### What the filter refuses unconditionally

`io_uring_setup`, `io_uring_enter` and `io_uring_register` return `EPERM` in every mode,
with no policy knob, alongside `ptrace`. The reason is structural rather than a judgement
about the syscalls: every other check in the filter matches a syscall *number*, and
`io_uring` exists to perform work without issuing the syscall that names it. A unit that can
call `io_uring_setup` can open, connect and send through queue entries the filter never
sees. Adding a knob for these would be adding a knob that switches off everything else.

### Read-only opens are not notified

The filter tests the open flags in BPF and notifies only when one of `O_WRONLY`, `O_RDWR`,
`O_CREAT` or `O_TRUNC` is set. Measured: 2,000 read-only opens produce **zero**
notifications, against 10–40 µs each if they did. rustc opens thousands of files per
compile. This is the difference between a tool people keep and one they remove, and it is
why performance work belongs in the BPF program rather than in the supervisor loop.

### Why notification decisions are advisory, and errno responses are not

`SECCOMP_USER_NOTIF_FLAG_CONTINUE` tells the kernel to run the syscall after the supervisor
answers — and the kernel then **re-reads the arguments**. A path or address read out of the
target's memory before answering can be changed in between. So a notification-based file
policy is good enough to *see* what a build does and not good enough to call enforcement;
the tier says `advisory` and carries the sentence explaining why.

An errno response is different: the syscall never runs, so there is no window and nothing to
race. That is why the network row reports `enforced:seccomp-errno` on a host with no
namespaces while the filesystem row on the same host reports `advisory:seccomp-notify`. If
that distinction ever looks like pedantry, it is the distinction the entire tier ladder is
made of.

### `Decision::AllowButWouldRefuse` is not decoration

Without that variant, observe mode records every request as granted, `init` generates no
grants, and the operator is told their build is clean when enforcing it would break — which
is precisely the discovery observe mode exists to spare them.

---

## 7. Landlock

**Raw syscalls, not the `landlock` crate,** and the second reason is not a preference.
`restrict_self` runs in the child, so it must not allocate; every ergonomic Landlock API
allocates, because building a ruleset means building a list. The split here — ruleset
constructed in the parent, child issues exactly one syscall against the inherited
descriptor — is the only shape that works, and a dependency cannot be adapted into it from
outside. It is the same reasoning the workspace manifest already gives for not taking
`seccompiler`: the thing a reviewer has to audit should be in the repository.

**Landlock denies by default only the rights a ruleset declares it handles.** Anything
outside `handled_access_fs` is untouched, so the handled set is exactly the write-shaped
rights:

* **not `EXECUTE`** — build scripts run `cc`, `pkg-config` and `git`; handling exec would
  deny every one of them outside a write zone.
* **`READ_FILE` / `READ_DIR` only when the policy withholds a path** — reads are
  unrestricted by default and the README says
  so. Handling reads here would silently make the tool do something its own documentation
  says it does not. (Read-deny is a scheduled feature with its own tier and its own
  documentation change; it does not arrive by quietly widening this constant.)
* **not `IOCTL_DEV`** — not a write, and ABI 5+ only.

ABI is a **tier dimension**, not a boolean: `handled_access` and `endpoint_access` are both
functions of the probed ABI, and the mechanism string carries the version (`landlock-v7`)
so a report says which kernel's Landlock it got.

---

## 8. Probing: a probe must test the whole thing it claims to predict

Nothing here is inferred from a kernel version string, because the version does not decide
any of it. Landlock can be compiled out, disabled at boot with `lsm=`, or blocked by a
container runtime's seccomp profile — this project's own host returns `ENOSYS` despite
running 6.18, which is how the fallback path came to be tested rather than assumed. User
namespaces are blocked by `kernel.unprivileged_userns_clone=0` on some distributions, by
`kernel.apparmor_restrict_unprivileged_userns=1` on Ubuntu 24.04 for unconfined binaries,
and by the default Docker seccomp profile, which denies `unshare` outright.

And a partial probe is worse than none. `unshare(CLONE_NEWUSER)` succeeding does not mean a
unit can be held: the child setup also writes three procfs maps, clones the mount tree,
marks it read-only, mounts a tmpfs and pivots into it. A host can allow the first and refuse
a later one — a GitHub Actions runner does exactly that — and an earlier probe that stopped
at the first syscall reported `user namespaces: yes` while every held unit died at `spawn`.

So `user_namespaces_work` runs **the real setup**, in a forked child, and reports whether it
survived. `doctor`, the enforcement path and the tests that gate on host capability then
agree because they are the same code rather than three readings of it.

**If you add a step to `apply_in_child`, add it to the probe's child too.** A step that is
in one and not the other reintroduces exactly this bug.

---

## 9. Attribution

A proc-macro is a shared object rustc loads and calls while compiling the consumer. There is
no separate process, so a sandbox around rustc constrains every proc-macro in that
compilation identically. The incumbent documents that limitation: one grant covers every
proc-macro in the build.

This module does better and **says how confident it is**:

| source | confidence |
|---|---|
| the instruction pointer at the syscall is inside a known proc-macro's `.so` | `exact` |
| it is in libc or libstd, but a stack scan finds that `.so`'s frame | `stack-scan` |
| neither | `closure` — what every other tool gives |

It degrades to the incumbent's answer, never to nothing. The stack scan is a heuristic and
is labelled one, because scanning the stack region for values inside a mapped `.so` will
also find stale frames from a call that already returned. Presenting a scan hit as certain
would be the overclaiming this project criticises in others — so if you improve the scan,
improve the *label* with it, and do not collapse the three-way distinction into a boolean.

---

## 10. Working on this crate

### Testing a fallback on a host that has everything

`BUILDCLAMP_DISABLE=ns,notify` (comma-separated, either or both) switches mechanisms off.
This exists for one reason and it is not debugging: **the fallback tiers have to be testable
on a host that has everything.** Without it, the advisory path and the refuse-rather-than-run
path could only be exercised on a machine that happened to lack the mechanism — which means
in practice they would be exercised by a user rather than by a test.

It can only ever take capability away, never add it, so a build that sets it gets less
enforcement and a report that says so. That is the safe direction for a switch to point, and
any new switch here must point the same way.

### Where to put a test

* **Pure logic** — `bpf::build`, `plan_tiers`, `attribution::owner_of`, path containment —
  goes in a unit test. These are cheap, they run everywhere including non-Linux, and they
  are where the density should be.
* **Anything that must actually be held** goes in the CLI end-to-end tests against the
  fixtures. Those tests must **fail rather than skip** when they cannot determine the host:
  a suite that silently skips reports "passed" while asserting nothing, and this repository
  has already shipped that bug once.
* **A tier claim** — that a mechanism produces the tier we say it produces — is a unit test
  on `plan_tiers` *plus* a fixture that demonstrates the mechanism, because the first alone
  only proves we are self-consistent.

### Things that are not safe to do

* Adding anything to the `pre_exec` closure without proving it cannot allocate (§2).
* Reordering `hold` or `apply_in_child` without reading §5.
* Making `drop_all_capabilities` conditional (§5, row 8).
* Making the `io_uring` refusal conditional (§6).
* Widening `handled_access` to cover reads without the documentation change that goes with
  it (§7).
* Adding a `Tier::Enforced` for a mechanism whose refusal happens after the syscall has run
  (§6).
* Adding a `HoldError` variant that means "we ran it anyway" (§1).

### A note on the comments

The comments in this crate are unusually long and they are not decoration. Where one says a
thing "was found by deadlocking a spike" or "was observed", it is recording a bug that has
already happened, and the sentence is there to stop the next person re-deriving it at the
cost of a day. Prune them at your own risk; if one turns out to be wrong, **correct it
rather than deleting it**, because a wrong comment and a missing comment cost the same to
discover and the missing one costs more to replace.
