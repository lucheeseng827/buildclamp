//! Linux enforcement: putting the pieces in the one order that works.
//!
//! The ordering below is not stylistic. Every step was placed by a spike that failed when
//! it was somewhere else, and the comments say which failure.

pub mod attribution;
pub mod bpf;
pub mod bpfcheck;
pub mod landlock;
pub mod ns;
pub mod seccomp;

use std::collections::BTreeMap;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::mpsc;
use std::time::Instant;

use buildclamp_core::{Capability, Forward, Tier};

use crate::{advisory, enforced, none, Held, HoldError, Plan, NOTIFY_LIMITATION};

/// Run `command` under `plan`.
pub fn hold(plan: &Plan, mut command: Command) -> Result<Held, HoldError> {
    let started = Instant::now();
    let host = crate::probe::host();

    // Decide the ladder before doing anything, so the tiers reported are the ones that
    // were actually attempted rather than a guess made afterwards.
    let disabled = Disabled::from_env();
    let use_ns = host.user_namespaces && !disabled.ns;
    let use_notify = host.seccomp_user_notif && !disabled.notify;

    if !use_ns && !use_notify {
        // Nothing at all is available. Refuse rather than run unheld: a tool that reports
        // success while enforcing nothing is worse than no tool, and this is the exact
        // failure mode of the nearest alternative.
        return Err(HoldError::NothingAvailable(format!(
            "no user namespaces and no seccomp notification on {} {}",
            host.os, host.kernel
        )));
    }

    // Observe mode applies NO enforcement — no empty network namespace, no read-only
    // root, no PID namespace. Only the notification filter, which refuses nothing.
    //
    // This is not a shortcut. A build behaves differently inside a namespace: a connection
    // fails with a different errno, the process list is shorter, a temporary file lands
    // somewhere else. Observe mode's answer has to be what the build does on the machine it
    // normally runs on, or the policy generated from it describes a build nobody has.
    let enforcing = use_ns && !plan.observe_only;

    // The Landlock ruleset, built HERE — in the parent, where allocating is safe. The
    // child issues one syscall against the descriptor and nothing else; see
    // `landlock::restrict_self` for why that split is a requirement and not a preference.
    //
    // It does not need a user namespace, so it is attempted whenever the run is enforcing
    // at all. On a host with Landlock but no user namespaces this is the difference
    // between a kernel-enforced filesystem tier and `advisory:seccomp-notify`.
    //
    // A ruleset that cannot be built is reported and then ignored: the mount namespace is
    // still there, and refusing the unit over a mechanism we have a fallback for would be
    // a worse trade than taking the fallback and naming it.
    let landlock_ruleset = if plan.observe_only {
        None
    } else {
        match host.landlock_abi {
            Some(abi) => {
                match landlock::Ruleset::build(abi, &plan.writable, &plan.withheld_reads) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!(
                            "buildclamp: this host reports Landlock ABI {abi} but refused the \
                         ruleset (errno {e}); falling back to the mount namespace"
                        );
                        None
                    }
                }
            }
            None => None,
        }
    };

    let tiers = plan_tiers(
        plan,
        enforcing,
        use_notify,
        landlock_ruleset.as_ref().map(|r| r.mechanism()),
    );

    // Everything the child will need, built here where allocating is safe. After the fork
    // the child cannot allocate: the allocator may be held by a thread that does not exist
    // there any more.
    let prepared = ns::Prepared::new(
        enforcing,
        enforcing && !plan.allow_net,
        enforcing,
        &plan.writable,
        command
            .get_current_dir()
            .map(|p| p.to_path_buf())
            .as_deref(),
    )
    .map_err(|e| HoldError::Setup(e.to_string()))?;

    let program = bpf::build(&bpf::FilterOptions {
        // Writes are notified only when asked for, or when there is no kernel-enforced
        // filesystem tier to fall back on — in which case notification is all there is,
        // and the tier says `advisory` for exactly that reason.
        observe_writes: plan.observe_writes || plan.observe_only || !use_ns,
        observe_net: use_notify,
        arch: bpf::Arch::NATIVE,
    })
    .map_err(HoldError::Setup)?;

    // The socketpair that carries the listener descriptor out of the child.
    let (parent_sock, child_sock) = socketpair().map_err(|e| HoldError::Setup(e.to_string()))?;

    // Built before the fork: the child writes only four bytes into it.
    let mut cmsg = seccomp::CmsgBuffer::new();

    let install_filter = use_notify;
    let child_sock_raw = child_sock;
    let parent_sock_raw = parent_sock;
    // A bare descriptor, so the closure captures a `Copy` integer and not the `Ruleset`,
    // whose `Drop` would close the fd in whichever process ran it last. The `Ruleset`
    // itself stays alive in this scope until after `spawn` has forked.
    let landlock_fd = landlock_ruleset.as_ref().map_or(-1, |r| r.raw_fd());

    // SAFETY: `pre_exec` runs between fork and exec in a process that has a supervisor
    // thread, so it must not allocate, lock or panic. Everything it touches — `prepared`,
    // `program`, `cmsg` — was built above; the closure only issues raw syscalls against
    // them and returns an `io::Error` built from a raw errno, which allocates nothing.
    unsafe {
        command.pre_exec(move || {
            libc::close(parent_sock_raw);
            if let Err(e) = prepared.apply_in_child() {
                return Err(std::io::Error::from_raw_os_error(e));
            }
            // After `apply_in_child`, which sets `no_new_privs` on every path it returns
            // `Ok` from — `landlock_restrict_self` needs it and returns EPERM without it.
            // Before the seccomp filter, so the filter cannot be the thing that refuses
            // this syscall on some future host with a stricter allowlist.
            //
            // A failure here fails the UNIT, deliberately. Every other fallback in this
            // file happens in the parent, where there is still a decision to make and a
            // tier to record; by this point the tier has been reported as Landlock and
            // running on would mean the report naming a mechanism that did not apply.
            if landlock_fd >= 0 {
                if let Err(e) = landlock::restrict_self(landlock_fd) {
                    return Err(std::io::Error::from_raw_os_error(e));
                }
            }
            if install_filter {
                let listener =
                    seccomp::install(&program).map_err(std::io::Error::from_raw_os_error)?;
                seccomp::send_listener(child_sock_raw, listener, &mut cmsg)
                    .map_err(std::io::Error::from_raw_os_error)?;
                libc::close(listener);
            }
            libc::close(child_sock_raw);
            Ok(())
        });
    }

    for (k, v) in &plan.env {
        command.env(k, v);
    }
    command.env_remove("BUILDCLAMP_POLICY");
    command.env(buildclamp_core::ENV_INSIDE, "1");
    if let Some(tmp) = &plan.private_tmp {
        command.env("TMPDIR", tmp);
    }

    // The supervisor must be receiving BEFORE the child is spawned. The child's own first
    // `execve` is notified, and `spawn` blocks until exec completes, so starting the
    // supervisor afterwards deadlocks on the very first unit. This was found by
    // deadlocking a spike; reversing these two statements deadlocks again.
    let (stop_tx, stop_rx) = mpsc::channel();
    let (req_tx, req_rx) = mpsc::channel();
    let decider = plan.decider();
    let macros = plan.proc_macro_objects.clone();
    let skip_exec = plan.skip_exec_target.clone();
    let supervisor = if install_filter {
        Some(std::thread::spawn(move || {
            match seccomp::recv_listener(parent_sock_raw) {
                Ok(Some(listener)) => {
                    let reqs =
                        seccomp::supervise(listener, decider, macros, skip_exec, stop_rx, started);
                    let _ = req_tx.send(reqs);
                }
                // End of file: the child died in `pre_exec` before it could send anything.
                // Not an error here — `wait` below reports what actually happened.
                _ => {
                    let _ = req_tx.send(Vec::new());
                }
            }
            unsafe { libc::close(parent_sock_raw) };
        }))
    } else {
        None
    };

    let mut child = command.spawn().map_err(HoldError::Spawn)?;
    // SAFETY: the child owns its end now.
    unsafe { libc::close(child_sock_raw) };

    let status = child.wait().map_err(HoldError::Spawn)?;
    let _ = stop_tx.send(());
    let requests = match supervisor {
        Some(h) => {
            let reqs = req_rx.recv().unwrap_or_default();
            let _ = h.join();
            reqs
        }
        None => Vec::new(),
    };

    Ok(Held {
        tiers,
        requests,
        exit_code: status.code(),
        signal: exit_signal(&status),
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// What actually constrained each capability, given what this host has.
///
/// Computed from the mechanisms that were *used*, never from what the policy asked for. A
/// tier is a statement about the machine the build ran on.
pub(crate) fn plan_tiers(
    plan: &Plan,
    use_ns: bool,
    use_notify: bool,
    landlock: Option<String>,
) -> BTreeMap<Forward<Capability>, Tier> {
    let mut t: BTreeMap<Forward<Capability>, Tier> = BTreeMap::new();

    if plan.observe_only {
        // Observe mode enforces nothing by design, and saying so per capability is more
        // honest than reporting the tier that would have applied. `--require-enforced`
        // therefore refuses an observe run, which is correct: it did not enforce.
        for cap in Capability::ALL {
            t.insert(cap.into(), none("observe mode: recorded, nothing enforced"));
        }
        return t;
    }

    t.insert(
        Capability::Net.into(),
        if plan.allow_net {
            none("the policy grants this unit the network")
        } else if use_ns {
            enforced("netns")
        } else if use_notify {
            // Without a namespace the only refusal available is an errno from the
            // supervisor — which IS authoritative, unlike an allowed call, because the
            // syscall never runs. So this is enforcement, by a weaker mechanism.
            enforced("seccomp-errno")
        } else {
            none("neither a network namespace nor seccomp is available on this host")
        },
    );

    // `unix` is granted by default and, until this row existed, was the one capability the
    // report never carried a tier for. A capability with no tier is an outcome recorded
    // without saying how it was constrained — the single thing the schema is built to make
    // impossible — and it went unnoticed precisely because the default is "allowed": the
    // row that would have been missing is the one nobody looks at. The unit test below no
    // longer excuses it.
    t.insert(
        Capability::Unix.into(),
        if plan.allow_unix {
            none("the policy grants this unit unix sockets")
        } else if use_notify {
            // The supervisor answers `socket`/`connect` with EPERM, so the syscall never
            // runs — the same authoritative-refusal argument as the `seccomp-errno` rung
            // for the network, and it is deliberately the same mechanism string.
            //
            // The network namespace is NOT named here even though the unit is in one.
            // An empty netns isolates the *abstract* unix namespace but not path-bound
            // sockets, and `/var/run/docker.sock` and the ssh agent are path-bound. A
            // tier that claimed `netns` would be claiming enforcement for the half that
            // matters on the strength of the half that does not.
            enforced("seccomp-errno")
        } else {
            none("seccomp notification is unavailable, so unix sockets cannot be refused")
        },
    );

    // Reads. The tier is `none` in two very different situations and the reason has to
    // tell them apart, because one is a decision and the other is a missing mechanism —
    // the same distinction `disable_overrides` exists for one level up.
    t.insert(
        Capability::FsRead.into(),
        if plan.withheld_reads.is_empty() {
            none("the policy withholds no reads; every path on this host is readable")
        } else if let Some(mechanism) = landlock.as_deref() {
            enforced(mechanism)
        } else {
            // Deliberately NOT an advisory seccomp tier. The supervisor could answer
            // `openat` and decide on the path, and it would cost 10–40 µs per open on a
            // syscall rustc issues thousands of times per build — a measurable slowdown on
            // every build, buying a tier that is defeatable by construction. Refusing to
            // offer it is the honest answer: this host cannot restrict reads.
            none(
                "landlock is absent on this host, so withheld paths cannot be made \
                 unreadable; a mount namespace cannot express a read restriction and \
                 seccomp could only do it advisorily, at 10–40 µs on every file rustc opens",
            )
        },
    );

    t.insert(
        Capability::FsWrite.into(),
        // Landlock first: it is the preferred rung, it does not need a user namespace, and
        // where both applied naming it is naming the stronger of the two. The mount
        // namespace is still in place underneath — the effective policy is the
        // intersection — so this label understates the enforcement rather than
        // overstating it, which is the only direction a tier is allowed to be wrong in.
        if let Some(mechanism) = landlock {
            enforced(&mechanism)
        } else if use_ns {
            enforced("mountns-ro")
        } else if use_notify {
            advisory("seccomp-notify", NOTIFY_LIMITATION)
        } else {
            none("neither a mount namespace nor seccomp is available on this host")
        },
    );

    // The mechanism here is the **user** namespace, and it took an experiment to find
    // that out, because the obvious answer is wrong.
    //
    // This used to report `scrub+pidns`, on the reasoning that a PID namespace hides the
    // processes whose `/proc/<pid>/environ` a unit would read. It does not, for two
    // separate reasons. `unshare(CLONE_NEWPID)` does not move the caller into the new
    // namespace — it sets `pid_for_children`, so the first process forked *afterwards*
    // becomes pid 1 there, and `apply_in_child` unshares and then `execve`s with no fork
    // in between. And measured on its own, `CLONE_NEWPID` does not stop the read at all.
    //
    // What stops it is `CLONE_NEWUSER`. A process in a child user namespace cannot pass
    // `ptrace_may_access` against a process in the parent one, so opening
    // `/proc/<pid>/environ` returns EPERM before a byte is read. Unsharing each flag
    // alone and attempting the read is what separates them:
    //
    // | unshared                 | read of a same-uid process's environ |
    // |--------------------------|--------------------------------------|
    // | nothing                  | 4096 bytes                           |
    // | `CLONE_NEWPID`           | 4096 bytes                           |
    // | `CLONE_NEWUSER`          | `EPERM`                              |
    //
    // So this is real enforcement — the open fails in the kernel, with no supervisor and
    // no race — and the name now says which mechanism delivers it. The PID namespace is
    // still requested and still worth requesting, but for what the unit *spawns*; see the
    // note in `ns::apply_in_child`. Anyone tempted to drop `CLONE_NEWUSER` for a host
    // that dislikes it should read this table first: it is load-bearing for this row.
    t.insert(
        Capability::EnvSecret.into(),
        if use_ns {
            enforced("scrub+userns")
        } else {
            advisory(
                "scrub",
                "the unit's own environment is scrubbed, but without a user namespace it \
                 can still read /proc/<pid>/environ of any process the same user owns, \
                 including cargo's",
            )
        },
    );

    t.insert(
        Capability::Exec.into(),
        if use_notify {
            // Advisory, NOT enforced, and the distinction is the same one the sibling test
            // `a_seccomp_errno_refusal_is_enforcement_but_a_notification_decision_is_not`
            // draws for the network. Exec is *recorded* and never refused — see
            // `PlanDecider::decide`, whose `_ => Decision::Allow` arm and comment say so —
            // and the recording arrives by seccomp notification, answered with CONTINUE. The
            // kernel re-reads the path after that answer, so the binary that runs can differ
            // from the one recorded. A capability the kernel never refuses, decided through
            // the racy mechanism, is advisory by this project's own definition; calling it
            // `enforced` was promoting a CONTINUE observation to a guarantee, which
            // `crates/sandbox/tests/no_continue_is_enforced.rs` now forbids.
            advisory(
                "seccomp-notify-record",
                "exec is recorded, never refused, and the kernel re-reads the path after                  the notification is answered, so the binary that runs can differ from the                  one recorded; a spawned process does inherit every namespace and the                  seccomp filter, so it is held as tightly as its parent",
            )
        } else {
            none("seccomp notification is unavailable, so exec cannot be recorded")
        },
    );

    t
}

fn exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

fn socketpair() -> std::io::Result<(RawFd, RawFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a live array of the right size; `socketpair` writes two descriptors.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

/// Mechanisms switched off by `BUILDCLAMP_DISABLE`.
///
/// A comma-separated list of `ns` and `notify`. This exists for one reason that is not
/// debugging: **the fallback tiers have to be testable on a host that has everything.**
/// Without it, the advisory path and the refuse-rather-than-run path could only be
/// exercised on a machine that happened to lack the mechanism, which means in practice
/// they would be exercised by a user rather than by a test.
///
/// It can only ever take capability away, never add it, so a build that sets it gets less
/// enforcement and a report that says so — which is the safe direction for a switch to
/// point.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Disabled {
    pub(crate) ns: bool,
    pub(crate) notify: bool,
}

impl Disabled {
    pub(crate) fn from_env() -> Self {
        match std::env::var("BUILDCLAMP_DISABLE") {
            Ok(v) => Self {
                ns: v.split(',').any(|s| s.trim() == "ns"),
                notify: v.split(',').any(|s| s.trim() == "notify"),
            },
            Err(_) => Self::default(),
        }
    }
}

/// Map a syscall number to its name, for the report.
///
/// Only the syscalls the filter can notify on are here; anything else means the filter and
/// this table disagree, which is a bug worth seeing in a report rather than hiding.
pub(crate) fn syscall_name(nr: i64) -> &'static str {
    #[cfg(target_arch = "aarch64")]
    let table: &[(i64, &str)] = &[
        (198, "socket"),
        (203, "connect"),
        (206, "sendto"),
        (211, "sendmsg"),
        (269, "sendmmsg"),
        (221, "execve"),
        (281, "execveat"),
        (56, "openat"),
        (437, "openat2"),
        (34, "mkdirat"),
        (35, "unlinkat"),
        (276, "renameat2"),
        (36, "symlinkat"),
        (37, "linkat"),
        (45, "truncate"),
        (53, "fchmodat"),
    ];
    #[cfg(not(target_arch = "aarch64"))]
    let table: &[(i64, &str)] = &[
        (41, "socket"),
        (42, "connect"),
        (44, "sendto"),
        (46, "sendmsg"),
        (307, "sendmmsg"),
        (59, "execve"),
        (322, "execveat"),
        (2, "open"),
        (257, "openat"),
        (437, "openat2"),
        (85, "creat"),
        (83, "mkdir"),
        (258, "mkdirat"),
        (87, "unlink"),
        (263, "unlinkat"),
        (84, "rmdir"),
        (82, "rename"),
        (264, "renameat"),
        (316, "renameat2"),
        (88, "symlink"),
        (266, "symlinkat"),
        (86, "link"),
        (265, "linkat"),
        (76, "truncate"),
        (90, "chmod"),
        (268, "fchmodat"),
    ];
    table
        .iter()
        .find(|(n, _)| *n == nr)
        .map(|(_, s)| *s)
        .unwrap_or("unknown-syscall")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_a_namespace_the_environment_tier_admits_the_proc_hole() {
        // Scrubbing a unit's own environment does not stop it reading cargo's through
        // /proc. Reporting that as "enforced" would be the overstatement this project
        // exists to avoid, and a fixture in this repository proves the hole is real.
        let t = plan_tiers(&Plan::default(), false, true, None);
        let (_, tier) = t.get_key_value(&Capability::EnvSecret.into()).unwrap();
        match tier {
            Tier::Advisory { limitation, .. } => {
                assert!(limitation.contains("without a user namespace"));
                assert!(limitation.contains("/proc/<pid>/environ"))
            }
            other => panic!("expected an advisory tier without a PID namespace, got {other:?}"),
        }
    }

    #[test]
    fn the_environment_tier_names_the_user_namespace_and_not_the_pid_namespace() {
        // Measured, not assumed: unsharing CLONE_NEWPID alone still lets a process read a
        // same-uid process's /proc/<pid>/environ, and unsharing CLONE_NEWUSER alone stops
        // it with EPERM. Naming `pidns` here credited the wrong mechanism — and it was
        // additionally wrong because unshare(CLONE_NEWPID) moves the next process forked,
        // not the caller, and the unit execs without forking.
        let t = plan_tiers(&Plan::default(), true, true, None);
        let (_, tier) = t.get_key_value(&Capability::EnvSecret.into()).unwrap();
        match tier {
            Tier::Enforced { mechanism } => {
                assert!(
                    mechanism.contains("userns"),
                    "the mechanism that actually refuses the read has to be the one named: {mechanism}"
                );
                assert!(
                    !mechanism.contains("pidns"),
                    "the PID namespace does not close this hole: {mechanism}"
                );
            }
            other => {
                panic!("a user namespace does refuse the read, so this is enforcement: {other:?}")
            }
        }
    }

    #[test]
    fn a_seccomp_errno_refusal_is_enforcement_but_a_notification_decision_is_not() {
        // The distinction is real: an errno response means the syscall never runs, while
        // an allowed call is re-read by the kernel after we answer.
        let t = plan_tiers(&Plan::default(), false, true, None);
        let net = t.get_key_value(&Capability::Net.into()).unwrap();
        assert!(net.1.is_enforced(), "an errno refusal is authoritative");
        let fs = t.get_key_value(&Capability::FsWrite.into()).unwrap();
        assert!(
            !fs.1.is_enforced(),
            "a path decision from a notification is not"
        );
        // Exec is the capability that carried the mislabel this test's name describes: it
        // is recorded through the notification supervisor and never refused, so it is a
        // notification decision and must not be enforcement either.
        let exec = t.get_key_value(&Capability::Exec.into()).unwrap();
        assert!(
            !exec.1.is_enforced(),
            "exec is recorded via a notification, never refused, so it is not enforcement"
        );
    }

    #[test]
    fn granting_the_network_reports_no_tier_rather_than_a_false_enforcement() {
        let plan = Plan {
            allow_net: true,
            ..Default::default()
        };
        let t = plan_tiers(&plan, true, true, None);
        let net = t.get_key_value(&Capability::Net.into()).unwrap();
        assert!(matches!(net.1, Tier::None { .. }));
    }

    #[test]
    fn every_capability_gets_a_tier_on_every_host_shape() {
        // A capability missing from the report reads as unconstrained-and-unmentioned,
        // which is the one thing a report must never be.
        for (ns, notify, ll) in [
            (true, true, None),
            (true, false, None),
            (false, true, None),
            // Landlock is orthogonal to both, so it has to be in this matrix too — a
            // Landlock host with no user namespace is a real shape and it is the one that
            // gains most from the rung existing.
            (true, true, Some("landlock-v7".to_string())),
            (false, true, Some("landlock-v1".to_string())),
        ] {
            let t = plan_tiers(&Plan::default(), ns, notify, ll);
            for cap in Capability::ALL {
                assert!(
                    t.contains_key(&cap.into()),
                    "{cap} has no tier with ns={ns} notify={notify}"
                );
            }
        }
    }

    #[test]
    fn syscall_names_cover_everything_the_filter_can_notify_on() {
        // A number the filter notifies on but this table does not know would appear in a
        // report as "unknown-syscall", which is a bug worth seeing rather than hiding.
        for name in ["socket", "connect", "execve", "openat"] {
            assert!(
                (0..600).any(|n| syscall_name(n) == name),
                "{name} is missing from the table"
            );
        }
        assert_eq!(syscall_name(99999), "unknown-syscall");
    }
}
