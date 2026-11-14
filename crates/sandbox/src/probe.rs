//! What this host can actually do, found out by trying rather than by guessing.
//!
//! Every answer here is a syscall result or a file read. Nothing is inferred from a
//! kernel version string, because the version does not decide any of it:
//!
//! * **Landlock** can be compiled out, disabled at boot with `lsm=`, or blocked by a
//!   container runtime's seccomp profile. This project's own host returns `ENOSYS`
//!   despite running 6.18, which is why the fallback path is tested rather than assumed.
//! * **User namespaces** are blocked by `kernel.unprivileged_userns_clone=0` on some
//!   distributions, by `kernel.apparmor_restrict_unprivileged_userns=1` on Ubuntu 24.04
//!   for unconfined binaries, and by the default Docker seccomp profile, which denies
//!   `unshare` outright.
//! * **`hidepid`** is a mount option on `/proc` that most systems do not set.
//!
//! A tool that read `uname` and concluded "6.12, so Landlock v6" would report enforcement
//! it did not have on every one of those hosts.
//!
//! # A probe must test the whole thing it claims to predict
//!
//! `unshare(CLONE_NEWUSER)` succeeding does not mean a unit can be held. The child setup
//! also writes three procfs maps, clones the mount tree, marks it read-only, mounts a
//! tmpfs and pivots into it. A host can allow the first and refuse a later one — a GitHub
//! Actions runner does exactly that — and a probe that stopped at the first syscall
//! reported `user namespaces: yes` while every held unit died at `spawn`.
//!
//! So [`user_namespaces_work`] runs the real setup, in a forked child, and reports whether
//! it survived. `doctor`, the enforcement path and the tests that gate on host capability
//! then agree because they are the same code, not three readings of it.

use buildclamp_core::HostCapabilities;

/// Probe this host.
///
/// Run once per invocation. The expensive answer is [`user_namespaces_work`], which forks
/// a child that performs the whole namespace setup and exits: a few milliseconds, and the
/// only way to answer the question truthfully.
pub fn host() -> HostCapabilities {
    HostCapabilities {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        kernel: kernel_release(),
        landlock_abi: landlock_abi(),
        user_namespaces: user_namespaces_work(),
        seccomp_user_notif: seccomp_user_notif_works(),
        proc_hidepid: proc_hides_other_processes(),
    }
}

/// The kernel release, for the report. Informational only — nothing branches on it.
fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// The Landlock ABI level, or `None` where the syscall is absent.
///
/// Asked of the kernel directly — `landlock_create_ruleset(NULL, 0,
/// LANDLOCK_CREATE_RULESET_VERSION)` returns the ABI level and creates nothing. The
/// `doctor` has to tell a person what their kernel has, so it asks the kernel.
///
/// **What this answers decides the filesystem tier.** [`crate::linux::landlock`] builds a
/// ruleset when this returns `Some`, and `plan_tiers` puts that rung above the mount
/// namespace, so the top of the filesystem ladder is `enforced:landlock-vN` here and
/// `enforced:mountns-ro` where this returns `None`. The number matters as well as the
/// presence: the handled mask grows at ABI 2 and again at ABI 3, and the mechanism string
/// carries the level so a report says which one held.
///
/// Two earlier versions of this comment were wrong in opposite directions — one claimed
/// enforcement went "through the crate" when the crate was an uncalled dependency, the
/// other that this was the only Landlock code in the project and enforced nothing, which
/// the rung then falsified. Check it against `linux::landlock` and `plan_tiers` rather
/// than trusting it.
#[cfg(target_os = "linux")]
fn landlock_abi() -> Option<i32> {
    // Both x86-64 and the asm-generic table (aarch64, riscv64) put it at 444.
    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    // SAFETY: with a null attribute pointer, a zero size and the VERSION flag, this call
    // only reports the supported ABI. It allocates nothing, creates no file descriptor
    // and has no effect on the calling process.
    let rc = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc > 0 {
        Some(rc as i32)
    } else {
        // ENOSYS (not built in), EOPNOTSUPP (built in, disabled at boot), or blocked by a
        // container runtime's own seccomp profile. All three mean the same thing here.
        None
    }
}

#[cfg(not(target_os = "linux"))]
fn landlock_abi() -> Option<i32> {
    None
}

/// Can this process hold a unit in a user namespace?
///
/// Answered by **running the real child setup** in a forked child, not by issuing the
/// first syscall of it. See the module docs: a host that allows `unshare(CLONE_NEWUSER)`
/// and refuses a later step is a host where the old probe said yes and every unit then
/// failed to spawn.
///
/// Tried in a child because the answer is only useful if it holds for the process that
/// will actually do it, and because doing any of this in *this* process would change what
/// the rest of the run can do.
#[cfg(target_os = "linux")]
fn user_namespaces_work() -> bool {
    // Built in the parent, where allocating is safe. This is the same type the launcher
    // hands the real child, with the shape an enforcing run asks for: a user namespace, a
    // private network, a PID namespace and a read-only root.
    let prepared = match crate::linux::ns::Prepared::new(true, true, true, &[], None) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // SAFETY: fork in a process that may have other threads. The child runs
    // `apply_in_child`, which is written for exactly this position — allocation-free,
    // lock-free and panic-free — and then `_exit`s, so no destructor and no allocator is
    // touched. Every namespace, mount, capability drop and `no_new_privs` it performs
    // belongs to the child and dies with it.
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            let ok = prepared.apply_in_child().is_ok();
            libc::_exit(if ok { 0 } else { 1 });
        }
        let mut status: libc::c_int = 0;
        if libc::waitpid(pid, &mut status, 0) < 0 {
            return false;
        }
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }
}

#[cfg(not(target_os = "linux"))]
fn user_namespaces_work() -> bool {
    false
}

/// Can this process install the notification filter a held unit needs?
///
/// Answered by **installing the real filter** in a forked child, not by asking whether the
/// kernel knows the action.
///
/// This used to ask `SECCOMP_GET_ACTION_AVAIL`, which reports a property of the *kernel* —
/// and the kernel is not what refuses. What refuses is the process's permission to install
/// a filter of its own: a hardened container profile that permits `SECCOMP_GET_ACTION_AVAIL`
/// and denies `SECCOMP_SET_MODE_FILTER` is an ordinary shape, and on such a host the old
/// question answered yes, `hold` reported `enforced:seccomp-errno` for the network and
/// `advisory:seccomp-notify-record` for exec, and then every unit died at `spawn` with
/// `Permission denied`. Measured by installing exactly that gate and asking both questions:
/// the old one returns 0, the real install returns `EPERM`.
///
/// That is the same failure [`user_namespaces_work`] was rewritten to avoid, for the reason
/// the module docs give: a probe must test the whole thing it claims to predict.
///
/// Tried in a forked child because installing a filter cannot be undone — doing it here
/// would put the rest of the run, and cargo, under a filter nobody asked for.
#[cfg(target_os = "linux")]
fn seccomp_user_notif_works() -> bool {
    // Built in the parent, where allocating is safe, and it is the filter a real unit gets
    // rather than a stub: a filter the kernel rejects on its own terms — too long, a jump
    // it cannot encode — is then caught here rather than at the first held unit.
    let program = match crate::linux::bpf::build(&crate::linux::bpf::FilterOptions::for_native()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // SAFETY: fork in a process that may have other threads. The child issues only raw
    // syscalls against `program`, which was built above, and then `_exit`s, so no
    // destructor and no allocator is touched. The filter and the `no_new_privs` bit
    // belong to the child and die with it.
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            // `SECCOMP_SET_MODE_FILTER` fails with `EACCES` for a caller holding neither
            // `CAP_SYS_ADMIN` nor `no_new_privs`. The enforcement path sets it for the
            // same reason, so the probe has to be in the same state or it is answering a
            // different question.
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                libc::_exit(1);
            }
            match crate::linux::seccomp::install(&program) {
                Ok(fd) => {
                    libc::close(fd);
                    libc::_exit(0)
                }
                Err(_) => libc::_exit(1),
            }
        }
        let mut status: libc::c_int = 0;
        if libc::waitpid(pid, &mut status, 0) < 0 {
            return false;
        }
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }
}

#[cfg(not(target_os = "linux"))]
fn seccomp_user_notif_works() -> bool {
    false
}

/// Does `/proc` hide other processes from this user?
///
/// This is the difference between "a build script cannot see your secrets" and "a build
/// script cannot see the copy of your secrets in *its own* environment". Without either
/// `hidepid` or a user namespace, any process of the same user can read
/// `/proc/<pid>/environ` — and a fixture in this repository reads 7,883 bytes of its
/// parent's environment that way and finds both planted credentials.
///
/// The user namespace, measured, and not the PID namespace: unsharing `CLONE_NEWPID`
/// alone leaves the read working, while `CLONE_NEWUSER` alone makes it `EPERM`, because a
/// child user namespace fails `ptrace_may_access` against the parent's. And `hidepid`
/// hides processes belonging to *other* users, so on its own it does not keep cargo — the
/// same user — out of reach either.
///
/// Probed by trying to read the environment of pid 1, which every user can normally do
/// and nobody can under `hidepid=2`.
fn proc_hides_other_processes() -> bool {
    match std::fs::read("/proc/1/environ") {
        // Readable: not hidden.
        Ok(_) => false,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        // Any other error means we could not tell. Report the unsafe answer: claiming
        // processes are hidden when we do not know would overstate the protection.
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probing_the_host_answers_every_question_without_panicking() {
        // The probe runs on every invocation, including on hosts where every mechanism is
        // missing. A panic here would make the tool unusable exactly where it most needs
        // to explain itself.
        let h = host();
        assert!(!h.os.is_empty());
        assert!(!h.arch.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_namespace_probe_leaves_this_process_alone() {
        // The probe performs the whole child setup, including dropping every capability
        // and setting `no_new_privs`. All of it must happen in the forked child: if any
        // of it leaked into the test process, every test that ran afterwards would do so
        // under conditions this one silently created. `no_new_privs` is the one to watch,
        // because it cannot be unset.
        const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;
        let before = unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS) };
        let _ = user_namespaces_work();
        let after = unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS) };
        assert_eq!(before, after, "the probe changed this process");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_seccomp_probe_installs_a_filter_without_installing_one_here() {
        // The probe now installs the real filter rather than asking whether the kernel
        // knows the action, which means it does something irreversible — in a child. If
        // it leaked, this process and every test after it would be running under a
        // seccomp filter and with `no_new_privs` set, neither of which can be undone.
        const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;
        const PR_GET_SECCOMP: libc::c_int = 21;
        let nnp_before = unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS) };
        let mode_before = unsafe { libc::prctl(PR_GET_SECCOMP) };

        let answered = seccomp_user_notif_works();

        assert_eq!(
            nnp_before,
            unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS) },
            "the probe set no_new_privs on this process"
        );
        assert_eq!(
            mode_before,
            unsafe { libc::prctl(PR_GET_SECCOMP) },
            "the probe left a seccomp filter on this process"
        );
        // The answer itself is host-dependent — a runner that denies SET_MODE_FILTER
        // makes it false, and reporting false there is the entire point of the change —
        // so the assertion is that it answered at all rather than what it answered.
        let _ = answered;
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_landlock_probe_reports_absence_rather_than_failing() {
        // This project's own host returns ENOSYS. A probe that panicked or errored there
        // would make the fallback path untestable on the machine that needs it.
        let abi = landlock_abi();
        assert!(abi.is_none() || abi.unwrap() >= 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_hidepid_probe_answers_the_unsafe_way_when_it_cannot_tell() {
        // Claiming processes are hidden when we do not know would overstate the
        // protection in a report someone relies on.
        let hidden = proc_hides_other_processes();
        if std::fs::read("/proc/1/environ").is_ok() {
            assert!(
                !hidden,
                "environ was readable, so it must not report hidden"
            );
        }
    }
}
