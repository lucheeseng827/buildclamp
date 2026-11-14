//! Installing the filter and supervising the notifications it raises.
//!
//! # The deadlock that shapes this whole module
//!
//! **The child's own first `execve` is notified**, and `Command::spawn` blocks reading
//! std's close-on-exec pipe until that exec completes. So if the supervisor thread is
//! started *after* `spawn`, nobody is serving the listener when the first notification
//! arrives and the process pair deadlocks on the very first unit.
//!
//! The supervisor thread must therefore already be blocked in `recvmsg` on a socketpair
//! **before** `spawn` is called. Which means the fork happens from a process that has more
//! than one thread, which is why everything in [`super::ns`] and in the `pre_exec` closure
//! is allocation-free, lock-free and panic-free. This ordering is not a preference; it was
//! found by deadlocking a spike, and reversing it deadlocks again.
//!
//! # Why the decisions are advisory
//!
//! `SECCOMP_USER_NOTIF_FLAG_CONTINUE` tells the kernel to run the syscall after the
//! supervisor answers — and the kernel then re-reads the arguments. A path or address read
//! out of the target's memory before answering can therefore be changed in between. That
//! makes notification-based file policy good enough to *see* what a build does and not
//! good enough to call enforcement, which is why the tier says `advisory` and carries the
//! sentence explaining it. Only an errno response is authoritative.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::mpsc;

use buildclamp_core::{Capability, Outcome, Request, UnitId};

/// `SECCOMP_FILTER_FLAG_NEW_LISTENER` — install and return a listener fd.
const NEW_LISTENER: libc::c_ulong = 1 << 3;

/// Install the filter in the calling process and return the listener fd.
///
/// # Safety
///
/// Called in a freshly forked child, after `PR_SET_NO_NEW_PRIVS`. Allocates nothing: the
/// program was built in the parent.
pub unsafe fn install(program: &[libc::sock_filter]) -> Result<RawFd, i32> {
    let prog = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_ptr() as *mut libc::sock_filter,
    };
    let fd = libc::syscall(
        libc::SYS_seccomp,
        libc::SECCOMP_SET_MODE_FILTER,
        NEW_LISTENER,
        &prog as *const libc::sock_fprog,
    );
    if fd < 0 {
        return Err(*libc::__errno_location());
    }
    Ok(fd as RawFd)
}

/// Send the listener fd to the parent over a unix socket.
///
/// # Safety
///
/// The `cmsghdr` buffer is pre-filled by the caller before the fork; this writes only the
/// four bytes of the descriptor into it and calls `sendmsg`. No allocation.
pub unsafe fn send_listener(sock: RawFd, listener: RawFd, buf: &mut CmsgBuffer) -> Result<(), i32> {
    buf.set_fd(listener);
    let mut iov_byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: &mut iov_byte as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };
    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = buf.len() as _;
    if libc::sendmsg(sock, &msg, 0) < 0 {
        return Err(*libc::__errno_location());
    }
    Ok(())
}

/// An 8-byte-aligned control-message buffer, built before the fork.
///
/// `cmsghdr` must be 8-byte aligned or the kernel rejects the message, and the header is
/// filled in the parent so the child writes only the descriptor.
#[repr(C, align(8))]
pub struct CmsgBuffer {
    bytes: [u8; 32],
    len: usize,
}

impl std::fmt::Debug for CmsgBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmsgBuffer")
            .field("len", &self.len)
            .finish()
    }
}

impl CmsgBuffer {
    /// Build the header. Safe to call in the parent; allocates nothing.
    pub fn new() -> Self {
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
        assert!(
            space <= 32,
            "CMSG_SPACE(4) is {space}, larger than this buffer; the assumption that a \
             single-descriptor control message fits in 32 bytes no longer holds"
        );
        let mut b = Self {
            bytes: [0; 32],
            len: space,
        };
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_control = b.bytes.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = space as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        }
        b
    }

    /// # Safety
    /// Writes four bytes into the pre-built control message. No allocation.
    unsafe fn set_fd(&mut self, fd: RawFd) {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_control = self.bytes.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = self.len as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl Default for CmsgBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Receive the listener fd the child sent.
///
/// Returns `Ok(None)` when the socket reached end of file, which means the child died in
/// `pre_exec` before it could send anything — a clean signal rather than a hang.
pub fn recv_listener(sock: RawFd) -> io::Result<Option<OwnedFd>> {
    let mut buf = CmsgBuffer::new();
    let mut iov_byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: &mut iov_byte as *mut u8 as *mut libc::c_void,
        iov_len: 1,
    };
    // SAFETY: every pointer refers to a live local; `recvmsg` writes only into them.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = buf.len() as _;
        let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Ok(None);
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Ok(None);
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut RawFd as *mut u8,
            std::mem::size_of::<RawFd>(),
        );
        if fd < 0 {
            return Ok(None);
        }
        Ok(Some(OwnedFd::from_raw_fd(fd)))
    }
}

// --- the notification protocol ------------------------------------------------------

const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc0502100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc0182101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x40082102;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompData {
    nr: libc::c_int,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

/// What the supervisor decided about one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Let the syscall run, and it was within the envelope.
    Allow,
    /// Let the syscall run, but enforcement **would** have refused it.
    ///
    /// Observe mode's whole output. Without this variant observe mode records every
    /// request as granted, `init` generates no grants, and the operator is told their
    /// build is clean when enforcing it would break — which is precisely the discovery
    /// observe mode exists to spare them.
    AllowButWouldRefuse,
    /// Fail it with this errno.
    Deny(i32),
}

/// How the supervisor decides. Supplied by the caller so this module stays free of policy.
pub trait Decider: Send {
    fn decide(&self, cap: Capability, target: &str) -> Decision;
}

/// Run the supervisor loop until the listener hangs up.
///
/// Returns everything the unit asked for. Runs on its own thread, started **before** the
/// child is spawned — see the module docs.
#[allow(clippy::too_many_arguments)]
pub fn supervise(
    listener: OwnedFd,
    decider: Box<dyn Decider>,
    proc_macros: Vec<(PathBuf, UnitId)>,
    skip_exec_target: Option<PathBuf>,
    stop: mpsc::Receiver<()>,
    started: std::time::Instant,
) -> Vec<Request> {
    let mut skip_exec_target = skip_exec_target;
    let mut out = Vec::new();
    let fd = listener.as_raw_fd();
    loop {
        match wait(fd) {
            // Nothing carries the filter any more: the unit and every child of it have
            // exited, so there can never be another notification.
            Waited::HungUp | Waited::Failed => break,
            // The poll timed out. This is the ONLY place the stop channel is checked, and
            // it must not fall through to the receive: `NOTIF_RECV` blocks forever when
            // there is nothing to receive, so treating a timeout as readable hangs the
            // build. It did, once, and this comment is why the branch is explicit.
            Waited::TimedOut => {
                if stop.try_recv().is_ok() && !ready(fd) {
                    break;
                }
                continue;
            }
            Waited::Readable => {}
        }

        // The kernel rejects a notification buffer that is not zeroed. Re-zeroed every
        // iteration rather than once, because the previous notification's bytes are still
        // in it and the resulting `EINVAL` is silent.
        let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
        // SAFETY: `notif` is a live, correctly sized, zeroed buffer of the type the ioctl
        // writes into.
        let rc = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) };
        if rc != 0 {
            match io::Error::last_os_error().raw_os_error() {
                // The target died between the poll and the receive.
                Some(libc::ENOENT) | Some(libc::EINTR) => continue,
                _ => break,
            }
        }

        let tid = notif.pid as i32;
        let (cap, syscall, target, second_write) = describe(&notif, tid);
        let attribution =
            super::attribution::attribute(tid, notif.data.instruction_pointer, &proc_macros);

        // Re-validate before answering. `describe` read `/proc/<tid>/mem`, and between the
        // receive and now the target may have died and its id been reused by an unrelated
        // process — in which case what was just read is another process's memory and must
        // not become a line in a security report.
        if !id_valid(fd, notif.id) {
            continue;
        }

        let decision = decider.decide(cap, &target);
        // A second write path — renameat's destination — must be inside the envelope too, or
        // it is an escape the source decision cannot see. The stricter decision wins.
        let decision = match &second_write {
            Some(dst) => stricter(decision, decider.decide(cap, dst)),
            None => decision,
        };
        let mut resp = SeccompNotifResp {
            id: notif.id,
            ..Default::default()
        };
        match decision {
            // CONTINUE requires val and error to be zero, which Default gives.
            Decision::Allow | Decision::AllowButWouldRefuse => {
                resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE
            }
            Decision::Deny(e) => resp.error = -e,
        }
        // SAFETY: `resp` is a live, correctly sized response naming the id just received.
        // ENOENT here means the target vanished while the notification was in flight,
        // which is normal at the end of a unit and is not an error.
        unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) };

        // buildclamp's own `exec` of the real build script, once. Recording it would put
        // our action at the top of the list of what the unit did.
        if cap == Capability::Exec
            && skip_exec_target
                .as_ref()
                .is_some_and(|p| p.as_os_str() == target.as_str())
        {
            skip_exec_target = None;
            continue;
        }

        let request = Request {
            at_ms: started.elapsed().as_millis() as u64,
            tid,
            capability: cap.into(),
            syscall: syscall.to_string(),
            // Both ends in the report, so a refused two-path write names where it was going
            // and not only where it came from.
            target: match &second_write {
                Some(dst) => format!("{target} -> {dst}"),
                None => target,
            },
            outcome: match decision {
                Decision::Allow => Outcome::Granted,
                Decision::AllowButWouldRefuse => Outcome::WouldBeUngranted,
                Decision::Deny(e) => Outcome::Ungranted { errno: e },
            },
            attribution,
        };

        // Collapse a PATH search into the program it was searching for.
        //
        // `execvp` issues one `execve` per PATH entry until one succeeds, so a build
        // script spawning `cc` produces a dozen events for the same intent — measured: 13
        // on this host. Recording each would bury the interesting lines in a real report,
        // and the supervisor cannot see which attempt succeeded because a notification
        // carries no result. Keeping the LAST attempt for a given program name is the
        // honest summary: it is the one that ran, and the ones before it are the
        // directories that did not have it.
        if let Some(prev) = out.last_mut() {
            if same_program_search(prev, &request) {
                *prev = request;
                continue;
            }
        }
        out.push(request);
    }
    out
}

/// Are these two `execve` records the same PATH search?
///
/// Compared by the program's basename, since a PATH walk differs only in the directory.
fn same_program_search(a: &Request, b: &Request) -> bool {
    let exec = buildclamp_core::Forward::Known(Capability::Exec);
    if a.capability != exec || b.capability != exec || a.tid != b.tid {
        return false;
    }
    let base = |s: &str| {
        std::path::Path::new(s)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
    };
    base(&a.target).is_some() && base(&a.target) == base(&b.target)
}

/// What one `poll` of the listener found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Waited {
    Readable,
    TimedOut,
    /// No task carries the filter any more.
    HungUp,
    Failed,
}

/// Wait for a notification, for a hang-up, or for the timeout that lets the caller check
/// whether the unit has finished.
///
/// A blocking `NOTIF_RECV` alone never returns once the last task exits, so `POLLHUP` is
/// what ends the loop, and the timeout is what makes the stop channel reachable.
fn wait(fd: RawFd) -> Waited {
    loop {
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd, a 200 ms timeout.
        let rc = unsafe { libc::poll(&mut p, 1, 200) };
        if rc < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Waited::Failed;
        }
        if rc == 0 {
            return Waited::TimedOut;
        }
        // Drain what is queued even when the hang-up bit is set alongside it: the last
        // notifications of a unit arrive together with its exit.
        if p.revents & libc::POLLIN != 0 {
            return Waited::Readable;
        }
        if p.revents & libc::POLLHUP != 0 {
            return Waited::HungUp;
        }
        return Waited::Failed;
    }
}

fn id_valid(fd: RawFd, id: u64) -> bool {
    // SAFETY: the ioctl reads eight bytes from the pointer and returns a status.
    unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0 }
}

fn ready(fd: RawFd) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live pollfd, zero timeout.
    unsafe { libc::poll(&mut p, 1, 0) > 0 }
}

/// Work out what a notification was asking for.
///
/// Best effort by construction: the arguments live in the target's memory and the kernel
/// re-reads them after we answer. See the module docs.
/// The capability, the syscall name, the primary path, and — for a syscall that writes a
/// **second** path — that path too. Both must be inside the envelope, or the second is an
/// escape the primary decision cannot see.
fn describe(notif: &SeccompNotif, tid: i32) -> (Capability, &'static str, String, Option<String>) {
    let nr = notif.data.nr as i64;
    let a = &notif.data.args;
    let sys = super::syscall_name(nr);
    match sys {
        "socket" => {
            let domain = a[0] as i32;
            let cap = if domain == libc::AF_UNIX {
                Capability::Unix
            } else {
                Capability::Net
            };
            (
                cap,
                "socket",
                format!("{} socket", family_name(domain)),
                None,
            )
        }
        "connect" | "sendto" | "sendmsg" | "sendmmsg" => {
            let (cap, target) = read_sockaddr(tid, a[1], a[2] as usize);
            (cap, sys, target, None)
        }
        "execve" | "execveat" => (
            Capability::Exec,
            sys,
            read_path(tid, if sys == "execve" { a[0] } else { a[1] }),
            None,
        ),
        // The `*at` family takes a directory descriptor and a path that may be relative to
        // it. `symlinkat(target, newdirfd, linkpath)` is the exception: its descriptor is
        // argument 1 and the path it creates is argument 2.
        "symlinkat" => (
            Capability::FsWrite,
            sys,
            resolve_at(tid, a[1] as i32, &read_path(tid, a[2])),
            None,
        ),
        // `renameat(olddirfd=a0, oldpath=a1, newdirfd=a2, newpath=a3)` writes BOTH ends: the
        // entry is removed from the source directory and created in the destination. Checking
        // only the source let a unit rename `OUT_DIR/x` into an ungranted directory — the
        // decider saw the permitted source, returned Allow, and the notification path ran the
        // move. Both paths are returned so both are checked; the stricter decision wins.
        "renameat" | "renameat2" => (
            Capability::FsWrite,
            sys,
            resolve_at(tid, a[0] as i32, &read_path(tid, a[1])),
            Some(resolve_at(tid, a[2] as i32, &read_path(tid, a[3]))),
        ),
        // `linkat(olddirfd=a0, oldpath=a1, newdirfd=a2, newpath=a3)`: the source is READ (the
        // hardlink target) and only the destination is created. The destination is the write
        // to check — the old code checked the source (a0/a1), which both refused a link *from*
        // a read-only location and missed the write into an ungranted directory entirely.
        "linkat" => (
            Capability::FsWrite,
            sys,
            resolve_at(tid, a[2] as i32, &read_path(tid, a[3])),
            None,
        ),
        "openat" | "openat2" | "mkdirat" | "unlinkat" | "fchmodat" => (
            Capability::FsWrite,
            sys,
            resolve_at(tid, a[0] as i32, &read_path(tid, a[1])),
            None,
        ),
        // The plain (non-`*at`) forms exist on x86-64 and take paths relative to the working
        // directory. Without these arms they fell through to the `_` arm below, which checks
        // argument 0 only — so a build script could reach an ungranted directory through the
        // plain syscall while the `*at` door was guarded.
        //
        // `rename(oldpath=a0, newpath=a1)` writes BOTH ends, exactly like `renameat`: the
        // entry leaves the source directory and is created in the destination, so both are
        // checked and the stricter decision wins.
        "rename" => (
            Capability::FsWrite,
            sys,
            resolve_at(tid, libc::AT_FDCWD, &read_path(tid, a[0])),
            Some(resolve_at(tid, libc::AT_FDCWD, &read_path(tid, a[1]))),
        ),
        // `link(oldpath=a0, newpath=a1)`: the source is READ (the hardlink target) and only
        // the destination is created, so argument 1 is the write to check — not argument 0,
        // which the `_` arm would have taken.
        "link" => (
            Capability::FsWrite,
            sys,
            resolve_at(tid, libc::AT_FDCWD, &read_path(tid, a[1])),
            None,
        ),
        // `symlink(target=a0, linkpath=a1)`: argument 0 is the symlink's *contents*, an
        // arbitrary string that is not a path being written; the file created is argument 1.
        "symlink" => (
            Capability::FsWrite,
            sys,
            resolve_at(tid, libc::AT_FDCWD, &read_path(tid, a[1])),
            None,
        ),
        // Everything else takes a path in argument 0, relative to the working directory.
        _ => (
            Capability::FsWrite,
            sys,
            resolve_at(tid, libc::AT_FDCWD, &read_path(tid, a[0])),
            None,
        ),
    }
}

/// The more restrictive of two decisions: a two-path write is allowed only if BOTH ends are.
///
/// `Deny` beats `AllowButWouldRefuse` beats `Allow`, so a permitted source cannot launder a
/// write into an ungranted destination, and observe mode still records a would-refuse when
/// either end is out of the envelope.
fn stricter(a: Decision, b: Decision) -> Decision {
    match (a, b) {
        (Decision::Deny(e), _) | (_, Decision::Deny(e)) => Decision::Deny(e),
        (Decision::AllowButWouldRefuse, _) | (_, Decision::AllowButWouldRefuse) => {
            Decision::AllowButWouldRefuse
        }
        _ => Decision::Allow,
    }
}

/// Make a path from an `*at` syscall absolute, the way the kernel will.
///
/// # The defect this exists for, measured
///
/// `proc-macro2`'s build script — which is in essentially every Rust dependency graph —
/// probes the compiler by writing into `OUT_DIR` and then deleting what it wrote. It does
/// the delete with `unlinkat(dirfd, "libproc_macro2.rmeta", 0)`, where the descriptor is
/// the directory and the path is a bare filename.
///
/// Read verbatim, that path is `libproc_macro2.rmeta`, which matches no writable root
/// because it is not a path to anywhere. So the supervisor recorded five ungranted writes
/// for a build script that never left `OUT_DIR`, on a run where the kernel-enforced
/// filesystem tier had permitted every one of them. Two things were wrong with that at
/// once: the report said a crate did something it did not, and `--gate` on an observe run
/// would have failed a build over it. Measured on 2026-09-15 against a graph of `libc`,
/// `libz-sys`, `openssl-sys`, `bindgen` and `ring`: five false findings, all from this,
/// and no true ones.
///
/// # How it resolves, and what it cannot
///
/// An absolute path is already absolute. `AT_FDCWD` resolves against `/proc/<tid>/cwd`, and
/// any other descriptor against `/proc/<tid>/fd/<n>` — the same interface `read_mem` uses
/// for the arguments themselves, so it needs no new access to the target.
///
/// If the descriptor cannot be read — it was closed, the target died, `/proc` is not
/// mounted — the path is returned **as it was given**, relative. That is the fail-closed
/// direction: an unresolvable relative path matches no writable root and is refused, which
/// is the behaviour every version before this had for every relative path. Silently
/// allowing one this cannot resolve would be the permissive direction, and the whole
/// notification tier is already the racy one.
fn resolve_at(tid: i32, dirfd: i32, path: &str) -> String {
    if path.starts_with('/') || path.is_empty() || path == "<unreadable>" {
        return path.to_string();
    }
    let link = if dirfd == libc::AT_FDCWD {
        format!("/proc/{tid}/cwd")
    } else if dirfd >= 0 {
        format!("/proc/{tid}/fd/{dirfd}")
    } else {
        // A negative descriptor that is not AT_FDCWD is a caller error the kernel will
        // reject with EBADF. Nothing to resolve against, and guessing would invent a path.
        return path.to_string();
    };
    match std::fs::read_link(&link) {
        // A descriptor can point at something that is not a path — a pipe, a socket, a
        // deleted file — and `readlink` gives `pipe:[12345]` or a name with " (deleted)"
        // appended. Neither is a directory a relative path can hang off, so the path is
        // left as it was rather than joined onto a fiction.
        Ok(dir) if dir.is_absolute() && !dir.to_string_lossy().ends_with(" (deleted)") => {
            dir.join(path).to_string_lossy().into_owned()
        }
        _ => path.to_string(),
    }
}

fn family_name(domain: i32) -> &'static str {
    match domain {
        libc::AF_INET => "AF_INET",
        libc::AF_INET6 => "AF_INET6",
        libc::AF_UNIX => "AF_UNIX",
        libc::AF_NETLINK => "AF_NETLINK",
        libc::AF_PACKET => "AF_PACKET",
        _ => "unknown-family",
    }
}

/// Read a NUL-terminated path out of the target's memory.
fn read_path(tid: i32, addr: u64) -> String {
    match read_mem(tid, addr, 4096) {
        Some(bytes) => {
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        }
        None => "<unreadable>".to_string(),
    }
}

/// Decode a `sockaddr` out of the target's memory into something a person can act on.
fn read_sockaddr(tid: i32, addr: u64, len: usize) -> (Capability, String) {
    let Some(bytes) = read_mem(tid, addr, len.clamp(2, 128)) else {
        return (Capability::Net, "<unreadable>".to_string());
    };
    if bytes.len() < 2 {
        return (Capability::Net, "<short>".to_string());
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    match family {
        libc::AF_INET if bytes.len() >= 8 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            (Capability::Net, format!("{ip}:{port}"))
        }
        libc::AF_INET6 if bytes.len() >= 24 => {
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            let ip = std::net::Ipv6Addr::from(octets);
            (Capability::Net, format!("[{ip}]:{port}"))
        }
        libc::AF_UNIX => {
            let end = bytes[2..]
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(bytes.len() - 2);
            let path = String::from_utf8_lossy(&bytes[2..2 + end]).into_owned();
            (
                Capability::Unix,
                if path.is_empty() {
                    "<abstract unix socket>".to_string()
                } else {
                    path
                },
            )
        }
        other => (Capability::Net, format!("{} address", family_name(other))),
    }
}

/// Read from `/proc/<tid>/mem`.
///
/// Opened per call and never cached. A cached descriptor against a reused thread id would
/// read a different process's memory, which is a wrong answer in a security report — the
/// worst kind.
fn read_mem(tid: i32, addr: u64, len: usize) -> Option<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    if addr == 0 {
        return None;
    }
    let f = std::fs::File::open(format!("/proc/{tid}/mem")).ok()?;
    let mut buf = vec![0u8; len];
    // A read that crosses into an unmapped page fails wholesale, so shrink until it
    // succeeds rather than giving up: a path near the end of a mapping is common.
    let mut want = len;
    while want > 0 {
        match f.read_at(&mut buf[..want], addr) {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                return Some(buf);
            }
            Ok(_) => return None,
            Err(_) if want > 64 => want /= 2,
            Err(_) => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_two_path_write_is_refused_when_either_end_is() {
        // renameat writes both ends; `stricter` is what makes checking both mean something.
        // A permitted source (Allow) and an ungranted destination (Deny) must come out Deny,
        // in either order — otherwise a unit renames OUT_DIR/x into an ungranted directory
        // and the permitted source launders the write.
        let deny = Decision::Deny(libc::EPERM);
        assert_eq!(stricter(Decision::Allow, deny), deny);
        assert_eq!(stricter(deny, Decision::Allow), deny);
        // Observe mode: a would-refuse on either end is recorded rather than swallowed.
        assert_eq!(
            stricter(Decision::Allow, Decision::AllowButWouldRefuse),
            Decision::AllowButWouldRefuse
        );
        assert_eq!(
            stricter(Decision::AllowButWouldRefuse, deny),
            deny,
            "a real refusal outranks a would-refuse"
        );
        // Both ends inside the envelope is the only way through.
        assert_eq!(stricter(Decision::Allow, Decision::Allow), Decision::Allow);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn plain_rename_link_symlink_check_the_created_path_not_argument_zero() {
        // The plain (non-`*at`) forms exist on x86-64 and used to fall through to the
        // argument-0 arm, so a build script could reach an ungranted directory through
        // `rename`/`link`/`symlink` while the `*at` door was guarded. `describe` reads the
        // paths out of the target's memory; pointing the args at strings in this process (so
        // `tid` is our own pid) exercises the arm selection without a traced child.
        let me = std::process::id() as i32;
        let old = std::ffi::CString::new("/src/old").unwrap();
        let new = std::ffi::CString::new("/dst/new").unwrap();
        let notif = |nr: libc::c_int, a0: u64, a1: u64| {
            let mut n: SeccompNotif = unsafe { std::mem::zeroed() };
            n.data.nr = nr;
            n.data.args[0] = a0;
            n.data.args[1] = a1;
            n
        };
        let (old_addr, new_addr) = (old.as_ptr() as u64, new.as_ptr() as u64);

        // rename(oldpath=a0, newpath=a1): both ends are writes, so both are checked.
        let (_cap, sys, primary, second) = describe(&notif(82, old_addr, new_addr), me);
        assert_eq!(sys, "rename");
        assert_eq!(primary, "/src/old");
        assert_eq!(second.as_deref(), Some("/dst/new"));

        // link(oldpath=a0, newpath=a1): only the created link (a1) is a write.
        let (_cap, sys, primary, second) = describe(&notif(86, old_addr, new_addr), me);
        assert_eq!(sys, "link");
        assert_eq!(primary, "/dst/new");
        assert_eq!(second, None);

        // symlink(target=a0, linkpath=a1): a0 is the link contents, not a path; a1 is created.
        let (_cap, sys, primary, second) = describe(&notif(88, old_addr, new_addr), me);
        assert_eq!(sys, "symlink");
        assert_eq!(primary, "/dst/new");
        assert_eq!(second, None);
    }

    #[test]
    fn a_relative_path_is_resolved_against_its_directory_descriptor() {
        // The measured defect: `proc-macro2`'s build script deletes what it wrote with
        // `unlinkat(dirfd, "libproc_macro2.rmeta", 0)`, and a supervisor that read that
        // path verbatim recorded five ungranted writes for a crate that never left
        // OUT_DIR — on a run where the kernel had permitted every one of them.
        use std::os::fd::AsRawFd;

        let dir = tempfile::tempdir().expect("a scratch directory");
        let handle = std::fs::File::open(dir.path()).expect("a directory descriptor");
        let me = std::process::id() as i32;
        let fd = handle.as_raw_fd();

        let resolved = resolve_at(me, fd, "libproc_macro2.rmeta");
        assert_eq!(
            std::path::Path::new(&resolved),
            dir.path().join("libproc_macro2.rmeta"),
            "a bare filename must come back under the directory the descriptor names"
        );
        // A nested relative path too, which is what `mkdirat` on a subdirectory produces.
        assert_eq!(
            std::path::Path::new(&resolve_at(me, fd, "probe/full.rmeta")),
            dir.path().join("probe/full.rmeta")
        );
    }

    #[test]
    fn an_absolute_path_is_left_exactly_as_it_was() {
        // Including one that looks like it could be joined. A supervisor that normalised
        // paths would be reporting a path the syscall did not use, and the report is the
        // evidence.
        for p in ["/tmp/x", "/", "/a/../b", "/proc/self/environ"] {
            assert_eq!(resolve_at(1, libc::AT_FDCWD, p), p);
        }
    }

    #[test]
    fn an_unresolvable_descriptor_leaves_the_path_relative_and_therefore_refused() {
        // The fail-closed direction, and the reason it is the right one: a relative path
        // matches no writable root, so it is refused — which is what every version before
        // this did for every relative path. Allowing one this could not resolve would be
        // the permissive direction, in the tier that is already the racy one.
        //
        // fd 4096 is not open in this process; a target that had closed it between the
        // syscall and the notification is the real case.
        let orphan = resolve_at(std::process::id() as i32, 4096, "something");
        assert_eq!(orphan, "something");

        // A descriptor that resolves to something that is not a directory path — a pipe —
        // must not be joined onto. `readlink` gives `pipe:[12345]`, and
        // `pipe:[12345]/something` is a path to nowhere that reads like a real one.
        let mut fds = [0i32; 2];
        // SAFETY: `pipe` writes two descriptors into a live array of two ints.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe() failed");
        let through_a_pipe = resolve_at(std::process::id() as i32, fds[0], "something");
        // SAFETY: both descriptors were just created by `pipe` and are not used after this.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        assert_eq!(through_a_pipe, "something");

        // And a negative descriptor that is not AT_FDCWD, which the kernel rejects with
        // EBADF: nothing to resolve against, and guessing would invent a path.
        assert_eq!(resolve_at(1, -7, "something"), "something");
    }

    #[test]
    fn a_path_the_supervisor_could_not_read_is_not_turned_into_one_it_could() {
        // `read_path` returns this marker when `/proc/<tid>/mem` could not be read. Joining
        // it onto a directory would produce `<out-dir>/<unreadable>`, which reads like a
        // real path somebody might go and look for.
        assert_eq!(
            resolve_at(1, libc::AT_FDCWD, "<unreadable>"),
            "<unreadable>"
        );
        assert_eq!(resolve_at(1, libc::AT_FDCWD, ""), "");
    }

    #[test]
    fn the_control_message_buffer_holds_a_single_descriptor() {
        // Asserted rather than assumed: CMSG_SPACE(4) is 24 on Linux, and a platform
        // where it is larger would silently truncate the message.
        let b = CmsgBuffer::new();
        assert!(b.len() <= 32);
        assert!(b.len() >= std::mem::size_of::<RawFd>());
    }

    #[test]
    fn an_ipv4_sockaddr_decodes_to_something_a_person_can_act_on() {
        // The destination is the single most useful line in an incident report, so the
        // decoder is tested against bytes rather than only in an integration test.
        let mut bytes = vec![0u8; 16];
        bytes[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&443u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&[23, 254, 165, 112]);
        let (cap, target) = decode_sockaddr_bytes(&bytes);
        assert_eq!(cap, Capability::Net);
        assert_eq!(target, "23.254.165.112:443");
    }

    #[test]
    fn a_unix_sockaddr_is_a_different_capability_from_a_network_one() {
        // The ssh agent and the docker socket are credential surfaces; collapsing them
        // into "net" would make the common case and the dangerous case indistinguishable.
        let mut bytes = vec![0u8; 32];
        bytes[0..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
        bytes[2..2 + 16].copy_from_slice(b"/run/docker.sock");
        let (cap, target) = decode_sockaddr_bytes(&bytes);
        assert_eq!(cap, Capability::Unix);
        assert_eq!(target, "/run/docker.sock");
    }

    #[test]
    fn a_truncated_sockaddr_reports_that_rather_than_inventing_an_address() {
        let (_, target) = decode_sockaddr_bytes(&[2]);
        assert_eq!(target, "<short>");
    }

    /// The pure half of [`read_sockaddr`], so the decoding is testable without a target
    /// process to read memory from.
    fn decode_sockaddr_bytes(bytes: &[u8]) -> (Capability, String) {
        if bytes.len() < 2 {
            return (Capability::Net, "<short>".to_string());
        }
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
        match family {
            libc::AF_INET if bytes.len() >= 8 => {
                let port = u16::from_be_bytes([bytes[2], bytes[3]]);
                let ip = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
                (Capability::Net, format!("{ip}:{port}"))
            }
            libc::AF_UNIX => {
                let end = bytes[2..]
                    .iter()
                    .position(|b| *b == 0)
                    .unwrap_or(bytes.len() - 2);
                let path = String::from_utf8_lossy(&bytes[2..2 + end]).into_owned();
                (Capability::Unix, path)
            }
            _ => (Capability::Net, "other".to_string()),
        }
    }

    #[test]
    fn reading_memory_from_a_process_that_does_not_exist_returns_nothing_rather_than_panicking() {
        // pid 0 is never a real process, and a supervisor that panicked on a dead target
        // would take the build with it.
        assert!(read_mem(0, 0x1000, 16).is_none());
        assert_eq!(read_path(0, 0x1000), "<unreadable>");
    }
}
