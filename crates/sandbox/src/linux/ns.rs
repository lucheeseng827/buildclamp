//! Namespaces and the capability lock: the pieces that run inside the forked child.
//!
//! # Everything here runs after `fork` and before `execve`
//!
//! That is the hardest constraint in the project. Between `fork` and `execve` in a
//! process that had more than one thread — and buildclamp's supervisor thread must
//! already exist, see [`super::seccomp`] — only async-signal-safe operations are sound.
//! The allocator may be held by a thread that no longer exists in the child; a `Mutex`
//! may be locked forever; a panic would unwind through a destroyed runtime.
//!
//! So every function in this module is **allocation-free**, takes no locks, cannot panic,
//! and issues only raw syscalls against buffers built before the fork. [`Prepared`] is
//! that pre-built state, assembled in the parent where allocation is fine.
//!
//! # The escape this closes
//!
//! A read-only root inside a user namespace is **decorative** without the capability
//! lock. With the namespaces set up and nothing else, a spike child ran
//! `mount -o remount,bind,rw /` and wrote to `/root`. The lock is not hardening; it is the
//! difference between a filesystem tier and a decoration, and there is deliberately no
//! option to switch it off.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// libc 0.2 exports the syscall numbers and every constant used here, but none of the
// function wrappers for the new mount API — glibc 2.39 does not export them either, so a
// raw `syscall()` is the only route.
const SYS_OPEN_TREE: libc::c_long = 428;
const SYS_MOVE_MOUNT: libc::c_long = 429;
const SYS_MOUNT_SETATTR: libc::c_long = 442;

const OPEN_TREE_CLONE: libc::c_uint = 1;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;

/// `struct mount_attr` from `<linux/mount.h>`. Not in libc 0.2.
#[repr(C)]
#[derive(Default)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// `CAP_LAST_CAP` as of 6.x. Dropping past the end is harmless (`EINVAL`), dropping short
/// would leave a capability the child could use, so this is deliberately generous.
const CAP_LAST_CAP: libc::c_int = 40;

const _LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Everything the child needs, built in the parent where allocating is safe.
///
/// Paths are `CString`s because the child cannot allocate one, and the uid and gid are
/// captured **before** the fork: after `unshare(CLONE_NEWUSER)` and before the map is
/// written, `getuid()` returns the overflow uid 65534, and mapping *that* fails `EPERM`.
#[derive(Debug)]
pub struct Prepared {
    /// Whether to enter a new user + mount namespace at all.
    ///
    /// Separate from the two below because it is the *base* of the set, not an
    /// addition to it: without it there is nothing to add `CLONE_NEWNET` to, and with it
    /// unconditionally there is no way to ask for no namespace. Observe mode asks for
    /// exactly that, and a host without user namespaces has no choice about it.
    pub new_user_ns: bool,
    pub new_net: bool,
    pub read_only_root: bool,
    /// Directories to re-attach writable, in the order they should be attached.
    pub writable: Vec<CString>,
    /// The cwd to restore after `pivot_root`, which does not do it for us.
    pub cwd: Option<CString>,
    /// `<uid> <uid> 1\n`, formatted in the parent.
    ///
    /// Formatted here and not in the child for a reason that cost a spike to find: after
    /// `unshare(CLONE_NEWUSER)` and before this map is written, `getuid()` returns the
    /// overflow uid 65534, and mapping *that* fails `EPERM`. The only order that works is
    /// to capture the real uid before the fork.
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    scratch: CString,
}

impl Prepared {
    /// Assemble the child's plan. Allocation happens here, not after the fork.
    pub fn new(
        new_user_ns: bool,
        new_net: bool,
        read_only_root: bool,
        writable: &[std::path::PathBuf],
        cwd: Option<&Path>,
    ) -> io::Result<Self> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let to_c = |p: &Path| -> io::Result<CString> {
            CString::new(p.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL"))
        };
        Ok(Self {
            new_user_ns,
            new_net,
            read_only_root,
            writable: writable
                .iter()
                .map(|p| to_c(p))
                .collect::<io::Result<_>>()?,
            cwd: match cwd {
                Some(p) => Some(to_c(p)?),
                None => None,
            },
            uid_map: format!("{uid} {uid} 1\n").into_bytes(),
            gid_map: format!("{gid} {gid} 1\n").into_bytes(),
            scratch: CString::new("/tmp/.buildclamp-root").expect("no NUL in a literal"),
        })
    }

    /// Everything the child does between `fork` and `execve`.
    ///
    /// # Safety
    ///
    /// Must be called only in a freshly forked child, before `execve`, in a process that
    /// will not return to normal Rust execution. Nothing here allocates, locks or panics.
    pub unsafe fn apply_in_child(&self) -> Result<(), i32> {
        // A plan that asks for nothing must do nothing *else*. `unshare` with no user
        // namespace cannot create the others, and on a host without user namespaces it
        // returns EPERM — which used to reach the caller as `spawn` failing with
        // `Permission denied`, killing the run rather than degrading it. The mechanisms
        // that *are* available (the notification filter) still apply; `Held::tiers`
        // reports `Tier::None` for whatever did not.
        //
        // `no_new_privs` is the exception, and it is not optional. The caller installs
        // the notification filter immediately after this returns, and
        // `SECCOMP_SET_MODE_FILTER` fails with **EACCES** for a caller that has neither
        // CAP_SYS_ADMIN nor `no_new_privs`. An earlier version returned plain `Ok(())`
        // here, so every observe run on every host — and every run on a host without
        // user namespaces, which is the case this branch exists to serve — failed at
        // `spawn` with `Permission denied` before the unit started.
        if !self.new_user_ns {
            return no_new_privs();
        }

        let mut flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
        if self.new_net {
            flags |= libc::CLONE_NEWNET;
        }
        // `CLONE_NEWPID` is deliberately NOT here, and the reason is a measurement.
        //
        // # What it cost
        //
        // `unshare(CLONE_NEWPID)` sets `pid_for_children` without moving the caller, so
        // from that moment the caller's pid namespace and its children's differ. The
        // kernel refuses `CLONE_THREAD` in that state — `copy_process` returns `-EINVAL`
        // when `CLONE_THREAD` is set and `pid_ns_for_children` is not the active
        // namespace — so a held unit could not create a thread. Measured with a C probe
        // that unshares and then calls `pthread_create`:
        //
        //   before any unshare              pthread_create ok
        //   after unshare(CLONE_NEWUSER)    pthread_create ok
        //   after unshare(CLONE_NEWPID)     pthread_create FAILED: Invalid argument
        //
        // That is not an edge case. `cc` compiles in parallel with threads, `bindgen`
        // uses them, and rustc fails at startup: `install_ctrlc_handler` spawns one and
        // panics with "Unable to install ctrlc handler", which is how this was found
        // while wiring up compile-unit holding. Each of those is a build broken by
        // buildclamp for a reason nothing in the report explains.
        //
        // It went unnoticed because every fixture here was single-threaded and no compile
        // unit had ever been held.
        //
        // # What removing it gives up, stated rather than waved through
        //
        // Processes the unit *spawns* are no longer in a private PID namespace, so they
        // can enumerate the host's processes. The unit itself always could — it was never
        // in that namespace — so what goes is a restriction on the children of untrusted
        // code that the untrusted code could lift by doing the work itself. No tier
        // claimed it: `plan_tiers` names `scrub+userns`, and the user namespace, which is
        // what actually returns EPERM on `/proc/<pid>/environ`, is untouched.
        //
        // Doing it properly means forking after the unshare so the unit really is pid 1,
        // with this process relaying the grandchild's exit status and re-raising its
        // signal, and the notification listener installed on the far side of that fork.
        // That is a design, not a flag.
        if libc::unshare(flags) != 0 {
            return Err(errno());
        }

        // The maps MUST be written before any mount change. procfs writes take
        // `mnt_want_write`, so once `/proc` is inside a read-only tree this is EROFS —
        // and an unmapped process cannot even create a file on a filesystem it just
        // mounted (EOVERFLOW, because its fsuid has no mapping in the superblock's user
        // namespace). Both were observed before this ordering was settled.
        write_file(c"/proc/self/setgroups", b"deny")?;
        write_file(c"/proc/self/uid_map", &self.uid_map)?;
        write_file(c"/proc/self/gid_map", &self.gid_map)?;

        if self.read_only_root {
            self.make_root_read_only()?;
        }

        if let Some(cwd) = &self.cwd {
            // `pivot_root` rewrites cwd only for processes whose cwd *was* the old root.
            // Cargo runs build scripts with cwd set to the manifest directory, so without
            // this every unit would keep a handle into the detached, still-writable old
            // tree. This is every unit, not a corner case.
            if libc::chdir(cwd.as_ptr()) != 0 {
                // A cwd that no longer exists inside the new tree is survivable; landing
                // in `/` is better than failing the unit.
                libc::chdir(c"/".as_ptr());
            }
        }

        self.drop_all_capabilities()?;
        Ok(())
    }

    /// Recipe B: clone the tree, mark it read-only atomically, and pivot into it.
    ///
    /// Preferred over remounting every entry in `/proc/self/mountinfo` because it needs no
    /// flag archaeology — a remount inside a user namespace must preserve each mount's
    /// existing locked flags or fail `EPERM` — and because cloning the whole tree also
    /// handles hidden duplicate mounts, which a mountinfo walk leaves writable and
    /// unreachable.
    unsafe fn make_root_read_only(&self) -> Result<(), i32> {
        let root = c"/".as_ptr();

        // Detach our mount propagation from the host's, or every change below would
        // propagate back out.
        if libc::mount(
            std::ptr::null(),
            root,
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        ) != 0
        {
            return Err(errno());
        }

        // Clone the writable directories FIRST, while the tree is still writable. After
        // the root is read-only there is nothing writable left to clone from.
        let mut rw_fds = [-1i32; MAX_WRITABLE];
        let n = self.writable.len().min(MAX_WRITABLE);
        for (slot, dir) in rw_fds.iter_mut().zip(self.writable.iter()).take(n) {
            *slot = libc::syscall(
                SYS_OPEN_TREE,
                libc::AT_FDCWD,
                dir.as_ptr(),
                OPEN_TREE_CLONE
                    | libc::AT_RECURSIVE as libc::c_uint
                    | libc::O_CLOEXEC as libc::c_uint,
            ) as i32;
            // A writable directory that does not exist yet is not fatal — the caller
            // creates OUT_DIR before the unit runs, but a policy may name a path that is
            // absent on this machine, and refusing the whole run for that would be worse
            // than running with one fewer writable directory. The report shows what was
            // granted, so a puzzled user can see it.
        }

        let root_fd = libc::syscall(
            SYS_OPEN_TREE,
            libc::AT_FDCWD,
            root,
            OPEN_TREE_CLONE | libc::AT_RECURSIVE as libc::c_uint | libc::O_CLOEXEC as libc::c_uint,
        ) as i32;
        if root_fd < 0 {
            return Err(errno());
        }

        let attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            ..Default::default()
        };
        let empty = c"".as_ptr();
        if libc::syscall(
            SYS_MOUNT_SETATTR,
            root_fd,
            empty,
            (libc::AT_EMPTY_PATH | libc::AT_RECURSIVE) as libc::c_uint,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        ) != 0
        {
            return Err(errno());
        }

        // A scratch mountpoint to pivot into. It lives on a private tmpfs so it vanishes
        // with the old root and leaves nothing on the host.
        let tmp = c"/tmp".as_ptr();
        let tmpfs = c"tmpfs".as_ptr();
        let mode = c"mode=700".as_ptr();
        if libc::mount(
            tmpfs,
            tmp,
            tmpfs,
            (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong,
            mode as *const libc::c_void,
        ) != 0
        {
            return Err(errno());
        }
        if libc::mkdir(self.scratch.as_ptr(), 0o700) != 0 {
            return Err(errno());
        }
        if libc::syscall(
            SYS_MOVE_MOUNT,
            root_fd,
            empty,
            libc::AT_FDCWD,
            self.scratch.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        ) != 0
        {
            return Err(errno());
        }

        let old_root = libc::open(root, libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC);
        if old_root < 0 {
            return Err(errno());
        }
        if libc::chdir(self.scratch.as_ptr()) != 0 {
            return Err(errno());
        }
        let dot = c".".as_ptr();
        if libc::syscall(libc::SYS_pivot_root, dot, dot) != 0 {
            return Err(errno());
        }
        // Detach the old root. `pivot_root(".", ".")` stacks it on the new root, so this
        // leaves no `put_old` directory behind and nothing of the host tree reachable.
        if libc::fchdir(old_root) != 0 {
            return Err(errno());
        }
        libc::umount2(dot, libc::MNT_DETACH);
        libc::close(old_root);
        if libc::chdir(root) != 0 {
            return Err(errno());
        }

        // Re-attach the writable directories on top of the read-only tree.
        for (fd, dir) in rw_fds.iter().zip(self.writable.iter()).take(n) {
            if *fd < 0 {
                continue;
            }
            libc::mkdir(dir.as_ptr(), 0o700);
            libc::syscall(
                SYS_MOVE_MOUNT,
                *fd,
                empty,
                libc::AT_FDCWD,
                dir.as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH,
            );
            libc::close(*fd);
        }
        Ok(())
    }

    /// Drop every capability, irrevocably.
    ///
    /// **Without this the read-only root is decorative** — a spike child remounted it
    /// read-write and wrote to `/root`. There is no option to skip it.
    unsafe fn drop_all_capabilities(&self) -> Result<(), i32> {
        // Securebits first, with every `*_LOCKED` bit, so nothing below can be undone.
        const SECBIT_NOROOT: libc::c_ulong = 1 << 0;
        const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;
        const SECBIT_NO_SETUID_FIXUP: libc::c_ulong = 1 << 2;
        const SECBIT_NO_SETUID_FIXUP_LOCKED: libc::c_ulong = 1 << 3;
        const SECBIT_KEEP_CAPS_LOCKED: libc::c_ulong = 1 << 5;
        const SECBIT_NO_CAP_AMBIENT_RAISE: libc::c_ulong = 1 << 6;
        const SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED: libc::c_ulong = 1 << 7;
        const PR_SET_SECUREBITS: libc::c_int = 28;

        libc::prctl(
            PR_SET_SECUREBITS,
            SECBIT_NOROOT
                | SECBIT_NOROOT_LOCKED
                | SECBIT_NO_SETUID_FIXUP
                | SECBIT_NO_SETUID_FIXUP_LOCKED
                | SECBIT_KEEP_CAPS_LOCKED
                | SECBIT_NO_CAP_AMBIENT_RAISE
                | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED,
        );

        // The bounding set: what the process could ever regain through exec.
        for cap in 0..=CAP_LAST_CAP {
            libc::prctl(libc::PR_CAPBSET_DROP, cap);
        }
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        );

        let hdr = CapHeader {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [CapData::default(); 2];
        libc::syscall(libc::SYS_capset, &hdr as *const CapHeader, data.as_ptr());

        no_new_privs()
    }
}

/// The most writable directories one unit can have.
///
/// A fixed array because the child cannot allocate. Four is generous: a unit gets
/// `OUT_DIR`, a private temp directory, the run directory, and at most one extra from an
/// explicit `write-paths` entry. A policy asking for more gets the first four and the
/// report shows what was granted, which is better than refusing the build.
const MAX_WRITABLE: usize = 8;

/// No new privileges through `exec`, ever.
///
/// Two independent reasons, and the second is why this is its own function rather than the
/// last line of [`Prepared::drop_all_capabilities`]:
///
/// * a unit that cannot gain privilege through `exec` is the weaker promise this tool
///   should keep even on a host where it could open no namespace at all; and
/// * it is a **precondition for installing a seccomp filter** without `CAP_SYS_ADMIN`.
///   `SECCOMP_SET_MODE_FILTER` returns `EACCES` without it, and the caller installs the
///   notification filter immediately after the child setup returns.
///
/// It is a one-way switch: once set it is inherited and cannot be cleared, which is also
/// why no unit test exercises it. A test that did would change the conditions of every
/// test that ran after it in the same process.
unsafe fn no_new_privs() -> Result<(), i32> {
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        return Err(errno());
    }
    Ok(())
}

/// Write to a procfs file with no allocation.
unsafe fn write_file(path: &std::ffi::CStr, contents: &[u8]) -> Result<(), i32> {
    let fd = libc::open(path.as_ptr(), libc::O_WRONLY);
    if fd < 0 {
        return Err(errno());
    }
    let n = libc::write(fd, contents.as_ptr() as *const libc::c_void, contents.len());
    libc::close(fd);
    if n < 0 {
        return Err(errno());
    }
    Ok(())
}

unsafe fn errno() -> i32 {
    *libc::__errno_location()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn preparation_captures_the_uid_before_any_namespace_exists() {
        // After unshare(CLONE_NEWUSER) and before the map is written, getuid() returns the
        // overflow uid 65534, and mapping THAT fails EPERM. Capturing in the parent is the
        // only order that works, and this test pins it.
        let p = Prepared::new(true, true, true, &[PathBuf::from("/tmp/x")], None).unwrap();
        let real = unsafe { libc::getuid() };
        assert_eq!(p.uid_map, format!("{real} {real} 1\n").into_bytes());
        assert_ne!(real, 65534, "the probe captured the overflow uid");
    }

    #[test]
    fn a_path_containing_a_nul_is_refused_in_the_parent_rather_than_in_the_child() {
        // The child cannot report an error usefully, so every fallible conversion happens
        // before the fork.
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let bad = PathBuf::from(OsString::from_vec(b"/tmp/a\0b".to_vec()));
        assert!(Prepared::new(true, false, true, &[bad], None).is_err());
    }

    #[test]
    fn a_plan_that_asks_for_no_namespace_records_that_it_wants_none() {
        // The base namespaces used to be unconditional, so there was no way to express
        // "apply nothing" — observe mode and a host without user namespaces both need it.
        // `apply_in_child` reads this field first and returns before any `unshare`.
        //
        // It does NOT return before `no_new_privs`: the caller installs a seccomp filter
        // straight after, and that fails EACCES without it. See `no_new_privs`.
        let p = Prepared::new(false, false, false, &[], None).unwrap();
        assert!(
            !p.new_user_ns,
            "an unenforced plan must not ask for a user namespace"
        );
    }

    #[test]
    fn the_writable_limit_is_a_fixed_array_because_the_child_cannot_allocate() {
        let many: Vec<PathBuf> = (0..20)
            .map(|i| PathBuf::from(format!("/tmp/d{i}")))
            .collect();
        let p = Prepared::new(true, false, true, &many, None).unwrap();
        // All are recorded; the child attaches the first MAX_WRITABLE of them, which is
        // enough for OUT_DIR, the private temp dir, the run directory and explicit paths.
        assert_eq!(p.writable.len(), 20);
    }
}
