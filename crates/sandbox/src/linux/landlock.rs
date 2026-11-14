//! The Landlock filesystem tier.
//!
//! Landlock is the preferred filesystem mechanism where the kernel has it: the kernel
//! refuses the write itself, per path, with no supervisor in the loop and no window in
//! which the decision could be raced. The mount namespace is the fallback and stays in
//! place alongside it.
//!
//! # Why this is raw syscalls and not the `landlock` crate
//!
//! Two reasons, and the second one is not a preference.
//!
//! The crate was a dependency of this workspace for months and nothing ever called it —
//! `grep -rn 'landlock::'` returned nothing — so the tier it was carried for did not
//! exist. That is the history, not the argument.
//!
//! The argument is [`restrict_self`]. It runs in the child, between `fork` and `execve`,
//! in a process whose parent has a supervisor thread — so it **must not allocate**: the
//! allocator may be held by a thread that does not exist on this side of the fork. Every
//! ergonomic Landlock API allocates, because building a ruleset means building a list.
//! The split here is the only shape that works: the ruleset is constructed in the parent,
//! where allocation is safe, and the child issues exactly one syscall against the
//! inherited descriptor. A dependency cannot be adapted into that shape from outside.
//!
//! It is the same reasoning the workspace manifest already gives for not taking
//! `seccompiler`: the thing a reviewer has to audit should be in the repository.
//!
//! # What is handled, and what is deliberately not
//!
//! Landlock denies by default *only* the access rights a ruleset declares it handles.
//! Anything not in `handled_access_fs` is untouched. So the handled set is exactly the
//! write-shaped rights and nothing else:
//!
//! * **not `EXECUTE`** — build scripts run `cc`, `pkg-config` and `git`, exec is granted
//!   by default, and handling it would deny every one of them outside a write zone.
//! * **`READ_FILE` / `READ_DIR` only when the policy withholds something.** Reads are
//!   unrestricted by default and the README says so. When `withhold-secret-reads` is on,
//!   the read bits join the handled set and the ruleset grants read beneath everything
//!   *except* the withheld paths — see [`read_roots`], which is where the awkwardness of
//!   expressing a deny-list in an allow-only mechanism lives. With the option off the bits
//!   are not handled at all, so a build that has not asked for this pays nothing and is
//!   restricted in no way it was not before.
//! * **not `IOCTL_DEV`** — not a write, and it is ABI 5+ only.

use std::os::fd::RawFd;
use std::path::Path;

/// The module keeps its own rather than widening `ns::errno`, which is private and
/// `unsafe` there for reasons that belong to that file.
fn errno() -> i32 {
    // SAFETY: `__errno_location` returns a valid pointer for the calling thread.
    unsafe { *libc::__errno_location() }
}

// The three syscalls. Landlock landed long after the asm-generic table had converged with
// x86-64, so unlike most of the numbers in this crate these are the same on every
// architecture — the same situation `bpf.rs` documents for io_uring's 425/426/427. A test
// below pins them rather than trusting that sentence.
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

// LANDLOCK_ACCESS_FS_*, from include/uapi/linux/landlock.h.
const WRITE_FILE: u64 = 1 << 1;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_CHAR: u64 = 1 << 6;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const MAKE_SOCK: u64 = 1 << 9;
const MAKE_FIFO: u64 = 1 << 10;
const MAKE_BLOCK: u64 = 1 << 11;
const MAKE_SYM: u64 = 1 << 12;
/// ABI 2. Linking or renaming *between* directories.
const REFER: u64 = 1 << 13;
/// ABI 3. `O_TRUNC`, `ftruncate`, `creat`.
const TRUNCATE: u64 = 1 << 14;
/// Opening a file for reading. ABI 1.
const READ_FILE: u64 = 1 << 2;
/// Listing a directory. ABI 1.
///
/// Handled together with [`READ_FILE`] and never apart: a build that could open a file but
/// not list its directory fails in ways that look like the file is missing, which sends
/// somebody debugging their own build script rather than reading the refusal.
const READ_DIR: u64 = 1 << 3;

/// Only the first field is ever sent. The kernel accepts a `size` smaller than the struct
/// it knows and treats the rest as zero, so passing eight bytes asks about the filesystem
/// and says nothing about the network or scoping fields that ABI 4 and 6 added. That is
/// what makes one binary work across every ABI without a version ladder here.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// The rights the kernel will accept on a rule keyed to a **non-directory**.
///
/// `landlock_add_rule` rejects the whole rule with `EINVAL` when `allowed_access` carries
/// a bit outside this set and the rule's file is not a directory — the kernel's own check
/// is `rule_attr.allowed_access & ~ACCESS_FILE` against `!S_ISDIR`. Every `MAKE_*` bit is
/// outside it, so passing the full handled mask at a device node fails, and it fails
/// silently in the sense that matters: the ruleset is still created, still applied, still
/// reports `enforced:landlock-vN`, and simply does not contain the rule you asked for.
///
/// Which is what happened. Narrowing `ALWAYS_WRITABLE` from `/dev` to endpoints turned
/// those grants from directory rules into file rules without narrowing the mask, and CI
/// came back with `/bin/sh: 1: cannot create /dev/null: Permission denied` — the same
/// symptom as the seccomp bug that preceded it, from an entirely different cause.
///
/// `EXECUTE` is in the kernel's set and not here, because it is not in `handled_access`
/// either. `READ_FILE` is here because it can be handled — see [`handled_access`] — and a
/// file rule that dropped it would make every granted file unreadable the moment the read
/// bits were handled at all.
const ACCESS_FILE: u64 = WRITE_FILE | TRUNCATE | READ_FILE;

/// The write-shaped rights this kernel understands.
///
/// Masked by ABI because `landlock_create_ruleset` returns `EINVAL` for a bit the running
/// kernel does not know — so a binary built against a newer header would refuse to create
/// any ruleset at all on an older kernel, which is a fallback to nothing dressed as a
/// safety check.
///
/// `restrict_reads` adds the read bits, and it is a parameter rather than always-on because
/// Landlock denies by default **only** what a ruleset declares it handles. Handling reads
/// unconditionally would make every path on the machine unreadable except the ones granted
/// back, on every run, for every user — an allow-list nobody asked for, arriving as a patch
/// release. With nothing withheld the bits stay out of the mask and the kernel restricts
/// reads in no way at all.
pub fn handled_access(abi: i32, restrict_reads: bool) -> u64 {
    let mut a = WRITE_FILE
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_CHAR
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM;
    if abi >= 2 {
        // Without this, a rename between two directories is refused outright on ABI 2+
        // even when both are writable — and `cc` renames its object files.
        a |= REFER;
    }
    if abi >= 3 {
        // `File::create` truncates. A build script that rewrites its generated file on a
        // second run does it constantly, so a handled-but-never-granted TRUNCATE would
        // break the ordinary case on the second build and not the first.
        a |= TRUNCATE;
    }
    if restrict_reads {
        // Both, always. See READ_DIR.
        a |= READ_FILE | READ_DIR;
    }
    a
}

/// The read rights a single read root may be keyed with, given whether it is a directory.
///
/// A regular file cannot take `READ_DIR`: `landlock_add_rule` rejects the whole rule with
/// `EINVAL` when `allowed_access` carries a bit outside [`ACCESS_FILE`] and the file is not a
/// directory (`READ_DIR` is outside it), and the caller skips a rejected rule — so granting a
/// file both bits left it with no rule at all, and a regular-file sibling of a withheld
/// directory (`$HOME/.config` beside a withheld `$HOME/.aws`) became unreadable. A directory
/// takes both; everything else takes `READ_FILE` alone.
fn read_access(is_dir: bool, handled: u64) -> u64 {
    let mut a = handled & READ_FILE;
    if is_dir {
        a |= handled & READ_DIR;
    }
    a
}

/// The directories to grant read on so that everything **except** `withheld` is readable.
///
/// # Expressing a deny-list in a mechanism that only allows
///
/// Landlock has no deny rule. A ruleset handles a right, which denies it everywhere, and
/// then grants it beneath named paths. To withhold `~/.aws` and leave the rest of a home
/// directory readable, the ruleset has to grant every *sibling* of `~/.aws` — and to
/// withhold `~/.config/gh` it has to grant every sibling of that, inside a `~/.config`
/// which is itself granted only entry by entry. So the answer is the complement of the
/// withheld set, computed by walking down from `/` and turning aside at every directory
/// that has something withheld beneath it.
///
/// The result is a handful of rules — `/usr`, `/etc`, `/home/dev/src`, … — rather than one,
/// and it is bounded by the number of entries in the directories along the withheld paths.
/// Measured on an ordinary developer home directory that is tens of rules, not thousands.
///
/// # The property that makes this worth doing rather than granting the parent
///
/// A withheld directory that **does not exist yet** is still excluded. The walk never
/// grants a directory that could contain a withheld name; it grants that directory's
/// current entries one at a time. So creating `~/.aws` after the ruleset is built does not
/// place it inside a granted region — where granting `~` wholesale and relying on `~/.aws`
/// being absent would have.
///
/// The converse limitation, stated because it is real: the grants **are** a snapshot. A
/// directory created in `~` after the ruleset is built is not beneath any granted root and
/// is therefore unreadable, not readable. That fails closed, and it is why this is computed
/// per run rather than cached.
pub fn read_roots(
    withheld: &[std::path::PathBuf],
    list: &dyn Fn(&Path) -> Vec<std::path::PathBuf>,
) -> Vec<std::path::PathBuf> {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    let blocked: BTreeSet<PathBuf> = withheld.iter().cloned().collect();
    // A withheld path that is not absolute, or that carries a `.` or `..` component, cannot
    // be matched against the absolute, lexical paths this walk produces from `/` — so the
    // subtree it names would slip into `out` and stay readable, the exact leak withholding
    // exists to close. Rather than grant a withheld region, refuse every read: an empty grant
    // set is only ever consumed under `restrict_reads`, where reads are handled and deny by
    // default, so it denies all reads and fails closed. The check is lexical on purpose —
    // canonicalisation is not used because a withheld directory may not exist yet.
    if blocked.iter().any(|b| {
        !b.is_absolute()
            || b.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
    }) {
        return Vec::new();
    }
    // Every strict ancestor of a withheld path has to be entered rather than granted.
    let mut enter: BTreeSet<PathBuf> = BTreeSet::new();
    for b in &blocked {
        let mut cur = b.parent();
        while let Some(p) = cur {
            enter.insert(p.to_path_buf());
            cur = p.parent();
        }
    }
    if enter.is_empty() {
        return Vec::new();
    }

    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![PathBuf::from("/")];
    while let Some(dir) = stack.pop() {
        for child in list(&dir) {
            if blocked.contains(&child) {
                // Never granted, and never descended into: the whole subtree is withheld.
                continue;
            }
            if enter.contains(&child) {
                stack.push(child);
            } else {
                out.push(child);
            }
        }
    }
    out.sort();
    out
}

/// Read a directory's entries, or nothing if it cannot be read.
///
/// An unreadable directory yields no grants, which fails closed: the build loses read
/// access beneath it rather than gaining access to something withheld.
pub fn entries(dir: &Path) -> Vec<std::path::PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten().map(|e| e.path()).collect()
}

/// A ruleset built in the parent, ready for the child to apply.
///
/// Holds an open descriptor. Dropping it closes the descriptor; it must therefore outlive
/// the `spawn` that forks the child which will use it.
pub struct Ruleset {
    fd: RawFd,
    abi: i32,
}

impl Ruleset {
    /// Build a ruleset granting the write rights beneath each of `writable`.
    ///
    /// `Ok(None)` means this host has no Landlock and the caller should fall back — not an
    /// error. `Err` means Landlock is present and refused, which is worth surfacing
    /// because it usually means the mask and the kernel disagree.
    pub fn build(
        abi: i32,
        writable: &[std::path::PathBuf],
        withheld: &[std::path::PathBuf],
    ) -> Result<Option<Self>, i32> {
        if abi < 1 {
            return Ok(None);
        }
        let restrict_reads = !withheld.is_empty();
        let handled = handled_access(abi, restrict_reads);
        let attr = RulesetAttr {
            handled_access_fs: handled,
        };

        // SAFETY: `attr` is a live local of exactly the size passed.
        let fd = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0,
            )
        };
        if fd < 0 {
            let e = errno();
            // ENOSYS is a kernel with the syscall compiled out, which the probe should
            // already have caught; treat it as absence rather than failure either way.
            if e == libc::ENOSYS || e == libc::EOPNOTSUPP {
                return Ok(None);
            }
            return Err(e);
        }
        let ruleset = Ruleset {
            fd: fd as RawFd,
            abi,
        };

        for dir in writable {
            // A write zone that does not exist yet is not fatal, for the same reason it is
            // not fatal in `ns.rs`: the caller creates them, and one that is missing means
            // one fewer writable directory rather than a build that cannot start. It fails
            // closed — the unit simply cannot write there.
            ruleset.allow(dir.as_path(), handled, true)?;
        }
        // The paths every unit may write to whatever the policy says: `/dev/null` and the
        // handful of device nodes that behave like it. See `crate::ALWAYS_WRITABLE`, which
        // the seccomp write decider reads from too so the two rungs cannot come to
        // disagree — they did, and it cost four CI rounds because the seccomp layer
        // answers first.
        //
        // These are files, not directories, which changes two things. The open must not
        // demand `O_DIRECTORY`, and the mask must be `endpoint_access` — the full handled
        // mask carries `MAKE_*` bits that the kernel refuses on a non-directory, taking
        // the whole rule with them. See `ACCESS_FILE`.
        //
        // A failure on one entry is skipped rather than propagated, which the write zones
        // above deliberately do not do. The difference is what each one means: a zone the
        // policy granted must be grantable or the ruleset is not the one the report will
        // claim, whereas these are a compatibility allowance, and taking down the whole
        // ruleset — and with it the enforced filesystem tier — because some container
        // presents `/dev/tty` in a shape the kernel will not key a rule on would trade the
        // boundary for a convenience. Skipping fails closed: one fewer writable endpoint.
        let endpoint = handled & ACCESS_FILE;
        for extra in crate::ALWAYS_WRITABLE {
            let _ = ruleset.allow(Path::new(extra), endpoint, false);
        }

        // The read complement, last, so a failure here cannot cost a write zone that was
        // already granted. Each root is granted the READ bits only: a directory the unit
        // may read is not thereby a directory it may write, and handing out the write mask
        // here would quietly widen every write zone to the whole filesystem.
        if restrict_reads {
            for root in read_roots(withheld, &entries) {
                // Open the root ONCE, with O_NOFOLLOW, and use that single descriptor for both
                // the symlink/type check and the rule. A separate lstat-then-open would leave a
                // window in which the final component could be swapped for a symlink, after
                // which the open would follow it and Landlock would key the rule to the withheld
                // target. `open_read_root_nofollow` returns `None` for a symlink root — and for
                // anything it cannot open or classify — so it is skipped, never granted. Fail
                // closed, the same direction every skip in this function takes.
                let Some((fd, is_dir)) = open_read_root_nofollow(&root) else {
                    continue;
                };
                // `READ_DIR` only where the root is a directory — a regular file rule carrying
                // it is rejected outright and would leave that file unreadable (see
                // `read_access`).
                let _ = ruleset.add_rule(fd, read_access(is_dir, handled));
                // SAFETY: we opened `fd` and nothing else holds it.
                unsafe { libc::close(fd) };
            }
        }
        Ok(Some(ruleset))
    }

    /// Grant `access` beneath `path`.
    ///
    /// `must_be_dir` is the caller saying which of the two kinds of path this is: a write
    /// zone, where anything but a directory means the grant would cover far less than
    /// intended, or a device endpoint from [`crate::ALWAYS_WRITABLE`], which is a file and
    /// would be skipped outright if the open demanded a directory. That is not a
    /// hypothetical: `/dev` used to be granted as a directory, and narrowing the constant
    /// to endpoints without this flag would have left every one of them silently ungranted
    /// and `2>/dev/null` refused again.
    ///
    /// A path that does not exist is skipped rather than refused: for a write zone the
    /// caller creates them and one missing means one fewer writable directory, and for a
    /// device node a container without `/dev/tty` is ordinary. Both fail closed — the unit
    /// simply cannot write there.
    fn allow(&self, path: &Path, access: u64, must_be_dir: bool) -> Result<(), i32> {
        let Some(parent_fd) = open_path(path, must_be_dir) else {
            return Ok(());
        };
        let r = self.add_rule(parent_fd, access);
        // SAFETY: we opened it and nothing else holds it.
        unsafe { libc::close(parent_fd) };
        r
    }

    /// Add a path-beneath rule keyed on an already-open `O_PATH` descriptor, granting
    /// `access` beneath it. The caller owns `parent_fd` and closes it; splitting the open
    /// out of the rule creation lets a read root be opened **once** with `O_NOFOLLOW` and
    /// that same descriptor both type-checked and keyed, which is what closes the symlink
    /// check-to-use race (see the read-root loop and [`open_read_root_nofollow`]).
    fn add_rule(&self, parent_fd: RawFd, access: u64) -> Result<(), i32> {
        let rule = PathBeneathAttr {
            allowed_access: access,
            parent_fd,
        };
        // SAFETY: `rule` is live for the call; `parent_fd` is an open O_PATH descriptor.
        let rc = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                self.fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const PathBeneathAttr,
                0,
            )
        };
        // Captured before the caller's `close`, which could otherwise clobber it.
        if rc != 0 {
            Err(errno())
        } else {
            Ok(())
        }
    }

    /// The descriptor to hand the child.
    ///
    /// Borrowed, not transferred: this type still owns it and closes it on drop, so the
    /// `Ruleset` must outlive the `spawn` that forks the child which will apply it. The
    /// caller passes the bare integer into `pre_exec` precisely so the closure captures a
    /// `Copy` value rather than the owner, whose `Drop` would then run in whichever
    /// process reached it first.
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// The tier label this ruleset earns, e.g. `landlock-v7`.
    ///
    /// The ABI number is in the label rather than behind an accessor because that is the
    /// only place it is needed: a reader of a report has to be able to tell a v1 ruleset,
    /// which cannot express `REFER` and therefore refuses cross-directory renames, from a
    /// v3 one that can.
    pub fn mechanism(&self) -> String {
        format!("landlock-v{}", self.abi)
    }
}

impl Drop for Ruleset {
    /// Closes the ruleset descriptor. See [`Ruleset::raw_fd`] for why the lifetime of this
    /// value is load-bearing rather than incidental.
    fn drop(&mut self) {
        // SAFETY: this type owns the descriptor.
        unsafe { libc::close(self.fd) };
    }
}

/// An `O_PATH` handle for Landlock to key a rule on, or `None` if the path cannot be
/// opened — as a directory when `must_be_dir`, and as anything otherwise.
///
/// `None` is not an error: a write zone the caller has not created yet, or a `/dev` that
/// does not exist in some minimal container, means one fewer rule rather than a build that
/// cannot start. It fails closed — the unit simply cannot write there.
fn open_path(path: &Path, must_be_dir: bool) -> Option<RawFd> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    // O_PATH: we want a handle for Landlock to key the rule on, not the ability to read
    // through it. O_CLOEXEC so a failure between here and `execve` cannot leak it.
    //
    // O_DIRECTORY when the caller says the path is a write zone: a rule accidentally
    // placed on a file where a directory was meant would grant far less than intended
    // while saying nothing about it, and failing the open is the louder answer. The device
    // endpoints are files, so they are opened without it — see `Ruleset::allow`.
    let mut flags = libc::O_PATH | libc::O_CLOEXEC;
    if must_be_dir {
        flags |= libc::O_DIRECTORY;
    }
    // SAFETY: `c` is a live NUL-terminated string.
    let fd = unsafe { libc::open(c.as_ptr(), flags) };
    if fd < 0 {
        None
    } else {
        Some(fd)
    }
}

/// An `O_PATH | O_NOFOLLOW` handle for a read root and whether it is a directory — or `None`
/// if it cannot be opened, cannot be `fstat`ed, or **is a symlink**.
///
/// One open, used for both the type check and the rule, is the whole point. Checking a path
/// with a separate `lstat` and then opening it again in [`open_path`] leaves a window in which
/// the final component can be swapped for a symlink; the second open, without `O_NOFOLLOW`,
/// would then follow it and Landlock would key the rule to the resolved target — the withheld
/// secret. `O_NOFOLLOW` with `O_PATH` does not fail on a symlink (that is the non-`O_PATH`
/// behaviour, `ELOOP`); it returns a descriptor to the **link itself**, which `fstat` then
/// identifies as `S_IFLNK` and this rejects. On anything else the descriptor refers to the
/// real object and is handed straight to [`Ruleset::add_rule`], with no second resolution to
/// race. Fails closed on every uncertainty: one fewer readable region, never one more.
///
/// `O_NOFOLLOW` only governs the final component; a symlink in a *parent* component is still
/// resolved, as it was when [`read_roots`] walked the tree to produce this path in the first
/// place. Closing that as well needs `openat2(RESOLVE_NO_SYMLINKS)` and is out of scope here.
fn open_read_root_nofollow(path: &Path) -> Option<(RawFd, bool)> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    let flags = libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: `c` is a live NUL-terminated string.
    let fd = unsafe { libc::open(c.as_ptr(), flags) };
    if fd < 0 {
        return None;
    }
    // SAFETY: `fd` is a valid open descriptor; `st` is zeroed and fully written by `fstat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        // SAFETY: we opened `fd` and nothing else holds it.
        unsafe { libc::close(fd) };
        return None;
    }
    let kind = st.st_mode & libc::S_IFMT;
    if kind == libc::S_IFLNK {
        // A symlink root: O_NOFOLLOW handed us the link itself. Never grant on it.
        // SAFETY: we opened `fd` and nothing else holds it.
        unsafe { libc::close(fd) };
        return None;
    }
    Some((fd, kind == libc::S_IFDIR))
}

/// Apply a ruleset to the calling process. **Child side.**
///
/// One syscall, no allocation, no locking, no panic — see the module docs for why that is
/// a requirement rather than a style. Must be called after `no_new_privs`, which
/// `ns::Prepared::apply_in_child` sets on every path it can return `Ok` from:
/// `landlock_restrict_self` returns `EPERM` without it.
///
/// # Safety
///
/// Call only between `fork` and `execve`, in the child. It is irreversible for this
/// process and every process it goes on to exec.
pub unsafe fn restrict_self(fd: RawFd) -> Result<(), i32> {
    if libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0) != 0 {
        return Err(errno());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_syscall_numbers_are_the_same_on_every_architecture() {
        // Landlock landed after the asm-generic table converged with x86-64, so one number
        // is right everywhere — the same rare case as io_uring's 425/426/427 in `bpf.rs`.
        // Asserted rather than trusted, because a table copied down from the wrong
        // architecture is how a sandbox comes to call an unrelated syscall and conclude
        // the mechanism is missing.
        assert_eq!(SYS_LANDLOCK_CREATE_RULESET, 444);
        assert_eq!(SYS_LANDLOCK_ADD_RULE, 445);
        assert_eq!(SYS_LANDLOCK_RESTRICT_SELF, 446);
    }

    #[test]
    fn reads_and_exec_are_never_handled_on_any_abi() {
        // The load-bearing test in this file. Handling a right means denying it everywhere
        // a rule does not grant it, so a stray bit here would silently turn buildclamp
        // into a tool that restricts reads — which the README states twice that it does
        // not do — or one that denies `cc` outside OUT_DIR.
        const EXECUTE: u64 = 1 << 0;
        const READ_FILE: u64 = 1 << 2;
        const READ_DIR: u64 = 1 << 3;
        for abi in 1..=10 {
            let h = handled_access(abi, false);
            assert_eq!(h & EXECUTE, 0, "ABI {abi} handled EXECUTE");
            assert_eq!(h & READ_FILE, 0, "ABI {abi} handled READ_FILE");
            assert_eq!(h & READ_DIR, 0, "ABI {abi} handled READ_DIR");
        }
    }

    #[test]
    fn the_mask_grows_with_the_abi_and_never_shrinks() {
        // A newer kernel must never be handed fewer rights than an older one, and an older
        // kernel must never be handed a bit it will reject with EINVAL.
        let v1 = handled_access(1, false);
        let v2 = handled_access(2, false);
        let v3 = handled_access(3, false);
        assert_eq!(v1 & REFER, 0, "REFER is ABI 2");
        assert_eq!(v1 & TRUNCATE, 0, "TRUNCATE is ABI 3");
        assert_eq!(v2 & REFER, REFER);
        assert_eq!(v2 & TRUNCATE, 0);
        assert_eq!(v3 & TRUNCATE, TRUNCATE);
        assert_eq!(v1 & v2, v1, "v2 must be a superset of v1");
        assert_eq!(v2 & v3, v2, "v3 must be a superset of v2");
        // An ABI above the newest one this file knows must not add unknown bits.
        assert_eq!(handled_access(99, false), v3);
    }

    #[test]
    fn write_shaped_rights_are_all_present_from_abi_one() {
        let h = handled_access(1, false);
        for (name, bit) in [
            ("WRITE_FILE", WRITE_FILE),
            ("REMOVE_DIR", REMOVE_DIR),
            ("REMOVE_FILE", REMOVE_FILE),
            ("MAKE_DIR", MAKE_DIR),
            ("MAKE_REG", MAKE_REG),
            ("MAKE_SYM", MAKE_SYM),
            ("MAKE_SOCK", MAKE_SOCK),
            ("MAKE_FIFO", MAKE_FIFO),
            ("MAKE_CHAR", MAKE_CHAR),
            ("MAKE_BLOCK", MAKE_BLOCK),
        ] {
            assert_eq!(h & bit, bit, "{name} missing from the ABI 1 mask");
        }
    }

    #[test]
    fn read_roots_grants_siblings_and_excludes_the_withheld_subtree() {
        use std::path::PathBuf;
        // A fake filesystem, so the walk is exercised without touching disk.
        let fs = |dir: &Path| -> Vec<PathBuf> {
            match dir.to_str().unwrap() {
                "/" => vec![PathBuf::from("/home"), PathBuf::from("/etc")],
                "/home" => vec![PathBuf::from("/home/user")],
                "/home/user" => vec![
                    PathBuf::from("/home/user/.aws"),
                    PathBuf::from("/home/user/project"),
                ],
                _ => Vec::new(),
            }
        };
        let roots = read_roots(&[PathBuf::from("/home/user/.aws")], &fs);
        assert_eq!(
            roots,
            vec![PathBuf::from("/etc"), PathBuf::from("/home/user/project")],
            "the withheld subtree is excluded and its siblings granted one at a time"
        );
        assert!(
            !roots.iter().any(|r| r.starts_with("/home/user/.aws")),
            "the withheld path must never end up granted"
        );
    }

    #[test]
    fn read_roots_fails_closed_on_a_non_absolute_or_dotdot_withheld_path() {
        use std::path::PathBuf;
        // The walk never runs for these: a withheld path that is relative or carries `.`/`..`
        // cannot be matched against the absolute paths the walk produces, so granting its
        // parent would leave the secret readable. Refusing every read (an empty grant set,
        // under restrict_reads) is the fail-closed answer.
        let fs = |_: &Path| Vec::new();
        for bad in [".aws", "home/user/.aws", "/home/../etc/secret", "/home/./x"] {
            assert!(
                read_roots(&[PathBuf::from(bad)], &fs).is_empty(),
                "`{bad}` is not absolute-normalised and must fail closed to no read grants"
            );
        }
    }

    #[test]
    fn a_symlink_read_root_is_never_granted() {
        // The leak this closes: `read_roots` compares a candidate's OWN path to the withheld
        // set, but the grant that follows resolves symlinks, so a symlink beside a withheld path
        // would be granted READ on its target. The single `O_NOFOLLOW` open returns the link's
        // own descriptor, which `fstat` identifies and this rejects (`None`) — with no second
        // resolution to race — while a real directory and a real file open to themselves with
        // the correct `is_dir`, so ordinary reads are unaffected.
        let dir = tempfile::tempdir().expect("a scratch dir");
        let real_dir = dir.path().join("realdir");
        std::fs::create_dir(&real_dir).unwrap();
        let real_file = dir.path().join("realfile");
        std::fs::write(&real_file, b"x").unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, b"top secret").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        // Open, record whether it was accepted (and its is_dir), and close so nothing leaks.
        let opened = |p: &Path| -> Option<bool> {
            open_read_root_nofollow(p).map(|(fd, is_dir)| {
                // SAFETY: `fd` came from `open_read_root_nofollow` and nothing else holds it.
                unsafe { libc::close(fd) };
                is_dir
            })
        };

        assert_eq!(
            opened(&real_dir),
            Some(true),
            "a real directory opens as a dir root"
        );
        assert_eq!(
            opened(&real_file),
            Some(false),
            "a real file opens as a file root"
        );
        assert_eq!(
            opened(&link),
            None,
            "a symlink read root must be rejected, never granted"
        );
        // A dangling symlink (target removed) is still a symlink: O_NOFOLLOW opens the link and
        // `fstat` still reports `S_IFLNK`, so it is still rejected.
        std::fs::remove_file(&secret).unwrap();
        assert_eq!(opened(&link), None, "a dangling symlink is still rejected");
        // A path that does not exist cannot be opened, so it is skipped — one fewer readable
        // region, never one more.
        assert_eq!(
            opened(&dir.path().join("nonexistent")),
            None,
            "a nonexistent root is skipped"
        );
    }

    #[test]
    fn a_read_root_takes_read_dir_only_when_it_is_a_directory() {
        // A regular-file read root keyed with READ_DIR is rejected whole (see ACCESS_FILE),
        // so a file sibling of a withheld directory would become unreadable. It must get
        // READ_FILE alone; a directory gets both.
        let handled = READ_FILE | READ_DIR;
        assert_eq!(read_access(true, handled), READ_FILE | READ_DIR);
        assert_eq!(read_access(false, handled), READ_FILE);
        assert_eq!(read_access(false, handled) & READ_DIR, 0);
        // A kernel that does not handle the read bits contributes neither, whatever the type.
        assert_eq!(read_access(true, 0), 0);
    }

    #[test]
    fn a_rule_on_a_device_node_carries_only_rights_the_kernel_allows_on_a_file() {
        // The regression for a whole CI round. `landlock_add_rule` checks
        // `allowed_access & ~ACCESS_FILE` when the rule's path is not a directory and
        // rejects the rule outright, so a `MAKE_*` bit at `/dev/null` loses the grant —
        // and loses it quietly: the ruleset is still created, still applied, and still
        // reports `enforced:landlock-vN`. The only symptom is a build script whose
        // `2>/dev/null` no longer works.
        //
        // This project's development host has no Landlock, so the mask cannot be checked
        // against a running kernel here. It can be checked against the rule.
        for abi in 1..=7 {
            let e = handled_access(abi, false) & ACCESS_FILE;
            for (name, bit) in [
                ("REMOVE_DIR", REMOVE_DIR),
                ("REMOVE_FILE", REMOVE_FILE),
                ("MAKE_CHAR", MAKE_CHAR),
                ("MAKE_DIR", MAKE_DIR),
                ("MAKE_REG", MAKE_REG),
                ("MAKE_SOCK", MAKE_SOCK),
                ("MAKE_FIFO", MAKE_FIFO),
                ("MAKE_BLOCK", MAKE_BLOCK),
                ("MAKE_SYM", MAKE_SYM),
                ("REFER", REFER),
            ] {
                assert_eq!(
                    e & bit,
                    0,
                    "ABI {abi}: {name} is directory-only, and the kernel refuses the whole \
                     rule rather than ignoring the bit"
                );
            }
            // And it must still grant what a redirect actually needs.
            assert_eq!(e & WRITE_FILE, WRITE_FILE, "ABI {abi}: no WRITE_FILE");
            assert!(
                e & !handled_access(abi, false) == 0,
                "ABI {abi}: an endpoint may never be granted a right the ruleset does not \
                 handle — `landlock_add_rule` refuses that too"
            );
        }
        // TRUNCATE arrives at ABI 3 and is file-applicable, so it belongs here from then
        // on: `>` truncates, and a redirect to an existing /dev/null does it every time.
        assert_eq!(handled_access(2, false) & ACCESS_FILE & TRUNCATE, 0);
        assert_eq!(handled_access(3, false) & ACCESS_FILE & TRUNCATE, TRUNCATE);
    }

    #[test]
    fn the_attr_structs_match_the_uapi_layout() {
        // `size` is passed to the kernel, so a layout change here is a wire-format change.
        assert_eq!(std::mem::size_of::<RulesetAttr>(), 8);
        // `landlock_path_beneath_attr` is __attribute__((packed)) in the uapi header:
        // u64 + i32 with no tail padding.
        assert_eq!(std::mem::size_of::<PathBeneathAttr>(), 12);
    }

    #[test]
    fn a_kernel_without_landlock_reports_absence_rather_than_failing() {
        // abi 0 is what `probe::landlock_abi` maps ENOSYS to. Absence is not an error: the
        // caller falls back to the mount namespace and the tier says which one applied.
        assert!(matches!(Ruleset::build(0, &[], &[]), Ok(None)));
    }
}
