//! Working out which proc-macro made a request.
//!
//! A proc-macro is a shared object that rustc loads and calls while compiling the
//! *consumer*. There is no separate process, so a sandbox around rustc constrains every
//! proc-macro in that compilation identically, and when something reaches the network it
//! can only say "something in this compilation did it". `cargo-acl`, the nearest existing
//! tool, documents exactly that limitation: one grant covers every proc-macro in the
//! build.
//!
//! This module does better, and says how confident it is.
//!
//! | source | confidence |
//! |---|---|
//! | the instruction pointer at the syscall is inside a known proc-macro's `.so` | `exact` |
//! | it is in libc or libstd, but a stack scan finds that `.so`'s frame | `stack-scan` |
//! | neither | `closure` — what every other tool gives |
//!
//! It degrades to the incumbent's answer, never to nothing. See `docs/adr/0004`.
//!
//! # Why the stack scan is a heuristic and is labelled one
//!
//! A scan of the stack region for values that fall inside a mapped `.so` will also find
//! stale frames from an earlier call that has already returned. So it names a likely
//! culprit rather than a certain one, and the report carries the distinction rather than
//! flattening it. Presenting a scan hit as certain would be exactly the overclaiming this
//! project criticises in others.

use std::path::{Path, PathBuf};

use buildclamp_core::{Attribution, UnitId};

/// Attribute one request.
///
/// `ip` is the instruction pointer the kernel recorded in `seccomp_data`, which is where
/// the syscall was made from.
pub fn attribute(tid: i32, ip: u64, proc_macros: &[(PathBuf, UnitId)]) -> Attribution {
    if proc_macros.is_empty() {
        // A build script: the unit is already one crate's code, so there is nothing to
        // narrow down.
        return Attribution::Unit;
    }
    let Some(maps) = read_maps(tid) else {
        return Attribution::Closure;
    };

    if ip != 0 {
        if let Some(id) = owner_of(ip, &maps, proc_macros) {
            return Attribution::Exact { proc_macro: id };
        }
    }

    // The instruction pointer is in libc or libstd, which is where it will be whenever the
    // call goes through the dynamically linked C library — the common case for anything
    // using `std::net` or `std::fs`. Fall back to the stack.
    match stack_scan(tid, &maps, proc_macros) {
        Some(id) => Attribution::StackScan { proc_macro: id },
        None => Attribution::Closure,
    }
}

/// One mapped region of the target's address space.
#[derive(Clone, Debug)]
struct Mapping {
    start: u64,
    end: u64,
    path: Option<PathBuf>,
    /// Executable, so it can contain a return address worth matching.
    executable: bool,
    /// Writable and not file-backed: a stack or a heap, which is what the scan reads.
    anonymous_rw: bool,
}

fn read_maps(tid: i32) -> Option<Vec<Mapping>> {
    let text = std::fs::read_to_string(format!("/proc/{tid}/maps")).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let perms = parts.next().unwrap_or("");
        let path = parts.nth(3).map(PathBuf::from);
        let (a, b) = range.split_once('-')?;
        let start = u64::from_str_radix(a, 16).ok()?;
        let end = u64::from_str_radix(b, 16).ok()?;
        out.push(Mapping {
            start,
            end,
            executable: perms.contains('x'),
            anonymous_rw: perms.starts_with("rw") && path.is_none(),
            path,
        });
    }
    Some(out)
}

/// Which proc-macro, if any, owns the mapping containing `addr`.
fn owner_of(addr: u64, maps: &[Mapping], proc_macros: &[(PathBuf, UnitId)]) -> Option<UnitId> {
    let m = maps
        .iter()
        .find(|m| addr >= m.start && addr < m.end && m.executable)?;
    let path = m.path.as_ref()?;
    matching_macro(path, proc_macros)
}

/// Compare by file name rather than by full path.
///
/// The path in `/proc/<tid>/maps` is the one rustc opened, and cargo hands rustc an
/// absolute path into the target directory — but a container bind-mount, a different
/// working directory, or a `--target-dir` can make the two spellings differ while naming
/// the same file. The hashed file name cargo generates is unique within a build, so it is
/// the reliable half.
fn matching_macro(path: &Path, proc_macros: &[(PathBuf, UnitId)]) -> Option<UnitId> {
    let name = path.file_name()?;
    proc_macros
        .iter()
        .find(|(p, _)| p.file_name() == Some(name))
        .map(|(_, id)| id.clone())
}

/// Scan the target's stack for a return address inside a known proc-macro.
///
/// Bounded deliberately: a stack can be megabytes, and this runs while the target is
/// blocked waiting for an answer. 64 KiB from the current stack pointer covers the call
/// depth a proc-macro expansion reaches without turning every notification into a long
/// read.
fn stack_scan(tid: i32, maps: &[Mapping], proc_macros: &[(PathBuf, UnitId)]) -> Option<UnitId> {
    let sp = read_stack_pointer(tid)?;
    let region = maps
        .iter()
        .find(|m| m.anonymous_rw && sp >= m.start && sp < m.end)?;
    let len = (region.end - sp).min(64 * 1024) as usize;
    let words = read_mem_words(tid, sp, len)?;
    for w in words {
        if let Some(id) = owner_of(w, maps, proc_macros) {
            return Some(id);
        }
    }
    None
}

/// The stack pointer, from `/proc/<tid>/syscall`.
///
/// That file is `nr arg0 … arg5 sp pc` while a thread is in a syscall, which is exactly
/// when the supervisor is looking. It can be unavailable under some hardening
/// configurations, and the rule then is to degrade to `closure` rather than guess.
fn read_stack_pointer(tid: i32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{tid}/syscall")).ok()?;
    let fields: Vec<&str> = text.split_whitespace().collect();
    if fields.len() < 9 || fields[0] == "running" {
        return None;
    }
    parse_hex(fields[7])
}

fn parse_hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

fn read_mem_words(tid: i32, addr: u64, len: usize) -> Option<Vec<u64>> {
    use std::os::unix::fs::FileExt;
    let f = std::fs::File::open(format!("/proc/{tid}/mem")).ok()?;
    let mut buf = vec![0u8; len];
    let n = f.read_at(&mut buf, addr).ok()?;
    Some(
        buf[..n]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_ne_bytes(*c))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn macros() -> Vec<(PathBuf, UnitId)> {
        vec![(
            PathBuf::from("/proj/target/debug/deps/libserde_derive-b7afaca4.so"),
            UnitId::new("serde_derive", "1.0.229"),
        )]
    }

    fn maps() -> Vec<Mapping> {
        vec![
            Mapping {
                start: 0x1000,
                end: 0x2000,
                path: Some(PathBuf::from("/usr/lib/libc.so.6")),
                executable: true,
                anonymous_rw: false,
            },
            Mapping {
                start: 0x5000,
                end: 0x6000,
                path: Some(PathBuf::from(
                    "/elsewhere/target/debug/deps/libserde_derive-b7afaca4.so",
                )),
                executable: true,
                anonymous_rw: false,
            },
        ]
    }

    #[test]
    fn a_build_script_needs_no_narrowing_because_the_unit_is_already_one_crate() {
        assert_eq!(attribute(0, 0x1234, &[]), Attribution::Unit);
    }

    #[test]
    fn an_address_inside_a_proc_macro_names_that_macro() {
        let id = owner_of(0x5500, &maps(), &macros()).unwrap();
        assert_eq!(id, UnitId::new("serde_derive", "1.0.229"));
    }

    #[test]
    fn an_address_in_libc_names_nothing_which_is_what_triggers_the_stack_scan() {
        assert_eq!(owner_of(0x1500, &maps(), &macros()), None);
    }

    #[test]
    fn matching_is_by_file_name_so_a_bind_mount_does_not_break_attribution() {
        // The path rustc opened and the path buildclamp recorded can differ — a container
        // bind mount, a different working directory, a --target-dir. The hashed file name
        // cargo generates is unique within a build, so it is the reliable half.
        let id = matching_macro(
            Path::new("/completely/other/prefix/libserde_derive-b7afaca4.so"),
            &macros(),
        );
        assert_eq!(id, Some(UnitId::new("serde_derive", "1.0.229")));
    }

    #[test]
    fn a_non_executable_mapping_is_never_the_answer() {
        // A return address must point into executable memory. Matching a data mapping
        // would attribute a request to whichever macro happened to have its rodata there.
        let mut m = maps();
        m[1].executable = false;
        assert_eq!(owner_of(0x5500, &m, &macros()), None);
    }

    #[test]
    fn a_thread_that_is_not_in_a_syscall_yields_no_stack_pointer() {
        // /proc/<tid>/syscall reads "running" for a thread on a CPU. Parsing that as an
        // address would scan a garbage region.
        assert!(read_stack_pointer(0).is_none());
    }

    #[test]
    fn attribution_degrades_to_the_closure_when_the_process_is_gone() {
        // Never a guess: an unreadable target means the same answer every other tool
        // gives, not an invented one.
        assert_eq!(attribute(0, 0x5500, &macros()), Attribution::Closure);
    }
}
