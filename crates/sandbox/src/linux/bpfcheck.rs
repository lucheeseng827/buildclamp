//! A reference interpreter for the filter, and the property that holds it honest.
//!
//! # Why an interpreter and not more unit tests
//!
//! `bpf::build` emits a classic-BPF program whose control flow is **relative jump
//! offsets**, resolved from forward labels after the fact. That is the part nobody can
//! read: a unit test asserting that instruction 14 is `JEQ 41, +9, +0` is a test of what
//! somebody typed, not of where the jump lands. An off-by-one in label resolution, an
//! instruction inserted between a jump and its target, a `jset` whose true and false arms
//! swap — each produces a filter that assembles, installs, and silently answers the wrong
//! question for some syscall.
//!
//! That class fails **open**. A jump that skips the `notify` return and falls into the
//! trailing `ALLOW` is a hole in the tier the whole product is a claim about, and nothing
//! about it looks wrong: the process runs, the build passes, the report says `enforced`.
//!
//! So the program is executed rather than inspected. [`run`] is a classic-BPF interpreter
//! over the instruction subset the builder emits; [`expected`] is a second, independent
//! statement of what the answer should be, written from the syscall tables rather than
//! from the program. Where they disagree, one of them is wrong and the test says which
//! input found it.
//!
//! # What this cannot catch
//!
//! A shared misunderstanding. If [`expected`] and `build` both believe `openat2` should be
//! notified unconditionally and the kernel disagrees about what that buys, both agree and
//! both are wrong. The differential covers **encoding**: offsets, ordering, the
//! architecture gate, flag masks. What the filter ought to say is the unit tests' and the
//! end-to-end suite's question, and it is asked there against a real kernel.
//!
//! It is also not the kernel's interpreter. It implements the four instruction classes
//! this builder uses and rejects everything else rather than guessing — a program that
//! reached an instruction this does not implement would be one whose behaviour this file
//! cannot speak for, and saying so is better than an answer nobody should trust.
//!
//! # The fuzz target
//!
//! `fuzz/fuzz_targets/bpf_differential.rs` calls [`check`] with bytes from libFuzzer. The
//! same function runs under `cargo test` over a deterministic sweep, so the property is
//! exercised on every commit rather than only where a fuzzer is installed — which is the
//! difference between a property and an aspiration.

use libc::sock_filter;

use super::bpf::{self, Arch, FilterOptions};

/// One `struct seccomp_data`, as the filter sees it.
///
/// The kernel presents this as a packet: `nr` at offset 0, `arch` at 4, the instruction
/// pointer at 8, and six 64-bit arguments from 16. [`run`] loads from those offsets, which
/// is the layout `bpf.rs` computes its own offsets from — deliberately duplicated here, so
/// that a change to one is a disagreement rather than a silent shared edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

impl SeccompData {
    /// A 32-bit word at a byte offset, the way `BPF_LD | BPF_W | BPF_ABS` reads one.
    ///
    /// `None` for an offset outside the structure or not word-aligned, because that is
    /// what the kernel does: the load fails and the program is terminated. Returning zero
    /// instead would make an out-of-range load look like a syscall number of zero, which
    /// is `read` on x86-64 — an interpreter that quietly answered about the wrong syscall
    /// is worse than one that refuses.
    fn word(&self, off: u32) -> Option<u32> {
        if !off.is_multiple_of(4) {
            return None;
        }
        match off {
            0 => Some(self.nr as u32),
            4 => Some(self.arch),
            8 => Some(self.instruction_pointer as u32),
            12 => Some((self.instruction_pointer >> 32) as u32),
            16..=63 => {
                let i = ((off - 16) / 8) as usize;
                let hi = (off - 16) % 8 == 4;
                let v = self.args[i];
                Some(if hi { (v >> 32) as u32 } else { v as u32 })
            }
            _ => None,
        }
    }
}

/// What happened when the program ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The program returned. This is the value the kernel would act on.
    Return(u32),
    /// The program did something this interpreter will not speak for, and here is what.
    Refused(String),
}

/// The instruction budget.
///
/// The builder emits only forward jumps, so no program it produces can loop — but this
/// interpreter is also pointed at programs a fuzzer mutated, and a backward jump there
/// would hang the target rather than fail it. The limit is generous next to the real
/// filter, which is a few hundred instructions.
const MAX_STEPS: usize = 100_000;

/// Execute a classic-BPF program against one syscall record.
pub fn run(prog: &[sock_filter], data: &SeccompData) -> Verdict {
    let mut a: u32 = 0;
    let mut pc: usize = 0;
    let mut steps = 0usize;

    loop {
        steps += 1;
        if steps > MAX_STEPS {
            return Verdict::Refused(format!("ran for more than {MAX_STEPS} instructions"));
        }
        let Some(i) = prog.get(pc) else {
            // The kernel rejects a program that can run off the end at load time; one
            // that reaches here was not validated, and this is that finding.
            return Verdict::Refused(format!("ran off the end at pc={pc}"));
        };
        let code = u32::from(i.code);
        pc += 1;

        const LD_W_ABS: u32 = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
        const JMP_JEQ_K: u32 = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
        const JMP_JSET_K: u32 = libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K;
        const JMP_JA: u32 = libc::BPF_JMP | libc::BPF_JA;
        const RET_K: u32 = libc::BPF_RET | libc::BPF_K;

        match code {
            LD_W_ABS => match data.word(i.k) {
                Some(v) => a = v,
                None => {
                    return Verdict::Refused(format!(
                        "loaded from offset {} which is outside struct seccomp_data",
                        i.k
                    ))
                }
            },
            JMP_JEQ_K | JMP_JSET_K => {
                let taken = if code == JMP_JEQ_K {
                    a == i.k
                } else {
                    a & i.k != 0
                };
                // Offsets are u8 and unsigned: classic BPF cannot jump backwards, which is
                // what makes termination a property of the encoding rather than of the
                // program. Added to `pc`, which is already past this instruction.
                pc += usize::from(if taken { i.jt } else { i.jf });
            }
            JMP_JA => pc += i.k as usize,
            RET_K => return Verdict::Return(i.k),
            other => {
                return Verdict::Refused(format!(
                    "instruction class 0x{other:04x} at pc={} is not one this builder emits",
                    pc - 1
                ))
            }
        }
    }
}

/// What the filter should answer, stated from the syscall tables rather than the program.
///
/// The second half of the differential. This is deliberately written in the order the
/// **specification** reads — architecture, then the categories in precedence order — and
/// not in the order `build` emits instructions, so that a reordering in the builder that
/// changed behaviour shows up as a disagreement rather than being mirrored.
pub fn expected(opts: &FilterOptions, data: &SeccompData) -> u32 {
    // The architecture gate is absolute and comes before everything: a record from another
    // architecture is a 32-bit compat call whose numbering is not this table's, and
    // answering it against this table is how a filter is bypassed.
    if data.arch != opts.arch.audit() {
        return libc::SECCOMP_RET_KILL_PROCESS;
    }
    // x32 shares x86-64's audit arch and sets the high bit in `nr`. Same reasoning.
    if opts.arch == Arch::X86_64 && (data.nr as u32) & 0x4000_0000 != 0 {
        return libc::SECCOMP_RET_KILL_PROCESS;
    }

    let nr = i64::from(data.nr);
    let t = bpf::table_for(opts.arch);

    // Denied outright, and this is checked BEFORE the notify categories on purpose: these
    // are the syscalls that would defeat the rest of the filter, and a program that let one
    // of them reach a notification instead would be handing the decision to a supervisor
    // the caller could then debug.
    if t.denied().contains(&nr) {
        return libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xffff);
    }

    if opts.observe_net && t.net_observed().contains(&nr) {
        return libc::SECCOMP_RET_USER_NOTIF;
    }
    if t.exec_observed().contains(&nr) {
        return libc::SECCOMP_RET_USER_NOTIF;
    }
    if opts.observe_writes {
        // `openat2` puts its flags in a struct in the caller's memory, so no BPF test can
        // read them: notified unconditionally, and the supervisor reads the struct.
        if t.openat2_number() == Some(nr) {
            return libc::SECCOMP_RET_USER_NOTIF;
        }
        // The two flag-tested opens. Everything else in the write class is unconditional.
        if let Some(arg) = t.open_flag_argument(nr) {
            let flags = data.args[arg] as u32;
            return if flags & bpf::WRITE_OPEN_MASK != 0 {
                libc::SECCOMP_RET_USER_NOTIF
            } else {
                libc::SECCOMP_RET_ALLOW
            };
        }
        if t.write_observed().contains(&nr) {
            return libc::SECCOMP_RET_USER_NOTIF;
        }
    }
    libc::SECCOMP_RET_ALLOW
}

/// The property: the program the builder emits answers what the tables say it should.
///
/// `Err` is a disagreement, with enough in the message to reproduce it — a fuzzer's
/// finding is worth nothing if the report does not say which record found it.
pub fn check(opts: &FilterOptions, data: &SeccompData) -> Result<(), String> {
    let prog = bpf::build(opts).map_err(|e| format!("the filter would not assemble: {e}"))?;
    match run(&prog, data) {
        Verdict::Return(got) => {
            let want = expected(opts, data);
            if got == want {
                Ok(())
            } else {
                Err(format!(
                    "filter answered 0x{got:08x}, the tables say 0x{want:08x}\n  \
                     arch={:?} observe_writes={} observe_net={}\n  \
                     nr={} data.arch=0x{:08x} args={:?}",
                    opts.arch, opts.observe_writes, opts.observe_net, data.nr, data.arch, data.args
                ))
            }
        }
        Verdict::Refused(why) => Err(format!(
            "the program did not return a verdict: {why}\n  \
             arch={:?} observe_writes={} observe_net={} nr={}",
            opts.arch, opts.observe_writes, opts.observe_net, data.nr
        )),
    }
}

/// Every option combination the builder can be asked for.
///
/// Four, and all four ship: a compile unit under a kernel-enforced filesystem tier turns
/// `observe_writes` off, and `observe_net` follows the policy. A sweep that only covered
/// the default would leave three of them untested.
pub fn all_options() -> Vec<FilterOptions> {
    let mut out = Vec::new();
    for arch in [Arch::X86_64, Arch::Aarch64] {
        for observe_writes in [false, true] {
            for observe_net in [false, true] {
                out.push(FilterOptions {
                    observe_writes,
                    observe_net,
                    arch,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(arch: Arch, nr: i64, args: [u64; 6]) -> SeccompData {
        SeccompData {
            nr: nr as i32,
            arch: arch.audit(),
            instruction_pointer: 0xdead_beef_0000_1234,
            args,
        }
    }

    /// Every syscall number the tables mention, plus the neighbours of each and a spread
    /// of numbers no table mentions.
    ///
    /// The neighbours are the point: an off-by-one in a jump lands on the *next*
    /// comparison, so a sweep of only the interesting numbers agrees with a filter whose
    /// arms are all shifted by one.
    fn numbers(arch: Arch) -> Vec<i64> {
        let t = bpf::table_for(arch);
        let mut out: Vec<i64> = Vec::new();
        for nr in t.every_number() {
            out.extend([nr - 1, nr, nr + 1]);
        }
        out.extend([-1, 0, 1, 2, 3, 400, 1000, 4096, i64::from(i32::MAX)]);
        out.sort_unstable();
        out.dedup();
        out
    }

    #[test]
    fn the_filter_agrees_with_the_tables_on_every_syscall_it_knows() {
        let flag_sets: [u64; 6] = [
            0,
            libc::O_RDONLY as u64,
            libc::O_WRONLY as u64,
            libc::O_RDWR as u64,
            (libc::O_CREAT | libc::O_RDONLY) as u64,
            (libc::O_TRUNC | libc::O_APPEND) as u64,
        ];
        let mut checked = 0usize;
        for opts in all_options() {
            for nr in numbers(opts.arch) {
                for flags in flag_sets {
                    // The same value in every argument slot, so whichever slot the filter
                    // reads, it reads this. A per-slot sweep would multiply the run by six
                    // and find nothing this does not: the property under test is which
                    // slot is read, and reading the wrong one is visible as a verdict that
                    // disagrees when the slots differ — which the next test covers.
                    let d = data(opts.arch, nr, [flags; 6]);
                    check(&opts, &d).unwrap_or_else(|e| panic!("{e}"));
                    checked += 1;
                }
            }
        }
        // A sweep that silently covered nothing is the failure this project has already
        // had once, in its own end-to-end suite.
        assert!(checked > 1_000, "only {checked} records were checked");
    }

    #[test]
    fn the_filter_reads_the_flags_out_of_the_right_argument() {
        // `open(path, flags)` has its flags in arg 1 and `openat(dirfd, path, flags)` in
        // arg 2. Reading the wrong one means every write-open is judged on an unrelated
        // value — a path pointer, whose low bits are arbitrary — so the verdict is right
        // about half the time and the bug survives a sweep that puts the same value in
        // every slot.
        for arch in [Arch::X86_64, Arch::Aarch64] {
            let opts = FilterOptions {
                observe_writes: true,
                observe_net: false,
                arch,
            };
            let t = bpf::table_for(arch);
            for nr in t.every_number() {
                let Some(slot) = t.open_flag_argument(nr) else {
                    continue;
                };
                // Write flags in the correct slot and nothing anywhere else.
                let mut args = [0u64; 6];
                args[slot] = libc::O_WRONLY as u64;
                check(&opts, &data(arch, nr, args)).unwrap_or_else(|e| panic!("{e}"));

                // …and write flags in every OTHER slot, which must not be mistaken for
                // the real one.
                let mut args = [libc::O_WRONLY as u64; 6];
                args[slot] = libc::O_RDONLY as u64;
                check(&opts, &data(arch, nr, args)).unwrap_or_else(|e| panic!("{e}"));
            }
        }
    }

    #[test]
    fn a_record_from_another_architecture_is_killed() {
        // The gate that must come before every number comparison. Without it a 32-bit
        // compat call is matched against this architecture's numbering, and `nr = 41` is
        // `socket` on x86-64 and something else entirely on i386.
        for opts in all_options() {
            for foreign in [0u32, 0x4000_0003, Arch::X86_64.audit() ^ 1, 0xffff_ffff] {
                if foreign == opts.arch.audit() {
                    continue;
                }
                let d = SeccompData {
                    nr: 41,
                    arch: foreign,
                    instruction_pointer: 0,
                    args: [0; 6],
                };
                let prog = bpf::build(&opts).unwrap();
                assert_eq!(
                    run(&prog, &d),
                    Verdict::Return(libc::SECCOMP_RET_KILL_PROCESS),
                    "arch 0x{foreign:08x} was not killed under {opts:?}"
                );
            }
        }
    }

    #[test]
    fn an_x32_call_is_killed_rather_than_matched_against_the_x86_64_table() {
        // x32 shares x86-64's audit arch and sets bit 30 in the syscall number, so the
        // arch gate alone does not catch it. `41 | X32_SYSCALL_BIT` would otherwise be
        // compared against nothing and fall through to ALLOW.
        let opts = FilterOptions {
            observe_writes: true,
            observe_net: true,
            arch: Arch::X86_64,
        };
        let prog = bpf::build(&opts).unwrap();
        for nr in [41i64, 42, 59, 101] {
            let d = data(Arch::X86_64, nr | 0x4000_0000, [0; 6]);
            assert_eq!(
                run(&prog, &d),
                Verdict::Return(libc::SECCOMP_RET_KILL_PROCESS),
                "x32 call {nr} was not killed"
            );
        }
    }

    #[test]
    fn the_interpreter_refuses_a_program_it_cannot_speak_for() {
        // The interpreter must not guess. A mutated program — which is what a fuzzer hands
        // it — can contain instruction classes this builder never emits, and an
        // interpreter that treated an unknown class as a no-op would report agreement
        // about a program whose behaviour it did not model.
        let unknown = [sock_filter {
            code: (libc::BPF_ALU | libc::BPF_ADD | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: 1,
        }];
        assert!(matches!(
            run(&unknown, &data(Arch::X86_64, 41, [0; 6])),
            Verdict::Refused(_)
        ));

        // And a program that can run off the end is a finding, not a verdict.
        let falls_off = [sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        }];
        assert!(matches!(
            run(&falls_off, &data(Arch::X86_64, 41, [0; 6])),
            Verdict::Refused(_)
        ));

        // A load from outside the structure is refused rather than read as zero, which
        // would be a syscall number of zero — `read` on x86-64.
        let far = [sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 4096,
        }];
        assert!(matches!(
            run(&far, &data(Arch::X86_64, 41, [0; 6])),
            Verdict::Refused(_)
        ));
    }

    #[test]
    fn a_backward_jump_cannot_be_encoded_so_the_interpreter_always_terminates() {
        // Classic BPF's jump offsets are unsigned bytes, which is what makes termination a
        // property of the encoding. The step budget exists for mutated programs; this pins
        // that the real ones never need it.
        for opts in all_options() {
            let prog = bpf::build(&opts).unwrap();
            for (pc, i) in prog.iter().enumerate() {
                // The instruction class is the low three bits. `code & BPF_JMP != 0` would
                // be wrong — BPF_JMP is 0x05 and BPF_RET is 0x06, so they share a bit and
                // every return would be read as a jump.
                const CLASS: u32 = 0x07;
                const OP: u32 = 0xf0;
                let code = u32::from(i.code);
                if code & CLASS != libc::BPF_JMP {
                    continue;
                }
                // `BPF_JA` carries its offset in `k`; every conditional carries two in
                // `jt` and `jf`.
                let offsets: Vec<usize> = if code & OP == libc::BPF_JA {
                    vec![i.k as usize]
                } else {
                    vec![usize::from(i.jt), usize::from(i.jf)]
                };
                for off in offsets {
                    assert!(
                        pc + 1 + off <= prog.len(),
                        "a jump at {pc} lands past the end of a {}-instruction program",
                        prog.len()
                    );
                }
            }
        }
    }
}
