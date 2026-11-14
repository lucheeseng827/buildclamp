//! The seccomp filter answers what the syscall tables say it should.
//!
//! Differential: `bpfcheck::run` executes the program the builder emitted, `bpfcheck::expected`
//! states the answer from the tables, and a disagreement is a filter whose control flow does
//! not do what its author believed. That class fails **open** — a jump that skips the notify
//! return and falls into the trailing ALLOW is a hole in the tier the whole product is a claim
//! about, and nothing about it looks wrong.
//!
//! The input is a syscall record rather than a byte stream, because the generator's own input
//! is three options and not arbitrary bytes. What is being searched is the space of syscalls
//! the filter has to answer about.

#![no_main]

use arbitrary::Arbitrary;
use buildclamp_sandbox::bpfcheck::{self, SeccompData};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    /// Which of the four option combinations, per architecture, to build.
    option_index: u8,
    nr: i32,
    /// Whether to use the filter's own audit arch or the one supplied below. Biased on
    /// purpose: an arbitrary 32-bit value is almost never a real audit arch, so without
    /// this the architecture gate would be the only branch ever reached.
    native_arch: bool,
    arch: u32,
    args: [u64; 6],
}

fuzz_target!(|input: Input| {
    let all = bpfcheck::all_options();
    let opts = all[usize::from(input.option_index) % all.len()];
    let data = SeccompData {
        nr: input.nr,
        arch: if input.native_arch {
            opts.arch.audit()
        } else {
            input.arch
        },
        instruction_pointer: 0,
        args: input.args,
    };
    if let Err(finding) = bpfcheck::check(&opts, &data) {
        panic!("{finding}");
    }
});
