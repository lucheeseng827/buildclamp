//! An instrumented probe proc-macro whose expansion issues a syscall from **its own
//! machine code**, not through libc.
//!
//! # Why the inline asm, and why it matters for attribution
//!
//! `evilmacro` reaches the network with `std::net`, which issues the `connect` syscall from
//! inside libc. The instruction pointer the kernel records in `seccomp_data` therefore
//! points into libc, not into the macro, and the best attribution can honestly do is a
//! stack scan or the closure — the same answer every other tool gives. This fixture exists
//! to exercise the OTHER path: it issues the `socket` syscall with an inline `syscall`
//! instruction compiled into `libprobemacro-*.so`, so the recorded instruction pointer
//! falls inside the macro's own shared object and the supervisor can name it at `exact`.
//!
//! `socket(AF_INET, …)` is deliberate: it is notified whenever the net tier is observed,
//! its arguments are all registers (no pointer into the target's memory to read), and the
//! sandbox refuses it without a network grant — so the probe is a finding whether or not it
//! ever gets as far as a `connect`. The fd, if the kernel returns one on an unheld run, is
//! closed immediately; the macro then expands to nothing so the consumer still compiles.
//!
//! Same rules as the sibling fixtures: it targets only its own process, and it never fails
//! the build on its own.

use proc_macro::TokenStream;

/// `socket(AF_INET, SOCK_STREAM, 0)` issued from this shared object's own code.
///
/// Returns the raw kernel result: a non-negative fd, or a negated errno. The `syscall`
/// instruction is what the seccomp filter traps on, and its address is inside this `.so`,
/// which is the whole point.
#[cfg(target_arch = "x86_64")]
unsafe fn raw_inet_socket() -> i64 {
    let ret: i64;
    // SAFETY: a socket(2) with constant register arguments and no memory operands. rcx and
    // r11 are clobbered by the `syscall` instruction and declared so.
    std::arch::asm!(
        "syscall",
        inlateout("rax") 41i64 => ret, // SYS_socket
        in("rdi") 2i64,                // AF_INET
        in("rsi") 1i64,                // SOCK_STREAM
        in("rdx") 0i64,                // protocol
        out("rcx") _,
        out("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

#[cfg(target_arch = "aarch64")]
unsafe fn raw_inet_socket() -> i64 {
    let ret: i64;
    // SAFETY: a socket(2) with constant register arguments and no memory operands.
    std::arch::asm!(
        "svc #0",
        in("x8") 198i64,              // SYS_socket
        inlateout("x0") 2i64 => ret, // AF_INET
        in("x1") 1i64,               // SOCK_STREAM
        in("x2") 0i64,               // protocol
        options(nostack, preserves_flags)
    );
    ret
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn raw_inet_socket() -> i64 {
    // The attribution path this fixture exercises is x86_64/aarch64 only, matching the
    // sandbox's own arch gating. On anything else the probe does nothing and says so.
    -1
}

#[proc_macro_derive(Probe)]
pub fn probe(_item: TokenStream) -> TokenStream {
    // SAFETY: see `raw_inet_socket`.
    let rc = unsafe { raw_inet_socket() };
    if rc >= 0 {
        // An unheld run may actually get an fd; do not leak it. This close is not a notified
        // syscall, so it does not muddy the report.
        unsafe {
            let _ = libc_close(rc as i32);
        }
        eprintln!("probemacro-step:1:socket:ok");
    } else {
        eprintln!("probemacro-step:1:socket:err:{}", -rc);
    }
    TokenStream::new()
}

/// A direct `close(2)`, to avoid a libc dependency in a fixture.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe fn libc_close(fd: i32) -> i64 {
    let ret: i64;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: close(2) with a single register argument.
    std::arch::asm!(
        "syscall",
        inlateout("rax") 3i64 => ret, // SYS_close
        in("rdi") fd as i64,
        out("rcx") _,
        out("r11") _,
        options(nostack, preserves_flags)
    );
    #[cfg(target_arch = "aarch64")]
    // SAFETY: close(2) with a single register argument.
    std::arch::asm!(
        "svc #0",
        in("x8") 57i64,               // SYS_close
        inlateout("x0") fd as i64 => ret,
        options(nostack, preserves_flags)
    );
    ret
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
unsafe fn libc_close(_fd: i32) -> i64 {
    -1
}
