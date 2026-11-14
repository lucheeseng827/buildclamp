//! A build script that creates threads.
//!
//! **This fixture exists because of a bug, and it is the plainest kind.** The sandbox used
//! to `unshare(CLONE_NEWPID)` in the child without forking before `execve`, which sets
//! `pid_for_children` without moving the caller. The kernel refuses `CLONE_THREAD` while
//! those two namespaces differ — `copy_process` returns `-EINVAL` — so every held unit was
//! single-threaded, and any that tried to create a thread died on it.
//!
//! Nothing caught it. Every other fixture here is single-threaded, and no compile unit had
//! ever been held; it surfaced only when rustc was put under the sandbox and panicked at
//! startup, because `install_ctrlc_handler` spawns a thread.
//!
//! That is the shape of failure this fixture guards: not a capability wrongly granted, but
//! a build broken by the tool for a reason nothing in the report would explain. `cc`
//! compiles in parallel with threads and `bindgen` uses them, so "held units cannot create
//! threads" means most `-sys` crates in the ecosystem.
//!
//! It asserts rather than reporting, unlike the hostile fixtures: a thread that cannot be
//! created here is a broken tool, not an observation about a policy.

use std::io::Write;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Several, and joined, so a failure is a failure rather than a race. `cc` spawns one
    // per translation unit; four is enough to be the same shape without being slow.
    let handles: Vec<_> = (0..4u32)
        .map(|i| std::thread::spawn(move || i * 2))
        .collect();
    let total: u32 = handles
        .into_iter()
        .map(|h| h.join().expect("a held unit must be able to create and join a thread"))
        .sum();
    assert_eq!(total, 12, "the threads ran and returned what they computed");

    // And one that outlives a scope boundary the way a worker pool does, because the
    // kernel check is on thread creation and a second creation after other work is where a
    // subtler regression would show.
    let nested = std::thread::spawn(|| std::thread::spawn(|| 7u32).join().unwrap())
        .join()
        .expect("a thread created from inside a thread");
    assert_eq!(nested, 7);

    let out = std::env::var("OUT_DIR").expect("cargo sets this");
    let mut f = std::fs::File::create(std::path::Path::new(&out).join("threads.rs")).unwrap();
    writeln!(f, "/// Proof the threads ran: their sum, computed in them.").unwrap();
    writeln!(f, "pub const THREAD_SUM: u32 = {total};").unwrap();
    writeln!(f, "pub const NESTED: u32 = {nested};").unwrap();
}
