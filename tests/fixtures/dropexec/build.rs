//! A build script that writes a program into `OUT_DIR` and then runs it.
//!
//! The shape of a dropper: fetch or unpack a payload into a directory the script may
//! write, then execute it. The same shape is also legitimate, and that is the point of the
//! fixture: a cmake `try_run` or an autoconf feature test compiles a small program into
//! its build directory and runs it. Write xor execute refuses the run by default, and a
//! grant naming the zone in `exec-zones` allows it.
//!
//! The payload is a copy of `/bin/true`, so nothing it does matters except whether it was
//! allowed to start. Like every fixture here it never fails its own build: each step
//! reports `dropexec-step:<n>:<name>:<ok|err:...>` and the script carries on.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets this"));
    let dropped = out.join("dropped");

    match std::fs::copy("/bin/true", &dropped)
        .and_then(|_| std::fs::set_permissions(&dropped, std::fs::Permissions::from_mode(0o755)))
    {
        Ok(()) => eprintln!("dropexec-step:1:write-program:ok"),
        Err(e) => eprintln!("dropexec-step:1:write-program:err:{:?}", e.kind()),
    }

    let ran = match Command::new(&dropped).status() {
        Ok(s) if s.success() => {
            eprintln!("dropexec-step:2:run-dropped:ok");
            true
        }
        Ok(s) => {
            eprintln!("dropexec-step:2:run-dropped:err:exit:{s}");
            false
        }
        Err(e) => {
            eprintln!("dropexec-step:2:run-dropped:err:{:?}", e.kind());
            false
        }
    };

    let mut f = std::fs::File::create(out.join("ran.rs")).unwrap();
    writeln!(f, "/// Whether the program this build script wrote was allowed to run.").unwrap();
    writeln!(f, "pub const RAN: bool = {ran};").unwrap();
}
