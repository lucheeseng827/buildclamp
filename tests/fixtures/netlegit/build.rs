//! A build script with a *legitimate* need for the network — the `openssl-sys` /
//! vendored-tarball shape, which is the case that makes a blanket network denial
//! unusable in the real world.
//!
//! The harness starts a TCP listener on loopback and passes its address in
//! `NETLEGIT_ENDPOINT`, so the fixture exercises the capability without depending
//! on any external host.
//!
//! Three outcomes the suite pins:
//!   * under the default policy — a network violation, exit 2;
//!   * under a policy whose `[[allow]]` entry grants `network` WITH a
//!     justification — clean, exit 0;
//!   * under the same entry with the justification removed — a policy parse
//!     error before any unit runs, exit 1. The justification is not decoration.

use std::io::Write;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=NETLEGIT_ENDPOINT");

    let out = std::env::var("OUT_DIR").expect("cargo sets this");
    let endpoint = std::env::var("NETLEGIT_ENDPOINT").unwrap_or_else(|_| "127.0.0.1:9".to_string());

    let fetched = match std::net::TcpStream::connect(&endpoint) {
        Ok(mut s) => {
            let _ = s.write_all(b"GET /pinned.tar.gz\n");
            eprintln!("netlegit:fetch:ok");
            true
        }
        Err(e) => {
            // A vendored-dependency build script that cannot fetch normally fails
            // loudly. This one does not, because the *tool* is what must fail the
            // build; see the evil fixture's module docs for why.
            eprintln!("netlegit:fetch:err:{:?}", e.kind());
            false
        }
    };

    std::fs::write(
        std::path::Path::new(&out).join("fetched.rs"),
        format!("pub const FETCHED: bool = {fetched};\n"),
    )
    .expect("OUT_DIR is writable");
}
