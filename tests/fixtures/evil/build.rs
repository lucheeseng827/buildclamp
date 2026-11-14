//! A replica of what `proc-macro1` did on 2026-08-20, reduced to the four
//! capabilities that mattered and made safe to run in a test suite.
//!
//! **This script never fails the build and never touches the internet.** Every
//! step reports its own outcome on stderr as `evil-step:<n>:<ok|err:...>` and
//! then continues. That is deliberate in two directions:
//!
//! * The *tool* must be what fails the build. A fixture that exits non-zero on a
//!   denied syscall would let a broken sandbox pass the test — the harness could
//!   not tell "we blocked it" from "the script crashed on its own".
//! * A partial defence has to be visible. If the network is denied but the
//!   persistence write is not, the test must see step 2 fail and step 5 succeed,
//!   rather than stopping at the first refusal.
//!
//! The C2 address is `127.0.0.1` on a port nothing listens on, reconstructed from
//! base64 exactly the way the real sample reconstructed its own. A fixture that
//! resolved a real hostname would make the test suite depend on DNS and would put
//! traffic on someone else's network; the *capability being exercised* is
//! identical either way, because the sandbox denies `socket`/`connect` before any
//! packet exists.

use std::io::Write;

fn main() {
    // Cargo re-runs this script only when it changes; without this it would also
    // re-run on every source edit, which makes the harness's "ran exactly once"
    // assertions flaky.
    println!("cargo:rerun-if-changed=build.rs");

    step(1, "decode-c2", || {
        let host = de(C2_HOST_B64)?;
        let port: u16 = de(C2_PORT_B64)?.parse().map_err(|_| "port".to_string())?;
        eprintln!("evil-note:c2={host}:{port}");
        Ok(())
    });

    step(2, "connect", || {
        let host = de(C2_HOST_B64)?;
        let port: u16 = de(C2_PORT_B64)?.parse().map_err(|_| "port".to_string())?;
        // A short timeout so an unsandboxed run (where the connection is merely
        // refused) does not hang the suite.
        let addr: std::net::SocketAddr = format!("{host}:{port}")
            .parse()
            .map_err(|e| format!("addr: {e}"))?;
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(400))
            .map(|_| ())
            .map_err(|e| format!("{:?}", e.kind()))
    });

    // The real sample scraped credential stores. Here we only report whether the
    // secrets were *reachable*, because the interesting question is whether the
    // tool removed them from this process's environment.
    step(3, "read-env-secrets", || {
        let mut seen = Vec::new();
        for k in ["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "CARGO_REGISTRY_TOKEN"] {
            if std::env::var(k).is_ok() {
                seen.push(k);
            }
        }
        eprintln!("evil-note:env-visible={}", seen.join(","));
        if seen.is_empty() {
            Ok(())
        } else {
            Err(format!("leaked:{}", seen.join(",")))
        }
    });

    // Scrubbing this process's environment does not help if the secrets are still
    // readable out of the parent's. Same uid, no hidepid, no user namespace: this
    // read succeeds. It is the reason the tool needs a user namespace and not just
    // an env filter, and this step is what proves the difference. The namespace that
    // matters is the user one, not the PID one — unsharing CLONE_NEWPID alone leaves
    // this very read returning the full environment.
    step(4, "read-parent-environ", || {
        let ppid = std::fs::read_to_string("/proc/self/stat")
            .map_err(|e| e.to_string())?
            .rsplit(COMM_CLOSE)
            .next()
            .and_then(|rest| rest.split_whitespace().nth(1).map(str::to_string))
            .ok_or_else(|| "stat".to_string())?;
        let blob = std::fs::read(format!("/proc/{ppid}/environ")).map_err(|e| format!("{:?}", e.kind()))?;
        let found = blob
            .split(|b| *b == 0)
            .filter_map(|kv| std::str::from_utf8(kv).ok())
            .any(|kv| kv.starts_with("GITHUB_TOKEN=") || kv.starts_with("AWS_SECRET_ACCESS_KEY="));
        eprintln!("evil-note:parent-environ-bytes={} secret={found}", blob.len());
        if found {
            Err("leaked-via-proc".to_string())
        } else {
            Ok(())
        }
    });

    // Persistence. The real sample used the registry, a LaunchAgent or a systemd
    // user unit depending on platform; all three are "a write outside OUT_DIR to a
    // path something else will later execute".
    step(5, "persist-outside-out-dir", || {
        let home = std::env::var("HOME").map_err(|_| "no HOME".to_string())?;
        let dir = std::path::Path::new(&home).join(".config/autostart");
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir:{:?}", e.kind()))?;
        let mut f = std::fs::File::create(dir.join("evil.desktop"))
            .map_err(|e| format!("create:{:?}", e.kind()))?;
        f.write_all(b"[Desktop Entry]\nExec=/bin/true\n")
            .map_err(|e| format!("write:{:?}", e.kind()))
    });

    // The legitimate half. A build script that could not do this would be useless,
    // so the sandbox must always permit it — and the crate must still compile when
    // every other step above was denied.
    step(6, "write-out-dir", || {
        let out = std::env::var("OUT_DIR").map_err(|_| "no OUT_DIR".to_string())?;
        std::fs::write(
            std::path::Path::new(&out).join("generated.rs"),
            "pub const GENERATED: u32 = 78;\n",
        )
        .map_err(|e| format!("{:?}", e.kind()))
    });

    step(7, "exec-subprocess", || {
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("id -u")
            .output()
            .map(|o| eprintln!("evil-note:exec-status={}", o.status))
            .map_err(|e| format!("{:?}", e.kind()))
    });
}

/// Split token for `/proc/self/stat`. The `comm` field is parenthesised and may
/// itself contain spaces and parentheses, so everything after the LAST `)` is the
/// fixed-layout remainder; ppid is its second whitespace-separated field.
const COMM_CLOSE: char = ')';

/// `127.0.0.1` and `9` (the discard port), base64-encoded and reassembled at run
/// time — the same obfuscation shape the real sample used, pointed at loopback so
/// the fixture can never reach anything.
const C2_HOST_B64: &str = "MTI3LjAuMC4x";
const C2_PORT_B64: &str = "OQ==";

fn de(s: &str) -> Result<String, String> {
    // A tiny standard-alphabet base64 decoder. Written out rather than pulled from
    // a crate because a fixture with a dependency would itself need a build, and
    // the point of the fixture is to be the only interesting thing in the graph.
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = A.iter().position(|a| *a == c).ok_or("bad base64")? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    String::from_utf8(out).map_err(|e| e.to_string())
}

fn step(n: u32, name: &str, f: impl FnOnce() -> Result<(), String>) {
    match f() {
        Ok(()) => eprintln!("evil-step:{n}:{name}:ok"),
        Err(e) => eprintln!("evil-step:{n}:{name}:err:{e}"),
    }
}
