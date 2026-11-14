//! A proc-macro whose payload runs at **expansion** time — that is, inside the
//! `rustc` process compiling whoever used it, not inside a build script.
//!
//! This is the half of the threat that a build-script-only tool misses entirely,
//! and it is the harder half to attribute: there is no separate process to name.
//! Everything here happens while rustc is compiling the *consumer* crate, so the
//! sandbox that must catch it is the one wrapped around every ordinary rustc
//! invocation, and the report can only say "while compiling `macrouser`, with
//! `evilmacro` in its dependency closure".
//!
//! The suite uses this fixture to pin exactly that: the violation is caught, and
//! the attribution names the consumer plus the proc-macros in its closure, and the
//! documentation says so rather than implying per-macro precision the design does
//! not have.
//!
//! Same rules as the other fixtures: loopback only, never fails on its own.

use proc_macro::TokenStream;

#[proc_macro_derive(Harmless)]
pub fn harmless(_item: TokenStream) -> TokenStream {
    // 1. Network, from inside rustc.
    match std::net::TcpStream::connect_timeout(
        &"127.0.0.1:9".parse().expect("literal"),
        std::time::Duration::from_millis(400),
    ) {
        Ok(_) => eprintln!("evilmacro-step:1:connect:ok"),
        Err(e) => eprintln!("evilmacro-step:1:connect:err:{:?}", e.kind()),
    }

    // 2. A write outside anything rustc has business writing to.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let target = std::path::Path::new(&home).join(".config/autostart/evilmacro.desktop");
    if let Some(parent) = target.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&target, b"[Desktop Entry]\nExec=/bin/true\n") {
        Ok(()) => eprintln!("evilmacro-step:2:persist:ok"),
        Err(e) => eprintln!("evilmacro-step:2:persist:err:{:?}", e.kind()),
    }

    // 3. Secrets from the environment rustc inherited.
    let visible: Vec<&str> = ["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"]
        .into_iter()
        .filter(|k| std::env::var(k).is_ok())
        .collect();
    eprintln!("evilmacro-step:3:env:{}", visible.join(","));

    // The macro still expands correctly. A fixture that produced broken code would
    // fail the build for the wrong reason.
    TokenStream::new()
}
