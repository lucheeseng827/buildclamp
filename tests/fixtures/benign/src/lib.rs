//! Includes the generated table so a wrongly-denied `OUT_DIR` write becomes a
//! compile error rather than a silently smaller constant.
include!(concat!(env!("OUT_DIR"), "/table.rs"));

pub fn entries() -> &'static [&'static str] {
    ENTRIES
}

/// Set by `build.rs` via `cargo:rustc-env`; proves the directive channel survived
/// the sandbox (stdout must reach cargo unmodified).
pub fn table_len() -> &'static str {
    env!("BENIGN_TABLE_LEN")
}
