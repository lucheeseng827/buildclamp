//! A parse is never more permissive than the text.
//!
//! The fails-open class: a `#[serde(default)]` that defaults the wrong way, a version
//! requirement that matches a unit it should not, a merge that unions where it should
//! replace. Each produces a policy that parses, reads correctly to a human, and grants
//! something nobody wrote down.
//!
//! The property is `buildclamp_core::fuzzcheck`'s, not this file's — see `fuzz/Cargo.toml`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Lossy rather than rejecting non-UTF-8: a policy file is text, and the bytes that
    // are not are the tokenizer's problem rather than an input to discard.
    let text = String::from_utf8_lossy(data);
    if let Err(finding) = buildclamp_core::fuzzcheck::policy_is_no_more_permissive_than_its_text(&text) {
        panic!("{finding}");
    }
});
