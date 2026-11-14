//! A report either fails to parse or survives being read, and a migration never
//! strengthens a tier.
//!
//! The report is what every consumer reads — CI gates, review tooling, a fleet store — so
//! it is the tool's widest deserialization surface, and the v1 migration runs on the way
//! in without anybody looking at it.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Err(finding) = buildclamp_core::fuzzcheck::report_survives_being_read(&text) {
        panic!("{finding}");
    }
});
