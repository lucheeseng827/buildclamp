//! Includes what the build script managed to read, so the outcome is a compile-time
//! constant a test can assert on rather than a log line it has to parse.
include!(concat!(env!("OUT_DIR"), "/loot.rs"));
