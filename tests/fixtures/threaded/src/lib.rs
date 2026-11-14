//! Includes what the threads computed, so a build that silently produced nothing fails to
//! compile rather than passing.
include!(concat!(env!("OUT_DIR"), "/threads.rs"));
