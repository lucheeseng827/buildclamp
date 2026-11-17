//! Includes whether the dropped program ran, so a build script that produced nothing fails
//! to compile rather than passing.
include!(concat!(env!("OUT_DIR"), "/ran.rs"));
