//! The library half exists only so the crate is a real dependency with a real
//! build script. It includes the generated file so that a run in which step 6 was
//! wrongly denied fails to compile — the fixture asserts its own legitimate half.
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

pub fn generated() -> u32 {
    GENERATED
}
