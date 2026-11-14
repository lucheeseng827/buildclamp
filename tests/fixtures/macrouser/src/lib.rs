//! Uses the fixture proc-macro, so expanding it happens while *this* crate is
//! compiled. The report's attribution for any violation must name `macrouser` as
//! the unit and `evilmacro` as a proc-macro in its closure.
use evilmacro::Harmless;

#[derive(Harmless)]
pub struct Thing;
