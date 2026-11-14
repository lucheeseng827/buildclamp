//! `buildclamp-shim` — the cargo-facing half.
//!
//! This crate knows cargo's file layout and process model, and nothing about kernels.
//! `buildclamp-core` decides what a build unit may do; `buildclamp-sandbox` makes a
//! kernel enforce it; this crate is what arranges for the two to meet at the moment
//! cargo spawns a unit.
//!
//! Everything here rests on facts measured against cargo 1.94.1 rather than on the
//! documentation, because cargo's command lines and file layout are not a stable
//! interface. The three that matter most:
//!
//! * A build-script compile is recognisable only from the whole argv, never from the
//!   compiler's name — under `cargo clippy` the workspace's own build script arrives
//!   with `clippy-driver` in front of rustc.
//! * `OUT_DIR`'s hash is **not** the compile directory's hash. The shim and the real
//!   binary live in `build/<pkg>-<hashA>/`; the script runs with
//!   `OUT_DIR=build/<pkg>-<hashB>/out`. The launcher must read `OUT_DIR` from its
//!   environment at run time; it cannot be derived from where the binary sits.
//! * Cargo captures a build script's stderr and shows it **only when the unit fails**.
//!   That is why the report is JSON in a run directory rather than printed, and why one
//!   well-formed line on the failure path is the entire developer experience.
//!
//! # Layout
//!
//! * [`roles`] — which of the three jobs this process was started to do, and the
//!   passthrough rules that make an inactive buildclamp cost nothing.
//! * [`swap`] — replacing a compiled build script with a shim, and undoing it.
//! * [`sweep`] — shimming build scripts the wrapper will never see, because cargo does
//!   NOT put `RUSTC_WRAPPER` in a fingerprint and a previously-built target directory
//!   stays Fresh forever. Without this the tool reports success while enforcing nothing
//!   on every repository that has ever run a plain `cargo build`.
//! * [`runrecord`] — the run directory: one JSON file per unit, atomically written,
//!   read back in a stable order.
//! * [`paths`] — resolving a unit's write zones to the absolute paths this run uses.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod paths;
pub mod roles;
pub mod runrecord;
pub mod swap;
pub mod sweep;

pub use crate::paths::{resolve_zones, UnitContext, UnitPaths};
pub use crate::roles::{detect, PassReason, Role, WrapperAction};
pub use crate::runrecord::RunDir;
pub use crate::swap::{is_shim, swap, unswap, Swapped};
pub use crate::sweep::{sweep, unsweep, SweepResult};
