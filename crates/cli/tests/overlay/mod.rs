//! The overlay: claims, documents and source this tree does not carry, read when a checkout
//! has them.
//!
//! `BUILDCLAMP_OVERLAY` names a directory holding one `CLAIMS.toml`:
//!
//! * `[[claim]]` entries whose evidence or cited document is not in this tree;
//! * `documents`, the extra files (relative to the module root) the absence-claim gate reads;
//! * `closed_tree`, optionally, a second source tree (relative to the module root) the
//!   source-wide gates also scan, and whose paths a claim may cite.
//!
//! When the variable is unset, or names a directory that is not there, every gate runs on
//! this tree alone. That is how the gates run wherever only this tree exists, so nothing
//! here may be needed for them to pass.

#![allow(dead_code)] // each test binary that includes this uses a different part of it

use std::fs;
use std::path::{Path, PathBuf};

pub struct Overlay {
    pub claims: Vec<toml::Value>,
    pub documents: Vec<String>,
    /// The second tree's path relative to the module root, whether or not it is present.
    pub closed_tree: Option<String>,
}

/// The overlay, if this checkout has one. A file that is there but does not parse is a
/// failure, not an absence: a broken overlay would otherwise switch its gates off silently.
pub fn load() -> Option<Overlay> {
    let dir = PathBuf::from(std::env::var_os("BUILDCLAMP_OVERLAY")?);
    let path = dir.join("CLAIMS.toml");
    let text = fs::read_to_string(&path).ok()?;
    let v: toml::Value = text
        .parse()
        .unwrap_or_else(|e| panic!("{} must be valid TOML: {e}", path.display()));
    let claims = v
        .get("claim")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let documents = v
        .get("documents")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|d| d.as_str().map(str::to_string))
        .collect();
    let closed_tree = v
        .get("closed_tree")
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    Some(Overlay {
        claims,
        documents,
        closed_tree,
    })
}

impl Overlay {
    /// The second source tree's directory, when this checkout has it.
    pub fn closed_tree_dir(&self, root: &Path) -> Option<PathBuf> {
        self.closed_tree
            .as_ref()
            .map(|n| root.join(n))
            .filter(|p| p.is_dir())
    }

    /// Whether `rel` lies in the second tree while that tree is absent. Such a path is
    /// optional; with the tree present it must exist like any other, so a typo is still
    /// caught wherever there is something to catch it against.
    pub fn is_in_absent_tree(&self, root: &Path, rel: &str) -> bool {
        match &self.closed_tree {
            Some(n) => rel.starts_with(&format!("{n}/")) && !root.join(n).is_dir(),
            None => false,
        }
    }
}
