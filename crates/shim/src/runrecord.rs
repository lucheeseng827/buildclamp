//! The run directory: how units that never meet each other assemble one report.
//!
//! Cargo runs units concurrently — `--jobs N` by default — and each held unit is a
//! separate process that exits before the next one starts. There is no shared memory and
//! no supervisor process spanning the build, so the only way the driver learns what
//! happened is a file per unit.
//!
//! **One file per unit, never one shared file.** Several processes appending to one file
//! is a corruption waiting for a busy build, and the failure mode would be a report that
//! is silently short — the worst possible failure for an audit artefact, because a
//! missing unit reads exactly like a clean one.
//!
//! Writes are atomic: a record is written to a temporary name in the same directory and
//! renamed into place. A crash mid-write therefore leaves a stray temporary that the
//! reader ignores, rather than a truncated record that fails to parse and reads as an
//! absent unit.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use buildclamp_core::{UnitId, UnitRecord};
use serde::{Deserialize, Serialize};

/// One proc-macro shared object, as the compile that produced it recorded it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct MacroRecord {
    object: PathBuf,
    id: UnitId,
}

/// The subdirectory holding one JSON file per unit.
const UNITS: &str = "units";
/// Where the proc-macro inventory lives, beside the unit records.
const MACROS: &str = "macros";

/// A run directory. Created by the driver, written by every held unit, read back once.
///
/// The unit records live under `root` (which the driver keeps under `target/`, where a held
/// unit can write its own record). The proc-macro inventory lives under `macros`, which the
/// driver places **outside** every sandbox-writable zone. A held compile is granted all of
/// `target/` — rustc writes across it — so an inventory kept under `root` could be forged by
/// the very code the sandbox is holding, and attribution and attestation would trust the
/// forgery. See [`RunDir::open_with_macro_dir`] and `buildclamp_core::ENV_MACRO_DIR`.
#[derive(Clone, Debug)]
pub struct RunDir {
    root: PathBuf,
    macros: PathBuf,
}

impl RunDir {
    /// Open (creating if needed) the run directory at `root`, keeping the macro inventory
    /// beside the unit records.
    ///
    /// This is the legacy layout, in which the inventory shares the unit-writable run
    /// directory. Prefer [`RunDir::open_with_macro_dir`] wherever the driver has provided a
    /// trusted directory; this spelling remains for callers that never touch the inventory
    /// (the build-script path) and for tests.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        let macros = root.join(MACROS);
        Self::open_with_macro_dir(root, macros)
    }

    /// Open the run directory with the proc-macro inventory in a separate `macros_dir`.
    ///
    /// `macros_dir` must be outside every sandbox-writable zone — the driver puts it outside
    /// `target/` — so that neither a held build script nor a held compile can forge an
    /// object→unit mapping that a later attribution or attestation would treat as genuine.
    pub fn open_with_macro_dir(
        root: impl Into<PathBuf>,
        macros_dir: impl Into<PathBuf>,
    ) -> io::Result<Self> {
        let root = root.into();
        let macros = macros_dir.into();
        fs::create_dir_all(root.join(UNITS))?;
        fs::create_dir_all(&macros)?;
        Ok(Self { root, macros })
    }

    /// Record a proc-macro shared object as it is produced.
    ///
    /// # Why this has to travel through the filesystem
    ///
    /// Attribution maps an instruction pointer inside a held rustc back to the proc-macro
    /// loaded there, which means the run holding the *consumer* needs the `.so` paths
    /// produced when the *macro crates* were compiled. Those are different rustc
    /// invocations, in different processes, scheduled by cargo in an order nobody controls
    /// and possibly in parallel. There is no shared memory between them and there must not
    /// be a daemon, so the run directory is the channel — the same one the unit records
    /// already use, for the same reason.
    ///
    /// One file per macro rather than an appended list, because cargo runs these
    /// concurrently under `--jobs N` and appending to a shared file from several processes
    /// is a corruption waiting for a busy build. That reasoning is not new here; it is the
    /// note on `write_unit`, applied to the second thing this directory carries.
    ///
    /// `docs/adr/0004` asserted this inventory existed. It did not: `proc_macro_objects`
    /// was `Vec::new()` at its only call site, so every attribution fell back to naming
    /// the compilation. This is the inventory that ADR described.
    pub fn write_macro(&self, object: &Path, id: &UnitId) -> io::Result<PathBuf> {
        let stem = format!(
            "{}-{}-{}",
            sanitise(&id.name),
            sanitise(&id.version),
            std::process::id()
        );
        let path = self.macros.join(format!("{stem}.json"));
        // A per-write nanosecond suffix so `create_new` below never collides with a stale
        // temporary a crashed write left behind (read_macros ignores non-`.json` files).
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp = self.macros.join(format!(".{stem}-{nanos}.tmp"));
        let json = serde_json::to_vec(&MacroRecord {
            object: object.to_path_buf(),
            id: id.clone(),
        })?;
        // `create_new`, so a symlink or file planted at the temporary path is neither
        // followed nor overwritten — the write fails closed instead of landing wherever a
        // link points. The inventory directory is trusted (the driver keeps it out of every
        // sandbox-writable zone), so this is defence in depth rather than the primary guard.
        {
            use std::io::Write as _;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            f.write_all(&json)?;
        }
        // Renamed into place rather than written in place, so a reader never sees a half
        // written entry: an inventory with a truncated path resolves to nothing and
        // attribution degrades without saying so.
        fs::rename(&tmp, &path)?;
        Ok(path)
    }

    /// Every proc-macro object recorded so far in this run.
    ///
    /// Read by each held compile unit as it starts, so the inventory reflects whatever has
    /// been compiled by then. That is a race by construction and a benign one: cargo
    /// compiles a proc-macro before anything that expands it, so a consumer's rustc always
    /// starts after its own macros exist. A macro compiled concurrently for some *other*
    /// consumer may be missing, and the cost is one attribution falling back to naming the
    /// compilation — never a wrong name.
    ///
    /// A corrupt entry is skipped rather than fatal, and this is the one place in the run
    /// directory where that is right. A unit record that cannot be read means the report is
    /// silently short of a unit; a macro entry that cannot be read means one attribution is
    /// less precise. Failing a build over the second would trade the build for a label.
    pub fn read_macros(&self) -> Vec<(PathBuf, UnitId)> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(&self.macros) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let Ok(text) = fs::read(&path) else { continue };
            let Ok(record) = serde_json::from_slice::<MacroRecord>(&text) else {
                continue;
            };
            out.push((record.object, record.id));
        }
        // Sorted so two runs of the same build hand attribution the same list in the same
        // order, which keeps a report diffable for the reason `read_units` sorts.
        out.sort();
        out.dedup();
        out
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Append one unit's record.
    ///
    /// The filename carries the unit's `instance` discriminator, not just its identity.
    /// One compiled build script is executed **more than once per build** whenever a
    /// crate is both a normal and a build dependency under `--target` — `libc`, `cfg-if`
    /// and `proc-macro2` in practically every cross build. Measured on cargo 1.94.1: the
    /// same binary runs twice, interleaved by cargo's scheduler, with identical
    /// `CARGO_PKG_NAME`, `CARGO_PKG_VERSION`, `CARGO_MANIFEST_DIR` and `TARGET`,
    /// distinguished only by `OUT_DIR`.
    ///
    /// Keying on name and version alone means the second write erases the first, and if
    /// the erased one is the run that made an ungranted request the report says the unit
    /// was clean. The pid is appended too, as a belt to that brace for the case where two
    /// runs somehow share an instance.
    pub fn write_unit(&self, record: &UnitRecord) -> io::Result<PathBuf> {
        let stem = format!(
            "{}-{}-{}-{}-{}",
            sanitise(&record.id.name),
            sanitise(&record.id.version),
            sanitise(&record.kind.to_string()),
            sanitise(record.instance.as_deref().unwrap_or("noinstance")),
            std::process::id()
        );
        let final_path = self.root.join(UNITS).join(format!("{stem}.json"));
        let tmp_path = self.root.join(UNITS).join(format!(".{stem}.tmp"));

        let json = serde_json::to_vec_pretty(record)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&tmp_path, json)?;
        // Atomic within the directory. A crash before this leaves a dotfile the reader
        // skips; a crash after leaves a complete record. There is no state in which a
        // half-written record is mistaken for a unit that did nothing.
        fs::rename(&tmp_path, &final_path)?;
        Ok(final_path)
    }

    /// Read every unit record back, in a stable order.
    ///
    /// Sorted by identity so two runs of the same build produce byte-comparable reports.
    /// Diffing two reports is how capability drift is found, and a report whose unit
    /// order depended on filesystem iteration would make every diff noise.
    pub fn read_units(&self) -> io::Result<Vec<UnitRecord>> {
        let dir = self.root.join(UNITS);
        let mut out = Vec::new();
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            // No directory means no units ran, which is a legitimate outcome — a fully
            // fresh build of a workspace with no build scripts and no proc-macros.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Skip the temporaries an interrupted write may have left.
            if name.starts_with('.') || !name.ends_with(".json") {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            match serde_json::from_slice::<UnitRecord>(&bytes) {
                Ok(r) => out.push(r),
                // A record that does not parse is a bug in this tool, and swallowing it
                // would make the report silently short. Surface it.
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unit record {} did not parse: {e}", entry.path().display()),
                    ))
                }
            }
        }
        // Sorted by identity and then by the run discriminator, so two runs of the same
        // build produce byte-comparable reports. Duration is deliberately NOT a sort key:
        // it varies run to run, and diffing two reports is how capability drift is found.
        out.sort_by(|a, b| {
            // The kind is compared as the string it is written as, which is what it was
            // before the field became wire-tolerant: an ordering that changed with a
            // refactor would re-order the units in every report and make two reports
            // straddling the change look like they differ.
            (&a.id, a.kind.to_string(), &a.instance).cmp(&(&b.id, b.kind.to_string(), &b.instance))
        });
        Ok(out)
    }
}

/// Make a crate name or version safe as a path component.
///
/// Crate names are already restricted to `[A-Za-z0-9_-]`, but a *version* from a git or
/// path dependency is whatever the manifest said, and a version containing a slash would
/// otherwise write outside the run directory.
fn sanitise(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use buildclamp_core::{CapabilitySet, Envelope, UnitId, UnitKind};

    fn record(name: &str, version: &str, kind: UnitKind) -> UnitRecord {
        UnitRecord {
            id: UnitId::new(name, version),
            kind: kind.into(),
            source: None,
            instance: None,
            envelope: Envelope::build_script_default(),
            tiers: std::collections::BTreeMap::new(),
            env_scrubbed: Vec::new(),
            requests: Vec::new(),
            observed: CapabilitySet::EMPTY,
            proc_macros_in_closure: Vec::new(),
            exit_code: Some(0),
            signal: None,
            duration_ms: 1,
        }
    }

    #[test]
    fn units_written_separately_are_all_read_back() {
        let d = tempfile::tempdir().unwrap();
        let run = RunDir::open(d.path()).unwrap();
        run.write_unit(&record("serde", "1.0.229", UnitKind::BuildScriptCompile))
            .unwrap();
        run.write_unit(&record("evil", "0.1.3", UnitKind::BuildScriptCompile))
            .unwrap();
        let back = run.read_units().unwrap();
        assert_eq!(back.len(), 2);
    }

    #[test]
    fn records_come_back_in_a_stable_order_so_two_reports_can_be_diffed() {
        // Drift detection is a diff of two reports. An order that depended on readdir
        // would make every diff noise and the feature useless.
        let d = tempfile::tempdir().unwrap();
        let run = RunDir::open(d.path()).unwrap();
        for n in ["zlib", "aho", "mio"] {
            run.write_unit(&record(n, "1.0.0", UnitKind::BuildScriptCompile))
                .unwrap();
        }
        let names: Vec<String> = run
            .read_units()
            .unwrap()
            .into_iter()
            .map(|r| r.id.name)
            .collect();
        assert_eq!(names, vec!["aho", "mio", "zlib"]);
    }

    /// The cross-build collision, reproduced as a unit test.
    ///
    /// Under `--target`, one build script runs twice with different `OUT_DIR`s and
    /// everything else identical. If the second record overwrote the first, a report
    /// could show a clean unit while the erased run was the one that reached the network.
    #[test]
    fn one_build_script_run_twice_under_cross_compilation_keeps_both_records() {
        let d = tempfile::tempdir().unwrap();
        let run = RunDir::open(d.path()).unwrap();
        let mut host = record("libc", "0.2.189", UnitKind::BuildScriptCompile);
        let mut target = record("libc", "0.2.189", UnitKind::BuildScriptCompile);
        host.instance = Some("libc-c2c95513".into());
        target.instance = Some("libc-b8458491".into());
        run.write_unit(&host).unwrap();
        run.write_unit(&target).unwrap();
        let back = run.read_units().unwrap();
        assert_eq!(back.len(), 2, "one run erased the other: {back:?}");
        let mut seen: Vec<_> = back.iter().filter_map(|r| r.instance.clone()).collect();
        seen.sort();
        assert_eq!(seen, vec!["libc-b8458491", "libc-c2c95513"]);
    }

    #[test]
    fn one_crate_compiled_as_two_kinds_keeps_both_records() {
        // Cargo compiles the same crate for host and target in a cross build. Two
        // records that overwrote each other would lose one of them silently.
        let d = tempfile::tempdir().unwrap();
        let run = RunDir::open(d.path()).unwrap();
        run.write_unit(&record("x", "1.0.0", UnitKind::BuildScriptCompile))
            .unwrap();
        run.write_unit(&record("x", "1.0.0", UnitKind::Compile))
            .unwrap();
        assert_eq!(run.read_units().unwrap().len(), 2);
    }

    #[test]
    fn an_empty_run_directory_reads_as_no_units_rather_than_an_error() {
        // A workspace with no build scripts and no proc-macros is a legitimate build.
        let d = tempfile::tempdir().unwrap();
        let run = RunDir {
            root: d.path().join("never-created"),
            macros: d.path().join("never-created-macros"),
        };
        assert!(run.read_units().unwrap().is_empty());
    }

    #[test]
    fn a_leftover_temporary_from_an_interrupted_write_is_ignored() {
        let d = tempfile::tempdir().unwrap();
        let run = RunDir::open(d.path()).unwrap();
        run.write_unit(&record("good", "1.0.0", UnitKind::BuildScriptCompile))
            .unwrap();
        fs::write(
            d.path().join("units").join(".half-written.tmp"),
            b"{ truncated",
        )
        .unwrap();
        assert_eq!(run.read_units().unwrap().len(), 1);
    }

    #[test]
    fn a_corrupt_record_is_surfaced_rather_than_silently_dropped() {
        // A report that is silently short is the worst failure for an audit artefact:
        // a missing unit reads exactly like a clean one.
        let d = tempfile::tempdir().unwrap();
        let run = RunDir::open(d.path()).unwrap();
        fs::write(d.path().join("units").join("broken.json"), b"{ not json").unwrap();
        let err = run.read_units().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_version_containing_a_slash_cannot_write_outside_the_run_directory() {
        // Git and path dependencies carry whatever the manifest said.
        let d = tempfile::tempdir().unwrap();
        let run = RunDir::open(d.path()).unwrap();
        let p = run
            .write_unit(&record(
                "x",
                "../../etc/passwd",
                UnitKind::BuildScriptCompile,
            ))
            .unwrap();
        assert!(p.starts_with(d.path()), "{}", p.display());
    }

    #[test]
    fn the_macro_inventory_lives_in_its_own_directory_not_under_the_run_root() {
        // A held compile can write all of `target/`, and the run root is under `target/`, so
        // an inventory kept there could be forged. With a separate macro directory, nothing
        // the sandbox grants overlaps it.
        let run_root = tempfile::tempdir().unwrap();
        let macro_root = tempfile::tempdir().unwrap();
        let run = RunDir::open_with_macro_dir(run_root.path(), macro_root.path()).unwrap();
        let object = Path::new("/proj/target/debug/deps/libmac.so");
        let id = UnitId::new("mac", "1.0.0");
        let written = run.write_macro(object, &id).unwrap();

        // It landed under the trusted macro directory, and nothing was written under the run
        // root — not even the `macros/` subdirectory the legacy layout used.
        assert!(
            written.starts_with(macro_root.path()),
            "{}",
            written.display()
        );
        assert!(!written.starts_with(run_root.path()));
        assert!(!run_root.path().join(MACROS).exists());

        // And it reads back from the trusted directory.
        assert_eq!(run.read_macros(), vec![(object.to_path_buf(), id)]);
    }

    #[test]
    fn a_forged_entry_under_the_run_root_is_never_read_when_a_trusted_dir_is_used() {
        // A held unit can write the run root but not the trusted macro directory. An entry it
        // plants under run_root/macros must stay invisible: read_macros reads only the
        // trusted directory, so a forged object->unit mapping cannot reach attribution.
        let run_root = tempfile::tempdir().unwrap();
        let macro_root = tempfile::tempdir().unwrap();
        let run = RunDir::open_with_macro_dir(run_root.path(), macro_root.path()).unwrap();

        let forged_dir = run_root.path().join(MACROS);
        fs::create_dir_all(&forged_dir).unwrap();
        let forged = MacroRecord {
            object: PathBuf::from("/evil.so"),
            id: UnitId::new("victim", "9.9.9"),
        };
        fs::write(
            forged_dir.join("forged.json"),
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();

        assert!(run.read_macros().is_empty());
    }
}
