//! What a build unit is, and how one is recognised from a rustc command line.
//!
//! Cargo does not hand a wrapper a tidy description of what it is about to compile. It
//! hands it an argv, and everything the tool knows about which unit it is looking at is
//! recovered from that argv plus a handful of environment variables. This module is
//! that recovery, and it is pure so it can be tested against recorded command lines
//! without a cargo in the loop.
//!
//! Every shape encoded here was captured from a real `cargo build -vv` on cargo 1.94.1
//! and is pinned by a table test. Cargo's command lines are not a stable interface, so
//! the tests exist to make a change in them a loud failure rather than a unit that
//! silently stops being held.

use serde::{Deserialize, Serialize};

/// The kinds of thing cargo runs that this tool cares about.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitKind {
    /// Compiling a `build.rs` into an executable. Recognised by
    /// `--crate-name build_script_build`.
    ///
    /// This compile is not itself dangerous — it is rustc reading source — but it is
    /// the moment the tool swaps the produced binary for a shim, so it is the single
    /// most important classification to get right. Missing one here means that build
    /// script later runs unheld.
    BuildScriptCompile,
    /// Compiling a proc-macro crate into a `.so`. Recognised by
    /// `--crate-type proc-macro`.
    ///
    /// Recorded for the inventory rather than swapped: a proc-macro is not executed by
    /// cargo, it is loaded by a later rustc. See [`UnitKind::Compile`].
    ProcMacroCompile,
    /// Compiling anything else — a library, a binary, a test.
    ///
    /// This is where proc-macros actually *execute*, inside this rustc process, which
    /// is why an ordinary compile is held at all. Attribution for anything a unit of
    /// this kind does can only name the crate being compiled plus the proc-macros in
    /// its closure; see `docs/adr/0004`.
    Compile,
    /// A `--print`, `-vV` or `-` probe. Cargo issues several per build to discover the
    /// compiler's capabilities. Passed through untouched: there is no crate, no output
    /// and nothing to hold.
    Probe,
}

impl std::fmt::Display for UnitKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl UnitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            UnitKind::BuildScriptCompile => "build-script-compile",
            UnitKind::ProcMacroCompile => "proc-macro-compile",
            UnitKind::Compile => "compile",
            UnitKind::Probe => "probe",
        }
    }
}

/// What a rustc invocation turned out to be.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RustcInvocation {
    pub kind: UnitKind,
    /// The value of `--crate-name`, when there is one.
    pub crate_name: Option<String>,
    /// The value of `--out-dir`, when there is one.
    pub out_dir: Option<String>,
    /// The `-C extra-filename=` suffix, without its leading `-`.
    ///
    /// Needed because the file rustc writes for a build script is
    /// `<out-dir>/<crate-name>-<extra-filename>`, and that is the path the swap has to
    /// find. Cargo passes this as either `-C extra-filename=-abc` (two argv entries) or
    /// `-Cextra-filename=-abc` (one), and both are seen in practice.
    ///
    /// Cargo 1.100 passes none for a build-script compile: each unit has its own
    /// directory (`build/<pkg>/<hash>/out/`), so rustc writes `<out-dir>/<crate-name>`.
    pub extra_filename: Option<String>,
}

impl RustcInvocation {
    /// The path rustc will write for a build-script compile, if this is one.
    ///
    /// Returns `None` for every other kind, and for a build-script compile that is
    /// missing either piece — which should not happen, and which the caller must treat
    /// as "pass through untouched" rather than as an error. A wrapper that fails the
    /// build because it did not recognise a command line is a wrapper that gets
    /// uninstalled.
    /// # The stem is the crate name, not the literal `build_script_build`
    ///
    /// This used to hard-code that literal, which was correct only while `classify`
    /// recognised nothing else. Once the classifier learned the `build_script_` prefix —
    /// so a manifest's `build = "x.rs"` is seen for what it is — the two disagreed, and
    /// disagreeing here is worse than not recognising the unit at all: `wrapper_action`
    /// gets `Some(path)` and returns `CompileThenSwap`, the swap then cannot find
    /// `build_script_build-<extra>` because rustc wrote `build_script_x-<extra>`, and
    /// `cli::main` prints the failure and lets the build continue — by design, since
    /// breaking a build over an unrecognised command line is how a wrapper gets
    /// uninstalled. The build script runs **unheld**. That is the exact bypass the
    /// prefix was added to close, arriving through the next door along.
    pub fn build_script_output(&self) -> Option<String> {
        if self.kind != UnitKind::BuildScriptCompile {
            return None;
        }
        let out = self.out_dir.as_ref()?;
        let name = self.crate_name.as_ref()?;
        // No suffix is not a missing piece: rustc then writes `<out-dir>/<crate-name>`,
        // which is cargo 1.100's layout. Treating it as one passed every build script
        // through unheld, with nothing in the report to say so.
        match &self.extra_filename {
            Some(extra) => Some(format!("{out}/{name}-{extra}")),
            None => Some(format!("{out}/{name}")),
        }
    }
}

impl RustcInvocation {
    /// The shared object rustc will write for a proc-macro compile, if this is one.
    ///
    /// `lib<crate_name>-<extra_filename>.so`, which is the name a later rustc dlopens when
    /// it expands the macro — and therefore the name that has to be in the inventory for
    /// attribution to resolve an instruction pointer back to a crate.
    ///
    /// The same shape as [`RustcInvocation::build_script_output`] and the same failure
    /// rule: a compile missing either piece returns `None` and the caller passes it
    /// through rather than guessing. An inventory entry pointing at a path rustc did not
    /// write is worse than a missing one — attribution would silently never match it, and
    /// the report would name the consumer where it could have named the macro.
    ///
    /// `.so` is hard-coded and this is Linux-only, which the whole crate already is. On a
    /// platform where rustc writes `.dylib` or `.dll` this would be wrong rather than
    /// merely unsupported, so it is worth saying rather than leaving to be discovered.
    pub fn proc_macro_output(&self) -> Option<String> {
        if self.kind != UnitKind::ProcMacroCompile {
            return None;
        }
        let out = self.out_dir.as_ref()?;
        let extra = self.extra_filename.as_ref()?;
        let name = self.crate_name.as_ref()?;
        Some(format!("{out}/lib{name}-{extra}.so"))
    }

    /// The profile directory (`<target>/debug`) a compile writes under, from its
    /// `--out-dir`: what a held compile is granted, because rustc also writes
    /// `incremental/` there, beside the out-dir rather than under it.
    ///
    /// Before cargo 1.100 the out-dir is `<profile>/deps`; from 1.100 it is
    /// `<profile>/build/<pkg>/<hash>/out`, where the parent is only the unit's own
    /// directory and granting it made every held compile fail on its incremental dir.
    pub fn profile_dir(&self) -> Option<std::path::PathBuf> {
        let out = std::path::Path::new(self.out_dir.as_ref()?);
        let unit_layout = out.ends_with("out")
            && out.ancestors().nth(3).and_then(|b| b.file_name()) == Some("build".as_ref());
        out.ancestors()
            .nth(if unit_layout { 4 } else { 1 })
            .map(std::path::Path::to_path_buf)
    }
}

/// The prefix cargo gives every build-script compile.
///
/// It used to be an exact `"build_script_build"` here, under a comment claiming that was the
/// name "regardless of the crate". It is not. The stem comes from the build file, and
/// `Cargo.toml`'s `build = "x.rs"` compiles as `build_script_x` — measured with
/// `cargo build -v` on a crate with exactly that manifest:
///
/// ```text
/// --crate-name build_script_x --crate-type bin --out-dir …/target/debug/build/pkg-<hash>
/// ```
///
/// The exact match therefore let any crate with a custom build file fall through to
/// `UnitKind::Compile` and be held as an ordinary library compile. `crates/shim/src/sweep.rs`
/// already scanned for this as a prefix, so the two halves of the tool disagreed about what a
/// build script looks like.
const BUILD_SCRIPT_CRATE_PREFIX: &str = "build_script_";

/// Classify a rustc command line.
///
/// `args` is everything after the compiler path — that is, cargo invokes
/// `<wrapper> <compiler> <args...>` and this takes the `args`.
///
/// # The argv[1] trap
///
/// The caller must NOT assume the compiler is `rustc`. Under `cargo clippy`, cargo sets
/// `RUSTC_WORKSPACE_WRAPPER` as well, and the workspace's own units arrive as
/// `<wrapper> clippy-driver <rustc> <args...>`. Measured on cargo 1.94.1: the five
/// dependency build scripts came through with `argv[1] = rustc` while **the primary
/// package's build script came through with `argv[1] = clippy-driver`** — so a
/// classifier that keyed on the compiler's basename would have skipped precisely the
/// build script a developer most wants held. This function scans the whole argv for
/// markers instead, which makes it indifferent to how many compiler-ish things are
/// stacked in front.
pub fn classify(args: &[String]) -> RustcInvocation {
    let mut crate_name = None;
    let mut out_dir = None;
    let mut extra_filename = None;
    let mut crate_types: Vec<String> = Vec::new();
    let mut saw_print_or_version = false;
    let mut reads_stdin = false;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];

        if let Some(v) = flag_value(args, i, "--crate-name") {
            crate_name = Some(v);
        } else if let Some(v) = flag_value(args, i, "--out-dir") {
            out_dir = Some(v);
        } else if let Some(v) = flag_value(args, i, "--crate-type") {
            crate_types.push(v);
        } else if a.starts_with("--print") || a == "-vV" || a == "--version" {
            // Cargo asks the compiler about itself several times per build: sysroot,
            // target cfgs, file-name patterns, the version banner. None of them compiles
            // anything, so none of them is a unit.
            saw_print_or_version = true;
        } else if a == "-" {
            // rustc reading source from stdin: the capability probe cargo runs first.
            reads_stdin = true;
        } else if let Some(v) = codegen_option(args, i, "extra-filename") {
            // `-C extra-filename=-abc` (two entries) or `-Cextra-filename=-abc` (one).
            extra_filename = Some(v.trim_start_matches('-').to_string());
        }
        i += 1;
    }

    let kind = if saw_print_or_version || reads_stdin || crate_name.is_none() {
        UnitKind::Probe
    } else if crate_name
        .as_deref()
        .is_some_and(|n| n.starts_with(BUILD_SCRIPT_CRATE_PREFIX))
        && !crate_types.iter().any(|t| t != "bin")
    {
        // The prefix, and no crate type that contradicts it.
        //
        // An earlier version took the prefix alone, on the reasoning that for a gate a
        // false positive is the safe direction — it "holds a unit that did not need
        // holding". That reasoning was wrong, and checking `roles::wrapper_action`
        // rather than assuming would have shown it: `BuildScriptCompile` never reaches
        // `HoldCompile`. It goes to `CompileThenSwap`, or passes through. So a library
        // from a package genuinely named `build-script-foo`, whose lib compiles under
        // `--crate-name build_script_foo --crate-type lib`, would not be held *more*
        // tightly by being misread — it would stop being held as a compile unit at all,
        // and the swap would go looking for a bin that was never written.
        //
        // Hence the second half, written as "nothing here contradicts a bin" rather than
        // "bin is present". The distinction matters: cargo does pass `--crate-type bin`
        // for build scripts today, but the trimmed fixtures below carry no `--crate-type`
        // at all, and requiring one would make the gate depend on a flag no test
        // guarantees — which is how a gate silently stops covering something. An absent
        // crate type still classifies as a build script; only an explicit non-bin one
        // rules it out.
        UnitKind::BuildScriptCompile
    } else if crate_types.iter().any(|t| t == "proc-macro") {
        UnitKind::ProcMacroCompile
    } else {
        UnitKind::Compile
    };

    RustcInvocation {
        kind,
        crate_name,
        out_dir,
        extra_filename,
    }
}

/// Pull the value of `--flag=value` or `--flag value`. Cargo uses both spellings in
/// the same command line, so both have to work.
fn flag_value(args: &[String], i: usize, flag: &str) -> Option<String> {
    let a = &args[i];
    if let Some(rest) = a.strip_prefix(flag).and_then(|r| r.strip_prefix('=')) {
        return Some(rest.to_string());
    }
    if a == flag {
        return args.get(i + 1).cloned();
    }
    None
}

/// Pull the value of a `-C <name>=<value>` codegen option from either spelling.
fn codegen_option(args: &[String], i: usize, name: &str) -> Option<String> {
    let a = &args[i];
    if a == "-C" {
        let next = args.get(i + 1)?;
        return next
            .strip_prefix(name)?
            .strip_prefix('=')
            .map(str::to_string);
    }
    a.strip_prefix("-C")?
        .strip_prefix(name)?
        .strip_prefix('=')
        .map(str::to_string)
}

/// Identity of a build unit: the crate whose code is about to run, and its version.
///
/// Deliberately `name` + `version` and nothing else. The source (registry, git, path)
/// is recorded in the report for a human, but it is not part of identity, because a
/// policy written against `openssl-sys 0.9` should keep applying when the same crate
/// arrives through a `[patch]` or a vendor directory — a grant that silently stopped
/// applying after a vendoring change would be a security regression introduced by a
/// build-system change.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
pub struct UnitId {
    pub name: String,
    pub version: String,
}

impl UnitId {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

impl std::fmt::Display for UnitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.name, self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    /// Every line here is a real command line captured from `cargo build -vv` /
    /// `cargo clippy -vv` on cargo 1.94.1, trimmed to the parts that classify. Cargo's
    /// argv is not a stable interface, so this table is what makes a change in it a
    /// loud failure instead of a unit that quietly stops being held.
    #[test]
    fn recorded_cargo_command_lines_classify_as_they_did_when_measured() {
        let cases: &[(&str, UnitKind, Option<&str>)] = &[
            (
                "--crate-name build_script_build --edition=2021 /reg/proc-macro2-1.0.107/build.rs \
                 --crate-type bin --emit=dep-info,link -C metadata=300b -C extra-filename=-861475 \
                 --out-dir /t/debug/build/proc-macro2-861475",
                UnitKind::BuildScriptCompile,
                Some("build_script_build"),
            ),
            // `build = "x.rs"` in Cargo.toml. Captured the same way as the rest, from
            // `cargo build -v` on a crate with that manifest — the stem follows the build
            // file, so an exact match on `build_script_build` classified this as `Compile`.
            (
                "--crate-name build_script_x --edition=2021 x.rs \
                 --crate-type bin --emit=dep-info,link -C extra-filename=-21e31c \
                 --out-dir /t/debug/build/bsprobe-21e31c",
                UnitKind::BuildScriptCompile,
                Some("build_script_x"),
            ),
            (
                "--crate-name serde_derive --edition=2021 /reg/serde_derive-1.0.229/src/lib.rs \
                 --crate-type proc-macro --emit=dep-info,link -C prefer-dynamic \
                 --out-dir /t/debug/deps",
                UnitKind::ProcMacroCompile,
                Some("serde_derive"),
            ),
            (
                "--crate-name unicode_ident --edition=2021 /reg/unicode-ident-1.0.24/src/lib.rs \
                 --crate-type lib --emit=dep-info,metadata,link --out-dir /t/debug/deps",
                UnitKind::Compile,
                Some("unicode_ident"),
            ),
            // The capability probe DOES carry a crate name — the literal `___` — so a
            // classifier that keyed on "has a crate name" would treat it as a compile.
            // `--print` has to win, and this row is what proves it does.
            (
                "- --crate-name ___ --print=file-names --crate-type bin --crate-type rlib \
                 --crate-type proc-macro --print=sysroot --print=cfg -Wwarnings",
                UnitKind::Probe,
                Some("___"),
            ),
            ("-vV", UnitKind::Probe, None),
        ];
        for (line, want_kind, want_name) in cases {
            let got = classify(&argv(line));
            assert_eq!(got.kind, *want_kind, "kind for: {line}");
            assert_eq!(got.crate_name.as_deref(), *want_name, "name for: {line}");
        }
    }

    #[test]
    fn a_probe_that_also_names_proc_macro_crate_types_is_still_a_probe() {
        // The capability probe passes `--crate-type proc-macro` among six others. If
        // `--print` did not win, every build would begin by trying to sandbox a probe
        // that has no crate and no output.
        let got = classify(&argv(
            "- --crate-name ___ --print=file-names --crate-type proc-macro",
        ));
        assert_eq!(got.kind, UnitKind::Probe);
    }

    #[test]
    fn the_build_script_output_path_is_recovered_from_either_dash_c_spelling() {
        let split = classify(&argv(
            "--crate-name build_script_build --out-dir /t/build/dep-8fec -C extra-filename=-8fec",
        ));
        let joined = classify(&argv(
            "--crate-name build_script_build --out-dir /t/build/dep-8fec -Cextra-filename=-8fec",
        ));
        let want = Some("/t/build/dep-8fec/build_script_build-8fec".to_string());
        assert_eq!(split.build_script_output(), want);
        assert_eq!(joined.build_script_output(), want);
    }

    #[test]
    fn a_custom_build_file_swaps_the_binary_rustc_actually_wrote() {
        // `build = "x.rs"` compiles as `build_script_x`, so rustc writes
        // `build_script_x-<extra>`. Hard-coding `build_script_build-` here sent the swap
        // to a path that does not exist; `cli::main` prints the failure and lets the
        // build continue, so the build script ran unheld — the bypass the prefix was
        // added to close, one door along. Recognising the unit and then looking for the
        // wrong file is worse than not recognising it, because the pass-through branch
        // that exists for the unrecognised case is never reached.
        let got = classify(&argv(
            "--crate-name build_script_x --crate-type bin --out-dir /t/build/pkg-21e31c \
             -C extra-filename=-21e31c",
        ));
        assert_eq!(got.kind, UnitKind::BuildScriptCompile);
        assert_eq!(
            got.build_script_output(),
            Some("/t/build/pkg-21e31c/build_script_x-21e31c".to_string())
        );
    }

    #[test]
    fn a_library_that_merely_looks_like_a_build_script_is_still_held_as_a_compile() {
        // A package named `build-script-foo` has a lib that compiles under
        // `--crate-name build_script_foo`. Reading that as a build script is not the safe
        // direction, which is the correction to what the comment on this branch used to
        // claim: `roles::wrapper_action` never routes `BuildScriptCompile` to
        // `HoldCompile`. It routes it to `CompileThenSwap` — after which the swap hunts a
        // bin rustc never wrote — or passes it through. Either way the library stops
        // being held, and this is where proc-macros execute.
        let got = classify(&argv(
            "--crate-name build_script_foo --edition=2021 src/lib.rs --crate-type lib \
             --emit=dep-info,metadata,link -C extra-filename=-9ab -C metadata=9ab \
             --out-dir /t/debug/deps",
        ));
        assert_eq!(got.kind, UnitKind::Compile);
        assert_eq!(got.build_script_output(), None);
    }

    #[test]
    fn an_absent_crate_type_still_reads_as_a_build_script() {
        // The second half of the classifier is "nothing contradicts a bin", not "bin is
        // present". Cargo passes `--crate-type bin` today, but the trimmed fixtures above
        // carry none, and a gate that depended on a flag no test guarantees is a gate
        // that silently stops covering something.
        let got = classify(&argv(
            "--crate-name build_script_build --out-dir /t/build/dep-8fec -C extra-filename=-8fec",
        ));
        assert_eq!(got.kind, UnitKind::BuildScriptCompile);
    }

    #[test]
    fn a_build_script_compile_missing_its_out_dir_yields_no_path_rather_than_a_guess() {
        // The caller must pass such an invocation through untouched. A wrapper that
        // failed the build because it did not recognise a command line is a wrapper
        // that gets uninstalled, and a wrapper that guesses a path is one that corrupts
        // a target directory.
        let got = classify(&argv(
            "--crate-name build_script_build -C extra-filename=-8fec",
        ));
        assert_eq!(got.kind, UnitKind::BuildScriptCompile);
        assert_eq!(got.build_script_output(), None);
    }

    #[test]
    fn a_build_script_compile_without_an_extra_filename_yields_the_unsuffixed_path() {
        // Captured from `cargo build -vv` on cargo 1.100.0: the build-script compile has
        // its own unit directory and no `-C extra-filename`, and cargo then executes
        // `<out-dir>/build_script_build` itself. Returning None here passed every build
        // script through unheld.
        let got = classify(&argv(
            "--crate-name build_script_build --crate-type bin \
             --out-dir /t/debug/build/bs/333cbacb469d7be5/out -C metadata=cde48755667e3bf7",
        ));
        assert_eq!(
            got.build_script_output(),
            Some("/t/debug/build/bs/333cbacb469d7be5/out/build_script_build".to_string())
        );
    }

    #[test]
    fn the_profile_directory_is_found_in_both_cargo_layouts() {
        for (out_dir, want) in [
            ("/t/debug/deps", "/t/debug"),
            ("/t/debug/build/serde/d050780cac9eb4b3/out", "/t/debug"),
            (
                "/t/x86_64-unknown-linux-musl/release/deps",
                "/t/x86_64-unknown-linux-musl/release",
            ),
        ] {
            let got = classify(&argv(&format!("--crate-name serde --out-dir {out_dir}")));
            assert_eq!(
                got.profile_dir(),
                Some(std::path::PathBuf::from(want)),
                "{out_dir}"
            );
        }
    }

    #[test]
    fn classification_ignores_what_is_in_front_of_rustc() {
        // Measured under `cargo clippy` on cargo 1.94.1: the workspace's own build
        // script arrives with clippy-driver in front. Keying on the compiler basename
        // would skip exactly the unit a developer most wants held.
        let got = classify(&argv(
            "/rustc --crate-name build_script_build --out-dir /t/build/x-1 -C extra-filename=-1",
        ));
        assert_eq!(got.kind, UnitKind::BuildScriptCompile);
    }

    #[test]
    fn a_proc_macro_compile_yields_the_shared_object_rustc_writes() {
        // Captured from `cargo build -vv`: a proc-macro crate compiles with
        // `--crate-type proc-macro` and rustc writes `lib<name>-<extra>.so` into
        // `--out-dir`. That path is what a later rustc dlopens, so it is the one the
        // inventory has to carry for attribution to resolve anything.
        let got = classify(&argv(
            "--crate-name serde_derive --crate-type proc-macro -C extra-filename=-861475 \
             --out-dir /t/debug/deps",
        ));
        assert_eq!(got.kind, UnitKind::ProcMacroCompile);
        assert_eq!(
            got.proc_macro_output(),
            Some("/t/debug/deps/libserde_derive-861475.so".to_string())
        );
    }

    #[test]
    fn nothing_but_a_proc_macro_compile_yields_a_shared_object_path() {
        // The same rule `build_script_output` follows, for the same reason: a path derived
        // from the wrong kind of unit would put an entry in the inventory that attribution
        // can never match, and the report would then name a consumer where it could have
        // named the macro.
        for line in [
            "--crate-name build_script_build --crate-type bin --out-dir /t -C extra-filename=-1",
            "--crate-name unicode_ident --crate-type lib --out-dir /t -C extra-filename=-1",
        ] {
            assert_eq!(classify(&argv(line)).proc_macro_output(), None, "{line}");
        }
        // And a proc-macro compile missing a piece yields nothing rather than a guess.
        let partial = classify(&argv("--crate-name x --crate-type proc-macro"));
        assert_eq!(partial.proc_macro_output(), None);
    }

    #[test]
    fn a_unit_id_prints_the_way_the_report_and_the_policy_spell_it() {
        assert_eq!(
            UnitId::new("openssl-sys", "0.9.104").to_string(),
            "openssl-sys@0.9.104"
        );
    }
}
