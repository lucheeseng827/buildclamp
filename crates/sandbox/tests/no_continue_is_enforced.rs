//! An architecture invariant: **no code path may
//! promote a CONTINUE-based decision to `enforced:`.**
//!
//! # Why this is a source scan and not only a behavioural test
//!
//! `plan_tiers` is exercised behaviourally elsewhere — a notify-only host must project no
//! enforced tier, and `a_seccomp_errno_refusal_is_enforcement_but_a_notification_decision_is_not`
//! pins the network and filesystem rows. But a behavioural test only covers the host
//! combinations it thinks to construct, and the mislabel this exists for lived on the
//! *exec* row, which that test did not check for two years. A grep over the source catches
//! a new `enforced("seccomp-notify…")` the day it is written, on any row, without anyone
//! having to think to add a host combination for it.
//!
//! # What counts as CONTINUE-based
//!
//! The seccomp *notification* supervisor. It reads an argument out of the unit's memory,
//! decides, and answers — and for an allowed call it answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`,
//! after which the kernel re-reads the argument. That re-read is the race
//! `seccomp_unotify(2)` warns about, and it is why a decision made this way is advisory.
//!
//! A classic-BPF filter returning an errno is **not** this. The kernel returns the errno
//! itself; the syscall never runs; there is no supervisor and no window. So
//! `enforced("seccomp-errno")` is legitimate and this invariant must not flag it — which is
//! the whole reason the rule keys on the mechanism string `notify` rather than on the word
//! `seccomp`.

use std::path::Path;

/// Every `.rs` file under a directory, read to a string.
fn sources(dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)
        .expect("the sandbox src dir is readable")
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            out.extend(sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push((
                path.display().to_string(),
                std::fs::read_to_string(&path).unwrap_or_default(),
            ));
        }
    }
    out
}

/// The argument text of each `name(...)` call in a source file, with its line number.
///
/// A deliberately small parser, but not a line-by-line one: it matches the call name only
/// where it is a real call (not the tail of another identifier and not on a comment or
/// definition line), then captures to the **balanced** close paren, across line breaks. The
/// old version took chars up to the first `)` on the same line, which produced an empty
/// capture for a call split across lines — a `enforced(\n "seccomp-notify")` would have read
/// as "no notify here". The caller fails closed on an empty capture for exactly that reason.
///
/// It still does not resolve a variable: `enforced(&mechanism)` is captured as `&mechanism`.
/// That is deliberate — the one such call in this crate holds a `landlock-v{n}` string, and
/// failing closed on every non-literal would flag it — so a mechanism smuggled through a
/// variable is a documented limit, and the behavioural tests plus the `advisory(` binding
/// below are the other half of the guarantee.
fn call_arguments(text: &str, name: &str) -> Vec<(usize, String)> {
    let def_a = format!("fn {name}");
    let def_b = format!("pub(crate) fn {name}");
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut search = 0;
    while let Some(rel) = text[search..].find(name) {
        let start = search + rel;
        search = start + name.len();
        let after = start + name.len();
        // A whole-identifier match: not the tail of another identifier (`unenforced`), and not
        // the head of a longer one (`enforcement`, `enforced_thing`).
        let prev_ident = text[..start]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        let next_ident = text[after..]
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if prev_ident || next_ident {
            continue;
        }
        // A call is one whose next significant token is `(`, skipping whitespace and `/* */`
        // block comments. A bare `name(` needle missed `enforced ("x")` and
        // `enforced /* why */ ("x")`, so a CONTINUE dressed with a space or a comment could
        // slip past this gate. (A `//` line comment or a string between the name and the paren
        // is out of this scan's scope; a full guard wants a Rust lexer, and `cargo fmt --check`
        // already removes a bare space before a call's paren.)
        let Some(paren_off) = open_paren_after(&text[after..]) else {
            continue;
        };
        let arg_start = after + paren_off + 1;
        // Skip the call's own definition line and any `//` comment before it on the line.
        let line_start = text[..start].rfind('\n').map_or(0, |n| n + 1);
        let before = &text[line_start..start];
        let trimmed = before.trim_start();
        if before.contains("//") || trimmed.starts_with(&def_a) || trimmed.starts_with(&def_b) {
            continue;
        }
        // Capture to the matching close paren, counting nesting and crossing line breaks.
        let mut depth = 1usize;
        let mut end = arg_start;
        while end < bytes.len() {
            match bytes[end] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            end += 1;
        }
        let line_no = text[..start].bytes().filter(|&b| b == b'\n').count() + 1;
        out.push((line_no, text[arg_start..end].trim().to_string()));
        search = end;
    }
    out
}

/// The byte offset of `(` in `s` if the next significant token — skipping ASCII whitespace and
/// `/* ... */` block comments — is an open paren, else `None`.
fn open_paren_after(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0;
    loop {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if s[i..].starts_with("/*") {
            // Rust block comments nest, so a scan that stopped at the first `*/` would end the
            // comment early: `enforced /* outer /* inner */ outer */ ("seccomp-notify")` would
            // read as closing at the inner `*/`, leaving `outer */ (` as the next tokens and
            // hiding the call from the gate. Track depth to the matching OUTER close instead.
            i += 2;
            let mut depth = 1usize;
            while i < b.len() && depth > 0 {
                if b[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if depth != 0 {
                return None;
            }
            continue;
        }
        break;
    }
    (i < b.len() && b[i] == b'(').then_some(i)
}

#[test]
fn no_enforced_tier_is_labelled_with_a_notification_mechanism() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = sources(&src);
    assert!(
        files.len() >= 4,
        "the source scan found only {} files; it is reading nothing",
        files.len()
    );

    let mut offenders: Vec<String> = Vec::new();
    let mut enforced_calls = 0usize;
    let mut saw_errno_enforced = false;

    for (path, text) in &files {
        for (line, arg) in call_arguments(text, "enforced") {
            enforced_calls += 1;
            // Fail closed on a capture the parser could not resolve to anything: an empty
            // argument is what a broken paren scan produces, and reading it as "no notify
            // here" is exactly the blind spot that let the multiline case pass. The mechanism
            // is CONTINUE-based iff it names the notification supervisor — `notify` catches
            // `seccomp-notify` and `seccomp-notify-record` alike; `errno` is the atomic
            // classic-BPF path and is legitimately enforced.
            if arg.is_empty() || arg.contains("notify") {
                offenders.push(format!("{path}:{line}: enforced({arg})"));
            }
            if arg.contains("errno") {
                saw_errno_enforced = true;
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a CONTINUE-based (seccomp-notify) decision is labelled `enforced`:\n  {}\n\n\
         seccomp_unotify(2): the notification mechanism must not be used to make security \
         policy decisions, which would be inherently race-prone. A tier decided by the \
         notification supervisor is advisory, never enforced — see \
         crates/sandbox/src/linux/mod.rs and the exec row's history.",
        offenders.join("\n  ")
    );

    // Positive controls, so a scan that silently matched nothing cannot pass. There ARE
    // enforced tiers in this crate, and at least one is the legitimate errno rung the rule
    // is careful not to flag.
    assert!(
        enforced_calls >= 4,
        "found only {enforced_calls} enforced() calls; the scan is not seeing them, so its \
         green result would mean nothing"
    );
    assert!(
        saw_errno_enforced,
        "the scan never saw `enforced(\"seccomp-errno\")`, so it cannot be distinguishing \
         the atomic errno rung from the racy notification one — which is the whole point"
    );
}

#[test]
fn the_notify_mechanism_exists_and_is_advisory() {
    // The other half of the same guarantee: the notification supervisor is real and is
    // used, and where it decides a capability that capability is advisory. A rule that
    // forbade `enforced(notify)` would also pass in a crate that had quietly stopped using
    // notification at all, so this pins that the mechanism is present and correctly graded.
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let both: String = sources(&src)
        .into_iter()
        .map(|(_, t)| format!("{t}\n"))
        .collect();
    // Bound to the arguments of real `advisory(` calls, not to the string appearing anywhere:
    // a `seccomp-notify` in a comment, or worse in an `enforced(` argument, must not satisfy
    // this — or the two tests could pass together while the mechanism was mislabelled. The
    // record mechanism's own call is multiline in `mod.rs`, which the cross-line parser reads.
    let advisory_args: Vec<String> = call_arguments(&both, "advisory")
        .into_iter()
        .map(|(_, a)| a)
        .collect();
    assert!(
        advisory_args
            .iter()
            .any(|a| a.contains("seccomp-notify-record")),
        "no `advisory(` call names `seccomp-notify-record`; if exec stopped being recorded \
         this test should change deliberately, not by accident"
    );
    assert!(
        advisory_args.iter().any(|a| a.contains("seccomp-notify")),
        "no `advisory(` call names the seccomp-notify mechanism"
    );
}

#[test]
fn whitespace_or_a_block_comment_before_the_paren_does_not_hide_a_call() {
    // The bypass: `enforced ("seccomp-notify")` and `enforced /* why */ ("...")` are calls a
    // bare `enforced(` needle missed, so a CONTINUE decision could be labelled enforced and
    // slip past the gate. Neither `unenforced` nor `enforcement` is an `enforced` call.
    let text = concat!(
        "let a = enforced(\"seccomp-errno\");\n",
        "let b = enforced (\"seccomp-notify\");\n",
        "let c = enforced /* why */ (\"seccomp-notify-record\");\n",
        "let d = unenforced(\"x\");\n",
        "let e = enforcement(\"y\");\n",
    );
    let args: Vec<String> = call_arguments(text, "enforced")
        .into_iter()
        .map(|(_, a)| a)
        .collect();
    assert_eq!(
        args.len(),
        3,
        "missed a spaced/commented call, or matched a different identifier: {args:?}"
    );
    assert!(args.iter().any(|a| a.contains("seccomp-errno")));
    assert!(
        args.iter().any(|a| a.contains("seccomp-notify\"")),
        "a space before the paren hid a call: {args:?}"
    );
    assert!(
        args.iter().any(|a| a.contains("seccomp-notify-record")),
        "a block comment before the paren hid a call: {args:?}"
    );
}

#[test]
fn a_nested_block_comment_before_the_paren_does_not_hide_a_call() {
    // Rust block comments nest. A scan that stopped at the first `*/` read
    // `enforced /* outer /* inner */ still-outer */ ("seccomp-notify")` as ending at the inner
    // `*/`, leaving `still-outer */ (` as the next tokens and hiding the call — so a CONTINUE
    // decision dressed in a nested comment could be labelled enforced and slip past the gate.
    let text = concat!(
        "let a = enforced /* outer /* inner */ still-outer */ (\"seccomp-notify\");\n",
        "let b = enforced(\"seccomp-errno\");\n",
    );
    let args: Vec<String> = call_arguments(text, "enforced")
        .into_iter()
        .map(|(_, a)| a)
        .collect();
    assert_eq!(
        args.len(),
        2,
        "a nested block comment before the paren hid a call: {args:?}"
    );
    assert!(
        args.iter().any(|a| a.contains("seccomp-notify\"")),
        "the call behind the nested comment must be seen: {args:?}"
    );
}
