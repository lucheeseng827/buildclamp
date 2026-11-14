//! The run header: the facts about a whole build, gathered once.
//!
//! Everything here is **best effort and never fatal**. buildclamp sits in the build path,
//! and a tool that failed a release because it could not read `.git/HEAD` would be
//! uninstalled the first time it did it. Every function in this file returns `None` where
//! it cannot answer, and [`buildclamp_core::Run`] is a document of nulls in the limit.
//!
//! It lives in the CLI rather than in `buildclamp-core` for the reason the workspace
//! manifest gives: core is pure — no I/O, no libc, no cargo, no clock — so its policy
//! semantics can be tested on a machine with no kernel features at all. Reading a clock
//! and a `.git` directory is exactly the impurity that boundary exists to keep out, so
//! core owns the *type* and this module owns the *gathering*.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use buildclamp_core::{rfc3339_utc, RepoRef, Run, ECOSYSTEM};

/// Gather everything knowable before cargo starts.
pub fn begin(cargo_args: &[String]) -> Run {
    Run {
        run_uuid: fresh_id(),
        started_at: now_rfc3339(),
        finished_at: None,
        repo: repo_ref(),
        target: target_triple(cargo_args),
        agent_id: non_empty(std::env::var(buildclamp_core::ENV_AGENT_ID).ok()),
        ci_correlation: non_empty(std::env::var(buildclamp_core::ENV_CI_CORRELATION).ok()),
        ecosystem: ECOSYSTEM.to_string(),
        // Filled in once the policy stack is loaded and its distributed layers are checked
        // against the committed trust root; unknown until then, so `false`/`None` here.
        policy_signature_verified: false,
        policy_signer_key_id: None,
    }
}

/// Record what the signature check found, once the policy stack is resolved.
pub fn stamp_policy_provenance(run: &mut Run, prov: &buildclamp_core::PolicyProvenance) {
    run.policy_signature_verified = prov.signature_verified;
    run.policy_signer_key_id = prov.signer_key_id();
}

/// Stamp the finish time. Called after cargo exits and before the report is written.
pub fn end(run: &mut Run) {
    run.finished_at = now_rfc3339();
}

/// An empty environment variable is an unset one.
///
/// CI systems export variables with empty values constantly — a job that did not set
/// `BUILDCLAMP_AGENT_ID` in one branch of a matrix still exports it as `""` — and an
/// empty string in the report is a field that looks answered and is not.
fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

fn now_rfc3339() -> Option<String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| rfc3339_utc(d.as_secs()))
}

/// A fresh run identifier, in UUID version 4 layout.
///
/// Sixteen bytes from `/dev/urandom`, with the version and variant bits set, rather than
/// a `uuid` dependency. The workspace manifest argues at length for a lean dependency
/// list in a tool whose whole subject is what a build pulls in and executes, and this is
/// twenty lines against a crate.
///
/// **It identifies a run, not a machine.** Nothing here reads the hostname, the MAC
/// address, the user or the working directory — a version 1 UUID would have embedded a
/// MAC address, which is a stable identifier for the customer's build machine appearing
/// in an artefact that gets mailed to reviewers.
///
/// If `/dev/urandom` cannot be read the id falls back to the clock and the pid. That is
/// weaker — two runs starting in the same nanosecond in the same pid namespace could
/// collide — and it is recorded here rather than hidden, because the alternative is
/// failing a build over an entropy source.
fn fresh_id() -> String {
    let mut b = [0u8; 16];
    // `read_exact` on an open handle, NOT `fs::read`. `/dev/urandom` is an endless
    // stream: `fs::read` reads to EOF, there is no EOF, and the process grows until the
    // kernel kills it. Written that way once here; every build died with SIGKILL after
    // about a minute, and the end-to-end suite reported the benign fixture as "refused"
    // because a signal death and a policy refusal both arrive as a non-zero status.
    match std::fs::File::open("/dev/urandom").and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut b)
    }) {
        Ok(()) => {}
        Err(_) => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            b[..8].copy_from_slice(&nanos.to_be_bytes());
            b[8..].copy_from_slice(&u64::from(std::process::id()).to_be_bytes());
        }
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// The target triple this build compiles for.
///
/// `--target` wins, because that is what the units will actually be built for. Without
/// one, the host triple is asked of the compiler itself — `rustc -vV` prints a `host:`
/// line — rather than assembled from `std::env::consts`, which has an OS and an
/// architecture and no idea whether this is `-gnu` or `-musl`. Guessing that distinction
/// is the whole reason this field exists: a capability difference between two libcs read
/// as capability drift is the noise the drift docs warn about.
fn target_triple(cargo_args: &[String]) -> Option<String> {
    if let Some(t) = flag_value(cargo_args, "--target") {
        return Some(t);
    }
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let out = std::process::Command::new(rustc).arg("-vV").output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(|t| t.trim().to_string())
}

/// `--flag value` or `--flag=value`, the two spellings cargo accepts.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
        if let Some(v) = a.strip_prefix(flag).and_then(|r| r.strip_prefix('=')) {
            return Some(v.to_string());
        }
    }
    None
}

/// The checkout this build ran in, read from `.git` directly.
///
/// Files rather than `git rev-parse`, for two reasons. A build host is one of the places
/// git may genuinely not be installed — the air-gapped image in `ROADMAP.md` is exactly
/// that shape — and spawning a process per build to learn a commit hash is a cost
/// incurred on every run for a field nobody blocks on.
fn repo_ref() -> Option<RepoRef> {
    let git = find_git_dir(&std::env::current_dir().ok()?)?;
    let head = std::fs::read_to_string(git.join("HEAD")).ok()?;
    let head = head.trim();

    let (reference, commit) = match head.strip_prefix("ref: ") {
        Some(r) => (Some(r.to_string()), resolve_ref(&git, r)),
        // A detached HEAD holds the object id directly. Common in CI: several providers
        // check out a commit rather than a branch, so this is the ordinary path there and
        // not an edge case.
        None if is_object_id(head) => (None, Some(head.to_string())),
        None => (None, None),
    };

    Some(RepoRef::record(origin_url(&git), commit, reference))
}

/// Walk up looking for `.git`, following a worktree's `gitdir:` pointer.
fn find_git_dir(start: &Path) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let candidate = dir.join(".git");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if candidate.is_file() {
            // A linked worktree or a submodule: `.git` is a file holding `gitdir: <path>`.
            let text = std::fs::read_to_string(&candidate).ok()?;
            let path = text.trim().strip_prefix("gitdir: ")?.trim();
            let p = PathBuf::from(path);
            return Some(if p.is_absolute() { p } else { dir.join(p) });
        }
    }
    None
}

/// Resolve `refs/heads/x` to an object id, loose file first and then `packed-refs`.
fn resolve_ref(git: &Path, reference: &str) -> Option<String> {
    if let Ok(text) = std::fs::read_to_string(git.join(reference)) {
        let t = text.trim().to_string();
        if is_object_id(&t) {
            return Some(t);
        }
    }
    // `git gc` packs refs away, so a repository that has been collected has no loose file
    // for a branch that has not moved since. A reader that only looked for the file would
    // report a null commit on exactly the repositories that have been around longest.
    let packed = std::fs::read_to_string(git.join("packed-refs")).ok()?;
    packed.lines().find_map(|line| {
        let (id, name) = line.split_once(' ')?;
        (name.trim() == reference && is_object_id(id)).then(|| id.to_string())
    })
}

/// Is this a SHA-1 or SHA-256 object id? Length is checked so a stray line cannot pass.
fn is_object_id(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// The `origin` remote's URL, out of `.git/config`.
///
/// A hand parser rather than a TOML one: git's config is INI-like but not TOML — section
/// headers carry a quoted subsection name, `[remote "origin"]`, which TOML reads as a
/// table called `remote` with a syntax error after it.
fn origin_url(git: &Path) -> Option<String> {
    let text = std::fs::read_to_string(git.join("config")).ok()?;
    let mut in_origin = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_origin = t.replace(' ', "") == "[remote\"origin\"]";
            continue;
        }
        if in_origin {
            if let Some((k, v)) = t.split_once('=') {
                if k.trim() == "url" {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// Who git thinks you are, for an exception's `author`.
///
/// # What this is, and what it is not
///
/// It is `user.email`, falling back to `user.name`, read the way git resolves it —
/// environment first, then the repository's own config, then the user's global one — and
/// it is **self-asserted**. Anyone who can write an exception can write any string here.
/// That is stated in the format's documentation rather than papered over, because the
/// thing that actually makes an exception accountable is that it is a committed block:
/// the commit has an author the forge verified, the block appeared in a diff, and it
/// stops working on its own.
///
/// So this exists to spare the person at 17:00 from typing their own address, not to
/// attest to anything. `None` means git has no identity configured here, and
/// `cargo buildclamp except` says so rather than writing "unknown" into a field whose
/// whole purpose is to name somebody.
///
/// Files rather than `git config --get`, for the same reason [`repo_ref`] reads files: a
/// build host is one of the places git may genuinely not be installed.
pub fn git_identity(start: &Path) -> Option<String> {
    // Git's own precedence, and the one CI actually sets.
    for var in [
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_EMAIL",
        "EMAIL",
        "GIT_AUTHOR_NAME",
    ] {
        if let Some(v) = non_empty(std::env::var(var).ok()) {
            return Some(v);
        }
    }
    let mut configs: Vec<PathBuf> = Vec::new();
    if let Some(git) = find_git_dir(start) {
        configs.push(git.join("config"));
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        configs.push(PathBuf::from(xdg).join("git/config"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        configs.push(PathBuf::from(&home).join(".gitconfig"));
        configs.push(PathBuf::from(home).join(".config/git/config"));
    }
    for path in configs {
        if let Some(who) = user_from_config(&path) {
            return Some(who);
        }
    }
    None
}

/// `user.email`, or `user.name` if that is all there is, out of one git config file.
fn user_from_config(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut in_user = false;
    let mut name = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_user = t.replace(' ', "") == "[user]";
            continue;
        }
        if !in_user {
            continue;
        }
        if let Some((k, v)) = t.split_once('=') {
            match k.trim() {
                // An address is what a reader can act on, so it wins outright.
                "email" => return non_empty(Some(v.trim().to_string())),
                "name" => name = non_empty(Some(v.trim().to_string())),
                _ => {}
            }
        }
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_prefers_an_address_and_falls_back_to_a_name() {
        let d = tempfile::tempdir().expect("a scratch directory");
        let both = d.path().join("both");
        std::fs::write(
            &both,
            "[core]\n\temail = not-this@example.com\n[user]\n\tname = Ada\n\temail = ada@example.com\n",
        )
        .unwrap();
        assert_eq!(user_from_config(&both).as_deref(), Some("ada@example.com"));

        let name_only = d.path().join("name-only");
        std::fs::write(&name_only, "[user]\n\tname = Ada Lovelace\n").unwrap();
        assert_eq!(
            user_from_config(&name_only).as_deref(),
            Some("Ada Lovelace")
        );

        // A `[user]` section that carries neither is not an identity, and an empty value
        // is not one either — writing `author = ""` would be refused by the policy parser
        // anyway, so producing it here would only move the error somewhere less useful.
        let neither = d.path().join("neither");
        std::fs::write(&neither, "[user]\n\tsigningkey = ABC\n\temail =\n").unwrap();
        assert_eq!(user_from_config(&neither), None);

        assert_eq!(user_from_config(&d.path().join("absent")), None);
    }

    #[test]
    fn a_run_id_has_the_shape_it_claims_and_two_of_them_differ() {
        let a = fresh_id();
        assert_eq!(a.len(), 36, "{a}");
        assert_eq!(a.as_bytes()[14], b'4', "version nibble: {a}");
        assert!(matches!(a.as_bytes()[19], b'8' | b'9' | b'a' | b'b'), "{a}");
        assert_ne!(a, fresh_id());
    }

    #[test]
    fn the_target_flag_wins_over_asking_the_compiler() {
        // Both spellings, because cargo accepts both and a cross build is the case this
        // field exists for.
        let split = vec!["--target".to_string(), "aarch64-unknown-linux-musl".into()];
        let joined = vec!["--target=aarch64-unknown-linux-musl".to_string()];
        for args in [split, joined] {
            assert_eq!(
                target_triple(&args).as_deref(),
                Some("aarch64-unknown-linux-musl")
            );
        }
    }

    #[test]
    fn an_empty_environment_variable_is_not_an_answer() {
        assert_eq!(non_empty(Some(String::new())), None);
        assert_eq!(non_empty(Some("  ".into())), None);
        assert_eq!(non_empty(Some("job-7".into())), Some("job-7".into()));
    }

    #[test]
    fn a_packed_ref_resolves_when_the_loose_file_has_been_collected() {
        // `git gc` packs refs away, so the repositories most likely to hit this path are
        // the oldest ones — exactly where a null commit would be least expected.
        let d = tempfile::tempdir().unwrap();
        let git = d.path();
        let id = "a".repeat(40);
        std::fs::write(
            git.join("packed-refs"),
            format!("# pack-refs\n{id} refs/heads/main\n"),
        )
        .unwrap();
        assert_eq!(resolve_ref(git, "refs/heads/main").as_deref(), Some(&*id));
        assert_eq!(resolve_ref(git, "refs/heads/other"), None);
    }

    #[test]
    fn the_origin_url_is_read_out_of_a_config_toml_cannot_parse() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("config"),
            "[core]\n\trepositoryformatversion = 0\n\
             [remote \"upstream\"]\n\turl = https://example.invalid/not-this.git\n\
             [remote \"origin\"]\n\turl = https://example.invalid/repo.git\n\tfetch = +refs\n",
        )
        .unwrap();
        assert_eq!(
            origin_url(d.path()).as_deref(),
            Some("https://example.invalid/repo.git")
        );
    }

    #[test]
    fn an_object_id_is_checked_by_length_as_well_as_by_alphabet() {
        assert!(is_object_id(&"0".repeat(40)));
        assert!(is_object_id(&"f".repeat(64)));
        assert!(!is_object_id("abc"));
        assert!(!is_object_id(&"g".repeat(40)));
    }

    #[test]
    fn a_worktree_pointer_file_is_followed_to_the_real_git_directory() {
        // A linked worktree and a submodule both have `.git` as a FILE. Treating one as
        // "no repository" would blank the run header on every worktree-based CI checkout.
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("realgit");
        std::fs::create_dir_all(&real).unwrap();
        let tree = d.path().join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join(".git"), format!("gitdir: {}\n", real.display())).unwrap();
        assert_eq!(find_git_dir(&tree), Some(real));
    }

    #[test]
    fn a_checkout_with_no_git_directory_is_a_run_with_no_repo_rather_than_an_error() {
        // The whole file's contract. A build in an unpacked tarball, a vendored tree or a
        // container with `.git` excluded is an ordinary build, and the header degrades to
        // nulls rather than failing it.
        let d = tempfile::tempdir().unwrap();
        let deep = d.path().join("a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        // Guarded: a temporary directory under a path that happens to sit inside a
        // checkout would make this test assert the opposite of what it says.
        if find_git_dir(d.path()).is_none() {
            assert_eq!(find_git_dir(&deep), None);
        }
    }
}
