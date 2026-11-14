//! The credential paths a build script is kept out of, and the honest shape of that list.
//!
//! # What this is, stated before what is in it
//!
//! It is a **deny-list**, and a deny-list is weaker than an allow-list. Everything not
//! named here stays readable by every build script: shell history, editor state, a
//! repository's own `.env`, a colleague's home directory on a shared box, the entire
//! source tree. The set names what is reliably credential-shaped across enough machines to
//! be worth denying by default — not everything that matters, and not everything an
//! attacker would want.
//!
//! An allow-list is the stronger design and is not available here. A build script legibly
//! needs to read the sysroot, the cargo registry, `/usr`, `/etc/ssl`, its own manifest
//! directory, `OUT_DIR`, and a long tail nobody can enumerate in advance — `cc` reads
//! compiler internals, `bindgen` reads system headers, `pkg-config` reads `.pc` files
//! wherever the distribution put them. Default-denying reads and granting back would break
//! every real graph on the first run, which is the failure mode `docs/adr/0001` is about.
//!
//! So: a named set, denied by default when the policy asks for it, with the residue
//! stated. The README carries the same sentence, because a reader who takes this for an
//! allow-list has been misled by us rather than by themselves.
//!
//! # Why these entries
//!
//! Each is a path whose *only* ordinary content is a credential, on a system where the
//! tool that owns it put it there. That test is what keeps the list short enough to be
//! defensible: `~/.ssh` is in and `~/Documents` is out, not because the second is
//! uninteresting but because denying it would break somebody's build script and teach them
//! to turn the feature off.
//!
//! The two 2026 incidents this project cites both read from paths on this list — one from
//! a cloud credential directory, one hunting keystores under a home directory — which is
//! the evidence for the shape rather than for any single entry.

use std::path::{Path, PathBuf};

/// A path withheld from build units, relative to a home directory or absolute.
///
/// `~/` is the only substitution, and it is done by the caller: this crate has no way to
/// read an environment and is not getting one. See [`expand`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Withheld {
    /// The path, with a leading `~/` meaning "beneath the unit's home directory".
    pub path: &'static str,
    /// What owns it, for the line a person reads when a build is refused.
    pub owner: &'static str,
}

const fn w(path: &'static str, owner: &'static str) -> Withheld {
    Withheld { path, owner }
}

/// The default withheld set.
///
/// Directories rather than files wherever the owning tool keeps a directory, because the
/// interesting file is rarely the only one: `~/.aws` holds `credentials` *and* `config`,
/// and a rule naming only the first leaves the account ids and role ARNs that make the
/// first useful.
pub const WITHHELD_READ_PATHS: &[Withheld] = &[
    // Cloud provider credentials. `~/.aws` is the path the June 2026 exfiltrator read.
    w("~/.aws", "AWS CLI"),
    w("~/.config/gcloud", "Google Cloud SDK"),
    w("~/.azure", "Azure CLI"),
    // Source control and registry tokens. A build script that can read these can publish
    // as you, which is how one compromised crate becomes several.
    w("~/.config/gh", "GitHub CLI"),
    w("~/.config/hub", "hub"),
    w("~/.cargo/credentials.toml", "cargo"),
    w("~/.cargo/credentials", "cargo (pre-1.39 spelling)"),
    w("~/.npmrc", "npm"),
    w("~/.netrc", "netrc, used by curl, git and cargo"),
    w("~/.git-credentials", "git credential store"),
    // Keys and agents.
    w("~/.ssh", "OpenSSH"),
    w("~/.gnupg", "GnuPG"),
    // Orchestration.
    w("~/.kube", "kubectl"),
    w(
        "~/.docker/config.json",
        "Docker, which stores registry auth here",
    ),
    // Browser profiles: saved passwords, session cookies and OAuth tokens, and the thing a
    // credential stealer reaches for after the files above.
    w("~/.mozilla", "Firefox"),
    w("~/.config/google-chrome", "Google Chrome"),
    w("~/.config/chromium", "Chromium"),
    w("~/.config/BraveSoftware", "Brave"),
    // Secret managers and password stores.
    w("~/.password-store", "pass"),
    w("~/.config/op", "1Password CLI"),
    w("~/.vault-token", "HashiCorp Vault"),
];

/// The withheld set with `~/` resolved against `home`.
///
/// `home` is a [`Path`], not a `&str`, and the join is native: a `HOME` whose bytes are not
/// valid Unicode is preserved exactly rather than passed through `to_string_lossy`, which
/// would replace the invalid bytes and point the withheld path at a *different* directory —
/// leaving the real credential files inside a granted region and readable.
///
/// Entries that are not under `~/` are returned as they are. Nothing is filtered on
/// whether the path exists: a directory that is absent **now** must still be excluded, or
/// creating `~/.aws` after a build starts would put it back inside a granted region. That
/// is the whole reason this returns names rather than a verified list.
pub fn expand(home: &Path) -> Vec<(PathBuf, &'static str)> {
    WITHHELD_READ_PATHS
        .iter()
        .map(|e| {
            let path = match e.path.strip_prefix("~/") {
                // `Path::join` is separator-aware, so a trailing slash on `home` produces no
                // doubled separator and a non-Unicode `home` keeps its bytes.
                Some(rest) => home.join(rest),
                None => PathBuf::from(e.path),
            };
            (path, e.owner)
        })
        .collect()
}

/// What this set does **not** cover, for the places that have to say so.
///
/// Kept next to the list rather than in a document, so that adding an entry and softening
/// the caveat are the same edit and a reviewer sees both.
pub const RESIDUAL_EXPOSURE: &str = "\
    This is a deny-list. Every path not named stays readable by every build script — shell \
    history, editor state, a repository's own .env file, the source tree itself, and any \
    credential a tool keeps somewhere this list does not know about. It narrows the \
    best-known credential locations; it does not make reads safe.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_home_relative_entry_resolves_and_an_absolute_one_does_not_move() {
        let got = expand(Path::new("/home/dev"));
        let paths: Vec<String> = got
            .iter()
            .map(|(p, _)| p.to_string_lossy().into_owned())
            .collect();
        assert!(paths.contains(&"/home/dev/.aws".to_string()));
        assert!(paths.contains(&"/home/dev/.cargo/credentials.toml".to_string()));
        assert!(paths.iter().all(|p| !p.contains('~')), "{paths:?}");
    }

    #[test]
    fn a_trailing_slash_on_home_does_not_produce_a_doubled_separator() {
        // `HOME=/root/` is legal and happens. `//root/.aws` would still resolve, and it
        // would not compare equal to the path anyone else prints.
        let got = expand(Path::new("/home/dev/"));
        assert!(
            got.iter()
                .any(|(p, _)| p.as_path() == Path::new("/home/dev/.aws")),
            "{got:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_non_unicode_home_is_preserved_byte_for_byte() {
        // The bug: `to_string_lossy()` replaced the invalid byte, so the withheld path named a
        // different directory and Landlock left the real credentials readable. A native join
        // keeps the bytes.
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let home_bytes = vec![b'/', b'h', 0xff, b'/', b'u'];
        let home = OsString::from_vec(home_bytes.clone());
        let got = expand(Path::new(&home));
        let aws = got
            .iter()
            .map(|(p, _)| p)
            .find(|p| p.as_os_str().as_bytes().ends_with(b"/.aws"))
            .expect("the ~/.aws entry");
        let mut expected = home_bytes;
        expected.extend_from_slice(b"/.aws");
        assert_eq!(aws.as_os_str().as_bytes(), expected.as_slice());
    }

    #[test]
    fn every_entry_names_what_owns_it() {
        // The owner is what makes the refusal line actionable: "read a path the policy
        // withholds" plus a path is a puzzle; plus "AWS CLI" is an answer.
        for e in WITHHELD_READ_PATHS {
            assert!(!e.owner.trim().is_empty(), "{} has no owner", e.path);
            assert!(
                e.path.starts_with("~/") || e.path.starts_with('/'),
                "{} is neither home-relative nor absolute",
                e.path
            );
        }
    }

    #[test]
    fn the_set_has_no_duplicates_and_no_entry_shadows_another() {
        // A path beneath another entry is dead weight, and worse, it reads as though
        // somebody checked. `~/.ssh/id_rsa` under `~/.ssh` would be exactly that.
        for (i, a) in WITHHELD_READ_PATHS.iter().enumerate() {
            for b in WITHHELD_READ_PATHS.iter().skip(i + 1) {
                assert_ne!(a.path, b.path, "duplicate entry {}", a.path);
                assert!(
                    !b.path.starts_with(&format!("{}/", a.path)),
                    "{} is already covered by {}",
                    b.path,
                    a.path
                );
            }
        }
    }

    #[test]
    fn the_residual_exposure_is_stated_as_a_deny_list() {
        // The one sentence this module exists to keep honest. If the list ever grows to
        // look comprehensive, this text is what stops the documentation from claiming it.
        assert!(RESIDUAL_EXPOSURE.contains("deny-list"));
        assert!(RESIDUAL_EXPOSURE.contains("does not make reads safe"));
    }
}
