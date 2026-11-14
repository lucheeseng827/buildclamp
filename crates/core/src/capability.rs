//! What a build unit may do, and what it was observed asking for.
//!
//! The capability set is deliberately small and closed. Every entry here is a thing a
//! real build script does — `cc` spawns a compiler, `bindgen` writes headers into
//! `OUT_DIR`, `openssl-sys` reads `OPENSSL_DIR`, a vendoring script fetches a tarball —
//! and a capability that no real build script needs is a capability we should not be
//! able to grant. An enum with five variants is auditable; a string-keyed permission
//! bag is not.
//!
//! The vocabulary rule from the design contract applies to every string in this file
//! that a user can see: a unit *requests* a capability, a policy *grants* it, and an
//! unmatched request is an **ungranted request** — never a violation, a breach or an
//! escape. The words are load-bearing because the tool's own positioning is that it is
//! not an accusation against dependencies.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The closed set of capabilities a build unit can be granted.
///
/// Ordering is the order they are reported in, chosen so the most consequential reads
/// first: reaching the network is how data leaves, and everything else is how it is
/// gathered.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Capability {
    /// Opening a socket or connecting to an address outside the machine.
    ///
    /// `AF_UNIX` is deliberately NOT this capability — see [`Capability::Unix`]. A
    /// build script talking to a local socket is doing something different from one
    /// talking to the internet, and collapsing them would make the common case
    /// (nothing) and the dangerous case (ssh-agent, the docker socket) indistinguishable.
    Net,
    /// Connecting to a unix-domain socket.
    ///
    /// Separated from [`Capability::Net`] because the interesting unix sockets on a
    /// developer's machine — the ssh agent, the docker daemon, a session keyring — are
    /// credential surfaces that no build script has a reason to touch, while the
    /// harmless ones (a local `nscd`) are invisible plumbing. v0 grants this by default
    /// because denying it breaks name resolution on some hosts, and says so.
    Unix,
    /// Reading a path the policy withholds.
    ///
    /// # This is the one capability that is a deny-list, and the docs must not blur it
    ///
    /// Every other capability here is "may the unit do this at all". This one is not.
    /// **Reads are allowed by default and stay allowed**: a build script reads the
    /// sysroot, the registry, `/usr`, its own manifest directory and a great deal else,
    /// and an allow-list over that is not a thing any real graph would survive. What this
    /// capability governs is a **named set of credential paths** — see
    /// [`crate::WITHHELD_READ_PATHS`] — which are withheld when the policy asks for it.
    ///
    /// So `fs-read` in a grant does not mean "may read files". It means "may also read the
    /// withheld ones", which is why a grant carrying it is worth a sentence in review.
    ///
    /// A deny-list is weaker than an allow-list and this project must never describe it as
    /// one. Everything not named remains readable, including plenty that is sensitive —
    /// shell history, editor state, a repository's own `.env`. The set names what is
    /// reliably credential-shaped, not everything that matters.
    FsRead,
    /// Writing anywhere on the filesystem.
    ///
    /// The zones a unit may write to are part of the envelope rather than part of the
    /// capability, so "may write" and "may write *here*" are one decision. See
    /// [`crate::envelope::WriteZone`].
    FsWrite,
    /// Reading a name from the environment that the policy classifies as a secret.
    ///
    /// This capability is unusual and the docs must not overstate it. There is no
    /// syscall for `getenv`, so a read cannot be observed; what the tool controls is
    /// **exposure** — whether the name is present in the unit's environment at all.
    /// Observe mode therefore reports which secret-shaped names *were reachable*, not
    /// which were read.
    EnvSecret,
    /// Executing another program.
    ///
    /// Granted by default, because `cc`, `pkg-config`, `protoc` and `git` are the
    /// ordinary business of build scripts. It is recorded on every unit regardless, so
    /// a build script that spawns `curl` is visible in the capability record even when
    /// nothing denied it.
    Exec,
}

impl Capability {
    /// Every capability, in report order.
    pub const ALL: [Capability; 6] = [
        Capability::Net,
        Capability::Unix,
        Capability::FsWrite,
        Capability::FsRead,
        Capability::EnvSecret,
        Capability::Exec,
    ];

    /// The policy-file key for this capability.
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Net => "net",
            Capability::Unix => "unix",
            Capability::FsRead => "fs-read",
            Capability::FsWrite => "fs-write",
            Capability::EnvSecret => "env-secret",
            Capability::Exec => "exec",
        }
    }

    /// Is this a capability buildclamp records but never refuses?
    ///
    /// Exactly one: [`Capability::Exec`]. A build script legitimately spawns `cc`,
    /// `pkg-config` and `git`, a spawned process inherits every namespace and the seccomp
    /// filter, and the sandbox's decider allows every exec by construction (its
    /// `_ => Decision::Allow` arm). So exec is *observed* — recorded on every unit so a
    /// build that shells out to something surprising is visible — and never denied.
    ///
    /// It matters for the enforcement floor. `--require-enforced` and a `doctor --require`
    /// floor ask "could this host refuse each capability atomically?", and the answer for
    /// an observe-only capability is "buildclamp does not refuse it on any host, by
    /// design." Counting it would make the floor unsatisfiable everywhere — an exec tier is
    /// advisory on every host that can record at all and `none` on the rest, never
    /// enforced — which is why the floor skips it rather than failing forever. See
    /// `Report::exit_code` and `Floor::unmet`.
    pub fn is_observe_only(self) -> bool {
        matches!(self, Capability::Exec)
    }

    /// One line a person can act on, used in `explain` output and in the single stderr
    /// line cargo shows when a unit is refused.
    pub fn describe(self) -> &'static str {
        match self {
            Capability::Net => "reach the network",
            Capability::Unix => "connect to a unix socket",
            Capability::FsRead => "read a path the policy withholds",
            Capability::FsWrite => "write outside its allowed zones",
            Capability::EnvSecret => "read a secret from the environment",
            Capability::Exec => "run another program",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Capability {
    type Err = UnknownCapability;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "net" => Ok(Capability::Net),
            "unix" => Ok(Capability::Unix),
            // `fs_write` is accepted alongside `fs-write` because TOML keys in this
            // ecosystem are written both ways and a policy that fails to parse over a
            // hyphen teaches nothing.
            "fs-write" | "fs_write" => Ok(Capability::FsWrite),
            "fs-read" | "fs_read" => Ok(Capability::FsRead),
            "env-secret" | "env_secret" => Ok(Capability::EnvSecret),
            "exec" => Ok(Capability::Exec),
            other => Err(UnknownCapability(other.to_string())),
        }
    }
}

/// A capability name that is not in the closed set.
#[derive(Debug, thiserror::Error)]
#[error(
    "unknown capability `{0}` — buildclamp understands net, unix, fs-write, fs-read, \
     env-secret and exec"
)]
pub struct UnknownCapability(pub String);

/// A set of capabilities, held as a bitmask so an envelope is `Copy` and comparing two
/// of them (which is what capability-drift detection does across versions) is one
/// integer comparison rather than a set walk.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilitySet(u8);

impl CapabilitySet {
    /// The empty set: the default envelope for a build unit with no grant.
    pub const EMPTY: CapabilitySet = CapabilitySet(0);

    fn bit(c: Capability) -> u8 {
        1 << (c as u8)
    }

    /// A set containing exactly the given capabilities.
    pub fn of(caps: &[Capability]) -> Self {
        let mut s = Self::EMPTY;
        for c in caps {
            s.insert(*c);
        }
        s
    }

    pub fn insert(&mut self, c: Capability) {
        self.0 |= Self::bit(c);
    }

    pub fn remove(&mut self, c: Capability) {
        self.0 &= !Self::bit(c);
    }

    pub fn contains(self, c: Capability) -> bool {
        self.0 & Self::bit(c) != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Capabilities in `self` that are absent from `other`.
    ///
    /// This is the drift primitive: `new.added_over(old)` is what a dependency bump
    /// gained. A build script that gained `net` between two patch releases is an
    /// early-warning signal in its own right, and it is one instruction.
    pub fn added_over(self, other: CapabilitySet) -> CapabilitySet {
        CapabilitySet(self.0 & !other.0)
    }

    pub fn iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .into_iter()
            .filter(move |c| self.contains(*c))
    }

    /// The raw bitmask, for telemetry envelopes built on this report.
    ///
    /// Exposed deliberately: a reader can see the exact bytes such an envelope would
    /// carry, and "a five-bit integer per (crate, version)" is a claim they can check
    /// in one line of Apache-2.0 source.
    pub fn bits(self) -> u8 {
        self.0
    }
}

impl fmt::Debug for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapabilitySet(")?;
        let mut first = true;
        for c in self.iter() {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            f.write_str(c.as_str())?;
        }
        f.write_str(")")
    }
}

impl fmt::Display for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("nothing");
        }
        let names: Vec<&str> = self.iter().map(Capability::as_str).collect();
        f.write_str(&names.join(", "))
    }
}

impl Serialize for CapabilitySet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // A list of names, not the integer. The report is read by people and diffed by
        // review tools; a bitmask in JSON would be unreadable in both.
        let names: Vec<Capability> = self.iter().collect();
        names.serialize(s)
    }
}

impl<'de> Deserialize<'de> for CapabilitySet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let names = Vec::<Capability>::deserialize(d)?;
        Ok(CapabilitySet::of(&names))
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<T: IntoIterator<Item = Capability>>(iter: T) -> Self {
        let mut s = CapabilitySet::EMPTY;
        for c in iter {
            s.insert(c);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_set_displays_as_nothing_not_as_an_empty_string() {
        // The report prints "requested: nothing"; an empty string there reads as a bug
        // in the tool rather than as a clean unit.
        assert_eq!(CapabilitySet::EMPTY.to_string(), "nothing");
    }

    #[test]
    fn drift_reports_only_what_was_gained() {
        let old = CapabilitySet::of(&[Capability::Exec, Capability::FsWrite]);
        let new = CapabilitySet::of(&[Capability::Exec, Capability::FsWrite, Capability::Net]);
        assert_eq!(new.added_over(old), CapabilitySet::of(&[Capability::Net]));
        // A capability that was dropped is not drift in the direction anyone alerts on.
        assert!(old.added_over(new).is_empty());
    }

    #[test]
    fn a_set_round_trips_through_json_as_names() {
        let s = CapabilitySet::of(&[Capability::Net, Capability::Exec]);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"["net","exec"]"#);
        assert_eq!(serde_json::from_str::<CapabilitySet>(&json).unwrap(), s);
    }

    #[test]
    fn capability_names_survive_both_spellings() {
        use std::str::FromStr;
        assert_eq!(
            Capability::from_str("fs-write").unwrap(),
            Capability::FsWrite
        );
        assert_eq!(
            Capability::from_str("fs_write").unwrap(),
            Capability::FsWrite
        );
        assert!(Capability::from_str("network").is_err());
    }

    #[test]
    fn iteration_is_in_report_order_regardless_of_insertion_order() {
        let a = CapabilitySet::of(&[Capability::Exec, Capability::Net]);
        let b = CapabilitySet::of(&[Capability::Net, Capability::Exec]);
        assert_eq!(a, b);
        let order: Vec<_> = a.iter().collect();
        assert_eq!(order, vec![Capability::Net, Capability::Exec]);
    }
}
