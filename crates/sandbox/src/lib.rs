//! `buildclamp-sandbox` — making a kernel enforce a capability envelope.
//!
//! This crate is handed a command and an envelope and knows nothing about cargo. Every
//! `unsafe` block in the project lives here; every other crate is
//! `#![forbid(unsafe_code)]`.
//!
//! # The property that distinguishes this from the alternatives
//!
//! **A missing mechanism can never result in an unheld run that reports success.**
//!
//! That sounds like a truism and it is not. The nearest existing tool, `cargo-acl`,
//! sandboxes build scripts with bubblewrap, and when `bwrap` is not on `PATH` it prints a
//! notice and **continues unsandboxed**. In a minimal CI container that is a security
//! control reporting success while enforcing nothing, and a passing build says nothing
//! about it.
//!
//! So this crate has no external dependency to be missing, and the type system carries
//! the honesty requirement: [`Held`] reports a [`Tier`] per capability, `Tier::Advisory`
//! carries the sentence explaining why it is not enforcement, and [`Plan::hold`] returns
//! an error rather than running a command it could not constrain.
//!
//! # The tier ladder
//!
//! | capability | preferred | fallback | last resort |
//! |---|---|---|---|
//! | network | empty network namespace | seccomp `EPERM` on `socket(AF_INET…)` | none |
//! | filesystem | Landlock | read-only root in a mount namespace | seccomp notification (**advisory**) |
//! | other processes | user namespace (a child userns fails `ptrace_may_access` against the parent's, so `/proc/<pid>/environ` is `EPERM`) | — | none |
//!
//! Every rung is **probed at runtime**, never inferred from a kernel version — see
//! [`probe`]. This project's own host has no Landlock at all, which is how the fallback
//! path came to be tested rather than assumed.
//!
//! # Portability
//!
//! The crate compiles everywhere. On a non-Linux target [`probe::host`] reports every
//! mechanism absent and [`Plan::hold`] refuses, so `cargo check` works on a Mac while the
//! honest answer about enforcement stays "not on this host".

#![warn(missing_debug_implementations)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use buildclamp_core::{Capability, Forward, Tier};

pub mod probe;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use crate::linux::bpf;
/// The reference interpreter and the property it holds the filter to.
///
/// Public because the fuzz targets under `fuzz/` are a separate crate and call it, and
/// because a customer auditing the filter can execute it here rather than read the
/// offsets. See the module docs for what a differential of this shape can and cannot
/// catch.
pub use crate::linux::bpfcheck;

/// What one held unit is allowed to do, in terms this crate understands.
///
/// Deliberately *not* `buildclamp_core::Envelope`: that type is about policy — zones,
/// grants, justifications — and this crate must not know what a grant is. The translation
/// lives in `buildclamp-shim`, which is the only crate that knows both.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    /// May the unit reach the network?
    pub allow_net: bool,
    /// May it connect to unix sockets?
    ///
    /// Separate from `allow_net` because the interesting unix sockets on a developer's
    /// machine — the ssh agent, the docker daemon, a session keyring — are credential
    /// surfaces, while the harmless ones are invisible plumbing.
    pub allow_unix: bool,
    /// Directories it may write to. Everything else is read-only.
    pub writable: Vec<PathBuf>,
    /// Paths the unit may not READ, withheld by the policy.
    ///
    /// Empty means reads are unrestricted, which is the default and the behaviour every
    /// version of this tool has had: the read bits are then not handled by the ruleset at
    /// all, so the kernel restricts nothing and the run pays nothing. See
    /// `crates/core/src/withhold.rs` for what goes in here and, more importantly, for what
    /// deliberately does not — this is a deny-list and the documentation must not let it
    /// be read as an allow-list.
    pub withheld_reads: Vec<PathBuf>,
    /// The only directories the unit may read beneath, besides the ones it may write.
    ///
    /// Empty — the default — means no read allowlist: reads are restricted only by
    /// `withheld_reads`, or not at all. Non-empty means everything else is unreadable on a
    /// Landlock host, and `withheld_reads` still applies inside these roots.
    pub read_allowed: Vec<PathBuf>,
    /// A private directory to expose as `TMPDIR`.
    pub private_tmp: Option<PathBuf>,
    /// The environment the unit will see. Already scrubbed by the caller: this crate does
    /// not decide what a secret is.
    ///
    /// Names and values are `OsString`, not `String`, so a variable whose name or value is
    /// not valid Unicode is passed through to the child verbatim rather than crashing the
    /// scrub (`std::env::vars` panics on exactly those; the caller reads `vars_os`).
    pub env: Vec<(OsString, OsString)>,
    /// Record every write, not just those outside the writable set.
    ///
    /// Off by default because rustc opens thousands of files and each notified syscall
    /// costs 10–40 µs — measured. `observe --deep` turns it on.
    pub observe_writes: bool,
    /// Record nothing and refuse nothing; only watch. Used by observe mode.
    pub observe_only: bool,
    /// Proc-macro shared objects this build produced, for attribution.
    pub proc_macro_objects: Vec<(PathBuf, buildclamp_core::UnitId)>,
    /// One `execve` target to leave out of the record.
    ///
    /// The launcher's own `exec` of the real build script is notified like any other, and
    /// recording it would put buildclamp's own action at the top of every unit's list of
    /// what that unit did. Naming the exact path rather than skipping the first `execve`
    /// blindly means a build script that genuinely re-executes that same binary is still
    /// recorded on its second attempt.
    pub skip_exec_target: Option<PathBuf>,
    /// Refuse every `execve` except the one that starts the held command itself.
    ///
    /// `false` by default, so `Plan { allow_net: true, ..Default::default() }` keeps the
    /// behaviour it always had: exec is not restricted.
    pub deny_exec: bool,
    /// Directories beneath which nothing may be executed.
    ///
    /// Write xor execute: a caller that passes its writable zones here stops a unit from
    /// writing a program and then running it. It does not stop `sh written.sh`, because an
    /// interpreter reading a script is a read, not an exec. Empty by default, which
    /// restricts nothing.
    pub no_exec: Vec<PathBuf>,
    /// Directories inside `no_exec` that may be executed from anyway: the zones a grant
    /// named in `exec-zones`, for the crates that build a program and then run it.
    pub exec_allowed: Vec<PathBuf>,
    /// Directories inside `no_exec` whose files may still be *mapped* executable, though not
    /// `execve`d: where rustc loads proc-macro shared objects from. They are left off the
    /// `noexec` mount, which would refuse the load; Landlock's EXECUTE rule, which governs
    /// `execve` only, still applies to them.
    pub load_allowed: Vec<PathBuf>,
    /// The only addresses the unit may connect to, when it may not have the network.
    ///
    /// Empty — the default — means `allow_net` decides alone. Non-empty, with `allow_net`
    /// false, the unit stays in an empty network namespace and the supervisor makes each
    /// allowed TCP connection itself and hands the unit the connected socket; anything else
    /// is refused. Resolved by the caller: this crate does not do DNS.
    pub net_allowed: Vec<std::net::SocketAddr>,
    /// The contents of a hosts file to mount over `/etc/hosts`, so the names behind
    /// `net_allowed` resolve inside a namespace that has no route to a resolver. Contents,
    /// not a path: the file is made here as an unnamed temporary, so no other unit can swap,
    /// rewrite or read it before it is mounted.
    pub hosts: Option<String>,
}

impl Plan {
    /// The rule the supervisor applies to each request.
    ///
    /// Built from the plan rather than passed in, so there is exactly one place where a
    /// capability turns into an allow or a refusal and no caller can supply a laxer one.
    #[cfg(target_os = "linux")]
    pub(crate) fn decider(
        &self,
        program: Option<PathBuf>,
        net_allowed: Vec<std::net::SocketAddr>,
    ) -> Box<dyn crate::linux::seccomp::Decider> {
        Box::new(PlanDecider {
            allow_net: self.allow_net,
            allow_unix: self.allow_unix,
            observe_only: self.observe_only,
            writable: self.writable.clone(),
            deny_exec: self.deny_exec,
            no_exec: self.no_exec.clone(),
            exec_allowed: self.exec_allowed.clone(),
            program,
            net_allowed,
        })
    }

    /// Does this plan restrict exec at all?
    pub(crate) fn restricts_exec(&self) -> bool {
        self.deny_exec || !self.no_exec.is_empty()
    }
}

/// The supervisor's rule, as a value the supervisor thread can own.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct PlanDecider {
    allow_net: bool,
    allow_unix: bool,
    observe_only: bool,
    writable: Vec<PathBuf>,
    deny_exec: bool,
    no_exec: Vec<PathBuf>,
    exec_allowed: Vec<PathBuf>,
    /// Addresses whose connect the supervisor performs itself. Empty unless the unit is in
    /// an empty network namespace: without one an unconnected UDP send is invisible to the
    /// supervisor, so allowing sockets at all would allow the network.
    net_allowed: Vec<std::net::SocketAddr>,
    /// The held command's own program, which every exec rule allows: refusing it would
    /// refuse the unit, not something the unit did.
    program: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
impl crate::linux::seccomp::Decider for PlanDecider {
    fn destination_mode(&self) -> bool {
        // `net_allowed` is non-empty only in destination mode, or in observe mode for a unit
        // whose grant lists destinations — where the unit is on the real network but
        // nothing is refused, so the datagram exception only changes what is recorded.
        !self.net_allowed.is_empty()
    }

    fn decide(&self, cap: Capability, target: &str) -> crate::linux::seccomp::Decision {
        use crate::linux::seccomp::Decision;
        let verdict = match cap {
            // A destination list: creating an inet socket reaches nothing in an empty
            // namespace, a connect to a listed address is made by the supervisor, and
            // every other connect is refused.
            Capability::Net if !self.allow_net && !self.net_allowed.is_empty() => {
                // Families the empty namespace contains: inet, and netlink, which glibc's
                // getaddrinfo opens to see which families exist (here, only `lo`). Packet
                // sockets, vsock — not namespaced at all — and anything unknown stay refused.
                if matches!(
                    target,
                    "AF_INET socket" | "AF_INET6 socket" | "AF_NETLINK socket"
                ) {
                    Decision::Allow
                } else {
                    match target.parse::<std::net::SocketAddr>() {
                        Ok(a) if self.net_allowed.contains(&a) => Decision::Proxy(a),
                        _ => Decision::Deny(libc::EPERM),
                    }
                }
            }
            Capability::Net if !self.allow_net => Decision::Deny(libc::EPERM),
            Capability::Unix if !self.allow_unix => Decision::Deny(libc::EPERM),
            Capability::FsWrite => {
                if self.writable.iter().any(|w| path_is_within(target, w))
                    || ALWAYS_WRITABLE
                        .iter()
                        .any(|w| path_is_within(target, std::path::Path::new(w)))
                {
                    Decision::Allow
                } else {
                    Decision::Deny(libc::EACCES)
                }
            }
            // A refusal here is authoritative — the syscall never runs — but an Allow is not:
            // the kernel re-reads the path after we answer, so a unit could show us an
            // allowed path and exec another. Landlock's EXECUTE right is what closes that,
            // and the tier is only `enforced` where it applied. This answer is what puts the
            // refusal in the report.
            Capability::Exec => {
                let is_program = self
                    .program
                    .as_deref()
                    .is_some_and(|p| p.as_os_str() == target);
                if is_program {
                    Decision::Allow
                } else if self.deny_exec
                    || (self.no_exec.iter().any(|d| path_is_within(target, d))
                        && !self.exec_allowed.iter().any(|d| path_is_within(target, d)))
                {
                    Decision::Deny(libc::EACCES)
                } else {
                    Decision::Allow
                }
            }
            _ => Decision::Allow,
        };

        // Observe mode refuses nothing, ever — its whole purpose is to record what a build
        // does without being the reason it broke — but it must still say what enforcement
        // WOULD have done. Recording everything as granted would make `init` generate no
        // grants at all and tell the operator their build is clean.
        if self.observe_only {
            return match verdict {
                Decision::Deny(_) => Decision::AllowButWouldRefuse,
                // Observe runs on the real network with no namespace: the unit's own
                // connect is what should happen, recorded as granted.
                Decision::Proxy(_) => Decision::Allow,
                other => other,
            };
        }
        verdict
    }
}

/// Writable to every unit, on top of whatever the policy granted.
///
/// `/dev/null` is here because a build script writing to it is not a policy question.
/// Every `configure`-shaped probe redirects there, `cc` does it constantly, and a shell's
/// `2>/dev/null` fails the whole command when the redirect is refused — so denying it does
/// not narrow what a build can reach, it stops builds. The rest of the list is the same
/// argument applied to the handful of neighbours that behave identically.
///
/// **This was a live bug on any host without user namespaces, and it predates the Landlock
/// tier.** The mount-namespace rung gives the unit a `/dev` that stays writable and never
/// consults this list, so the gap only appeared where the seccomp write supervisor is the
/// filesystem tier — `!use_ns`, which is exactly the advisory-tier host this decider
/// exists to serve. It surfaced from a Landlock test that sets `BUILDCLAMP_DISABLE=ns` to
/// isolate its own rung and spent four CI rounds looking like a Landlock fault, because
/// the two layers had different ideas about `/dev` and the seccomp one answered first.
///
/// **Endpoints, not the directory.** The first version of this constant was `["/dev"]`,
/// and that was too much: `path_is_within` is a prefix test, so it also admitted
/// `/dev/shm`, `/dev/mqueue` and `/dev/pts`, which are mode-1777 and writable by an
/// unprivileged unit. A held build could create host shared-memory files outside every
/// zone in `Plan::writable` — a durable side effect and a channel to any other process on
/// the box, which is exactly the class of thing the write boundary exists to stop. DAC
/// rescues the root-owned device nodes; it does not rescue those three, so the list has to
/// name what it means.
///
/// What is here is character devices with no persistence and no cross-process channel —
/// writing to them cannot outlive the build or be read by anything else — plus the
/// `/proc/self/fd` aliases, which can only ever name a descriptor the unit already holds.
/// What is deliberately absent is every writable subtree of `/dev`. A build that genuinely
/// needs `/dev/shm` asks for it with a grant, and until it does the report names it as an
/// ungranted request instead of passing it in silence.
///
/// `linux::landlock` grants the same entries for the same reason and reads from this same
/// constant, so the two rungs cannot come to disagree — they did once, and it cost four CI
/// rounds because the seccomp layer answers first.
pub(crate) const ALWAYS_WRITABLE: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    // Symlinks into `/proc/self/fd`. A write through one of these goes to a descriptor the
    // unit was already given, so admitting them adds nothing it could not already do.
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/fd",
];

/// Is `target` inside `dir`?
///
/// A prefix comparison on components rather than on the string, so `/tmp/outdir-evil`
/// does not count as being inside `/tmp/outdir`. That off-by-one is the whole difference
/// between a write policy and a suggestion.
#[cfg(target_os = "linux")]
fn path_is_within(target: &str, dir: &std::path::Path) -> bool {
    let t = std::path::Path::new(target);
    if !t.is_absolute() {
        // A relative path is resolved by the kernel against a cwd the supervisor cannot
        // see atomically. Refusing is the safe answer, and the tier already says this
        // decision is advisory.
        return false;
    }
    t.components().count() >= dir.components().count()
        && t.components().zip(dir.components()).all(|(a, b)| a == b)
}

/// The tiers an enforcing run would reach on a host with these capabilities.
///
/// Computed from the probe results by the **same function** that labels a real run, with
/// the default envelope — nothing granted, so every capability is one enforcement is
/// supposed to hold. Sharing the function is the point: two readings of the ladder, one in
/// `doctor` and one in the report, would drift apart and the drift would be invisible
/// until somebody compared a prediction with an outcome.
///
/// # What it is not
///
/// It is a **projection, and an upper bound on one capability**. `landlock_abi` is what
/// the kernel says it supports; building the ruleset can still fail with `EPERM` under a
/// restrictive container runtime, and a real run then falls back to the mount namespace
/// and says so in the report. Everything else here is measured rather than reported —
/// `user_namespaces` runs the whole child setup in a fork, seccomp notification is tried —
/// so the only way this overstates a host is by naming Landlock where a ruleset would be
/// refused, and the fallback rung it lands on is itself enforced.
///
/// The report is the authority on what happened. This answers a different question, before
/// anything has happened: can this lane enforce at all?
#[cfg(target_os = "linux")]
pub fn projected_tiers(
    host: &buildclamp_core::HostCapabilities,
) -> BTreeMap<Forward<Capability>, Tier> {
    // `BUILDCLAMP_DISABLE` is read here as well as in `hold`, and it has to be. The probe
    // asks the kernel, and the switch is an operator taking a mechanism away afterwards —
    // so without this a lane with `BUILDCLAMP_DISABLE=ns` in its environment would be told
    // it reaches `enforced:netns` and would then run every unit at the fallback rung. A
    // projection that ignored the switch would be reassuring exactly where somebody had
    // turned enforcement off, which is the one case the report's `disable_overrides` field
    // exists to make impossible to miss.
    let off = crate::linux::Disabled::from_env();
    crate::linux::plan_tiers(
        // The default envelope's shape for exec: allowed, but never from a writable
        // directory. Projecting deny-all instead skipped the `mountns-noexec` rung, so on a
        // host with user namespaces but no Landlock `doctor` said advisory while every real
        // build was enforced. The path only has to be non-empty; nothing is mounted.
        &Plan {
            no_exec: vec![PathBuf::from("/")],
            ..Plan::default()
        },
        host.user_namespaces && !off.ns,
        host.seccomp_user_notif && !off.notify,
        host.landlock_abi.map(|abi| format!("landlock-v{abi}")),
        // A build script never lives in a zone it can write; the projection is the default.
        false,
        // The default envelope has no destination list.
        false,
    )
}

/// On a host this crate cannot enforce on at all, nothing is projected.
///
/// An empty map is not "no requirements met by default": `Floor::unmet` reads a missing
/// tier as `none`, so every requirement in a declared floor fails here — which is the
/// correct answer for a platform with no enforcement.
#[cfg(not(target_os = "linux"))]
pub fn projected_tiers(
    _host: &buildclamp_core::HostCapabilities,
) -> BTreeMap<Forward<Capability>, Tier> {
    BTreeMap::new()
}

/// The outcome of holding one command.
#[derive(Clone, Debug)]
pub struct Held {
    /// What actually constrained each capability, on this host, for this unit.
    ///
    /// One tier per capability, and **every** capability: a capability missing from this
    /// map is an outcome recorded without saying how it was constrained, which is the one
    /// thing the report schema exists to make impossible.
    pub tiers: BTreeMap<Forward<Capability>, Tier>,
    /// Everything the unit asked for.
    pub requests: Vec<buildclamp_core::Request>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub duration_ms: u64,
}

/// Why a unit could not be held.
///
/// Every variant is a refusal to run rather than a reason to run unheld. That is the
/// point of the crate; see the module docs.
#[derive(Debug, thiserror::Error)]
pub enum HoldError {
    #[error(
        "buildclamp cannot enforce anything on this host ({0}). Refusing to run the build \
         unit rather than run it unheld and report success — use `--observe` if you want \
         to record without enforcing, or `cargo buildclamp doctor` to see what is missing."
    )]
    NothingAvailable(String),

    #[error("setting up the sandbox for this build unit failed: {0}")]
    Setup(String),

    #[error("could not start the build unit: {0}")]
    Spawn(#[source] std::io::Error),

    #[error(
        "buildclamp has no enforcement for {0}. Only Linux is supported in this version, \
         and running unheld while reporting success is not something buildclamp will do."
    )]
    UnsupportedPlatform(String),
}

impl Plan {
    /// Run `command` under this plan and supervise it.
    ///
    /// The command is executed to completion. On success the caller gets what actually
    /// constrained each capability and everything the unit asked for.
    #[cfg(target_os = "linux")]
    pub fn hold(&self, command: std::process::Command) -> Result<Held, HoldError> {
        crate::linux::hold(self, command)
    }

    /// The non-Linux stub. Refuses, and says why, rather than running unheld.
    #[cfg(not(target_os = "linux"))]
    pub fn hold(&self, _command: std::process::Command) -> Result<Held, HoldError> {
        Err(HoldError::UnsupportedPlatform(
            std::env::consts::OS.to_string(),
        ))
    }
}

/// A `Tier::None` with a reason, for the many places one is produced.
pub(crate) fn none(reason: impl Into<String>) -> Tier {
    Tier::None {
        reason: reason.into(),
    }
}

/// A `Tier::Enforced` naming its mechanism.
pub(crate) fn enforced(mechanism: impl Into<String>) -> Tier {
    Tier::Enforced {
        mechanism: mechanism.into(),
    }
}

/// A `Tier::Advisory` naming its mechanism and stating why it is not enforcement.
///
/// There is no way to construct an advisory tier without that sentence, because the
/// sentence is the whole point: a report that said "advisory" without saying what a
/// determined script could do about it would be as misleading as saying "enforced".
pub(crate) fn advisory(mechanism: impl Into<String>, limitation: impl Into<String>) -> Tier {
    Tier::Advisory {
        mechanism: mechanism.into(),
        limitation: limitation.into(),
    }
}

/// The sentence that goes on every seccomp-notification tier.
pub(crate) const NOTIFY_LIMITATION: &str =
    "the supervisor reads the path or address out of the unit's memory and then answers; \
     for an allowed call the kernel re-reads the argument afterwards, so a determined \
     unit could change it in between";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_advisory_tier_cannot_exist_without_stating_its_limitation() {
        // Encoded in the constructor rather than in review: a report saying "advisory"
        // without saying what a determined unit could do about it misleads as badly as
        // one saying "enforced".
        let t = advisory("seccomp-notify", NOTIFY_LIMITATION);
        match t {
            Tier::Advisory { limitation, .. } => assert!(limitation.contains("re-reads")),
            other => panic!("expected an advisory tier, got {other:?}"),
        }
    }

    #[test]
    fn a_plan_that_grants_nothing_is_the_default() {
        // The default must be the safe one: a Plan built with `..Default::default()` in a
        // future caller must not accidentally grant the network.
        let p = Plan::default();
        assert!(!p.allow_net);
        assert!(!p.allow_unix);
        assert!(p.writable.is_empty());
        assert!(!p.observe_writes);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_non_linux_host_refuses_rather_than_running_unheld() {
        let err = Plan::default()
            .hold(std::process::Command::new("/bin/true"))
            .unwrap_err();
        assert!(matches!(err, HoldError::UnsupportedPlatform(_)));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod always_writable_tests {
    use super::*;
    use crate::linux::seccomp::{Decider, Decision};

    fn decider(writable: &[&str]) -> PlanDecider {
        PlanDecider {
            allow_net: false,
            allow_unix: true,
            observe_only: false,
            writable: writable.iter().map(PathBuf::from).collect(),
            deny_exec: false,
            no_exec: Vec::new(),
            exec_allowed: Vec::new(),
            program: None,
            net_allowed: Vec::new(),
        }
    }

    #[test]
    fn a_destination_list_lets_only_inet_sockets_be_created() {
        // vsock is not network-namespaced at all and packet sockets reach raw frames; the
        // list must not open them. Netlink is namespaced and glibc needs it to resolve.
        let mut d = decider(&["/tmp/out"]);
        d.net_allowed = vec!["127.0.0.1:443".parse().unwrap()];
        for ok in ["AF_INET socket", "AF_INET6 socket", "AF_NETLINK socket"] {
            assert!(
                matches!(d.decide(Capability::Net, ok), Decision::Allow),
                "{ok}"
            );
        }
        for refused in ["AF_PACKET socket", "unknown-family socket"] {
            assert!(
                matches!(d.decide(Capability::Net, refused), Decision::Deny(_)),
                "{refused}"
            );
        }
    }

    #[test]
    fn a_unit_may_always_write_to_dev_null() {
        // The regression this constant exists for. Without it the seccomp write supervisor
        // — the filesystem tier on every host with no user namespaces — denied /dev/null,
        // so every `2>/dev/null` in a build script failed its whole command. That is not a
        // narrower sandbox, it is a broken build, and it shipped for as long as the
        // advisory tier has existed.
        let d = decider(&["/tmp/out"]);
        assert!(matches!(
            d.decide(Capability::FsWrite, "/dev/null"),
            Decision::Allow
        ));
        assert!(matches!(
            d.decide(Capability::FsWrite, "/dev/stderr"),
            Decision::Allow
        ));
    }

    #[test]
    fn the_writable_subtrees_of_dev_are_not_always_writable() {
        // The bug in the first version of the constant, kept as a test because the fix is
        // one character away from being undone: `ALWAYS_WRITABLE` was `["/dev"]`, and
        // `path_is_within` is a prefix test, so it admitted every one of these.
        //
        // These three are the ones that matter, and DAC does not cover for them the way it
        // covers for a root-owned device node — they are mode 1777, so an unprivileged
        // unit really can create files there. A write to /dev/shm outlives the build and
        // any other process on the host can read it, which makes it both a durable side
        // effect outside `Plan::writable` and a channel between two units that the report
        // would have shown as fully enforced.
        let d = decider(&["/tmp/out"]);
        for target in [
            "/dev/shm/leaked",
            "/dev/shm/.hidden/payload",
            "/dev/mqueue/channel",
            "/dev/pts/3",
            // Not a subtree, but the same mistake: `/dev` itself is not an endpoint, so
            // creating a node directly in it is a policy question like any other.
            "/dev/newnode",
        ] {
            assert!(
                matches!(d.decide(Capability::FsWrite, target), Decision::Deny(_)),
                "{target} is outside every write zone and must not be admitted by the \
                 /dev allowance"
            );
        }
    }

    #[test]
    fn the_always_writable_list_does_not_open_anything_else() {
        // It is an exception, not a hole. A path that merely starts with the same letters
        // as an entry must not slip through, and neither must anything outside the list.
        let d = decider(&["/tmp/out"]);
        for target in [
            "/etc/passwd",
            "/home/ci/.ssh/authorized_keys",
            "/devious/file",
            "/tmp/elsewhere",
            // The prefix trap in its narrowest form: one entry is `/dev/null`, and this
            // shares every character of it.
            "/dev/nullify",
        ] {
            assert!(
                matches!(d.decide(Capability::FsWrite, target), Decision::Deny(_)),
                "{target} should not be writable"
            );
        }
        // And the granted zone still is.
        assert!(matches!(
            d.decide(Capability::FsWrite, "/tmp/out/generated.rs"),
            Decision::Allow
        ));
    }
}
