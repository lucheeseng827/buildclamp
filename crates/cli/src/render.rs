//! Turning a report into something a person reads.
//!
//! Pure string building, so every line the tool prints is testable without running a
//! build. That matters more than it sounds: the single line cargo shows when a unit is
//! refused **is the product** for most users, and a line that is wrong or vague is a
//! support ticket that starts "my build broke and I don't know why".
//!
//! # The vocabulary rule
//!
//! Nothing here says violation, breach, denied, blocked, malicious or suspicious. A
//! request the envelope did not cover is an **ungranted request**, and the sentence is
//! about the policy not covering it rather than about the crate having done wrong. Two
//! reasons, and the second is the load-bearing one:
//!
//! * It is usually true. Most ungranted requests in practice are `cc` doing something
//!   ordinary that the policy has not described yet.
//! * The words a security tool uses about other people's code end up pasted into their
//!   issue tracker. A tool that calls a maintainer's crate malicious because it read an
//!   environment variable has made an accusation on its user's behalf that its user
//!   never checked.

use buildclamp_core::{Capability, Report, UnitRecord};

/// The one line cargo will show when a held build script exits non-zero.
///
/// Cargo captures a build script's stderr and prints it **only** when the unit fails, so
/// this is the whole developer experience of a refusal: it has to name the crate, the
/// capability, the destination and what to do next, in a few lines, with no colour and
/// no assumption anything else is visible.
pub fn refusal_line(unit: &UnitRecord) -> String {
    let Some(first) = unit.ungranted().next() else {
        return String::new();
    };
    let mut s = format!(
        "buildclamp: the {kind} for `{id}` asked to {what} and the policy does not grant it.\n  \
         it tried to: {syscall} {target}\n  \
         its envelope: {granted} (from {source})\n",
        kind = describe_kind(unit),
        id = unit.id,
        what = describe_capability(&first.capability),
        syscall = first.syscall,
        target = first.target,
        granted = unit.envelope.granted,
        source = unit.envelope.source.describe(),
    );
    let more = unit.ungranted().count().saturating_sub(1);
    if more > 0 {
        s.push_str(&format!("  and {more} further ungranted request(s)\n"));
    }
    s.push_str(&format!(
        "  to allow it, add a grant with a reason:\n\
         \x20   [grants.\"{name}\"]\n\
         \x20   capabilities = [{caps}]\n\
         \x20   why = \"...\"\n\
         \x20 or run `cargo buildclamp explain {name}` to see the whole envelope.\n",
        name = unit.id.name,
        caps = wanted_capabilities(unit),
    ));
    s
}

fn describe_kind(unit: &UnitRecord) -> String {
    match unit.kind.copied() {
        Some(buildclamp_core::UnitKind::BuildScriptCompile) => "build script".to_string(),
        Some(buildclamp_core::UnitKind::ProcMacroCompile) => "proc-macro compile".to_string(),
        Some(buildclamp_core::UnitKind::Compile) => "compilation".to_string(),
        Some(buildclamp_core::UnitKind::Probe) => "probe".to_string(),
        // A kind from a newer agent. Printed as it was written rather than as a guess:
        // the person reading a refusal needs to know which thing was refused, and
        // "compilation" would be a confident answer nobody here established.
        None => format!("unit ({})", unit.kind),
    }
}

/// One line about a capability, whether or not this build knows it.
fn describe_capability(c: &buildclamp_core::Forward<Capability>) -> String {
    match c.copied() {
        Some(c) => c.describe().to_string(),
        None => format!("use `{c}`, which this buildclamp does not recognise"),
    }
}

/// The capability list a person would need to paste into a grant, quoted for TOML.
fn wanted_capabilities(unit: &UnitRecord) -> String {
    let mut caps: Vec<Capability> = unit.envelope.granted.iter().collect();
    for r in unit.ungranted() {
        // An unrecognised capability is left out of the paste-in line rather than quoted
        // into it: this build cannot know the name is one a policy would accept, and a
        // suggestion that does not parse is worse than a shorter one.
        if let Some(c) = r.capability.copied() {
            if !caps.contains(&c) {
                caps.push(c);
            }
        }
    }
    caps.sort();
    caps.iter()
        .map(|c| format!("\"{}\"", c.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The summary printed at the end of a run.
pub fn summary(report: &Report, show_all: bool) -> String {
    let mut out = String::new();
    let units = report.units.len();
    let ungranted: usize = report.units.iter().map(|u| u.ungranted().count()).sum();
    let advisory = report
        .units
        .iter()
        .filter(|u| u.has_advisory_tier())
        .count();

    out.push_str(&format!(
        "buildclamp {} — {} mode\n",
        report.tool_version,
        report.mode.as_str()
    ));

    // Immediately after the mode line and before any count, because everything below is
    // measured under whatever was switched off and reads as reassuring without this.
    //
    // Found by running it: with `BUILDCLAMP_MODE=off` this function printed "nothing
    // asked for more than its envelope" over a build where nothing had been held. The
    // report carried the override faithfully and the terminal did not, which is the half
    // people actually read — a switch that is non-silent only in a JSON file somebody has
    // to go and open is a silent switch.
    for o in &report.disable_overrides {
        out.push_str(&format!(
            "\n  !! ENFORCEMENT WAS SWITCHED OFF: {} = {}\n     {}\n     This was somebody's \
             decision, not a limit of this machine.\n",
            o.source, o.value, o.effect
        ));
    }
    if !report.disable_overrides.is_empty() {
        out.push('\n');
    }
    out.push_str(&format!(
        "  build units held           {units}\n  ungranted requests         {ungranted}\n"
    ));
    if advisory > 0 {
        // Never hidden and never soft-pedalled: a green run whose enforcement was only
        // advisory is exactly the false assurance this tool exists to avoid.
        out.push_str(&format!(
            "  ! units where at least one capability was only ADVISORY   {advisory}\n  \
             run `cargo buildclamp doctor` to see what this host can enforce\n"
        ));
    }

    // A report written by a newer agent is readable — the wire types carry a name this
    // build does not know rather than failing the document — but reading it means reading
    // LESS than was recorded, and that has to be said. Tolerance without this line is just
    // a quieter way to under-report.
    let unknown = report.unknown_names();
    if !unknown.is_empty() {
        out.push_str(&format!(
            "  ! this report names {} thing(s) this buildclamp does not know: {}\n  \
             it was written by a newer version, and what you are reading is less than \
             what it recorded. Upgrade the reader.\n",
            unknown.len(),
            unknown.join(", ")
        ));
    }

    let interesting: Vec<&UnitRecord> = if show_all {
        report.units.iter().collect()
    } else {
        report.units_with_ungranted().collect()
    };

    if interesting.is_empty() {
        out.push_str("\n  nothing asked for more than its envelope.\n");
        return out;
    }

    out.push('\n');
    for u in interesting {
        out.push_str(&format!("  {} [{}]\n", u.id, u.kind));
        for (cap, tier) in &u.tiers {
            out.push_str(&format!("      {:<12} {}\n", cap.to_string(), tier.label()));
        }
        for r in &u.requests {
            let mark = if r.outcome.is_ungranted() { "x" } else { " " };
            out.push_str(&format!(
                "    {mark} {:<10} {} {}\n",
                r.capability.to_string(),
                r.syscall,
                r.target
            ));
        }
        if !u.env_scrubbed.is_empty() {
            out.push_str(&format!(
                "      environment withheld: {}\n",
                u.env_scrubbed.join(", ")
            ));
        }
    }
    out
}

/// `cargo buildclamp doctor`: what this host can actually do.
///
/// Printed before anyone trusts a green build. Every line is a probe result, never a
/// capability assumed from a kernel version.
pub fn doctor(host: &buildclamp_core::HostCapabilities) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "host: {} {} on {}\n\n",
        host.os, host.kernel, host.arch
    ));

    out.push_str("what this machine can enforce:\n");
    out.push_str(&yes_no(
        "landlock (filesystem)",
        host.landlock_abi.is_some(),
        &match host.landlock_abi {
            Some(v) => format!("ABI v{v}"),
            None => "absent — the filesystem falls back to a mount namespace".to_string(),
        },
    ));
    out.push_str(&yes_no(
        "user namespaces",
        host.user_namespaces,
        if host.user_namespaces {
            "read-only root and a private network are enforceable"
        } else {
            "blocked — some distributions and container runtimes forbid this"
        },
    ));
    out.push_str(&yes_no(
        "seccomp notification",
        host.seccomp_user_notif,
        if host.seccomp_user_notif {
            "requests can be observed and answered"
        } else {
            "absent — buildclamp cannot see what a unit asks for"
        },
    ));
    out.push_str(&yes_no(
        "/proc hides other processes",
        host.proc_hidepid,
        // `hidepid` hides processes belonging to *other users*, and a build script runs
        // as the same user as cargo — so on its own it does not keep cargo's environment
        // out of reach either way. What does is the user namespace, which is why both
        // branches name it rather than only the one where the probe said no.
        if host.proc_hidepid {
            "other users' processes are hidden; a unit could still read secrets from \
             another process of the same user, unless a user namespace applies"
        } else {
            "a unit could read secrets from another process of the same user, \
             unless a user namespace applies"
        },
    ));

    // Which enforcement is OFF, named on every run rather than left to be inferred from
    // four "yes" lines and one "no". A prospect can hand this to their own platform team
    // as a tier statement for their runners, and a lane can see the gap the day it opens
    // instead of on the build where somebody happens to read the report.
    out.push_str("\nwhat an enforcing run would reach here:\n");
    let projected = buildclamp_sandbox::projected_tiers(host);
    let mut missing: Vec<String> = Vec::new();
    for cap in Capability::ALL {
        let tier = projected.get(&buildclamp_core::Forward::Known(cap));
        let label = tier.map_or_else(|| "absent".to_string(), buildclamp_core::Tier::label);
        out.push_str(&format!("  {:<28} {label}\n", cap.as_str()));
        if tier.is_none_or(|t| !t.is_enforced()) {
            missing.push(cap.as_str().to_string());
        }
    }
    if !missing.is_empty() {
        out.push_str(&format!(
            "  ! not enforced here: {}\n  \
             declare what this lane needs with `--require`, e.g. \
             `cargo buildclamp doctor --require net=enforced`\n",
            missing.join(", ")
        ));
    }

    if !host.user_namespaces && host.landlock_abi.is_none() {
        out.push_str(
            "\n  ! neither Landlock nor user namespaces are available here.\n  \
             buildclamp can still observe, and it will report every capability as\n  \
             advisory rather than claiming an enforcement it did not achieve.\n  \
             `--require-enforced` will fail a run on this host, which is the point.\n",
        );
    }

    // If any capability fell to the seccomp-notify advisory tier, say WHY it is advisory in
    // the kernel's own words rather than ours. A tool telling you its own enforcement is
    // weak is easy to discount; the same sentence from the kernel's manual is not, and
    // quoting it verbatim is what stops "advisory" reading as a buildclamp hedge. The
    // citation is in the string so a sceptic can go and check it, and an advisory-race
    // harness can demonstrate exactly this sentence on a running host.
    let any_notify_advisory = projected.values().any(|t| {
        matches!(t, buildclamp_core::Tier::Advisory { mechanism, .. } if mechanism == "seccomp-notify")
    });
    if any_notify_advisory {
        out.push_str(&format!("\n  {SECCOMP_UNOTIFY_WARNING}\n"));
    }
    out
}

/// The sentence `seccomp_unotify(2)` uses about its own security properties, verbatim.
pub const SECCOMP_UNOTIFY_WARNING: &str = "\
seccomp_unotify(2): \"the seccomp user-space notification mechanism must not be used to \
make security policy decisions about the system call, which would be inherently \
race-prone.\" A seccomp-notify tier is reported as advisory for exactly that reason, and \
never as enforced.";

/// What a declared floor this host does not meet looks like on the way out.
///
/// It names the mechanism and not only the grade, because whoever reads it is deciding
/// between changing the runner and changing the floor, and "advisory" alone does not say
/// which mechanism went missing.
pub fn unmet_floor(unmet: &[buildclamp_core::floor::Unmet]) -> String {
    let mut out =
        String::from("\n  ! this host does not meet the enforcement floor this lane declared:\n");
    for u in unmet {
        out.push_str(&format!(
            "      {:<12} required {:<9} got {}\n",
            u.capability.as_str(),
            u.required.as_str(),
            u.tier
        ));
    }
    out.push_str(
        "  \n  This is a misconfigured lane, not a finding about your dependencies: the\n  \
         machine cannot provide what the pipeline said it needed, so a green build here\n  \
         would mean less than the same build elsewhere. Fix the runner, or lower the\n  \
         floor deliberately and in writing.\n",
    );
    out
}

/// What break-glass did to this run, and what it costs.
///
/// Printed on **every** run with an exception in the policy, live or lapsed, and on every
/// `--grace` run that excused something. A control that quietly stands a refusal down is
/// the failure this whole project is organised against: the loudness is the feature, and
/// the bound is said next to the excuse so nobody reads "passed" and stops there.
pub fn break_glass(
    glass: &buildclamp_core::BreakGlass,
    uses: &[buildclamp_core::ExceptionUse],
    unreviewed: &buildclamp_core::Unreviewed,
    policy_path: &std::path::Path,
) -> String {
    let mut out = String::new();

    if !uses.is_empty() {
        out.push_str("\n  ! BREAK-GLASS: a unit ran wider than this policy allows\n");
        for u in uses {
            out.push_str(&format!(
                "      {}@{}  until {}  ({})\n",
                u.unit.name, u.unit.version, u.expires, u.author
            ));
            out.push_str(&format!(
                "        grants   {}\n",
                if u.grants.is_empty() {
                    "every capability — the block names none".to_string()
                } else {
                    u.grants
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ));
            // What it actually did, which is the line that turns a block into a grant or
            // into a deletion. An exception nobody used is one to remove.
            out.push_str(&format!("        used     {}\n", u.exercised));
            if !u.stood_down.is_empty() {
                let names: Vec<String> = u.stood_down.iter().map(|c| c.to_string()).collect();
                out.push_str(&format!(
                    "        refused  {} — the kernel still said no; only the verdict stood \
                     down\n",
                    names.join(", ")
                ));
            }
            out.push_str(&format!("        {}\n", u.reason));
        }
    }

    if !unreviewed.excepted.is_empty() {
        out.push_str("\n  ! BREAK-GLASS: an exception is holding back --strict\n");
        for (name, expires) in &unreviewed.excepted {
            out.push_str(&format!(
                "      {name} has an unreviewed grant, excused until {expires}\n"
            ));
        }
    }

    // Lapsed blocks are named even when nothing used them. A build that just went red
    // because an exception ran out looks identical to the one the exception was written
    // for, and somebody who is not told will write the same block a second time.
    for e in glass.expired() {
        out.push_str(&format!(
            "\n  note: the exception for `{}` expired on {} and no longer applies.\n        \
             Delete the block, or review the grant it was standing in for.\n",
            e.crate_name,
            e.expires.as_deref().unwrap_or("an unreadable date")
        ));
    }

    if !unreviewed.in_grace.is_empty() {
        out.push_str(&format!(
            "\n  --grace: {} grant(s) are new enough to warn rather than fail\n",
            unreviewed.in_grace.len()
        ));
        for g in &unreviewed.in_grace {
            out.push_str(&format!(
                "      {} first seen {}, {} more run(s) before it fails\n",
                g.crate_name, g.first_seen, g.days_left
            ));
        }
    }

    if unreviewed.count() > 0 {
        out.push_str(&format!(
            "  --strict: {} grant(s) in {} are still `reviewed = false`\n",
            unreviewed.count(),
            policy_path.display()
        ));
    }

    if !uses.is_empty() || !unreviewed.excepted.is_empty() || !unreviewed.in_grace.is_empty() {
        out.push_str(
            "  \n  None of this is approval. Every line above is work somebody still owes, and\n  \
             every one of them stops excusing anything by itself — an exception on the day\n  \
             it names, a grace window when the grant is no longer new.\n",
        );
    }
    out
}

/// The block behind a widened envelope, for `explain`.
///
/// Printed after the envelope rather than folded into it, because the two say different
/// things: the envelope is what this crate may do today, and this is why it is wider than
/// the policy alone, who decided that, and when it stops.
pub fn explain_exception(e: &buildclamp_core::Exception) -> String {
    let mut out = String::from("\n  ! a live [[exception]] widened this envelope\n");
    out.push_str(&format!(
        "      until    {}\n      author   {}\n      reason   {}\n",
        e.expires.as_deref().unwrap_or("an unreadable date"),
        e.author,
        e.reason
    ));
    if e.capabilities.is_empty() {
        out.push_str("      grants   every capability — the block names none\n");
    } else {
        out.push_str(&format!(
            "      grants   {}\n",
            e.capabilities
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    out.push_str(
        "  \n  It does not widen `write-zones`: a write outside them is still refused by the\n           kernel, and the run's verdict standing down is what an exception buys there. A\n           crate that needs a new zone needs a grant, which is a line somebody reviews.\n",
    );
    out
}

/// What `init` wrote, and what is still owed.
///
/// The residual — grants still unreviewed after a baseline — is the last line on purpose.
/// It is the number that says whether a baseline is worth anything: one that accepts
/// everything is one nobody checked, and one that accepts nothing has not been measured
/// against a real graph. A command that printed only what it accepted would be reporting
/// its own success rate.
pub fn init_summary(
    out: &std::path::Path,
    grants: usize,
    acceptance: &buildclamp_core::Acceptance,
) -> String {
    if acceptance.total() == 0 {
        return format!(
            "buildclamp: wrote {} with {grants} grant(s), all unreviewed.\n",
            out.display()
        );
    }
    let mut text = format!(
        "buildclamp: wrote {} with {grants} grant(s).\n\
         \n  accepted from the baseline   {}\n  still unreviewed             {}\n",
        out.display(),
        acceptance.accepted.len(),
        acceptance.residual.len()
    );
    for who in &acceptance.residual {
        text.push_str(&format!("      {who}\n"));
    }
    if acceptance.residual.is_empty() {
        text.push_str(
            "  \n  A baseline that covers everything is worth looking at twice: it means the\n  \
             document vouched for every crate in this graph at the exact version you are\n  \
             on, which is a strong claim for it to be making.\n",
        );
    } else {
        text.push_str(&format!(
            "  \n  Each accepted grant is pinned to the exact version the baseline named, so a\n  \
             patch bump comes back here rather than inheriting the approval. Replace the\n  \
             `why` on the {} above with a real reason and set `reviewed = true`.\n",
            acceptance.residual.len()
        ));
    }
    text
}

/// What `verify` established, and — in the same breath — what it did not.
pub fn verified(v: &buildclamp_core::Verified, args: &crate::args::VerifyArgs) -> String {
    let p = &v.statement.predicate;
    let mut out = String::from("\n  checked by buildclamp:\n");
    out.push_str(&check("in-toto Statement v1", true, "the `_type` field"));
    out.push_str(&check(
        "predicateType",
        true,
        buildclamp_core::PREDICATE_TYPE,
    ));
    out.push_str(&check(
        "artefact digest",
        v.checked_artefact,
        if v.checked_artefact {
            "matches the file you gave"
        } else {
            "NOT CHECKED — pass --artefact <file>"
        },
    ));
    out.push_str(&check(
        "policy digest",
        v.checked_policy,
        if v.checked_policy {
            "matches the file you gave"
        } else {
            "NOT CHECKED — pass --policy <file>"
        },
    ));
    out.push_str(&check(
        "report digest",
        v.checked_report,
        if v.checked_report {
            "matches the file you gave"
        } else {
            "NOT CHECKED — pass --report <file>"
        },
    ));

    // Printed on every run, pass or fail, and not as a footnote. Half a verification
    // reported as "verified" is the overstatement this project exists to avoid, about the
    // one document people quote at auditors.
    out.push_str(
        "\n  NOT checked by buildclamp:\n    \
         signature          this binary links no cryptography, deliberately — run\n                       \
         `cosign verify-attestation` or `gh attestation verify`\n",
    );

    if !v.errata.is_empty() {
        out.push_str("\n  ! ERRATA apply to this statement\n");
        for e in &v.errata {
            out.push_str(&format!(
                "      {} ({})  {} reads as {}\n        {}\n",
                e.id,
                e.published,
                e.capability.as_deref().unwrap_or("this statement"),
                e.corrected_tier,
                e.finding
            ));
        }
        out.push_str(
            "  \n  A signed statement cannot be unsigned. An erratum is how a tier this\n  \
             project later found to be overstated gets corrected, and it downgrades the\n  \
             answer below.\n",
        );
    }

    out.push('\n');
    out.push_str(&p.plain_english());

    if args.require_fully_enforced && !v.is_fully_enforced() {
        out.push_str(
            "\n  --require-fully-enforced: this statement does not describe a fully enforced\n  \
             run. See the lines above for which part.\n",
        );
    }
    out
}

fn check(label: &str, ok: bool, detail: &str) -> String {
    format!(
        "    {:<18} {}  {}\n",
        label,
        if ok { "yes" } else { "no " },
        detail
    )
}

fn yes_no(label: &str, ok: bool, detail: &str) -> String {
    format!(
        "  {:<28} {}  {}\n",
        label,
        if ok { "yes" } else { "no " },
        detail
    )
}

/// How many units the markdown summary names before it stops and counts.
///
/// GitHub surfaces roughly ten annotations per update out of about fifty accepted, and a
/// job summary has a size limit of its own. A first `init` on a real estate produces a
/// couple of hundred grants, so a summary that listed everything would be cut off by the
/// platform at whatever point it happened to reach — losing the tail silently, which is the
/// worst of the available failures. Twenty is enough to act on and short enough to survive.
const MARKDOWN_UNIT_LIMIT: usize = 20;

/// A GitHub-flavoured markdown summary of a run, for a CI job summary or a PR comment.
///
/// # What it is for
///
/// The terminal summary is read by whoever typed the command. This is read by whoever did
/// not: a reviewer looking at a pull request, deciding in a few seconds whether the build
/// asked for anything it should not have. So it leads with the answer, names the tier that
/// produced it, and links to the report rather than reproducing it.
///
/// # Bounded, and it says when it is bounding
///
/// Truncation that announces itself is a summary; truncation that does not is a lie by
/// omission, and this project's own rule about reports that are short. Every list here
/// stops at [`MARKDOWN_UNIT_LIMIT`] and prints how many it left out.
pub fn markdown(report: &Report, report_path: &std::path::Path) -> String {
    let mut out = String::new();
    let ungranted: Vec<&UnitRecord> = report.units_with_ungranted().collect();
    let advisory = report
        .units
        .iter()
        .filter(|u| u.has_advisory_tier() || u.has_unenforced_tier())
        .count();

    out.push_str("## buildclamp\n\n");

    // The override first, above the verdict, for the same reason the terminal summary puts
    // it there: everything below is measured under whatever was switched off, and it reads
    // as reassuring without this.
    for o in &report.disable_overrides {
        out.push_str(&format!(
            "> [!CAUTION]\n> **Enforcement was switched off** — `{}` = `{}`.\n> {}\n>              This was somebody's decision, not a limit of this machine.\n\n",
            o.source, o.value, o.effect
        ));
    }

    if ungranted.is_empty() {
        out.push_str("✅ **Nothing asked for more than its envelope.**\n\n");
    } else {
        out.push_str(&format!(
            "❌ **{} unit(s) asked for something the policy does not grant.**\n\n",
            ungranted.len()
        ));
    }

    out.push_str("| | |\n|---|---|\n");
    out.push_str(&format!("| build units held | {} |\n", report.units.len()));
    out.push_str(&format!(
        "| ungranted requests | {} |\n",
        report
            .units
            .iter()
            .map(|u| u.ungranted().count())
            .sum::<usize>(),
    ));
    out.push_str(&format!(
        "| host | {} {} on {} |\n",
        report.host.os, report.host.kernel, report.host.arch,
    ));
    if let Some(target) = &report.run.target {
        out.push_str(&format!("| target | {target} |\n"));
    }
    out.push('\n');

    // The tiers, which is the thing this project exists to make visible. A reviewer who
    // reads "no findings" without reading "nothing was enforced" has been told the
    // opposite of the truth.
    if let Some(first) = report.units.first() {
        out.push_str("<details><summary>Enforcement tiers on this host</summary>\n\n");
        out.push_str("| capability | tier |\n|---|---|\n");
        for (cap, tier) in &first.tiers {
            out.push_str(&format!("| `{cap}` | `{}` |\n", tier.label()));
        }
        out.push_str("\n</details>\n\n");
    }
    if advisory > 0 {
        out.push_str(&format!(
            "> [!WARNING]\n> {advisory} unit(s) had at least one capability that was              **not enforced** on this host. Run `cargo buildclamp doctor` to see what is              missing.\n\n"
        ));
    }

    for u in ungranted.iter().take(MARKDOWN_UNIT_LIMIT) {
        out.push_str(&format!("### `{}` [{}]\n\n", u.id, u.kind));
        for r in u.ungranted().take(MARKDOWN_UNIT_LIMIT) {
            out.push_str(&format!(
                "- `{}` — `{}` `{}`\n",
                r.capability, r.syscall, r.target
            ));
        }
        let more = u.ungranted().count().saturating_sub(MARKDOWN_UNIT_LIMIT);
        if more > 0 {
            out.push_str(&format!("- …and {more} further ungranted request(s)\n"));
        }
        out.push('\n');
    }
    let more_units = ungranted.len().saturating_sub(MARKDOWN_UNIT_LIMIT);
    if more_units > 0 {
        out.push_str(&format!(
            "…and **{more_units} further unit(s)** not listed here. The full record is the              report, which is why this links to it rather than growing.\n\n"
        ));
    }

    let unknown = report.unknown_names();
    if !unknown.is_empty() {
        out.push_str(&format!(
            "> [!NOTE]\n> This report names {} thing(s) this buildclamp does not know: {}.              It was written by a newer version, so you are reading less than it              recorded.\n\n",
            unknown.len(),
            unknown.join(", ")
        ));
    }

    out.push_str(&format!(
        "<sub>Full report: `{}` — `cargo buildclamp report --json`</sub>\n",
        report_path.display()
    ));
    out
}

/// `cargo buildclamp explain <crate>`.
pub fn explain(
    name: &str,
    version: Option<&str>,
    envelope: &buildclamp_core::Envelope,
    withheld: &[String],
) -> String {
    let mut out = format!(
        "{name}{}\n\n  envelope   {}\n  from       {}\n",
        version.map(|v| format!(" {v}")).unwrap_or_default(),
        envelope.granted,
        envelope.source.describe(),
    );
    if let Some(why) = &envelope.why {
        out.push_str(&format!("  why        {why}\n"));
        out.push_str(&format!(
            "  reviewed   {}\n",
            if envelope.reviewed {
                "yes"
            } else {
                "NO — `--strict` will refuse this run"
            }
        ));
    }
    if envelope.permits(Capability::FsWrite) {
        let zones: Vec<String> = envelope
            .write_zones
            .iter()
            .map(ToString::to_string)
            .collect();
        out.push_str(&format!(
            "  may write  {}\n",
            if zones.is_empty() {
                "nowhere".to_string()
            } else {
                zones.join(", ")
            }
        ));
    }
    if !envelope.net_destinations.is_empty() {
        out.push_str(&format!(
            "  expects    {}\n  {}\n",
            envelope.net_destinations.join(", "),
            "(recorded for the report; buildclamp does NOT enforce a destination list)"
        ));
    }
    if !withheld.is_empty() {
        out.push_str(&format!("\n  environment withheld ({}):\n", withheld.len()));
        for name in withheld {
            out.push_str(&format!("    {name}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use buildclamp_core::{
        Attribution, CapabilitySet, Envelope, HostCapabilities, Mode, Outcome, Request, Tier,
        UnitId, UnitKind,
    };

    fn refused_unit() -> UnitRecord {
        UnitRecord {
            id: UnitId::new("evil", "0.1.3"),
            kind: UnitKind::BuildScriptCompile.into(),
            source: None,
            instance: None,
            envelope: Envelope::build_script_default(),
            tiers: std::collections::BTreeMap::from([(
                Capability::Net.into(),
                Tier::Enforced {
                    mechanism: "netns".into(),
                },
            )]),
            env_scrubbed: vec!["GITHUB_TOKEN".into()],
            requests: vec![Request {
                at_ms: 12,
                tid: 4242,
                capability: Capability::Net.into(),
                syscall: "connect".into(),
                target: "203.0.113.7:443".into(),
                outcome: Outcome::Ungranted { errno: 1 },
                attribution: Attribution::Unit,
            }],
            observed: CapabilitySet::of(&[Capability::Net]),
            proc_macros_in_closure: Vec::new(),
            exit_code: Some(101),
            signal: None,
            duration_ms: 87,
        }
    }

    #[test]
    fn the_refusal_line_names_the_crate_the_capability_and_the_destination() {
        // Cargo shows this and nothing else. If it does not answer "which dependency,
        // and what did it try to do", the tool has failed at the only moment that counts.
        let s = refusal_line(&refused_unit());
        assert!(s.contains("evil@0.1.3"), "{s}");
        assert!(s.contains("reach the network"), "{s}");
        assert!(s.contains("203.0.113.7:443"), "{s}");
        assert!(s.contains("connect"), "{s}");
        assert!(s.contains("cargo buildclamp explain evil"), "{s}");
    }

    #[test]
    fn the_refusal_line_shows_a_grant_that_would_actually_work() {
        // Someone will paste this. It has to keep the capabilities the unit already had
        // as well as the one it was refused, because a grant replaces the defaults.
        let s = refusal_line(&refused_unit());
        assert!(s.contains("[grants.\"evil\"]"), "{s}");
        assert!(s.contains("\"net\""), "{s}");
        assert!(s.contains("\"fs-write\""), "{s}");
        assert!(s.contains("\"exec\""), "{s}");
        assert!(s.contains("why = "), "{s}");
    }

    #[test]
    fn no_output_anywhere_calls_a_crate_malicious_or_a_request_a_violation() {
        // The words a security tool uses about other people's code end up in their issue
        // tracker. This test is the enforcement of the vocabulary rule.
        let mut r = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
        r.units.push(refused_unit());
        let corpus = format!(
            "{}{}{}",
            refusal_line(&refused_unit()),
            summary(&r, true),
            explain(
                "evil",
                Some("0.1.3"),
                &Envelope::build_script_default(),
                &["X".into()]
            )
        );
        let lower = corpus.to_lowercase();
        for banned in [
            "violation",
            "malicious",
            "suspicious",
            "breach",
            "unauthorized",
            "unauthorised",
            "attack",
            "compromised",
            "blocked",
        ] {
            assert!(
                !lower.contains(banned),
                "output used the word `{banned}`:\n{corpus}"
            );
        }
    }

    #[test]
    fn the_markdown_summary_bounds_itself_and_says_that_it_did() {
        // The mangling case the roadmap names: a first `init` on a real estate produces a
        // couple of hundred findings, GitHub surfaces roughly ten annotations out of about
        // fifty, and a summary that listed everything would be cut off by the platform
        // wherever it happened to reach. Truncation that announces itself is a summary;
        // truncation that does not is the lie by omission this project keeps naming.
        let mut r = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
        for i in 0..200 {
            let mut u = refused_unit();
            u.id = UnitId::new(format!("crate{i}"), "1.0.0");
            r.units.push(u);
        }
        let md = markdown(&r, std::path::Path::new("/w/target/buildclamp/report.json"));

        assert!(md.contains("200 unit(s) asked for something"), "{md}");
        assert!(
            md.contains("**180 further unit(s)** not listed here"),
            "the count it left out must be stated:\n{md}"
        );
        assert_eq!(
            md.matches("### `crate").count(),
            20,
            "exactly the limit, not everything and not an arbitrary cut"
        );
        assert!(
            md.contains("report.json"),
            "and it must point at the full record"
        );
    }

    #[test]
    fn a_clean_markdown_summary_still_names_the_tiers_that_produced_it() {
        // A reviewer who reads "no findings" without reading "nothing was enforced" has
        // been told the opposite of the truth, which is the failure this whole project is
        // organised around. The tiers travel with the verdict.
        let mut r = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
        let mut u = refused_unit();
        u.requests.clear();
        r.units.push(u);
        let md = markdown(&r, std::path::Path::new("/w/report.json"));

        assert!(
            md.contains("Nothing asked for more than its envelope"),
            "{md}"
        );
        assert!(md.contains("Enforcement tiers on this host"), "{md}");
        assert!(md.contains("enforced:netns"), "{md}");
    }

    #[test]
    fn a_markdown_summary_puts_an_override_above_the_verdict() {
        // Same ordering rule as the terminal summary, for the same reason: everything
        // below is measured under whatever was switched off.
        let mut r = Report::new("0.1.0", Mode::Off, vec!["build".into()]);
        r.disable_overrides.push(buildclamp_core::DisableOverride {
            source: "BUILDCLAMP_MODE".into(),
            value: "off".into(),
            effect: "every unit ran unheld".into(),
        });
        let md = markdown(&r, std::path::Path::new("/w/report.json"));
        let caution = md
            .find("Enforcement was switched off")
            .expect("the caution");
        let verdict = md.find("Nothing asked for more").expect("the verdict");
        assert!(caution < verdict, "the override must come first:\n{md}");
    }

    #[test]
    fn the_summary_never_hides_that_enforcement_was_only_advisory() {
        let mut r = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
        let mut u = refused_unit();
        u.requests.clear();
        u.tiers = std::collections::BTreeMap::from([(
            Capability::FsWrite.into(),
            Tier::Advisory {
                mechanism: "seccomp-notify".into(),
                limitation: "the kernel re-reads the path after we answer".into(),
            },
        )]);
        r.units.push(u);
        let s = summary(&r, false);
        assert!(s.contains("ADVISORY"), "{s}");
        assert!(s.contains("doctor"), "{s}");
    }

    #[test]
    fn a_clean_run_says_so_plainly_rather_than_printing_nothing() {
        let r = Report::new("0.1.0", Mode::Enforce, vec!["build".into()]);
        let s = summary(&r, false);
        assert!(
            s.contains("nothing asked for more than its envelope"),
            "{s}"
        );
    }

    #[test]
    fn doctor_on_a_host_with_neither_mechanism_says_what_that_means_for_the_user() {
        let host = HostCapabilities {
            os: "linux".into(),
            kernel: "6.18.44".into(),
            arch: "x86_64".into(),
            landlock_abi: None,
            user_namespaces: false,
            seccomp_user_notif: true,
            proc_hidepid: false,
        };
        let s = doctor(&host);
        assert!(s.contains("advisory"), "{s}");
        assert!(s.contains("--require-enforced"), "{s}");
        // And it must say what the missing hidepid actually costs.
        assert!(s.contains("read secrets from another process"), "{s}");
        // A notify-only host has fs-write at advisory:seccomp-notify, so the kernel's own
        // sentence about the race must appear — verbatim, because a tool calling its own
        // enforcement weak is easy to discount and the man page is not.
        assert!(s.contains("seccomp_unotify(2)"), "{s}");
        assert!(
            s.contains("inherently"),
            "the man-page sentence must be quoted: {s}"
        );
    }

    #[test]
    fn the_seccomp_warning_is_absent_where_nothing_falls_to_a_notification_decision() {
        // A host that reaches everything has no advisory:seccomp-notify tier, so the
        // warning would be noise. Exec is advisory-by-notification on every host, but it is
        // `seccomp-notify-record` rather than `seccomp-notify`, and the warning is about
        // decisions rather than recording — so a full host stays quiet.
        let host = HostCapabilities {
            os: "linux".into(),
            kernel: "6.18.44".into(),
            arch: "x86_64".into(),
            landlock_abi: Some(7),
            user_namespaces: true,
            seccomp_user_notif: true,
            proc_hidepid: true,
        };
        let s = doctor(&host);
        assert!(!s.contains("seccomp_unotify(2)"), "{s}");
    }

    #[test]
    fn explain_says_when_a_grant_is_unreviewed_and_what_that_costs() {
        let mut e = Envelope::build_script_default();
        e.why = Some("OBSERVED 2026-09-01: connected to crates.io:443".into());
        e.reviewed = false;
        let s = explain("fetcher", Some("1.2.3"), &e, &[]);
        assert!(s.contains("NO — `--strict` will refuse this run"), "{s}");
    }

    #[test]
    fn explain_says_out_loud_that_destinations_are_not_enforced() {
        // Shipping an advisory field that reads as enforcement is the exact trap this
        // project exists to avoid, so the word appears wherever the field does.
        let mut e = Envelope::build_script_default();
        e.net_destinations = vec!["crates.io:443".into()];
        let s = explain("fetcher", None, &e, &[]);
        assert!(s.contains("does NOT enforce"), "{s}");
    }
}
