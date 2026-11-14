#!/bin/sh
# Emit one row of the enforcement matrix for the host this runs on.
#
#     ops/matrix-row.sh --label "GKE default node image"
#
# The matrix in docs/MATRIX.md is a set of these. It is published INCLUDING the rows where
# the answer is `none`, and this script is published so that the rows are not something you
# have to take our word for: run it on your own fleet and compare.
#
# ## What it measures, and what it does not
#
# Two things, both from the released binary and neither from a source checkout:
#
#   * `doctor --json` — what the kernel offers and the tier each capability projects to.
#     This is a statement about the machine.
#   * `selftest --no-network` — a real process run inside the same envelope a build script
#     gets, with the network denied, failing if anything in it opened a socket. This is a
#     statement about the enforcement actually working, observed by the kernel.
#
# The second is why the first is not enough on its own. A host can report
# `net: enforced:netns` and still fail to hold a process — a container runtime that permits
# `unshare` but not `pivot_root`, a seccomp profile that lets the filter install and blocks
# the notification ioctl — and a matrix built from the projection alone would record the
# claim rather than the outcome. **A cell where doctor says `enforced` and the selftest
# does not pass is a release blocker**, not a footnote.
#
# It does NOT run the incident fixtures. Those need the source tree and a compiler; the
# end-to-end suite is where they live. This is the part a customer can run on a production
# node with one binary and no toolchain.
#
# ## Output
#
# JSON on stdout, one object, ready to append to a matrix file. `--markdown` prints the
# table row instead. Exit status is 0 when the row was produced — a host that cannot
# enforce is a valid row and not an error — and 1 only when the row could not be measured
# at all, because a matrix with a silently missing cell is worse than one with a gap in it.
#
# Pass `--label` with something a reader can act on: "GKE 1.31 default node image", "GitHub
# Actions ubuntu-24.04", "stock docker run, no --security-opt". The kernel version alone
# does not say which of those it was, and that is the question the matrix exists to answer.

set -eu

BIN="${BUILDCLAMP:-cargo-buildclamp}"
LABEL=""
FORMAT="json"

while [ $# -gt 0 ]; do
    case "$1" in
        --label) LABEL="${2:?--label needs a value}"; shift 2 ;;
        --markdown) FORMAT="markdown"; shift ;;
        --json) FORMAT="json"; shift ;;
        -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "matrix-row.sh: unknown argument: $1" >&2; exit 1 ;;
    esac
done

if ! command -v "$BIN" >/dev/null 2>&1 && [ ! -x "$BIN" ]; then
    echo "matrix-row.sh: $BIN is not on PATH. Set BUILDCLAMP to the binary." >&2
    exit 1
fi

DOCTOR=$("$BIN" buildclamp doctor --json) || {
    echo "matrix-row.sh: doctor failed, so this host has no row rather than an empty one." >&2
    exit 1
}

# `selftest` answers in exit codes precisely so that a script does not have to read prose:
# 0 the network was denied and nothing asked for it, 2 something asked for it, 1 the check
# could not be carried out on this host. The third is a legitimate matrix answer — it is
# what a host with no enforcement says — and the row records which of the three it was.
set +e
SELFTEST_OUT=$("$BIN" buildclamp selftest --no-network 2>&1)
SELFTEST_CODE=$?
set -e
case "$SELFTEST_CODE" in
    0) SELFTEST="held" ;;
    2) SELFTEST="escaped" ;;
    *) SELFTEST="unavailable" ;;
esac

# The one line of the selftest worth carrying: which tier actually held the command. The
# rest of its output is the held process's own, which on the default command is a whole
# second doctor document — useful to read, useless in a row, and the reason this extracts
# rather than embeds.
SELFTEST_TIER=$(printf '%s' "$SELFTEST_OUT" | sed -n 's/.*network tier \{1,\}\([a-z:+-]*\).*/\1/p' | tail -1)
[ -n "$SELFTEST_TIER" ] || SELFTEST_TIER="none"

VERSION=$("$BIN" --version 2>/dev/null | tr -d '\n' || echo "unknown")
WHEN=$(date -u +%Y-%m-%d)

# A row is only worth having if somebody can tell which machine it describes, and the
# kernel string alone does not say whether this was a bare runner, a container or a managed
# node image — which is the whole question the matrix answers. So an unlabelled row says so
# rather than borrowing a field that looks like an answer.
[ -n "$LABEL" ] || LABEL="unlabelled host"

if [ "$FORMAT" = "markdown" ]; then
    field() { printf '%s' "$DOCTOR" | sed -n "s/.*\"$1\": \{0,1\}\"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}.*/\1/p" | head -1; }
    grade() {
        printf '%s' "$DOCTOR" | tr -d ' \n' \
            | sed -n "s/.*\"$1\":{\"grade\":\"\([a-z]*\)\".*/\1/p" | head -1
    }
    printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' \
        "$LABEL" \
        "$(field kernel)" \
        "$(field landlock_abi)" \
        "$(grade net)" \
        "$(grade fs-write)" \
        "$(grade env-secret)" \
        "$SELFTEST ($SELFTEST_TIER)" \
        "$WHEN"
    exit 0
fi

# The doctor document verbatim, wrapped with what this script adds. Verbatim because a
# consumer that already parses a report's `host` object should not need a second schema,
# and because a field this script did not think to forward is a field the matrix loses.
printf '{\n'
printf '  "label": "%s",\n' "$LABEL"
printf '  "measured": "%s",\n' "$WHEN"
printf '  "tool_version": "%s",\n' "$VERSION"
printf '  "selftest_no_network": "%s",\n' "$SELFTEST"
printf '  "selftest_tier": "%s",\n' "$SELFTEST_TIER"
printf '  "doctor":\n'
printf '%s\n' "$DOCTOR" | sed 's/^/  /'
printf '}\n'
