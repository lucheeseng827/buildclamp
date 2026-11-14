#!/bin/sh
# Merge ops/seccomp-additions.json into a container seccomp profile.
#
#     ops/make-seccomp-profile.sh /usr/share/containers/seccomp.json > buildclamp-seccomp.json
#     docker run --security-opt seccomp=buildclamp-seccomp.json …
#
# ## Why this takes a base profile instead of shipping one
#
# A runtime's default profile is an allowlist of around three hundred syscall names. A copy
# of it maintained by hand in this repository would be wrong in the direction that breaks
# containers — one name missing and something unrelated in the image stops working with an
# EPERM that names nothing — and it would be wrong silently, going stale every time the
# runtime updated its own. The authoritative copy is the one your runtime ships. This adds
# to it.
#
# Where to find the base:
#
#   podman / cri-o    /usr/share/containers/seccomp.json
#   docker            profiles/seccomp/default.json in the moby/moby source tree; the
#                     daemon compiles its default in rather than installing a file
#   kubernetes        whatever `seccompProfile.localhostProfile` points at on the node
#
# Pass `--check` instead of a base profile and it verifies the additions list against the
# sandbox source rather than merging anything: a syscall the sandbox issues and this file
# does not name is a container that reports a weaker tier than its kernel offers, and that
# is a defect to catch in CI rather than in somebody's cluster.

set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ADDITIONS="$HERE/seccomp-additions.json"

if [ "${1:-}" = "--check" ]; then
    # Every `libc::SYS_x` and every direct libc call the sandbox makes, against the names
    # this file lists. Deliberately over-broad on the source side: a name that turns up
    # here and is genuinely unrestricted everywhere costs one line in the additions file,
    # and a name that is missing costs a customer a silently weaker tier.
    src="$HERE/../crates/sandbox/src"
    [ -d "$src" ] || { echo "make-seccomp-profile.sh: --check needs the source tree" >&2; exit 1; }
    missing=""
    for name in $(grep -rhoE 'libc::SYS_[a-z0-9_]+' "$src" | sed 's/libc::SYS_//' | sort -u); do
        grep -q "\"$name\"" "$ADDITIONS" || missing="$missing $name"
    done
    # The three Landlock syscalls are issued by number rather than through `libc::SYS_`,
    # because libc has no constant for them on every platform this builds for. Their
    # numbers are asserted in landlock.rs; their names have to be asserted here.
    for name in landlock_create_ruleset landlock_add_rule landlock_restrict_self; do
        grep -q "\"$name\"" "$ADDITIONS" || missing="$missing $name"
    done
    if [ -n "$missing" ]; then
        echo "make-seccomp-profile.sh: the sandbox issues syscalls the additions file does" >&2
        echo "  not name:$missing" >&2
        echo "  A container profile built from this file would refuse them, and buildclamp" >&2
        echo "  would report a weaker tier than the kernel can provide — which looks exactly" >&2
        echo "  like an old kernel. Add them to ops/seccomp-additions.json." >&2
        exit 1
    fi
    echo "make-seccomp-profile.sh: every syscall the sandbox issues is named in the additions."
    exit 0
fi

BASE="${1:?usage: make-seccomp-profile.sh <base-profile.json> | --check}"
[ -f "$BASE" ] || { echo "make-seccomp-profile.sh: no such profile: $BASE" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || {
    echo "make-seccomp-profile.sh: needs python3 to edit JSON. Merging by hand: take every" >&2
    echo "  name under \`additions\` in $ADDITIONS and add one" >&2
    echo "  {\"names\": [...], \"action\": \"SCMP_ACT_ALLOW\"} entry to the base profile's" >&2
    echo "  \`syscalls\` array." >&2
    exit 1
}

python3 - "$BASE" "$ADDITIONS" <<'PY'
import json, sys

base = json.load(open(sys.argv[1]))
additions = json.load(open(sys.argv[2]))

names = []
for entry in additions["additions"]:
    names.extend(entry["names"])

# Appended as ONE unconditional allow rule rather than edited into the existing ones.
#
# The base profile restricts some of these by argument — Docker allows `clone` only when no
# namespace flag is set — and rewriting that rule in place would be editing a security
# decision whose other consumers we cannot see. A later ALLOW entry is what actually lifts
# the restriction under libseccomp's rule precedence, and it leaves the original rule
# visible in the diff so a reviewer can see what was widened and for whom.
base.setdefault("syscalls", []).append({
    "names": sorted(set(names)),
    "action": "SCMP_ACT_ALLOW",
    "comment": "added by buildclamp: see ops/seccomp-additions.json for what each is for",
})
json.dump(base, sys.stdout, indent=2)
sys.stdout.write("\n")
PY
