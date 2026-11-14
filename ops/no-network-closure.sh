#!/usr/bin/env bash
# Assert that no PUBLISHED BINARY can open a socket, over its resolved dependency closure.
#
# ## Why this exists alongside the grep and does not replace it
#
# `ops/ci.yml` greps Cargo.toml files for six line-anchored dependency names. That check
# stays: it is fast, it needs no resolver, and it catches a *library* crate gaining a
# client before anything reachable depends on it. What it cannot do is see the graph.
# Measured against it, on this repository's own regex:
#
#     reqwest = "0.12"            CAUGHT
#     reqwest.workspace = true    MISSED   — no `=` directly after the name
#       reqwest = "0.12"          MISSED   — `^` anchor, indented under a target table
#     some-wrapper = "1"          MISSED   — pulls hyper transitively, names it nowhere
#
# Three of four forms pass a check that the security docs describe as
# establishable from `cargo tree`. This script is the `cargo tree` half.
#
# ## Scope: `-e normal`, deliberately
#
# Development and build dependencies are excluded. The property being defended is about
# the ARTEFACT — what the binary a customer runs beside their build can do — and neither
# a dev-dependency nor a build-dependency ships inside it. Build-time code on the
# maintainer's own machine is a different question, and the repo-wide grep is what covers
# it. Saying which of the two a check answers is the whole point of having both.
#
# Usage:
#   ops/no-network-closure.sh            check every published binary
#   ops/no-network-closure.sh --selftest prove the check fails on a transitive client
set -uo pipefail

# Crates that mean "this artefact can reach the network". `socket2` is included because it
# is the layer under most of the others and a direct use of it is the same capability
# wearing a smaller name.
DENY='^(reqwest|hyper|hyper-util|ureq|isahc|curl|surf|socket2|h2|native-tls|rustls|openssl|attohttpc|minreq)$'

fail=0

# closure_of <manifest> <package>  →  the normal dependency closure, one crate name a line
closure_of() {
  cargo tree -e normal --manifest-path "$1" -p "$2" --prefix none 2>/dev/null \
    | sed 's/ v[0-9].*//' | sed 's/ (\*)$//' | grep -v '^$' | sort -u
}

# Binary packages in a workspace, discovered rather than named: any member under
# `crates/` with a `src/main.rs`. Two reasons this beats a hardcoded list. It picks up a
# new binary automatically, and a new binary is exactly when somebody forgets to add one
# here. And it keeps this script free of package names: discovery works the same in
# any workspace it is pointed at, including one this tree does not carry.
discover_bins() {
  local root
  root="$(dirname "$1")"
  local m
  for m in "$root"/crates/*/Cargo.toml; do
    [ -f "$m" ] || continue
    [ -f "$(dirname "$m")/src/main.rs" ] || continue
    sed -n 's/^name *= *"\(.*\)"/\1/p' "$m" | head -1
  done
}

check_binary() {
  local manifest="$1" pkg="$2" label="$3"
  local closure hits
  closure="$(closure_of "$manifest" "$pkg")"
  if [ -z "$closure" ]; then
    echo "::error::could not resolve the closure of ${pkg}; the check proved nothing"
    fail=1
    return
  fi
  hits="$(printf '%s\n' "$closure" | grep -iE "$DENY" || true)"
  if [ -n "$hits" ]; then
    echo "::error::${label} (${pkg}) can reach the network. Its resolved closure contains:"
    printf '    %s\n' $hits
    echo "::error::This artefact runs on a machine where a third-party build script also"
    echo "::error::runs. A tool that denies build scripts the network must not itself be"
    echo "::error::able to reach it, and a customer must be able to establish that from"
    echo "::error::\`cargo tree\` rather than from a promise."
    fail=1
  else
    echo "ok  ${label}: $(printf '%s\n' "$closure" | wc -l | tr -d ' ') crates, none of them a network client"
  fi

  # tokio is not in either closure today. If it ever is, the feature set is the question:
  # tokio without `net` cannot open a socket, and banning the crate outright would be a
  # rule nobody could follow if async ever became useful for something local.
  if printf '%s\n' "$closure" | grep -qx 'tokio'; then
    if cargo tree -e normal --manifest-path "$manifest" -p "$pkg" -f '{p} {f}' 2>/dev/null \
        | grep '^tokio ' | grep -q '\bnet\b'; then
      echo "::error::${label} depends on tokio with the \`net\` feature enabled"
      fail=1
    fi
  fi
}

selftest() {
  # The gate must be observed to fail, or it is decoration. Builds, in a scratch
  # directory, exactly the shape the grep cannot see: a victim that names only a local
  # wrapper, and a wrapper that depends on a crate called `hyper`. Path dependencies, so
  # this needs no network — which it could not have anyway.
  local w
  w="$(mktemp -d)"
  trap 'rm -rf "$w"' RETURN

  mkdir -p "$w/hyper/src" "$w/wrapper/src" "$w/src"
  cat > "$w/hyper/Cargo.toml" <<'EOF'
[package]
name = "hyper"
version = "0.0.1"
edition = "2021"
EOF
  echo 'pub fn get() {}' > "$w/hyper/src/lib.rs"

  cat > "$w/wrapper/Cargo.toml" <<'EOF'
[package]
name = "wrapper"
version = "0.0.1"
edition = "2021"
[dependencies]
hyper = { path = "../hyper" }
EOF
  echo 'pub fn go() { hyper::get() }' > "$w/wrapper/src/lib.rs"

  cat > "$w/Cargo.toml" <<'EOF'
[package]
name = "victim"
version = "0.0.1"
edition = "2021"
[dependencies]
wrapper = { path = "wrapper" }
[workspace]
EOF
  echo 'fn main() { wrapper::go() }' > "$w/src/main.rs"

  echo "selftest: a binary that reaches hyper only transitively"

  # 1. The old grep must MISS it. If it catches it, the fixture is not testing what it
  #    claims to and this script's reason for existing is unproven.
  if grep -rniE "^(reqwest|ureq|isahc|curl|surf|hyper)\s*=" --include=Cargo.toml "$w/Cargo.toml" >/dev/null 2>&1; then
    echo "::error::selftest invalid: the grep caught the transitive fixture, so it does not"
    echo "::error::demonstrate the gap this script fills. Fix the fixture."
    return 1
  fi
  echo "  ok  the Cargo.toml grep does not see it"

  # 2. This check must CATCH it.
  local closure
  closure="$(closure_of "$w/Cargo.toml" victim)"
  if ! printf '%s\n' "$closure" | grep -qiE "$DENY"; then
    echo "::error::selftest FAILED: the closure check did not flag a transitive hyper."
    echo "::error::resolved closure was:"
    printf '    %s\n' $closure
    return 1
  fi
  echo "  ok  the closure check flags it"
  echo "selftest passed"
  return 0
}

cd "$(dirname "$0")/.."

if [ "${1:-}" = "--selftest" ]; then
  selftest || exit 1
  exit 0
fi

# Every artefact that runs on a machine where a third-party build script also runs: this
# workspace, plus the overlay's second tree when BUILDCLAMP_OVERLAY names one (see
# crates/cli/tests/overlay/mod.rs). Without it, this workspace alone.
manifests="Cargo.toml"
if [ -n "${BUILDCLAMP_OVERLAY:-}" ] && [ -f "$BUILDCLAMP_OVERLAY/CLAIMS.toml" ]; then
  second="$(sed -n '/^closed_tree = "/{s/^closed_tree = "//;s/"$//;p;}' "$BUILDCLAMP_OVERLAY/CLAIMS.toml")"
  [ -n "$second" ] && manifests="$manifests $second/Cargo.toml"
fi
checked=0
for manifest in $manifests; do
  [ -f "$manifest" ] || continue
  for pkg in $(discover_bins "$manifest"); do
    check_binary "$manifest" "$pkg" "$manifest"
    checked=$((checked + 1))
  done
done

if [ "$checked" -eq 0 ]; then
  echo "::error::no binary packages were discovered, so this check proved nothing"
  exit 1
fi

exit $fail
