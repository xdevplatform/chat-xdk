#!/usr/bin/env bash
#
# Unified version management for all chat-xdk bindings.
#
# The canonical version lives in the workspace Cargo.toml ([workspace.package]).
# This script reads it and stamps every binding manifest to match, so all
# packages (crates.io, PyPI, npm, NuGet, Maven, Go tag) release in lockstep.
#
# Usage:
#   scripts/version.sh get                 # print current version
#   scripts/version.sh set 1.2.3           # set an exact version
#   scripts/version.sh bump patch|minor|major|beta|none   (none: keep current)
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CARGO_TOML="$ROOT_DIR/Cargo.toml"
CARGO_LOCK="$ROOT_DIR/Cargo.lock"
PYPROJECT="$ROOT_DIR/crates/pyo3/pyproject.toml"
NPM_PKG="$ROOT_DIR/crates/wasm/js/package.json"
POM="$ROOT_DIR/crates/jvm/java/chatxdk/pom.xml"
CSPROJ="$ROOT_DIR/crates/dotnet/dotnet/ChatXdk/ChatXdk.csproj"
EXAMPLE_POM="$ROOT_DIR/examples/jvm/pom.xml"

get_current_version() {
  perl -ne 'if (/^\[workspace\.package\]/){$f=1;next} if (/^\[/){$f=0} if ($f && /^version\s*=\s*"([^"]+)"/){print $1;exit}' "$CARGO_TOML"
}

compute_bump() {
  local current="$1" kind="$2"
  if [[ ! "$current" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-([A-Za-z0-9.]+))?$ ]]; then
    echo "error: cannot parse current version '$current'" >&2
    exit 1
  fi
  local major="${BASH_REMATCH[1]}" minor="${BASH_REMATCH[2]}" patch="${BASH_REMATCH[3]}" pre="${BASH_REMATCH[5]:-}"
  case "$kind" in
    none) echo "$current" ;;
    patch) echo "$major.$minor.$((patch + 1))" ;;
    minor) echo "$major.$((minor + 1)).0" ;;
    major) echo "$((major + 1)).0.0" ;;
    beta)
      if [[ "$pre" =~ ^beta\.([0-9]+)$ ]]; then
        echo "$major.$minor.$patch-beta.$(( ${BASH_REMATCH[1]} + 1 ))"
      else
        echo "$major.$minor.$((patch + 1))-beta.1"
      fi
      ;;
    *) echo "error: unknown bump kind '$kind'" >&2; exit 1 ;;
  esac
}

# In-place replace first match of a pattern using perl (portable: macOS + Linux).
set_version() {
  local v="$1"
  # Maven Central rejects only -SNAPSHOT versions; prerelease qualifiers like
  # -beta.N are ordinary immutable versions and must be stamped verbatim, or a
  # beta release would publish (and burn) the final version number.
  local maven_v="$v"
  if [[ "$maven_v" == *-SNAPSHOT ]]; then
    echo "error: refusing to stamp a -SNAPSHOT version into the pom" >&2
    exit 1
  fi

  # Cargo workspace package version (only the [workspace.package] one, at line start).
  perl -0pi -e "s/(\\[workspace\\.package\\][^\\[]*?\\nversion\\s*=\\s*\")[^\"]*(\")/\${1}$v\${2}/s" "$CARGO_TOML"
  # chat-xdk-macros workspace-dependency version (required by cargo publish for
  # path dependencies; must track the workspace version).
  perl -pi -e "s/^(chat-xdk-macros\\s*=.*version\\s*=\\s*\")[^\"]*(\")/\${1}$v\${2}/" "$CARGO_TOML"
  # Lockfile entries for the workspace members (every chat-xdk-* package pins
  # the workspace version). Stamped textually rather than via `cargo update`
  # so the script works without a toolchain or the juicebox-sdk sibling
  # checkout; without this, the stamped Cargo.toml and the committed
  # Cargo.lock disagree and `--locked` builds of the release tag fail.
  # Workspace members carry no `source` line in the lock; the lookahead skips
  # any registry crate that happens to share the name prefix (these crates are
  # also published to crates.io), whose pinned version must not be touched.
  perl -0pi -e "s/(name = \"chat-xdk[^\"]*\"\\nversion = \")[^\"]*(\")(?!\\nsource)/\${1}$v\${2}/g" "$CARGO_LOCK"
  # A silent stamp miss (e.g. a lockfile format change) would quietly
  # reintroduce the manifest/lockfile mismatch, so verify the result.
  local lock_v
  lock_v="$(perl -0ne 'print $1 if /name = "chat-xdk-core"\nversion = "([^"]+)"/' "$CARGO_LOCK")"
  if [[ "$lock_v" != "$v" ]]; then
    echo "error: Cargo.lock stamp failed (chat-xdk-core at '${lock_v:-missing}', expected '$v')" >&2
    exit 1
  fi
  # PyPI project version.
  perl -pi -e "s/^version\\s*=\\s*\"[^\"]*\"/version = \"$v\"/ if !\$done && /^version\\s*=/; \$done=1 if /^version\\s*=/" "$PYPROJECT"
  # npm package version (first "version" key).
  perl -0pi -e "s/\"version\":\\s*\"[^\"]*\"/\"version\": \"$v\"/" "$NPM_PKG"
  # Maven project version (first <version> only).
  perl -0pi -e "s{<version>.*?</version>}{<version>$maven_v</version>}s" "$POM"
  # .NET package version.
  perl -0pi -e "s{<Version>.*?</Version>}{<Version>$v</Version>}s" "$CSPROJ"
  # JVM example's chatxdk.version property (Maven cannot express a path
  # dependency, so the example pins the locally installed jar's version).
  perl -0pi -e "s{<chatxdk\.version>[^<]*</chatxdk\.version>}{<chatxdk.version>$maven_v</chatxdk.version>}s" "$EXAMPLE_POM"
}

print_all() {
  echo "canonical (Cargo.toml):  $(get_current_version)"
  echo "lockfile (Cargo.lock):   $(perl -0ne 'print $1 if /name = "chat-xdk-core"\nversion = "([^"]+)"/' "$CARGO_LOCK")"
  echo "macros dep (Cargo.toml): $(perl -ne 'print $1 if /^chat-xdk-macros\s*=.*version\s*=\s*"([^"]+)"/' "$CARGO_TOML")"
  echo "python (pyproject):      $(perl -ne 'print $1 if /^version\s*=\s*"([^"]+)"/' "$PYPROJECT")"
  echo "npm (package.json):      $(perl -0ne 'print $1 if /"version":\s*"([^"]+)"/' "$NPM_PKG")"
  echo "jvm (pom.xml):           $(perl -0ne 'print $1 if m{<version>(.*?)</version>}s' "$POM")"
  echo "dotnet (csproj):         $(perl -0ne 'print $1 if m{<Version>(.*?)</Version>}s' "$CSPROJ")"
  echo "go:                      (tag-based: go/chatxdk/v<version>)"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    get) get_current_version; echo ;;
    list) print_all ;;
    set)
      local v="${2:?usage: version.sh set X.Y.Z}"
      set_version "$v"
      echo "Set all bindings to $v:"
      print_all
      ;;
    bump)
      local kind="${2:?usage: version.sh bump patch|minor|major|beta}"
      local current new
      current="$(get_current_version)"
      new="$(compute_bump "$current" "$kind")"
      set_version "$new"
      echo "Bumped $current -> $new:"
      print_all
      ;;
    *)
      echo "Usage: $0 {get|list|set <version>|bump <patch|minor|major|beta>}" >&2
      exit 1
      ;;
  esac
}

main "$@"
