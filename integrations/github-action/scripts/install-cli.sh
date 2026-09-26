#!/usr/bin/env bash
# Installs the rowsafe CLI for the Rowsafe GitHub Action.
#
#   install-cli.sh resolve   pick the version and platform, and say whether
#                            actions/cache should restore the CLI
#   install-cli.sh install   use the cached CLI or download it; verify it;
#                            put it on PATH
#
# The CLI comes from the GitHub release of rowsafe/rowsafe. Before it runs,
# it is checked two ways:
#   1. its SHA-256 against the release's SHA256SUMS (downloaded fresh on
#      every run, also when the CLI came from the cache);
#   2. its SLSA build provenance with `gh attestation verify`: GitHub Actions
#      built exactly this file from rowsafe/rowsafe with the release workflow,
#      at this version's tag (Sigstore, public transparency log).
#
# Inputs (environment):
#   INPUT_VERSION            "latest" (default) or a version such as 0.4.0
#   INPUT_CLI_PATH           use this rowsafe binary instead (not downloaded,
#                            not verified)
#   INPUT_VERIFY_PROVENANCE  auto (default: verify when gh can), true, false
#   GH_TOKEN                 token for gh attestation verify (github.token)
set -euo pipefail

REPO=rowsafe/rowsafe
SIGNER_WORKFLOW=$REPO/.github/workflows/release.yml
DOWNLOAD_BASE=${ROWSAFE_ACTION_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download}

say() { printf '%s\n' "$*"; }
fail() {
  printf '::error title=Rowsafe::%s\n' "$*"
  exit 1
}
output() { printf '%s=%s\n' "$1" "$2" >>"${GITHUB_OUTPUT:-/dev/null}"; }

fetch() { # URL FILE
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --retry-delay 2 --retry-connrefused \
    --connect-timeout 20 --max-time 300 -o "$2" "$1"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

# platform sets PLAT, e.g. linux-amd64 (the release asset suffix).
platform() {
  local os arch
  case "${RUNNER_OS:-$(uname -s)}" in
    Linux) os=linux ;;
    macOS | Darwin) os=darwin ;;
    *) fail "The Rowsafe action runs on Linux and macOS runners (this one is ${RUNNER_OS:-$(uname -s)}). Use runs-on: ubuntu-latest for this job." ;;
  esac
  case "${RUNNER_ARCH:-$(uname -m)}" in
    X64 | x86_64 | amd64) arch=amd64 ;;
    ARM64 | arm64 | aarch64) arch=arm64 ;;
    *) fail "The rowsafe CLI is built for x64 and ARM64 runners (this one is ${RUNNER_ARCH:-$(uname -m)})." ;;
  esac
  PLAT=$os-$arch
}

# latest_version follows github.com/OWNER/REPO/releases/latest to the newest
# release's tag (no API call, so no rate limit).
latest_version() {
  local url
  url=$(curl -fsS --proto '=https' --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 60 \
    -o /dev/null -w '%{redirect_url}' "https://github.com/$REPO/releases/latest") || return 1
  url=${url##*/tag/v}
  printf '%s\n' "$url" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || return 1
  printf '%s\n' "$url"
}

resolve() {
  local version=${INPUT_VERSION:-latest} plat dir
  platform
  plat=$PLAT
  output platform "$plat"
  if [ -n "${INPUT_CLI_PATH:-}" ]; then
    output version local
    output cache false
    return
  fi
  version=${version#v}
  if [ "$version" = latest ] || [ -z "$version" ]; then
    version=$(latest_version) || fail "Couldn't find the latest rowsafe release on GitHub. Set the version input (e.g. version: 0.4.0) or try again."
  fi
  printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' ||
    fail "version must be \"latest\" or a release such as 0.4.0 (got \"${INPUT_VERSION}\")."
  dir="${RUNNER_TOOL_CACHE:-${RUNNER_TEMP:-/tmp}}/rowsafe/$version/$plat"
  output version "$version"
  output dir "$dir"
  # A self-hosted runner may already have it in its tool cache.
  if [ -x "$dir/rowsafe" ]; then output cache false; else output cache true; fi
}

verify_provenance() { # FILE VERSION
  local mode=${INPUT_VERIFY_PROVENANCE:-auto} signer
  case $mode in
    false) say "  provenance: not checked (verify-provenance: false)"; return ;;
    auto | true) ;;
    *) fail "verify-provenance must be auto, true or false (got \"$mode\")." ;;
  esac
  if ! command -v gh >/dev/null 2>&1 || ! gh attestation verify --help >/dev/null 2>&1; then
    [ "$mode" = true ] && fail "verify-provenance is true, but this runner has no GitHub CLI with 'gh attestation'. Install gh 2.49 or later, or set verify-provenance: auto."
    say "::warning title=Rowsafe::The CLI's checksum matches, but its build provenance wasn't checked: this runner has no GitHub CLI (gh 2.49+)."
    return
  fi
  if [ -z "${GH_TOKEN:-}" ]; then
    [ "$mode" = true ] && fail "verify-provenance is true, but there is no GitHub token to look up attestations. Pass github-token."
    say "::warning title=Rowsafe::The CLI's checksum matches, but its build provenance wasn't checked: no GitHub token (github-token input)."
    return
  fi
  if ! signer=$(gh attestation verify "$1" --repo "$REPO" --signer-workflow "$SIGNER_WORKFLOW" \
    --source-ref "refs/tags/v$2" --format json \
    --jq '.[0].verificationResult.signature.certificate | "\(.buildSignerURI) at commit \(.sourceRepositoryDigest)"' 2>"$TMP/gh.err"); then
    sed 's/^/  gh: /' "$TMP/gh.err"
    fail "The rowsafe CLI $2 didn't pass build provenance verification, so it wasn't run. If GitHub's API was down, re-run the job; otherwise report it: https://github.com/$REPO/security/advisories/new"
  fi
  say "  provenance: built by ${signer#https://github.com/}"
}

download() { # VERSION PLATFORM DEST
  say "  downloading rowsafe $1 ($2) from github.com/$REPO"
  fetch "$DOWNLOAD_BASE/v$1/rowsafe-$2" "$TMP/rowsafe" ||
    fail "Couldn't download rowsafe $1 for $2 from GitHub. Check that release v$1 exists, or try again."
  mkdir -p "$3"
  mv "$TMP/rowsafe" "$3/rowsafe"
}

install() {
  local version=$INPUT_RESOLVED_VERSION plat=$INPUT_RESOLVED_PLATFORM dir=${INPUT_RESOLVED_DIR:-} want got bin
  bin="${RUNNER_TEMP:-/tmp}/rowsafe-action-bin"
  mkdir -p "$bin"
  if [ -n "${INPUT_CLI_PATH:-}" ]; then
    [ -x "$INPUT_CLI_PATH" ] || fail "cli-path: $INPUT_CLI_PATH is not an executable file."
    ln -sf "$(cd "$(dirname "$INPUT_CLI_PATH")" && pwd)/$(basename "$INPUT_CLI_PATH")" "$bin/rowsafe"
    say "Using the rowsafe CLI at $INPUT_CLI_PATH ($("$bin/rowsafe" version)); not downloaded, so not verified by this action."
    printf '%s\n' "$bin" >>"${GITHUB_PATH:-/dev/null}"
    output path "$bin/rowsafe"
    output cli-version "$("$bin/rowsafe" version)"
    return
  fi

  say "::group::Installing the rowsafe CLI $version ($plat)"
  fetch "$DOWNLOAD_BASE/v$version/SHA256SUMS" "$TMP/SHA256SUMS" ||
    fail "Couldn't download SHA256SUMS for rowsafe $version from GitHub. Check that release v$version exists, or try again."
  want=$(awk -v f="rowsafe-$plat" '$2 == f || $2 == "*" f { print $1 }' "$TMP/SHA256SUMS")
  printf '%s\n' "$want" | grep -Eq '^[0-9a-f]{64}$' || fail "Release v$version has no rowsafe CLI for $plat."

  if [ -x "$dir/rowsafe" ]; then
    got=$(sha256_of "$dir/rowsafe")
    if [ "$got" = "$want" ]; then
      say "  using the cached copy"
    else
      say "::warning title=Rowsafe::The cached rowsafe CLI doesn't match the release checksum; downloading it again."
      rm -f "$dir/rowsafe"
    fi
  fi
  [ -x "$dir/rowsafe" ] || download "$version" "$plat" "$dir"
  got=$(sha256_of "$dir/rowsafe")
  if [ "$got" != "$want" ]; then
    rm -f "$dir/rowsafe"
    fail "The downloaded rowsafe CLI doesn't match the release checksum (got $got, SHA256SUMS says $want), so it wasn't run. Re-run the job; if it happens again, report it."
  fi
  say "  checksum: OK ($want)"
  verify_provenance "$dir/rowsafe" "$version"
  chmod 0755 "$dir/rowsafe"
  ln -sf "$dir/rowsafe" "$bin/rowsafe"
  say "::endgroup::"
  say "rowsafe CLI $version ($plat) installed and verified."
  printf '%s\n' "$bin" >>"${GITHUB_PATH:-/dev/null}"
  output path "$bin/rowsafe"
  output cli-version "$version"
}

TMP=$(mktemp -d "${RUNNER_TEMP:-/tmp}/rowsafe-install.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

case "${1:-}" in
  resolve) resolve ;;
  install) install ;;
  *) fail "usage: install-cli.sh resolve|install" ;;
esac
