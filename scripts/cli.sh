#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# rowsafe CLI installer for macOS and Linux, served at https://rowsafe.sh/cli
#
#   curl -fsSL https://rowsafe.sh/cli | sh
#
# Downloads the rowsafe CLI for this computer from the latest GitHub release
# of rowsafe/rowsafe, checks it against the release's SHA256SUMS, and puts it
# on your PATH. No sudo needed. Run it again to update.
#
# Where it goes: /usr/local/bin when you can write there (or run as root),
# otherwise ~/.local/bin, added to your shell's PATH if it isn't on it yet.
#
# Environment:
#   ROWSAFE_VERSION      a version such as 0.10.12 (default: the latest)
#   ROWSAFE_INSTALL_DIR  install into this folder instead
#   ROWSAFE_NO_MODIFY_PATH=1  never change a shell profile
set -eu

REPO=rowsafe/rowsafe
DOWNLOAD_BASE=${ROWSAFE_DOWNLOAD_BASE:-https://github.com/$REPO/releases/download}
LATEST_URL=${ROWSAFE_LATEST_URL:-https://github.com/$REPO/releases/latest}
PROTO=${ROWSAFE_CURL_PROTO:-=https} # tests serve a fake release over http

say() { printf '%s\n' "$*"; }
die() {
  printf 'rowsafe: %s\n' "$*" >&2
  exit 1
}

fetch() { # URL FILE
  curl -fsSL --proto "$PROTO" --tlsv1.2 --retry 3 --retry-delay 2 \
    --connect-timeout 20 --max-time 300 -o "$2" "$1"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

detect_platform() {
  case $(uname -s) in
    Darwin) OS=darwin ;;
    Linux) OS=linux ;;
    *) die "the rowsafe CLI runs on macOS and Linux (this is $(uname -s)). On Windows, use WSL." ;;
  esac
  case $(uname -m) in
    x86_64 | amd64) ARCH=amd64 ;;
    arm64 | aarch64) ARCH=arm64 ;;
    *) die "the rowsafe CLI is built for x86-64 and ARM64 (this is $(uname -m))" ;;
  esac
  # A shell running under Rosetta reports x86_64 on Apple silicon: install
  # the native build.
  if [ "$OS" = darwin ] && [ "$ARCH" = amd64 ] &&
    [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
    ARCH=arm64
  fi
}

# latest_version follows github.com/OWNER/REPO/releases/latest to the newest
# release's tag (no API call, so no rate limit).
latest_version() {
  url=$(curl -fsS --proto "$PROTO" --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 60 \
    -o /dev/null -w '%{redirect_url}' "$LATEST_URL") || return 1
  url=${url##*/tag/v}
  printf '%s\n' "$url" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || return 1
  printf '%s\n' "$url"
}

on_path() { # DIR
  case ":$PATH:" in *":$1:"*) return 0 ;; esac
  return 1
}

pick_dir() {
  if [ -n "${ROWSAFE_INSTALL_DIR:-}" ]; then
    DIR=$ROWSAFE_INSTALL_DIR
  elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    DIR=/usr/local/bin
  elif [ "$(id -u)" -eq 0 ]; then
    DIR=/usr/local/bin
  else
    [ -n "${HOME:-}" ] || die "HOME isn't set; set ROWSAFE_INSTALL_DIR to a folder on your PATH"
    DIR=$HOME/.local/bin
  fi
  mkdir -p "$DIR" || die "couldn't create $DIR; set ROWSAFE_INSTALL_DIR to a folder you can write"
  [ -w "$DIR" ] || die "can't write to $DIR; set ROWSAFE_INSTALL_DIR to a folder you can write"
}

# add_to_path adds DIR to the PATH in the profile of the user's login shell,
# once, unless ROWSAFE_NO_MODIFY_PATH is set. PATH_NOTE says what to do next.
add_to_path() {
  PATH_NOTE=''
  on_path "$DIR" && return 0
  line="export PATH=\"$DIR:\$PATH\""
  case ${SHELL:-} in
    */zsh) profile=${ZDOTDIR:-$HOME}/.zshrc ;;
    */bash) if [ "$OS" = darwin ]; then profile=$HOME/.bash_profile; else profile=$HOME/.bashrc; fi ;;
    */fish)
      profile=$HOME/.config/fish/conf.d/rowsafe.fish
      line="fish_add_path \"$DIR\""
      ;;
    *) profile=$HOME/.profile ;;
  esac
  if [ "${ROWSAFE_NO_MODIFY_PATH:-}" = 1 ]; then
    PATH_NOTE="Add $DIR to your PATH: $line"
    return 0
  fi
  if [ -f "$profile" ] && grep -qF "$line" "$profile" 2>/dev/null; then
    :
  else
    mkdir -p "$(dirname "$profile")"
    printf '\n# rowsafe CLI\n%s\n' "$line" >>"$profile" || {
      PATH_NOTE="Add $DIR to your PATH: $line"
      return 0
    }
    say "Added $DIR to your PATH in $profile."
  fi
  PATH_NOTE="Open a new terminal (or run: $line), then:"
}

main() {
  command -v curl >/dev/null 2>&1 || die "curl is needed to download the CLI"
  detect_platform

  version=${ROWSAFE_VERSION:-latest}
  version=${version#v}
  if [ "$version" = latest ] || [ -z "$version" ]; then
    version=$(latest_version) || die "couldn't find the latest release on GitHub; try again, or set ROWSAFE_VERSION (e.g. 0.10.12)"
  fi
  printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "ROWSAFE_VERSION should look like 0.10.12, not $version"

  asset=rowsafe-$OS-$ARCH
  tmp=$(mktemp -d 2>/dev/null || mktemp -d -t rowsafe)
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 1' INT TERM

  say "Downloading rowsafe $version for $OS/$ARCH..."
  fetch "$DOWNLOAD_BASE/v$version/$asset" "$tmp/rowsafe" || die "couldn't download $asset $version from GitHub"
  fetch "$DOWNLOAD_BASE/v$version/SHA256SUMS" "$tmp/SHA256SUMS" || die "couldn't download the release's SHA256SUMS"
  want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/SHA256SUMS")
  [ -n "$want" ] || die "$asset isn't listed in the release's SHA256SUMS"
  got=$(sha256_of "$tmp/rowsafe")
  [ "$got" = "$want" ] || die "the download doesn't match the release's SHA256SUMS (got $got, want $want); nothing was installed"
  chmod 755 "$tmp/rowsafe"
  "$tmp/rowsafe" version >/dev/null 2>&1 || die "the downloaded CLI doesn't run on this computer; nothing was installed"

  pick_dir
  # Move into place in one step, so a running rowsafe is never half-written.
  if ! cp "$tmp/rowsafe" "$DIR/.rowsafe.new.$$" || ! mv -f "$DIR/.rowsafe.new.$$" "$DIR/rowsafe"; then
    rm -f "$DIR/.rowsafe.new.$$"
    die "couldn't write $DIR/rowsafe; set ROWSAFE_INSTALL_DIR to a folder you can write"
  fi
  say "Installed rowsafe $version in $DIR/rowsafe."

  other=$(command -v rowsafe 2>/dev/null || true)
  if [ -n "$other" ] && [ "$other" != "$DIR/rowsafe" ] && on_path "$DIR"; then
    say "Note: $other comes first on your PATH; remove it to use this one."
  fi

  add_to_path
  say ''
  [ -z "$PATH_NOTE" ] || say "$PATH_NOTE"
  say "  rowsafe login"
}

main "$@"
