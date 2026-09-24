#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Rowsafe agent installer, served at https://rowsafe.sh (and /install)
#
#   curl -fsSL https://rowsafe.sh | sudo sh -s rse_...
#
# The argument is the one-time enrollment token from `rowsafe hosts
# enroll-token` (ROWSAFE_ENROLL_TOKEN=rse_... in the environment works too).
# ROWSAFE_URL defaults to https://api.rowsafe.sh; set it only for a
# self-hosted control plane: sudo ROWSAFE_URL=https://... sh -s rse_...
#
# Installs or upgrades rowsafe-agent on a Debian 12/13 or Ubuntu 22.04/24.04
# host (amd64 or arm64) that runs PostgreSQL. Running it again is safe: it only
# changes what differs, and it never restarts PostgreSQL.
#
# Options (when piping, pass them after `sh -s --`):
#   rse_...                the enrollment token
#   --setup-storage        (re)run the guided backup storage setup
#   --storage PROVIDER     preselect r2, b2, s3, wasabi, spaces or s3-compatible
#   --no-prompt            never ask questions, even on a terminal
#   --check-storage        test the configured backup storage; change nothing
#   --uninstall            stop and remove the agent; keep configuration and state
#   --uninstall --purge    also delete /etc/rowsafe, /var/lib/rowsafe, /var/log/rowsafe
#   --download-only DIR    download and verify the agent into DIR; install nothing
#   -h, --help
#
# Guided setup: when the backup storage isn't configured yet and a terminal is
# attached, the installer asks for it on /dev/tty (the script itself arrives on
# stdin), tests it by writing, reading and deleting a small file with
# pgBackRest, and can generate the encryption passphrase. Without a terminal
# (or with --no-prompt) it never asks and prints exactly what to set instead.
#
# Installer settings (environment):
#   ROWSAFE_VERSION         install exactly this version (default: the channel's latest)
#   ROWSAFE_CHANNEL         channel to install from (default: stable)
#   ROWSAFE_RELEASES_URL    release location (default: https://releases.rowsafe.sh/agent)
#   ROWSAFE_ALLOW_DOWNGRADE=1  allow ROWSAFE_VERSION older than the installed version
#
# Agent settings (ROWSAFE_URL, ROWSAFE_ENROLL_TOKEN, ROWSAFE_REPO_*, ...) found
# in the environment are written to /etc/rowsafe/agent.env; see AGENT_VARS.
#
# Every download is verified before anything is installed: the release
# manifest must carry a valid Ed25519 signature from the Rowsafe release key
# embedded below, and the binary must match the SHA-256 and size in that signed
# manifest. Secret values are never printed.
#
# Everything lives in functions and `main` runs on the last line, so a
# download cut short by the network runs nothing.

set -eu
umask 077

# Base64 of the raw 32-byte Ed25519 release public key. `make release` fills
# this in; the unrendered placeholder makes the installer refuse to run.
RELEASE_PUBLIC_KEY='@RELEASE_PUBLIC_KEY@'

INSTALL_DIR=/opt/rowsafe
CONFIG_DIR=/etc/rowsafe
STATE_DIR=/var/lib/rowsafe
LOG_DIR=/var/log/rowsafe
ENV_FILE=$CONFIG_DIR/agent.env
UNIT_FILE=/etc/systemd/system/rowsafe-agent.service
LOGROTATE_FILE=/etc/logrotate.d/rowsafe
GUARD_FILE=$INSTALL_DIR/bin/rowsafe-agent-guard
SERVICE=rowsafe-agent.service
AGENT_USER=postgres
DEFAULT_RELEASES_URL=https://releases.rowsafe.sh/agent
MAX_ARTIFACT_SIZE=536870912 # 512 MiB, the same limit the agent enforces

REQUIRED_REPO_VARS="ROWSAFE_REPO_S3_ENDPOINT ROWSAFE_REPO_S3_BUCKET ROWSAFE_REPO_S3_KEY ROWSAFE_REPO_S3_KEY_SECRET ROWSAFE_REPO_CIPHER_PASS"
# Agent settings copied from the installer's environment into agent.env.
AGENT_VARS="ROWSAFE_URL ROWSAFE_ENROLL_TOKEN $REQUIRED_REPO_VARS
  ROWSAFE_REPO_S3_REGION ROWSAFE_REPO_S3_URI_STYLE ROWSAFE_REPO_PATH_PREFIX
  ROWSAFE_REPO_S3_PORT ROWSAFE_REPO_S3_CA_FILE ROWSAFE_REPO_S3_VERIFY_TLS
  ROWSAFE_AUTO_UPDATE ROWSAFE_PG_USER ROWSAFE_PG_BIN_DIR ROWSAFE_PGBACKREST_BIN
  ROWSAFE_DRILL_DIR ROWSAFE_DRILL_PORT ROWSAFE_POLL_INTERVAL ROWSAFE_HEARTBEAT_INTERVAL"

PROMPT=auto        # auto: ask on a terminal when needed; never: --no-prompt
SETUP_STORAGE=0    # --setup-storage: offer to replace configured storage settings
STORAGE_PROVIDER='' # --storage: preselected provider for the guided setup
TTY=0              # 1 once /dev/tty is open on fd 3
TTY_SAVED=''       # terminal settings to restore (stty -g)
STORAGE_CLEAR=''   # agent.env keys the guided setup turns back into comments
STORAGE_GUIDED=0

TMP=
CHANGED=0          # binary, unit, guard or config changed: a running agent needs a restart
KEEP_INSTALLED=0   # the installed version is newer than the channel's: leave it
APT_UPDATED=0

# Colours only on a terminal, and never with NO_COLOR (https://no-color.org).
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != dumb ]; then
  BOLD=$(printf '\033[1m') RED=$(printf '\033[31m') YELLOW=$(printf '\033[33m') GREEN=$(printf '\033[32m') RESET=$(printf '\033[0m')
else
  BOLD='' RED='' YELLOW='' GREEN='' RESET=''
fi
# Check marks and the passphrase box need a UTF-8 locale; plain ASCII otherwise.
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
  *UTF-8* | *utf-8* | *UTF8* | *utf8*) CHECK='✓' CROSS='✗' BOX_H='─' BOX_V='│' BOX_TL='┌' BOX_TR='┐' BOX_BL='└' BOX_BR='┘' ;;
  *) CHECK='ok' CROSS='x' BOX_H='-' BOX_V='|' BOX_TL='+' BOX_TR='+' BOX_BL='+' BOX_BR='+' ;;
esac

say() { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$BOLD" "$RESET" "$*"; }
ok() { printf '    %s%s%s %s\n' "$GREEN" "$CHECK" "$RESET" "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf '%swarning:%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die() {
  printf '%serror:%s %s\n' "$RED" "$RESET" "$*" >&2
  exit 1
}

cleanup() {
  # Never leave the terminal with echo off (Ctrl-C at a hidden prompt).
  if [ "$TTY" = 1 ] && [ -n "$TTY_SAVED" ]; then stty "$TTY_SAVED" <&3 2>/dev/null || true; fi
  if [ -n "$TMP" ]; then rm -rf "$TMP"; fi
}
trap cleanup EXIT
# After Ctrl-C at a question, end the half-typed line before exiting.
trap 'if [ "$TTY" = 1 ]; then printf "\n" >&3; fi; exit 130' INT TERM

usage() {
  cat <<'EOF'
Rowsafe agent installer

  curl -fsSL https://rowsafe.sh | sudo sh -s rse_...

Options (when piping, pass them after `sh -s --`):
  rse_...                the one-time enrollment token from `rowsafe hosts enroll-token`
  --setup-storage        set up (or change) the backup storage, even if it is configured
  --storage PROVIDER     skip the "where" question: r2, b2, s3, wasabi, spaces, s3-compatible
  --no-prompt            never ask questions, even on a terminal (for automation)
  --check-storage        test the backup storage in /etc/rowsafe/agent.env; change nothing
  --uninstall            stop and remove the agent; keep configuration and state
  --uninstall --purge    also delete /etc/rowsafe, /var/lib/rowsafe and /var/log/rowsafe
  --download-only DIR    download and verify the agent into DIR; install nothing
  -h, --help             show this help

Environment:
  ROWSAFE_VERSION        install exactly this version (default: the channel's latest)
  ROWSAFE_CHANNEL        channel to install from (default: stable)
  ROWSAFE_RELEASES_URL   release location (default: https://releases.rowsafe.sh/agent)
  ROWSAFE_ALLOW_DOWNGRADE=1  allow ROWSAFE_VERSION older than the installed version
  ROWSAFE_URL, ROWSAFE_ENROLL_TOKEN, ROWSAFE_REPO_*  written to /etc/rowsafe/agent.env
                         (ROWSAFE_ENROLL_TOKEN may instead be the argument rse_...)
                         (ROWSAFE_URL defaults to https://api.rowsafe.sh)

Backup storage (guided setup):
  Run from a terminal, the installer walks you through the backup storage the
  first time: where to keep backups (Cloudflare R2, Backblaze B2, Amazon S3,
  Wasabi, DigitalOcean Spaces or any S3-compatible store), the bucket and its
  access key. It then tests the bucket by writing, reading and deleting a
  small file, and explains what to fix if that fails. Finally it creates (or
  takes) the passphrase that encrypts your backups: it is shown once, so save
  it in your password manager. Without it, backups can't be restored.

  Secrets are typed hidden and never printed. Nothing is saved until you have
  answered everything; settings go to /etc/rowsafe/agent.env (postgres, 0600).
  Run it again with --setup-storage to change the storage later.

  Without a terminal (cloud-init, CI, configuration management) or with
  --no-prompt, set ROWSAFE_REPO_S3_ENDPOINT, _BUCKET, _KEY, _KEY_SECRET and
  ROWSAFE_REPO_CIPHER_PASS in the environment instead, and check them with
  --check-storage.

Documentation: https://rowsafe.sh/docs/reference/agent-configuration
EOF
}

# ---------------------------------------------------------------- helpers

have() { command -v "$1" >/dev/null 2>&1; }

systemd_running() { [ -d /run/systemd/system ]; }

sha256_of() { sha256sum "$1" | awk '{ print $1 }'; }

size_of() { wc -c <"$1" | tr -d ' '; }

# norm_version v0.2.10 -> 0.2.10, the same normalisation the agent uses.
norm_version() {
  printf '%s\n' "$1" | grep -Eq '^v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$' || return 1
  printf '%s\n' "$1" | sed 's/^v//' | awk -F. '{ printf "%d.%d.%d\n", $1, $2, $3 }'
}

# version_cmp A B prints -1, 0 or 1.
version_cmp() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    split(a, x, "."); split(b, y, ".")
    for (i = 1; i <= 3; i++) {
      if (x[i] + 0 < y[i] + 0) { print -1; exit }
      if (x[i] + 0 > y[i] + 0) { print 1; exit }
    }
    print 0
  }'
}

# installed_version prints the version the managed symlink points at, if any.
installed_version() {
  link=$(readlink "$INSTALL_DIR/rowsafe-agent" 2>/dev/null) || return 0
  case $link in
    versions/*/rowsafe-agent) link=${link#versions/}; printf '%s\n' "${link%/rowsafe-agent}" ;;
  esac
}

fetch() {
  curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --connect-timeout 20 --max-time 900 \
    -o "$2" "$1" </dev/null
}

apt_install() {
  have apt-get || die "apt-get not found; install $* yourself and re-run"
  if [ "$APT_UPDATED" = 0 ]; then
    if ! DEBIAN_FRONTEND=noninteractive apt-get update -q >"$TMP/apt.log" 2>&1 </dev/null; then
      tail -n 20 "$TMP/apt.log" >&2
      die "apt-get update failed"
    fi
    APT_UPDATED=1
  fi
  if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "$@" >>"$TMP/apt.log" 2>&1 </dev/null; then
    tail -n 20 "$TMP/apt.log" >&2
    die "installing $* failed"
  fi
}

# write_file PATH MODE OWNER:GROUP < content. Returns 0 if the file changed.
write_file() {
  cat >"$TMP/write_file"
  if [ -f "$1" ] && cmp -s "$TMP/write_file" "$1"; then
    return 1
  fi
  install -m "$2" -o "${3%%:*}" -g "${3#*:}" "$TMP/write_file" "$1.rowsafe-new"
  mv -f "$1.rowsafe-new" "$1"
  return 0
}

# ---------------------------------------------------------------- checks

require_root() {
  [ "$(id -u)" -eq 0 ] || die "run the installer as root (e.g. pipe it to 'sudo sh')"
}

detect_arch() {
  [ "$(uname -s)" = Linux ] || die "the Rowsafe agent runs on Linux"
  case $(uname -m) in
    x86_64 | amd64) ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) die "unsupported CPU architecture $(uname -m); Rowsafe ships linux/amd64 and linux/arm64" ;;
  esac
}

detect_os() {
  [ -r /etc/os-release ] || die "cannot read /etc/os-release"
  # shellcheck disable=SC1091
  OS_ID=$(. /etc/os-release && printf '%s' "${ID:-}")
  # shellcheck disable=SC1091
  OS_VERSION=$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")
  # shellcheck disable=SC1091
  OS_NAME=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-$OS_ID $OS_VERSION}")
  case "$OS_ID $OS_VERSION" in
    "debian 12" | "debian 13" | "ubuntu 22.04" | "ubuntu 24.04") ;;
    *)
      if [ "${ROWSAFE_ALLOW_UNSUPPORTED_OS:-}" = 1 ]; then
        warn "$OS_NAME is not a supported system; continuing because ROWSAFE_ALLOW_UNSUPPORTED_OS=1"
      else
        die "$OS_NAME is not supported (Debian 12/13, Ubuntu 22.04/24.04). Set ROWSAFE_ALLOW_UNSUPPORTED_OS=1 to try anyway."
      fi
      ;;
  esac
}

# check_postgres finds the postgres OS user and the installed server majors.
check_postgres() {
  id -u "$AGENT_USER" >/dev/null 2>&1 ||
    die "no '$AGENT_USER' user on this host. Rowsafe adopts an existing PostgreSQL; install PostgreSQL first."
  PG_MAJORS=''
  for bin in /usr/lib/postgresql/*/bin/postgres; do
    [ -x "$bin" ] || continue
    major=${bin#/usr/lib/postgresql/}
    PG_MAJORS="$PG_MAJORS ${major%%/*}"
  done
  PG_MAJORS=${PG_MAJORS# }
  if [ -z "$PG_MAJORS" ] && [ -z "${ROWSAFE_PG_BIN_DIR:-}" ]; then
    die "no PostgreSQL server found under /usr/lib/postgresql. Restore drills need the server binaries (pg_ctl); set ROWSAFE_PG_BIN_DIR if they live elsewhere."
  fi
}

ensure_base_tools() {
  missing=''
  have curl || missing="$missing curl"
  have openssl || missing="$missing openssl"
  [ -e /etc/ssl/certs/ca-certificates.crt ] || missing="$missing ca-certificates"
  if [ -n "$missing" ]; then
    step "Installing${missing}"
    # shellcheck disable=SC2086
    apt_install $missing
  fi
  check_openssl
}

check_openssl() {
  have openssl || die "openssl is required to verify release signatures"
  v=$(openssl version 2>/dev/null || true)
  case $v in
    "OpenSSL 3."* | "OpenSSL 4."*) ;;
    *) die "OpenSSL 3 or newer is required to verify release signatures (found: ${v:-nothing})" ;;
  esac
  have curl || die "curl is required"
  have sha256sum || die "sha256sum is required"
  have base64 || die "base64 is required"
}

# ---------------------------------------------------------------- release

# verify_signature MANIFEST SIGFILE checks the Ed25519 signature against the
# key built into this script. Nothing from the manifest is read before this.
verify_signature() {
  case $RELEASE_PUBLIC_KEY in
    *@*) die "this copy of the installer has no release key built in. Use https://rowsafe.sh/install (or one rendered by 'make release')." ;;
  esac
  printf '%s' "$RELEASE_PUBLIC_KEY" | grep -Eq '^[A-Za-z0-9+/]{43}=$' ||
    die "the release public key built into this installer is malformed"
  # An Ed25519 SubjectPublicKeyInfo is the fixed 12-byte DER header
  # 302a300506032b6570032100 followed by the 32 raw key bytes. 12 bytes is a
  # multiple of 3, so the header's base64 (MCowBQYDK2VwAyEA) can be put in
  # front of the key's base64 to get the PEM body directly.
  printf '%s\n%s\n%s\n' '-----BEGIN PUBLIC KEY-----' "MCowBQYDK2VwAyEA$RELEASE_PUBLIC_KEY" \
    '-----END PUBLIC KEY-----' >"$TMP/release.pub"

  tr -d ' \t\r\n' <"$2" >"$TMP/signature.b64"
  grep -Eq '^[A-Za-z0-9+/]{86}==$' "$TMP/signature.b64" || die "the release signature is malformed"
  base64 -d <"$TMP/signature.b64" >"$TMP/signature.bin" 2>/dev/null || die "the release signature is malformed"
  [ "$(size_of "$TMP/signature.bin")" = 64 ] || die "the release signature is malformed"

  if ! openssl pkeyutl -verify -pubin -inkey "$TMP/release.pub" -rawin \
    -in "$1" -sigfile "$TMP/signature.bin" >/dev/null 2>&1; then
    die "the release manifest's signature is INVALID. Refusing to install; nothing was changed."
  fi
}

# parse_manifest reads the verified manifest (protocol.ReleaseManifest).
# Release manifests contain no whitespace inside values, so deleting all
# whitespace yields compact JSON that sed can pick apart reliably.
parse_manifest() {
  flat=$(tr -d ' \t\r\n' <"$1")
  v=$(printf '%s\n' "$flat" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
  REL_VERSION=$(norm_version "$v") || die "the signed manifest has an invalid version '$v'"
  art=$(printf '%s\n' "$flat" | sed -n "s|.*\"linux/$ARCH\":{\([^}]*\)}.*|\1|p")
  [ -n "$art" ] || die "release $REL_VERSION has no build for linux/$ARCH"
  REL_URL=$(printf '%s\n' "$art" | sed -n 's/.*"url":"\([^"]*\)".*/\1/p')
  REL_SHA=$(printf '%s\n' "$art" | sed -n 's/.*"sha256":"\([^"]*\)".*/\1/p')
  REL_SIZE=$(printf '%s\n' "$art" | sed -n 's/.*"size":\([0-9]*\).*/\1/p')
  printf '%s\n' "$REL_URL" | grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~/%+-]+$' ||
    die "the signed manifest has an invalid download URL for linux/$ARCH"
  printf '%s\n' "$REL_SHA" | grep -Eq '^[0-9a-f]{64}$' ||
    die "the signed manifest has an invalid sha256 for linux/$ARCH"
  printf '%s\n' "$REL_SIZE" | grep -Eq '^[1-9][0-9]{0,9}$' && [ "$REL_SIZE" -le "$MAX_ARTIFACT_SIZE" ] ||
    die "the signed manifest has an implausible size for linux/$ARCH"
}

# resolve_release downloads and verifies the manifest for ROWSAFE_VERSION or
# the channel. It changes nothing on the host.
resolve_release() {
  base=${ROWSAFE_RELEASES_URL:-$DEFAULT_RELEASES_URL}
  base=${base%/}
  case $base in https://*) ;; *) die "ROWSAFE_RELEASES_URL must be an https URL" ;; esac
  WANT_VERSION=''
  if [ -n "${ROWSAFE_VERSION:-}" ]; then
    WANT_VERSION=$(norm_version "$ROWSAFE_VERSION") || die "ROWSAFE_VERSION must look like 1.2.3 (got '$ROWSAFE_VERSION')"
    where=$WANT_VERSION
  else
    where=${ROWSAFE_CHANNEL:-stable}
    printf '%s\n' "$where" | grep -Eq '^[a-z0-9][a-z0-9-]{0,31}$' || die "invalid ROWSAFE_CHANNEL '$where'"
  fi
  RELEASE_SOURCE=$where

  step "Fetching the signed release manifest ($where)"
  fetch "$base/$where/manifest.json" "$TMP/manifest.json" ||
    die "could not download $base/$where/manifest.json"
  fetch "$base/$where/manifest.json.sig" "$TMP/manifest.json.sig" ||
    die "could not download $base/$where/manifest.json.sig"
  verify_signature "$TMP/manifest.json" "$TMP/manifest.json.sig"
  parse_manifest "$TMP/manifest.json"
  if [ -n "$WANT_VERSION" ] && [ "$REL_VERSION" != "$WANT_VERSION" ]; then
    die "asked for $WANT_VERSION but the signed manifest is for $REL_VERSION"
  fi
  ok "manifest for $REL_VERSION is signed by the Rowsafe release key"
}

# download_binary fetches the artifact into $TMP and checks it against the
# signed manifest.
download_binary() {
  step "Downloading rowsafe-agent $REL_VERSION (linux/$ARCH)"
  fetch "$REL_URL" "$TMP/rowsafe-agent" || die "could not download $REL_URL"
  got=$(size_of "$TMP/rowsafe-agent")
  [ "$got" = "$REL_SIZE" ] || die "downloaded $got bytes but the signed manifest says $REL_SIZE; refusing to install"
  got=$(sha256_of "$TMP/rowsafe-agent")
  [ "$got" = "$REL_SHA" ] || die "checksum mismatch (got $got, signed manifest says $REL_SHA); refusing to install"
  chmod 0755 "$TMP/rowsafe-agent"
  ok "SHA-256 and size match the signed manifest"
}

# ---------------------------------------------------------------- install

ensure_pgbackrest() {
  if ! have pgbackrest; then
    if grep -Eqs 'apt\.postgresql\.org' /etc/apt/sources.list /etc/apt/sources.list.d/*; then
      src="the PostgreSQL apt repository (apt.postgresql.org)"
    else
      src="the $OS_ID archive"
    fi
    step "Installing pgBackRest from $src"
    apt_install pgbackrest
  fi
  PGBR_VERSION=$(pgbackrest version 2>/dev/null | sed -n 's/^pgBackRest //p')
  ok "pgBackRest ${PGBR_VERSION:-(unknown version)} at $(command -v pgbackrest)"
  pgbr_bin=${ROWSAFE_PGBACKREST_BIN:-/usr/bin/pgbackrest}
  [ -x "$pgbr_bin" ] ||
    warn "the agent runs $pgbr_bin, which does not exist; set ROWSAFE_PGBACKREST_BIN in $ENV_FILE"
  # PostgreSQL 18 support arrived in pgBackRest 2.55.0. Rowsafe is tested
  # against the current apt.postgresql.org release (2.59).
  case " $PG_MAJORS " in
    *" 18 "*)
      if [ -n "$PGBR_VERSION" ] && have dpkg && dpkg --compare-versions "$PGBR_VERSION" lt 2.55.0; then
        warn "pgBackRest $PGBR_VERSION predates PostgreSQL 18 support (2.55.0). Install pgbackrest from apt.postgresql.org before adopting a PostgreSQL 18 cluster."
      fi
      ;;
  esac
}

# install_binary puts the verified binary under versions/ (unless an
# identical one is already there). It does not switch the symlink.
install_binary() {
  vdir=$INSTALL_DIR/versions/$REL_VERSION
  STAGED=$vdir/rowsafe-agent
  install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$vdir"
  install -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$TMP/rowsafe-agent" "$vdir/.rowsafe-agent.install"
  mv -f "$vdir/.rowsafe-agent.install" "$STAGED"
  CHANGED=1
}

# switch_version points the managed symlink at the staged version, the same
# atomic swap the agent's self-update uses.
switch_version() {
  target=versions/$REL_VERSION/rowsafe-agent
  [ "$(readlink "$INSTALL_DIR/rowsafe-agent" 2>/dev/null || true)" = "$target" ] && return 0
  ln -sfn "$target" "$INSTALL_DIR/rowsafe-agent.install"
  chown -h "$AGENT_USER:$AGENT_USER" "$INSTALL_DIR/rowsafe-agent.install"
  mv -Tf "$INSTALL_DIR/rowsafe-agent.install" "$INSTALL_DIR/rowsafe-agent"
  # A manual install supersedes any self-update that was in flight.
  rm -rf "$STATE_DIR/update/pending"
  CHANGED=1
  ok "$INSTALL_DIR/rowsafe-agent -> $target"
}

make_dirs() {
  install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$INSTALL_DIR" "$INSTALL_DIR/versions"
  install -d -m 0755 -o root -g root "$INSTALL_DIR/bin"
  install -d -m 0750 -o root -g "$AGENT_USER" "$CONFIG_DIR"
  install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$CONFIG_DIR/pgbackrest" "$STATE_DIR" "$LOG_DIR"
}

install_guard() {
  if write_file "$GUARD_FILE" 0755 root:root <<'ROWSAFE_GUARD_EOF'; then
#!/bin/sh
# rowsafe-agent-guard: systemd ExecStartPre for rowsafe-agent.
#
# After a self-update the agent writes an update/pending directory and
# restarts into the new version. If that version keeps dying before it
# confirms itself, this script (which does not depend on the agent binary)
# switches the symlink back to the previous version.
#
# It always exits 0 so it can never be the reason the agent fails to start.

install_dir=${ROWSAFE_INSTALL_DIR:-/opt/rowsafe}
state_dir=${ROWSAFE_STATE_DIR:-/var/lib/rowsafe}/update
max_boots=${ROWSAFE_UPDATE_MAX_BOOTS:-3}
pending=$state_dir/pending

[ -d "$pending" ] || exit 0

boots=$(cat "$pending/boots" 2>/dev/null || echo 0)
case $boots in ''|*[!0-9]*) boots=0 ;; esac
boots=$((boots + 1))
echo "$boots" > "$pending/boots" 2>/dev/null

[ "$boots" -le "$max_boots" ] && exit 0

previous=$(cat "$pending/previous" 2>/dev/null)
target=$(cat "$pending/target" 2>/dev/null)
case $previous in
  versions/*/rowsafe-agent) ;;
  *) echo "rowsafe-agent-guard: invalid previous version path '$previous'; not rolling back" >&2; exit 0 ;;
esac
if [ ! -x "$install_dir/$previous" ]; then
  echo "rowsafe-agent-guard: $install_dir/$previous is missing; cannot roll back" >&2
  exit 0
fi

# Atomic swap: build the new link beside the old one, then rename over it.
# shellcheck disable=SC2015 # the { } block runs if either step fails, as intended
ln -sfn "$previous" "$install_dir/rowsafe-agent.guard" &&
  mv -f "$install_dir/rowsafe-agent.guard" "$install_dir/rowsafe-agent" || {
  echo "rowsafe-agent-guard: rollback symlink swap failed" >&2
  exit 0
}
printf '%s %s\n' "$target" "$boots" > "$state_dir/guard-rollback"
rm -rf "$pending"
echo "rowsafe-agent-guard: version $target failed to start $boots times; rolled back to $previous" >&2
exit 0
ROWSAFE_GUARD_EOF
    CHANGED=1
  fi
}

install_unit() {
  if write_file "$UNIT_FILE" 0644 root:root <<'ROWSAFE_UNIT_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-agent: the Rowsafe database host agent.
#
# Installed by https://rowsafe.sh/install as
# /etc/systemd/system/rowsafe-agent.service, which the installer overwrites.
# Put local changes in a drop-in: systemctl edit rowsafe-agent

[Unit]
Description=Rowsafe agent (PostgreSQL backups, WAL archiving and restore drills)
Documentation=https://rowsafe.sh/docs/reference/agent-configuration
Wants=network-online.target
# Ordering only: the agent must keep running (and reporting) while
# PostgreSQL is down, so it does not require it.
After=network-online.target postgresql.service
# Never give up restarting: backups and monitoring must recover on their own.
StartLimitIntervalSec=0

[Service]
Type=simple
User=postgres
Group=postgres
EnvironmentFile=/etc/rowsafe/agent.env
# Rolls the symlink back to the previous version when a self-update keeps
# crashing before it confirms itself. It always exits 0.
ExecStartPre=/opt/rowsafe/bin/rowsafe-agent-guard
# A symlink into /opt/rowsafe/versions/ that self-update swaps atomically.
ExecStart=/opt/rowsafe/rowsafe-agent run
# The agent exits 0 to switch versions after an update, so restart on success too.
Restart=always
RestartSec=5
# Stop pgBackRest and a drill's scratch PostgreSQL together with the agent
# (they run in this unit's cgroup), and give a drill time to clean up.
KillMode=control-group
TimeoutStopSec=120
UMask=0077
# Production comes first. If the host runs out of memory, the kernel kills
# the agent, pgBackRest or a drill's scratch PostgreSQL (all in this unit)
# before production PostgreSQL. Under contention they also get less CPU and IO.
OOMScoreAdjust=500
CPUWeight=50
IOWeight=50

# Hardening. The agent needs to: write pgBackRest configs to
# /etc/rowsafe/pgbackrest, swap its own symlink and versions in /opt/rowsafe,
# keep state and run drills under /var/lib/rowsafe, write logs to
# /var/log/rowsafe, read the PostgreSQL data directory (pgBackRest) and
# connect to PostgreSQL's Unix socket.
NoNewPrivileges=yes
# /usr, /boot and /etc read-only, with the exceptions below. /var stays
# writable (drills, logs, pgBackRest reading the data directory).
ProtectSystem=full
ReadWritePaths=/etc/rowsafe /opt/rowsafe -/var/lib/rowsafe -/var/log/rowsafe
ProtectHome=yes
# No PrivateTmp: pgBackRest's lock files live in /tmp/pgbackrest and must be
# shared with the archive-push commands PostgreSQL runs outside this unit.
PrivateTmp=no
# A private /dev with only pseudo devices; /dev/shm (needed by a drill's
# PostgreSQL) is still shared.
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
# Unix sockets for PostgreSQL, IP for the control plane and the S3
# repository, netlink for glibc's address lookups.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=
AmbientCapabilities=
# Deliberately unset: SystemCallFilter and MemoryDenyWriteExecute. A drill
# starts a full PostgreSQL with production's shared_preload_libraries (and
# JIT); a filter that breaks an extension would look like a failed restore.

[Install]
WantedBy=multi-user.target
ROWSAFE_UNIT_EOF
    CHANGED=1
    UNIT_CHANGED=1
  fi
}

install_logrotate() {
  if [ ! -d /etc/logrotate.d ]; then
    warn "logrotate is not installed; pgBackRest logs in $LOG_DIR will not be rotated"
    return 0
  fi
  write_file "$LOGROTATE_FILE" 0644 root:root <<'ROWSAFE_LOGROTATE_EOF' || true
# SPDX-License-Identifier: Apache-2.0
# pgBackRest file logs (log-level-file=detail) written by the Rowsafe agent and
# by PostgreSQL's archive_command. Installed as /etc/logrotate.d/rowsafe by
# https://rowsafe.sh/install. pgBackRest reopens its log on every command, so
# plain create-style rotation is safe.
/var/log/rowsafe/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    su postgres postgres
    create 0640 postgres postgres
}
ROWSAFE_LOGROTATE_EOF
}

# ---------------------------------------------------------------- agent.env

env_template() {
  cat <<'EOF'
# Rowsafe agent configuration, read by rowsafe-agent.service (EnvironmentFile=).
# Owned by postgres with mode 0600 because it holds repository credentials.
# Values are single-quoted and must not contain single quotes or newlines.
# Every setting: https://rowsafe.sh/docs/reference/agent-configuration
#
# Apply changes by re-running the installer (it self-tests the configuration
# before starting the agent) or with: systemctl restart rowsafe-agent

# Control plane (default shown; set only for a self-hosted one), and the
# one-time enrollment token from `rowsafe hosts enroll-token`. The token is
# used up on first start and can be deleted afterwards.
#ROWSAFE_URL='https://api.rowsafe.sh'
#ROWSAFE_ENROLL_TOKEN=''

# Backup repository: a private S3-compatible bucket (Cloudflare R2) and an API
# token scoped to that bucket with Object Read & Write. The endpoint is a host
# name without https://, e.g. <account-id>.eu.r2.cloudflarestorage.com
#ROWSAFE_REPO_S3_ENDPOINT=''
#ROWSAFE_REPO_S3_BUCKET=''
#ROWSAFE_REPO_S3_KEY=''
#ROWSAFE_REPO_S3_KEY_SECRET=''

# Client-side encryption passphrase, at least 20 characters, e.g. from
# `openssl rand -base64 48`. Store it in your secret manager BEFORE the first
# backup. Without it every backup in the repository is unreadable, and nobody,
# Rowsafe included, can recover it.
#ROWSAFE_REPO_CIPHER_PASS=''

# Optional; the defaults are shown.
#ROWSAFE_REPO_PATH_PREFIX='/rowsafe'
#ROWSAFE_REPO_S3_REGION='auto'
#ROWSAFE_REPO_S3_URI_STYLE='path'
#ROWSAFE_AUTO_UPDATE='true'

# Only for S3-compatible stores other than R2 (e.g. MinIO); leave unset for R2.
#ROWSAFE_REPO_S3_PORT='443'
#ROWSAFE_REPO_S3_CA_FILE='/etc/ssl/certs/my-ca.pem'
#ROWSAFE_REPO_S3_VERIFY_TLS='true'
EOF
}

# check_value KEY VALUE rejects values the env file can't hold or the agent
# would refuse, without ever printing the value.
check_value() {
  nl='
'
  case $2 in
    *"'"* | *"$nl"*) die "$1 must not contain single quotes or newlines" ;;
  esac
  case $1 in
    ROWSAFE_URL)
      case $2 in
        https://* | http://localhost* | http://127.0.0.1*) ;;
        *) die "ROWSAFE_URL must start with https:// (plain http only for localhost)" ;;
      esac
      ;;
    ROWSAFE_ENROLL_TOKEN)
      case $2 in rse_*) ;; *) die "ROWSAFE_ENROLL_TOKEN does not look like an enrollment token (rse_...)" ;; esac
      ;;
    ROWSAFE_REPO_S3_ENDPOINT)
      case $2 in *://*) die "ROWSAFE_REPO_S3_ENDPOINT is a host name without a scheme, e.g. <account-id>.eu.r2.cloudflarestorage.com" ;; esac
      ;;
    ROWSAFE_REPO_CIPHER_PASS)
      [ "${#2}" -ge 20 ] || die "ROWSAFE_REPO_CIPHER_PASS must be at least 20 characters"
      ;;
  esac
}

# set_env_var KEY replaces KEY's line (active or commented out) in the env
# file with the value of the environment variable KEY. The value travels
# through the environment, never through a command line.
set_env_var() {
  RS_KEY=$1 awk -v q="'" '
    BEGIN { k = ENVIRON["RS_KEY"]; line = k "=" q ENVIRON[k] q }
    index($0, k "=") == 1 || index($0, "#" k "=") == 1 {
      if (!done) print line
      done = 1
      next
    }
    { print }
    END { if (!done) print line }
  ' "$ENV_FILE" >"$ENV_FILE.rowsafe-new"
  mv -f "$ENV_FILE.rowsafe-new" "$ENV_FILE"
}

# clear_env_var KEY turns an active KEY line back into the template's
# commented-out default, so the agent uses its default again.
clear_env_var() {
  line=''
  if ! grep -q "^#$1=" "$ENV_FILE"; then
    line=$(env_template | grep "^#$1=" | head -n 1)
    [ -n "$line" ] || line="#$1=''"
  fi
  RS_KEY=$1 RS_LINE=$line awk '
    index($0, ENVIRON["RS_KEY"] "=") == 1 {
      if (ENVIRON["RS_LINE"] != "" && !done) print ENVIRON["RS_LINE"]
      done = 1
      next
    }
    { print }
  ' "$ENV_FILE" >"$ENV_FILE.rowsafe-new"
  mv -f "$ENV_FILE.rowsafe-new" "$ENV_FILE"
}

# env_value KEY prints KEY's active value from the env file (unquoted).
env_value() {
  [ -f "$ENV_FILE" ] || return 0
  awk -v k="$1" 'index($0, k "=") == 1 { v = substr($0, length(k) + 2) } END { print v }' "$ENV_FILE" |
    sed "s/^'\(.*\)'\$/\1/; s/^\"\(.*\)\"\$/\1/"
}

write_env() {
  step "Writing $ENV_FILE"
  if [ ! -f "$ENV_FILE" ]; then
    env_template >"$ENV_FILE"
    ENV_CREATED=1
  fi
  before=$(sha256_of "$ENV_FILE")
  written=''
  for key in $AGENT_VARS; do
    eval "val=\${$key:-}"
    [ -n "$val" ] || continue
    check_value "$key" "$val"
    set_env_var "$key"
    written="$written $key"
  done
  for key in $STORAGE_CLEAR; do
    clear_env_var "$key"
  done
  chown "$AGENT_USER:$AGENT_USER" "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
  if [ "$(sha256_of "$ENV_FILE")" != "$before" ]; then
    CHANGED=1
    if [ "$STORAGE_GUIDED" = 1 ]; then
      ok "saved your backup storage settings (secrets are only in this file)"
    else
      note "set from the installer's environment:${written}"
    fi
  elif [ -z "${ENV_CREATED:-}" ]; then
    note "unchanged"
  fi
}

# missing_config prints the settings the agent still needs.
missing_config() {
  out=''
  for key in $REQUIRED_REPO_VARS; do
    [ -n "$(env_value "$key")" ] || out="$out $key"
  done
  if [ ! -f "$STATE_DIR/agent.json" ] && [ -z "$(env_value ROWSAFE_ENROLL_TOKEN)" ]; then
    out="$out ROWSAFE_ENROLL_TOKEN"
  fi
  printf '%s\n' "${out# }"
}

# ---------------------------------------------------------------- terminal

# open_tty opens the terminal on fd 3 for the guided setup. The script itself
# arrives on stdin (curl ... | sh), so answers come from /dev/tty. That device
# exists even without a controlling terminal, so opening it is the real test,
# done in a subshell because a failed redirection on `exec` ends the script.
open_tty() {
  [ "$PROMPT" != never ] || return 0
  (: <>/dev/tty) 2>/dev/null || return 0
  exec 3<>/dev/tty
  TTY=1
  TTY_SAVED=$(stty -g <&3 2>/dev/null || true)
}

tty_say() { printf '%s\n' "$*" >&3; }
tty_hint() { printf '  %s\n' "$*" >&3; }
tty_bad() { printf '  %s%s%s %s\n' "$RED" "$CROSS" "$RESET" "$*" >&3; }

tty_echo_on() {
  if [ -n "$TTY_SAVED" ]; then stty "$TTY_SAVED" <&3 2>/dev/null || true; else stty echo <&3 2>/dev/null || true; fi
}

# trim VAR strips surrounding white space (and the CR of a pasted line).
trim() {
  eval "_t=\$$1"
  _t=${_t#"${_t%%[![:space:]]*}"}
  _t=${_t%"${_t##*[![:space:]]}"}
  eval "$1=\$_t"
}

tty_read() {
  IFS= read -r _a <&3 || {
    printf '\n' >&3
    die "no answer; nothing was saved"
  }
  trim _a
}

# ask VAR QUESTION [DEFAULT]
ask() {
  if [ -n "${3:-}" ]; then printf '%s [%s]: ' "$2" "$3" >&3; else printf '%s: ' "$2" >&3; fi
  tty_read
  [ -n "$_a" ] || _a=${3:-}
  eval "$1=\$_a"
}

# ask_secret VAR QUESTION reads without echo. Echo goes off before the
# question appears, so nothing typed ahead is shown either.
ask_secret() {
  stty -echo <&3 2>/dev/null || true
  printf '%s: ' "$2" >&3
  if ! IFS= read -r _a <&3; then
    tty_echo_on
    printf '\n' >&3
    die "no answer; nothing was saved"
  fi
  tty_echo_on
  printf '\n' >&3
  trim _a
  eval "$1=\$_a"
}

# confirm QUESTION y|n (the default) succeeds on yes.
confirm() {
  _p='[y/N]'
  [ "$2" = y ] && _p='[Y/n]'
  while :; do
    printf '%s %s ' "$1" "$_p" >&3
    tty_read
    case ${_a:-$2} in
      [Yy] | [Yy][Ee][Ss]) return 0 ;;
      [Nn] | [Nn][Oo]) return 1 ;;
    esac
    tty_hint "Please answer y or n."
  done
}

# choose VAR QUESTION DEFAULT MAX reads a menu number.
choose() {
  _c=''
  while :; do
    ask _c "$2" "$3"
    case $_c in
      '' | *[!0-9]*) ;;
      *) if [ "$_c" -ge 1 ] && [ "$_c" -le "$4" ]; then
        eval "$1=\$_c"
        return 0
      fi ;;
    esac
    tty_hint "Please type a number from 1 to $4."
  done
}

# matches VALUE ERE, for values that are not secret.
matches() { printf '%s\n' "$1" | grep -Eq "$2"; }

# host_of INPUT turns a pasted URL or host into a lower-case host[:port].
host_of() { printf '%s\n' "$1" | sed -e 's|^[A-Za-z][A-Za-z0-9+.-]*://||' -e 's|[/?#].*$||' | tr '[:upper:]' '[:lower:]'; }

# ---------------------------------------------------------------- storage

PROVIDERS='r2 b2 s3 wasabi spaces s3-compatible'

provider_number() {
  n=1
  for p in $PROVIDERS; do
    [ "$p" = "$1" ] && {
      echo $n
      return 0
    }
    n=$((n + 1))
  done
  return 1
}

# s_get KEY prints KEY from the installer's environment, else from agent.env.
s_get() {
  eval "_v=\${$1:-}"
  [ -n "$_v" ] || _v=$(env_value "$1")
  printf '%s' "$_v"
}

# load_storage reads the repository settings into S_*, the environment
# taking precedence over agent.env (the same values write_env would save).
load_storage() {
  S_ENDPOINT=$(s_get ROWSAFE_REPO_S3_ENDPOINT)
  S_BUCKET=$(s_get ROWSAFE_REPO_S3_BUCKET)
  S_KEY=$(s_get ROWSAFE_REPO_S3_KEY)
  S_SECRET=$(s_get ROWSAFE_REPO_S3_KEY_SECRET)
  S_CIPHER=$(s_get ROWSAFE_REPO_CIPHER_PASS)
  S_REGION=$(s_get ROWSAFE_REPO_S3_REGION)
  S_URI=$(s_get ROWSAFE_REPO_S3_URI_STYLE)
  S_PORT=$(s_get ROWSAFE_REPO_S3_PORT)
  S_CA=$(s_get ROWSAFE_REPO_S3_CA_FILE)
  S_VERIFY=$(s_get ROWSAFE_REPO_S3_VERIFY_TLS)
  load_storage_path
}

# load_storage_path sets S_PATH, the repository root the agent's stanzas live
# under (RenderConfig: repo1-path=<prefix>/<stanza>).
load_storage_path() {
  _p=$(s_get ROWSAFE_REPO_PATH_PREFIX)
  [ -n "$_p" ] || _p=/rowsafe
  _p=$(printf '%s\n' "$_p" | sed -e 's|^/*||' -e 's|/*$||')
  S_PATH=/$_p
}

storage_configured() {
  for key in $REQUIRED_REPO_VARS; do
    [ -n "$(env_value "$key")" ] || return 1
  done
}

# st_run PGBACKREST ARGS... runs pgBackRest as the agent user against the S_*
# repository, the way the agent's rendered config would (without the cipher:
# the test file is not a backup). Settings travel in the environment only,
# never on a command line or in a file.
st_run() {
  _bin=$1
  shift
  (
    export PGBACKREST_REPO1_TYPE=s3
    export PGBACKREST_REPO1_S3_ENDPOINT="$S_ENDPOINT"
    export PGBACKREST_REPO1_S3_BUCKET="$S_BUCKET"
    export PGBACKREST_REPO1_S3_REGION="${S_REGION:-auto}"
    export PGBACKREST_REPO1_S3_URI_STYLE="${S_URI:-path}"
    export PGBACKREST_REPO1_S3_KEY="$S_KEY"
    export PGBACKREST_REPO1_S3_KEY_SECRET="$S_SECRET"
    export PGBACKREST_REPO1_PATH="$S_PATH"
    [ -z "$S_PORT" ] || export PGBACKREST_REPO1_STORAGE_PORT="$S_PORT"
    [ -z "$S_CA" ] || export PGBACKREST_REPO1_STORAGE_CA_FILE="$S_CA"
    case $S_VERIFY in
      0 | [Nn] | [Nn][Oo] | [Ff][Aa][Ll][Ss][Ee] | [Oo][Ff][Ff]) export PGBACKREST_REPO1_STORAGE_VERIFY_TLS=n ;;
    esac
    export PGBACKREST_LOG_LEVEL_FILE=off PGBACKREST_LOG_LEVEL_CONSOLE=off PGBACKREST_LOG_LEVEL_STDERR=warn
    export PGBACKREST_IO_TIMEOUT=5
    cd /
    exec runuser -u "$AGENT_USER" -- timeout 120 "$_bin" --no-config "$@"
  )
}

# storage_test writes, reads back and deletes a small file in the S_*
# repository with pgBackRest, the client the agent uses for backups.
storage_test() {
  pgbr=${ROWSAFE_PGBACKREST_BIN:-/usr/bin/pgbackrest}
  [ -x "$pgbr" ] || pgbr=$(command -v pgbackrest 2>/dev/null) || die "pgBackRest is not installed; run the installer first"
  where="bucket '$S_BUCKET' at $S_ENDPOINT${S_PORT:+:$S_PORT}"
  note "writing, reading and deleting a test file in $where..."
  probe=rowsafe-storage-test-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
  printf 'Rowsafe storage test from %s\n' "$(uname -n)" >"$TMP/probe"
  if ! st_run "$pgbr" repo-put "$probe" <"$TMP/probe" >"$TMP/storage.log" 2>&1; then
    storage_failed "could not write to $where"
    return 1
  fi
  if ! st_run "$pgbr" repo-get "$probe" </dev/null >"$TMP/probe.back" 2>"$TMP/storage.log" ||
    ! cmp -s "$TMP/probe" "$TMP/probe.back"; then
    st_run "$pgbr" repo-rm "$probe" </dev/null >/dev/null 2>&1 || true
    storage_failed "wrote a test file to $where but could not read it back"
    return 1
  fi
  if ! st_run "$pgbr" repo-rm "$probe" </dev/null >"$TMP/storage.log" 2>&1; then
    storage_failed "could not delete the test file from $where. The key needs delete access too: old backups are deleted when they expire."
    return 1
  fi
  ok "backup storage works: wrote, read back and deleted a test file"
}

storage_failed() {
  printf '    %s%s %s%s\n' "$RED" "$CROSS" "$1" "$RESET"
  storage_explain | while IFS= read -r line; do say "      $line"; done
}

# storage_explain turns pgBackRest's error in $TMP/storage.log into the
# likely cause. S3 errors carry a <Code>; connection errors are pgBackRest's.
storage_explain() {
  log=$TMP/storage.log
  if grep -q RequestTimeTooSkewed "$log"; then
    say "This server's clock is wrong: it says $(date -u '+%Y-%m-%d %H:%M') UTC."
    say "Storage refuses requests from a clock more than 15 minutes off."
    say "Turn on time sync (timedatectl set-ntp true), then try again."
  elif grep -q InvalidAccessKeyId "$log"; then
    say "The access key ID was not recognised. Copy it again from your provider."
    case ${S_PROVIDER:-} in
      r2) say "(R2: use the Access Key ID, 32 characters, not the token value.)" ;;
      b2) say "(B2: use the application key's keyID, not the account ID.)" ;;
    esac
  elif grep -q SignatureDoesNotMatch "$log"; then
    say "The secret doesn't match the access key ID. Copy the secret again; it is"
    say "shown only once, so if you no longer have it, create a new key."
  elif grep -q NoSuchBucket "$log"; then
    say "There is no bucket named '$S_BUCKET' there. Check the name, and that you"
    say "created it in this account (and region)."
  elif grep -Eq 'AuthorizationHeaderMalformed|PermanentRedirect|IncorrectEndpoint|IllegalLocationConstraint|InvalidRegion|failed with 301' "$log"; then
    say "The bucket is in a different region. Check the region (or endpoint) you chose."
  elif grep -Eq 'AccessDenied|failed with 403' "$log"; then
    say "The key is valid but not allowed to use this bucket. Give it read, write"
    say "and delete access to '$S_BUCKET' (R2: Object Read & Write)."
  elif grep -q 'unable to get address' "$log"; then
    say "Can't find $S_ENDPOINT. Check the account ID or region, and that this"
    say "server can look up internet names (DNS)."
  elif grep -Eq 'unable to connect|onnection refused|No route to host' "$log"; then
    say "Can't connect to $S_ENDPOINT on port ${S_PORT:-443}. Check that a firewall"
    say "allows outgoing HTTPS from this server."
  elif grep -Eqi 'certificate|tls|ssl' "$log"; then
    say "The storage's TLS certificate is not trusted. For a private CA, set"
    say "ROWSAFE_REPO_S3_CA_FILE in the environment and run the installer again."
  elif grep -Eqi 'timeout|timed out' "$log"; then
    say "The storage did not answer in time. Check the endpoint and the network."
  fi
  # The underlying error, for support: the storage's error code and message
  # if it sent one, else pgBackRest's error. pgBackRest redacts credentials;
  # mask them anyway in case a provider echoes one back.
  RS_A=$S_KEY RS_B=$S_SECRET RS_C=${S_CIPHER:-} awk '
    function mask(s, v,   i) {
      if (v == "") return s
      while ((i = index(s, v)) > 0) s = substr(s, 1, i - 1) "***" substr(s, i + length(v))
      return s
    }
    function tag(s, t,   a, b) {
      a = index(s, "<" t ">"); b = index(s, "</" t ">")
      return (a && b > a) ? substr(s, a + length(t) + 2, b - a - length(t) - 2) : ""
    }
    err == "" && /ERROR: \[/ {
      err = $0
      sub(/^.*ERROR: \[[0-9]+\]: /, "", err)
    }
    code == "" && /<Code>/ {
      code = tag($0, "Code")
      if (tag($0, "Message") != "") code = code ": " tag($0, "Message")
    }
    END {
      s = code != "" ? "storage said: " code : err != "" ? "pgBackRest: " err : ""
      s = mask(mask(mask(s, ENVIRON["RS_A"]), ENVIRON["RS_B"]), ENVIRON["RS_C"])
      if (s != "") print "(" substr(s, 1, 200) ")"
    }' "$log"
}

# ---- the guided setup

storage_menu() {
  tty_say ""
  tty_say "${BOLD}Where should Rowsafe store your backups?${RESET}"
  tty_say "  1) Cloudflare R2          recommended: 10 GB free, no egress fees"
  tty_say "  2) Backblaze B2"
  tty_say "  3) Amazon S3"
  tty_say "  4) Wasabi"
  tty_say "  5) DigitalOcean Spaces"
  tty_say "  6) Other S3-compatible storage (MinIO, Ceph, Hetzner, OVH, ...)"
}

ask_r2() {
  tty_hint "In Cloudflare: R2 > Create bucket, then R2 > Manage API tokens > Create"
  tty_hint "API token with \"Object Read & Write\" for that bucket. The token page"
  tty_hint "shows the account ID and the S3 endpoint; paste either."
  while :; do
    ask _v "Cloudflare account ID" "$S_ENDPOINT"
    h=$(host_of "$_v")
    acct=$(printf '%s\n' "$h" | sed -nE 's/^([0-9a-f]{32})(\.(eu|fedramp))?(\.r2\.cloudflarestorage\.com)?$/\1/p')
    [ -n "$acct" ] && break
    tty_bad "An account ID is 32 characters, 0-9 and a-f."
  done
  case $h in
    *.r2.cloudflarestorage.com) S_ENDPOINT=$h ;;
    *)
      if confirm "Is the bucket in the EU jurisdiction (created with \"EU\" data location)?" n; then
        S_ENDPOINT=$acct.eu.r2.cloudflarestorage.com
      else
        S_ENDPOINT=$acct.r2.cloudflarestorage.com
      fi
      ;;
  esac
  S_REGION=auto S_URI=path
}

ask_b2() {
  tty_hint "In Backblaze: Buckets lists each bucket's endpoint, e.g."
  tty_hint "s3.us-west-004.backblazeb2.com. Under Application Keys, add a key with"
  tty_hint "Read and Write access to the bucket: keyID and applicationKey."
  while :; do
    ask _v "Bucket endpoint or region (e.g. us-west-004)" "$S_REGION"
    r=$(host_of "$_v" | sed -nE 's/^(s3\.)?([a-z]+-[a-z]+-[0-9]{3})(\.backblazeb2\.com)?$/\2/p')
    [ -n "$r" ] && break
    tty_bad "That isn't a B2 region; it looks like us-west-004 or eu-central-003."
  done
  S_ENDPOINT=s3.$r.backblazeb2.com S_REGION=$r S_URI=path
}

ask_s3() {
  tty_hint "Use an IAM access key allowed to list, read, write and delete objects"
  tty_hint "in the bucket (s3:ListBucket, s3:GetObject, s3:PutObject, s3:DeleteObject)."
  while :; do
    ask _v "AWS region of the bucket (e.g. us-east-1, eu-central-1)" "$S_REGION"
    r=$(host_of "$_v" | sed -nE 's/^(s3[.-])?([a-z]{2}(-gov)?-[a-z]+-[0-9])(\.amazonaws\.com)?$/\2/p')
    [ -n "$r" ] && break
    tty_bad "That isn't an AWS region; it looks like us-east-1 or eu-central-1."
  done
  S_ENDPOINT=s3.$r.amazonaws.com S_REGION=$r S_URI=host
}

ask_wasabi() {
  tty_hint "Use an access key (Access Keys > Create new access key) whose user may"
  tty_hint "read, write and delete in the bucket."
  while :; do
    ask _v "Wasabi region of the bucket (e.g. us-east-1, eu-central-1)" "$S_REGION"
    h=$(host_of "$_v")
    [ "$h" = s3.wasabisys.com ] && h=us-east-1
    r=$(printf '%s\n' "$h" | sed -nE 's/^(s3\.)?([a-z]{2}-[a-z]+-[0-9])(\.wasabisys\.com)?$/\2/p')
    [ -n "$r" ] && break
    tty_bad "That isn't a Wasabi region; it looks like us-east-1 or eu-central-2."
  done
  S_ENDPOINT=s3.$r.wasabisys.com S_REGION=$r S_URI=path
}

ask_spaces() {
  tty_hint "Create a key under Spaces Object Storage > Access Keys with read/write"
  tty_hint "access to the Space (bucket)."
  _d=''
  case $S_ENDPOINT in *.digitaloceanspaces.com) _d=${S_ENDPOINT%%.*} ;; esac
  while :; do
    ask _v "Datacenter of the Space (e.g. nyc3, fra1, sgp1)" "$_d"
    r=$(host_of "$_v" | sed -nE 's/^([a-z0-9-]+\.)?([a-z]{3}[0-9])(\.digitaloceanspaces\.com)?$/\2/p')
    [ -n "$r" ] && break
    tty_bad "That isn't a Spaces datacenter; it looks like nyc3 or fra1."
  done
  # Spaces signs with us-east-1 whatever the datacenter; the endpoint picks it.
  S_ENDPOINT=$r.digitaloceanspaces.com S_REGION=us-east-1 S_URI=host
}

ask_other() {
  tty_hint "The S3 API endpoint of your storage, e.g. s3.example.com or"
  tty_hint "minio.example.com:9000. pgBackRest only talks to storage over HTTPS."
  while :; do
    ask _v "Endpoint" "$S_ENDPOINT${S_PORT:+:$S_PORT}"
    case $_v in
      [Hh][Tt][Tt][Pp]://*)
        tty_bad "Plain http:// is not supported; the endpoint must serve HTTPS."
        continue
        ;;
    esac
    h=$(host_of "$_v")
    p=''
    case $h in
      *:*)
        p=${h##*:}
        h=${h%:*}
        ;;
    esac
    if matches "$h" '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' && { [ -z "$p" ] || matches "$p" '^[1-9][0-9]{0,4}$'; }; then
      [ "$p" != 443 ] || p=''
      break
    fi
    tty_bad "That doesn't look like a host name (and optional :port)."
  done
  S_ENDPOINT=$h S_PORT=$p
  ask S_REGION "Region (most self-hosted storage accepts us-east-1)" "${S_REGION:-us-east-1}"
  if confirm "Use path-style URLs? MinIO, Ceph and most self-hosted storage need them." y; then S_URI=path; else S_URI=host; fi
  # TLS options for a private CA come from the environment or agent.env.
  S_CA=$(s_get ROWSAFE_REPO_S3_CA_FILE)
  S_VERIFY=$(s_get ROWSAFE_REPO_S3_VERIFY_TLS)
}

ask_credentials() {
  while :; do
    ask _v "Bucket name" "$S_BUCKET"
    _v=${_v#s3://}
    _v=${_v%/}
    matches "$_v" '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' && break
    tty_bad "Bucket names are 3-63 characters: lowercase letters, numbers, dots and hyphens."
  done
  S_BUCKET=$_v
  # Host-style URLs put the bucket in the TLS host name; dots break that.
  case $S_URI:$S_BUCKET in host:*.*) S_URI=path ;; esac

  _k=''
  [ -z "$S_KEY" ] || _k=' (Enter keeps the last one)'
  while :; do
    ask _v "Access key ID$_k"
    [ -n "$_v" ] || _v=$S_KEY
    case $_v in
      '') ;;
      *[[:space:]]* | *"'"* | *'"'*) tty_bad "That contains spaces or quotes; paste just the key ID." ;;
      *) break ;;
    esac
  done
  S_KEY=$_v

  _k=''
  [ -z "$S_SECRET" ] || _k=', Enter keeps the last one'
  while :; do
    ask_secret _v "Secret access key (hidden$_k)"
    [ -n "$_v" ] || _v=$S_SECRET
    case $_v in
      '') ;;
      *[[:space:]]* | *"'"*) tty_bad "That contains spaces or quotes; paste just the secret." ;;
      *) break ;;
    esac
  done
  S_SECRET=$_v
}

show_passphrase() {
  _h=''
  _i=0
  while [ $_i -lt 54 ]; do
    _h=$_h$BOX_H
    _i=$((_i + 1))
  done
  box() { printf '  %s  %-50s  %s\n' "$BOX_V" "$1" "$BOX_V" >&3; }
  tty_say ""
  tty_say "  $BOX_TL$_h$BOX_TR"
  box "Your backup encryption passphrase:"
  box ""
  printf '  %s      %s%s%s        %s\n' "$BOX_V" "$BOLD" "$1" "$RESET" "$BOX_V" >&3
  box ""
  box "Save this in your password manager now."
  box "Without it, your backups can't be restored."
  box "Rowsafe can't recover it."
  tty_say "  $BOX_BL$_h$BOX_BR"
  tty_say ""
}

# choose_passphrase sets S_CIPHER: kept, generated (shown once) or typed.
choose_passphrase() {
  current=$(env_value ROWSAFE_REPO_CIPHER_PASS)
  if [ -n "$current" ]; then
    tty_say ""
    tty_say "This server already has a backup encryption passphrase. Keep it unless"
    tty_say "you are starting over: backups made with it can only be restored with it."
    if confirm "Keep the current encryption passphrase?" y; then
      S_CIPHER=$current
      ok "kept the current encryption passphrase"
      return 0
    fi
  fi
  tty_say ""
  tty_say "${BOLD}Backups are encrypted on this server before they are uploaded.${RESET}"
  tty_say "  1) Generate a strong passphrase for me (recommended)"
  tty_say "  2) Use my own passphrase"
  _n=1 _p1='' _p2=''
  choose _n "Choose 1-2" 1 2
  if [ "$_n" = 1 ]; then
    # 40 letters and digits (~238 bits): no symbols, so a double-click copies it whole.
    S_CIPHER=$(head -c 1024 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' 2>/dev/null | head -c 40)
    [ "${#S_CIPHER}" = 40 ] || die "could not generate a passphrase"
    show_passphrase "$S_CIPHER"
    last4=${S_CIPHER#"${S_CIPHER%????}"}
    while :; do
      ask _v "Saved it? Type its last 4 characters to continue"
      [ "$_v" = "$last4" ] && break
      tty_bad "That doesn't match. Save the passphrase in the box above, then type its last 4 characters."
    done
    ok "passphrase confirmed"
    return 0
  fi
  while :; do
    ask_secret _p1 "Your passphrase (at least 20 characters, hidden)"
    case $_p1 in
      *"'"*)
        tty_bad "Single quotes can't be used in the passphrase."
        continue
        ;;
    esac
    if [ "${#_p1}" -lt 20 ]; then
      tty_bad "That is ${#_p1} characters; use at least 20."
      continue
    fi
    ask_secret _p2 "Type it again"
    [ "$_p1" = "$_p2" ] && break
    tty_bad "The two don't match. Try again."
  done
  S_CIPHER=$_p1
  tty_hint "Keep it in your password manager: without it, backups can't be restored."
  ok "passphrase set"
}

# maybe_guided_storage runs the guided setup on a terminal when the storage
# is not configured yet (or --setup-storage asks for it). Settings in the
# installer's environment mean automation: then it never asks.
maybe_guided_storage() {
  [ "$TTY" = 1 ] || return 0
  if [ "$SETUP_STORAGE" = 0 ]; then
    for key in $REQUIRED_REPO_VARS; do
      eval "v=\${$key:-}"
      [ -z "$v" ] || return 0
    done
    if storage_configured; then
      ok "backup storage: bucket '$(env_value ROWSAFE_REPO_S3_BUCKET)' at $(env_value ROWSAFE_REPO_S3_ENDPOINT) (change it with --setup-storage)"
      return 0
    fi
  fi
  guided_storage
}

guided_storage() {
  say ""
  step "Backup storage"
  if storage_configured; then
    tty_say "Backups go to bucket '$(env_value ROWSAFE_REPO_S3_BUCKET)' at $(env_value ROWSAFE_REPO_S3_ENDPOINT)."
    if ! confirm "Replace these storage settings?" n; then
      ok "kept the current storage settings"
      return 0
    fi
    tty_hint "Existing backups stay where they are; new ones go to the new bucket."
  else
    tty_say "Rowsafe keeps your backups in a storage bucket that you own. You need an"
    tty_say "empty bucket and an access key that can read, write and delete in it."
  fi
  S_ENDPOINT='' S_BUCKET='' S_KEY='' S_SECRET='' S_REGION='' S_URI='' S_PORT='' S_CA='' S_VERIFY='' S_CIPHER=''
  load_storage_path
  n=1
  [ -z "$STORAGE_PROVIDER" ] || n=$(provider_number "$STORAGE_PROVIDER")
  last=''
  while :; do
    storage_menu
    choose n "Choose 1-6" "$n" 6
    if [ "$n" != "$last" ]; then
      # Another provider: its endpoint and region defaults don't carry over.
      S_ENDPOINT='' S_REGION='' S_URI='' S_PORT='' S_CA='' S_VERIFY=''
    fi
    last=$n
    S_PROVIDER=$(printf '%s\n' "$PROVIDERS" | cut -d' ' -f"$n")
    tty_say ""
    case $S_PROVIDER in
      r2) ask_r2 ;;
      b2) ask_b2 ;;
      s3) ask_s3 ;;
      wasabi) ask_wasabi ;;
      spaces) ask_spaces ;;
      *) ask_other ;;
    esac
    ask_credentials
    say ""
    step "Testing the backup storage"
    storage_test && break
    say ""
    confirm "Change the settings and test again?" y && continue
    if confirm "Save them anyway? The agent will run, but backups fail until the storage works." n; then
      warn "saved storage settings that failed the test; check them with --check-storage"
      break
    fi
    die "nothing was saved. Run the installer again once the storage is ready."
  done
  choose_passphrase
  STORAGE_GUIDED=1

  ROWSAFE_REPO_S3_ENDPOINT=$S_ENDPOINT ROWSAFE_REPO_S3_BUCKET=$S_BUCKET
  ROWSAFE_REPO_S3_KEY=$S_KEY ROWSAFE_REPO_S3_KEY_SECRET=$S_SECRET ROWSAFE_REPO_CIPHER_PASS=$S_CIPHER
  ROWSAFE_REPO_S3_REGION=$S_REGION ROWSAFE_REPO_S3_URI_STYLE=$S_URI
  export ROWSAFE_REPO_S3_ENDPOINT ROWSAFE_REPO_S3_BUCKET ROWSAFE_REPO_S3_KEY ROWSAFE_REPO_S3_KEY_SECRET \
    ROWSAFE_REPO_CIPHER_PASS ROWSAFE_REPO_S3_REGION ROWSAFE_REPO_S3_URI_STYLE
  # Settings from a previous provider must not linger in agent.env.
  if [ -n "$S_PORT" ]; then
    ROWSAFE_REPO_S3_PORT=$S_PORT
    export ROWSAFE_REPO_S3_PORT
  else
    unset ROWSAFE_REPO_S3_PORT
    STORAGE_CLEAR="$STORAGE_CLEAR ROWSAFE_REPO_S3_PORT"
  fi
  if [ "$S_PROVIDER" != s3-compatible ]; then
    unset ROWSAFE_REPO_S3_CA_FILE ROWSAFE_REPO_S3_VERIFY_TLS
    STORAGE_CLEAR="$STORAGE_CLEAR ROWSAFE_REPO_S3_CA_FILE ROWSAFE_REPO_S3_VERIFY_TLS"
  fi
}

# check_storage (--check-storage) tests the configured repository and
# changes nothing.
check_storage() {
  require_root
  [ -f "$ENV_FILE" ] || die "$ENV_FILE doesn't exist yet; install the agent first"
  load_storage
  missing=''
  for key in $REQUIRED_REPO_VARS; do
    [ "$key" = ROWSAFE_REPO_CIPHER_PASS ] && continue
    [ -n "$(s_get "$key")" ] || missing="$missing $key"
  done
  [ -z "$missing" ] || die "the backup storage is not configured; missing:$missing"
  step "Testing the backup storage"
  storage_test || die "the backup storage test failed; nothing was changed"
}

# ---------------------------------------------------------------- service

# run_selftest BINARY runs `BINARY selftest` as postgres with agent.env, the
# same check the agent runs before switching to a new version.
run_selftest() {
  if systemd_running; then
    systemd-run --quiet --wait --pipe --collect -p User="$AGENT_USER" -p EnvironmentFile="$ENV_FILE" \
      "$1" selftest >"$TMP/selftest.json" 2>"$TMP/selftest.err" </dev/null
  else
    # Without systemd (e.g. in a container) load the file with sh. The
    # installer writes single-quoted values, which sh and systemd read alike.
    # shellcheck disable=SC2016 # $1 and $2 expand in the inner shell
    runuser -u "$AGENT_USER" -- sh -c 'set -a; . "$1"; set +a; exec "$2" selftest' \
      rowsafe-selftest "$ENV_FILE" "$1" >"$TMP/selftest.json" 2>"$TMP/selftest.err" </dev/null
  fi
}

print_selftest_errors() {
  awk '{
    s = $0
    if (!sub(/.*"errors":\[/, "", s)) next
    sub(/\].*/, "", s)
    n = split(s, e, "\",\"")
    for (i = 1; i <= n; i++) { gsub(/^"|"$/, "", e[i]); gsub(/\\"/, "\"", e[i]); if (e[i] != "") print "    - " e[i] }
  }' "$TMP/selftest.json" >&2
  if ! grep -q '"errors"' "$TMP/selftest.json" 2>/dev/null; then
    tail -n 5 "$TMP/selftest.err" >&2 || true
  fi
}

# agent_busy is true while a backup or restore drill is running; restarting
# the agent then would kill it.
agent_busy() {
  if have pgrep && pgrep -u "$AGENT_USER" -f 'pgbackrest .*(backup|restore)$' >/dev/null 2>&1; then
    return 0
  fi
  [ -n "$(ls -A "$STATE_DIR/drills" 2>/dev/null)" ]
}

start_agent() {
  if systemctl is-active --quiet "$SERVICE"; then
    if [ "$CHANGED" = 0 ]; then
      SERVICE_STATE="running (unchanged)"
      return 0
    fi
    if agent_busy; then
      warn "a backup or restore drill is running, so the agent was not restarted. Run 'systemctl restart rowsafe-agent' once it has finished (a leftover $STATE_DIR/drills/* directory also counts as running)."
      SERVICE_STATE="running the previous version until restarted"
      return 0
    fi
    step "Restarting the agent"
    systemctl restart "$SERVICE"
  else
    step "Starting the agent"
    systemctl start "$SERVICE"
  fi
  # Give it a moment to enroll and prove it stays up.
  i=0
  while [ $i -lt 15 ]; do
    sleep 1
    i=$((i + 1))
    [ -f "$STATE_DIR/agent.json" ] && [ $i -ge 3 ] && break
  done
  if systemctl is-active --quiet "$SERVICE"; then
    SERVICE_STATE="running"
  else
    journalctl -u "$SERVICE" -n 20 --no-pager >&2 2>/dev/null || true
    die "rowsafe-agent did not stay up; see 'journalctl -u rowsafe-agent'"
  fi
}

probe_postgres() {
  PG_SUMMARY="not checked"
  if runuser -u "$AGENT_USER" -- "$INSTALL_DIR/rowsafe-agent" inspect >"$TMP/inspect.json" 2>"$TMP/inspect.err" </dev/null; then
    field() { sed -n "s/.*\"$1\": *\"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}\$/\1/p" "$TMP/inspect.json" | head -n 1; }
    PG_SUMMARY="$(field server_version), data directory $(field data_directory), archive_mode=$(field archive_mode)"
  else
    PG_SUMMARY="not reachable on /var/run/postgresql port 5432 as $AGENT_USER (fine if it uses another port or socket; pass --port/--socket-dir to adopt)"
  fi
}

host_id() {
  sed -n 's/.*"host_id": *"\([^"]*\)".*/\1/p' "$STATE_DIR/agent.json" 2>/dev/null | head -n 1
}

# ---------------------------------------------------------------- modes

install_agent() {
  require_root
  detect_os
  detect_arch
  check_postgres
  say "${BOLD}Rowsafe agent installer${RESET}: backups, WAL archiving and restore drills for"
  say "the PostgreSQL on this server. PostgreSQL itself is never restarted."
  say ""
  step "Installing the Rowsafe agent on $(uname -n) ($OS_NAME, $ARCH)"
  ensure_base_tools

  # 1. Resolve and verify the release. Nothing on the host changes if this fails.
  resolve_release
  installed=$(installed_version)
  if [ -n "$installed" ]; then
    case $(version_cmp "$REL_VERSION" "$installed") in
      -1)
        if [ -z "$WANT_VERSION" ]; then
          note "installed version $installed is newer than $RELEASE_SOURCE ($REL_VERSION); keeping it"
          KEEP_INSTALLED=1
          REL_VERSION=$installed
        elif [ "${ROWSAFE_ALLOW_DOWNGRADE:-}" = 1 ]; then
          warn "downgrading from $installed to $REL_VERSION. Pin the host to $REL_VERSION in the control plane, or it will be offered $installed again."
        else
          die "rowsafe-agent $installed is installed; refusing to downgrade to $REL_VERSION (set ROWSAFE_ALLOW_DOWNGRADE=1 if you mean it)"
        fi
        ;;
    esac
  fi
  STAGED=$INSTALL_DIR/versions/$REL_VERSION/rowsafe-agent
  need_binary=1
  if [ "$KEEP_INSTALLED" = 1 ]; then
    need_binary=0
  elif [ -x "$STAGED" ] && [ "$(sha256_of "$STAGED")" = "$REL_SHA" ]; then
    need_binary=0
    ok "rowsafe-agent $REL_VERSION is already on disk and matches the manifest"
  fi
  [ "$need_binary" = 0 ] || download_binary

  # 2. Dependencies and layout.
  ensure_pgbackrest
  step "Installing into $INSTALL_DIR"
  make_dirs
  [ "$need_binary" = 0 ] || install_binary
  install_guard
  UNIT_CHANGED=0
  install_unit
  install_logrotate
  maybe_guided_storage
  write_env

  if systemd_running; then
    [ "$UNIT_CHANGED" = 0 ] || systemctl daemon-reload
    systemctl enable --quiet "$SERVICE"
  else
    warn "systemd is not running here; the service was installed but cannot be enabled or started"
  fi

  # 3. Unconfigured: stop here and say exactly what to fill in.
  missing=$(missing_config)
  if [ -n "$missing" ]; then
    switch_version
    if systemd_running; then summary "installed and enabled, not started"; else summary "installed, not started"; fi
    say ""
    say "${BOLD}Before the agent can start, set these in $ENV_FILE:${RESET}"
    for key in $missing; do say "    $key"; done
    say ""
    say "  - ROWSAFE_ENROLL_TOKEN comes from \`rowsafe hosts enroll-token\`."
    say "  - ROWSAFE_REPO_* are your private bucket and a token scoped to it."
    say "  - Generate ROWSAFE_REPO_CIPHER_PASS with \`openssl rand -base64 48\` and store it"
    say "    in your secret manager FIRST: without it no backup can ever be restored."
    say ""
    say "Edit the file (as root), then run this installer again: it self-tests the"
    say "configuration and starts the agent."
    case " $missing " in
      *" ROWSAFE_REPO_"*)
        say ""
        if [ "$PROMPT" = never ]; then
          say "Easier: run the installer on a terminal without --no-prompt and it walks"
        else
          say "Easier: run the installer from a terminal (e.g. over ssh) and it walks"
        fi
        say "you through the storage setup and tests it. Check storage settings you"
        say "set by hand with: sudo sh install.sh --check-storage"
        ;;
    esac
    return 0
  fi

  # 4. Configured: self-test the staged version before it goes live.
  step "Self-testing rowsafe-agent $REL_VERSION"
  if ! run_selftest "$STAGED"; then
    say "${RED}Self-test failed:${RESET}" >&2
    print_selftest_errors
    if [ -z "$installed" ]; then
      switch_version
      die "fix the problems above in $ENV_FILE, then run the installer again. The agent is installed but not started."
    fi
    # Don't leave a version that failed its self-test lying around.
    if [ "$need_binary" = 1 ] && [ "$installed" != "$REL_VERSION" ]; then rm -rf "${STAGED%/rowsafe-agent}"; fi
    die "keeping rowsafe-agent $installed. Fix the problems above in $ENV_FILE, then run the installer again."
  fi
  ok "configuration, pgBackRest and control plane reachable"
  switch_version

  SERVICE_STATE="not started (no systemd)"
  if systemd_running; then
    start_agent
  fi
  probe_postgres
  summary "$SERVICE_STATE"
  say ""
  say "${BOLD}${GREEN}${CHECK} All set.${RESET} ${BOLD}Next: go back to the Rowsafe dashboard.${RESET}"
  say "    This server ($(uname -n)) shows up there within a minute; choose which"
  say "    database to protect. Or, from your workstation:"
  say "    rowsafe hosts list"
  say "    rowsafe adopt <name> --host $(uname -n)"
  say ""
  say "Adopting only prints a read-only plan; nothing changes until you run \`rowsafe apply <name>\`."
}

summary() {
  say ""
  say "${BOLD}Rowsafe agent $REL_VERSION: $1${RESET}"
  say "    binary       $INSTALL_DIR/versions/$REL_VERSION/rowsafe-agent"
  say "    config       $ENV_FILE (postgres, 0600)"
  say "    pgBackRest   ${PGBR_VERSION:-unknown}"
  [ -z "${PG_SUMMARY:-}" ] || say "    PostgreSQL   $PG_SUMMARY"
  id=$(host_id)
  [ -z "$id" ] || say "    host         enrolled as $id"
  say "    logs         journalctl -u rowsafe-agent -f"
}

# archive_refs lists PostgreSQL config files whose archive_command still uses
# a pgBackRest config under /etc/rowsafe.
archive_refs() {
  grep -ls "$CONFIG_DIR/pgbackrest" /var/lib/postgresql/*/*/postgresql.auto.conf \
    /etc/postgresql/*/*/postgresql.conf /etc/postgresql/*/*/conf.d/*.conf 2>/dev/null | tr '\n' ' '
}

uninstall_agent() {
  require_root
  purge=$1
  refs=$(archive_refs)
  if [ "$purge" = 1 ] && [ -n "$refs" ]; then
    die "PostgreSQL still archives WAL with Rowsafe's pgBackRest config ($refs). Purging $CONFIG_DIR would make every archive_command fail and fill pg_wal until PostgreSQL stops. Disable archiving first (https://rowsafe.sh/docs/guides/adopt#rollback), then purge."
  fi
  step "Removing the Rowsafe agent"
  if systemd_running; then
    systemctl disable --now --quiet "$SERVICE" 2>/dev/null || true
  fi
  rm -f "$UNIT_FILE"
  if systemd_running; then systemctl daemon-reload; fi
  rm -rf "$INSTALL_DIR"
  ok "service and $INSTALL_DIR removed"
  if [ "$purge" = 1 ]; then
    rm -rf "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR" "$LOGROTATE_FILE"
    ok "$CONFIG_DIR, $STATE_DIR, $LOG_DIR and $LOGROTATE_FILE deleted"
  else
    # archive_command may keep logging to $LOG_DIR, so keep rotating it.
    note "kept $CONFIG_DIR, $STATE_DIR, $LOG_DIR and $LOGROTATE_FILE (delete them with --uninstall --purge)"
  fi
  if [ -n "$refs" ]; then
    note "WAL archiving set up by Rowsafe keeps running: it only needs pgbackrest and $CONFIG_DIR/pgbackrest."
  fi
  note "pgBackRest stays installed, and backups in the repository were not touched."
  note "The host still appears in the control plane (\`rowsafe hosts list\`)."
}

download_only() {
  dir=$1
  detect_arch
  check_openssl
  resolve_release
  download_binary
  mkdir -p "$dir"
  cp "$TMP/manifest.json" "$TMP/manifest.json.sig" "$dir/"
  cp "$TMP/rowsafe-agent" "$dir/rowsafe-agent"
  chmod 0755 "$dir/rowsafe-agent"
  ok "verified rowsafe-agent $REL_VERSION (linux/$ARCH) saved to $dir/rowsafe-agent"
}

main() {
  mode=install
  purge=0
  dir=''
  token=''
  while [ $# -gt 0 ]; do
    case $1 in
      rse_*)
        # Never echo the token, not even in errors.
        [ -z "$token" ] || die "more than one enrollment token given"
        token=$1
        ;;
      --uninstall) mode=uninstall ;;
      --purge) purge=1 ;;
      --setup-storage) SETUP_STORAGE=1 ;;
      --no-prompt) PROMPT=never ;;
      --check-storage) mode=check-storage ;;
      --storage)
        [ $# -ge 2 ] || die "--storage needs a provider: $PROVIDERS"
        case " $PROVIDERS other minio " in
          *" $2 "*) ;;
          *) die "unknown storage provider '$2' (one of: $PROVIDERS)" ;;
        esac
        STORAGE_PROVIDER=$2
        case $2 in other | minio) STORAGE_PROVIDER=s3-compatible ;; esac
        shift
        ;;
      --download-only)
        [ $# -ge 2 ] || die "--download-only needs a directory"
        mode=download
        dir=$2
        shift
        ;;
      -h | --help)
        usage
        return 0
        ;;
      -*) die "unknown option '$1' (see --help)" ;;
      *) die "unexpected argument: expected an enrollment token (rse_...) or options (see --help)" ;;
    esac
    shift
  done
  if [ -n "$token" ]; then
    [ "$mode" = install ] || die "an enrollment token only goes with an install"
    if [ -n "${ROWSAFE_ENROLL_TOKEN:-}" ] && [ "$ROWSAFE_ENROLL_TOKEN" != "$token" ]; then
      die "two different enrollment tokens: one as the argument, another in ROWSAFE_ENROLL_TOKEN; pass only one"
    fi
    ROWSAFE_ENROLL_TOKEN=$token
    export ROWSAFE_ENROLL_TOKEN
  fi
  if [ "$purge" = 1 ] && [ "$mode" != uninstall ]; then
    die "--purge only goes with --uninstall"
  fi
  if [ "$mode" != install ] && { [ "$SETUP_STORAGE" = 1 ] || [ -n "$STORAGE_PROVIDER" ]; }; then
    die "--setup-storage and --storage only go with an install"
  fi
  TMP=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-install.XXXXXX")
  if [ "$mode" = install ]; then
    open_tty
    if [ "$TTY" = 0 ] && { [ "$SETUP_STORAGE" = 1 ] || [ -n "$STORAGE_PROVIDER" ]; }; then
      die "the guided storage setup needs a terminal; set ROWSAFE_REPO_* in the environment instead (see --help)"
    fi
  fi
  case $mode in
    install) install_agent ;;
    check-storage) check_storage ;;
    uninstall) uninstall_agent "$purge" ;;
    download) download_only "$dir" ;;
  esac
}

main "$@"
