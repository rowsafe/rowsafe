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
# host (amd64 or arm64) that runs PostgreSQL, sets up the backup storage,
# finds PostgreSQL on the server and turns on its backups. Running it again is
# safe: it only changes what differs. It restarts PostgreSQL only when the
# person at the terminal says yes.
#
# Options (when piping, pass them after `sh -s --`):
#   rse_...                the enrollment token
#   --setup-storage        (re)run the guided backup storage setup
#   --storage PROVIDER     preselect r2, b2, s3, wasabi, spaces or s3-compatible
#   --no-prompt            never ask questions, even on a terminal
#   --no-setup             don't look for PostgreSQL or turn on backups
#   --protect NAME         without questions: turn on backups for this server's
#                          PostgreSQL as NAME (never restarts it)
#   --protect-port PORT    with --protect: the cluster on PORT (when there are several)
#   --allow-restart        allow Rowsafe to restart or stop PostgreSQL when you
#                          ask (Restart and Rewind in the dashboard, `rowsafe
#                          restart`); only when someone confirms
#   --no-allow-restart     turn that off again
#   --allow-create-cluster allow Rowsafe to create a new PostgreSQL cluster (on a
#                          free port in 5440-5499) when you fork a database to
#                          this server; only when someone confirms
#   --no-allow-create-cluster  turn that off again
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
# Database setup: then, on a terminal, it finds PostgreSQL on this server
# (`rowsafe-agent setup`, run as postgres), shows what would change, asks
# "Turn on backups now?" and, if PostgreSQL needs a restart for that, asks
# "Restart PostgreSQL now?" (default no). Rowsafe notices a restart done later
# and finishes by itself.
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
# Root's files live in root's directories: /opt/rowsafe belongs to the agent
# user (self-update swaps versions there), so root never writes inside it.
LIB_DIR=/usr/local/lib/rowsafe
GUARD_FILE=$LIB_DIR/rowsafe-agent-guard
OLD_GUARD_DIR=$INSTALL_DIR/bin # where installers before 0.3 put the guard
SERVICE=rowsafe-agent.service
# Restarts on request (--allow-restart): a root helper started by a path unit.
RESTART_HELPER=$LIB_DIR/rowsafe-pg-restart
RESTART_SERVICE_FILE=/etc/systemd/system/rowsafe-pg-restart.service
RESTART_PATH_FILE=/etc/systemd/system/rowsafe-pg-restart.path
RESTART_ALLOW_FILE=$CONFIG_DIR/restart-allowed
RESTART_DIR=$STATE_DIR/restart
# Forks (--allow-create-cluster): new clusters created by their own unit,
# started by the restart helper.
CREATE_HELPER=$LIB_DIR/rowsafe-pg-create-cluster
CREATE_UNIT_FILE=/etc/systemd/system/rowsafe-pg-create-cluster@.service
CREATE_ALLOW_FILE=$CONFIG_DIR/create-cluster-allowed
CREATED_CLUSTERS_FILE=$CONFIG_DIR/created-clusters
CREATE_PORTS=5440-5499
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
NO_SETUP=0         # --no-setup
PROTECT_NAME=''    # --protect NAME
PROTECT_PORT=''    # --protect-port PORT
ALLOW_RESTART=''   # --allow-restart (yes) / --no-allow-restart (no); '' = ask once, on a terminal
ALLOW_CREATE_CLUSTER='' # --allow-create-cluster (yes) / --no-allow-create-cluster (no); '' = ask once
SETUP_STOP=0       # the plan limit was reached: don't offer more databases

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
  --no-setup             don't look for PostgreSQL or turn on backups
  --protect NAME         without questions: turn on backups for this server's PostgreSQL,
                         named NAME in Rowsafe. Never restarts PostgreSQL; prints the
                         command when it needs a restart
  --protect-port PORT    with --protect: the PostgreSQL on PORT (when there are several)
  --allow-restart        allow Rowsafe to restart or stop PostgreSQL when you ask
                         (Restart and Rewind in the dashboard, `rowsafe restart`),
                         only when someone confirms
  --no-allow-restart     turn that off (and remove the restart helper)
  --allow-create-cluster allow Rowsafe to create a new PostgreSQL cluster (a free port
                         in 5440-5499) when you fork a database to this server,
                         only when someone confirms (Debian and Ubuntu)
  --no-allow-create-cluster  turn that off
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
  first time: paste your bucket's URL (or pick Cloudflare R2, Backblaze B2,
  Amazon S3, Wasabi, DigitalOcean Spaces or any S3-compatible store), then its
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

Turning on backups:
  Once the agent runs, the installer looks for PostgreSQL on this server,
  asks for its name in Rowsafe, shows what would change and asks before
  changing anything. If PostgreSQL needs a restart for backups to start, it
  asks "Restart PostgreSQL now?" (default no); if you'd rather restart later,
  Rowsafe notices the restart by itself and finishes. Rowsafe itself never
  restarts PostgreSQL on its own: with --allow-restart (or yes at the
  question), it restarts or stops PostgreSQL when you ask (Restart, and
  Rewind the whole database, in the dashboard), and only when someone
  confirms. Automation: --protect NAME.

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

# as_agent CMD... runs CMD as the agent user. Everything under /opt/rowsafe
# and /var/lib/rowsafe (the agent's own directories) is changed this way:
# root acting there could be tricked by a planted symlink into changing any
# file on the system.
as_agent() { (cd / && runuser -u "$AGENT_USER" -- "$@" </dev/null); }

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
  { as_agent install -d -m 0755 "$vdir" &&
    as_agent install -m 0755 "$TMP/rowsafe-agent" "$vdir/.rowsafe-agent.install" &&
    as_agent mv -f "$vdir/.rowsafe-agent.install" "$STAGED"; } ||
    die "could not put rowsafe-agent $REL_VERSION into $vdir as $AGENT_USER (see above)"
  CHANGED=1
}

# switch_version points the managed symlink at the staged version, the same
# atomic swap the agent's self-update uses.
switch_version() {
  target=versions/$REL_VERSION/rowsafe-agent
  [ "$(readlink "$INSTALL_DIR/rowsafe-agent" 2>/dev/null || true)" = "$target" ] && return 0
  as_agent ln -sfn "$target" "$INSTALL_DIR/rowsafe-agent.install"
  as_agent mv -Tf "$INSTALL_DIR/rowsafe-agent.install" "$INSTALL_DIR/rowsafe-agent"
  # A manual install supersedes any self-update that was in flight.
  as_agent rm -rf "$STATE_DIR/update/pending"
  CHANGED=1
  ok "$INSTALL_DIR/rowsafe-agent -> $target"
}

make_dirs() {
  # These parents belong to root, so creating them as root is safe.
  install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$INSTALL_DIR"
  install -d -m 0755 -o root -g root "$LIB_DIR"
  install -d -m 0750 -o root -g "$AGENT_USER" "$CONFIG_DIR"
  install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$CONFIG_DIR/pgbackrest" "$STATE_DIR" "$LOG_DIR"
  # Inside the agent's directories: as the agent.
  as_agent mkdir -p -m 0755 "$INSTALL_DIR/versions"
  as_agent mkdir -p -m 0700 "$RESTART_DIR"
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
ExecStartPre=/usr/local/lib/rowsafe/rowsafe-agent-guard
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
# connect to PostgreSQL's Unix socket. For a standby server it also adds
# (and removes) the standby's lines in pg_hba.conf, which Debian and Ubuntu
# keep in /etc/postgresql.
NoNewPrivileges=yes
# /usr, /boot and /etc read-only, with the exceptions below. /var stays
# writable (drills, logs, pgBackRest reading the data directory).
ProtectSystem=full
ReadWritePaths=/etc/rowsafe /opt/rowsafe -/var/lib/rowsafe -/var/log/rowsafe -/etc/postgresql
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

# ---------------------------------------------------------------- restarts

# Rowsafe never restarts or stops PostgreSQL on its own. With root's
# permission (--allow-restart, or yes at the question), a person can ask for
# a restart (dashboard, `rowsafe restart`) or a rewind of the whole database
# (which stops PostgreSQL, swaps its data directory and starts it): the agent
# (unprivileged) writes a request to $RESTART_DIR, rowsafe-pg-restart.path
# starts the root helper, and the helper restarts, stops or starts only a
# unit listed in $RESTART_ALLOW_FILE.

install_restart_helper() {
  install -d -m 0755 -o root -g root "${RESTART_HELPER%/*}"
  _changed=0
  if write_file "$RESTART_HELPER" 0755 root:root <<'ROWSAFE_RESTART_HELPER_EOF'; then
#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# rowsafe-pg-restart: restarts or stops PostgreSQL when a person asked
# Rowsafe to (Restart in the dashboard, `rowsafe restart`; Rewind the whole
# database, which stops PostgreSQL, swaps its data directory and starts it).
#
# Installed by https://rowsafe.sh/install as
# /usr/local/lib/rowsafe/rowsafe-pg-restart, only when root allowed it
# (--allow-restart, or yes at the installer's question). It runs as root in
# rowsafe-pg-restart.service, which rowsafe-pg-restart.path starts when the
# agent writes a request; the agent itself cannot restart anything.
#
# The request (/var/lib/rowsafe/restart/request, in a directory the agent
# user owns) is one line: "ID ACTION PORT", ACTION being restart, stop or
# start ("ID PORT", from agents before 0.4.0, means restart). It is read and
# removed with the agent user's privileges, never root's, so nothing planted
# there (a symlink, a FIFO) can make root read, write or wait on anything.
# The port must be listed in /etc/rowsafe/restart-allowed ("PORT UNIT"
# lines, written by root); only that unit is restarted, stopped or started,
# and it is restarted at most once a minute. The answer goes to
# /run/rowsafe-pg-restart/result (root's directory, readable by the agent)
# as key=value lines: id, action, ok (1 or 0), unit, error and finished_at.
#
# Forks: "ID create-cluster PORT MAJOR NAME" asks for a new, empty
# PostgreSQL cluster (a person forked a database to a new port). Only when
# root allowed it (/etc/rowsafe/create-cluster-allowed, "ports MIN-MAX",
# written by the installer with --allow-create-cluster): the helper checks
# the request and starts rowsafe-pg-create-cluster@MAJOR-PORT-NAME.service,
# a separate sandboxed unit that runs pg_createcluster and can't write
# anything of Rowsafe's. Once it succeeded and the new cluster's
# configuration names the requested port, this helper lists the cluster in
# /etc/rowsafe/created-clusters ("PORT UNIT") and then stops and starts it
# like the clusters in restart-allowed. A failure's reason comes from that
# unit's journal, never from a file another process could write.
#
# The agent reads the next line to know what this helper can do.
# actions: restart stop start create-cluster

set -u
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
dir=${ROWSAFE_RESTART_DIR:-/var/lib/rowsafe/restart}
out_dir=${RUNTIME_DIRECTORY:-/run/rowsafe-pg-restart}
allow=${ROWSAFE_RESTART_ALLOW:-/etc/rowsafe/restart-allowed}
create_allow=${ROWSAFE_CREATE_CLUSTER_ALLOW:-/etc/rowsafe/create-cluster-allowed}
created=${ROWSAFE_CREATED_CLUSTERS:-/etc/rowsafe/created-clusters}
pg_conf_root=${ROWSAFE_PG_CONF_ROOT:-/etc/postgresql}
journalctl=${ROWSAFE_JOURNALCTL:-journalctl}
state=${STATE_DIRECTORY:-/var/lib/rowsafe-pg-restart}
agent_user=${ROWSAFE_AGENT_USER:-postgres}
systemctl=${ROWSAFE_SYSTEMCTL:-systemctl}
min_interval=60

log() { echo "rowsafe-pg-restart: $*" >&2; }

# as_agent runs a command with the agent user's privileges.
as_agent() { setpriv --reuid="$agent_user" --regid="$agent_user" --init-groups -- "$@"; }

id='' action='' unit='' ok=0 err=''

# answer writes the result atomically into root's own directory.
answer() {
  tmp=$(mktemp "$out_dir/.result.XXXXXX") || {
    log "cannot write the result in $out_dir"
    exit 0
  }
  printf 'id=%s\naction=%s\nok=%s\nunit=%s\nerror=%s\nfinished_at=%s\n' "$id" "$action" "$ok" "$unit" "$err" "$(date +%s)" >"$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$out_dir/result"
}

refuse() {
  err=$1
  log "refused: $1"
  answer
  exit 0
}

# root_only FILE: FILE is a regular file only root can change.
root_only() {
  [ "$(stat -c '%u' "$1")" = 0 ] || refuse "$1 is not owned by root"
  case $(stat -c '%A' "$1") in
    ?????w???? | ????????w?) refuse "$1 is writable by others than root" ;;
  esac
}

# create_cluster PORT MAJOR NAME: a new cluster for a fork, through its own
# sandboxed unit, when root allowed it and PORT is in the allowed range.
create_cluster() {
  c_port=$1 c_major=$2 c_name=$3
  [ -f "$create_allow" ] && [ ! -L "$create_allow" ] || refuse "creating PostgreSQL clusters from Rowsafe is not allowed on this server"
  root_only "$create_allow"
  range=$(awk '$1 == "ports" && $2 ~ /^[0-9]+-[0-9]+$/ { print $2; exit }' "$create_allow")
  [ -n "$range" ] || refuse "creating PostgreSQL clusters from Rowsafe is not allowed on this server"
  [ "$c_port" -ge "${range%-*}" ] && [ "$c_port" -le "${range#*-}" ] ||
    refuse "port $c_port is not in the ports Rowsafe may create clusters on ($range)"
  [ -f "$created" ] && [ ! -L "$created" ] || refuse "$created is missing: run the installer again with --allow-create-cluster"
  root_only "$created"
  for list in "$allow" "$created"; do
    if [ -f "$list" ] && awk -v p="$c_port" '$1 == p { f = 1 } END { exit !f }' "$list"; then
      refuse "port $c_port is already used by a cluster Rowsafe manages"
    fi
  done
  [ ! -e "$pg_conf_root/$c_major/$c_name" ] && [ ! -L "$pg_conf_root/$c_major/$c_name" ] ||
    refuse "a PostgreSQL $c_major cluster named $c_name already exists"
  unit=rowsafe-pg-create-cluster@$c_major-$c_port-$c_name.service
  log "create-cluster PostgreSQL $c_major $c_name on port $c_port (request $id)"
  since=$(date +%s)
  out=$(timeout 120 "$systemctl" start "$unit" 2>&1 </dev/null)
  rc=$?
  conf=$pg_conf_root/$c_major/$c_name/postgresql.conf
  if [ "$rc" = 0 ]; then
    # Only a cluster that is there, on the requested port, is listed.
    if [ -f "$conf" ] && [ ! -L "$conf" ] &&
      grep -Eq "^[[:space:]]*port[[:space:]]*=[[:space:]]*'?$c_port'?([[:space:]]|#|\$)" "$conf"; then
      if printf '%s postgresql@%s-%s.service\n' "$c_port" "$c_major" "$c_name" >>"$created"; then
        ok=1
        unit=postgresql@$c_major-$c_name.service
        log "create-cluster $unit: done"
      else
        err="the cluster was created, but $created couldn't be updated"
      fi
    else
      err="the new cluster's configuration ($conf) doesn't name port $c_port"
    fi
  else
    why=$("$journalctl" -u "$unit" --since "@$since" -o cat -n 20 --no-pager 2>/dev/null |
      sed -n 's/^rowsafe-pg-create-cluster: //p' | tail -n 1 | tr -cd '[:print:]' | cut -c1-300)
    if [ -n "$why" ]; then
      err=$why
    elif [ "$rc" = 124 ]; then
      err="creating the cluster did not finish within 2 minutes"
    else
      err="systemctl start $unit failed: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)"
    fi
  fi
  [ -z "$err" ] || log "$err"
  answer
  exit 0
}

request=$dir/request
as_agent test -e "$request" -o -L "$request" 2>/dev/null || exit 0
# Only a regular file is read, for at most 5 seconds; whatever it was, it is
# removed so the path unit doesn't fire again.
# shellcheck disable=SC2016 # $1 expands in the inner shell
line=$(as_agent sh -c '
  if [ -f "$1" ] && [ ! -L "$1" ]; then timeout 5 head -c 200 -- "$1"; fi
  rm -f -- "$1"' rowsafe-pg-restart "$request" 2>/dev/null | head -n 1)

if printf '%s\n' "$line" | grep -Eq '^[A-Za-z0-9_-]{1,64} [0-9]{1,5}$'; then
  id=${line% *}
  action=restart
  port=${line#* }
elif printf '%s\n' "$line" | grep -Eq '^[A-Za-z0-9_-]{1,64} (restart|stop|start) [0-9]{1,5}$'; then
  id=${line%% *}
  rest=${line#* }
  action=${rest% *}
  port=${rest#* }
elif printf '%s\n' "$line" | grep -Eq '^[A-Za-z0-9_-]{1,64} create-cluster [1-9][0-9]{3,4} [1-9][0-9] [a-z][a-z0-9_]{0,39}$'; then
  id=${line%% *}
  action=create-cluster
  # shellcheck disable=SC2086 # split the checked request into its fields
  set -- $line
  create_cluster "$3" "$4" "$5"
else
  refuse "malformed request"
fi

# The unit comes from restart-allowed or, for clusters created for forks,
# created-clusters; both must be files only root can change.
listed() { [ -f "$1" ] && [ ! -L "$1" ]; }
listed "$allow" || listed "$created" || refuse "restarting or stopping PostgreSQL from Rowsafe is not allowed on this server"
unit=''
for list in "$allow" "$created"; do
  listed "$list" || continue
  root_only "$list"
  unit=$(awk -v p="$port" '$1 == p && $2 ~ /^[A-Za-z0-9@._-]+\.service$/ { print $2; exit }' "$list")
  [ -z "$unit" ] || break
done
[ -n "$unit" ] || refuse "port $port is not in $allow: restarting or stopping it from Rowsafe is not allowed"

if [ "$action" = restart ]; then
  mkdir -p "$state"
  stamp=$state/last-$unit
  now=$(date +%s)
  last=$(cat "$stamp" 2>/dev/null || echo 0)
  case $last in '' | *[!0-9]*) last=0 ;; esac
  if [ $((now - last)) -lt "$min_interval" ]; then
    refuse "PostgreSQL ($unit) was restarted less than a minute ago; try again in a minute"
  fi
  echo "$now" >"$stamp"
fi

log "$action $unit (request $id)"
out=$(timeout 120 "$systemctl" "$action" "$unit" 2>&1 </dev/null)
rc=$?
if [ "$rc" = 0 ]; then
  ok=1
  log "${action} $unit: done"
else
  out=$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)
  if [ "$rc" = 124 ]; then
    err="systemctl $action $unit did not finish within 2 minutes"
  else
    err="systemctl $action $unit failed${out:+: $out}"
  fi
  log "$err"
fi
answer
ROWSAFE_RESTART_HELPER_EOF
    _changed=1
  fi
  if write_file "$RESTART_SERVICE_FILE" 0644 root:root <<'ROWSAFE_RESTART_SERVICE_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-pg-restart.service: restarts, stops or starts a PostgreSQL cluster
# that root listed in /etc/rowsafe/restart-allowed, when the Rowsafe agent
# asks because a person did (see /usr/local/lib/rowsafe/rowsafe-pg-restart).
# Started by rowsafe-pg-restart.path; installed by https://rowsafe.sh/install
# only when root allowed it.

[Unit]
Description=Rowsafe: restart or stop PostgreSQL on request
Documentation=https://rowsafe.sh/docs/reference/agent-configuration

[Service]
Type=oneshot
ExecStart=/usr/local/lib/rowsafe/rowsafe-pg-restart
TimeoutStartSec=180
# The agent user, whose privileges read and remove the request.
Environment=ROWSAFE_AGENT_USER=postgres
# The answer: root's own directory, which the agent can read.
RuntimeDirectory=rowsafe-pg-restart
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
# When each unit was last restarted (at most once a minute), out of the
# agent's reach.
StateDirectory=rowsafe-pg-restart
StateDirectoryMode=0700
UMask=0022

# Hardening. Root never writes into the agent's directory: the request is
# read and removed as the agent user (hence CAP_SETUID/CAP_SETGID, to drop
# to it). Then it asks systemd over its private socket to restart, stop or
# start one unit.
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=-/var/lib/rowsafe/restart -/etc/rowsafe/created-clusters
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
ROWSAFE_RESTART_SERVICE_EOF
    _changed=1
  fi
  if write_file "$RESTART_PATH_FILE" 0644 root:root <<'ROWSAFE_RESTART_PATH_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-pg-restart.path: starts rowsafe-pg-restart.service when the Rowsafe
# agent asks to restart or stop PostgreSQL (someone clicked Restart or Rewind
# in the dashboard, or ran `rowsafe restart`). Installed by
# https://rowsafe.sh/install only when root allowed it; remove it with
# --no-allow-restart.

[Unit]
Description=Rowsafe: watch for requests to restart or stop PostgreSQL
Documentation=https://rowsafe.sh/docs/reference/agent-configuration

[Path]
PathExists=/var/lib/rowsafe/restart/request
Unit=rowsafe-pg-restart.service

[Install]
WantedBy=multi-user.target
ROWSAFE_RESTART_PATH_EOF
    _changed=1
  fi
  if systemd_running; then
    [ "$_changed" = 0 ] || systemctl daemon-reload
    systemctl enable --now --quiet rowsafe-pg-restart.path
  else
    warn "systemd is not running here; the restart helper was installed but cannot be enabled"
  fi
}

remove_restart_helper() {
  [ -e "$RESTART_PATH_FILE" ] || [ -e "$RESTART_SERVICE_FILE" ] || [ -e "$RESTART_HELPER" ] || return 0
  if systemd_running; then
    systemctl disable --now --quiet rowsafe-pg-restart.path 2>/dev/null || true
  fi
  rm -f "$RESTART_PATH_FILE" "$RESTART_SERVICE_FILE" "$RESTART_HELPER"
  rmdir "${RESTART_HELPER%/*}" 2>/dev/null || true
  if systemd_running; then systemctl daemon-reload; fi
}

# restart_pairs prints "PORT UNIT" for the discovered clusters with a
# systemd unit (the ones a restart helper can restart).
restart_pairs() {
  [ -s "$TMP/clusters" ] || return 0
  awk -F '\t' '$12 != "-" && $12 ~ /^[A-Za-z0-9@._-]+\.service$/ { print $1, $12 }' "$TMP/clusters"
}

# restart_allowed PORT: is PORT in the allow list?
restart_allowed() {
  [ -f "$RESTART_ALLOW_FILE" ] && awk -v p="$1" '$1 == p { f = 1 } END { exit !f }' "$RESTART_ALLOW_FILE"
}

allow_restarts() {
  _pairs=$(restart_pairs)
  if [ -z "$_pairs" ]; then
    warn "found no systemd service running PostgreSQL here, so restarting or stopping it from Rowsafe stays off"
    return 0
  fi
  {
    echo "# PostgreSQL clusters Rowsafe may restart or stop when someone asks"
    echo "# (Restart and Rewind in the dashboard, \`rowsafe restart\`), only when they"
    echo "# confirm. Written by the installer (root); run it with --no-allow-restart"
    echo "# to turn this off."
    echo "# PORT UNIT"
    printf '%s\n' "$_pairs"
  } | write_file "$RESTART_ALLOW_FILE" 0644 root:root || true
  install_restart_helper
  ok "Rowsafe may restart or stop PostgreSQL when you ask (Restart, Rewind), only when someone confirms (turn off with --no-allow-restart)"
}

disallow_restarts() {
  create_clusters_allowed || remove_restart_helper # forks still use the helper
  if [ -d "$CONFIG_DIR" ]; then
    {
      echo "# Restarting or stopping PostgreSQL from Rowsafe is off on this server."
      echo "# Run the installer with --allow-restart to turn it on."
    } | write_file "$RESTART_ALLOW_FILE" 0644 root:root || true
  fi
}

# restart_access applies --allow-restart / --no-allow-restart, or asks once
# on a terminal. A re-run keeps the earlier answer (and refreshes the list).
restart_access() {
  case $ALLOW_RESTART in
    yes) allow_restarts ;;
    no)
      disallow_restarts
      ok "restarting or stopping PostgreSQL from Rowsafe is off"
      ;;
    *)
      if [ -f "$RESTART_ALLOW_FILE" ]; then
        if grep -q '^[0-9]' "$RESTART_ALLOW_FILE"; then allow_restarts; fi
        return 0
      fi
      [ "$TTY" = 1 ] && [ -n "$(restart_pairs)" ] || return 0
      say ""
      if confirm "Allow Rowsafe to restart or stop PostgreSQL when you ask? Only when someone clicks Restart or Rewind in the dashboard and confirms." y; then
        allow_restarts
      else
        disallow_restarts
        note "OK: Rowsafe can't restart or stop PostgreSQL (change it with --allow-restart)"
      fi
      ;;
  esac
}

# ---------------------------------------------------------------- forks

# With root's permission (--allow-create-cluster, or yes at the question),
# forking a database to this server can create a new PostgreSQL cluster for
# it: the agent asks the restart helper, which starts
# rowsafe-pg-create-cluster@MAJOR-PORT-NAME.service (root, its own sandbox)
# to run pg_createcluster on a port in $CREATE_PORTS. The new cluster is
# listed in $CREATED_CLUSTERS_FILE, so the helper may stop and start it.

create_clusters_allowed() { grep -qs '^ports ' "$CREATE_ALLOW_FILE"; }

install_create_cluster() {
  install -d -m 0755 -o root -g root "${CREATE_HELPER%/*}"
  _changed=0
  if write_file "$CREATE_HELPER" 0755 root:root <<'ROWSAFE_CREATE_CLUSTER_EOF'; then
#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# rowsafe-pg-create-cluster: creates a new, empty PostgreSQL cluster when a
# person forks a database in Rowsafe to a new port on this server.
#
# Installed by https://rowsafe.sh/install as
# /usr/local/lib/rowsafe/rowsafe-pg-create-cluster, only when root allowed
# it (--allow-create-cluster, or yes at the installer's question). It runs as
# root in rowsafe-pg-create-cluster@MAJOR-PORT-NAME.service, which only the
# root helper (rowsafe-pg-restart) starts, after checking the agent's
# request; the agent itself cannot create anything.
#
# It checks everything again: the port must be in the range root allowed
# (/etc/rowsafe/create-cluster-allowed, "ports MIN-MAX") and unused, the
# PostgreSQL major version installed and the name free. Then it runs
# pg_createcluster (Debian and Ubuntu, postgresql-common) without starting
# the cluster. It writes nothing of Rowsafe's: the root helper checks the new
# cluster and lists it in /etc/rowsafe/created-clusters itself, and reads a
# failure's reason (the last "rowsafe-pg-create-cluster:" line) from this
# unit's journal.

set -u
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
allow=${ROWSAFE_CREATE_CLUSTER_ALLOW:-/etc/rowsafe/create-cluster-allowed}
created=${ROWSAFE_CREATED_CLUSTERS:-/etc/rowsafe/created-clusters}
pg_root=${ROWSAFE_PG_ROOT:-/usr/lib/postgresql}
conf_root=${ROWSAFE_PG_CONF_ROOT:-/etc/postgresql}
pg_createcluster=${ROWSAFE_PG_CREATECLUSTER:-pg_createcluster}

fail() {
  echo "rowsafe-pg-create-cluster: $1" >&2
  exit 1
}

instance=${1:-}
printf '%s\n' "$instance" | grep -Eq '^[1-9][0-9]-[1-9][0-9]{3,4}-[a-z][a-z0-9_]{0,39}$' || fail "malformed cluster request"
major=${instance%%-*}
rest=${instance#*-}
port=${rest%%-*}
name=${rest#*-}

[ -f "$allow" ] && [ ! -L "$allow" ] && [ "$(stat -c '%u' "$allow")" = 0 ] ||
  fail "creating PostgreSQL clusters from Rowsafe is not allowed on this server"
case $(stat -c '%A' "$allow") in
  ?????w???? | ????????w?) fail "$allow is writable by others than root" ;;
esac
range=$(awk '$1 == "ports" && $2 ~ /^[0-9]+-[0-9]+$/ { print $2; exit }' "$allow")
[ -n "$range" ] && [ "$port" -ge "${range%-*}" ] && [ "$port" -le "${range#*-}" ] ||
  fail "port $port is not in the ports Rowsafe may create clusters on (${range:-none})"
[ -x "$pg_root/$major/bin/postgres" ] || fail "PostgreSQL $major is not installed on this server"
command -v "$pg_createcluster" >/dev/null 2>&1 ||
  fail "pg_createcluster is missing: Rowsafe creates clusters on Debian and Ubuntu (package postgresql-common)"
[ ! -e "$conf_root/$major/$name" ] || fail "a PostgreSQL $major cluster named $name already exists"
if grep -Eqs "^[[:space:]]*port[[:space:]]*=[[:space:]]*'?$port'?([[:space:]]|#|\$)" "$conf_root"/*/*/postgresql.conf; then
  fail "port $port is already used by another PostgreSQL cluster"
fi
if [ -f "$created" ] && awk -v p="$port" '$1 == p { f = 1 } END { exit !f }' "$created"; then
  fail "port $port is already used by a cluster Rowsafe created"
fi

out=$("$pg_createcluster" --port "$port" --start-conf auto "$major" "$name" 2>&1 </dev/null) ||
  fail "pg_createcluster failed: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)"
echo "rowsafe-pg-create-cluster: created PostgreSQL $major cluster $name on port $port" >&2
ROWSAFE_CREATE_CLUSTER_EOF
    _changed=1
  fi
  if write_file "$CREATE_UNIT_FILE" 0644 root:root <<'ROWSAFE_CREATE_UNIT_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-pg-create-cluster@MAJOR-PORT-NAME.service: creates a new, empty
# PostgreSQL cluster for a fork (pg_createcluster), when a person forked a
# database in Rowsafe to a new port on this server. Started only by the root
# helper (rowsafe-pg-restart.service) after it checked the agent's request;
# installed by https://rowsafe.sh/install only when root allowed it
# (--allow-create-cluster).

[Unit]
Description=Rowsafe: create PostgreSQL cluster %i for a fork
Documentation=https://rowsafe.sh/docs/guides/fork

[Service]
Type=oneshot
ExecStart=/usr/local/lib/rowsafe/rowsafe-pg-create-cluster %i
TimeoutStartSec=110
UMask=0022

# Hardening. pg_createcluster writes the cluster's configuration, data and
# log directories, runs initdb as postgres (hence CAP_SETUID/CAP_SETGID) and
# hands the new files to postgres (CAP_CHOWN, CAP_FOWNER). It can't write
# anything else: the root helper checks the new cluster and lists it in
# /etc/rowsafe/created-clusters itself, and reads a failure's reason from
# this unit's journal.
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETUID CAP_SETGID
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/etc/postgresql /var/lib/postgresql -/var/log/postgresql
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
ROWSAFE_CREATE_UNIT_EOF
    _changed=1
  fi
  if [ ! -f "$CREATED_CLUSTERS_FILE" ]; then
    {
      echo "# PostgreSQL clusters Rowsafe created for forks (PORT UNIT). The restart"
      echo "# helper may stop and start them like those in restart-allowed."
    } | write_file "$CREATED_CLUSTERS_FILE" 0644 root:root || true
  fi
  if systemd_running && [ "$_changed" = 1 ]; then systemctl daemon-reload; fi
}

remove_create_cluster() {
  [ -e "$CREATE_HELPER" ] || [ -e "$CREATE_UNIT_FILE" ] || return 0
  rm -f "$CREATE_HELPER" "$CREATE_UNIT_FILE"
  if systemd_running; then systemctl daemon-reload; fi
}

allow_create_clusters() {
  if ! command -v pg_createcluster >/dev/null 2>&1; then
    warn "pg_createcluster isn't installed here (Debian and Ubuntu's postgresql-common), so creating clusters for forks stays off"
    return 0
  fi
  {
    echo "# Rowsafe may create a new PostgreSQL cluster on one of these ports when"
    echo "# someone forks a database to this server and confirms. Written by the"
    echo "# installer (root); run it with --no-allow-create-cluster to turn this off."
    echo "ports $CREATE_PORTS"
  } | write_file "$CREATE_ALLOW_FILE" 0644 root:root || true
  install_create_cluster
  install_restart_helper
  as_agent mkdir -p -m 0700 "$RESTART_DIR"
  ok "Rowsafe may create a new PostgreSQL cluster (ports $CREATE_PORTS) when you fork a database here (turn off with --no-allow-create-cluster)"
}

disallow_create_clusters() {
  remove_create_cluster
  if [ -d "$CONFIG_DIR" ]; then
    {
      echo "# Creating PostgreSQL clusters for forks is off on this server."
      echo "# Run the installer with --allow-create-cluster to turn it on."
    } | write_file "$CREATE_ALLOW_FILE" 0644 root:root || true
  fi
  # The helper stays while restarts are allowed; clusters created earlier
  # stay listed in $CREATED_CLUSTERS_FILE.
  grep -qs '^[0-9]' "$RESTART_ALLOW_FILE" || grep -qs '^[0-9]' "$CREATED_CLUSTERS_FILE" || remove_restart_helper
}

# create_cluster_access applies --allow-create-cluster /
# --no-allow-create-cluster, or asks once on a terminal. A re-run keeps the
# earlier answer.
create_cluster_access() {
  case $ALLOW_CREATE_CLUSTER in
    yes) allow_create_clusters ;;
    no)
      disallow_create_clusters
      ok "creating PostgreSQL clusters for forks is off"
      ;;
    *)
      if [ -f "$CREATE_ALLOW_FILE" ]; then
        if create_clusters_allowed; then allow_create_clusters; fi
        return 0
      fi
      [ "$TTY" = 1 ] && command -v pg_createcluster >/dev/null 2>&1 || return 0
      say ""
      if confirm "Allow Rowsafe to create a new PostgreSQL cluster here when you fork a database to this server? Only when someone confirms a fork; ports $CREATE_PORTS." y; then
        allow_create_clusters
      else
        disallow_create_clusters
        note "OK: forks to this server go into an empty cluster you create (change it with --allow-create-cluster)"
      fi
      ;;
  esac
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

BUCKET_RE='^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'

# parse_bucket_url URL fills S_PROVIDER, S_ENDPOINT, S_PORT, S_BUCKET,
# S_REGION and S_URI from a pasted bucket URL: Cloudflare R2's "S3 API" URL
# (https://<account>[.eu|.fedramp].r2.cloudflarestorage.com/<bucket>),
# Backblaze B2, Amazon S3, Wasabi and DigitalOcean Spaces in path or
# virtual-host form, s3://<bucket> (AWS), or any other https endpoint
# (host[:port]/<bucket>). S_BUCKET stays empty when the URL has none, and
# S_REGION when it must be asked (s3://, other storage). Returns 1 when it
# can't tell, 2 for a provider's dashboard link rather than the bucket's.
parse_bucket_url() {
  S_PROVIDER='' S_ENDPOINT='' S_PORT='' S_BUCKET='' S_REGION='' S_URI=''
  _u=$1
  case $_u in
    [Ss]3://*)
      _b=$(printf '%s\n' "${_u#*://}" | sed 's|[/?#].*$||')
      matches "$_b" "$BUCKET_RE" || return 1
      S_PROVIDER=s3 S_BUCKET=$_b S_URI=host
      return 0
      ;;
    [Hh][Tt][Tt][Pp][Ss]://*) ;;
    *://*) return 1 ;;
  esac
  _h=$(host_of "$_u")
  # The first path segment: the bucket in path-style URLs.
  _seg=$(printf '%s\n' "$_u" | sed -e 's|^[A-Za-z][A-Za-z0-9+.-]*://||' -e 's|^[^/?#]*||' -e 's|^/*||' -e 's|[/?#].*$||')
  case $_h in
    dash.cloudflare.com | *.backblaze.com | backblaze.com | console.aws.amazon.com | *.console.aws.amazon.com | \
      console.wasabisys.com | cloud.digitalocean.com)
      return 2
      ;;
  esac
  _hb=''
  if _m=$(printf '%s\n' "$_h" | sed -nE 's/^[0-9a-f]{32}(\.(eu|fedramp))?\.r2\.cloudflarestorage\.com$/x/p') && [ -n "$_m" ]; then
    S_PROVIDER=r2 S_ENDPOINT=$_h S_REGION=auto S_URI=path
  elif _m=$(printf '%s\n' "$_h" | sed -nE 's/^(([a-z0-9][a-z0-9.-]*)\.)?s3\.([a-z]+-[a-z]+-[0-9]{3})\.backblazeb2\.com$/\2|\3/p') && [ -n "$_m" ]; then
    _hb=${_m%%|*} S_REGION=${_m#*|}
    S_PROVIDER=b2 S_ENDPOINT=s3.$S_REGION.backblazeb2.com S_URI=path
  elif _m=$(printf '%s\n' "$_h" | sed -nE 's/^(([a-z0-9][a-z0-9.-]*)\.)?s3[.-]([a-z]{2}(-gov)?-[a-z]+-[0-9])\.amazonaws\.com$/\2|\3/p') && [ -n "$_m" ]; then
    _hb=${_m%%|*} S_REGION=${_m#*|}
    S_PROVIDER=s3 S_ENDPOINT=s3.$S_REGION.amazonaws.com S_URI=host
  elif _m=$(printf '%s\n' "$_h" | sed -nE 's/^(([a-z0-9][a-z0-9.-]*)\.)?s3\.amazonaws\.com$/\2|/p') && [ -n "$_m" ]; then
    _hb=${_m%%|*} S_REGION=us-east-1
    S_PROVIDER=s3 S_ENDPOINT=s3.us-east-1.amazonaws.com S_URI=host
  elif _m=$(printf '%s\n' "$_h" | sed -nE 's/^(([a-z0-9][a-z0-9.-]*)\.)?s3\.(([a-z]{2}-[a-z]+-[0-9])\.)?wasabisys\.com$/\2|\4/p') && [ -n "$_m" ]; then
    _hb=${_m%%|*} S_REGION=${_m#*|}
    [ -n "$S_REGION" ] || S_REGION=us-east-1
    S_PROVIDER=wasabi S_ENDPOINT=s3.$S_REGION.wasabisys.com S_URI=path
  elif _m=$(printf '%s\n' "$_h" | sed -nE 's/^(([a-z0-9][a-z0-9-]*)\.)?([a-z]{3}[0-9])(\.cdn)?\.digitaloceanspaces\.com$/\2|\3/p') && [ -n "$_m" ]; then
    _hb=${_m%%|*}
    # Spaces signs with us-east-1 whatever the datacenter; the endpoint picks it.
    S_PROVIDER=spaces S_ENDPOINT=${_m#*|}.digitaloceanspaces.com S_REGION=us-east-1 S_URI=host
  else
    _p=''
    case $_h in
      *:*)
        _p=${_h##*:}
        _h=${_h%:*}
        ;;
    esac
    matches "$_h" '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$' || return 1
    [ -z "$_p" ] || matches "$_p" '^[1-9][0-9]{0,4}$' || return 1
    [ "$_p" != 443 ] || _p=''
    S_PROVIDER=s3-compatible S_ENDPOINT=$_h S_PORT=$_p S_URI=path
  fi
  S_BUCKET=${_hb:-$_seg}
  matches "$S_BUCKET" "$BUCKET_RE" || S_BUCKET=''
  # Host-style URLs put the bucket in the TLS host name; dots break that.
  case $S_URI:$S_BUCKET in host:*.*) S_URI=path ;; esac
  return 0
}

provider_name() {
  case $1 in
    r2) echo "Cloudflare R2" ;;
    b2) echo "Backblaze B2" ;;
    s3) echo "Amazon S3" ;;
    wasabi) echo "Wasabi" ;;
    spaces) echo "DigitalOcean Spaces" ;;
    *) echo "S3-compatible storage" ;;
  esac
}

# key_hint says where the provider makes the access key.
key_hint() {
  case $S_PROVIDER in
    r2) tty_hint "Access key: R2 > Manage API tokens > Create API token, \"Object Read & Write\" for this bucket." ;;
    b2) tty_hint "Access key: Application Keys > Add a New Application Key with Read and Write access to the bucket." ;;
    s3) tty_hint "Access key: an IAM key allowed to list, read, write and delete objects in the bucket." ;;
    wasabi) tty_hint "Access key: Access Keys > Create new access key, for a user who may read, write and delete in the bucket." ;;
    spaces) tty_hint "Access key: Spaces Object Storage > Access Keys, with read/write access to the Space." ;;
    *) tty_hint "Access key: one that can list, read, write and delete in the bucket." ;;
  esac
}

# ask_bucket_url is the first storage question: a pasted bucket URL fills in
# everything it can. Enter, or a URL it can't read, switches to the menu.
ask_bucket_url() {
  tty_say ""
  tty_say "${BOLD}Paste your bucket's URL${RESET}, or press Enter to pick your provider instead."
  tty_hint "Cloudflare R2: the \"S3 API\" URL on the bucket's Settings page, like"
  tty_hint "https://<account-id>.r2.cloudflarestorage.com/<bucket>. Others: the bucket's endpoint URL."
  while :; do
    ask _v "Bucket URL" "$S_URL"
    if [ -z "$_v" ]; then
      S_MODE=menu
      return 0
    fi
    case $_v in
      [Hh][Tt][Tt][Pp]://*)
        tty_bad "Plain http:// is not supported; the storage must serve HTTPS."
        continue
        ;;
    esac
    _rc=0
    parse_bucket_url "$_v" || _rc=$?
    case $_rc in
      0) break ;;
      2) tty_bad "That's a link to your provider's dashboard, not to the bucket. Pick your provider:" ;;
      *) tty_bad "Rowsafe can't tell which storage that is. Pick your provider:" ;;
    esac
    S_MODE=menu
    return 0
  done
  S_URL=$_v
  tty_hint "$(provider_name "$S_PROVIDER"), endpoint $S_ENDPOINT${S_PORT:+:$S_PORT}${S_BUCKET:+, bucket $S_BUCKET}"
  [ -z "$S_BUCKET" ] || S_BUCKET_KNOWN=1
  case $S_PROVIDER in
    s3) [ -n "$S_REGION" ] || ask_s3 ;;
    s3-compatible)
      ask S_REGION "Region (most self-hosted storage accepts us-east-1)" us-east-1
      # TLS options for a private CA come from the environment or agent.env.
      S_CA=$(s_get ROWSAFE_REPO_S3_CA_FILE)
      S_VERIFY=$(s_get ROWSAFE_REPO_S3_VERIFY_TLS)
      ;;
  esac
  key_hint
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
  while [ "$S_BUCKET_KNOWN" = 0 ]; do
    ask _v "Bucket name" "$S_BUCKET"
    _v=${_v#s3://}
    _v=${_v%/}
    if matches "$_v" "$BUCKET_RE"; then
      S_BUCKET=$_v
      break
    fi
    tty_bad "Bucket names are 3-63 characters: lowercase letters, numbers, dots and hyphens."
  done
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
  S_URL='' S_MODE=url
  load_storage_path
  n=1
  if [ -n "$STORAGE_PROVIDER" ]; then
    n=$(provider_number "$STORAGE_PROVIDER")
    S_MODE=menu
  fi
  last=''
  while :; do
    S_BUCKET_KNOWN=0
    [ "$S_MODE" = menu ] || ask_bucket_url
    if [ "$S_MODE" = menu ]; then
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
    fi
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

# ---------------------------------------------------------------- databases

# agent_run ARGS... runs the installed agent as the agent user with only
# agent.env in its environment, like the service. Never on the installer's
# stdin: that is the script itself when piped from curl.
agent_run() {
  # shellcheck disable=SC2016 # $1 expands in the inner shell
  runuser -u "$AGENT_USER" -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/var/lib/postgresql \
    LANG="${LANG:-C}" LC_ALL="${LC_ALL:-}" \
    sh -c 'set -a; . "$1"; set +a; shift; exec "$@"' rowsafe-setup "$ENV_FILE" "$INSTALL_DIR/rowsafe-agent" "$@" </dev/null
}

# agent_show ARGS... runs agent_run with its output indented like note, and
# returns its exit status.
agent_show() {
  {
    _src=0
    agent_run "$@" 2>&1 || _src=$?
    echo "$_src" >"$TMP/agent.rc"
  } | sed 's/^/    /'
  return "$(cat "$TMP/agent.rc")"
}

agent_running() {
  if systemd_running; then
    systemctl is-active --quiet "$SERVICE"
  else
    have pgrep && pgrep -u "$AGENT_USER" -f 'rowsafe-agent run' >/dev/null 2>&1
  fi
}

# discover lists the local PostgreSQL clusters in $TMP/clusters (the
# tab-separated lines of `rowsafe-agent setup discover`).
discover() {
  : >"$TMP/clusters"
  if ! agent_run setup discover >"$TMP/clusters" 2>"$TMP/discover.err"; then
    sed 's/^/    /' "$TMP/discover.err" >&2
    warn "could not look for PostgreSQL on this server"
    : >"$TMP/clusters"
    return 1
  fi
  sed 's/^/    /' "$TMP/discover.err"
  return 0
}

# The cluster being set up (one line of $TMP/clusters).
C_PORT='' C_SOCK='' C_MAJOR='' C_CLUSTER='' C_NAME='' C_REG='' C_STATUS='' C_DBS='' C_SIZE='' C_UNIT='' C_ID=''

# read_cluster LINE splits a discover line (no field is empty: "-" stands
# for nothing, so tabs never collapse).
read_cluster() {
  _f() { printf '%s\n' "$1" | cut -f"$2"; }
  C_PORT=$(_f "$1" 1) C_SOCK=$(_f "$1" 2) C_MAJOR=$(_f "$1" 3) C_CLUSTER=$(_f "$1" 4)
  C_NAME=$(_f "$1" 7) C_REG=$(_f "$1" 8) C_STATUS=$(_f "$1" 9) C_DBS=$(_f "$1" 10)
  C_SIZE=$(_f "$1" 11) C_UNIT=$(_f "$1" 12) C_ID=$(_f "$1" 13)
  [ "$C_ID" != - ] || C_ID=''
}

cluster_desc() {
  _d=$C_DBS
  [ "$_d" != - ] || _d=none
  printf 'PostgreSQL %s on port %s (%s; databases: %s)' "$C_MAJOR" "$C_PORT" "$C_SIZE" "$(printf '%s' "$_d" | sed 's/,/, /g')"
}

# restart_cmd is how a person restarts this cluster.
restart_cmd() {
  if [ "$C_UNIT" != - ]; then
    echo "sudo systemctl restart ${C_UNIT%.service}"
  elif [ "$C_CLUSTER" != - ]; then
    echo "sudo pg_ctlcluster $C_MAJOR $C_CLUSTER restart"
  else
    echo "sudo systemctl restart postgresql"
  fi
}

restart_later() {
  say ""
  say "    OK. Restart PostgreSQL when it suits you:"
  say "        $(restart_cmd)"
  if restart_allowed "$C_PORT"; then
    say "    (or with Restart PostgreSQL in the Rowsafe dashboard)."
  fi
  say "    Rowsafe notices the restart by itself and finishes setting up. Nothing else to do."
}

# restart_postgres restarts the cluster, because the person said yes.
restart_postgres() {
  step "Restarting PostgreSQL $C_MAJOR"
  _rc=0
  if systemd_running && [ "$C_UNIT" != - ]; then
    timeout 180 systemctl restart "$C_UNIT" >"$TMP/restart.log" 2>&1 </dev/null || _rc=$?
  elif [ "$C_CLUSTER" != - ] && have pg_ctlcluster; then
    timeout 180 pg_ctlcluster "$C_MAJOR" "$C_CLUSTER" restart >"$TMP/restart.log" 2>&1 </dev/null || _rc=$?
  else
    warn "the installer doesn't know how PostgreSQL is run on this server, so it can't restart it"
    return 1
  fi
  if [ "$_rc" != 0 ]; then
    tail -n 5 "$TMP/restart.log" | sed 's/^/    /' >&2
    warn "restarting PostgreSQL failed"
    return 1
  fi
  ok "PostgreSQL restarted"
}

offer_restart() {
  say ""
  tty_say "PostgreSQL needs a quick restart for backups to start. It takes a few"
  tty_say "seconds; open connections are dropped and apps reconnect."
  if confirm "Restart PostgreSQL now?" n; then
    if restart_postgres; then
      finish_setup
      return 0
    fi
  fi
  restart_later
}

# finish_setup [TIMEOUT] waits until the database is protected and its first
# full backup runs, then shows where to see it.
finish_setup() {
  _rc=0
  agent_show setup wait --database "$C_ID" --timeout "${1:-5m}" || _rc=$?
  [ "$_rc" = 0 ] || [ "$_rc" = 2 ] || warn "could not follow the setup (see above); Rowsafe finishes it on its own"
  if agent_run setup status --database "$C_ID" >"$TMP/status" 2>/dev/null; then
    _url=$(cut -f5 "$TMP/status")
    [ -z "$_url" ] || [ "$_url" = - ] || note "Dashboard: $_url"
  fi
}

# ask_name asks for the database's name in Rowsafe, into C_NAME.
ask_name() {
  while :; do
    ask _v "Name it in Rowsafe" "$C_NAME"
    if matches "$_v" '^[a-z][a-z0-9-]{1,39}$'; then
      C_NAME=$_v
      return 0
    fi
    tty_bad "Use 2-40 lowercase letters, digits and dashes, starting with a letter."
  done
}

# plan_cluster registers the cluster and shows the plan; its exit status is
# `setup plan`'s. C_ID is set once registered.
plan_cluster() {
  install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$TMP/setup"
  rm -f "$TMP/setup/id"
  _rc=0
  agent_show setup plan --name "$C_NAME" --port "$C_PORT" --socket-dir "$C_SOCK" --id-file "$TMP/setup/id" || _rc=$?
  C_ID=$(cat "$TMP/setup/id" 2>/dev/null || true)
  return "$_rc"
}

# protect_cluster (interactive): plan, "Turn on backups?", apply, restart.
protect_cluster() {
  step "Preparing a plan"
  while :; do
    _prc=0
    plan_cluster || _prc=$?
    [ "$_prc" = 7 ] || break
    ask_name
  done
  _force=''
  case $_prc in
    0)
      say ""
      if ! confirm "Nothing changes until you say yes. Turn on backups for $C_NAME now?" y; then
        note "OK, nothing was changed. Turn them on later in the Rowsafe dashboard, or run this installer again."
        return 0
      fi
      ;;
    3)
      say ""
      if ! confirm "Replace it with Rowsafe?" n; then
        note "OK, nothing was changed."
        return 0
      fi
      _force=1
      ;;
    4)
      SETUP_STOP=1
      return 0
      ;;
    5) return 0 ;;
    10)
      offer_restart
      return 0
      ;;
    *)
      warn "could not prepare a plan for $C_NAME (see above); you can finish in the Rowsafe dashboard"
      return 0
      ;;
  esac
  step "Turning on backups for $C_NAME"
  _arc=0
  agent_show setup apply --database "$C_ID" ${_force:+--force} || _arc=$?
  case $_arc in
    0) finish_setup ;;
    10) offer_restart ;;
    *) warn "turning on backups for $C_NAME failed (see above); nothing restarted" ;;
  esac
}

# setup_databases (interactive) goes through every cluster found.
setup_databases() {
  if [ ! -s "$TMP/clusters" ]; then
    note "No running PostgreSQL found that the agent can reach. Once it runs, run this installer again."
    return 0
  fi
  _count=$(wc -l <"$TMP/clusters" | tr -d ' ')
  while IFS= read -r _line <&4; do
    [ "$SETUP_STOP" = 0 ] || break
    read_cluster "$_line"
    say ""
    case $C_REG:$C_STATUS in
      yes:active)
        ok "$(cluster_desc) is protected as $C_NAME"
        continue
        ;;
      yes:verifying)
        ok "$(cluster_desc): backups are on as $C_NAME; Rowsafe is checking them"
        continue
        ;;
      yes:awaiting_restart)
        note "Found $(cluster_desc): backups for $C_NAME wait for a PostgreSQL restart."
        offer_restart
        continue
        ;;
      yes:*)
        note "Found $(cluster_desc): added to Rowsafe as $C_NAME, backups not on yet."
        ;;
      *)
        note "Found $(cluster_desc)"
        if [ "$_count" -gt 1 ] && ! confirm "Set up backups for it?" y; then
          continue
        fi
        ask_name
        ;;
    esac
    protect_cluster
  done 4<"$TMP/clusters"
}

# protect_unattended is --protect NAME: no questions, never a restart.
protect_unattended() {
  step "Turning on backups for $PROTECT_NAME"
  if [ -n "$PROTECT_PORT" ]; then
    _line=$(awk -F '\t' -v p="$PROTECT_PORT" '$1 == p' "$TMP/clusters")
    [ -n "$_line" ] || die "found no PostgreSQL on port $PROTECT_PORT that the agent can reach"
  else
    case $(wc -l <"$TMP/clusters" | tr -d ' ') in
      0) die "found no running PostgreSQL that the agent can reach" ;;
      1) _line=$(cat "$TMP/clusters") ;;
      *) die "found several PostgreSQL clusters (ports $(cut -f1 "$TMP/clusters" | tr '\n' ' ')); pick one with --protect-port" ;;
    esac
  fi
  read_cluster "$_line"
  C_NAME=$PROTECT_NAME
  note "$(cluster_desc)"
  _prc=0
  plan_cluster || _prc=$?
  case $_prc in
    0) ;;
    5) return 0 ;;
    10)
      restart_later
      return 0
      ;;
    3) die "another backup tool is set up for this PostgreSQL; run the installer on a terminal to replace it" ;;
    7) die "the name $PROTECT_NAME is taken in your Rowsafe organization; pick another with --protect" ;;
    *) die "could not turn on backups for $PROTECT_NAME (see above)" ;;
  esac
  _arc=0
  agent_show setup apply --database "$C_ID" || _arc=$?
  case $_arc in
    0) finish_setup 3m ;;
    10) restart_later ;;
    *) die "turning on backups for $PROTECT_NAME failed (see above)" ;;
  esac
}

# next_steps says how to turn on backups when the installer didn't.
next_steps() {
  say ""
  say "${BOLD}${GREEN}${CHECK} All set.${RESET} ${BOLD}Next: turn on backups for this server's PostgreSQL.${RESET}"
  if [ "${1:-}" = not-running ]; then
    say "    Once the agent runs, run this installer again from a terminal: it finds"
    say "    PostgreSQL and asks before changing anything. Or use the Rowsafe dashboard."
  else
    say "    Run this installer again from a terminal: it finds PostgreSQL and asks"
    say "    before changing anything (or, without questions: --protect NAME)."
    say "    Or use the Rowsafe dashboard, where $(uname -n) shows up within a minute."
  fi
}

# databases runs once the agent is up: restart access, then backups.
databases() {
  [ "$ALLOW_RESTART" != no ] || disallow_restarts
  [ -z "$ALLOW_CREATE_CLUSTER" ] || create_cluster_access # forks
  if [ ! -f "$STATE_DIR/agent.json" ] || ! agent_running; then
    [ -z "$PROTECT_NAME" ] || die "the agent is not running, so backups can't be turned on yet; see 'journalctl -u rowsafe-agent'"
    [ "$ALLOW_RESTART" != yes ] || warn "the agent is not running; run the installer again with --allow-restart once it is"
    next_steps not-running
    return 0
  fi
  interactive=0
  if [ "$TTY" = 1 ] && [ "$NO_SETUP" = 0 ]; then interactive=1; fi
  if [ "$interactive" = 1 ] || [ -n "$PROTECT_NAME" ] || [ "$ALLOW_RESTART" = yes ] || grep -qs '^[0-9]' "$RESTART_ALLOW_FILE"; then
    say ""
    step "Looking for PostgreSQL on this server"
    if ! discover; then
      [ -z "$PROTECT_NAME" ] || die "could not look for PostgreSQL (see above)"
      next_steps
      return 0
    fi
    restart_access
    [ -n "$ALLOW_CREATE_CLUSTER" ] || create_cluster_access # forks
  fi
  if [ -n "$PROTECT_NAME" ]; then
    protect_unattended
  elif [ "$interactive" = 1 ]; then
    setup_databases
  else
    next_steps
  fi
}

# ---------------------------------------------------------------- modes

install_agent() {
  require_root
  detect_os
  detect_arch
  check_postgres
  say "${BOLD}Rowsafe agent installer${RESET}: backups, restore to any second and weekly"
  say "restore tests for the PostgreSQL on this server. Nothing changes without your yes."
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
  # The unit now runs the guard from $LIB_DIR. (/opt is root's, so removing
  # this one path as root follows no symlink the agent could plant.)
  rm -rf "$OLD_GUARD_DIR"

  # 3. Unconfigured: stop here and say exactly what to fill in.
  missing=$(missing_config)
  if [ -n "$missing" ]; then
    [ -z "$PROTECT_NAME" ] || warn "--protect needs the agent running; set the settings below, then run the installer again"
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
    if [ "$need_binary" = 1 ] && [ "$installed" != "$REL_VERSION" ]; then as_agent rm -rf "${STAGED%/rowsafe-agent}"; fi
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
  databases
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
  remove_restart_helper
  remove_create_cluster
  rm -f "$GUARD_FILE"
  rmdir "$LIB_DIR" 2>/dev/null || true
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
      --no-setup) NO_SETUP=1 ;;
      --allow-restart) ALLOW_RESTART=yes ;;
      --no-allow-restart) ALLOW_RESTART=no ;;
      --allow-create-cluster) ALLOW_CREATE_CLUSTER=yes ;;
      --no-allow-create-cluster) ALLOW_CREATE_CLUSTER=no ;;
      --protect)
        [ $# -ge 2 ] || die "--protect needs the database's name in Rowsafe"
        printf '%s\n' "$2" | grep -Eq '^[a-z][a-z0-9-]{1,39}$' ||
          die "--protect: names use 2-40 lowercase letters, digits and dashes, starting with a letter"
        PROTECT_NAME=$2
        shift
        ;;
      --protect-port)
        [ $# -ge 2 ] || die "--protect-port needs a port"
        printf '%s\n' "$2" | grep -Eq '^[1-9][0-9]{0,4}$' || die "--protect-port needs a port number"
        PROTECT_PORT=$2
        shift
        ;;
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
  if [ "$mode" != install ] && { [ "$NO_SETUP" = 1 ] || [ -n "$PROTECT_NAME" ] || [ -n "$ALLOW_RESTART" ] || [ -n "$ALLOW_CREATE_CLUSTER" ]; }; then
    die "--no-setup, --protect, --allow-restart and --allow-create-cluster only go with an install"
  fi
  [ -z "$PROTECT_PORT" ] || [ -n "$PROTECT_NAME" ] || die "--protect-port only goes with --protect"
  [ "$NO_SETUP" = 0 ] || [ -z "$PROTECT_NAME" ] || die "--no-setup and --protect contradict each other"
  TMP=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-install.XXXXXX")
  # The agent user writes one file into $TMP/setup (0700, its own).
  chmod 0711 "$TMP"
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
