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
#   --storage PROVIDER     preselect rowsafe (Rowsafe Storage: no bucket needed,
#                          works without a terminal), r2, b2, s3, wasabi, spaces
#                          or s3-compatible
#   --no-prompt            never ask questions, even on a terminal
#   --no-setup             don't look for PostgreSQL or turn on backups
#   --protect NAME         without questions: turn on backups for this server's
#                          PostgreSQL as NAME (never restarts it)
#   --protect-port PORT    with --protect: the cluster on PORT (when there are several)
#   --allow-restart        allow Rowsafe to restart or stop PostgreSQL when you
#                          ask (Restart and Rewind in the dashboard, `rowsafe
#                          restart`); only when someone confirms
#   --no-allow-restart     turn that off again
#   --files PATH           back up the folder PATH (uploads) with the database
#   --allow-files          allow Rowsafe to put restored files back (as the
#                          folder's owner); --no-allow-files turns it off
#   --no-files             don't ask about folders with uploads
#   --allow-create-cluster allow Rowsafe to create a new PostgreSQL cluster (on a
#                          free port in 5440-5499) when you fork a database to
#                          this server; only when someone confirms
#   --no-allow-create-cluster  turn that off again
#   --allow-firewall       allow Rowsafe to limit who can reach PostgreSQL's port
#                          with the firewall when you ask (Security in the
#                          dashboard); never touches SSH or other ports
#   --no-allow-firewall    turn that off again (and remove Rowsafe's rule)
#   --allow-updates        allow Rowsafe to install PostgreSQL updates and upgrade
#                          PostgreSQL when you click Update or Upgrade (needs
#                          --allow-restart); --no-allow-updates turns it off
#   --allow-security-updates  allow Rowsafe to install the server's security
#                          updates when you click Install; --no-allow-security-updates
#   --allow-reboot         allow Rowsafe to reboot the server when you click
#                          Reboot; --no-allow-reboot
#   --check-storage        test the configured backup storage; change nothing
#   --add-storage          set up a second backup copy in another bucket (guided)
#   --remove-second-copy   stop sending backups to the second copy
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
# PgBouncer on request (--allow-pooler): the same helper, started by its own
# path unit; the pgbouncer package goes in and out through its own unit.
POOLER_SERVICE_FILE=/etc/systemd/system/rowsafe-pooler.service
POOLER_PATH_FILE=/etc/systemd/system/rowsafe-pooler.path
POOLER_APT_FILE=/etc/systemd/system/rowsafe-pooler-apt@.service
POOLER_DROPIN_DIR=/etc/systemd/system/pgbouncer.service.d
POOLER_ALLOW_FILE=$CONFIG_DIR/pooler-allowed
POOLER_DIR=$STATE_DIR/pooler
# The firewall on request (--allow-firewall): a root helper of its own.
FIREWALL_HELPER=$LIB_DIR/rowsafe-firewall
FIREWALL_SERVICE_FILE=/etc/systemd/system/rowsafe-firewall.service
FIREWALL_PATH_FILE=/etc/systemd/system/rowsafe-firewall.path
FIREWALL_RESTORE_FILE=/etc/systemd/system/rowsafe-firewall-restore.service
FIREWALL_ALLOW_FILE=$CONFIG_DIR/firewall-allowed
FIREWALL_DIR=$STATE_DIR/firewall
# Updates on request (--allow-updates, --allow-security-updates,
# --allow-reboot): the same helper, run by its own service and path unit.
UPDATE_SERVICE_FILE=/etc/systemd/system/rowsafe-pg-update.service
UPDATE_PATH_FILE=/etc/systemd/system/rowsafe-pg-update.path
UPDATES_ALLOW_FILE=$CONFIG_DIR/updates-allowed
AGENT_USER=postgres
# >>> mysql: a server with MySQL or MariaDB and no PostgreSQL runs the agent
# as the mysql user (detect_host_engine), like postgres on a PostgreSQL one.
HOST_ENGINE=postgresql
AGENT_HOME=/var/lib/postgresql
PERCONA_KEY_FPR=4D1BB29D63D98E422B2113B19334A25F8507EFA5
MYSQL_CONF_LINK=/etc/mysql/conf.d/zz-rowsafe.cnf
# <<< mysql
DEFAULT_RELEASES_URL=https://releases.rowsafe.sh/agent
MAX_ARTIFACT_SIZE=536870912 # 512 MiB, the same limit the agent enforces

REQUIRED_REPO_VARS="ROWSAFE_REPO_S3_ENDPOINT ROWSAFE_REPO_S3_BUCKET ROWSAFE_REPO_S3_KEY ROWSAFE_REPO_S3_KEY_SECRET ROWSAFE_REPO_CIPHER_PASS"
# Agent settings copied from the installer's environment into agent.env.
AGENT_VARS="ROWSAFE_URL ROWSAFE_ENROLL_TOKEN $REQUIRED_REPO_VARS ROWSAFE_STORAGE
  ROWSAFE_REPO_S3_REGION ROWSAFE_REPO_S3_URI_STYLE ROWSAFE_REPO_PATH_PREFIX
  ROWSAFE_REPO_S3_PORT ROWSAFE_REPO_S3_CA_FILE ROWSAFE_REPO_S3_VERIFY_TLS
  ROWSAFE_AUTO_UPDATE ROWSAFE_PG_USER ROWSAFE_PG_BIN_DIR ROWSAFE_PGBACKREST_BIN
  ROWSAFE_DRILL_DIR ROWSAFE_DRILL_PORT ROWSAFE_POLL_INTERVAL ROWSAFE_HEARTBEAT_INTERVAL
  ROWSAFE_MYSQL_BIN_DIR ROWSAFE_MYSQL_SCRATCH_MEMORY"
# ---- second copy (--add-storage): the second storage's settings
REPO2_VARS="ROWSAFE_REPO2_S3_ENDPOINT ROWSAFE_REPO2_S3_BUCKET ROWSAFE_REPO2_S3_KEY ROWSAFE_REPO2_S3_KEY_SECRET ROWSAFE_REPO2_CIPHER_PASS"
REPO2_OPT_VARS="ROWSAFE_REPO2_S3_REGION ROWSAFE_REPO2_S3_URI_STYLE ROWSAFE_REPO2_PATH_PREFIX ROWSAFE_REPO2_S3_PORT ROWSAFE_REPO2_S3_CA_FILE ROWSAFE_REPO2_S3_VERIFY_TLS"
AGENT_VARS="$AGENT_VARS $REPO2_VARS $REPO2_OPT_VARS"
SECOND_COPY=''     # --add-storage (add) / --remove-second-copy (remove)
# ---- end second copy

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
ALLOW_POOLER=''    # --allow-pooler (yes) / --no-allow-pooler (no); '' = ask once, on a terminal
ALLOW_POOLER_PUBLIC=0 # --allow-pooler-public: PgBouncer may also listen on every address
ALLOW_FIREWALL=''  # --allow-firewall (yes) / --no-allow-firewall (no); '' = ask once, on a terminal
ALLOW_UPDATES=''   # --allow-updates / --no-allow-updates (PostgreSQL updates and upgrades)
ALLOW_SECURITY=''  # --allow-security-updates / --no-allow-security-updates
ALLOW_REBOOT=''    # --allow-reboot / --no-allow-reboot
SETUP_STOP=0       # the plan limit was reached: don't offer more databases
MONGODB_REPLSET='' # --mongodb-replica-set (yes) / --no-mongodb-replica-set (no); '' = ask on a terminal

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
  --storage PROVIDER     skip the "where" question: rowsafe (Rowsafe Storage, no bucket
                         needed; also without a terminal), r2, b2, s3, wasabi, spaces,
                         s3-compatible
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
  --files PATH           back up the folder PATH (uploads, media) with the database,
                         so a restore brings back both; repeat for several
  --allow-files          allow Rowsafe to put restored files back into protected
                         folders (as their owner) and to read folders you add in
                         the dashboard, only when someone asks; --no-allow-files
                         turns it off
  --no-files             don't ask about folders with uploads
  --allow-create-cluster allow Rowsafe to create a new PostgreSQL cluster (a free port
                         in 5440-5499) when you fork a database to this server,
                         only when someone confirms (Debian and Ubuntu)
  --no-allow-create-cluster  turn that off
  --allow-pooler         allow Rowsafe to install and manage PgBouncer (connection
                         pooling) when you turn pooling on in the dashboard
  --no-allow-pooler      turn that off
  --allow-pooler-public  with --allow-pooler: also let PgBouncer listen on public
                         addresses when someone chooses that (put a firewall in front)
  --allow-firewall       allow Rowsafe to limit who can reach PostgreSQL's port with
                         the firewall (nftables) when you ask, under Security in the
                         dashboard; never touches SSH or other ports
  --no-allow-firewall    turn that off (and remove Rowsafe's rule and helper)
  --allow-updates        allow Rowsafe to install PostgreSQL updates and upgrade PostgreSQL
                         when you click Update or Upgrade and confirm (needs --allow-restart)
  --no-allow-updates     turn that off
  --allow-security-updates  allow Rowsafe to install the server's security updates when
                         you click Install and confirm (--no-allow-security-updates: off)
  --allow-reboot         allow Rowsafe to reboot the server when you click Reboot and
                         confirm (--no-allow-reboot: off)
  --mongodb-replica-set  MongoDB: turn a standalone server into a single-member replica
                         set without asking (one MongoDB restart); restoring to any
                         second needs it
  --no-mongodb-replica-set  never do that
  --check-storage        test the backup storage in /etc/rowsafe/agent.env; change nothing
  --add-storage          add a second backup copy in another bucket, ideally at another
                         provider (guided, like the first storage), or change it
  --remove-second-copy   stop sending backups to the second copy (its bucket is kept)
  --uninstall            stop and remove the agent; keep configuration and state
  --uninstall --purge    also delete /etc/rowsafe, /var/lib/rowsafe and /var/log/rowsafe
  --download-only DIR    download and verify the agent into DIR; install nothing
  -h, --help             show this help

Environment:
  ROWSAFE_VERSION        install exactly this version (default: the channel's latest)
  ROWSAFE_CHANNEL        channel to install from (default: stable)
  ROWSAFE_RELEASES_URL   release location (default: https://releases.rowsafe.sh/agent)
  ROWSAFE_ALLOW_DOWNGRADE=1  allow ROWSAFE_VERSION older than the installed version
  ROWSAFE_MONGODB_ADMIN_USER, ROWSAFE_MONGODB_ADMIN_PASSWORD  without a terminal: a MongoDB
                         administrator to create Rowsafe's own MongoDB user (used once,
                         never saved)
  ROWSAFE_URL, ROWSAFE_ENROLL_TOKEN, ROWSAFE_REPO_*  written to /etc/rowsafe/agent.env
                         (ROWSAFE_ENROLL_TOKEN may instead be the argument rse_...)
                         (ROWSAFE_URL defaults to https://api.rowsafe.sh)

Backup storage (guided setup):
  Run from a terminal, the installer first asks where backups go: Rowsafe
  Storage (nothing to set up; the free plan includes 10 GB) or your own
  bucket. Either way they are encrypted on this server with a passphrase only
  you have, so Rowsafe can't read them. For your own bucket: paste its URL (or pick Cloudflare R2, Backblaze B2,
  Amazon S3, Wasabi, DigitalOcean Spaces or any S3-compatible store), then its
  access key. It then tests the bucket by writing, reading and deleting a
  small file, and explains what to fix if that fails. Finally it creates (or
  takes) the passphrase that encrypts your backups: it is shown once, so save
  it in your password manager. Without it, backups can't be restored.

  Secrets are typed hidden and never printed. Nothing is saved until you have
  answered everything; settings go to /etc/rowsafe/agent.env (postgres, 0600).
  Run it again with --setup-storage to change the storage later.

  A second copy (--add-storage) keeps everything in a second bucket too, with
  its own key and its own passphrase, so losing one bucket, account or
  provider never loses your backups. It is set up the same way. PostgreSQL
  never waits for it: if the second storage is down, backups go on in the
  first one and Rowsafe alerts you. Without a terminal, set
  ROWSAFE_REPO2_S3_ENDPOINT, _BUCKET, _KEY, _KEY_SECRET and
  ROWSAFE_REPO2_CIPHER_PASS (and _S3_REGION) instead.

  Without a terminal (cloud-init, CI, configuration management) or with
  --no-prompt, pass --storage rowsafe (the passphrase comes from
  ROWSAFE_REPO_CIPHER_PASS, or is generated and kept in agent.env), or set
  ROWSAFE_REPO_S3_ENDPOINT, _BUCKET, _KEY, _KEY_SECRET and
  ROWSAFE_REPO_CIPHER_PASS in the environment, and check with --check-storage.

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

# >>> mysql
# detect_host_engine: without a postgres user but with MySQL or MariaDB,
# Rowsafe protects MySQL/MariaDB and the agent runs as the mysql user, which
# can read the data directory (backups) and start private servers on it
# (restore tests, Rewind copies).
detect_host_engine() {
  id -u postgres >/dev/null 2>&1 && return 0
  id -u mysql >/dev/null 2>&1 || return 0
  for _b in /usr/sbin/mariadbd /usr/sbin/mysqld; do
    [ -x "$_b" ] || continue
    if "$_b" --version 2>/dev/null | grep -qi mariadb; then HOST_ENGINE=mariadb; else HOST_ENGINE=mysql; fi
    MYSQLD_BIN=$_b
    AGENT_USER=mysql
    AGENT_HOME=$STATE_DIR
    return 0
  done
}
# <<< mysql

# >>> mongodb: without PostgreSQL and MySQL/MariaDB but with MongoDB, the
# agent runs as its own system user, rowsafe.
detect_mongodb_host() {
  [ "$HOST_ENGINE" = postgresql ] || return 0
  id -u postgres >/dev/null 2>&1 && return 0
  mongodb_present || return 0
  HOST_ENGINE=mongodb
  use_rowsafe_user
  AGENT_HOME=$STATE_DIR
}

# mongodb_setup: on a MongoDB server without PostgreSQL, a unit drop-in runs
# the agent as rowsafe (like mysql_setup does for MySQL).
mongodb_setup() {
  _dropin=/etc/systemd/system/$SERVICE.d
  if [ "$HOST_ENGINE" != mongodb ]; then
    [ ! -f "$_dropin/10-mongodb.conf" ] || { rm -f "$_dropin/10-mongodb.conf"; UNIT_CHANGED=1; CHANGED=1; }
    return 0
  fi
  install -d -m 0755 "$_dropin"
  if printf '# Written by the Rowsafe installer: this server runs MongoDB.\n[Unit]\nAfter=mongod.service\n[Service]\nUser=rowsafe\nGroup=rowsafe\n' |
    write_file "$_dropin/10-mongodb.conf" 0644 root:root; then
    UNIT_CHANGED=1 CHANGED=1
  fi
}
# <<< mongodb
# >>> mysql

engine_label() {
  case ${1:-$HOST_ENGINE} in mysql) echo MySQL ;; mariadb) echo MariaDB ;; mongodb) echo MongoDB ;; *) echo PostgreSQL ;; esac
}

# ensure_mysql_tools installs the physical backup tool: mariadb-backup from
# the same apt source as the server, or Percona XtraBackup (8.0 or 8.4, the
# server's) from Percona's repository, whose signing key is checked against
# its pinned fingerprint. pgBackRest is installed too: the installer's
# storage test uses it.
ensure_mysql_tools() {
  _ver=$("$MYSQLD_BIN" --version 2>/dev/null | sed -n 's/.*Ver \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
  if [ "$HOST_ENGINE" = mariadb ]; then
    if ! have mariadb-backup && ! have mariabackup; then
      step "Installing mariadb-backup (MariaDB's backup tool)"
      apt_install mariadb-backup
    fi
    TOOLS_SUMMARY="mariadb-backup $(mariadb-backup --version 2>&1 | sed -n 's/.*MariaDB server \([0-9.]*\).*/\1/p')"
  else
    case $_ver in
      8.0.*) _pkg=percona-xtrabackup-80 _repo=pxb-80 ;;
      8.4.*) _pkg=percona-xtrabackup-84 _repo=pxb-84-lts ;;
      *) die "MySQL ${_ver:-(unknown version)}: Rowsafe supports MySQL 8.0 and 8.4" ;;
    esac
    if ! dpkg -s "$_pkg" >/dev/null 2>&1; then
      step "Installing Percona XtraBackup ($_pkg) from Percona's repository"
      have gpg || apt_install gnupg
      _codename=$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")
      fetch https://repo.percona.com/yum/PERCONA-PACKAGING-KEY "$TMP/percona.asc"
      _fpr=$(gpg --show-keys --with-colons "$TMP/percona.asc" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')
      [ "$_fpr" = "$PERCONA_KEY_FPR" ] || die "Percona's signing key has an unexpected fingerprint ($_fpr); not installing XtraBackup"
      gpg --dearmor <"$TMP/percona.asc" >"$TMP/percona.gpg"
      install -m 0644 -o root -g root "$TMP/percona.gpg" /usr/share/keyrings/rowsafe-percona.gpg
      echo "deb [signed-by=/usr/share/keyrings/rowsafe-percona.gpg] https://repo.percona.com/$_repo/apt $_codename main" |
        write_file /etc/apt/sources.list.d/rowsafe-percona-xtrabackup.list 0644 root:root || true
      APT_UPDATED=0
      apt_install "$_pkg"
    fi
    TOOLS_SUMMARY=$(xtrabackup --version 2>&1 | sed -n 's/^xtrabackup version \([^ ]*\).*/XtraBackup \1/p')
    have mysqlbinlog || warn "mysqlbinlog is missing (MySQL's server or client package has it): restores need it"
  fi
  ok "${TOOLS_SUMMARY:-backup tool installed}"
  have pgbackrest || apt_install pgbackrest
}

# mysql_setup gives the agent (the mysql user) what it needs: a unit
# drop-in that runs it as mysql, an option file Rowsafe writes the binary
# log settings to (included from /etc/mysql/conf.d, empty until you turn on
# backups), and, on Ubuntu's AppArmor profile for mysqld, access to Rowsafe's
# folders (restore tests and copies run mysqld on data under $STATE_DIR).
mysql_setup() {
  _dropin=/etc/systemd/system/$SERVICE.d
  if [ "$AGENT_USER" = postgres ]; then
    [ ! -f "$_dropin/10-mysql.conf" ] || { rm -f "$_dropin/10-mysql.conf"; UNIT_CHANGED=1; CHANGED=1; }
    return 0
  fi
  install -d -m 0755 "$_dropin"
  if printf '# Written by the Rowsafe installer: this server runs MySQL or MariaDB.\n[Unit]\nAfter=mysql.service mariadb.service\n[Service]\nUser=mysql\nGroup=mysql\n' |
    write_file "$_dropin/10-mysql.conf" 0644 root:root; then
    UNIT_CHANGED=1 CHANGED=1
  fi
  install -d -m 0750 -o mysql -g mysql "$CONFIG_DIR/mysql"
  if [ ! -f "$CONFIG_DIR/mysql/server.cnf" ]; then
    as_agent sh -c 'umask 027; printf "# Written by Rowsafe (https://rowsafe.sh): binary log settings for backups.\n[mysqld]\n" >"$1"' \
      rowsafe "$CONFIG_DIR/mysql/server.cnf"
  fi
  if [ -d /etc/mysql/conf.d ] && [ ! -e "$MYSQL_CONF_LINK" ]; then
    ln -s "$CONFIG_DIR/mysql/server.cnf" "$MYSQL_CONF_LINK"
    ok "$MYSQL_CONF_LINK -> $CONFIG_DIR/mysql/server.cnf (settings Rowsafe needs, added only when you turn on backups)"
  fi
  if [ -f /etc/apparmor.d/usr.sbin.mysqld ] && ! grep -qs 'Rowsafe' /etc/apparmor.d/local/usr.sbin.mysqld; then
    install -d -m 0755 /etc/apparmor.d/local
    {
      echo "# Rowsafe: restore tests and Rewind copies run mysqld on data under $STATE_DIR;"
      echo "# the server reads Rowsafe's binary log settings from $CONFIG_DIR/mysql."
      echo "$STATE_DIR/ r,"
      echo "$STATE_DIR/** rwk,"
      echo "$CONFIG_DIR/mysql/ r,"
      echo "$CONFIG_DIR/mysql/* r,"
    } >>/etc/apparmor.d/local/usr.sbin.mysqld
    if have apparmor_parser && [ -d /sys/kernel/security/apparmor ]; then
      apparmor_parser -r /etc/apparmor.d/usr.sbin.mysqld 2>/dev/null || warn "could not reload mysqld's AppArmor profile"
    fi
  fi
}

# mysql_account creates Rowsafe's own MySQL/MariaDB account (as root, via
# the server's socket; or with the administrator password on a terminal).
mysql_account() {
  [ "$C_ENGINE" = mysql ] || [ "$C_ENGINE" = mariadb ] || return 0
  [ ! -f "$STATE_DIR/engines/$C_ENGINE/account-$C_PORT.cnf" ] || return 0
  _sock=$C_SOCK
  [ "$_sock" != - ] || _sock=''
  if "$INSTALL_DIR/rowsafe-agent" setup mysql-account --engine "$C_ENGINE" --port "$C_PORT" ${_sock:+--socket "$_sock"} \
    --owner "$AGENT_USER" --state-dir "$STATE_DIR" >"$TMP/account.log" 2>&1 </dev/null; then
    note "$(cat "$TMP/account.log")"
    return 0
  fi
  if [ "$TTY" != 1 ]; then
    sed 's/^/    /' "$TMP/account.log" >&2
    warn "could not log in to $(engine_label "$C_ENGINE") as root through its socket; run the installer on a terminal to give the root password once"
    return 1
  fi
  note "Rowsafe needs its own $(engine_label "$C_ENGINE") account; root can't log in without a password here."
  ask_secret _pw "$(engine_label "$C_ENGINE") root password (used once to create the account, not kept)"
  ( umask 077; printf '%s' "$_pw" >"$TMP/adminpw" )
  _pw=''
  _rc=0
  "$INSTALL_DIR/rowsafe-agent" setup mysql-account --engine "$C_ENGINE" --port "$C_PORT" ${_sock:+--socket "$_sock"} \
    --owner "$AGENT_USER" --state-dir "$STATE_DIR" --admin-password-file "$TMP/adminpw" >"$TMP/account.log" 2>&1 </dev/null || _rc=$?
  rm -f "$TMP/adminpw"
  if [ "$_rc" = 0 ]; then note "$(cat "$TMP/account.log")"; return 0; fi
  sed 's/^/    /' "$TMP/account.log" >&2
  return 1
}
# <<< mysql

# check_postgres finds the postgres OS user and the installed server majors.
check_postgres() {
  [ "$HOST_ENGINE" = postgresql ] || return 0 # mysql
  id -u "$AGENT_USER" >/dev/null 2>&1 ||
    die "no '$AGENT_USER' user on this host. Rowsafe adopts an existing PostgreSQL or MongoDB; install one first."
  PG_MAJORS=''
  for bin in /usr/lib/postgresql/*/bin/postgres; do
    [ -x "$bin" ] || continue
    major=${bin#/usr/lib/postgresql/}
    PG_MAJORS="$PG_MAJORS ${major%%/*}"
  done
  PG_MAJORS=${PG_MAJORS# }
  if [ -z "$PG_MAJORS" ] && [ -z "${ROWSAFE_PG_BIN_DIR:-}" ] && ! mongodb_present; then
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
  as_agent mkdir -p -m 0700 "$POOLER_DIR"
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

# install_helper_script writes the root helper (restarts, updates, and
# PgBouncer with --allow-pooler); HELPER_CHANGED=1 when it changed.
install_helper_script() {
  install -d -m 0755 -o root -g root "${RESTART_HELPER%/*}"
  HELPER_CHANGED=0
  if write_file "$RESTART_HELPER" 0755 root:root <<'ROWSAFE_RESTART_HELPER_EOF'; then
#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# rowsafe-pg-restart: restarts or stops PostgreSQL when a person asked
# Rowsafe to (Restart in the dashboard, `rowsafe restart`; Rewind the whole
# database, which stops PostgreSQL, swaps its data directory and starts it),
# and installs PostgreSQL updates, upgrades PostgreSQL, installs security
# updates or reboots the server when a person clicked that and root allowed
# it (update mode, below).
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
# Files (only when root allowed it: --allow-files, which writes
# /etc/rowsafe/files-allowed, the folders Rowsafe may read and restore
# into, with everything under them) come in their own request file,
# /var/lib/rowsafe/restart/files-request, answered in
# /run/rowsafe-pg-restart/files-result, so they never overwrite a restart
# request or its answer. "ID files-read PATH" gives the agent user read
# access to PATH (POSIX ACLs, never ownership or modes); "ID files-put MODE
# STAGE PATH" puts files the agent restored into
# /var/lib/rowsafe/files-staging/STAGE/tree back into PATH as PATH's owner.
# MODE: missing (never overwrite), replace, or mirror (also delete the files
# listed in STAGE/delete). The agent is not trusted with that: root copies
# the staged files (read as the agent user) and puts them back only if they
# are plain files and folders (no links, devices or FIFOs, no set-user-ID or
# set-group-ID bits, no path leaving PATH), never through a symbolic link in
# PATH, and deletes only files whose folder is really inside PATH.
#
# Update mode (ROWSAFE_HELPER_MODE=update, set by rowsafe-pg-update.service,
# which rowsafe-pg-update.path starts): the request is
# /var/lib/rowsafe/restart/update-request, read the same way, and the answer
# /run/rowsafe-pg-restart/update-result. Only these requests exist:
#
#   ID pg-minor-update PORT                  newest minor release of PORT's major
#   ID pg-install-major PORT MAJOR           install MAJOR (and PORT's extensions for it)
#   ID pg-upgrade PORT MAJOR METHOD          pg_upgradecluster to MAJOR (copy, clone or link)
#   ID pg-upgrade-undo PORT start|nostart    back to the version kept by that upgrade
#   ID pg-upgrade-cleanup PORT               remove the version kept aside by an upgrade or undo
#   ID security-updates                      install pending security updates
#   ID reboot                                reboot the server
#
# Each needs its word in /etc/rowsafe/updates-allowed (root's, written by
# the installer): "postgresql" for the pg-* requests, which also only act on
# a port in /etc/rowsafe/restart-allowed whose unit is Debian's
# postgresql@MAJOR-NAME.service; "security" and "reboot" for the others.
# Package names are fixed here: a minor update installs only PORT's major
# (never another one), a new major only postgresql-MAJOR, its client and the
# counterparts of the extension packages PORT's major has installed. What an
# upgrade keeps for undo is recorded in root's state directory, with the data
# directories it checked. A cluster is only removed while its data directory
# is still the recorded one (a real directory of the agent user, of that
# major, not a system directory), and pg_dropcluster then runs as the agent
# user, never as root (see drop_cluster).
#
# Forks: "ID create-cluster PORT MAJOR NAME" (restart mode) asks for a new,
# empty PostgreSQL cluster (a person forked a database to a new port). Only
# when root allowed it (/etc/rowsafe/create-cluster-allowed, "ports
# MIN-MAX", written by the installer with --allow-create-cluster): the
# helper checks the request and starts
# rowsafe-pg-create-cluster@MAJOR-PORT-NAME.service, a separate sandboxed
# unit that runs pg_createcluster and can't write anything of Rowsafe's.
# Once it succeeded and the new cluster's configuration names the requested
# port, this helper lists the cluster in /etc/rowsafe/created-clusters
# ("PORT UNIT") and then stops and starts it like the clusters in
# restart-allowed. A failure's reason comes from that unit's journal, never
# from a file another process could write.
#
# The agent reads the next lines to know what this helper can do.
# actions: restart stop start create-cluster files-read files-put
# update-actions: pg-minor-update pg-install-major pg-upgrade pg-upgrade-undo pg-upgrade-cleanup security-updates reboot
#
# The same helper manages PgBouncer when root allowed that (--allow-pooler):
# see "PgBouncer" below.

set -u
PATH=${ROWSAFE_HELPER_PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}
dir=${ROWSAFE_RESTART_DIR:-/var/lib/rowsafe/restart}
out_dir=${RUNTIME_DIRECTORY:-/run/rowsafe-pg-restart}
allow=${ROWSAFE_RESTART_ALLOW:-/etc/rowsafe/restart-allowed}
updates_allow=${ROWSAFE_UPDATES_ALLOW:-/etc/rowsafe/updates-allowed}
create_allow=${ROWSAFE_CREATE_CLUSTER_ALLOW:-/etc/rowsafe/create-cluster-allowed}
created=${ROWSAFE_CREATED_CLUSTERS:-/etc/rowsafe/created-clusters}
pg_conf_root=${ROWSAFE_PG_CONF_ROOT:-/etc/postgresql}
journalctl=${ROWSAFE_JOURNALCTL:-journalctl}
state=${STATE_DIRECTORY:-/var/lib/rowsafe-pg-restart}
files_allow=${ROWSAFE_FILES_ALLOW:-/etc/rowsafe/files-allowed}
files_staging=${ROWSAFE_FILES_STAGING:-/var/lib/rowsafe/files-staging}
agent_user=${ROWSAFE_AGENT_USER:-postgres}
systemctl=${ROWSAFE_SYSTEMCTL:-systemctl}
mode=${ROWSAFE_HELPER_MODE:-restart}
min_interval=60

log() { echo "rowsafe-pg-restart: $*" >&2; }

# as_agent runs a command with the agent user's privileges.
as_agent() { setpriv --reuid="$agent_user" --regid="$agent_user" --init-groups -- "$@"; }

id='' action='' unit='' ok=0 err='' extra='' result_name=result fpath='' fmode='' fstage=''

# add KEY VALUE adds a line to the answer (one line, at most 1000 bytes).
add() {
  extra="$extra$1=$(printf '%s' "$2" | tr '\n\r' '  ' | cut -c1-1000)
"
}

# answer writes the result atomically into root's own directory.
answer() {
  tmp=$(mktemp "$out_dir/.result.XXXXXX") || {
    log "cannot write the result in $out_dir"
    exit 0
  }
  printf 'id=%s\naction=%s\nok=%s\nunit=%s\nerror=%s\n%sfinished_at=%s\n' "$id" "$action" "$ok" "$unit" "$err" "$extra" "$(date +%s)" >"$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$out_dir/$result_name"
}

refuse() {
  err=$1
  log "refused: $1"
  answer
  exit 0
}

# have_request FILE: something (anything) is at FILE.
have_request() { as_agent test -e "$1" -o -L "$1" 2>/dev/null; }
# ---------------------------------------------------------------- PgBouncer
# In rowsafe-pooler.service (ROWSAFE_HELPER_MODE=pooler) the helper manages
# PgBouncer instead, when someone turned pooling on, changed it or turned it
# off in Rowsafe, and only where root allowed it (--allow-pooler):
# /etc/rowsafe/pooler-allowed lists the PostgreSQL ports PgBouncer may pool
# (found by root with pg_lsclusters, never by the agent), and "public" when
# root also allowed PgBouncer to listen on every address
# (--allow-pooler-public). The request (/var/lib/rowsafe/pooler/request,
# read as the agent user like a restart request) is one line
# "ID ACTION KEY=VALUE...", ACTION being pooler-install, pooler-configure,
# pooler-reload or pooler-off. Every value is checked against a strict
# pattern, and the helper writes PgBouncer's configuration itself from its
# own template: PgBouncer only ever sends connections to an allowed port on
# 127.0.0.1. That unit has no network and a read-only system; installing or
# removing the pgbouncer package (the only package the helper touches) runs
# in rowsafe-pooler-apt@install.service or @purge.service
# (ROWSAFE_HELPER_MODE=pooler-apt), which takes no input from the agent, at
# most once every 10 minutes. The answer goes to /run/rowsafe-pooler/result:
# id, action, ok, error, version, installed, removed, running and
# finished_at.
#
# pooler-actions: install configure reload off

pooler_allow=${ROWSAFE_POOLER_ALLOW:-/etc/rowsafe/pooler-allowed}
pgb_dir=${ROWSAFE_PGBOUNCER_DIR:-/etc/pgbouncer}
apt_get=${ROWSAFE_APT_GET:-apt-get}
pgb_unit=pgbouncer.service
pgb_marker=';; Managed by Rowsafe'
apt_unit=rowsafe-pooler-apt
# Seconds between two package installs or removals (the unit's environment,
# root's to change; tests shorten it).
apt_cooldown=${ROWSAFE_POOLER_APT_COOLDOWN:-600}
case $apt_cooldown in '' | *[!0-9]*) apt_cooldown=600 ;; esac
p_args='' p_version='' p_installed=0 p_removed=0 p_running=0

pooler_answer() {
  tmp=$(mktemp "$out_dir/.result.XXXXXX") || {
    log "cannot write the result in $out_dir"
    exit 0
  }
  printf 'id=%s\naction=%s\nok=%s\nerror=%s\nversion=%s\ninstalled=%s\nremoved=%s\nrunning=%s\nfinished_at=%s\n' \
    "$id" "$action" "$ok" "$err" "$p_version" "$p_installed" "$p_removed" "$p_running" "$(date +%s)" >"$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$out_dir/result"
}

pooler_refuse() {
  err=$1
  log "refused: $1"
  pooler_answer
  exit 0
}

# pooler_kv KEY prints the value of KEY=... in the request ('' if absent).
pooler_kv() { printf '%s\n' "$p_args" | tr ' ' '\n' | sed -n "s/^$1=//p" | head -n 1; }

# pooler_num KEY MIN MAX [DEFAULT] checks that KEY's value is a number in
# range and leaves it in $n (never in a subshell: a refusal must exit).
pooler_num() {
  n=$(pooler_kv "$1")
  if [ -z "$n" ] && [ $# -ge 4 ]; then n=$4; fi
  case $n in '' | *[!0-9]* | 0?*) pooler_refuse "invalid $1" ;; esac
  [ "${#n}" -le 6 ] && [ "$n" -ge "$2" ] && [ "$n" -le "$3" ] || pooler_refuse "$1 must be between $2 and $3"
}

pooler_ip() {
  printf '%s\n' "$1" | grep -Eq '^(([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)$'
}

pooler_installed() { command -v pgbouncer >/dev/null 2>&1; }

pooler_version() { p_version=$(pgbouncer --version 2>/dev/null | awk 'NR == 1 { print $2 }'); }

# pooler_ours: the configuration is Rowsafe's (or PgBouncer's untouched
# default, which nothing uses). Anything else belongs to someone else and is
# never replaced.
pooler_ours() {
  _ini=$pgb_dir/pgbouncer.ini
  [ -e "$_ini" ] || return 0
  [ -f "$_ini" ] && [ ! -L "$_ini" ] || return 1
  [ "$(head -n 1 "$_ini")" = "$pgb_marker" ] && return 0
  _want=$(dpkg-query -W -f='${Conffiles}\n' pgbouncer 2>/dev/null | awk -v f="$_ini" '$1 == f { print $2 }')
  [ -n "$_want" ] && [ "$(md5sum <"$_ini" | awk '{ print $1 }')" = "$_want" ]
}

# pooler_secure_dir: root owns the directory before root writes in it (the
# package gives the files to postgres, the agent's user).
pooler_secure_dir() {
  [ ! -L "$pgb_dir" ] || pooler_refuse "$pgb_dir is a symbolic link"
  install -d -m 0755 -o root -g root "$pgb_dir" || pooler_refuse "cannot create $pgb_dir"
  chown root:root "$pgb_dir" && chmod 0755 "$pgb_dir" || pooler_refuse "cannot secure $pgb_dir"
}

# pooler_put SRC FILE: SRC (in root's state directory) becomes FILE
# (root, the agent user's group, 0640), atomically.
pooler_put() {
  _tmp=$(mktemp "$pgb_dir/.rowsafe.XXXXXX") || pooler_refuse "cannot write in $pgb_dir"
  cat "$1" >"$_tmp" && chown "root:$agent_user" "$_tmp" && chmod 0640 "$_tmp" && mv -f "$_tmp" "$2" || {
    rm -f "$_tmp" "$1"
    pooler_refuse "cannot write $2"
  }
  rm -f "$1"
}

pooler_active() { "$systemctl" is-active --quiet "$pgb_unit" 2>/dev/null; }

# pooler_stop stops PgBouncer and disables it at boot (two calls: a failed
# disable must not leave it running).
pooler_stop() {
  _out=$(timeout 60 "$systemctl" stop "$pgb_unit" 2>&1 </dev/null) ||
    pooler_refuse "stopping PgBouncer failed: $(printf '%s' "$_out" | tr '\n' ' ' | cut -c1-300)"
  _out=$(timeout 60 "$systemctl" disable --quiet "$pgb_unit" 2>&1 </dev/null) ||
    log "could not disable $pgb_unit: $(printf '%s' "$_out" | tr '\n' ' ' | cut -c1-300)"
}

# pooler_apt ACTION: install or purge the pgbouncer package in its own unit
# (network and a writable system), at most once every 10 minutes.
pooler_apt() {
  _now=$(date +%s)
  _last=$(cat "$state/last-apt" 2>/dev/null || echo 0)
  case $_last in '' | *[!0-9]*) _last=0 ;; esac
  if [ $((_now - _last)) -lt "$apt_cooldown" ]; then
    pooler_refuse "PgBouncer was installed or removed less than 10 minutes ago; try again in $(((apt_cooldown - _now + _last + 59) / 60)) minutes"
  fi
  echo "$_now" >"$state/last-apt"
  log "$1 pgbouncer (request $id)"
  _out=$(timeout 1000 "$systemctl" start "$apt_unit@$1.service" 2>&1 </dev/null) ||
    pooler_refuse "$1 of the pgbouncer package failed: $(tail -n 3 "$state/apt.log" 2>/dev/null | tr '\n' ' ' | cut -c1-300)$(printf '%s' "$_out" | tr '\n' ' ' | cut -c1-100)"
}

# pooler_apt_main runs in rowsafe-pooler-apt@ACTION.service: root started it,
# with nothing from the agent but the unit's instance name.
pooler_apt_main() {
  state=${STATE_DIRECTORY:-/var/lib/rowsafe-pooler}
  export DEBIAN_FRONTEND=noninteractive
  case ${ROWSAFE_APT_ACTION:-} in
    install)
      if ! timeout 600 "$apt_get" install -y -q --no-install-recommends pgbouncer </dev/null >"$state/apt.log" 2>&1; then
        timeout 300 "$apt_get" update -q </dev/null >>"$state/apt.log" 2>&1 || true
        timeout 600 "$apt_get" install -y -q --no-install-recommends pgbouncer </dev/null >>"$state/apt.log" 2>&1 || exit 1
      fi
      ;;
    purge) timeout 600 "$apt_get" purge -y -q pgbouncer </dev/null >"$state/apt.log" 2>&1 || exit 1 ;;
    *)
      log "unknown package action"
      exit 1
      ;;
  esac
  exit 0
}

pooler_install() {
  if ! pooler_installed; then
    pooler_apt install
    pooler_installed || pooler_refuse "the pgbouncer package was installed but pgbouncer is not on the PATH"
    : >"$state/installed-by-rowsafe"
    p_installed=1
    # The package starts PgBouncer with its default configuration, which
    # serves nothing; Rowsafe's starts once configured.
    if [ ! -e "$state/was-enabled" ]; then echo 0 >"$state/was-enabled"; fi
    pooler_stop
  fi
  pooler_ours || pooler_refuse "PgBouncer on this server has its own configuration ($pgb_dir/pgbouncer.ini); Rowsafe doesn't replace it"
  pooler_version
  ok=1
}

# pooler_allowed_port PORT: root listed PORT in the allow list.
pooler_allowed_port() { awk -v p="$1" '$1 == p { f = 1 } END { exit !f }' "$pooler_allow"; }

pooler_configure() {
  pooler_installed || pooler_refuse "PgBouncer is not installed"
  pooler_ours || pooler_refuse "PgBouncer on this server has its own configuration ($pgb_dir/pgbouncer.ini); Rowsafe doesn't replace it"
  pooler_num dbport 1 65535 && _dbport=$n
  pooler_allowed_port "$_dbport" ||
    pooler_refuse "port $_dbport is not in $pooler_allow: pooling it from Rowsafe is not allowed"
  pooler_num port 1024 65535 6432 && _port=$n
  pooler_num pool_size 1 1000 && _pool=$n
  pooler_num reserve_pool 0 1000 0 && _reserve=$n
  pooler_num max_db_conn 0 10000 0 && _maxdb=$n
  pooler_num max_client_conn 10 100000 && _maxcl=$n
  pooler_num prepared 0 5000 0 && _prepared=$n
  pooler_num restart 0 1 0 && _restart=$n
  pooler_num target_port 1 65535 "$_dbport" && _tport=$n
  # PgBouncer only reaches PostgreSQL on this server, on a port root allowed.
  pooler_allowed_port "$_tport" ||
    pooler_refuse "port $_tport is not in $pooler_allow: PgBouncer can't send connections there"
  _mode=$(pooler_kv mode)
  case $_mode in transaction | session) ;; *) pooler_refuse "mode must be transaction or session" ;; esac
  _thost=$(pooler_kv target_host)
  case ${_thost:-127.0.0.1} in
    127.0.0.1) _thost=127.0.0.1 ;;
    *) pooler_refuse "PgBouncer only sends connections to PostgreSQL on this server (127.0.0.1)" ;;
  esac
  _listen=$(pooler_kv listen)
  [ -n "$_listen" ] || _listen=127.0.0.1
  if [ "$_listen" = '*' ]; then
    grep -qx 'public' "$pooler_allow" ||
      pooler_refuse "listening on every address isn't allowed on this server (the installer's --allow-pooler-public)"
  else
    _n=0
    for _a in $(printf '%s' "$_listen" | tr ',' ' '); do
      _n=$((_n + 1))
      pooler_ip "$_a" && [ "$_n" -le 16 ] || pooler_refuse "invalid listen address"
    done
  fi
  _authdb=$(pooler_kv auth_dbname)
  [ -z "$_authdb" ] || printf '%s\n' "$_authdb" | grep -Eq '^[a-z_][a-z0-9_]{0,62}$' || pooler_refuse "invalid auth_dbname"
  _password=$(pooler_kv password)
  [ -z "$_password" ] || printf '%s\n' "$_password" | grep -Eq '^[0-9a-f]{32,128}$' || pooler_refuse "invalid password"
  # Databases with an entry of their own (a RELOAD moves them to a new
  # target; older PgBouncers keep pools made from "*" on the old one).
  _dbs=$(pooler_kv dbs)
  for _d in $(printf '%s' "$_dbs" | tr ',' ' '); do
    printf '%s\n' "$_d" | grep -Eq '^[A-Za-z0-9_-]{1,63}$' && [ "$_d" != pgbouncer ] || pooler_refuse "invalid database name in dbs"
  done

  pooler_secure_dir
  # Keep PgBouncer's own files, to put back when pooling is turned off.
  for _f in pgbouncer.ini userlist.txt; do
    if [ -f "$pgb_dir/$_f" ] && [ ! -e "$state/$_f.orig" ] && [ "$(head -n 1 "$pgb_dir/$_f")" != "$pgb_marker" ]; then
      cp -p "$pgb_dir/$_f" "$state/$_f.orig" || pooler_refuse "cannot keep a copy of $pgb_dir/$_f"
    fi
  done
  if [ ! -e "$state/was-enabled" ]; then
    if "$systemctl" is-enabled --quiet "$pgb_unit" 2>/dev/null; then echo 1 >"$state/was-enabled"; else echo 0 >"$state/was-enabled"; fi
  fi
  if [ -n "$_password" ]; then
    printf '%s\n"rowsafe_pgbouncer" "%s"\n' "$pgb_marker" "$_password" >"$state/userlist.new"
    pooler_put "$state/userlist.new" "$pgb_dir/userlist.txt"
  elif [ "$(head -n 1 "$pgb_dir/userlist.txt" 2>/dev/null)" != "$pgb_marker" ]; then
    pooler_refuse "the password of PgBouncer's lookup role is missing"
  fi
  {
    echo "$pgb_marker"
    echo ";; https://rowsafe.sh/docs/guides/connection-pooling"
    echo ";; The Rowsafe root helper writes this file when someone turns pooling on"
    echo ";; or changes it in Rowsafe: changes made here are replaced. Turning"
    echo ";; pooling off in Rowsafe puts PgBouncer's own configuration back."
    echo "[databases]"
    for _d in $(printf '%s' "$_dbs" | tr ',' ' '); do
      echo "$_d = host=$_thost port=$_tport auth_user=rowsafe_pgbouncer"
    done
    echo "* = host=$_thost port=$_tport auth_user=rowsafe_pgbouncer"
    echo ""
    echo "[pgbouncer]"
    echo "logfile = /var/log/postgresql/pgbouncer.log"
    echo "pidfile = /var/run/postgresql/pgbouncer.pid"
    echo "listen_addr = $_listen"
    echo "listen_port = $_port"
    echo "unix_socket_dir = /var/run/postgresql"
    echo "auth_type = scram-sha-256"
    echo "auth_file = $pgb_dir/userlist.txt"
    echo "auth_user = rowsafe_pgbouncer"
    echo "auth_query = SELECT uname, phash FROM rowsafe_pgbouncer.user_lookup(\$1)"
    echo "admin_users = rowsafe_pgbouncer"
    if [ -n "$_authdb" ]; then echo "auth_dbname = $_authdb"; fi
    echo "pool_mode = $_mode"
    echo "default_pool_size = $_pool"
    echo "reserve_pool_size = $_reserve"
    echo "reserve_pool_timeout = 3"
    echo "max_db_connections = $_maxdb"
    echo "max_client_conn = $_maxcl"
    if [ "$_prepared" -gt 0 ]; then echo "max_prepared_statements = $_prepared"; fi
    echo "server_reset_query = DISCARD ALL"
    echo "ignore_startup_parameters = extra_float_digits"
    echo "server_lifetime = 3600"
    echo "server_idle_timeout = 600"
  } >"$state/pgbouncer.new"
  pooler_put "$state/pgbouncer.new" "$pgb_dir/pgbouncer.ini"

  # Enough file descriptors for max_client_conn (the unit's default is 1024).
  _dropin=${ROWSAFE_SYSTEMD_DIR:-/etc/systemd/system}/$pgb_unit.d
  if [ ! -f "$_dropin/rowsafe.conf" ]; then
    install -d -m 0755 -o root -g root "$_dropin" &&
      printf '%s\n[Service]\nLimitNOFILE=65536\n' "# Written by Rowsafe; removed when pooling is turned off." >"$_dropin/rowsafe.conf" &&
      "$systemctl" daemon-reload || log "could not raise PgBouncer's file limit"
    _restart=1
  fi
  "$systemctl" enable --quiet "$pgb_unit" >/dev/null 2>&1 || log "could not enable $pgb_unit"
  if [ "$_restart" = 1 ] || ! pooler_active; then
    log "restarting $pgb_unit (request $id)"
    _out=$(timeout 60 "$systemctl" restart "$pgb_unit" 2>&1 </dev/null) ||
      pooler_refuse "PgBouncer did not start: $(printf '%s' "$_out" | tr '\n' ' ' | cut -c1-300); see journalctl -u $pgb_unit"
  fi
  pooler_active && p_running=1
  pooler_version
  ok=1
}

pooler_reload() {
  pooler_installed || pooler_refuse "PgBouncer is not installed"
  [ "$(head -n 1 "$pgb_dir/pgbouncer.ini" 2>/dev/null)" = "$pgb_marker" ] || pooler_refuse "PgBouncer is not managed by Rowsafe here"
  _out=$(timeout 60 "$systemctl" reload "$pgb_unit" 2>&1 </dev/null) ||
    pooler_refuse "reloading PgBouncer failed: $(printf '%s' "$_out" | tr '\n' ' ' | cut -c1-300)"
  pooler_active && p_running=1
  pooler_version
  ok=1
}

pooler_off() {
  pooler_num remove_package 0 1 1 && _remove=$n
  if ! pooler_installed || [ "$(head -n 1 "$pgb_dir/pgbouncer.ini" 2>/dev/null)" != "$pgb_marker" ]; then
    ok=1 # nothing of Rowsafe's to undo
    return 0
  fi
  log "turning PgBouncer off (request $id)"
  pooler_stop
  pooler_secure_dir
  if [ "$_remove" = 1 ] && [ -e "$state/installed-by-rowsafe" ]; then
    pooler_apt purge
    p_removed=1
    rm -f "$pgb_dir/pgbouncer.ini" "$pgb_dir/userlist.txt"
    rmdir "$pgb_dir" 2>/dev/null || true
  else
    for _f in pgbouncer.ini userlist.txt; do
      if [ -f "$state/$_f.orig" ]; then
        cp -p "$state/$_f.orig" "$pgb_dir/$_f" || pooler_refuse "cannot put $pgb_dir/$_f back"
      else
        rm -f "$pgb_dir/$_f"
      fi
    done
    if [ "$(cat "$state/was-enabled" 2>/dev/null)" = 1 ]; then
      "$systemctl" enable --now --quiet "$pgb_unit" >/dev/null 2>&1 || log "could not start $pgb_unit again"
    fi
  fi
  _dropin=${ROWSAFE_SYSTEMD_DIR:-/etc/systemd/system}/$pgb_unit.d
  if [ -f "$_dropin/rowsafe.conf" ]; then
    rm -f "$_dropin/rowsafe.conf"
    rmdir "$_dropin" 2>/dev/null || true
    "$systemctl" daemon-reload || true
  fi
  rm -f "$state/installed-by-rowsafe" "$state/was-enabled" "$state/pgbouncer.ini.orig" "$state/userlist.txt.orig"
  pooler_active && p_running=1
  ok=1
}

pooler_main() {
  out_dir=${RUNTIME_DIRECTORY:-/run/rowsafe-pooler}
  state=${STATE_DIRECTORY:-/var/lib/rowsafe-pooler}
  mkdir -p "$state" && chmod 0700 "$state"
  request=$dir/request
  as_agent test -e "$request" -o -L "$request" 2>/dev/null || exit 0
  # shellcheck disable=SC2016 # $1 expands in the inner shell
  line=$(as_agent sh -c '
    if [ -f "$1" ] && [ ! -L "$1" ]; then timeout 5 head -c 2000 -- "$1"; fi
    rm -f -- "$1"' rowsafe-pg-restart "$request" 2>/dev/null | head -n 1)
  printf '%s\n' "$line" | grep -Eq '^[A-Za-z0-9_-]{1,64} pooler-[a-z]{1,20}( [a-z_]{1,20}=[A-Za-z0-9.:,*_-]{0,300}){0,20}$' ||
    pooler_refuse "malformed request"
  id=${line%% *}
  rest=${line#* }
  action=${rest%% *}
  p_args=${rest#"$action"}
  [ -f "$pooler_allow" ] && [ ! -L "$pooler_allow" ] || pooler_refuse "managing PgBouncer from Rowsafe is not allowed on this server"
  [ "$(stat -c '%u' "$pooler_allow")" = 0 ] || pooler_refuse "$pooler_allow is not owned by root"
  case $(stat -c '%A' "$pooler_allow") in
    ?????w???? | ????????w?) pooler_refuse "$pooler_allow is writable by others than root" ;;
  esac
  grep -q '^[0-9]' "$pooler_allow" || pooler_refuse "managing PgBouncer from Rowsafe is not allowed on this server"
  case $action in
    pooler-install) pooler_install ;;
    pooler-configure) pooler_configure ;;
    pooler-reload) pooler_reload ;;
    pooler-off) pooler_off ;;
    *) pooler_refuse "unknown action $action" ;;
  esac
  log "$action: done (request $id)"
  pooler_answer
}

case ${ROWSAFE_HELPER_MODE:-} in
  pooler)
    pooler_main
    exit 0
    ;;
  pooler-apt) pooler_apt_main ;;
esac
# ------------------------------------------------------------ end PgBouncer

# read_request FILE [MAX] prints the request's first line (at most MAX
# bytes, 200 by default, read for at most 5 seconds, as the agent user, only
# from a regular file) and removes it, whatever it was, so the path unit
# doesn't fire again.
read_request() {
  # shellcheck disable=SC2016 # $1 and $2 expand in the inner shell
  as_agent sh -c '
    if [ -f "$1" ] && [ ! -L "$1" ]; then timeout 5 head -c "$2" -- "$1"; fi
    rm -f -- "$1"' rowsafe-pg-restart "$1" "${2:-200}" 2>/dev/null | head -n 1
}

# check_root_file FILE MISSING: FILE must be a regular file root owns and
# only root can write; MISSING is the refusal when it isn't there.
check_root_file() {
  [ -f "$1" ] && [ ! -L "$1" ] || refuse "$2"
  [ "$(stat -c '%u' "$1")" = 0 ] || refuse "$1 is not owned by root"
  case $(stat -c '%A' "$1") in
    ?????w???? | ????????w?) refuse "$1 is writable by others than root" ;;
  esac
}

# allowed_unit PORT prints the unit the restart allow list names for PORT.
allowed_unit() {
  # Only Debian's cluster units (postgresql@MAJOR-NAME.service), whatever the
  # file says; ports compare as strings.
  awk -v p="$1" '$1 "" == p "" && $2 ~ /^postgresql@[0-9]+-[A-Za-z0-9_.-]+\.service$/ { print $2; exit }' "$allow"
}

# created_unit PORT prints the unit of a cluster created for a fork on PORT
# (Debian's cluster units only, like allowed_unit).
created_unit() {
  [ -f "$created" ] || [ -L "$created" ] || return 0
  check_root_file "$created" "$created is missing"
  awk -v p="$1" '$1 "" == p "" && $2 ~ /^postgresql@[0-9]+-[A-Za-z0-9_.-]+\.service$/ { print $2; exit }' "$created"
}

# create_cluster PORT MAJOR NAME: a new cluster for a fork, through its own
# sandboxed unit, when root allowed it and PORT is in the allowed range.
create_cluster() {
  c_port=$1 c_major=$2 c_name=$3
  check_root_file "$create_allow" "creating PostgreSQL clusters from Rowsafe is not allowed on this server"
  range=$(awk '$1 == "ports" && $2 ~ /^[0-9]+-[0-9]+$/ { print $2; exit }' "$create_allow")
  [ -n "$range" ] || refuse "creating PostgreSQL clusters from Rowsafe is not allowed on this server"
  [ "$c_port" -ge "${range%-*}" ] && [ "$c_port" -le "${range#*-}" ] ||
    refuse "port $c_port is not in the ports Rowsafe may create clusters on ($range)"
  check_root_file "$created" "$created is missing: run the installer again with --allow-create-cluster"
  for list in "$allow" "$created"; do
    if [ -f "$list" ] && awk -v p="$c_port" '$1 "" == p "" { f = 1 } END { exit !f }' "$list"; then
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

# ---------------------------------------------------------------- files (restart mode, --allow-files)

# files_check_path refuses unless $fpath is a plain, existing folder (no
# symbolic link on the way) under a folder root allowed, and not a system
# or database folder.
files_check_path() {
  check_root_file "$files_allow" "reading or restoring folders from Rowsafe is not allowed on this server"
  case $fpath in
    */../* | */.. | */./* | */. | *//* | */) refuse "$fpath is not a plain path" ;;
  esac
  case $fpath/ in
    /etc/* | /root/* | /boot/* | /proc/* | /sys/* | /dev/* | /run/* | /usr/* | /bin/* | /sbin/* | /lib/* | /lib64/* | \
      /var/lib/postgresql/* | /var/lib/rowsafe/* | /var/lib/rowsafe-pg-restart/* | /opt/rowsafe/* | \
      /var/lib/docker/containers/* | */.ssh/* | */.gnupg/*)
      refuse "$fpath is a system or database folder: Rowsafe never touches it" ;;
  esac
  real=$(realpath -e -- "$fpath" 2>/dev/null) || refuse "$fpath doesn't exist"
  [ "$real" = "$fpath" ] || refuse "$fpath goes through a symbolic link (to $real)"
  [ -d "$fpath" ] || refuse "$fpath is not a folder"
  allowed=0
  while IFS= read -r root; do
    case $root in '' | '#'* | / | [!/]*) continue ;; esac
    case $fpath in "$root" | "$root"/*) allowed=1 ;; esac
  done <"$files_allow"
  [ "$allowed" = 1 ] || refuse "$fpath is not under a folder listed in $files_allow"
}

# files_read gives the agent user read access to the folder and what is in
# it, now and later (default ACLs), and passage through its parents.
files_read() {
  files_check_path
  out=$(setfacl -R -P -m "u:$agent_user:rX" -- "$fpath" 2>&1) || refuse "setfacl failed on $fpath: $(printf '%s' "$out" | head -n 3 | tr '\n' ' ')"
  find -P "$fpath" -type d -exec setfacl -m "d:u:$agent_user:rX" -- {} + 2>/dev/null ||
    refuse "setting the default ACL on the folders in $fpath failed"
  p=${fpath%/*}
  while [ -n "$p" ]; do
    as_agent test -x "$p" 2>/dev/null || setfacl -m "u:$agent_user:x" -- "$p" || refuse "can't let Rowsafe through $p"
    p=${p%/*}
  done
  ok=1
  log "files-read $fpath (request $id): done"
}

# files_put puts the staged files into the folder as its owner. The agent
# (whose files these are) is not trusted: root takes its own copy (read as
# the agent user), checks it, and the owner extracts that copy. Root never
# opens anything in the agent's directories or in PATH itself.
files_put() {
  files_check_path
  src=$files_staging/$fstage
  as_agent test -d "$src/tree" -a ! -L "$src/tree" -a ! -L "$src" 2>/dev/null || refuse "nothing is staged for restore $fstage"
  owner=$(stat -c '%u' "$fpath")
  group=$(stat -c '%g' "$fpath")
  [ "$owner" != 0 ] || refuse "$fpath belongs to root: Rowsafe won't write there as root"
  as_owner() { setpriv --reuid="$owner" --regid="$group" --clear-groups -- "$@"; }
  mkdir -p "$state" && chmod 0700 "$state"
  work=$(mktemp -d "$state/put.XXXXXX") || refuse "no room for a private copy of the staged files"
  trap 'rm -rf "$work"' EXIT
  as_agent tar -C "$src/tree" -cf - . >"$work/files.tar" 2>/dev/null || refuse "reading the staged files failed"
  if ! LC_ALL=C tar -tvf "$work/files.tar" >"$work/list" 2>/dev/null ||
    ! LC_ALL=C tar -tf "$work/files.tar" >"$work/names" 2>/dev/null; then
    refuse "the staged files are unreadable"
  fi
  bad=$(awk '{
    t = substr($1, 1, 1)
    if (t == "l") { print "a symbolic link"; exit }
    if (t == "h") { print "a hard link"; exit }
    if (t != "-" && t != "d") { print "a device, FIFO or socket"; exit }
    if (substr($1, 4, 1) ~ /[sS]/ || substr($1, 7, 1) ~ /[sS]/) { print "a set-user-ID or set-group-ID file"; exit }
  }' "$work/list")
  [ -z "$bad" ] || refuse "the staged files include $bad: Rowsafe only puts back plain files and folders"
  if grep -Eq '^/|(^|/)\.\.(/|$)' "$work/names"; then refuse "a staged path leaves the folder"; fi
  # Never write through a symbolic link in the folder: every folder the
  # files go into must be a real one (or not exist yet).
  # shellcheck disable=SC2016 # $1 expands in the inner shell
  link=$(grep '/$' "$work/names" | as_owner sh -c '
    cd -- "$1" || exit 1
    while IFS= read -r d; do
      d=${d%/}
      case $d in "" | .) continue ;; esac
      if [ -L "$d" ]; then printf "%s\n" "$d"; exit 0; fi
    done' rowsafe-files-put "$fpath")
  [ -z "$link" ] || refuse "$fpath/${link#./} is a symbolic link: Rowsafe won't write through it"
  if [ "$fmode" = mirror ] && as_agent test -f "$src/delete" -a ! -L "$src/delete"; then
    # Only files whose folder resolves to PATH or inside it, without a
    # symbolic link on the way, are removed.
    # shellcheck disable=SC2016 # $1 expands in the inner shell
    as_agent cat -- "$src/delete" | as_owner sh -c '
      cd -- "$1" || exit 1
      while IFS= read -r f; do
        case $f in "" | /* | ../* | */../* | */.. | .. | ./* | */./* | .) continue ;; esac
        d=$(dirname -- "$f")
        r=$(realpath -e -- "$d" 2>/dev/null) || continue
        if [ "$d" = . ]; then [ "$r" = "$1" ] || continue; else [ "$r" = "$1/$d" ] || continue; fi
        if [ -L "$f" ] || { [ -e "$f" ] && [ ! -d "$f" ]; }; then rm -f -- "$f"; fi
      done' rowsafe-files-put "$fpath" || refuse "removing the files added since from $fpath failed"
  fi
  # Existing folders keep their owner and mode; missing never replaces a
  # file; modes are the owner's umask applied to the snapshot's.
  keep=--no-overwrite-dir
  [ "$fmode" != missing ] || keep=--skip-old-files
  # shellcheck disable=SC2016 # $1 and $2 expand in the inner shell
  out=$(as_owner sh -c 'umask 022; exec tar -C "$1" -xf - --no-same-owner --no-same-permissions "$2"' \
    rowsafe-files-put "$fpath" "$keep" <"$work/files.tar" 2>&1) ||
    refuse "putting the files into $fpath failed: $(printf '%s' "$out" | head -n 3 | tr '\n' ' ')"
  ok=1
  log "files-put $fmode $fstage into $fpath as uid $owner (request $id): done"
}

# files_main answers a files request (restart mode, when no restart request
# is waiting). It has its own request and result files, so a files request
# never overwrites a restart request or its answer.
files_main() {
  result_name=files-result
  have_request "$dir/files-request" || exit 0
  line=$(read_request "$dir/files-request" 600)
  if printf '%s\n' "$line" | grep -Eq '^[A-Za-z0-9_-]{1,64} files-read /[A-Za-z0-9._@+,=/-]{1,400}$'; then
    id=${line%% *}
    action=files-read
    fpath=${line#* files-read }
  elif printf '%s\n' "$line" | grep -Eq '^[A-Za-z0-9_-]{1,64} files-put (missing|replace|mirror) [A-Za-z0-9_-]{1,64} /[A-Za-z0-9._@+,=/-]{1,400}$'; then
    id=${line%% *}
    action=files-put
    rest=${line#* files-put }
    fmode=${rest%% *}
    rest=${rest#* }
    fstage=${rest%% *}
    fpath=${rest#* }
  else
    refuse "malformed request"
  fi
  case $action in
    files-read) files_read ;;
    files-put) files_put ;;
  esac
  answer
  exit 0
}

# ---------------------------------------------------------------- restart mode

restart_main() {
  # A restart request first, then a files request (each fires the path unit).
  have_request "$dir/request" || files_main
  line=$(read_request "$dir/request")
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
  unit=''
  if [ -f "$allow" ] || [ -L "$allow" ] || { [ ! -f "$created" ] && [ ! -L "$created" ]; }; then
    check_root_file "$allow" "restarting or stopping PostgreSQL from Rowsafe is not allowed on this server"
    unit=$(allowed_unit "$port")
  fi
  [ -n "$unit" ] || unit=$(created_unit "$port")
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
}

# ---------------------------------------------------------------- update mode

work_log=$state/update.log

# tail_log is the end of the current action's log, for errors.
tail_log() { tail -n 12 "$work_log" 2>/dev/null | tr '\n' ' ' | cut -c1-700; }

# update_allowed WORD REFUSAL: root allowed WORD in the updates allow list.
update_allowed() {
  check_root_file "$updates_allow" "$2"
  awk -v k="$1" '$1 == k { f = 1 } END { exit !f }' "$updates_allow" || refuse "$2"
}

lsclusters() { pg_lsclusters -h 2>/dev/null; }

# cluster_for_port PORT sets c_major, c_name, c_status, c_datadir and unit
# for the Debian cluster on PORT, which must be in the restart allow list
# as its postgresql@MAJOR-NAME.service.
cluster_for_port() {
  check_root_file "$allow" "Rowsafe may not restart PostgreSQL on this server, which updating it needs (run the installer again with --allow-restart)"
  unit=$(allowed_unit "$1")
  [ -n "$unit" ] || refuse "port $1 is not in $allow: Rowsafe may not restart it, which updating it needs"
  c_line=$(lsclusters | awk -v p="$1" '$3 == p { print; exit }')
  [ -n "$c_line" ] || refuse "no PostgreSQL cluster managed by postgresql-common (pg_lsclusters) uses port $1"
  # shellcheck disable=SC2086 # split the pg_lsclusters line into its fields
  set -- $c_line
  c_major=$1 c_name=$2 c_status=$4 c_owner=$5 c_datadir=$6
  printf '%s\n' "$c_major" | grep -Eq '^[1-9][0-9]$' || refuse "unsupported PostgreSQL version $c_major"
  printf '%s\n' "$c_name" | grep -Eq '^[A-Za-z0-9_.-]{1,63}$' || refuse "unexpected cluster name $c_name"
  [ "$c_owner" = "$agent_user" ] || refuse "the cluster on port $port belongs to $c_owner, not $agent_user"
  [ "$unit" = "postgresql@$c_major-$c_name.service" ] ||
    refuse "PostgreSQL on port $port runs as $unit, not as postgresql@$c_major-$c_name.service: Rowsafe updates only clusters managed by Debian's postgresql-common"
}

# cluster_field MAJOR NAME FIELD prints a pg_lsclusters field (3 port,
# 4 status, 6 data directory).
cluster_field() { lsclusters | awk -v m="$1" -v n="$2" -v f="$3" '$1 == m && $2 == n { print $f; exit }'; }

pkg_version() { dpkg-query -W -f='${Version}' "$1" 2>/dev/null; }

# installed_pkgs PATTERN prints the installed packages matching PATTERN.
installed_pkgs() {
  dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' "$1" 2>/dev/null | awk '$1 == "ii" { print $2 }' |
    grep -Ev -- '-(dbgsym|dbg|doc)$'
}

candidate() { apt-cache policy "$1" 2>/dev/null | awk '$1 == "Candidate:" { print $2; exit }'; }

# apt_run ARGS... runs apt-get non-interactively, keeping configuration
# files as they are and never restarting services by itself (needrestart).
apt_run() {
  timeout "${apt_timeout:-1800}" env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 \
    APT_LISTCHANGES_FRONTEND=none UCF_FORCE_CONFFOLD=1 \
    apt-get -q -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    "$@" >>"$work_log" 2>&1 </dev/null
}

apt_refresh() { apt_run update || log "apt-get update failed; using the package lists as they are"; }

# active_since UNIT: when UNIT last became active (monotonic microseconds).
active_since() { "$systemctl" show -p ActiveEnterTimestampMonotonic --value "$1" 2>/dev/null; }

# set_allowed_unit PORT UNIT points PORT's restart allow list entry at UNIT.
set_allowed_unit() {
  tmp=$(mktemp "$allow.XXXXXX") || return 1
  awk -v p="$1" -v u="$2" '$1 == p { print p, u; next } { print }' "$allow" >"$tmp" &&
    chmod 0644 "$tmp" && mv -f "$tmp" "$allow"
}

# A cluster's settings live in the agent user's /etc/postgresql/MAJOR/NAME:
# change them as that user, never as root.
set_port() { as_agent pg_conftool "$1" "$2" set port "$3" >>"$work_log" 2>&1; }
set_start() {
  # shellcheck disable=SC2016 # $1, $2 and $3 expand in the inner shell
  as_agent sh -c 'f=/etc/postgresql/$1/$2/start.conf; [ ! -L "$f" ] && printf "%s\n" "$3" >"$f"' sh "$1" "$2" "$3"
}

# Removing a cluster. postgresql-common reads where a cluster's data lives
# (data_directory, or a "pgdata" link) and its log file (a "log" link) from
# /etc/postgresql/MAJOR/NAME, which the agent user owns: as root,
# pg_dropcluster would remove whatever those point at. So Rowsafe checks the
# data directory against the one root recorded when it created or upgraded
# the cluster, and runs pg_dropcluster with the agent user's privileges:
# whatever the configuration says, it can then only remove what that user
# could remove anyway. Root only stops the unit and tells systemd and apt.

# check_conf_dir MAJOR NAME: the configuration directory is a real
# directory (no symbolic link on its path) and has no log link pointing
# outside /var/log/postgresql. Sets why and returns 1 otherwise.
check_conf_dir() {
  cd_=/etc/postgresql/$1/$2
  if [ ! -d "$cd_" ] || [ "$(realpath -e -- "$cd_" 2>/dev/null)" != "$cd_" ]; then
    why="the configuration directory $cd_ is missing or its path goes through a symbolic link"
    return 1
  fi
  if [ -L "$cd_/log" ]; then
    case $(readlink -- "$cd_/log") in
      /var/log/postgresql/*) ;;
      *)
        why="$cd_/log points outside /var/log/postgresql"
        return 1
        ;;
    esac
  fi
  return 0
}

# check_data_dir DIR MAJOR: DIR is a PostgreSQL MAJOR data directory the
# agent user owns, an absolute path with no symbolic link on it, and no
# system directory. Sets why and returns 1 otherwise.
check_data_dir() {
  case $1 in
    /*) ;;
    *)
      why="the data directory \"$1\" is not an absolute path"
      return 1
      ;;
  esac
  if [ "$(realpath -e -- "$1" 2>/dev/null)" != "$1" ]; then
    why="the data directory $1 is missing or its path goes through a symbolic link"
    return 1
  fi
  case $1 in
    / | /etc | /etc/* | /usr | /usr/* | /var | /var/lib | /var/log | /home | /root | /root/* | /boot | /boot/* | \
      /bin | /bin/* | /sbin | /sbin/* | /lib | /lib/* | /lib64 | /lib64/* | /proc | /proc/* | /sys | /sys/* | /dev | /dev/* | /run | /tmp | /opt | /srv | /mnt | /media)
      why="the data directory $1 is a system directory"
      return 1
      ;;
  esac
  if [ "$(stat -c %U -- "$1")" != "$agent_user" ]; then
    why="the data directory $1 isn't owned by $agent_user"
    return 1
  fi
  if [ "$(as_agent timeout 5 head -c 16 -- "$1/PG_VERSION" 2>/dev/null | tr -d '\n')" != "$2" ]; then
    why="$1 is not a PostgreSQL $2 data directory"
    return 1
  fi
  return 0
}

# drop_cluster MAJOR NAME WANT removes a cluster whose data directory must
# still be WANT (recorded by root). Sets why and returns 1 when it refuses
# or fails.
drop_cluster() {
  why=''
  check_conf_dir "$1" "$2" || return 1
  d_=$(cluster_field "$1" "$2" 6)
  if [ "$d_" != "$3" ]; then
    why="PostgreSQL $1/$2's data directory is now ${d_:-unknown}, not $3 as recorded"
    return 1
  fi
  check_data_dir "$d_" "$1" || return 1
  timeout 180 "$systemctl" stop "postgresql@$1-$2.service" >>"$work_log" 2>&1 </dev/null
  if ! as_agent pg_dropcluster "$1" "$2" >>"$work_log" 2>&1 </dev/null; then
    why="pg_dropcluster failed: $(tail_log)"
    return 1
  fi
  "$systemctl" daemon-reload >>"$work_log" 2>&1
  [ ! -x /usr/share/postgresql-common/pg_updateaptconfig ] || /usr/share/postgresql-common/pg_updateaptconfig >>"$work_log" 2>&1
  return 0
}

free_port() { lsclusters | awk 'BEGIN { p = 5433 } $3 >= p { p = $3 + 1 } END { print p }'; }

# An upgrade's record (root's state directory): key=value lines.
record_file() { printf '%s/upgrade-%s\n' "$state" "$1"; }
record_get() { awk -F= -v k="$2" '$1 == k { print substr($0, length(k) + 2); exit }' "$1"; }
# record_put FILE KEY=VALUE... sets keys (later values win).
record_put() {
  f=$1
  shift
  tmp=$(mktemp "$state/.upgrade.XXXXXX") || return 1
  { [ ! -f "$f" ] || cat "$f"; printf '%s\n' "$@"; } |
    awk -F= '{ v[$1] = $0; if (!($1 in seen)) { seen[$1] = 1; order[++n] = $1 } } END { for (i = 1; i <= n; i++) print v[order[i]] }' >"$tmp" &&
    mv -f "$tmp" "$f"
}

act_pg_minor_update() {
  update_allowed postgresql "installing PostgreSQL updates from Rowsafe is not allowed on this server (run the installer again with --allow-updates)"
  cluster_for_port "$port"
  m=$c_major
  before=$(pkg_version "postgresql-$m")
  [ -n "$before" ] || refuse "PostgreSQL $m is not installed from packages here (postgresql-$m)"
  pkgs="postgresql-$m postgresql-client-$m libpq5 $(installed_pkgs "postgresql-$m-*" | tr '\n' ' ')"
  : >"$work_log"
  t0=$(active_since "$unit")
  apt_refresh
  log "updating $pkgs (request $id)"
  # shellcheck disable=SC2086 # package names, built above
  apt_run install -y --only-upgrade $pkgs || refuse "installing the update failed: $(tail_log)"
  after=$(pkg_version "postgresql-$m")
  add from_package "$before"
  add package "$after"
  add packages "$pkgs"
  add other_clusters "$(lsclusters | awk -v m="$m" -v p="$port" '$1 == m && $3 != p { printf "%s/%s (port %s) ", $1, $2, $3 }')"
  restarted=0
  case $c_status in
    online*)
      if [ "$after" != "$before" ]; then
        if [ "$(active_since "$unit")" = "$t0" ]; then
          # The packages didn't restart it: start the new binaries now.
          out=$(timeout 180 "$systemctl" restart "$unit" 2>&1 </dev/null) ||
            refuse "the update is installed, but restarting $unit failed: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)"
        fi
        restarted=1
      fi
      ;;
  esac
  add restarted "$restarted"
  ok=1
  log "PostgreSQL $m: $before -> $after (restarted: $restarted)"
}

act_pg_install_major() {
  update_allowed postgresql "installing PostgreSQL from Rowsafe is not allowed on this server (run the installer again with --allow-updates)"
  cluster_for_port "$port"
  [ "$major" -gt "$c_major" ] || refuse "PostgreSQL $major is not newer than PostgreSQL $c_major on port $port"
  : >"$work_log"
  apt_refresh
  c=$(candidate "postgresql-$major")
  [ -n "$c" ] && [ "$c" != "(none)" ] || refuse "PostgreSQL $major is not available from this server's package sources"
  before=$(lsclusters | awk -v m="$major" '$1 == m { printf " %s ", $2 }')
  pkgs="postgresql-$major postgresql-client-$major"
  missing=''
  for p in $(installed_pkgs "postgresql-$c_major-*"); do
    n=postgresql-$major-${p#postgresql-"$c_major"-}
    c=$(candidate "$n")
    if [ -n "$c" ] && [ "$c" != "(none)" ]; then pkgs="$pkgs $n"; else missing="$missing $n"; fi
  done
  log "installing $pkgs (request $id)"
  # shellcheck disable=SC2086 # package names, built above
  apt_timeout=3600 apt_run install -y --no-install-recommends $pkgs || refuse "installing PostgreSQL $major failed: $(tail_log)"
  # postgresql-common creates (and starts) an empty "main" cluster for a
  # newly installed major; the upgrade needs that name free.
  dropped='' left=''
  for n in $(lsclusters | awk -v m="$major" '$1 == m { print $2 }'); do
    case $before in *" $n "*) continue ;; esac
    # Its data directory as the package just created it.
    if drop_cluster "$major" "$n" "$(cluster_field "$major" "$n" 6)"; then
      dropped="$dropped $major/$n"
    else
      left="$left $major/$n ($why)"
      log "left the new cluster $major/$n in place: $why"
    fi
  done
  add left "$left"
  add packages "$pkgs"
  add missing "$missing"
  add dropped "$dropped"
  ok=1
}

act_pg_upgrade() {
  update_allowed postgresql "upgrading PostgreSQL from Rowsafe is not allowed on this server (run the installer again with --allow-updates)"
  cluster_for_port "$port"
  [ "$major" -gt "$c_major" ] || refuse "PostgreSQL $major is not newer than PostgreSQL $c_major on port $port"
  rec=$(record_file "$port")
  [ ! -e "$rec" ] || refuse "the version kept by an earlier upgrade on port $port is still there: remove it first"
  [ -x "/usr/lib/postgresql/$major/bin/pg_upgrade" ] || refuse "PostgreSQL $major is not installed: rehearse the upgrade first (it installs it)"
  case $c_status in
    *recovery*) refuse "PostgreSQL on port $port is a replica: upgrade the primary" ;;
    online*) ;;
    *) refuse "PostgreSQL on port $port is not running" ;;
  esac
  [ -z "$(cluster_field "$major" "$c_name" 1)" ] || refuse "a PostgreSQL $major cluster named $c_name already exists"
  # Where the old version's data lives, checked and recorded now: it is
  # what a later cleanup may remove, and nothing else.
  check_conf_dir "$c_major" "$c_name" || refuse "Rowsafe won't upgrade this cluster: $why"
  check_data_dir "$c_datadir" "$c_major" || refuse "Rowsafe won't upgrade this cluster: $why"
  flag=''
  case $method in link) flag=--link ;; clone) flag=--clone ;; esac
  jobs=$(nproc 2>/dev/null || echo 1)
  [ "$jobs" -le 8 ] 2>/dev/null || jobs=8
  : >"$work_log"
  old_unit=$unit
  new_unit=postgresql@$major-$c_name.service
  log "upgrading $c_major/$c_name to $major ($method, request $id)"
  # shellcheck disable=SC2086 # $flag is empty or one option
  if ! timeout 12h pg_upgradecluster -v "$major" -m upgrade $flag -j "$jobs" --no-start "$c_major" "$c_name" >>"$work_log" 2>&1 </dev/null; then
    why=$(tail_log)
    # pg_upgradecluster removes the new cluster and starts the old one
    # again when pg_upgrade fails; make sure the old one runs.
    case $(cluster_field "$c_major" "$c_name" 4) in
      online*) ;;
      *) timeout 180 "$systemctl" start "$old_unit" >>"$work_log" 2>&1 </dev/null ;;
    esac
    case $(cluster_field "$c_major" "$c_name" 4) in
      online*)
        add rolled_back 1
        refuse "pg_upgrade failed, and PostgreSQL $c_major runs as before: $why"
        ;;
    esac
    refuse "pg_upgrade failed, and PostgreSQL $c_major could not be started again: $why"
  fi
  old_port=$(cluster_field "$c_major" "$c_name" 3)
  new_data=$(cluster_field "$major" "$c_name" 6)
  check_data_dir "$new_data" "$major" || new_data=''
  record_put "$rec" "id=$id" "port=$port" "from=$c_major" "to=$major" "name=$c_name" "method=$method" \
    "aside_port=$old_port" "status=upgraded" "created=$(date +%s)" "old_data=$c_datadir" "new_data=$new_data" ||
    refuse "could not record the upgrade"
  set_allowed_unit "$port" "$new_unit" || refuse "could not update $allow"
  unit=$new_unit
  "$systemctl" daemon-reload >>"$work_log" 2>&1
  if ! timeout 600 "$systemctl" start "$new_unit" >>"$work_log" 2>&1 </dev/null; then
    why=$(tail_log)
    if [ "$method" = link ]; then
      add kept "$c_major/$c_name"
      refuse "PostgreSQL $major did not start: $why. In Fast mode the old version can't simply be started again: Undo restores it from the backup taken just before"
    fi
    # Safe mode: the old data is untouched. Put it back and start it.
    "$systemctl" stop "$new_unit" >>"$work_log" 2>&1
    set_port "$major" "$c_name" "$old_port"
    set_start "$major" "$c_name" manual
    set_port "$c_major" "$c_name" "$port"
    set_start "$c_major" "$c_name" auto
    set_allowed_unit "$port" "$old_unit"
    unit=$old_unit
    "$systemctl" daemon-reload >>"$work_log" 2>&1
    if timeout 180 "$systemctl" start "$old_unit" >>"$work_log" 2>&1 </dev/null; then
      startwhy=$why
      if [ -n "$new_data" ] && drop_cluster "$major" "$c_name" "$new_data"; then
        rm -f "$rec"
      else
        # Kept, stopped: the record lets a person remove it later.
        record_put "$rec" "status=undone" "aside_port=$old_port"
        add kept "$major/$c_name"
      fi
      add rolled_back 1
      refuse "PostgreSQL $major did not start ($startwhy); Rowsafe put PostgreSQL $c_major back and started it"
    fi
    refuse "PostgreSQL $major did not start ($why), and starting PostgreSQL $c_major again failed too: $(tail_log)"
  fi
  add from "$c_major"
  add to "$major"
  add aside_port "$old_port"
  add old_data_dir "$c_datadir"
  add new_data_dir "$new_data"
  ok=1
  log "upgraded $c_major/$c_name to $major; $c_major kept on port $old_port, stopped"
}

# read_record PORT sets rec, r_from, r_to, r_name, r_status and r_aside
# from PORT's upgrade record, checking every value.
read_record() {
  rec=$(record_file "$1")
  [ -f "$rec" ] || refuse "there is no upgrade on port $1 that Rowsafe keeps a version for"
  r_from=$(record_get "$rec" from) r_to=$(record_get "$rec" to) r_name=$(record_get "$rec" name)
  r_status=$(record_get "$rec" status) r_aside=$(record_get "$rec" aside_port)
  printf '%s %s %s %s %s\n' "$r_from" "$r_to" "$r_aside" "$r_name" "$r_status" |
    grep -Eq '^[1-9][0-9] [1-9][0-9] [0-9]{1,5} [A-Za-z0-9_.-]{1,63} (upgraded|undone)$' ||
    refuse "the upgrade record for port $1 is damaged"
}

act_pg_upgrade_undo() {
  update_allowed postgresql "upgrading PostgreSQL from Rowsafe is not allowed on this server (run the installer again with --allow-updates)"
  check_root_file "$allow" "Rowsafe may not restart PostgreSQL on this server"
  read_record "$port"
  [ "$r_status" = upgraded ] || refuse "that upgrade was already undone"
  new_unit=postgresql@$r_to-$r_name.service
  old_unit=postgresql@$r_from-$r_name.service
  [ "$(allowed_unit "$port")" = "$new_unit" ] || refuse "port $port is not PostgreSQL $r_to's in $allow"
  [ "$(cluster_field "$r_to" "$r_name" 3)" = "$port" ] || refuse "PostgreSQL $r_to/$r_name is not on port $port"
  unit=$new_unit
  : >"$work_log"
  log "undoing the upgrade of $r_from/$r_name to $r_to (request $id)"
  timeout 180 "$systemctl" stop "$new_unit" >>"$work_log" 2>&1 </dev/null || refuse "stopping PostgreSQL $r_to failed: $(tail_log)"
  aside=$r_aside
  other=$(lsclusters | awk -v q="$aside" -v m="$r_from" -v n="$r_name" '$3 == q && !($1 == m && $2 == n) { print; exit }')
  [ -z "$other" ] || aside=$(free_port)
  { set_port "$r_to" "$r_name" "$aside" && set_start "$r_to" "$r_name" manual &&
    set_port "$r_from" "$r_name" "$port" && set_start "$r_from" "$r_name" auto &&
    set_allowed_unit "$port" "$old_unit"; } || refuse "switching the clusters' ports failed: $(tail_log)"
  unit=$old_unit
  "$systemctl" daemon-reload >>"$work_log" 2>&1
  record_put "$rec" "status=undone" "aside_port=$aside"
  add kept "$r_to/$r_name"
  add aside_port "$aside"
  add data_dir "$(cluster_field "$r_from" "$r_name" 6)"
  if [ "$start" = start ]; then
    timeout 300 "$systemctl" start "$old_unit" >>"$work_log" 2>&1 </dev/null ||
      refuse "PostgreSQL $r_from did not start: $(tail_log)"
  fi
  ok=1
}

act_pg_upgrade_cleanup() {
  update_allowed postgresql "upgrading PostgreSQL from Rowsafe is not allowed on this server (run the installer again with --allow-updates)"
  read_record "$port"
  if [ "$r_status" = upgraded ]; then kept=$r_from; else kept=$r_to; fi
  [ "$(cluster_field "$kept" "$r_name" 3)" != "$port" ] || refuse "PostgreSQL $kept/$r_name is the one on port $port"
  status=$(cluster_field "$kept" "$r_name" 4)
  case $status in
    '')
      rm -f "$rec"
      add freed 0
      ok=1
      return 0
      ;;
    down) ;;
    *) refuse "PostgreSQL $kept/$r_name is running ($status); Rowsafe won't remove it" ;;
  esac
  if [ "$r_status" = upgraded ]; then want=$(record_get "$rec" old_data); else want=$(record_get "$rec" new_data); fi
  [ -n "$want" ] || refuse "the upgrade record doesn't say where PostgreSQL $kept/$r_name's data lives, so Rowsafe won't remove it: remove it yourself with pg_dropcluster"
  data=$(cluster_field "$kept" "$r_name" 6)
  size=$(as_agent du -sb -- "$data" 2>/dev/null | cut -f1)
  : >"$work_log"
  log "removing $kept/$r_name, kept by an upgrade (request $id)"
  drop_cluster "$kept" "$r_name" "$want" || refuse "Rowsafe didn't remove PostgreSQL $kept/$r_name: $why"
  rm -f "$rec"
  add freed "${size:-0}"
  add dropped "$kept/$r_name"
  # Its programs too, when no cluster of that major is left and nothing
  # else would be removed with them.
  if [ -z "$(lsclusters | awk -v m="$kept" '$1 == m')" ]; then
    pkgs=$(printf '%s\n%s\n' "$(installed_pkgs "postgresql-$kept")" "$(installed_pkgs "postgresql-$kept-*")" | grep . | tr '\n' ' ')
    if [ -n "$pkgs" ]; then
      # shellcheck disable=SC2086 # package names from dpkg
      removes=$(apt-get -s remove $pkgs 2>/dev/null | awk '/^Remv / { print $2 }' | sort)
      # shellcheck disable=SC2086
      if [ "$removes" = "$(printf '%s\n' $pkgs | sort)" ] && apt_run remove -y $pkgs; then
        add packages_removed "$pkgs"
      else
        add packages_kept "$pkgs"
      fi
    fi
  fi
  ok=1
}

act_security_updates() {
  update_allowed security "installing security updates from Rowsafe is not allowed on this server (run the installer again with --allow-security-updates)"
  cooldown security-updates 300
  : >"$work_log"
  apt_refresh
  # Upgrades of installed packages from a security origin. PostgreSQL's
  # server packages are left for Update PostgreSQL, which saves a Mark,
  # restarts in a controlled way and checks archiving.
  list=$(apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null |
    awk '/^Inst [^ ]+ \[/ && /-security|Debian-Security/ { print $2 }' | sort -u)
  held=$(printf '%s\n' "$list" | grep -E '^postgresql-[0-9]+(-.+)?$' | tr '\n' ' ')
  pkgs=$(printf '%s\n' "$list" | grep -Ev '^postgresql-[0-9]+(-.+)?$' | grep . | tr '\n' ' ')
  n=0
  if [ -n "$pkgs" ]; then
    log "installing security updates: $pkgs (request $id)"
    # shellcheck disable=SC2086 # package names from apt
    apt_timeout=5400 apt_run install -y --only-upgrade $pkgs || refuse "installing the security updates failed: $(tail_log)"
    # shellcheck disable=SC2086
    n=$(printf '%s\n' $pkgs | wc -l | tr -d ' ')
  fi
  add installed "$n"
  add packages "$pkgs"
  add held_back "$held"
  if [ -e /run/reboot-required ]; then add reboot_required 1; else add reboot_required 0; fi
  ok=1
}

# cooldown ACTION SECONDS: at most one ACTION per SECONDS (root's own stamp).
cooldown() {
  stamp=$state/last-$1
  now=$(date +%s)
  last=$(cat "$stamp" 2>/dev/null || echo 0)
  case $last in '' | *[!0-9]*) last=0 ;; esac
  [ $((now - last)) -ge "$2" ] || refuse "$1 ran less than $(($2 / 60)) minutes ago; try again later"
  echo "$now" >"$stamp"
}

act_reboot() {
  update_allowed reboot "rebooting the server from Rowsafe is not allowed here (run the installer again with --allow-reboot)"
  cooldown reboot 600
  log "rebooting the server (request $id)"
  # The answer comes before the reboot: it says the reboot was asked for.
  ok=1
  add status rebooting
  add requested_at "$(date +%s)"
  answer
  sleep 3
  "$systemctl" --no-block reboot
  exit 0
}

update_main() {
  result_name=update-result
  have_request "$dir/update-request" || exit 0
  mkdir -p "$state"
  line=$(read_request "$dir/update-request")
  port='' major='' method='' start=''
  # Every request's exact shape; anything else is refused before it is split.
  rid='[A-Za-z0-9_-]{1,64}'
  if printf '%s\n' "$line" | grep -Eq "^$rid (pg-minor-update|pg-upgrade-cleanup) [0-9]{1,5}\$"; then
    # shellcheck disable=SC2086 # validated just above
    set -- $line
    id=$1 action=$2 port=$3
  elif printf '%s\n' "$line" | grep -Eq "^$rid pg-upgrade-undo [0-9]{1,5} (start|nostart)\$"; then
    # shellcheck disable=SC2086
    set -- $line
    id=$1 action=$2 port=$3 start=$4
  elif printf '%s\n' "$line" | grep -Eq "^$rid pg-install-major [0-9]{1,5} [1-9][0-9]\$"; then
    # shellcheck disable=SC2086
    set -- $line
    id=$1 action=$2 port=$3 major=$4
  elif printf '%s\n' "$line" | grep -Eq "^$rid pg-upgrade [0-9]{1,5} [1-9][0-9] (copy|clone|link)\$"; then
    # shellcheck disable=SC2086
    set -- $line
    id=$1 action=$2 port=$3 major=$4 method=$5
  elif printf '%s\n' "$line" | grep -Eq "^$rid (security-updates|reboot)\$"; then
    id=${line%% *} action=${line#* }
  else
    refuse "malformed request"
  fi
  case $action in
    pg-minor-update) act_pg_minor_update ;;
    pg-install-major) act_pg_install_major ;;
    pg-upgrade) act_pg_upgrade ;;
    pg-upgrade-undo) act_pg_upgrade_undo ;;
    pg-upgrade-cleanup) act_pg_upgrade_cleanup ;;
    security-updates) act_security_updates ;;
    reboot) act_reboot ;;
  esac
  answer
}

case $mode in
  update) update_main ;;
  *) restart_main ;;
esac
ROWSAFE_RESTART_HELPER_EOF
    HELPER_CHANGED=1
  fi
}

install_restart_helper() {
  install_helper_script
  _changed=$HELPER_CHANGED
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
# Files requests (--allow-files) have their own file, so they never
# overwrite a restart request.
PathExists=/var/lib/rowsafe/restart/files-request
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
  remove_update_units # they run the same helper
  files_allowed && return 0 # files use the helper too (files section)
  [ -e "$RESTART_PATH_FILE" ] || [ -e "$RESTART_SERVICE_FILE" ] || [ -e "$RESTART_HELPER" ] || return 0
  if systemd_running; then
    systemctl disable --now --quiet rowsafe-pg-restart.path 2>/dev/null || true
  fi
  rm -f "$RESTART_PATH_FILE" "$RESTART_SERVICE_FILE"
  [ -e "$POOLER_PATH_FILE" ] || rm -f "$RESTART_HELPER" # PgBouncer still uses it
  rmdir "${RESTART_HELPER%/*}" 2>/dev/null || true
  if systemd_running; then systemctl daemon-reload; fi
}

# restart_pairs prints "PORT UNIT" for the discovered clusters with a
# systemd unit (the ones a restart helper can restart).
restart_pairs() {
  [ -s "$TMP/clusters" ] || return 0
  awk -F '\t' '($14 == "" || $14 == "postgresql") && $1 ~ /^[1-9][0-9]*$/ && $12 ~ /^postgresql@[0-9]+-[A-Za-z0-9_.-]+\.service$/ { print $1, $12 }' "$TMP/clusters"
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
  rm -f "$UPDATES_ALLOW_FILE" # updates need the helper too
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
      # Asked only where restarts are allowed: the created cluster is
      # stopped and started by the same helper.
      [ "$TTY" = 1 ] && command -v pg_createcluster >/dev/null 2>&1 && grep -qs '^[0-9]' "$RESTART_ALLOW_FILE" || return 0
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

# ---------------------------------------------------------------- updates

# Rowsafe never installs anything on its own. With root's permission, per
# capability, a person can click Update PostgreSQL (minor updates and major
# upgrades), Install security updates or Reboot in the dashboard and
# confirm: the agent writes a request to $RESTART_DIR/update-request,
# rowsafe-pg-update.path starts the same root helper in update mode, and the
# helper does only what $UPDATES_ALLOW_FILE lists. It needs the restart
# helper (PostgreSQL updates restart the cluster).

install_update_units() {
  _changed=0
  if write_file "$UPDATE_SERVICE_FILE" 0644 root:root <<'ROWSAFE_UPDATE_SERVICE_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-pg-update.service: installs PostgreSQL updates, upgrades
# PostgreSQL, installs security updates or reboots the server when the
# Rowsafe agent asks because a person clicked that, and only what root
# allowed in /etc/rowsafe/updates-allowed (see
# /usr/local/lib/rowsafe/rowsafe-pg-restart, update mode). Started by
# rowsafe-pg-update.path; installed by https://rowsafe.sh/install only when
# root allowed one of them (--allow-updates, --allow-security-updates,
# --allow-reboot).

[Unit]
Description=Rowsafe: install PostgreSQL updates or upgrade PostgreSQL on request
Documentation=https://rowsafe.sh/docs/guides/updates

[Service]
Type=oneshot
ExecStart=/usr/local/lib/rowsafe/rowsafe-pg-restart
Environment=ROWSAFE_HELPER_MODE=update
# The agent user, whose privileges read and remove the request and change a
# cluster's own settings.
Environment=ROWSAFE_AGENT_USER=postgres
# A major upgrade of a large database in Safe mode copies all its data.
TimeoutStartSec=13h
# The answer: root's own directory, which the agent can read (shared with
# rowsafe-pg-restart.service).
RuntimeDirectory=rowsafe-pg-restart
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
# What an upgrade keeps for undo, and the last action's log, out of the
# agent's reach.
StateDirectory=rowsafe-pg-restart
StateDirectoryMode=0700
UMask=0022

# Unlike rowsafe-pg-restart.service this one can't be sandboxed much: apt,
# the packages' own scripts and pg_upgradecluster write under /usr, /etc and
# /var, download packages and start PostgreSQL. What it can do is limited by
# the script instead: only the requests it knows, each checked against
# root's allow lists, with package names it builds itself.
ProtectHome=read-only
PrivateTmp=no
LockPersonality=yes
RestrictRealtime=yes
ROWSAFE_UPDATE_SERVICE_EOF
    _changed=1
  fi
  if write_file "$UPDATE_PATH_FILE" 0644 root:root <<'ROWSAFE_UPDATE_PATH_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-pg-update.path: starts rowsafe-pg-update.service when the Rowsafe
# agent asks to update or upgrade PostgreSQL, install security updates or
# reboot (someone clicked that in the dashboard and confirmed). Installed by
# https://rowsafe.sh/install only when root allowed it; removed when every
# one of those is turned off (--no-allow-updates, --no-allow-security-updates,
# --no-allow-reboot).

[Unit]
Description=Rowsafe: watch for requests to update PostgreSQL or the server
Documentation=https://rowsafe.sh/docs/guides/updates

[Path]
PathExists=/var/lib/rowsafe/restart/update-request
Unit=rowsafe-pg-update.service

[Install]
WantedBy=multi-user.target
ROWSAFE_UPDATE_PATH_EOF
    _changed=1
  fi
  if systemd_running; then
    [ "$_changed" = 0 ] || systemctl daemon-reload
    systemctl enable --now --quiet rowsafe-pg-update.path
  else
    warn "systemd is not running here; the update helper was installed but cannot be enabled"
  fi
}

remove_update_units() {
  [ -e "$UPDATE_PATH_FILE" ] || [ -e "$UPDATE_SERVICE_FILE" ] || return 0
  if systemd_running; then
    systemctl disable --now --quiet rowsafe-pg-update.path 2>/dev/null || true
  fi
  rm -f "$UPDATE_PATH_FILE" "$UPDATE_SERVICE_FILE"
  if systemd_running; then systemctl daemon-reload; fi
}

# update_allowed WORD: is WORD in the updates allow list?
update_allowed() {
  [ -f "$UPDATES_ALLOW_FILE" ] && awk -v w="$1" '$1 == w { f = 1 } END { exit !f }' "$UPDATES_ALLOW_FILE"
}

# decide_update FLAG WORD QUESTION DEFAULT prints yes or no: the flag, else
# the earlier answer (a re-run keeps it), else the answer to QUESTION on a
# terminal, else no.
decide_update() {
  case $1 in
    yes | no)
      echo "$1"
      return 0
      ;;
  esac
  if [ -f "$UPDATES_ALLOW_FILE" ]; then
    if update_allowed "$2"; then echo yes; else echo no; fi
    return 0
  fi
  if [ "$TTY" = 1 ] && confirm "$3" "$4"; then echo yes; else echo no; fi
}

# update_access applies --allow-updates, --allow-security-updates and
# --allow-reboot (and their --no- forms), or asks once on a terminal.
update_access() {
  if [ ! -x "$RESTART_HELPER" ] || ! grep -qs '^[0-9]' "$RESTART_ALLOW_FILE"; then
    case "$ALLOW_UPDATES$ALLOW_SECURITY$ALLOW_REBOOT" in
      *yes*) warn "installing updates or rebooting from Rowsafe needs --allow-restart too (the same helper does it); left off" ;;
    esac
    remove_update_units
    [ ! -f "$UPDATES_ALLOW_FILE" ] || rm -f "$UPDATES_ALLOW_FILE"
    return 0
  fi
  [ -f "$UPDATES_ALLOW_FILE" ] || [ "$TTY" = 1 ] || [ -n "$ALLOW_UPDATES$ALLOW_SECURITY$ALLOW_REBOOT" ] || return 0
  [ -f "$UPDATES_ALLOW_FILE" ] || [ "$TTY" = 0 ] || say ""
  _pg=$(decide_update "$ALLOW_UPDATES" postgresql "Allow Rowsafe to install PostgreSQL updates when you click Update? Minor updates and major upgrades, only when someone confirms; a Mark is saved first." y)
  _sec=$(decide_update "$ALLOW_SECURITY" security "Allow Rowsafe to install this server's security updates when you click Install? Only when someone confirms." n)
  _reboot=no
  if [ "$_sec" = yes ] || [ "$ALLOW_REBOOT" = yes ]; then
    _reboot=$(decide_update "$ALLOW_REBOOT" reboot "Allow Rowsafe to reboot this server when you click Reboot? Only when someone confirms; a Mark is saved first." n)
  fi
  {
    echo "# What Rowsafe may install or do on this server when someone clicks it in"
    echo "# the dashboard and confirms. Written by the installer (root); change it by"
    echo "# running the installer with --allow-updates / --no-allow-updates,"
    echo "# --allow-security-updates / --no-allow-security-updates and --allow-reboot /"
    echo "# --no-allow-reboot."
    [ "$_pg" != yes ] || echo "postgresql   # PostgreSQL minor updates and major upgrades (clusters in restart-allowed)"
    [ "$_sec" != yes ] || echo "security     # security updates (PostgreSQL's own packages excepted)"
    [ "$_reboot" != yes ] || echo "reboot       # rebooting the server"
  } | write_file "$UPDATES_ALLOW_FILE" 0644 root:root || true
  if [ "$_pg$_sec$_reboot" = nonono ]; then
    remove_update_units
    note "OK: Rowsafe can't install updates or reboot here (change it with --allow-updates, --allow-security-updates, --allow-reboot)"
    return 0
  fi
  install_update_units
  [ "$_pg" != yes ] || ok "Rowsafe may install PostgreSQL updates and upgrade PostgreSQL when you click Update or Upgrade and confirm (turn off with --no-allow-updates)"
  [ "$_sec" != yes ] || ok "Rowsafe may install security updates when you click Install and confirm (turn off with --no-allow-security-updates)"
  [ "$_reboot" != yes ] || ok "Rowsafe may reboot this server when you click Reboot and confirm (turn off with --no-allow-reboot)"
}

# ---------------------------------------------------------------- firewall

# With root's permission (--allow-firewall, or yes at the question), a
# person can have Rowsafe let only chosen addresses reach PostgreSQL's port
# (Security in the dashboard): the agent (unprivileged) writes a request to
# $FIREWALL_DIR, rowsafe-firewall.path starts the root helper, and the
# helper changes only its own nftables table, only for a port listed in
# $FIREWALL_ALLOW_FILE. It runs in a unit of its own: the restart helper's
# sandbox has no network access and stays that way.

install_firewall_helper() {
  install -d -m 0755 -o root -g root "${FIREWALL_HELPER%/*}"
  _changed=0
  if write_file "$FIREWALL_HELPER" 0755 root:root <<'ROWSAFE_FIREWALL_HELPER_EOF'; then
#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# rowsafe-firewall: lets only chosen addresses reach PostgreSQL's port, when
# a person asked Rowsafe to (Security in the dashboard) and root allowed it
# for that port.
#
# Installed by https://rowsafe.sh/install as
# /usr/local/lib/rowsafe/rowsafe-firewall, only when root allowed it
# (--allow-firewall, or yes at the installer's question). It runs as root in
# rowsafe-firewall.service, which rowsafe-firewall.path starts when the
# agent writes a request; the agent itself cannot change the firewall. It
# runs in a unit of its own, not in rowsafe-pg-restart's, because it needs
# the host's network namespace and CAP_NET_ADMIN, which the restart helper
# never gets.
#
# The agent is not trusted. Its request (/var/lib/rowsafe/firewall/request,
# in a directory the agent user owns) is one line, "ID ACTION PORT", ACTION
# being apply, remove or status. For apply,
# /var/lib/rowsafe/firewall/addresses holds the allowed IPv4 and IPv6
# addresses or ranges, one per line (at most 32). They are only read, with
# the agent user's privileges: root never writes or removes anything in the
# agent's directory (the agent removes its request itself). A request ID is
# handled once. Whatever /etc/rowsafe/firewall-allowed (root's) lists, a
# port is refused unless it is at least 1024, no sshd listens on it, and a
# socket of the postgres user listens on it.
#
# Rules live in one nftables table of Rowsafe's own, "inet rowsafe", which
# matches only the allowed PostgreSQL ports: connections to such a port
# from anywhere but the allowed addresses and the server itself are
# dropped; SSH and every other port are never touched. The whole table is
# replaced in one nft transaction, checked with nft -c first. Ports that
# Docker publishes are not covered (their traffic is forwarded, not
# delivered to this server), and the postgres-socket check refuses them.
#
# A new rule is kept as pending-PORT: the helper answers phase=pending and
# waits up to 60 seconds for the agent to confirm
# (/var/lib/rowsafe/firewall/confirm holding the request ID), which the
# agent does only once it still reaches Rowsafe and PostgreSQL. Confirmed,
# it becomes port-PORT; otherwise the previous rules are put back.
#
# Answers go to /run/rowsafe-firewall (root's directory, readable by the
# agent): "result" (id, action, phase, ok, error, finished_at) and, per
# port, "port-PORT" (addresses, applied_at, loaded: whether nftables really
# holds the rules). The rules are kept in /var/lib/rowsafe-firewall and
# loaded again at boot by rowsafe-firewall-restore.service
# ("rowsafe-firewall --restore", which drops unconfirmed rules).

set -u
set -f
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
dir=${ROWSAFE_FIREWALL_DIR:-/var/lib/rowsafe/firewall}
out_dir=${RUNTIME_DIRECTORY:-/run/rowsafe-firewall}
allow=${ROWSAFE_FIREWALL_ALLOW:-/etc/rowsafe/firewall-allowed}
state=${STATE_DIRECTORY:-/var/lib/rowsafe-firewall}
agent_user=${ROWSAFE_AGENT_USER:-postgres}
nft=${ROWSAFE_NFT:-nft}
ss=${ROWSAFE_SS:-ss}
sshd=${ROWSAFE_SSHD:-sshd}
confirm_wait=${ROWSAFE_FIREWALL_CONFIRM_WAIT:-60}

log() { echo "rowsafe-firewall: $*" >&2; }

# as_agent runs a command with the agent user's privileges.
as_agent() { setpriv --reuid="$agent_user" --regid="$agent_user" --init-groups -- "$@"; }

id='' action='' port='' phase='done' ok=0 err=''

# answer writes the result atomically into root's own directory.
answer() {
  tmp=$(mktemp "$out_dir/.result.XXXXXX") || {
    log "cannot write the result in $out_dir"
    exit 0
  }
  printf 'id=%s\naction=%s\nphase=%s\nok=%s\nerror=%s\nfinished_at=%s\n' "$id" "$action" "$phase" "$ok" "$err" "$(date +%s)" >"$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$out_dir/result"
}

refuse() {
  err=$1
  phase='done' ok=0
  log "refused: $1"
  answer
  exit 0
}

# read_agent_file PATH MAXBYTES: prints a regular file, read as the agent
# user; a symlink, FIFO or anything else prints nothing. Nothing is removed.
read_agent_file() {
  # shellcheck disable=SC2016 # $1 and $2 expand in the inner shell
  as_agent sh -c 'if [ -f "$1" ] && [ ! -L "$1" ]; then timeout 5 head -c "$2" -- "$1"; fi' rowsafe-firewall "$1" "$2" 2>/dev/null
}

# valid_port: 1024 to 65535, digits only, no leading zero.
valid_port() {
  printf '%s\n' "$1" | grep -Eq '^[1-9][0-9]{0,4}$' && [ "$1" -ge 1024 ] && [ "$1" -le 65535 ]
}

# valid_cidr: an IPv4 or IPv6 address or range, nothing else.
valid_cidr() {
  printf '%s\n' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' && {
    printf '%s\n' "$1" | awk -F'[./]' '{ for (i = 1; i <= 4; i++) if ($i > 255) exit 1; if (NF == 5 && ($5 < 8 || $5 > 32)) exit 1 }'
    return
  }
  printf '%s\n' "$1" | grep -Eq '^[0-9A-Fa-f:]{2,39}(/[0-9]{1,3})?$' || return 1
  case $1 in *:*) ;; *) return 1 ;; esac
  case $1 in */*) [ "${1#*/}" -ge 16 ] && [ "${1#*/}" -le 128 ] || return 1 ;; esac
}

# listed_port PORT: in root's allow list (ports compare as strings).
listed_port() {
  [ -f "$allow" ] && [ ! -L "$allow" ] || return 1
  [ "$(stat -c '%u' "$allow")" = 0 ] || return 1
  case $(stat -c '%A' "$allow") in ?????w???? | ????????w?) return 1 ;; esac
  awk -v p="$1" '$1 "" == p "" { f = 1 } END { exit !f }' "$allow"
}

# listen_ports [UID]: the TCP ports with a listening socket (of UID).
listen_ports() {
  "$ss" -ltnHe 2>/dev/null | awk -v u="${1:-}" '
    u == "" || index($0, " uid:" u " ") { n = split($4, a, ":"); print a[n] }' | sort -u
}

# ssh_port PORT: sshd listens on PORT, or is set to.
ssh_port() {
  {
    "$sshd" -T 2>/dev/null | awk '$1 == "port" { print $2 }'
    "$ss" -ltnHp 2>/dev/null | awk '/"sshd"/ { n = split($4, a, ":"); print a[n] }'
  } | awk -v p="$1" '$1 "" == p "" { f = 1 } END { exit !f }'
}

# rule_files prints the rule files in $state: port-P, and pending-P which
# replaces port-P while it waits for its confirmation.
rule_files() {
  find "$state" -maxdepth 1 -type f \( -name 'port-*' -o -name 'pending-*' \) 2>/dev/null |
    awk -F/ '{ f = $NF; p = f; sub(/^(port|pending)-/, "", p); if (f ~ /^pending-/ || !(p in r)) r[p] = $0 } END { for (p in r) print r[p] }' | sort
}

# render prints the whole table.
render() {
  echo "table inet rowsafe {}"
  echo "delete table inet rowsafe"
  echo "table inet rowsafe {"
  echo "  chain input {"
  echo "    type filter hook input priority filter - 5; policy accept;"
  echo "    iifname \"lo\" accept"
  for f in $(rule_files); do
    p=${f##*/}
    p=${p#*-}
    valid_port "$p" || continue
    v4=$(grep -v ':' "$f" | paste -sd, -)
    v6=$(grep ':' "$f" | paste -sd, -)
    [ -z "$v4" ] || echo "    tcp dport $p ip saddr { $v4 } accept"
    [ -z "$v6" ] || echo "    tcp dport $p ip6 saddr { $v6 } accept"
    echo "    tcp dport $p drop"
  done
  echo "  }"
  echo "}"
}

loaded() { "$nft" list table inet rowsafe >/dev/null 2>&1; }

# load applies the rules in $state (or removes the table when none are
# left), and checks nftables holds them.
load() {
  if [ -n "$(rule_files)" ]; then
    render >"$state/rules.nft.new" || return 1
    "$nft" -c -f "$state/rules.nft.new" 2>"$state/nft.err" || return 1
    "$nft" -f "$state/rules.nft.new" 2>"$state/nft.err" || return 1
    mv -f "$state/rules.nft.new" "$state/rules.nft"
    loaded || {
      echo "nftables does not hold Rowsafe's table after loading it" >"$state/nft.err"
      return 1
    }
  else
    rm -f "$state/rules.nft"
    if loaded; then
      "$nft" delete table inet rowsafe 2>"$state/nft.err" || return 1
    fi
  fi
}

# publish writes the public view of each confirmed rule for the agent.
publish() {
  find "$out_dir" -maxdepth 1 -type f -name 'port-*' -exec rm -f {} + 2>/dev/null
  l=0
  if loaded; then l=1; fi
  find "$state" -maxdepth 1 -type f -name 'port-*' 2>/dev/null | while read -r f; do
    p=${f##*/port-}
    tmp=$(mktemp "$out_dir/.port.XXXXXX") || return 0
    printf 'addresses=%s\napplied_at=%s\nloaded=%s\n' "$(paste -sd, - <"$f")" "$(stat -c '%Y' "$f")" "$l" >"$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$out_dir/port-$p"
  done
}

mkdir -p "$state"
chmod 0700 "$state"

if [ "${1:-}" = --restore ]; then
  # Unconfirmed rules never come back.
  find "$state" -maxdepth 1 -type f -name 'pending-*' -exec rm -f {} + 2>/dev/null
  if load; then
    publish
    log "rules loaded"
  else
    log "loading the rules failed: $(cat "$state/nft.err" 2>/dev/null)"
    exit 1
  fi
  exit 0
fi

line=$(read_agent_file "$dir/request" 200 | head -n 1)
[ -n "$line" ] || exit 0
if printf '%s\n' "$line" | grep -Eq '^[A-Za-z0-9_-]{1,64} (apply|remove|status) [1-9][0-9]{0,4}$'; then
  id=${line%% *}
  rest=${line#* }
  action=${rest% *}
  port=${rest#* }
else
  refuse "malformed request"
fi
# Each request is handled once (the agent removes it once it has the answer).
[ "$(cat "$state/last-request" 2>/dev/null)" != "$id" ] || exit 0
printf '%s\n' "$id" >"$state/last-request"

if [ "$action" = status ]; then
  publish
  ok=1
  answer
  exit 0
fi

command -v "$nft" >/dev/null 2>&1 || refuse "nftables (the nft command) is not installed on this server"
valid_port "$port" || refuse "port $port can't be managed by Rowsafe: only ports 1024 to 65535"
listed_port "$port" || refuse "port $port is not in $allow: changing the firewall for it from Rowsafe is not allowed"
if ssh_port "$port"; then refuse "port $port is SSH's: Rowsafe never touches it"; fi

# Keep the current rules to go back to.
rm -rf "$state/previous"
mkdir -p "$state/previous"
for f in $(rule_files); do cp -p "$f" "$state/previous/"; done

rollback() {
  find "$state" -maxdepth 1 -type f \( -name 'port-*' -o -name 'pending-*' \) -exec rm -f {} + 2>/dev/null
  find "$state/previous" -maxdepth 1 -type f -exec cp -p {} "$state/" \; 2>/dev/null
  if ! load; then
    publish
    return 1
  fi
  publish
}

if [ "$action" = apply ]; then
  uid=$(id -u "$agent_user" 2>/dev/null) || refuse "no $agent_user user"
  listen_ports "$uid" | grep -qx "$port" ||
    refuse "no PostgreSQL of the $agent_user user listens on port $port here (a port Docker publishes bypasses this firewall: limit it in the compose file instead)"
  addrs=$(read_agent_file "$dir/addresses" 4096 | head -n 33)
  n=0
  : >"$state/new-$port"
  for a in $addrs; do
    valid_cidr "$a" || {
      rm -f "$state/new-$port"
      refuse "not an address or range: $(printf '%s' "$a" | cut -c1-60)"
    }
    n=$((n + 1))
    printf '%s\n' "$a" >>"$state/new-$port"
  done
  [ "$n" -ge 1 ] && [ "$n" -le 32 ] || {
    rm -f "$state/new-$port"
    refuse "between 1 and 32 addresses are needed, got $n"
  }
  mv -f "$state/new-$port" "$state/pending-$port"
else
  rm -f "$state/port-$port" "$state/pending-$port"
fi

if ! load; then
  e=$(tr '\n' ' ' <"$state/nft.err" 2>/dev/null | cut -c1-300)
  if rollback; then
    refuse "nft refused the rules: $e"
  fi
  refuse "nft refused the rules ($e), and putting the previous rules back failed too: check with 'nft list table inet rowsafe'"
fi
log "$action port $port (request $id)"

if [ "$action" = apply ]; then
  # Wait for the agent to confirm it still reaches Rowsafe and PostgreSQL.
  phase=pending ok=1
  answer
  confirmed=0
  i=0
  while [ "$i" -lt "$((confirm_wait * 2))" ]; do
    if [ "$(read_agent_file "$dir/confirm" 100 | head -n 1)" = "$id" ]; then
      confirmed=1
      break
    fi
    sleep 0.5
    i=$((i + 1))
  done
  phase='done'
  if [ "$confirmed" != 1 ]; then
    if rollback; then
      ok=0 err="the agent did not confirm within ${confirm_wait}s that it still reaches Rowsafe and PostgreSQL, so the previous rules were put back"
    else
      ok=0 err="the agent did not confirm within ${confirm_wait}s, and putting the previous rules back failed: check with 'nft list table inet rowsafe'"
    fi
    log "$err"
    answer
    exit 0
  fi
  mv -f "$state/pending-$port" "$state/port-$port"
fi
publish
ok=1
log "$action port $port: done"
answer
ROWSAFE_FIREWALL_HELPER_EOF
    _changed=1
  fi
  if write_file "$FIREWALL_SERVICE_FILE" 0644 root:root <<'ROWSAFE_FIREWALL_SERVICE_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-firewall.service: lets only chosen addresses reach a PostgreSQL
# port root listed in /etc/rowsafe/firewall-allowed, when the Rowsafe agent
# asks because a person did (see /usr/local/lib/rowsafe/rowsafe-firewall).
# Started by rowsafe-firewall.path; installed by https://rowsafe.sh/install
# only when root allowed it.

[Unit]
Description=Rowsafe: limit who can reach PostgreSQL's port, on request
Documentation=https://rowsafe.sh/docs/guides/security

[Service]
Type=oneshot
ExecStart=/usr/local/lib/rowsafe/rowsafe-firewall
TimeoutStartSec=120
# The agent user, whose privileges read and remove the request.
Environment=ROWSAFE_AGENT_USER=postgres
# The answer: root's own directory, which the agent can read.
RuntimeDirectory=rowsafe-firewall
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
# The rules, out of the agent's reach.
StateDirectory=rowsafe-firewall
StateDirectoryMode=0700
UMask=0022

# Hardening. It needs the host's network namespace and CAP_NET_ADMIN to
# change nftables (over netlink), and CAP_SETUID/CAP_SETGID to read the
# request as the agent user. No IP traffic at all, and nothing it can write
# in the agent's directory.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SETUID CAP_SETGID
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX AF_NETLINK
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
ROWSAFE_FIREWALL_SERVICE_EOF
    _changed=1
  fi
  if write_file "$FIREWALL_PATH_FILE" 0644 root:root <<'ROWSAFE_FIREWALL_PATH_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-firewall.path: starts rowsafe-firewall.service when the Rowsafe
# agent asks to change who can reach PostgreSQL's port (someone chose the
# allowed addresses under Security in the dashboard). Installed by
# https://rowsafe.sh/install only when root allowed it; remove it with
# --no-allow-firewall.

[Unit]
Description=Rowsafe: watch for requests to limit who can reach PostgreSQL
Documentation=https://rowsafe.sh/docs/guides/security

[Path]
# The helper never removes the request (the agent does): start on a change.
PathChanged=/var/lib/rowsafe/firewall/request
Unit=rowsafe-firewall.service

[Install]
WantedBy=multi-user.target
ROWSAFE_FIREWALL_PATH_EOF
    _changed=1
  fi
  if write_file "$FIREWALL_RESTORE_FILE" 0644 root:root <<'ROWSAFE_FIREWALL_RESTORE_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-firewall-restore.service: loads the rules Rowsafe's firewall
# helper keeps (/var/lib/rowsafe-firewall) at boot, after the system's own
# firewall. Installed by https://rowsafe.sh/install only when root allowed
# it; remove it with --no-allow-firewall.

[Unit]
Description=Rowsafe: load the PostgreSQL port rules at boot
Documentation=https://rowsafe.sh/docs/guides/security
After=nftables.service ufw.service firewalld.service network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/lib/rowsafe/rowsafe-firewall --restore
RuntimeDirectory=rowsafe-firewall
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
StateDirectory=rowsafe-firewall
StateDirectoryMode=0700
UMask=0022
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX AF_NETLINK
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
ROWSAFE_FIREWALL_RESTORE_EOF
    _changed=1
  fi
  as_agent mkdir -p -m 0700 "$FIREWALL_DIR"
  if systemd_running; then
    [ "$_changed" = 0 ] || systemctl daemon-reload
    systemctl enable --now --quiet rowsafe-firewall.path
    systemctl enable --quiet rowsafe-firewall-restore.service
  else
    warn "systemd is not running here; the firewall helper was installed but cannot be enabled"
  fi
}

remove_firewall_helper() {
  [ -e "$FIREWALL_PATH_FILE" ] || [ -e "$FIREWALL_SERVICE_FILE" ] || [ -e "$FIREWALL_HELPER" ] || return 0
  if systemd_running; then
    systemctl disable --now --quiet rowsafe-firewall.path 2>/dev/null || true
    systemctl disable --quiet rowsafe-firewall-restore.service 2>/dev/null || true
  fi
  # Rowsafe's rule goes with the helper: nothing it set up stays behind.
  if command -v nft >/dev/null 2>&1 && nft list table inet rowsafe >/dev/null 2>&1; then
    nft delete table inet rowsafe || warn "could not remove Rowsafe's firewall rules (nft delete table inet rowsafe)"
  fi
  rm -rf /var/lib/rowsafe-firewall /run/rowsafe-firewall
  rm -f "$FIREWALL_PATH_FILE" "$FIREWALL_SERVICE_FILE" "$FIREWALL_RESTORE_FILE" "$FIREWALL_HELPER"
  rmdir "${FIREWALL_HELPER%/*}" 2>/dev/null || true
  if systemd_running; then systemctl daemon-reload; fi
}

# ssh_port_here PORT: sshd listens on PORT here, or is set to.
ssh_port_here() {
  {
    sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }'
    ss -ltnHp 2>/dev/null | awk '/"sshd"/ { n = split($4, a, ":"); print a[n] }'
  } | awk -v p="$1" '$1 "" == p "" { f = 1 } END { exit !f }'
}

# firewall_ports prints the TCP ports PostgreSQL listens on, found by root
# itself (pg_lsclusters, and the agent user's listening sockets), never
# taken from the agent: 1024 to 65535, never one sshd uses.
firewall_ports() {
  {
    if command -v pg_lsclusters >/dev/null 2>&1; then pg_lsclusters -h 2>/dev/null | awk '{ print $3 }'; fi
    if _uid=$(id -u "$AGENT_USER" 2>/dev/null) && command -v ss >/dev/null 2>&1; then
      ss -ltnHe 2>/dev/null | awk -v u="$_uid" 'index($0, " uid:" u " ") { n = split($4, a, ":"); print a[n] }'
    fi
  } | grep -Ex '[1-9][0-9]{3,4}' | awk '$1 >= 1024 && $1 <= 65535' | sort -un | while read -r _p; do
    ssh_port_here "$_p" || echo "$_p"
  done
}

# firewall_listed prints the ports already in the allow list.
firewall_listed() {
  [ -f "$FIREWALL_ALLOW_FILE" ] || return 0
  grep -Ex '[1-9][0-9]{3,4}' "$FIREWALL_ALLOW_FILE" || true
}

# write_firewall_allow PORTS...: the allow list, written by root.
write_firewall_allow() {
  {
    echo "# PostgreSQL ports whose firewall rule Rowsafe may set when someone asks"
    echo "# (Security in the dashboard): only the chosen addresses may reach the"
    echo "# port. SSH and other ports are never touched. Written by the installer"
    echo "# (root); run it with --no-allow-firewall to turn this off."
    echo "# PORT"
    printf '%s\n' "$@" | sort -un
  } | write_file "$FIREWALL_ALLOW_FILE" 0644 root:root || true
}

allow_firewall() {
  if ! command -v nft >/dev/null 2>&1; then
    warn "nftables isn't installed here (no nft command), so limiting who can reach PostgreSQL stays off. Install it (e.g. apt install nftables) and run the installer again with --allow-firewall"
    return 0
  fi
  _ports=$(firewall_ports)
  _listed=$(firewall_listed)
  if [ -z "$_ports$_listed" ]; then
    warn "found no PostgreSQL listening here, so the firewall stays off for Rowsafe"
    return 0
  fi
  # shellcheck disable=SC2086 # one port per word
  write_firewall_allow $_listed $_ports
  install_firewall_helper
  ok "Rowsafe may limit who can reach PostgreSQL's port ($(firewall_listed | paste -sd, - | sed 's/,/, /g')) when you ask (Security), never SSH or other ports (turn off with --no-allow-firewall)"
}

disallow_firewall() {
  remove_firewall_helper
  if [ -d "$CONFIG_DIR" ]; then
    {
      echo "# Limiting who can reach PostgreSQL with the firewall is off for Rowsafe."
      echo "# Run the installer with --allow-firewall to turn it on."
    } | write_file "$FIREWALL_ALLOW_FILE" 0644 root:root || true
  fi
}

# firewall_access applies --allow-firewall / --no-allow-firewall, or asks
# once on a terminal (default no). A re-run keeps the allow list as it is,
# and adds a port it doesn't list only after a fresh yes.
firewall_access() {
  case $ALLOW_FIREWALL in
    yes) allow_firewall ;;
    no)
      disallow_firewall
      ok "limiting who can reach PostgreSQL with the firewall is off for Rowsafe"
      ;;
    *)
      if [ -n "$(firewall_listed)" ]; then
        install_firewall_helper
        _new=$(firewall_ports | grep -vxF "$(firewall_listed)" || true)
        [ -n "$_new" ] && [ "$TTY" = 1 ] || return 0
        say ""
        if confirm "PostgreSQL also listens on port $(printf '%s' "$_new" | paste -sd, - | sed 's/,/, /g'). Allow Rowsafe's firewall rule for it too?" n; then
          # shellcheck disable=SC2046 # one port per word
          write_firewall_allow $(firewall_listed) $_new
        fi
        return 0
      fi
      [ -f "$FIREWALL_ALLOW_FILE" ] && return 0 # a no, kept
      [ "$TTY" = 1 ] && command -v nft >/dev/null 2>&1 || return 0
      _ports=$(firewall_ports)
      [ -n "$_ports" ] || return 0
      say ""
      if confirm "Allow Rowsafe to limit who can reach PostgreSQL's port ($(printf '%s' "$_ports" | paste -sd, - | sed 's/,/, /g')) with the firewall? Only when someone picks the allowed addresses in the dashboard and confirms; SSH and other ports are never touched." n; then
        allow_firewall
      else
        disallow_firewall
        note "OK: Rowsafe won't change the firewall (change it with --allow-firewall)"
      fi
      ;;
  esac
}

# ---------------------------------------------------------------- PgBouncer

# Connection pooling. With root's permission (--allow-pooler, or yes at the
# question), a person can turn pooling on for a database in the dashboard:
# the agent (unprivileged) writes a request to $POOLER_DIR,
# rowsafe-pooler.path starts the root helper in PgBouncer mode, and the
# helper installs the pgbouncer package, writes its configuration from its
# own template and starts it, only for a PostgreSQL port listed in
# $POOLER_ALLOW_FILE. Nothing is installed until someone turns pooling on.

install_pooler_units() {
  install_helper_script
  _changed=$HELPER_CHANGED
  if write_file "$POOLER_SERVICE_FILE" 0644 root:root <<'ROWSAFE_POOLER_SERVICE_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-pooler.service: configures, reloads or turns off PgBouncer in front
# of a PostgreSQL cluster that root listed in /etc/rowsafe/pooler-allowed,
# when the Rowsafe agent asks because a person turned pooling on, changed it
# or turned it off (see "PgBouncer" in /usr/local/lib/rowsafe/rowsafe-pg-restart).
# Started by rowsafe-pooler.path; installed by https://rowsafe.sh/install
# only when root allowed it. Installing or removing the pgbouncer package
# runs in rowsafe-pooler-apt@.service, which this unit starts.

[Unit]
Description=Rowsafe: manage PgBouncer on request
Documentation=https://rowsafe.sh/docs/guides/connection-pooling

[Service]
Type=oneshot
ExecStart=/usr/local/lib/rowsafe/rowsafe-pg-restart
TimeoutStartSec=1500
Environment=ROWSAFE_HELPER_MODE=pooler
# The agent user, whose privileges read and remove the request, and the
# directory it writes requests to.
Environment=ROWSAFE_AGENT_USER=postgres
Environment=ROWSAFE_RESTART_DIR=/var/lib/rowsafe/pooler
# The answer: root's own directory, which the agent can read.
RuntimeDirectory=rowsafe-pooler
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
# PgBouncer's original configuration, whether Rowsafe installed the package
# and when it last installed or removed it, out of the agent's reach.
StateDirectory=rowsafe-pooler
StateDirectoryMode=0700
UMask=0022

# Hardening. The system is read-only except PgBouncer's configuration and
# its systemd drop-in directory; no network. The request is read and removed
# as the agent user (CAP_SETUID/CAP_SETGID); root then writes PgBouncer's
# files (CAP_CHOWN, CAP_FOWNER, CAP_DAC_OVERRIDE for the package's
# postgres-owned files) and asks systemd, over its private socket, to start
# or reload pgbouncer.service or rowsafe-pooler-apt@.service.
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=-/etc/pgbouncer -/etc/systemd/system/pgbouncer.service.d -/var/lib/rowsafe/pooler
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
ROWSAFE_POOLER_SERVICE_EOF
    _changed=1
  fi
  if write_file "$POOLER_PATH_FILE" 0644 root:root <<'ROWSAFE_POOLER_PATH_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-pooler.path: starts rowsafe-pooler.service when the Rowsafe agent
# asks to install, configure or turn off PgBouncer (someone turned pooling on,
# changed it or turned it off in Rowsafe). Installed by
# https://rowsafe.sh/install only when root allowed it; remove it with
# --no-allow-pooler.

[Unit]
Description=Rowsafe: watch for requests to manage PgBouncer
Documentation=https://rowsafe.sh/docs/guides/connection-pooling

[Path]
PathExists=/var/lib/rowsafe/pooler/request
Unit=rowsafe-pooler.service

[Install]
WantedBy=multi-user.target
ROWSAFE_POOLER_PATH_EOF
    _changed=1
  fi
  if write_file "$POOLER_APT_FILE" 0644 root:root <<'ROWSAFE_POOLER_APT_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-pooler-apt@install.service / @purge.service: installs or removes
# the pgbouncer package, and nothing else. Started only by
# rowsafe-pooler.service (root), at most once every 10 minutes; it takes no
# input from the agent but its instance name. Installed by
# https://rowsafe.sh/install only when root allowed PgBouncer.

[Unit]
Description=Rowsafe: %i the pgbouncer package
Documentation=https://rowsafe.sh/docs/guides/connection-pooling

[Service]
Type=oneshot
ExecStart=/usr/local/lib/rowsafe/rowsafe-pg-restart
TimeoutStartSec=900
Environment=ROWSAFE_HELPER_MODE=pooler-apt
Environment=ROWSAFE_APT_ACTION=%i
StateDirectory=rowsafe-pooler
StateDirectoryMode=0700
UMask=0022

# apt and dpkg need the network and write access to the system, so this unit
# is less confined; it only ever runs "apt-get install pgbouncer" or
# "apt-get purge pgbouncer".
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
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
SystemCallArchitectures=native
SystemCallFilter=@system-service
ROWSAFE_POOLER_APT_EOF
    _changed=1
  fi
  # The helper's unit may only write PgBouncer's drop-in directory, so it
  # must exist.
  install -d -m 0755 -o root -g root "$POOLER_DROPIN_DIR"
  if systemd_running; then
    [ "$_changed" = 0 ] || systemctl daemon-reload
    systemctl enable --now --quiet rowsafe-pooler.path
  else
    warn "systemd is not running here; the PgBouncer helper was installed but cannot be enabled"
  fi
}

remove_pooler_units() {
  [ -e "$POOLER_PATH_FILE" ] || [ -e "$POOLER_SERVICE_FILE" ] || [ -e "$POOLER_APT_FILE" ] || return 0
  if systemd_running; then
    systemctl disable --now --quiet rowsafe-pooler.path 2>/dev/null || true
  fi
  rm -f "$POOLER_PATH_FILE" "$POOLER_SERVICE_FILE" "$POOLER_APT_FILE"
  rmdir "$POOLER_DROPIN_DIR" 2>/dev/null || true
  [ -e "$RESTART_PATH_FILE" ] || rm -f "$RESTART_HELPER" # restarts still use it
  rmdir "${RESTART_HELPER%/*}" 2>/dev/null || true
  if systemd_running; then systemctl daemon-reload; fi
}

# pooler_ports prints the ports of this server's PostgreSQL clusters, found
# by root: pg_lsclusters (Debian and Ubuntu), else the TCP ports that
# processes of the agent user listen on. Never the agent's own discovery:
# the agent user owns the agent's binary.
pooler_ports() {
  if have pg_lsclusters; then
    pg_lsclusters -h 2>/dev/null | awk '$3 ~ /^[0-9]+$/ && $3 > 0 && $3 < 65536 { print $3 }' | sort -un
    return 0
  fi
  _uid=$(id -u "$AGENT_USER" 2>/dev/null) || return 0
  have ss || return 0
  ss -Hltne 2>/dev/null | awk -v u="uid:$_uid" '{ for (i = 1; i <= NF; i++) if ($i == u) { n = split($4, a, ":"); print a[n] } }' |
    awk '$1 ~ /^[0-9]+$/' | sort -un
}

# pooler_allowed_ports prints the ports already in the allow list.
pooler_allowed_ports() {
  [ -f "$POOLER_ALLOW_FILE" ] && awk '$1 ~ /^[0-9]+$/ { print $1 }' "$POOLER_ALLOW_FILE"
}

# write_pooler_allow PORTS PUBLIC writes the allow list.
write_pooler_allow() {
  {
    echo "# PostgreSQL clusters Rowsafe may put PgBouncer (connection pooling) in"
    echo "# front of, when someone turns pooling on in Rowsafe and confirms."
    echo "# Written by the installer (root); run it with --no-allow-pooler to turn"
    echo "# this off. \"public\": PgBouncer may listen on every address"
    echo "# (--allow-pooler-public)."
    echo "# PORT"
    printf '%s\n' "$1"
    if [ "$2" = 1 ]; then echo public; fi
  } | write_file "$POOLER_ALLOW_FILE" 0644 root:root || true
}

# allow_pooler: --allow-pooler, or yes at the question: every cluster root
# finds, plus the ones allowed before.
allow_pooler() {
  _ports=$(printf '%s\n%s\n' "$(pooler_allowed_ports)" "$(pooler_ports)" | awk 'NF' | sort -un)
  if [ -z "$_ports" ]; then
    warn "found no PostgreSQL here, so managing PgBouncer from Rowsafe stays off"
    return 0
  fi
  _public=$ALLOW_POOLER_PUBLIC
  if grep -qsx public "$POOLER_ALLOW_FILE"; then _public=1; fi
  write_pooler_allow "$_ports" "$_public"
  install_pooler_units
  ok "Rowsafe may install and manage PgBouncer when you turn pooling on, only when someone confirms (turn off with --no-allow-pooler)"
  if [ "$_public" = 1 ]; then note "PgBouncer may listen on public addresses when someone chooses that: put a firewall in front of it."; fi
}

# refresh_pooler: a re-run keeps the allow list as it is and adds a cluster
# found since only when someone says yes on a terminal.
refresh_pooler() {
  _have=$(pooler_allowed_ports)
  _ports=$_have
  for _newport in $(pooler_ports); do
    printf '%s\n' "$_have" | grep -qx "$_newport" && continue
    # (confirm uses $_p itself.)
    if [ "$TTY" = 1 ] && confirm "Also allow PgBouncer for the PostgreSQL on port $_newport?" n; then
      _ports=$(printf '%s\n%s\n' "$_ports" "$_newport" | awk 'NF' | sort -un)
    fi
  done
  _public=$ALLOW_POOLER_PUBLIC
  if grep -qsx public "$POOLER_ALLOW_FILE"; then _public=1; fi
  _was_public=0
  if grep -qsx public "$POOLER_ALLOW_FILE"; then _was_public=1; fi
  if [ "$_ports" != "$_have" ] || [ "$_public" != "$_was_public" ]; then
    write_pooler_allow "$_ports" "$_public"
  fi
  install_pooler_units
}

disallow_pooler() {
  remove_pooler_units
  if [ -d "$CONFIG_DIR" ]; then
    {
      echo "# Managing PgBouncer from Rowsafe is off on this server."
      echo "# Run the installer with --allow-pooler to turn it on."
    } | write_file "$POOLER_ALLOW_FILE" 0644 root:root || true
  fi
  if [ -f /etc/pgbouncer/pgbouncer.ini ] && [ "$(head -n 1 /etc/pgbouncer/pgbouncer.ini)" = ';; Managed by Rowsafe' ]; then
    note "PgBouncer set up by Rowsafe keeps running for your apps; Rowsafe can no longer change it or turn it off."
  fi
}

# pooler_access applies --allow-pooler / --no-allow-pooler, or asks once on a
# terminal. A re-run keeps the earlier answer (and refreshes the list).
pooler_access() {
  case $ALLOW_POOLER in
    yes) allow_pooler ;;
    no)
      disallow_pooler
      ok "managing PgBouncer from Rowsafe is off"
      ;;
    *)
      if [ -f "$POOLER_ALLOW_FILE" ]; then
        if grep -q '^[0-9]' "$POOLER_ALLOW_FILE"; then refresh_pooler; fi
        return 0
      fi
      [ "$TTY" = 1 ] && [ -n "$(pooler_ports)" ] || return 0
      say ""
      if confirm "Allow Rowsafe to install and manage PgBouncer? Nothing is installed now: only when someone turns connection pooling on in the dashboard and confirms." y; then
        allow_pooler
      else
        disallow_pooler
        note "OK: Rowsafe won't install or manage PgBouncer (change it with --allow-pooler)"
      fi
      ;;
  esac
}

# ---------------------------------------------------------------- files
# (feat/files) The folders that go with a database (uploads, media): the
# agent backs them up with restic into the database's bucket, encrypted with
# a key derived from the backup passphrase (no second secret to keep).
#
#   --files PATH       protect PATH with the database (repeat for several);
#                      root gives the agent user read access (ACL) if needed
#   --allow-files      let Rowsafe put restored files back as the folder's
#                      owner, and read folders added later in the dashboard,
#                      under the roots in /etc/rowsafe/files-allowed (via the
#                      root helper); --no-allow-files turns it off
#   --no-files         don't ask about folders
#
# restic is a pinned release from its GitHub releases, verified against the
# SHA-256 published in the release's SHA256SUMS (signed by restic's release
# key, CF8F18F2844575973F79D4E191A6868BD3F7A907, checked when it was pinned).

RESTIC_VERSION=0.19.1
RESTIC_SHA256_AMD64=f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c
RESTIC_SHA256_ARM64=a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465
RESTIC_BIN=$LIB_DIR/restic
FILES_ALLOW_FILE=$CONFIG_DIR/files-allowed
FILES_DROPIN_DIR=/etc/systemd/system/rowsafe-pg-restart.service.d
FILES_DROPIN=$FILES_DROPIN_DIR/rowsafe-files.conf
# Where folders added later in the dashboard may be (root's allow list).
FILES_DEFAULT_ROOTS="/srv /var/www /opt /data /app /var/lib/docker/volumes"
FILES_PATHS=''     # --files PATH (newline-separated)
ALLOW_FILES=''     # --allow-files (yes) / --no-allow-files (no); '' = ask once, on a terminal
NO_FILES=0         # --no-files
FILES_PROTECTED='' # folders protected by this run (newline-separated)
FILES_DB_ID='' FILES_DB_NAME=''

restic_ok() {
  [ -x "$RESTIC_BIN" ] && "$RESTIC_BIN" version 2>/dev/null | grep -q "^restic $RESTIC_VERSION "
}

# ensure_restic installs the pinned restic into $LIB_DIR (root's). A failed
# or mismatching download leaves files backups off; database backups are
# not affected.
ensure_restic() {
  if restic_ok; then
    ok "restic $RESTIC_VERSION (backs up the folders that go with your databases)"
    return 0
  fi
  case $ARCH in
    amd64) _sum=$RESTIC_SHA256_AMD64 ;;
    arm64) _sum=$RESTIC_SHA256_ARM64 ;;
  esac
  have bunzip2 || apt_install bzip2
  _url=${ROWSAFE_RESTIC_URL:-https://github.com/restic/restic/releases/download}/v$RESTIC_VERSION/restic_${RESTIC_VERSION}_linux_$ARCH.bz2
  rm -f "$TMP/restic.bz2" "$TMP/restic"
  if ! fetch "$_url" "$TMP/restic.bz2"; then
    restic_from_distro "could not download restic from $_url"
    return 0
  fi
  _got=$(sha256sum "$TMP/restic.bz2" | cut -d' ' -f1)
  if [ "$_got" != "$_sum" ]; then
    rm -f "$TMP/restic.bz2"
    warn "the restic download from $_url does not match the SHA-256 of the official $RESTIC_VERSION release ($_got instead of $_sum): not installed. Backups of files stay off; database backups are not affected."
    return 0
  fi
  if ! bunzip2 -c "$TMP/restic.bz2" >"$TMP/restic" || ! chmod 0755 "$TMP/restic" || ! "$TMP/restic" version >/dev/null 2>&1; then
    warn "the verified restic $RESTIC_VERSION does not run here; files backups stay off"
    return 0
  fi
  install -d -m 0755 -o root -g root "$LIB_DIR"
  install -m 0755 -o root -g root "$TMP/restic" "$RESTIC_BIN.new"
  mv -f "$RESTIC_BIN.new" "$RESTIC_BIN"
  ok "restic $RESTIC_VERSION installed (official release, SHA-256 verified) for backing up the folders that go with your databases"
}

# restic_from_distro falls back to the distribution's package when it is
# recent enough (0.17 or newer); the agent finds it on PATH.
restic_from_distro() {
  _v=$(apt-cache policy restic 2>/dev/null | awk '/Candidate:/ { print $2 }' | sed 's/^[0-9]*://; s/[-+~].*//')
  case $_v in
    0.1[7-9]* | 0.[2-9][0-9]* | [1-9]*)
      if apt_install restic 2>/dev/null; then
        ok "restic $_v from $OS_NAME's packages ($1)"
        return 0
      fi
      ;;
  esac
  warn "$1, and $OS_NAME has no recent enough restic package: backups of files stay off until the installer runs again with GitHub reachable. Database backups are not affected."
}

files_allowed() { grep -qs '^/' "$FILES_ALLOW_FILE"; }

# files_grant_read gives the agent user read access to a folder the person
# chose to protect (POSIX ACLs; ownership and modes stay as they are).
files_grant_read() {
  have setfacl || apt_install acl
  if ! setfacl -R -P -m "u:$AGENT_USER:rX" -- "$1" ||
    ! find -P "$1" -type d -exec setfacl -m "d:u:$AGENT_USER:rX" -- {} +; then
    warn "could not give the agent read access to $1 (see above); it is not protected"
    return 1
  fi
  _p=${1%/*}
  while [ -n "$_p" ]; do
    as_agent test -x "$_p" 2>/dev/null || setfacl -m "u:$AGENT_USER:x" -- "$_p" || true
    _p=${_p%/*}
  done
  ok "gave the Rowsafe agent read access to $1 (read-only, with an ACL; nothing else changed)"
}

# files_pick_database sets FILES_DB_ID and FILES_DB_NAME: the database the
# folders go with.
files_pick_database() {
  agent_run setup discover >"$TMP/files-dbs" 2>/dev/null || return 1
  awk -F '\t' '$8 == "yes" && $13 != "-" { print $13 "\t" $7 }' "$TMP/files-dbs" >"$TMP/files-db"
  if [ -n "$PROTECT_NAME" ]; then
    awk -F '\t' -v n="$PROTECT_NAME" '$2 == n' "$TMP/files-db" >"$TMP/files-db1"
    mv "$TMP/files-db1" "$TMP/files-db"
  fi
  case $(wc -l <"$TMP/files-db" | tr -d ' ') in
    0) return 1 ;;
    1) _line=$(cat "$TMP/files-db") ;;
    *)
      [ "$TTY" = 1 ] || return 1
      say ""
      tty_say "Which database do these files go with?"
      _i=0
      while IFS="$(printf '\t')" read -r _id _name; do
        _i=$((_i + 1))
        tty_say "  $_i) $_name"
      done <"$TMP/files-db"
      while :; do
        ask _n "Number" 1
        if matches "$_n" '^[0-9]+$' && [ "$_n" -ge 1 ] && [ "$_n" -le "$_i" ]; then break; fi
        tty_bad "Type a number from 1 to $_i."
      done
      _line=$(sed -n "${_n}p" "$TMP/files-db")
      ;;
  esac
  FILES_DB_ID=$(printf '%s\n' "$_line" | cut -f1)
  FILES_DB_NAME=$(printf '%s\n' "$_line" | cut -f2)
}

# files_protect PATH protects one folder.
files_protect() {
  _acc=$(agent_run files access "$1" 2>"$TMP/files.err") || {
    warn "$(cat "$TMP/files.err"): skipped"
    return 0
  }
  case $_acc in
    missing)
      warn "$1 doesn't exist on this server; skipped"
      return 0
      ;;
    no) files_grant_read "$1" || return 0 ;;
  esac
  if ! agent_run files add --database "$FILES_DB_ID" --path "$1" >"$TMP/files.out" 2>"$TMP/files.err"; then
    warn "$(sed 's/^error: //' "$TMP/files.err")"
    return 0
  fi
  FILES_PROTECTED="$FILES_PROTECTED$1
"
  ok "$1 is backed up with $FILES_DB_NAME: every 15 minutes and at every Mark, into the same bucket"
}

# files_setup runs after the database setup: --files, or (on a terminal)
# "Does this app store uploads on this server?".
files_setup() {
  _ask=0
  if [ "$TTY" = 1 ] && [ "$NO_FILES" = 0 ] && [ "$NO_SETUP" = 0 ] && [ -z "$FILES_PATHS" ]; then _ask=1; fi
  if [ -z "$FILES_PATHS" ] && [ "$_ask" = 0 ]; then
    [ -z "$ALLOW_FILES" ] || files_access
    return 0
  fi
  if ! files_pick_database; then
    [ -z "$FILES_PATHS" ] || warn "--files: no database on this server is set up with Rowsafe yet (or several: add --protect NAME), so folders can't be protected yet"
    return 0
  fi
  agent_run files list --database "$FILES_DB_ID" >"$TMP/files-have" 2>/dev/null || : >"$TMP/files-have"
  if [ "$_ask" = 1 ]; then
    "$INSTALL_DIR/rowsafe-agent" files discover 2>/dev/null >"$TMP/files-found" || : >"$TMP/files-found"
    _asked=0
    while IFS="$(printf '\t')" read -r _path _bytes _count _readable _size _why <&4; do
      grep -qxF -- "$_path" "$TMP/files-have" && continue
      [ "$_asked" -lt 3 ] || break
      _asked=$((_asked + 1))
      say ""
      if confirm "Does this app store uploads on this server? Rowsafe found $_path ($_size, $_count files: $_why). Back it up with $FILES_DB_NAME, so a restore brings back both?" y; then
        FILES_PATHS="$FILES_PATHS$_path
"
      fi
    done 4<"$TMP/files-found"
    if [ "$_asked" = 0 ] && [ ! -s "$TMP/files-have" ]; then
      say ""
      note "Does your app store uploads (CVs, photos) on this server? Back that folder up with"
      note "$FILES_DB_NAME, so a restore brings back both: add it in the dashboard (Rewind, then"
      note "Files), or run this installer again with --files /path/to/uploads."
    fi
  fi
  printf '%s' "$FILES_PATHS" | while IFS= read -r _path; do
    [ -z "$_path" ] || grep -qxF -- "$_path" "$TMP/files-have" || printf '%s\n' "$_path"
  done >"$TMP/files-todo"
  while IFS= read -r _path <&4; do
    files_protect "$_path"
  done 4<"$TMP/files-todo"
  if [ -n "$FILES_PROTECTED" ]; then
    note "Files are encrypted on this server with a key derived from your backup passphrase: the same passphrase restores them."
  fi
  files_access
}

# files_access applies --allow-files / --no-allow-files, or asks once on a
# terminal once a folder is protected. A re-run keeps the earlier answer.
files_access() {
  case $ALLOW_FILES in
    yes) allow_files ;;
    no)
      disallow_files
      ok "putting restored files back from Rowsafe is off (restores wait next to the folder)"
      ;;
    *)
      if [ -f "$FILES_ALLOW_FILE" ]; then
        if files_allowed; then allow_files; fi
        return 0
      fi
      [ "$TTY" = 1 ] && [ -n "$FILES_PROTECTED" ] || return 0
      say ""
      if confirm "Allow Rowsafe to put restored files back into these folders (as their owner), and to read folders you add later in the dashboard? Only when someone asks and confirms." y; then
        allow_files
      else
        disallow_files
        note "OK: restored files will wait next to the folder for you (change it with --allow-files)"
      fi
      ;;
  esac
}

allow_files() {
  _roots=$( {
    printf '%s' "$FILES_PROTECTED"
    grep -s '^/' "$FILES_ALLOW_FILE" || true
    printf '%s\n' $FILES_DEFAULT_ROOTS
  } | awk 'NF && !seen[$0]++')
  {
    echo "# Folders Rowsafe may read (to back them up) and put restored files back"
    echo "# into, with everything under them, when someone asks and confirms. The"
    echo "# root helper never touches system or database folders, whatever this says."
    echo "# Written by the installer (root); run it with --no-allow-files to turn"
    echo "# this off."
    printf '%s\n' "$_roots"
  } | write_file "$FILES_ALLOW_FILE" 0644 root:root || true
  install -d -m 0755 -o root -g root "$FILES_DROPIN_DIR"
  _home=''
  printf '%s\n' "$_roots" | grep -q '^/home\(/\|$\)' && _home=no
  {
    echo "# Written by the Rowsafe installer because root allowed Rowsafe to read the"
    echo "# folders in $FILES_ALLOW_FILE and put restored files back there as their"
    echo "# owner (--allow-files). Removed with --no-allow-files."
    echo "[Service]"
    printf '%s\n' "$_roots" | sed 's/^/ReadWritePaths=-/'
    [ -z "$_home" ] || echo "ProtectHome=no"
    echo "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_FOWNER CAP_DAC_READ_SEARCH"
  } | write_file "$FILES_DROPIN" 0644 root:root || true
  have setfacl || apt_install acl
  install_restart_helper
  if systemd_running; then systemctl daemon-reload; fi
  ok "Rowsafe may put restored files back into the folders you protect, as their owner, when someone asks (turn off with --no-allow-files)"
}

disallow_files() {
  rm -f "$FILES_DROPIN"
  rmdir "$FILES_DROPIN_DIR" 2>/dev/null || true
  if [ -d "$CONFIG_DIR" ]; then
    {
      echo "# Reading and restoring folders through Rowsafe's root helper is off."
      echo "# Run the installer with --allow-files to turn it on."
    } | write_file "$FILES_ALLOW_FILE" 0644 root:root || true
  fi
  grep -qs '^[0-9]' "$RESTART_ALLOW_FILE" || grep -qs '^[0-9]' "$CREATED_CLUSTERS_FILE" || remove_restart_helper
  if systemd_running; then systemctl daemon-reload; fi
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

# Where backups go: 'rowsafe' for Rowsafe Storage (nothing to set up: the
# location and short-lived credentials come from Rowsafe, and the
# ROWSAFE_REPO_S3_* settings below are not used), or 'own' for your bucket.
# Backups are encrypted on this server with the passphrase either way.
#ROWSAFE_STORAGE='own'

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
  repo2_template
}

# repo2_template is the second copy's part of agent.env.
repo2_template() {
  cat <<'EOF'

# Second backup copy (optional; `install.sh --add-storage` sets it up): a
# second bucket, ideally at another provider, with its own key and its own
# encryption passphrase (keep it in your password manager too). The same
# optional settings as above exist with ROWSAFE_REPO2_.
#ROWSAFE_REPO2_S3_ENDPOINT=''
#ROWSAFE_REPO2_S3_BUCKET=''
#ROWSAFE_REPO2_S3_REGION='auto'
#ROWSAFE_REPO2_S3_KEY=''
#ROWSAFE_REPO2_S3_KEY_SECRET=''
#ROWSAFE_REPO2_CIPHER_PASS=''
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
    ROWSAFE_REPO_S3_ENDPOINT | ROWSAFE_REPO2_S3_ENDPOINT)
      case $2 in *://*) die "$1 is a host name without a scheme, e.g. <account-id>.eu.r2.cloudflarestorage.com" ;; esac
      ;;
    ROWSAFE_REPO_CIPHER_PASS | ROWSAFE_REPO2_CIPHER_PASS)
      [ "${#2}" -ge 20 ] || die "$1 must be at least 20 characters"
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
  if [ "$SECOND_COPY" = add ] && ! grep -q 'ROWSAFE_REPO2_' "$ENV_FILE"; then repo2_template >>"$ENV_FILE"; fi
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
    if [ "$STORAGE_GUIDED" = 1 ] || [ -n "$SECOND_COPY" ]; then
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
  for key in $(required_repo_vars); do
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
  for key in $(required_repo_vars); do
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
      S_CA=$(s_get "${S_PREFIX:-ROWSAFE_REPO_}S3_CA_FILE")
      S_VERIFY=$(s_get "${S_PREFIX:-ROWSAFE_REPO_}S3_VERIFY_TLS")
      ;;
  esac
  key_hint
}

# ---- Rowsafe Storage (no bucket needed)
#
# Backups go to a bucket Rowsafe operates, in this organization's own
# prefix. The agent gets short-lived credentials for it from Rowsafe; the
# passphrase stays here, so Rowsafe only ever stores ciphertext.

ROWSAFE_REPO_S3_VARS="ROWSAFE_REPO_S3_ENDPOINT ROWSAFE_REPO_S3_BUCKET ROWSAFE_REPO_S3_KEY ROWSAFE_REPO_S3_KEY_SECRET ROWSAFE_REPO_S3_REGION ROWSAFE_REPO_S3_URI_STYLE ROWSAFE_REPO_S3_PORT"
OFFER_FREE=''
GENERATED_PASS=0

# on_rowsafe_storage: backups go (or, set in the environment, will go) to
# Rowsafe Storage.
on_rowsafe_storage() { [ "$(s_get ROWSAFE_STORAGE)" = rowsafe ]; }

# required_repo_vars prints the settings the storage needs.
required_repo_vars() {
  if on_rowsafe_storage; then echo ROWSAFE_REPO_CIPHER_PASS; else echo "$REQUIRED_REPO_VARS"; fi
}

storage_desc() {
  if on_rowsafe_storage; then
    echo "Rowsafe Storage"
  else
    echo "bucket '$(env_value ROWSAFE_REPO_S3_BUCKET)' at $(env_value ROWSAFE_REPO_S3_ENDPOINT)"
  fi
}

# storage_offer succeeds when the control plane offers Rowsafe Storage, and
# sets OFFER_FREE to what the free plan includes (e.g. "10 GB").
storage_offer() {
  _url=$(s_get ROWSAFE_URL)
  [ -n "$_url" ] || _url=https://api.rowsafe.sh
  _o=$(curl -fsS --max-time 5 "${_url%/}/v1/storage/offer" 2>/dev/null) || return 1
  case $_o in *'"available":true'*) ;; *) return 1 ;; esac
  _b=$(printf '%s\n' "$_o" | sed -n 's/.*"free_bytes":\([0-9][0-9]*\).*/\1/p')
  OFFER_FREE=''
  [ -z "$_b" ] || OFFER_FREE="$((_b / 1000000000)) GB free"
  return 0
}

# rowsafe_storage_ask: "where should backups go?", into S_WHERE.
rowsafe_storage_ask() {
  tty_say ""
  tty_say "${BOLD}Where should backups go?${RESET}"
  tty_say "  1) Rowsafe Storage     nothing to set up${OFFER_FREE:+ ($OFFER_FREE)}"
  tty_say "  2) Your own bucket     Cloudflare R2, Amazon S3, Backblaze B2, ..."
  tty_hint "Either way, backups are encrypted on this server first: Rowsafe can't read them."
  _w=1
  choose _w "Choose 1-2" 1 2
  S_WHERE=rowsafe
  [ "$_w" = 1 ] || S_WHERE=own
}

# rowsafe_storage_env saves Rowsafe Storage with the passphrase S_CIPHER,
# and turns the bucket settings back into comments.
rowsafe_storage_env() {
  ROWSAFE_STORAGE=rowsafe ROWSAFE_REPO_CIPHER_PASS=$S_CIPHER
  export ROWSAFE_STORAGE ROWSAFE_REPO_CIPHER_PASS
  for key in $ROWSAFE_REPO_S3_VARS; do
    unset "$key"
    STORAGE_CLEAR="$STORAGE_CLEAR $key"
  done
  STORAGE_GUIDED=1
}

rowsafe_storage_guided() {
  tty_say ""
  tty_say "Backups go to Rowsafe Storage. Nothing to set up: Rowsafe gives this server"
  tty_say "short-lived access to your organization's space and renews it by itself."
  choose_passphrase
  rowsafe_storage_env
  ok "backups go to Rowsafe Storage, encrypted with your passphrase"
}

# rowsafe_storage_unattended (--storage rowsafe, no terminal): the
# passphrase from the environment or agent.env, else a new one kept in
# agent.env (rowsafe_storage_passphrase_note says where).
rowsafe_storage_unattended() {
  if storage_configured && on_rowsafe_storage; then
    ok "backup storage: Rowsafe Storage"
    return 0
  fi
  S_CIPHER=$(s_get ROWSAFE_REPO_CIPHER_PASS)
  if [ -z "$S_CIPHER" ]; then
    S_CIPHER=$(gen_passphrase)
    [ "${#S_CIPHER}" = 40 ] || die "could not generate a passphrase"
    GENERATED_PASS=1
  fi
  rowsafe_storage_env
}

rowsafe_storage_passphrase_note() {
  [ "$GENERATED_PASS" = 1 ] || return 0
  say ""
  warn "a backup encryption passphrase was generated and saved as ROWSAFE_REPO_CIPHER_PASS in $ENV_FILE."
  say "    Copy it into your password manager now: without it, backups can't be restored,"
  say "    and Rowsafe can't recover it. Show it with: sudo grep CIPHER_PASS $ENV_FILE"
}

# rowsafe_storage_test runs the agent's storage test once it is enrolled.
rowsafe_storage_test() {
  say ""
  step "Testing Rowsafe Storage"
  if agent_show storage test --wait 60s; then
    return 0
  fi
  warn "Rowsafe Storage didn't work yet (see above). The agent keeps trying; test again with --check-storage"
}

# gen_passphrase prints 40 letters and digits (~238 bits): no symbols, so a
# double-click copies it whole.
gen_passphrase() {
  head -c 1024 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' 2>/dev/null | head -c 40
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
  S_CA=$(s_get "${S_PREFIX:-ROWSAFE_REPO_}S3_CA_FILE")
  S_VERIFY=$(s_get "${S_PREFIX:-ROWSAFE_REPO_}S3_VERIFY_TLS")
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
  box "Your ${PASS_WHAT:-backup} encryption passphrase:"
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
  current=$(env_value "${PASS_KEY:-ROWSAFE_REPO_CIPHER_PASS}")
  if [ -n "$current" ]; then
    tty_say ""
    tty_say "This server already has a ${PASS_WHAT:-backup} encryption passphrase. Keep it unless"
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
    S_CIPHER=$(gen_passphrase)
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
  # --storage rowsafe needs no questions without a terminal, or with the
  # passphrase in the environment (automation).
  if [ "$STORAGE_PROVIDER" = rowsafe ] && { [ "$TTY" = 0 ] || [ -n "${ROWSAFE_REPO_CIPHER_PASS:-}" ]; }; then
    rowsafe_storage_unattended
    return 0
  fi
  [ "$TTY" = 1 ] || return 0
  if [ "$SETUP_STORAGE" = 0 ]; then
    for key in $REQUIRED_REPO_VARS; do
      eval "v=\${$key:-}"
      [ -z "$v" ] || return 0
    done
    if storage_configured; then
      ok "backup storage: $(storage_desc) (change it with --setup-storage)"
      return 0
    fi
  fi
  guided_storage
}

guided_storage() {
  say ""
  step "Backup storage"
  # Rowsafe Storage (rowsafe_storage_* below): offered when the control
  # plane has it, or asked for with --storage rowsafe.
  S_WHERE=own
  _offered=0
  if [ "$STORAGE_PROVIDER" = rowsafe ]; then
    S_WHERE=rowsafe
  elif [ -z "$STORAGE_PROVIDER" ] && ! on_rowsafe_storage && storage_offer; then
    _offered=1
  fi
  if storage_configured && on_rowsafe_storage; then
    tty_say "Backups go to Rowsafe Storage."
    if [ "$S_WHERE" = rowsafe ] || ! confirm "Move them to your own bucket?" n; then
      ok "kept Rowsafe Storage"
      return 0
    fi
    tty_hint "Rowsafe takes a new full backup in your bucket right away, and restores"
    tty_hint "start from it. The backups in Rowsafe Storage are deleted after 30 days."
  elif storage_configured; then
    tty_say "Backups go to bucket '$(env_value ROWSAFE_REPO_S3_BUCKET)' at $(env_value ROWSAFE_REPO_S3_ENDPOINT)."
    if ! confirm "Replace these storage settings?" n; then
      ok "kept the current storage settings"
      return 0
    fi
    tty_hint "Existing backups stay where they are; new ones go to the new storage."
    [ "$_offered" = 0 ] || rowsafe_storage_ask
  else
    [ "$_offered" = 0 ] || rowsafe_storage_ask
    if [ "$S_WHERE" = own ]; then
      tty_say "Rowsafe keeps your backups in a storage bucket that you own. You need an"
      tty_say "empty bucket and an access key that can read, write and delete in it."
    fi
  fi
  if [ "$S_WHERE" = rowsafe ]; then
    rowsafe_storage_guided
    return 0
  fi
  load_storage_path
  storage_questions
  choose_passphrase
  STORAGE_GUIDED=1

  ROWSAFE_REPO_S3_ENDPOINT=$S_ENDPOINT ROWSAFE_REPO_S3_BUCKET=$S_BUCKET
  ROWSAFE_REPO_S3_KEY=$S_KEY ROWSAFE_REPO_S3_KEY_SECRET=$S_SECRET ROWSAFE_REPO_CIPHER_PASS=$S_CIPHER
  ROWSAFE_REPO_S3_REGION=$S_REGION ROWSAFE_REPO_S3_URI_STYLE=$S_URI
  export ROWSAFE_REPO_S3_ENDPOINT ROWSAFE_REPO_S3_BUCKET ROWSAFE_REPO_S3_KEY ROWSAFE_REPO_S3_KEY_SECRET \
    ROWSAFE_REPO_CIPHER_PASS ROWSAFE_REPO_S3_REGION ROWSAFE_REPO_S3_URI_STYLE
  # Settings from a previous provider must not linger in agent.env.
  unset ROWSAFE_STORAGE
  STORAGE_CLEAR="$STORAGE_CLEAR ROWSAFE_STORAGE"
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

# storage_questions asks for a bucket and its key until the test passes (or
# the person saves failing settings on purpose), into S_*. With S_AVOID set
# to "<endpoint>/<bucket>", that bucket is refused (the second copy must not
# go to the first storage's bucket).
storage_questions() {
  S_ENDPOINT='' S_BUCKET='' S_KEY='' S_SECRET='' S_REGION='' S_URI='' S_PORT='' S_CA='' S_VERIFY='' S_CIPHER=''
  S_URL='' S_MODE=url
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
    if [ -n "${S_AVOID:-}" ] && [ "$S_ENDPOINT/$S_BUCKET" = "$S_AVOID" ]; then
      tty_bad "That is the bucket your backups already go to. The second copy needs another bucket, ideally at another provider."
      S_MODE=url
      continue
    fi
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
}

# check_storage (--check-storage) tests the configured repository and
# changes nothing.
check_storage() {
  require_root
  [ -f "$ENV_FILE" ] || die "$ENV_FILE doesn't exist yet; install the agent first"
  if on_rowsafe_storage; then
    [ -f "$STATE_DIR/agent.json" ] || die "the agent has not connected to Rowsafe yet, so Rowsafe Storage can't be tested"
    step "Testing Rowsafe Storage"
    agent_show storage test --wait 30s || die "the Rowsafe Storage test failed; nothing was changed"
    return 0
  fi
  load_storage
  missing=''
  for key in $REQUIRED_REPO_VARS; do
    [ "$key" = ROWSAFE_REPO_CIPHER_PASS ] && continue
    [ -n "$(s_get "$key")" ] || missing="$missing $key"
  done
  [ -z "$missing" ] || die "the backup storage is not configured; missing:$missing"
  step "Testing the backup storage"
  storage_test || die "the backup storage test failed; nothing was changed"
  if second_configured; then
    load_second
    step "Testing the second copy's storage"
    storage_test || die "the second copy's storage test failed; nothing was changed"
  fi
}

# ---------------------------------------------------------------- second copy (--add-storage)
# A second bucket (ideally at another provider) that gets the backups and the
# change log too. Its settings are ROWSAFE_REPO2_* in agent.env; the agent
# does the rest (it sets up the second storage and switches archive_command,
# with a reload, no restart), and the control plane schedules its backups.

second_configured() {
  for key in $REPO2_VARS; do
    [ -n "$(env_value "$key")" ] || return 1
  done
}

# load_second reads the second copy's settings into S_* (the environment
# taking precedence over agent.env).
load_second() {
  S_ENDPOINT=$(s_get ROWSAFE_REPO2_S3_ENDPOINT)
  S_BUCKET=$(s_get ROWSAFE_REPO2_S3_BUCKET)
  S_KEY=$(s_get ROWSAFE_REPO2_S3_KEY)
  S_SECRET=$(s_get ROWSAFE_REPO2_S3_KEY_SECRET)
  S_CIPHER=$(s_get ROWSAFE_REPO2_CIPHER_PASS)
  S_REGION=$(s_get ROWSAFE_REPO2_S3_REGION)
  S_URI=$(s_get ROWSAFE_REPO2_S3_URI_STYLE)
  S_PORT=$(s_get ROWSAFE_REPO2_S3_PORT)
  S_CA=$(s_get ROWSAFE_REPO2_S3_CA_FILE)
  S_VERIFY=$(s_get ROWSAFE_REPO2_S3_VERIFY_TLS)
  _p=$(s_get ROWSAFE_REPO2_PATH_PREFIX)
  [ -n "$_p" ] || _p=/rowsafe
  _p=$(printf '%s\n' "$_p" | sed -e 's|^/*||' -e 's|/*$||')
  S_PATH=/$_p
}

# second_copy runs before write_env: --add-storage asks for (or, without a
# terminal, tests) the second storage; --remove-second-copy turns it off.
second_copy() {
  case $SECOND_COPY in
    add) ;;
    remove)
      if ! second_configured; then
        ok "no second copy is set up on this server"
        return 0
      fi
      for key in $REPO2_VARS $REPO2_OPT_VARS; do unset "$key"; done
      STORAGE_CLEAR="$STORAGE_CLEAR $REPO2_VARS $REPO2_OPT_VARS"
      return 0
      ;;
    *) return 0 ;;
  esac
  storage_configured || die "set up the first backup storage first: run the installer without --add-storage"
  first="$(env_value ROWSAFE_REPO_S3_ENDPOINT)/$(env_value ROWSAFE_REPO_S3_BUCKET)"
  if [ "$TTY" = 0 ]; then
    # Automation: the settings come from the environment.
    missing=''
    for key in $REPO2_VARS; do
      [ -n "$(s_get "$key")" ] || missing="$missing $key"
    done
    [ -z "$missing" ] || die "--add-storage without a terminal needs these in the environment:$missing"
    load_second
    [ "$S_ENDPOINT/$S_BUCKET" != "$first" ] || die "the second copy must go to another bucket than the first storage ($S_BUCKET)"
    step "Testing the second copy's storage"
    storage_test || die "the second copy's storage test failed; nothing was saved"
    return 0
  fi
  say ""
  step "Second backup copy"
  tty_say "A second copy keeps your backups and the change log in a second bucket too,"
  tty_say "ideally at another provider: if one bucket, account or provider is ever lost,"
  tty_say "the other still has everything. PostgreSQL never waits for it. Its key and"
  tty_say "its own encryption passphrase stay on this server, like the first ones."
  tty_say ""
  tty_say "Your backups go to bucket '$(env_value ROWSAFE_REPO_S3_BUCKET)' at $(env_value ROWSAFE_REPO_S3_ENDPOINT)."
  if second_configured; then
    tty_say "The second copy goes to bucket '$(env_value ROWSAFE_REPO2_S3_BUCKET)' at $(env_value ROWSAFE_REPO2_S3_ENDPOINT)."
    if ! confirm "Move the second copy to another bucket?" n; then
      ok "kept the second copy's settings"
      SECOND_COPY=''
      return 0
    fi
    tty_hint "What is in the old bucket stays there; new backups go to the new one."
  fi
  tty_hint "Tip: a bucket at another provider than the first one protects you best."
  S_AVOID=$first S_PREFIX=ROWSAFE_REPO2_
  _pp=$(s_get ROWSAFE_REPO2_PATH_PREFIX)
  [ -n "$_pp" ] || _pp=/rowsafe
  S_PATH=/$(printf '%s\n' "$_pp" | sed -e 's|^/*||' -e 's|/*$||')
  storage_questions
  S_AVOID='' S_PREFIX=''
  PASS_KEY=ROWSAFE_REPO2_CIPHER_PASS PASS_WHAT="second copy"
  choose_passphrase
  tty_hint "This passphrase is not the first storage's: keep both in your password manager."
  PASS_KEY='' PASS_WHAT=''

  ROWSAFE_REPO2_S3_ENDPOINT=$S_ENDPOINT ROWSAFE_REPO2_S3_BUCKET=$S_BUCKET
  ROWSAFE_REPO2_S3_KEY=$S_KEY ROWSAFE_REPO2_S3_KEY_SECRET=$S_SECRET ROWSAFE_REPO2_CIPHER_PASS=$S_CIPHER
  ROWSAFE_REPO2_S3_REGION=$S_REGION ROWSAFE_REPO2_S3_URI_STYLE=$S_URI
  export ROWSAFE_REPO2_S3_ENDPOINT ROWSAFE_REPO2_S3_BUCKET ROWSAFE_REPO2_S3_KEY ROWSAFE_REPO2_S3_KEY_SECRET \
    ROWSAFE_REPO2_CIPHER_PASS ROWSAFE_REPO2_S3_REGION ROWSAFE_REPO2_S3_URI_STYLE
  if [ -n "$S_PORT" ]; then
    ROWSAFE_REPO2_S3_PORT=$S_PORT
    export ROWSAFE_REPO2_S3_PORT
  else
    unset ROWSAFE_REPO2_S3_PORT
    STORAGE_CLEAR="$STORAGE_CLEAR ROWSAFE_REPO2_S3_PORT"
  fi
  if [ "$S_PROVIDER" != s3-compatible ]; then
    unset ROWSAFE_REPO2_S3_CA_FILE ROWSAFE_REPO2_S3_VERIFY_TLS
    STORAGE_CLEAR="$STORAGE_CLEAR ROWSAFE_REPO2_S3_CA_FILE ROWSAFE_REPO2_S3_VERIFY_TLS"
  fi
}

# second_copy_done runs once the agent restarted with the new settings: it
# waits for the agent to set up the second copy for each database with
# backups on, and says what happens next.
second_copy_done() {
  say ""
  if [ "$SECOND_COPY" = remove ]; then
    say "${BOLD}${GREEN}${CHECK} The second copy is off.${RESET} New backups and the change log go only to the first storage."
    say "    What is already in the second bucket stays there: delete it at your provider"
    say "    once you no longer need it."
    return 0
  fi
  stanzas=''
  for f in "$CONFIG_DIR"/pgbackrest/*.conf; do
    case $f in *.copy2.conf | *'*'*) continue ;; esac
    stanzas="$stanzas $(basename "$f" .conf)"
  done
  if [ -z "$stanzas" ]; then
    say "${BOLD}${GREEN}${CHECK} Second copy saved.${RESET} It starts with the first database you turn backups on for."
    return 0
  fi
  if ! agent_running; then
    say "${BOLD}Second copy saved.${RESET} The agent isn't running, so it starts once the agent does."
    return 0
  fi
  step "Turning on the second copy"
  note "the agent sets it up for:$stanzas"
  i=0
  while :; do
    waiting=''
    for st in $stanzas; do
      [ -f "$CONFIG_DIR/pgbackrest/$st.copy2.conf" ] && [ -d "$STATE_DIR/copy2-queue/$st" ] || waiting="$waiting $st"
    done
    [ -n "$waiting" ] || break
    i=$((i + 1))
    if [ "$i" -gt 45 ]; then
      warn "the agent hasn't set up the second copy for$waiting yet; it keeps trying (see journalctl -u rowsafe-agent)"
      break
    fi
    sleep 2
  done
  [ -n "$waiting" ] || ok "the second copy is set up; PostgreSQL's change log now goes to both storages (reloaded, no restart)"
  say ""
  say "${BOLD}${GREEN}${CHECK} Second copy on.${RESET} Rowsafe takes a first full backup into it now, then one every week."
  say "    If the second storage is ever unreachable, PostgreSQL carries on, backups keep"
  say "    going to the first storage, and Rowsafe alerts you. The dashboard shows both"
  say "    storages, how far the copy is, and what each costs."
}
# ---- end second copy

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
  runuser -u "$AGENT_USER" -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$AGENT_HOME" \
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
C_PORT='' C_SOCK='' C_MAJOR='' C_CLUSTER='' C_NAME='' C_REG='' C_STATUS='' C_DBS='' C_SIZE='' C_UNIT='' C_ID='' C_ENGINE=postgresql

# read_cluster LINE splits a discover line (no field is empty: "-" stands
# for nothing, so tabs never collapse).
read_cluster() {
  _f() { printf '%s\n' "$1" | cut -f"$2"; }
  C_PORT=$(_f "$1" 1) C_SOCK=$(_f "$1" 2) C_MAJOR=$(_f "$1" 3) C_CLUSTER=$(_f "$1" 4)
  C_NAME=$(_f "$1" 7) C_REG=$(_f "$1" 8) C_STATUS=$(_f "$1" 9) C_DBS=$(_f "$1" 10)
  C_SIZE=$(_f "$1" 11) C_UNIT=$(_f "$1" 12) C_ID=$(_f "$1" 13) C_ENGINE=$(_f "$1" 14)
  [ "$C_ID" != - ] || C_ID=''
  [ -n "$C_ENGINE" ] && [ "$C_ENGINE" != - ] || C_ENGINE=postgresql
}

cluster_desc() {
  _d=$C_DBS
  [ "$_d" != - ] || _d=none
  printf '%s %s on port %s (%s; databases: %s)' "$(engine_label "$C_ENGINE")" "$C_MAJOR" "$C_PORT" "$C_SIZE" "$(printf '%s' "$_d" | sed 's/,/, /g')"
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
  say "    OK. Restart $(engine_label "$C_ENGINE") when it suits you:"
  say "        $(restart_cmd)"
  if restart_allowed "$C_PORT"; then
    say "    (or with Restart in the Rowsafe dashboard)."
  fi
  say "    Rowsafe notices the restart by itself and finishes setting up. Nothing else to do."
}

# restart_postgres restarts the cluster, because the person said yes.
restart_postgres() {
  step "Restarting $(engine_label "$C_ENGINE") $C_MAJOR"
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
  ok "$(engine_label "$C_ENGINE") restarted"
}

offer_restart() {
  say ""
  tty_say "$(engine_label "$C_ENGINE") needs a quick restart for backups to start. It takes a few"
  tty_say "seconds; open connections are dropped and apps reconnect."
  if confirm "Restart $(engine_label "$C_ENGINE") now?" n; then
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
  mysql_account || return 1 # mysql
  _sock=''
  [ "$C_SOCK" = - ] || _sock=$C_SOCK
  agent_show setup plan --name "$C_NAME" --port "$C_PORT" ${_sock:+--socket-dir "$_sock"} --id-file "$TMP/setup/id" --engine "$C_ENGINE" || _rc=$?
  C_ID=$(cat "$TMP/setup/id" 2>/dev/null || true)
  return "$_rc"
}

# protect_cluster (interactive): plan, "Turn on backups?", apply, restart.
protect_cluster() {
  if [ "$C_ENGINE" = mongodb ] && ! mongodb_prepare; then
    note "Backups for $C_NAME are not on yet. Run this installer again when you're ready."
    return 0
  fi
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
    if { [ "$C_ENGINE" = mysql ] || [ "$C_ENGINE" = mariadb ]; } && [ "$AGENT_USER" != mysql ]; then # mysql
      note "Found $(cluster_desc): Rowsafe protects $(engine_label "$C_ENGINE") on servers without PostgreSQL for now; skipped."
      continue
    fi
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
        note "Found $(cluster_desc): backups for $C_NAME wait for a restart."
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
  if [ "$C_ENGINE" = mongodb ]; then
    mongodb_prepare 1 || die "MongoDB on port $C_PORT isn't ready for backups (see above)"
  fi
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
  [ "$ALLOW_FIREWALL" != no ] || disallow_firewall
  [ "$ALLOW_POOLER" != no ] || disallow_pooler
  if [ ! -f "$STATE_DIR/agent.json" ] || ! agent_running; then
    [ -z "$PROTECT_NAME" ] || die "the agent is not running, so backups can't be turned on yet; see 'journalctl -u rowsafe-agent'"
    [ "$ALLOW_RESTART" != yes ] || warn "the agent is not running; run the installer again with --allow-restart once it is"
    [ "$ALLOW_FIREWALL" != yes ] || warn "the agent is not running; run the installer again with --allow-firewall once it is"
    [ "$ALLOW_POOLER" != yes ] || warn "the agent is not running; run the installer again with --allow-pooler once it is"
    next_steps not-running
    return 0
  fi
  if on_rowsafe_storage; then rowsafe_storage_test; fi
  interactive=0
  if [ "$TTY" = 1 ] && [ "$NO_SETUP" = 0 ]; then interactive=1; fi
  if [ "$interactive" = 1 ] || [ -n "$PROTECT_NAME" ] || [ "$ALLOW_RESTART" = yes ] || grep -qs '^[0-9]' "$RESTART_ALLOW_FILE" ||
    [ -n "$ALLOW_UPDATES$ALLOW_SECURITY$ALLOW_REBOOT" ] || [ "$ALLOW_FIREWALL" = yes ] || grep -qs '^[0-9]' "$FIREWALL_ALLOW_FILE" ||
    [ "$ALLOW_POOLER" = yes ] || grep -qs '^[0-9]' "$POOLER_ALLOW_FILE"; then
    say ""
    step "Looking for $(engine_label) on this server"
    if ! discover; then
      [ -z "$PROTECT_NAME" ] || die "could not look for PostgreSQL (see above)"
      next_steps
      return 0
    fi
    restart_access
    [ -n "$ALLOW_CREATE_CLUSTER" ] || create_cluster_access # forks
    update_access
    firewall_access
    pooler_access
  fi
  if [ -n "$PROTECT_NAME" ]; then
    protect_unattended
  elif [ "$interactive" = 1 ]; then
    setup_databases
  else
    next_steps
  fi
  files_setup # files section
}

# ---------------------------------------------------------------- MongoDB
#
# MongoDB servers are found by `rowsafe-agent setup discover` like
# PostgreSQL clusters (engine column "mongodb"). Before their plan, the
# installer makes sure of three things, asking first:
#   - the MongoDB Database Tools (mongodump, mongorestore) are installed,
#     from MongoDB's own apt repository, whose signing key is checked
#     against the fingerprint below;
#   - the server is a replica set (a single member is enough): restoring to
#     any second needs its oplog. A standalone server is converted with
#     replication.replSetName (and a keyFile when access control is on) in
#     its config file and one restart, then replSetInitiate;
#   - Rowsafe has its own MongoDB user ("rowsafe", random password saved for
#     the agent only). Where access control is on, an administrator signs in
#     once for that; the password is never stored.

# MongoDB 8.0 release signing key (pgp.mongodb.com/server-8.0.asc).
MONGODB_KEY_URL=https://pgp.mongodb.com/server-8.0.asc
MONGODB_KEY_FPR=4B0752C1BCA238C0B4EE14DC41DE058A4E7DCA05
MONGODB_KEYRING=/usr/share/keyrings/mongodb-server-8.0.asc
MONGODB_LIST=/etc/apt/sources.list.d/mongodb-org-8.0.list
MONGODB_KEYFILE=/etc/mongodb-rowsafe.key

mongodb_present() {
  have mongod || [ -x /usr/bin/mongod ] || { have pgrep && pgrep -x mongod >/dev/null 2>&1; }
}

# use_rowsafe_user: a server without PostgreSQL runs the agent as its own
# system user, rowsafe.
use_rowsafe_user() {
  AGENT_USER=rowsafe
  if ! id -u rowsafe >/dev/null 2>&1; then
    step "Creating the system user rowsafe for the agent"
    useradd --system --user-group --home-dir "$STATE_DIR" --no-create-home --shell /usr/sbin/nologin rowsafe ||
      die "could not create the rowsafe user"
  fi
}

# ensure_mongodb_tools installs mongodump and mongorestore when MongoDB runs
# here without them.
ensure_mongodb_tools() {
  mongodb_present || return 0
  if have mongodump && have mongorestore; then
    ok "MongoDB Database Tools at $(command -v mongodump)"
    return 0
  fi
  step "Installing the MongoDB Database Tools (mongodump, mongorestore) from MongoDB's repository"
  if ! grep -Eqs 'repo\.mongodb\.org' /etc/apt/sources.list /etc/apt/sources.list.d/*; then
    have gpg || apt_install gnupg
    fetch "$MONGODB_KEY_URL" "$TMP/mongodb.asc" || die "could not download MongoDB's signing key from $MONGODB_KEY_URL"
    fpr=$(gpg --show-keys --with-colons "$TMP/mongodb.asc" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')
    [ "$fpr" = "$MONGODB_KEY_FPR" ] ||
      die "MongoDB's signing key has an unexpected fingerprint (${fpr:-none}); not adding its repository"
    install -m 0644 -o root -g root "$TMP/mongodb.asc" "$MONGODB_KEYRING"
    # shellcheck disable=SC1091
    codename=$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")
    case $OS_ID in
      ubuntu) line="deb [ arch=amd64,arm64 signed-by=$MONGODB_KEYRING ] https://repo.mongodb.org/apt/ubuntu $codename/mongodb-org/8.0 multiverse" ;;
      # MongoDB publishes bookworm packages; the tools run on newer Debian too.
      *) line="deb [ signed-by=$MONGODB_KEYRING ] https://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" ;;
    esac
    printf '%s\n' "$line" | write_file "$MONGODB_LIST" 0644 root:root || true
    APT_UPDATED=0
  fi
  apt_install mongodb-database-tools
  ok "MongoDB Database Tools installed"
}

# agent_in ARGS...: agent_run with the caller's stdin (a password, one line).
agent_in() {
  # shellcheck disable=SC2016 # $1 expands in the inner shell
  runuser -u "$AGENT_USER" -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$STATE_DIR" \
    LANG="${LANG:-C}" LC_ALL="${LC_ALL:-}" \
    sh -c 'set -a; . "$1"; set +a; shift; exec "$@"' rowsafe-setup "$ENV_FILE" "$INSTALL_DIR/rowsafe-agent" "$@"
}

# mongodb_status reads `rowsafe-agent mongodb status` into M_* variables.
M_REPLSET='' M_AUTH='' M_LOGIN='' M_CONFIG='' M_DBPATH='' M_UNIT=''
mongodb_status() {
  agent_run mongodb status --port "$C_PORT" >"$TMP/mstatus" 2>"$TMP/mstatus.err" || return 1
  _m() { sed -n "s/^$1=//p" "$TMP/mstatus" | head -n 1; }
  M_REPLSET=$(_m replset) M_AUTH=$(_m auth) M_LOGIN=$(_m login) M_CONFIG=$(_m config)
  M_DBPATH=$(_m dbpath) M_UNIT=$(_m unit)
  [ "$M_UNIT" != - ] || M_UNIT=''
  [ -n "$M_UNIT" ] || { systemd_running && systemctl is-active --quiet mongod.service && M_UNIT=mongod.service; } || true
}

# mongodb_admin asks for (or takes from the environment) an administrator's
# login, into M_ADMIN and M_ADMIN_PW. Never stored.
M_ADMIN='' M_ADMIN_PW=''
mongodb_admin() {
  [ -z "$M_ADMIN" ] || return 0
  if [ -n "${ROWSAFE_MONGODB_ADMIN_USER:-}" ]; then
    M_ADMIN=$ROWSAFE_MONGODB_ADMIN_USER M_ADMIN_PW=${ROWSAFE_MONGODB_ADMIN_PASSWORD:-}
    return 0
  fi
  [ "$TTY" = 1 ] || return 1
  tty_say ""
  tty_say "MongoDB has access control on. To create Rowsafe's own user, an administrator"
  tty_say "signs in once (a user with the root or userAdminAnyDatabase role). The password"
  tty_say "is used for this only and never saved."
  ask M_ADMIN "MongoDB administrator user" admin
  ask_secret M_ADMIN_PW "Password for $M_ADMIN"
}

# mongodb_as_admin CMD...: run an agent mongodb command, as an administrator
# when needed. Its exit status is the command's.
mongodb_as_admin() {
  if [ -n "$M_ADMIN" ]; then
    printf '%s\n' "$M_ADMIN_PW" | agent_in mongodb "$@" --port "$C_PORT" --admin-user "$M_ADMIN"
  else
    agent_run mongodb "$@" --port "$C_PORT"
  fi
}

# mongodb_login creates Rowsafe's MongoDB user.
mongodb_login() {
  [ "$M_LOGIN" = ok ] && return 0
  _rc=0
  mongodb_as_admin login >"$TMP/mlogin" 2>&1 || _rc=$?
  while [ "$_rc" = 11 ] || [ "$_rc" = 12 ]; do
    [ "$_rc" = 12 ] && { tty_bad "MongoDB refused that login."; M_ADMIN=''; }
    [ "$_rc" = 11 ] && [ -n "$M_ADMIN" ] && { tty_bad "That user can't create users."; M_ADMIN=''; }
    mongodb_admin || { warn "MongoDB has access control on: set ROWSAFE_MONGODB_ADMIN_USER and ROWSAFE_MONGODB_ADMIN_PASSWORD (used once, never saved), or run the installer on a terminal"; return 1; }
    [ -n "${ROWSAFE_MONGODB_ADMIN_USER:-}" ] && [ "$_rc" = 12 ] && return 1
    _rc=0
    mongodb_as_admin login >"$TMP/mlogin" 2>&1 || _rc=$?
  done
  sed 's/^/    /' "$TMP/mlogin"
  [ "$_rc" = 0 ]
}

# mongodb_set_yaml FILE SECTION KEY VALUE sets section.key in a mongod
# config file (two-space indent, as MongoDB's packages write it).
mongodb_set_yaml() {
  if grep -Eq "^$2:[[:space:]]*$" "$1"; then
    awk -v s="$2" -v k="$3" -v v="$4" '
      { print }
      $0 ~ "^" s ":[[:space:]]*$" { print "  " k ": " v }' "$1" >"$TMP/mconf" && cat "$TMP/mconf" >"$1"
  else
    printf '\n%s:\n  %s: %s\n' "$2" "$3" "$4" >>"$1"
  fi
}

# mongodb_replset converts a standalone server into a single-member
# replica set: config file, keyFile when access control is on, restart,
# replSetInitiate.
mongodb_replset() {
  if [ -z "$M_CONFIG" ] || [ "$M_CONFIG" = - ] || [ ! -f "$M_CONFIG" ] || [ -z "$M_UNIT" ]; then
    warn "MongoDB on port $C_PORT isn't started from a config file by a systemd unit the installer knows, so it can't turn on the replica set for you"
    note "Do it yourself: add 'replication: {replSetName: rs0}' to its configuration, restart it,"
    note "run rs.initiate() in mongosh, then run this installer again."
    return 1
  fi
  if grep -Eq '^[[:space:]]+replSetName:' "$M_CONFIG"; then
    note "$M_CONFIG already names a replica set; restarting MongoDB would start it"
  else
    cp -p "$M_CONFIG" "$M_CONFIG.rowsafe-backup"
    mongodb_set_yaml "$M_CONFIG" replication replSetName rs0
    if [ "$M_AUTH" = on ] && ! grep -Eq '^[[:space:]]+keyFile:' "$M_CONFIG"; then
      owner=$(stat -c %U "${M_DBPATH:-/var/lib/mongodb}" 2>/dev/null || echo mongodb)
      openssl rand -base64 756 >"$TMP/keyfile"
      install -m 0400 -o "$owner" -g "$owner" "$TMP/keyfile" "$MONGODB_KEYFILE"
      mongodb_set_yaml "$M_CONFIG" security keyFile "$MONGODB_KEYFILE"
      ok "created $MONGODB_KEYFILE (replica set members use it to trust each other)"
    fi
    ok "$M_CONFIG: replication.replSetName rs0 (the previous file is $M_CONFIG.rowsafe-backup)"
  fi
  step "Restarting MongoDB ($M_UNIT)"
  if ! timeout 180 systemctl restart "$M_UNIT" >"$TMP/mrestart" 2>&1 </dev/null; then
    tail -n 5 "$TMP/mrestart" | sed 's/^/    /' >&2
    warn "MongoDB didn't start with the replica set; putting the previous configuration back"
    [ ! -f "$M_CONFIG.rowsafe-backup" ] || cp -p "$M_CONFIG.rowsafe-backup" "$M_CONFIG"
    timeout 180 systemctl restart "$M_UNIT" </dev/null || true
    return 1
  fi
  _i=0
  until mongodb_status || [ $_i -ge 60 ]; do sleep 1; _i=$((_i + 1)); done
  _rc=0
  mongodb_as_admin initiate >"$TMP/minit" 2>&1 || _rc=$?
  if [ "$_rc" = 11 ] || [ "$_rc" = 12 ]; then
    mongodb_admin && { _rc=0; mongodb_as_admin initiate >"$TMP/minit" 2>&1 || _rc=$?; }
  fi
  sed 's/^/    /' "$TMP/minit"
  [ "$_rc" = 0 ] || { warn "starting the replica set failed (see above)"; return 1; }
  ok "MongoDB on port $C_PORT is now a single-member replica set"
}

# mongodb_prepare gets a MongoDB server ready for its plan. Interactive
# unless unattended=1 (then it never restarts without --mongodb-replica-set).
mongodb_prepare() {
  _unattended=${1:-0}
  M_ADMIN='' M_ADMIN_PW=''
  if ! mongodb_status; then
    sed 's/^/    /' "$TMP/mstatus.err" >&2
    warn "could not look at MongoDB on port $C_PORT"
    return 1
  fi
  if [ "$M_REPLSET" = - ] || [ -z "$M_REPLSET" ]; then
    say ""
    note "MongoDB on port $C_PORT runs as a standalone server. Restoring to any second needs"
    note "its change log (the oplog), which only a replica set keeps. A replica set of one"
    note "member changes nothing for your apps; it takes one MongoDB restart (a few seconds)."
    case $MONGODB_REPLSET in
      yes) ;;
      no) note "Skipped (--no-mongodb-replica-set)."; return 1 ;;
      *)
        if [ "$_unattended" = 1 ] || [ "$TTY" = 0 ]; then
          note "Run the installer on a terminal, or add --mongodb-replica-set, to turn it on."
          return 1
        fi
        confirm "Turn on the replica set and restart MongoDB now?" n || { note "OK, nothing was changed."; return 1; }
        ;;
    esac
    mongodb_replset || return 1
  fi
  mongodb_login || return 1
}

# ---------------------------------------------------------------- modes

install_agent() {
  require_root
  detect_os
  detect_arch
  detect_host_engine # mysql
  detect_mongodb_host # mongodb
  check_postgres
  say "${BOLD}Rowsafe agent installer${RESET}: backups, restore to any second and weekly"
  say "restore tests for the $(engine_label) on this server. Nothing changes without your yes."
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
  if [ "$HOST_ENGINE" = postgresql ] || [ "$HOST_ENGINE" = mongodb ]; then ensure_pgbackrest; else ensure_mysql_tools; fi # mysql
  ensure_mongodb_tools # mongodb (only where MongoDB runs)
  ensure_restic # files section
  step "Installing into $INSTALL_DIR"
  make_dirs
  [ "$need_binary" = 0 ] || install_binary
  install_guard
  UNIT_CHANGED=0
  install_unit
  mysql_setup # mysql
  mongodb_setup # mongodb
  install_logrotate
  maybe_guided_storage
  second_copy
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
  [ "$HOST_ENGINE" != postgresql ] || probe_postgres
  summary "$SERVICE_STATE"
  rowsafe_storage_passphrase_note
  if [ -n "$SECOND_COPY" ]; then second_copy_done; else databases; fi
}

summary() {
  say ""
  say "${BOLD}Rowsafe agent $REL_VERSION: $1${RESET}"
  say "    binary       $INSTALL_DIR/versions/$REL_VERSION/rowsafe-agent"
  say "    config       $ENV_FILE (postgres, 0600)"
  if [ -n "${TOOLS_SUMMARY:-}" ]; then say "    backups      $TOOLS_SUMMARY"; else say "    pgBackRest   ${PGBR_VERSION:-unknown}"; fi
  ! storage_configured || say "    storage      $(storage_desc)"
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
  rm -f "$FILES_ALLOW_FILE" "$FILES_DROPIN" "$RESTIC_BIN" # files section
  rmdir "$FILES_DROPIN_DIR" 2>/dev/null || true
  remove_pooler_units
  remove_restart_helper
  remove_create_cluster
  remove_firewall_helper
  rm -f "$GUARD_FILE"
  rmdir "$LIB_DIR" 2>/dev/null || true
  if systemd_running; then systemctl daemon-reload; fi
  rm -rf "$INSTALL_DIR"
  ok "service and $INSTALL_DIR removed"
  rm -f "/etc/systemd/system/$SERVICE.d/10-mysql.conf" # mysql
  if [ "$purge" = 1 ]; then
    if [ -L "$MYSQL_CONF_LINK" ]; then # mysql: keep the server's binary log settings
      cp "$CONFIG_DIR/mysql/server.cnf" "$MYSQL_CONF_LINK.rowsafe-new" 2>/dev/null &&
        mv -f "$MYSQL_CONF_LINK.rowsafe-new" "$MYSQL_CONF_LINK" || rm -f "$MYSQL_CONF_LINK"
    fi
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
      --mongodb-replica-set) MONGODB_REPLSET=yes ;;
      --no-mongodb-replica-set) MONGODB_REPLSET=no ;;
      --no-allow-restart) ALLOW_RESTART=no ;;
      --files) # files section
        [ $# -ge 2 ] || die "--files needs a folder's path"
        printf '%s\n' "$2" | grep -Eq '^/[A-Za-z0-9._@+,=/-]+$' || die "--files: give an absolute path (letters, digits and ._@+,=- only)"
        FILES_PATHS="$FILES_PATHS${2%/}
"
        shift
        ;;
      --allow-files) ALLOW_FILES=yes ;;
      --no-allow-files) ALLOW_FILES=no ;;
      --no-files) NO_FILES=1 ;;
      --allow-create-cluster) ALLOW_CREATE_CLUSTER=yes ;;
      --no-allow-create-cluster) ALLOW_CREATE_CLUSTER=no ;;
      --allow-firewall) ALLOW_FIREWALL=yes ;;
      --no-allow-firewall) ALLOW_FIREWALL=no ;;
      --allow-pooler) ALLOW_POOLER=yes ;;
      --no-allow-pooler) ALLOW_POOLER=no ;;
      --allow-pooler-public) ALLOW_POOLER_PUBLIC=1 ;;
      --allow-updates) ALLOW_UPDATES=yes ;;
      --no-allow-updates) ALLOW_UPDATES=no ;;
      --allow-security-updates) ALLOW_SECURITY=yes ;;
      --no-allow-security-updates) ALLOW_SECURITY=no ;;
      --allow-reboot) ALLOW_REBOOT=yes ;;
      --no-allow-reboot) ALLOW_REBOOT=no ;;
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
      --add-storage) SECOND_COPY=add ;;
      --remove-second-copy) SECOND_COPY=remove ;;
      --storage)
        [ $# -ge 2 ] || die "--storage needs a provider: rowsafe $PROVIDERS"
        case " rowsafe $PROVIDERS other minio " in
          *" $2 "*) ;;
          *) die "unknown storage provider '$2' (one of: rowsafe $PROVIDERS)" ;;
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
  if [ "$mode" != install ] && { [ "$SETUP_STORAGE" = 1 ] || [ -n "$STORAGE_PROVIDER" ] || [ -n "$SECOND_COPY" ]; }; then
    die "--setup-storage, --storage, --add-storage and --remove-second-copy only go with an install"
  fi
  # The second copy is its own step: no database questions around it.
  [ -z "$SECOND_COPY" ] || NO_SETUP=1
  if [ "$mode" != install ] && { [ "$NO_SETUP" = 1 ] || [ -n "$PROTECT_NAME" ] || [ -n "$ALLOW_RESTART$ALLOW_UPDATES$ALLOW_SECURITY$ALLOW_REBOOT$ALLOW_FIREWALL$ALLOW_POOLER$ALLOW_CREATE_CLUSTER" ]; }; then
    die "--no-setup, --protect and the --allow- options only go with an install"
  fi
  if [ "$mode" != install ] && { [ -n "$FILES_PATHS" ] || [ -n "$ALLOW_FILES" ] || [ "$NO_FILES" = 1 ]; }; then
    die "--files, --allow-files and --no-files only go with an install"
  fi
  [ -z "$PROTECT_PORT" ] || [ -n "$PROTECT_NAME" ] || die "--protect-port only goes with --protect"
  [ "$NO_SETUP" = 0 ] || [ -z "$PROTECT_NAME" ] || die "--no-setup and --protect contradict each other"
  TMP=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-install.XXXXXX")
  # The agent user writes one file into $TMP/setup (0700, its own).
  chmod 0711 "$TMP"
  if [ "$mode" = install ]; then
    open_tty
    if [ "$TTY" = 0 ] && [ "$STORAGE_PROVIDER" != rowsafe ] && { [ "$SETUP_STORAGE" = 1 ] || [ -n "$STORAGE_PROVIDER" ]; }; then
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
