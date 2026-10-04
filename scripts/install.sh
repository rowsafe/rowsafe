#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Rowsafe agent installer, served at https://rowsafe.sh (and /install)
#
#   curl -fsSL https://rowsafe.sh | sudo sh
#
# prints a link that opens the approval page with its code; approving the
# server there enrolls it. For automation (no terminal), pass a one-time
# enrollment token instead:
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
#   --install-postgres VERSION  on a fresh server: install PostgreSQL VERSION
#                          (13-18) from the PostgreSQL project's repository
#                          (apt.postgresql.org, its signing key checked) and
#                          start it; refuses if PostgreSQL is already installed.
#                          With --protect, that new PostgreSQL is restarted once
#                          if backups need it
#   --listen-public        PostgreSQL listens on every address: TLS on (a
#                          self-signed certificate made here), SCRAM-SHA-256
#                          passwords for logins from the network (hostssl rules
#                          for 0.0.0.0/0 and ::/0; local rules unchanged). Put a
#                          firewall in front: it decides who can connect
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
#   --allow-tuning         allow Rowsafe to change MongoDB's or ClickHouse's settings
#                          when you ask (Tuning), only in its own settings file
#   --no-allow-tuning      turn that off again
#   --allow-sqlite-modes   allow Rowsafe to close the listed SQLite files to the
#                          server's other users when you click Apply fix under
#                          Security (others' access only; owners and ACLs stay)
#   --no-allow-sqlite-modes  turn that off again
#   --firewall-ssh         for servers Rowsafe creates (implies --allow-firewall):
#                          the firewall also limits who can reach SSH, and
#                          PostgreSQL's port is closed to everyone until the
#                          dashboard's allowed addresses arrive;
#                          --no-firewall-ssh gives SSH back to you
#   --allow-updates        allow Rowsafe to install PostgreSQL updates and upgrade
#                          PostgreSQL when you click Update or Upgrade (needs
#                          --allow-restart); --no-allow-updates turns it off
#   --allow-security-updates  allow Rowsafe to install the server's security
#                          updates when you click Install; --no-allow-security-updates
#   --allow-reboot         allow Rowsafe to reboot the server when you click
#                          Reboot (needs --allow-security-updates); --no-allow-reboot
#   --permissions          on a server where Rowsafe is installed, change only
#                          what it may do (--allow-X, --no-allow-X), nothing
#                          else; what `sudo rowsafe-allow NAME` runs
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
# The database units the restart helper acts on (its db_unit_re): Debian's
# PostgreSQL clusters and the MySQL, MariaDB, MongoDB, ClickHouse, Redis and
# Valkey units.
DB_UNIT_RE='^(postgresql@[0-9]+-[A-Za-z0-9_.-]+|mysqld?|mariadb|(mysqld?|mariadb)@[A-Za-z0-9_.-]+|mongod|mongodb|clickhouse-server|(redis|valkey)(-server)?(@[A-Za-z0-9_.-]+)?)[.]service$'
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
# Tuning for MongoDB and ClickHouse (--allow-tuning): root's copy of the
# agent writes the settings into Rowsafe's own files, nothing else.
TUNING_ALLOW_FILE=$CONFIG_DIR/tuning-allowed
TUNING_SERVICE_FILE=/etc/systemd/system/rowsafe-tuning.service
TUNING_PATH_FILE=/etc/systemd/system/rowsafe-tuning.path
TUNING_DIR=$STATE_DIR/tuning
# Closing SQLite files to other users (--allow-sqlite-modes): root's copy of
# the agent changes only others' access to the listed SQLite files.
SQLITE_MODES_ALLOW_FILE=$CONFIG_DIR/sqlite-modes-allowed
SQLITE_MODES_SERVICE_FILE=/etc/systemd/system/rowsafe-sqlite-modes.service
SQLITE_MODES_PATH_FILE=/etc/systemd/system/rowsafe-sqlite-modes.path
SQLITE_MODES_DIR=$STATE_DIR/sqlite-modes

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
# Changing all that later (permissions section): `sudo rowsafe-allow`, which
# runs the installer's --permissions mode from root's verified copy of it.
ALLOW_COMMAND=/usr/local/sbin/rowsafe-allow
INSTALLER_COPY=$LIB_DIR/install.sh
AGENT_USER=postgres
# >>> mysql: a server with MySQL or MariaDB and no PostgreSQL runs the agent
# as the mysql user (detect_host_engine), like postgres on a PostgreSQL one.
HOST_ENGINE=postgresql
PG_MAJORS=''
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
ALLOW_POOLER_PUBLIC='' # --allow-pooler-public (yes) / --no-allow-pooler-public (no): PgBouncer on every address
ALLOW_FIREWALL=''  # --allow-firewall (yes) / --no-allow-firewall (no); '' = ask once, on a terminal
ALLOW_TUNING=''    # --allow-tuning (yes) / --no-allow-tuning (no): MongoDB and ClickHouse settings files
ALLOW_SQLITE_MODES='' # --allow-sqlite-modes (yes) / --no-allow-sqlite-modes (no): close SQLite files to other users
POOLER_TARGET_ADD='' POOLER_TARGET_DEL='' # --allow-pooler-target / --no-allow-pooler-target ADDRESS:PORT (ProxySQL)
FIREWALL_SSH=''    # --firewall-ssh (yes) / --no-firewall-ssh (no): SSH's allow list too (servers Rowsafe creates)
ALLOW_UPDATES=''   # --allow-updates / --no-allow-updates (PostgreSQL updates and upgrades)
ALLOW_SECURITY=''  # --allow-security-updates / --no-allow-security-updates
ALLOW_REBOOT=''    # --allow-reboot / --no-allow-reboot
SETUP_STOP=0       # the plan limit was reached: don't offer more databases
MONGODB_STANDBY='' # --mongodb-standby (yes): Rowsafe may make this MongoDB part of a standby pair
M_CLONES=''        # --mongodb-clones (yes): this (empty) MongoDB may receive clones
CH_CLONES=''       # --clickhouse-clones (yes): this (empty) ClickHouse may receive clones
MYSQL_STANDBY=''   # --mysql-standby (yes) / --no-mysql-standby (no); '' = ask once, on a terminal
MONGODB_REPLSET='' # --mongodb-replica-set (yes) / --no-mongodb-replica-set (no); '' = ask on a terminal
INSTALL_PG=''      # --install-postgres VERSION (servers Rowsafe creates)
LISTEN_PUBLIC=0    # --listen-public
PG_OURS=0          # the PostgreSQL here is the one --install-postgres installed
SQLITE_PATHS=''    # --sqlite PATH, one per line
SQLITE_LIST=$CONFIG_DIR/sqlite-paths # the agent's SQLite files (one per line)
SQLITE_CLONE_DIRS='' # --sqlite-clone-dir DIR, one per line
SQLITE_CLONE_LIST=$CONFIG_DIR/sqlite-clone-dirs # folders SQLite clones may be written to

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

  curl -fsSL https://rowsafe.sh | sudo sh
      prints a link; approve the server in your browser and the install goes on
  curl -fsSL https://rowsafe.sh | sudo sh -s rse_...
      for automation (no terminal): a one-time enrollment token instead

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
  --install-postgres VERSION
                         on a fresh server: install PostgreSQL VERSION (13-18) from the
                         PostgreSQL project's repository (apt.postgresql.org, its signing
                         key checked) and start it. Refuses if PostgreSQL is already
                         installed; a re-run keeps the one it installed. With --protect,
                         that new PostgreSQL is restarted once if backups need it
  --listen-public        make PostgreSQL reachable from the network: it listens on every
                         address, with TLS (a self-signed certificate made on this server)
                         and SCRAM-SHA-256 passwords for every login from the network
                         (local rules stay as they are). Put a firewall in front: it
                         decides who can connect. Restarts PostgreSQL only if it was
                         installed by --install-postgres or you say yes; otherwise the
                         change waits for its next restart
  --sqlite PATH          protect the SQLite database file PATH (repeat for several);
                         with --protect NAME, give exactly one. The installer also finds
                         the SQLite files running apps have open and asks about each
  --sqlite-clone-dir DIR allow Rowsafe to write clones of SQLite databases (new files,
                         never over an existing one) into the folder DIR; repeat for
                         several. The agent gets write access to it (an ACL)
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
  --allow-tuning         allow Rowsafe to change MongoDB's or ClickHouse's settings when
                         you ask under Tuning, only in its own settings file
  --no-allow-tuning      turn that off
  --allow-sqlite-modes   allow Rowsafe to close the listed SQLite files to the server's
                         other users when you click Apply fix under Security (only
                         others' access goes; owners, groups and ACLs stay)
  --no-allow-sqlite-modes  turn that off
  --allow-pooler-target ADDRESS:PORT    let ProxySQL send connections to the MySQL
                         on another server (the primary after a standby's promotion)
  --no-allow-pooler-target ADDRESS:PORT  turn that off
  --firewall-ssh         for servers Rowsafe creates (implies --allow-firewall): the
                         firewall also limits who can reach SSH, and PostgreSQL's port
                         is closed to everyone until the allowed addresses arrive
  --no-firewall-ssh      Rowsafe stops limiting who can reach SSH
  --allow-updates        allow Rowsafe to install PostgreSQL updates and upgrade PostgreSQL
                         when you click Update or Upgrade and confirm (needs --allow-restart)
  --no-allow-updates     turn that off
  --allow-security-updates  allow Rowsafe to install the server's security updates when
                         you click Install and confirm (--no-allow-security-updates: off)
  --allow-reboot         allow Rowsafe to reboot the server when you click Reboot and
                         confirm (needs --allow-security-updates; --no-allow-reboot: off)
  --no-allow-pooler-public  PgBouncer listens on this server's own addresses only
  --permissions          change only what Rowsafe may do on this server, where it is
                         installed: --allow-X and --no-allow-X, nothing else (no
                         download, the agent and backups untouched). Prints what
                         Rowsafe may do. `sudo rowsafe-allow NAME` runs this
  --mysql-standby        MySQL/MariaDB: let Rowsafe set up standby servers with this
                         server (its MySQL account gets administrator rights, used only
                         when someone adds, promotes or removes a standby and confirms);
                         an empty server can then become another server's standby
  --no-mysql-standby     don't
  --mongodb-standby      MongoDB: let Rowsafe set up standby servers with this server:
                         its user gets clusterManager, and root's helper may hand out
                         the replica set's key file and add replSetName, keyFile and
                         an address to mongod.conf (a copy kept); restarts stay the
                         ones a person confirms (needs --allow-restart)
  --mongodb-clones       MongoDB: keep an empty server ready to receive clones of a
                         database from another server (Rowsafe's user there gets the
                         restore and readWriteAnyDatabase roles)
  --clickhouse-clones    ClickHouse: keep an empty server ready to receive clones of a
                         database from another server (Rowsafe's user there may then
                         create and drop databases)
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
  ROWSAFE_CLICKHOUSE_ADMIN_USER, ROWSAFE_CLICKHOUSE_ADMIN_PASSWORD  without a terminal: a
                         ClickHouse administrator to create Rowsafe's own ClickHouse user
                         when it can't be added as a users.d file (used once, never saved)
  ROWSAFE_REDIS_ADMIN_USER, ROWSAFE_REDIS_ADMIN_PASSWORD  without a terminal: a Redis or
                         Valkey administrator (default, for a server with only a
                         password) to create Rowsafe's own user (used once, never saved)
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

  A new server, without a terminal (cloud-init):
    curl -fsSL https://rowsafe.sh | sh -s -- rse_... --no-prompt --install-postgres 17 \
      --listen-public --storage rowsafe --protect NAME
  installs PostgreSQL 17, makes it reachable with TLS and passwords, keeps
  backups in Rowsafe Storage with a passphrase generated on the server (see it
  in the dashboard, sealed to your browser) and turns them on.

  ClickHouse: Rowsafe's own ClickHouse user is added as
  /etc/clickhouse-server/users.d/rowsafe.xml (ClickHouse loads it by itself,
  no restart), or with an administrator's login once. The agent joins the
  clickhouse group to read (never write) ClickHouse's data folder: it copies
  each new part to your bucket as it appears, so you can restore to any
  second.

  Redis and Valkey: Rowsafe gets its own ACL user, rowsafe (as the default
  user when it has no password, else with an administrator's login once).
  Redis keeps it in its ACL file or configuration file; when it can't write
  them, the installer adds the user's line (the password's hash, never the
  password) to the configuration file. Backups come from the server itself
  over replication, so nothing is installed or restarted. Redis Cluster,
  Redis older than 7.0 and Valkey older than 7.2 are not supported yet.

  SQLite: a database is a file your app opens. The installer finds the
  files running programs have open (here and inside Docker containers, as
  root, read-only) and asks which to protect; --sqlite PATH adds one. The
  agent then needs read and write access to the file, its -wal and -shm
  files and their folder: the installer gives it to the agent's user with a
  POSIX ACL (installing the acl package if needed), plus a default ACL on
  the folder so the -wal and -shm files your app creates later are covered,
  and prints what it changed. Owners, groups and other users' access stay as
  they were. Files on network filesystems (NFS, SMB, sshfs...) are refused:
  SQLite's locking isn't reliable there. Clones (Fork in the dashboard) are
  new files written only into folders you allow with --sqlite-clone-dir (or
  answer yes when asked): the agent gets write access to the folder (an
  ACL, and a default ACL so the folder's owner can use the new files too).

What Rowsafe may do on this server:
  Rowsafe only restarts PostgreSQL, installs updates, reboots, manages
  PgBouncer or the firewall when someone clicks that in the dashboard and
  confirms, and only what root allowed here. On a terminal the installer asks
  once (a re-run keeps the answers) and then shows what is allowed. Change it
  any time with `sudo rowsafe-allow` (list), `sudo rowsafe-allow NAME` (allow)
  and `sudo rowsafe-allow --remove NAME`. Names: restart, create-cluster,
  updates, security-updates, reboot, pooler, pooler-public, firewall, tuning,
  sqlite-modes. Some
  need another: create-cluster, updates and security-updates need restart,
  reboot needs security-updates, pooler-public needs pooler. Turning one off
  turns off what needs it.

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

apt_update() {
  if ! DEBIAN_FRONTEND=noninteractive apt-get update -q >"$TMP/apt.log" 2>&1 </dev/null; then
    tail -n 20 "$TMP/apt.log" >&2
    die "apt-get update failed"
  fi
  APT_UPDATED=1
}

apt_install() {
  have apt-get || die "apt-get not found; install $* yourself and re-run"
  [ "$APT_UPDATED" = 1 ] || apt_update
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
# >>> clickhouse: without PostgreSQL, MySQL/MariaDB and MongoDB but with
# ClickHouse, the agent runs as its own system user, rowsafe, too.
detect_clickhouse_host() {
  [ "$HOST_ENGINE" = postgresql ] || return 0
  id -u postgres >/dev/null 2>&1 && return 0
  clickhouse_present || return 0
  HOST_ENGINE=clickhouse
  use_rowsafe_user
  AGENT_HOME=$STATE_DIR
}

# clickhouse_setup: on a ClickHouse server without PostgreSQL, a unit
# drop-in runs the agent as rowsafe (like mongodb_setup).
clickhouse_setup() {
  _dropin=/etc/systemd/system/$SERVICE.d
  if [ "$HOST_ENGINE" != clickhouse ]; then
    [ ! -f "$_dropin/10-clickhouse.conf" ] || { rm -f "$_dropin/10-clickhouse.conf"; UNIT_CHANGED=1; CHANGED=1; }
    return 0
  fi
  install -d -m 0755 "$_dropin"
  # The clickhouse group reads ClickHouse's data folder (never writes it):
  # restores to any second copy each new part from there as it appears.
  _groups=
  getent group clickhouse >/dev/null 2>&1 && _groups='SupplementaryGroups=clickhouse\n'
  if printf "# Written by the Rowsafe installer: this server runs ClickHouse.\n[Unit]\nAfter=clickhouse-server.service\n[Service]\nUser=rowsafe\nGroup=rowsafe\n${_groups}" |
    write_file "$_dropin/10-clickhouse.conf" 0644 root:root; then
    UNIT_CHANGED=1 CHANGED=1
  fi
}
# <<< clickhouse
# >>> redis: without PostgreSQL, MySQL/MariaDB, MongoDB and ClickHouse but
# with Redis or Valkey, the agent runs as its own system user, rowsafe, too.
# A server too old for Rowsafe is refused here, before anything changes.
detect_redis_host() {
  [ "$HOST_ENGINE" = postgresql ] || return 0
  id -u postgres >/dev/null 2>&1 && return 0
  redis_present || return 0
  HOST_ENGINE=redis
  if redis_find_program; then
    HOST_ENGINE=$REDIS_FOUND_ENGINE
    _why=$(redis_too_old "$HOST_ENGINE" "$REDIS_VERSION")
    [ -z "$_why" ] || die "$_why. Nothing was changed on this server."
  elif have valkey-server || [ -f /lib/systemd/system/valkey-server.service ] || [ -f /usr/lib/systemd/system/valkey-server.service ]; then
    HOST_ENGINE=valkey
  fi
  use_rowsafe_user
  AGENT_HOME=$STATE_DIR
}

# redis_setup: on a Redis or Valkey server without PostgreSQL, a unit
# drop-in runs the agent as rowsafe. The server's group (redis or valkey)
# lets it read, never write, the server's snapshot file, which it only uses
# when the server refuses to send it a copy over replication. Nothing of the
# server's (folders, modes) is changed for that.
redis_setup() {
  _dropin=/etc/systemd/system/$SERVICE.d
  case $HOST_ENGINE in
    redis | valkey) ;;
    *)
      [ ! -f "$_dropin/10-redis.conf" ] || { rm -f "$_dropin/10-redis.conf"; UNIT_CHANGED=1; CHANGED=1; }
      return 0
      ;;
  esac
  install -d -m 0755 "$_dropin"
  _grp=$(redis_group)
  if {
    echo "# Written by the Rowsafe installer: this server runs $(engine_label)."
    echo "[Unit]"
    echo "After=redis-server.service redis.service valkey-server.service valkey.service"
    echo "[Service]"
    echo "User=rowsafe"
    echo "Group=rowsafe"
    [ -z "$_grp" ] || echo "SupplementaryGroups=$_grp"
  } | write_file "$_dropin/10-redis.conf" 0644 root:root; then
    UNIT_CHANGED=1 CHANGED=1
  fi
}

# redis_group prints the group the Redis or Valkey packages made (redis or
# valkey), nothing when there is none.
redis_group() {
  _order='redis valkey'
  [ "$HOST_ENGINE" != valkey ] || _order='valkey redis'
  for _g in $_order; do
    if getent group "$_g" >/dev/null 2>&1; then
      echo "$_g"
      return 0
    fi
  done
}
# <<< redis
# >>> mysql

engine_label() {
  case ${1:-$HOST_ENGINE} in
    mysql) echo MySQL ;; mariadb) echo MariaDB ;; mongodb) echo MongoDB ;; clickhouse) echo ClickHouse ;;
    redis) echo Redis ;; valkey) echo Valkey ;; sqlite) echo SQLite ;; *) echo PostgreSQL ;;
  esac
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
  if [ "$HOST_ENGINE" != mysql ] && [ "$HOST_ENGINE" != mariadb ]; then
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
  _sb=''
  ! mysql_standby_wanted || _sb=1
  [ ! -f "$STATE_DIR/engines/$C_ENGINE/account-$C_PORT.cnf" ] || [ -n "$_sb" ] || return 0
  _sock=$C_SOCK
  [ "$_sock" != - ] || _sock=''
  if "$INSTALL_DIR/rowsafe-agent" setup mysql-account --engine "$C_ENGINE" --port "$C_PORT" ${_sock:+--socket "$_sock"} \
    --owner "$AGENT_USER" --state-dir "$STATE_DIR" ${_sb:+--standby} >"$TMP/account.log" 2>&1 </dev/null; then
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
    --owner "$AGENT_USER" --state-dir "$STATE_DIR" --admin-password-file "$TMP/adminpw" ${_sb:+--standby} >"$TMP/account.log" 2>&1 </dev/null || _rc=$?
  rm -f "$TMP/adminpw"
  if [ "$_rc" = 0 ]; then note "$(cat "$TMP/account.log")"; return 0; fi
  sed 's/^/    /' "$TMP/account.log" >&2
  return 1
}

# mysql_standby_wanted: --mysql-standby, or yes to the question (asked once,
# on a terminal).
mysql_standby_wanted() {
  case $MYSQL_STANDBY in
    yes) return 0 ;;
    no) return 1 ;;
  esac
  [ "$TTY" = 1 ] || return 1
  say ""
  note "Standby servers: Rowsafe can keep a second $(engine_label "$C_ENGINE") server in sync with this one (or this one with another),"
  note "ready to take over. For that its $(engine_label "$C_ENGINE") account needs administrator rights, used only when someone adds,"
  note "promotes or removes a standby in the dashboard and confirms."
  if [ -n "$(pooler_allowed_ports)" ]; then
    note "ProxySQL pools this server's $(engine_label "$C_ENGINE") (connection pooling): after a standby on another server is"
    note "promoted, ProxySQL follows it only where root approved that server, with one command here:"
    note "  sudo rowsafe-allow pooler-target STANDBY_ADDRESS PORT   (the Standby page shows the exact one)"
  fi
  if confirm "Allow standby servers with this server?" n; then MYSQL_STANDBY=yes; return 0; fi
  MYSQL_STANDBY=no
  return 1
}
# <<< mysql

# check_postgres finds the postgres OS user and the installed server majors.
check_postgres() {
  [ "$HOST_ENGINE" = postgresql ] || return 0 # mysql
  id -u "$AGENT_USER" >/dev/null 2>&1 ||
    die "no '$AGENT_USER' user on this host. Rowsafe adopts an existing PostgreSQL, MySQL, MariaDB, MongoDB, ClickHouse, Redis or Valkey; install one first."
  PG_MAJORS=''
  for bin in /usr/lib/postgresql/*/bin/postgres; do
    [ -x "$bin" ] || continue
    major=${bin#/usr/lib/postgresql/}
    PG_MAJORS="$PG_MAJORS ${major%%/*}"
  done
  PG_MAJORS=${PG_MAJORS# }
  if [ -z "$PG_MAJORS" ] && [ -z "${ROWSAFE_PG_BIN_DIR:-}" ] && ! mongodb_present && ! clickhouse_present && ! redis_present; then
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

# ---------------------------------------------------------------- servers Rowsafe creates
#
# --install-postgres VERSION and --listen-public are for a fresh server
# (Create a server for me): cloud-init runs the installer once, without a
# terminal, to install PostgreSQL, make it reachable and protect it:
#
#   curl -fsSL https://rowsafe.sh | sh -s -- rse_... --no-prompt \
#     --install-postgres 17 --listen-public --storage rowsafe --protect shop
#
# Running it again changes nothing that is already in place.

# The PostgreSQL project's apt repository (https://www.postgresql.org/download/linux/debian/),
# set up the way its instructions describe, with the signing key's
# fingerprint checked before apt trusts it.
PGDG_KEY_URL=https://www.postgresql.org/media/keys/ACCC4CF8.asc
PGDG_KEY_FPR=B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8
PGDG_KEY_FILE=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
PGDG_LIST=/etc/apt/sources.list.d/pgdg.list
# The major --install-postgres installed (a re-run recognizes it as its own).
PG_INSTALLED_FILE=$CONFIG_DIR/installed-postgresql
# --listen-public's self-signed certificate (root's directory, the key
# readable by the postgres group only, as PostgreSQL requires).
PG_TLS_DIR=/etc/ssl/rowsafe-postgresql
# Cluster --listen-public works on (pg_target).
LP_MAJOR='' LP_NAME='' LP_PORT=''

# existing_postgres describes PostgreSQL already on this server, if any:
# server binaries, server packages or a running postgres process.
existing_postgres() {
  for _b in /usr/lib/postgresql/*/bin/postgres; do
    [ -x "$_b" ] || continue
    _m=${_b#/usr/lib/postgresql/}
    printf 'PostgreSQL %s in /usr/lib/postgresql/%s' "${_m%%/*}" "${_m%%/*}"
    return 0
  done
  if have dpkg-query; then
    # shellcheck disable=SC2016 # dpkg-query's own ${...} fields
    _p=$(dpkg-query -W -f '${Package} ${db:Status-Status}\n' 'postgresql-[0-9]*' 2>/dev/null | awk '$2 == "installed" { print $1; exit }')
    if [ -n "$_p" ]; then
      printf 'the package %s' "$_p"
      return 0
    fi
  fi
  if have pgrep && pgrep -x postgres >/dev/null 2>&1; then
    printf 'a running PostgreSQL server'
    return 0
  fi
  return 0
}

# pgdg_repo adds the PostgreSQL project's apt repository.
pgdg_repo() {
  # shellcheck disable=SC1091 # the system's own file
  _codename=$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")
  [ -n "$_codename" ] || die "can't tell this system's release name (VERSION_CODENAME in /etc/os-release)"
  have gpg || apt_install gnupg
  fetch "$PGDG_KEY_URL" "$TMP/pgdg.asc" || die "could not download the PostgreSQL project's signing key ($PGDG_KEY_URL)"
  install -d -m 0700 "$TMP/gnupg"
  GNUPGHOME=$TMP/gnupg gpg --batch --show-keys --with-colons "$TMP/pgdg.asc" >"$TMP/pgdg.keys" 2>/dev/null || true
  _fpr=$(awk -F: '$1 == "fpr" { print $10; exit }' "$TMP/pgdg.keys")
  [ "$(grep -c '^pub:' "$TMP/pgdg.keys")" = 1 ] && [ "$_fpr" = "$PGDG_KEY_FPR" ] ||
    die "the PostgreSQL project's signing key isn't the expected one (fingerprint ${_fpr:-unreadable}); not installing PostgreSQL"
  install -d -m 0755 -o root -g root "${PGDG_KEY_FILE%/*}"
  write_file "$PGDG_KEY_FILE" 0644 root:root <"$TMP/pgdg.asc" || true
  echo "deb [signed-by=$PGDG_KEY_FILE] https://apt.postgresql.org/pub/repos/apt $_codename-pgdg main" |
    write_file "$PGDG_LIST" 0644 root:root || true
  apt_update
  ok "the PostgreSQL project's repository (apt.postgresql.org, key $PGDG_KEY_FPR)"
}

# install_postgres is --install-postgres VERSION: PostgreSQL from the
# PostgreSQL project's repository, its main cluster running. It refuses on a
# server with PostgreSQL already, unless that is the one it installed.
install_postgres() {
  _v=$INSTALL_PG
  ensure_base_tools
  if [ "$(cat "$PG_INSTALLED_FILE" 2>/dev/null)" = "$_v" ] && [ -x "/usr/lib/postgresql/$_v/bin/postgres" ]; then
    ok "PostgreSQL $_v is installed (by an earlier run of this installer)"
  else
    _found=$(existing_postgres)
    if [ -n "$_found" ]; then
      die "PostgreSQL is already installed on this server ($_found), so --install-postgres won't install another one. Run the installer without --install-postgres to protect the PostgreSQL that is there."
    fi
    step "Installing PostgreSQL $_v from the PostgreSQL project's repository"
    pgdg_repo
    _c=$(apt-cache policy "postgresql-$_v" 2>/dev/null | awk '$1 == "Candidate:" { print $2; exit }')
    [ -n "$_c" ] && [ "$_c" != "(none)" ] ||
      die "PostgreSQL $_v isn't available for $OS_NAME from the PostgreSQL project's repository; pick another version (13-18)"
    # The package creates and starts the main cluster: UTF-8, whatever
    # locale cloud-init runs with.
    if ! env LANG=C.UTF-8 LC_ALL=C.UTF-8 DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
      "postgresql-$_v" "postgresql-client-$_v" >>"$TMP/apt.log" 2>&1 </dev/null; then
      tail -n 20 "$TMP/apt.log" >&2
      die "installing PostgreSQL $_v failed"
    fi
    install -d -m 0750 -o root -g postgres "$CONFIG_DIR"
    printf '%s\n' "$_v" | write_file "$PG_INSTALLED_FILE" 0644 root:root || true
    ok "PostgreSQL $_c installed"
  fi
  PG_OURS=1
  pg_ensure_cluster "$_v" main
}

# pg_cluster_status MAJOR NAME prints the cluster's status (online, down...),
# nothing when it doesn't exist.
pg_cluster_status() { pg_lsclusters -h 2>/dev/null | awk -v m="$1" -v n="$2" '$1 == m && $2 == n { print $4; exit }'; }

# pg_ensure_cluster MAJOR NAME creates the cluster when it is missing and
# starts it when it is down.
pg_ensure_cluster() {
  have pg_lsclusters || die "pg_lsclusters is missing: the PostgreSQL packages look incomplete"
  _st=$(pg_cluster_status "$1" "$2")
  if [ -z "$_st" ]; then
    step "Creating PostgreSQL $1's $2 cluster"
    if ! env LANG=C.UTF-8 LC_ALL=C.UTF-8 pg_createcluster "$1" "$2" >"$TMP/pg.log" 2>&1 </dev/null; then
      tail -n 10 "$TMP/pg.log" | sed 's/^/    /' >&2
      die "creating PostgreSQL $1's $2 cluster failed"
    fi
    _st=down
  fi
  case $_st in
    online*) ;;
    *)
      _rc=0
      if systemd_running; then
        timeout 180 systemctl start "postgresql@$1-$2" >"$TMP/pg.log" 2>&1 </dev/null || _rc=$?
      else
        timeout 180 pg_ctlcluster "$1" "$2" start >"$TMP/pg.log" 2>&1 </dev/null || _rc=$?
      fi
      if [ "$_rc" != 0 ]; then
        tail -n 10 "$TMP/pg.log" | sed 's/^/    /' >&2
        die "PostgreSQL $1 ($2) doesn't start (see above)"
      fi
      ;;
  esac
  case $(pg_cluster_status "$1" "$2") in
    online*) ;;
    *) die "PostgreSQL $1 ($2) isn't running" ;;
  esac
  ok "PostgreSQL $1 ($2) is running on port $(pg_lsclusters -h | awk -v m="$1" -v n="$2" '$1 == m && $2 == n { print $3; exit }')"
}

# pg_restart_cluster MAJOR NAME restarts it (only for --install-postgres's
# own cluster, or after a yes on the terminal).
pg_restart_cluster() {
  _rc=0
  if systemd_running; then
    timeout 180 systemctl restart "postgresql@$1-$2" >"$TMP/pg.log" 2>&1 </dev/null || _rc=$?
  else
    timeout 180 pg_ctlcluster "$1" "$2" restart >"$TMP/pg.log" 2>&1 </dev/null || _rc=$?
  fi
  if [ "$_rc" != 0 ]; then
    tail -n 10 "$TMP/pg.log" | sed 's/^/    /' >&2
    return 1
  fi
}

# pg_sql PORT SQL runs a fixed statement as postgres and prints the result.
pg_sql() {
  (cd / && runuser -u postgres -- psql -X -A -t -q -v ON_ERROR_STOP=1 -p "$1" -d postgres -c "$2") </dev/null
}

# pg_target picks the cluster --listen-public works on: --install-postgres's,
# the one on --protect-port, or the only one.
pg_target() {
  have pg_lsclusters || die "--listen-public needs Debian's PostgreSQL cluster tools (pg_lsclusters)"
  if [ -n "$INSTALL_PG" ]; then
    _line=$(pg_lsclusters -h 2>/dev/null | awk -v m="$INSTALL_PG" '$1 == m && $2 == "main"')
  elif [ -n "$PROTECT_PORT" ]; then
    _line=$(pg_lsclusters -h 2>/dev/null | awk -v p="$PROTECT_PORT" '$3 == p')
  else
    case $(pg_lsclusters -h 2>/dev/null | grep -c .) in
      0) die "--listen-public: no PostgreSQL cluster on this server" ;;
      1) _line=$(pg_lsclusters -h 2>/dev/null) ;;
      *) die "--listen-public: this server has several PostgreSQL clusters; pick one with --protect NAME --protect-port PORT" ;;
    esac
  fi
  [ -n "$_line" ] || die "--listen-public: found no such PostgreSQL cluster"
  LP_MAJOR=$(printf '%s\n' "$_line" | awk '{ print $1 }')
  LP_NAME=$(printf '%s\n' "$_line" | awk '{ print $2 }')
  LP_PORT=$(printf '%s\n' "$_line" | awk '{ print $3 }')
  case $(printf '%s\n' "$_line" | awk '{ print $4 }') in
    online*) ;;
    *) die "--listen-public: PostgreSQL $LP_MAJOR ($LP_NAME) isn't running" ;;
  esac
}

# pg_tls_cert makes the self-signed certificate, once, on this server.
pg_tls_cert() {
  install -d -m 0750 -o root -g postgres "$PG_TLS_DIR"
  if [ -s "$PG_TLS_DIR/server.key" ] && [ -s "$PG_TLS_DIR/server.crt" ]; then
    return 0
  fi
  _cn=$(hostname -f 2>/dev/null || uname -n)
  printf '%s\n' "$_cn" | grep -Eq '^[A-Za-z0-9.-]{1,253}$' || _cn=$(uname -n)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=$_cn" -addext "subjectAltName=DNS:$_cn" \
    -keyout "$TMP/pg-tls.key" -out "$TMP/pg-tls.crt" >"$TMP/openssl.log" 2>&1 ||
    die "could not make a TLS certificate for PostgreSQL: $(tail -n 1 "$TMP/openssl.log")"
  install -m 0640 -o root -g postgres "$TMP/pg-tls.key" "$PG_TLS_DIR/server.key"
  install -m 0644 -o root -g root "$TMP/pg-tls.crt" "$PG_TLS_DIR/server.crt"
  rm -f "$TMP/pg-tls.key"
  ok "made a self-signed TLS certificate for PostgreSQL ($PG_TLS_DIR)"
}

# listen_public is --listen-public: PostgreSQL listens on every address,
# with TLS and SCRAM-SHA-256 passwords for logins from the network (the
# cloud firewall decides who can connect). Local rules stay as they are.
listen_public() {
  pg_target
  step "Making PostgreSQL $LP_MAJOR reachable from the network (TLS and passwords only)"
  pg_tls_cert
  _changed=0
  for _kv in "listen_addresses=*" "ssl=on" "ssl_cert_file=$PG_TLS_DIR/server.crt" \
    "ssl_key_file=$PG_TLS_DIR/server.key" "password_encryption=scram-sha-256"; do
    _k=${_kv%%=*} _val=${_kv#*=}
    _cur=$(pg_sql "$LP_PORT" "SELECT setting FROM pg_settings WHERE name = '$_k'") ||
      die "could not read PostgreSQL's settings on port $LP_PORT"
    [ "$_cur" != "$_val" ] || continue
    pg_sql "$LP_PORT" "ALTER SYSTEM SET $_k = '$_val'" >/dev/null || die "could not set $_k"
    _changed=1
  done
  _hba=$(pg_sql "$LP_PORT" "SHOW hba_file") || die "could not find PostgreSQL's pg_hba.conf"
  [ -f "$_hba" ] || die "PostgreSQL's pg_hba.conf ($_hba) isn't a file"
  if ! grep -qs '^# Rowsafe --listen-public' "$_hba"; then
    # The file is postgres's, in postgres's directory: written as postgres.
    # shellcheck disable=SC2016 # $1 expands in the inner shell
    printf '%s\n' "" "# Rowsafe --listen-public: logins from the network need TLS and a password" \
      "# (SCRAM-SHA-256); the cloud firewall decides who can connect at all." \
      "hostssl all             all             0.0.0.0/0               scram-sha-256" \
      "hostssl all             all             ::/0                    scram-sha-256" |
      (cd / && runuser -u postgres -- sh -c 'cat >>"$1"' rowsafe-hba "$_hba") || die "could not add the rules to $_hba"
    _changed=1
  fi
  if [ "$_changed" = 1 ]; then
    pg_sql "$LP_PORT" "SELECT pg_reload_conf()" >/dev/null || die "could not reload PostgreSQL"
    sleep 1
  fi
  _bad=$(pg_sql "$LP_PORT" "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL") || _bad=unknown
  [ "$_bad" = 0 ] || die "PostgreSQL rejects $_hba (see pg_hba_file_rules)"
  _pending=$(pg_sql "$LP_PORT" "SELECT count(*) FROM pg_settings WHERE pending_restart") || _pending=0
  if [ "$_pending" != 0 ]; then
    if [ "$PG_OURS" = 1 ]; then
      note "restarting the new PostgreSQL so it listens on the network"
      pg_restart_cluster "$LP_MAJOR" "$LP_NAME" || die "restarting PostgreSQL $LP_MAJOR ($LP_NAME) failed (see above)"
    elif [ "$TTY" = 1 ] && {
      tty_say "PostgreSQL needs a quick restart to listen on the network. Open connections are dropped."
      confirm "Restart PostgreSQL now?" n
    }; then
      pg_restart_cluster "$LP_MAJOR" "$LP_NAME" || die "restarting PostgreSQL $LP_MAJOR ($LP_NAME) failed (see above)"
    else
      warn "PostgreSQL listens on the network after its next restart: sudo systemctl restart postgresql@$LP_MAJOR-$LP_NAME"
      return 0
    fi
  fi
  [ "$(pg_sql "$LP_PORT" "SHOW ssl")" = on ] || die "PostgreSQL's TLS didn't turn on (see its log in /var/log/postgresql)"
  if [ "$_changed" = 0 ] && [ "$_pending" = 0 ]; then
    ok "PostgreSQL $LP_MAJOR listens on the network (port $LP_PORT, TLS and passwords only); nothing to change"
  else
    ok "PostgreSQL $LP_MAJOR listens on the network (port $LP_PORT, TLS and passwords only)"
  fi
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
# rowsafe-pg-restart: restarts or stops PostgreSQL (or the MySQL, MariaDB,
# MongoDB, ClickHouse, Redis or Valkey server Rowsafe protects) when a person asked
# Rowsafe to (Restart in the dashboard, `rowsafe restart`; Rewind the whole
# database, which stops the database, swaps its data and starts it),
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
# Files mode (ROWSAFE_HELPER_MODE=files, set by rowsafe-files-helper.service,
# which rowsafe-files-helper.path starts; only when root allowed it with
# --allow-files): the request is /var/lib/rowsafe/restart/files-request and
# the answer /run/rowsafe-pg-restart/files-result. "ID files-read PATH"
# gives the agent user read access to PATH (POSIX ACLs, never ownership or
# modes); "ID files-put MODE STAGE PATH" puts files the agent restored into
# /var/lib/rowsafe/files-staging/STAGE/tree back into PATH as PATH's owner.
# MODE: missing (never overwrite), replace, or mirror (also delete the files
# listed in STAGE/delete). PATH must be listed exactly in
# /etc/rowsafe/files-allowed ("PATH UID": the folders the person protected
# with the installer, and their owner then) and still be owned by that uid;
# never a system, database or home folder, nor one the agent user owns or
# can write (nor any folder on the way or inside). The agent is not trusted
# with the rest either: root copies the staged files (read as the agent
# user, at most 20 GB by default) and puts them back only if they are plain
# files and folders (no links, devices or FIFOs, no set-user-ID or
# set-group-ID bits, no path leaving PATH or into .ssh, .gnupg or
# .config/systemd), never through a symbolic link in PATH, as the owner
# with the owner's own group; it deletes only files whose folder is really
# inside PATH. At most one files-put every 2 minutes and one files-read
# every 10 minutes.
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
#   ID db-minor-update PORT                  newest release of the series (8.0, 10.11, 7.0, 25.8)
#                                            of the MySQL, MariaDB, MongoDB or ClickHouse server on PORT
#   ID db-upgrade PORT SERIES                that server to a newer series (8.0 -> 8.4), keeping a copy
#                                            of its data directory and its old packages for undo
#   ID db-upgrade-undo PORT                  back to the kept data and packages (the newer data is kept aside)
#   ID db-upgrade-cleanup PORT               delete what an upgrade or its undo kept
#
# db-* requests need the word "database" and act only on a port in
# /etc/rowsafe/restart-allowed whose unit is one of those servers' units;
# they install only that server's own packages (see db_patterns), already
# installed ones, at the newest version of the installed series.
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
# MongoDB standbys: "ID mongodb-key-export PORT" copies the replica set's
# key file of the MongoDB on PORT to /var/lib/rowsafe/restart/mongodb-key-out
# (written as the agent user, which seals it to the standby server's agent);
# "ID mongodb-standby-config PORT SETNAME key|nokey ADDR" makes the empty
# MongoDB on PORT ready to join replica set SETNAME: it installs the key the
# agent left in /var/lib/rowsafe/restart/mongodb-key-in (read as the agent
# user, checked) as /etc/rowsafe/mongodb-standby-PORT.key, readable by
# MongoDB only, and sets replication.replSetName, security.keyFile and (with
# ADDR, an IP address) net.bindIp in its configuration file, keeping a copy
# of the file as it was (CONFIG.rowsafe-backup). It restarts nothing: a
# restart is a separate request a person confirmed. Both need PORT in
# /etc/rowsafe/mongodb-standby-allowed ("PORT UNIT CONFIG", written by the
# installer with --mongodb-standby).
#
# actions: restart stop start create-cluster files-read files-put mongodb-key-export mongodb-standby-config
# update-actions: pg-minor-update pg-install-major pg-upgrade pg-upgrade-undo pg-upgrade-cleanup security-updates reboot db-minor-update db-upgrade db-upgrade-undo db-upgrade-cleanup
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
# At most this many bytes of files are put back at once (root can change it
# in the files unit: Environment=ROWSAFE_FILES_MAX_BYTES=...).
files_max=${ROWSAFE_FILES_MAX_BYTES:-21474836480}
case $files_max in '' | *[!0-9]*) files_max=21474836480 ;; esac
agent_user=${ROWSAFE_AGENT_USER:-postgres}
systemctl=${ROWSAFE_SYSTEMCTL:-systemctl}
mode=${ROWSAFE_HELPER_MODE:-restart}
min_interval=60

mongo_allow=${ROWSAFE_MONGODB_STANDBY_ALLOW:-/etc/rowsafe/mongodb-standby-allowed}
mongo_key_dir=${ROWSAFE_MONGODB_KEY_DIR:-/etc/rowsafe}

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
# (network and a writable system): each of install and purge at most once
# every 10 minutes, so removing it right after installing it still works.
pooler_apt() {
  _now=$(date +%s)
  _last=$(cat "$state/last-apt-$1" 2>/dev/null || echo 0)
  case $_last in '' | *[!0-9]*) _last=0 ;; esac
  if [ $((_now - _last)) -lt "$apt_cooldown" ]; then
    case $1 in install) _what=installed ;; *) _what=removed ;; esac
    pooler_refuse "PgBouncer was $_what less than 10 minutes ago; try again in $(((apt_cooldown - _now + _last + 59) / 60)) minutes"
  fi
  echo "$_now" >"$state/last-apt-$1"
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
      pooler_refuse "listening on every address isn't allowed on this server (allow it on the server with: sudo rowsafe-allow pooler-public)"
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

# db_unit_re: the database units a restart, stop or start may act on,
# whatever the allow list says: Debian's PostgreSQL cluster units
# (postgresql@MAJOR-NAME.service), and the units the MySQL, MariaDB,
# MongoDB, ClickHouse, Redis and Valkey packages install (mysql, mysqld,
# mariadb and their @instance forms, mongod, mongodb, clickhouse-server,
# redis-server, redis, valkey-server, valkey and their @instance forms).
db_unit_re='^(postgresql@[0-9]+-[A-Za-z0-9_.-]+|mysqld?|mariadb|(mysqld?|mariadb)@[A-Za-z0-9_.-]+|mongod|mongodb|clickhouse-server|(redis|valkey)(-server)?(@[A-Za-z0-9_.-]+)?)[.]service$'

# allowed_unit PORT prints the unit the restart allow list names for PORT.
allowed_unit() {
  # Only database units (db_unit_re), whatever the file says; ports compare
  # as strings.
  awk -v p="$1" -v re="$db_unit_re" '$1 "" == p "" && $2 ~ re { print $2; exit }' "$allow"
}

# created_unit PORT prints the unit of a cluster created for a fork on PORT
# (Debian's cluster units only, like allowed_unit).
created_unit() {
  [ -f "$created" ] || [ -L "$created" ] || return 0
  check_root_file "$created" "$created is missing"
  awk -v p="$1" '$1 "" == p "" && $2 ~ /^postgresql@[0-9]+-[A-Za-z0-9_.-]+\.service$/ { print $2; exit }' "$created"
}

# ---------------------------------------------------------------- MongoDB standbys

# mongo_allowed PORT sets m_unit and m_conf from the MongoDB standby allow
# list, which only root can write.
mongo_allowed() {
  check_root_file "$mongo_allow" "making MongoDB a standby server is not allowed on this server (install Rowsafe there with --mongodb-standby)"
  m_line=$(awk -v p="$1" '$1 "" == p "" { print $2 " " $3; exit }' "$mongo_allow")
  [ -n "$m_line" ] || refuse "port $1 is not in $mongo_allow"
  m_unit=${m_line%% *}
  m_conf=${m_line#* }
  printf '%s\n' "$m_unit" | grep -Eq '^(mongod|mongodb)(@[A-Za-z0-9_.-]+)?\.service$' || refuse "$m_unit is not a MongoDB unit"
  case $m_conf in
    /etc/*.conf | /etc/*.yaml | /etc/*.yml) ;;
    *) refuse "$m_conf is not a MongoDB configuration file under /etc" ;;
  esac
  case $m_conf in *..*) refuse "$m_conf is not a plain path" ;; esac
  check_root_file "$m_conf" "$m_conf is missing"
}

# yaml_get FILE SECTION KEY prints section.key of a block-style YAML file.
yaml_get() {
  awk -v s="$2" -v k="$3" '
    /^[^[:space:]#]/ { insec = ($0 ~ "^" s ":[[:space:]]*(#.*)?$") ; next }
    insec && $0 ~ "^[[:space:]]+" k ":" {
      sub("^[[:space:]]+" k ":[[:space:]]*", ""); sub("[[:space:]]+#.*$", ""); gsub(/["\047]/, ""); print; exit
    }' "$1"
}

# yaml_set FILE SECTION KEY VALUE sets section.key in place: it replaces the
# key, or adds it at the end of the section with the section's own
# indentation, or adds the section. Inline sections ({...}) are refused.
yaml_set() {
  if grep -Eq "^$2:[[:space:]]*[^[:space:]#]" "$1"; then
    refuse "$1 writes $2 inline; Rowsafe only changes block-style sections"
  fi
  y_tmp=$(mktemp "$1.rowsafe.XXXXXX") || refuse "cannot write next to $1"
  awk -v s="$2" -v k="$3" -v v="$4" '
    function put() { if (!done) { print (ind == "" ? "  " : ind) k ": " v; done = 1 } }
    /^[^[:space:]#]/ { if (insec) put(); insec = ($0 ~ "^" s ":[[:space:]]*(#.*)?$"); if (insec) seen = 1; print; next }
    insec && /^[[:space:]]+[^[:space:]#]/ && ind == "" { match($0, /^[[:space:]]+/); ind = substr($0, 1, RLENGTH) }
    insec && $0 ~ "^[[:space:]]+" k ":" { put(); next }
    { print }
    END { if (insec) put(); if (!seen) { print ""; print s ":"; print "  " k ": " v } }' "$1" >"$y_tmp" || refuse "cannot change $1"
  cat "$y_tmp" >"$1"
  rm -f "$y_tmp"
}

# mongo_user is the user the MongoDB unit runs as.
mongo_user() {
  m_user=$("$systemctl" show -p User --value "$m_unit" 2>/dev/null)
  [ -n "$m_user" ] || m_user=mongodb
  id -u "$m_user" >/dev/null 2>&1 || m_user=mongod
  id -u "$m_user" >/dev/null 2>&1 || refuse "the user MongoDB runs as is unknown"
}

mongo_key_export() {
  mongo_allowed "$1"
  m_key=$(yaml_get "$m_conf" security keyFile)
  [ -n "$m_key" ] || refuse "MongoDB on port $1 has no key file in $m_conf"
  case $m_key in /*) ;; *) refuse "the key file path in $m_conf is not absolute" ;; esac
  [ -f "$m_key" ] && [ ! -L "$m_key" ] || refuse "$m_key is not a plain file"
  [ "$(stat -c %s "$m_key")" -le 1100 ] || refuse "$m_key is larger than a MongoDB key file"
  tr -d 'A-Za-z0-9+/= \n\r\t' <"$m_key" | grep -q . && refuse "$m_key is not a MongoDB key file"
  # shellcheck disable=SC2016 # $1 expands in the inner shell
  as_agent sh -c 'umask 077; rm -f -- "$1"; cat >"$1"' rowsafe-pg-restart "$dir/mongodb-key-out" <"$m_key" ||
    refuse "cannot hand the key file to the agent"
  ok=1
}

mongo_standby_config() {
  port=$1 m_set=$2 m_keyflag=$3 m_addr=$4
  mongo_allowed "$port"
  m_cur=$(yaml_get "$m_conf" replication replSetName)
  [ -z "$m_cur" ] || [ "$m_cur" = "$m_set" ] || refuse "MongoDB on port $port already names replica set $m_cur"
  [ -e "$m_conf.rowsafe-backup" ] || cp -p "$m_conf" "$m_conf.rowsafe-backup" || refuse "cannot keep a copy of $m_conf"
  if [ "$m_keyflag" = key ]; then
    # shellcheck disable=SC2016
    m_keydata=$(as_agent sh -c 'if [ -f "$1" ] && [ ! -L "$1" ]; then head -c 1100 -- "$1"; fi; rm -f -- "$1"' rowsafe-pg-restart "$dir/mongodb-key-in" 2>/dev/null)
    m_len=$(printf '%s' "$m_keydata" | tr -d ' \n\r\t' | wc -c)
    [ "$m_len" -ge 6 ] && [ "$m_len" -le 1024 ] || refuse "the key the agent left is not a MongoDB key"
    printf '%s' "$m_keydata" | tr -d 'A-Za-z0-9+/= \n\r\t' | grep -q . && refuse "the key the agent left is not a MongoDB key"
    mongo_user
    m_keyfile=$mongo_key_dir/mongodb-standby-$port.key
    m_tmp=$(mktemp "$mongo_key_dir/.mongodb-key.XXXXXX") || refuse "cannot write in $mongo_key_dir"
    printf '%s\n' "$m_keydata" >"$m_tmp"
    chown "$m_user" "$m_tmp" && chmod 0400 "$m_tmp" && mv -f "$m_tmp" "$m_keyfile" || refuse "cannot install the key file"
    yaml_set "$m_conf" security keyFile "$m_keyfile"
  fi
  yaml_set "$m_conf" replication replSetName "$m_set"
  if [ "$m_addr" != - ]; then
    m_bind=$(yaml_get "$m_conf" net bindIp)
    [ -n "$m_bind" ] || m_bind=127.0.0.1
    case ",$m_bind," in
      *",$m_addr,"* | *,0.0.0.0,* | *,::,*) ;;
      *) yaml_set "$m_conf" net bindIp "$m_bind,$m_addr" ;;
    esac
  fi
  log "MongoDB on port $port: replica set $m_set, key $m_keyflag, address $m_addr in $m_conf (a copy of it as it was: $m_conf.rowsafe-backup)"
  add config "$m_conf"
  ok=1
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
  check_root_file "$created" "$created is missing: allow it on the server with: sudo rowsafe-allow create-cluster"
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

# ---------------------------------------------------------------- files (files mode, --allow-files)

# files_folder_uid prints the owner uid root recorded for exactly $fpath in
# the files allow list ("PATH UID" lines), or nothing.
files_folder_uid() {
  awk -v p="$fpath" '$1 == p && $2 ~ /^[0-9]+$/ && NF == 2 { print $2; exit }' "$files_allow"
}

# files_agent_can_write DIR: DIR is owned by the agent user or writable by
# it (as the agent sees it, or by mode bits for others and its groups).
files_agent_can_write() {
  [ "$(stat -c '%u' -- "$1")" = "$agent_uid" ] && return 0
  as_agent test -w "$1" 2>/dev/null && return 0
  _m=$(stat -c '%a %g' -- "$1")
  _perm=${_m% *} _gid=${_m#* }
  [ $((0$_perm & 02)) = 0 ] || return 0
  if [ $((0$_perm & 020)) != 0 ]; then
    for _g in $agent_groups; do [ "$_g" != "$_gid" ] || return 0; done
  fi
  return 1
}

# files_check_home refuses a folder that is, contains or sits inside a home
# directory (getent passwd). Exceptions: the folder IS the home of a service
# account (uid 1-999, no login shell), or sits inside such an account's
# home (/var/www for www-data). Homes that are / or don't exist are skipped.
files_check_home() {
  getent passwd >"$work_pw" 2>/dev/null || refuse "can't read the list of users"
  while IFS=: read -r _u _x _uid _gid _gecos _home _shell; do
    case $_home in '' | / | [!/]*) continue ;; esac
    _home=${_home%/}
    [ -d "$_home" ] || continue
    _service=0
    case $_uid in '' | *[!0-9]*) _uid=0 ;; esac
    if [ "$_uid" -ge 1 ] && [ "$_uid" -le 999 ]; then
      case $_shell in */nologin | */false | '') _service=1 ;; esac
    fi
    case $_home in
      "$fpath")
        [ "$_service" = 1 ] || refuse "$fpath is the home folder of $_u: Rowsafe never writes there"
        ;;
      "$fpath"/*) refuse "$fpath contains the home folder of $_u ($_home): Rowsafe never writes there" ;;
    esac
    case $fpath in
      "$_home"/*)
        [ "$_service" = 1 ] || refuse "$fpath is inside the home folder of $_u ($_home): Rowsafe never writes there"
        ;;
    esac
  done <"$work_pw"
}

# files_check_path refuses unless $fpath is a plain, existing folder (no
# symbolic link on the way) that root listed exactly in the files allow
# list, still owned by the uid recorded there, not a system, database or
# home folder, with no folder on the way the agent user owns or can write.
files_check_path() {
  check_root_file "$files_allow" "reading or restoring folders from Rowsafe is not allowed on this server"
  case $fpath in
    */../* | */.. | */./* | */. | *//* | */) refuse "$fpath is not a plain path" ;;
  esac
  case $fpath/ in
    /etc/* | /root/* | /boot/* | /proc/* | /sys/* | /dev/* | /run/* | /usr/* | /bin/* | /sbin/* | /lib/* | /lib64/* | \
      /var/lib/postgresql/* | /var/lib/rowsafe/* | /var/lib/rowsafe-pg-restart/* | /var/lib/rowsafe-files-helper/* | \
      /opt/rowsafe/* | /var/lib/docker/containers/* | */.ssh/* | */.gnupg/* | */.config/systemd/*)
      refuse "$fpath is a system or database folder: Rowsafe never touches it" ;;
  esac
  want_uid=$(files_folder_uid)
  [ -n "$want_uid" ] || refuse "$fpath is not a folder root allowed in $files_allow (run the installer again with --files $fpath)"
  real=$(realpath -e -- "$fpath" 2>/dev/null) || refuse "$fpath doesn't exist"
  [ "$real" = "$fpath" ] || refuse "$fpath goes through a symbolic link (to $real)"
  [ -d "$fpath" ] || refuse "$fpath is not a folder"
  [ "$(stat -c '%u' -- "$fpath")" = "$want_uid" ] ||
    refuse "$fpath belongs to uid $(stat -c '%u' -- "$fpath") now, not uid $want_uid as when root allowed it: run the installer again with --files $fpath"
  agent_uid=$(id -u "$agent_user" 2>/dev/null) || refuse "no user $agent_user"
  agent_groups=$(id -G "$agent_user" 2>/dev/null)
  files_check_home
  _p=$fpath
  while [ -n "$_p" ]; do
    if files_agent_can_write "$_p"; then refuse "Rowsafe's own user can change $_p: Rowsafe won't use root there"; fi
    _p=${_p%/*}
  done
  if files_agent_can_write /; then refuse "Rowsafe's own user can change /"; fi
  # No folder inside is the agent's or writable by it either.
  _found=$(find -P "$fpath" -xdev -type d \( -user "$agent_uid" -o -perm -0002 \) -print -quit 2>/dev/null)
  [ -z "$_found" ] || refuse "Rowsafe's own user can change $_found: Rowsafe won't use root there"
  for _g in $agent_groups; do
    _found=$(find -P "$fpath" -xdev -type d -group "$_g" -perm -0020 -print -quit 2>/dev/null)
    [ -z "$_found" ] || refuse "Rowsafe's own user can change $_found (group): Rowsafe won't use root there"
  done
  _found=$(as_agent find -P "$fpath" -xdev -type d -writable -print -quit 2>/dev/null)
  [ -z "$_found" ] || refuse "Rowsafe's own user can change $_found: Rowsafe won't use root there"
}

# acl_grant_read DIR USER WORKDIR lets USER read DIR and everything in it,
# now and later (default ACLs). Masks that were already there are put back
# as they were, so no other named entry gains rights; a new mask covers only
# the owning group and USER.
acl_grant_read() {
  getfacl -R -P -s -p -- "$1" >"$3/acl.before" 2>/dev/null || return 1
  setfacl -R -P -m "u:$2:rX" -- "$1" || return 1
  find -P "$1" -xdev -type d -exec setfacl -m "d:u:$2:rX" -- {} + || return 1
  [ -s "$3/acl.before" ] || return 0
  getfacl -R -P -s -p -- "$1" >"$3/acl.after" 2>/dev/null || return 1
  awk '
    FNR == 1 { pass++ }
    /^# file: / { f = substr($0, 9); if (pass == 1) had[f] = 1; else keep = (f in had) }
    pass == 1 { if ($0 ~ /^mask::/) m[f] = $0; else if ($0 ~ /^default:mask::/) dm[f] = $0; next }
    !keep || /^# (owner|group|flags):/ { next }
    /^mask::/ && (f in m) { print m[f]; next }
    /^default:mask::/ && (f in dm) { print dm[f]; next }
    { print }
  ' "$3/acl.before" "$3/acl.after" >"$3/acl.restore"
  [ ! -s "$3/acl.restore" ] || setfacl --restore="$3/acl.restore"
}

# acl_grant_x DIR USER lets USER through DIR, keeping DIR's mask if it has
# one.
acl_grant_x() {
  if getfacl -p -s -- "$1" 2>/dev/null | grep -q '^mask::'; then
    setfacl -n -m "u:$2:x" -- "$1"
  else
    setfacl -m "u:$2:x" -- "$1"
  fi
}

# files_read gives the agent user read access to the folder and what is in
# it, now and later (default ACLs), and passage through its parents, never
# widening an ACL mask that was there.
files_read() {
  files_check_path
  cooldown files-read 600
  work=$(mktemp -d "$state/read.XXXXXX") || refuse "no room in $state"
  trap 'rm -rf "$work"' EXIT
  trap 'exit 143' TERM INT HUP
  out=$(acl_grant_read "$fpath" "$agent_user" "$work" 2>&1) || refuse "setting the ACLs on $fpath failed: $(printf '%s' "$out" | head -n 3 | tr '\n' ' ')"
  p=${fpath%/*}
  while [ -n "$p" ]; do
    as_agent test -x "$p" 2>/dev/null || acl_grant_x "$p" "$agent_user" || refuse "can't let Rowsafe through $p"
    p=${p%/*}
  done
  ok=1
  log "files-read $fpath (request $id): done"
}

# files_bad_names FILE prints the first path in FILE (one per line) that
# leaves the folder or goes into .ssh, .gnupg or .config/systemd.
files_bad_names() {
  grep -E '^/|(^|/)\.\.(/|$)|(^|/)\.ssh(/|$)|(^|/)\.gnupg(/|$)|(^|/)\.config/systemd(/|$)' "$1" | head -n 1
}

# files_put puts the staged files into the folder as its owner. The agent
# (whose files these are) is not trusted: root takes its own copy (read as
# the agent user, at most files_max bytes), checks it, and the owner (with
# the owner's own primary group) extracts that copy. Root never opens
# anything in the agent's directories or in PATH itself.
files_put() {
  files_check_path
  src=$files_staging/$fstage
  as_agent test -d "$src/tree" -a ! -L "$src/tree" -a ! -L "$src" 2>/dev/null || refuse "nothing is staged for restore $fstage"
  owner=$want_uid
  [ "$owner" != 0 ] || refuse "$fpath belongs to root: Rowsafe won't write there as root"
  [ "$owner" != "$agent_uid" ] || refuse "$fpath belongs to Rowsafe's own user, which puts files back by itself"
  group=$(getent passwd "$owner" | cut -d: -f4)
  case $group in '' | *[!0-9]*) refuse "uid $owner, which owns $fpath, has no entry in the user list" ;; esac
  as_owner() { setpriv --reuid="$owner" --regid="$group" --clear-groups -- "$@"; }
  # The staged size, as the agent sees it, before copying anything.
  size=$(as_agent du -s -B1 --apparent-size -- "$src/tree" 2>/dev/null | cut -f1)
  case $size in '' | *[!0-9]*) refuse "can't measure the staged files" ;; esac
  [ "$size" -le "$files_max" ] || refuse "the staged files are $size bytes, more than the $files_max bytes Rowsafe may put back at once"
  cooldown files-put 120
  work=$(mktemp -d "$state/put.XXXXXX") || refuse "no room for a private copy of the staged files"
  trap 'rm -rf "$work"' EXIT
  trap 'exit 143' TERM INT HUP
  # tar adds headers: the copy may exceed the files by 1/16 at most.
  cap=$((files_max + files_max / 16 + 1048576))
  { as_agent tar -C "$src/tree" -cSf - . 2>/dev/null; echo $? >"$work/rc"; } | head -c $((cap + 1)) >"$work/files.tar"
  [ "$(stat -c '%s' "$work/files.tar")" -le "$cap" ] || refuse "the staged files are more than the $files_max bytes Rowsafe may put back at once"
  [ "$(cat "$work/rc")" = 0 ] || refuse "reading the staged files failed"
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
  bad=$(files_bad_names "$work/names")
  [ -z "$bad" ] || refuse "a staged path leaves the folder or goes where Rowsafe never writes ($bad)"
  # Never write through a symbolic link in the folder: every folder on the
  # way to every file must be a real one (or not exist yet).
  awk '{
    sub(/\/$/, ""); sub(/^\.\//, "")
    if ($0 == "" || $0 == ".") next
    n = split($0, c, "/"); p = ""
    for (i = 1; i < n; i++) { p = (p == "" ? c[i] : p "/" c[i]); if (!(p in s)) { s[p] = 1; print p } }
    if (!($0 in s)) { s[$0] = 1; print $0 }
  }' "$work/names" >"$work/parents"
  # shellcheck disable=SC2016 # $1 expands in the inner shell
  link=$(as_owner sh -c '
    cd -- "$1" || { echo "?"; exit 0; }
    while IFS= read -r d; do
      if [ -L "$d" ]; then printf "%s\n" "$d"; exit 0; fi
    done' rowsafe-files-put "$fpath" <"$work/parents") || link="?"
  [ "$link" != "?" ] || refuse "can't check $fpath as its owner"
  [ -z "$link" ] || refuse "$fpath/$link is a symbolic link: Rowsafe won't write through it"
  if [ "$fmode" = mirror ] && as_agent test -f "$src/delete" -a ! -L "$src/delete"; then
    as_agent head -c 67108864 -- "$src/delete" >"$work/delete" 2>/dev/null || refuse "reading the list of files to remove failed"
    bad=$(files_bad_names "$work/delete")
    [ -z "$bad" ] || refuse "a path to remove leaves the folder or goes where Rowsafe never writes ($bad)"
    # Only files whose folder resolves to PATH or inside it, without a
    # symbolic link on the way, are removed.
    # shellcheck disable=SC2016 # $1 expands in the inner shell
    as_owner sh -c '
      cd -- "$1" || exit 1
      while IFS= read -r f; do
        case $f in "" | /* | ../* | */../* | */.. | .. | ./* | */./* | .) continue ;; esac
        d=$(dirname -- "$f")
        r=$(realpath -e -- "$d" 2>/dev/null) || continue
        if [ "$d" = . ]; then [ "$r" = "$1" ] || continue; else [ "$r" = "$1/$d" ] || continue; fi
        if [ -L "$f" ] || { [ -e "$f" ] && [ ! -d "$f" ]; }; then rm -f -- "$f"; fi
      done' rowsafe-files-put "$fpath" <"$work/delete" || refuse "removing the files added since from $fpath failed"
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
  log "files-put $fmode $fstage into $fpath as uid $owner gid $group (request $id): done"
}

# files_main answers a files request (rowsafe-files-helper.service, which
# rowsafe-files-helper.path starts). It has its own request and result
# files, and its own unit, so the rights it needs never widen the restart
# helper's.
files_main() {
  result_name=files-result
  state=${STATE_DIRECTORY:-/var/lib/rowsafe-files-helper}
  mkdir -p "$state" && chmod 0700 "$state"
  rm -rf "$state"/put.* "$state"/read.* # left by a run that was killed
  work_pw=$state/passwd
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
  have_request "$dir/request" || exit 0
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
  elif printf '%s\n' "$line" | grep -Eq '^[A-Za-z0-9_-]{1,64} mongodb-key-export [0-9]{1,5}$'; then
    # shellcheck disable=SC2086 # split the checked request into its fields
    set -- $line
    id=$1 action=$2
    mongo_key_export "$3"
    answer
    exit 0
  elif printf '%s\n' "$line" | grep -Eq '^[A-Za-z0-9_-]{1,64} mongodb-standby-config [0-9]{1,5} [A-Za-z0-9_-]{1,64} (key|nokey) ([0-9.]{7,15}|[0-9a-fA-F:]{2,39}|-)$'; then
    # shellcheck disable=SC2086
    set -- $line
    id=$1 action=$2
    mongo_standby_config "$3" "$4" "$5" "$6"
    answer
    exit 0
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
    check_root_file "$allow" "restarting or stopping the database from Rowsafe is not allowed on this server"
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
      refuse "$unit was restarted less than a minute ago; try again in a minute"
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
  check_root_file "$allow" "Rowsafe may not restart PostgreSQL on this server, which updating it needs (allow it on the server with: sudo rowsafe-allow restart)"
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
  update_allowed postgresql "installing PostgreSQL updates from Rowsafe is not allowed on this server (allow it on the server with: sudo rowsafe-allow updates)"
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
  update_allowed postgresql "installing PostgreSQL from Rowsafe is not allowed on this server (allow it on the server with: sudo rowsafe-allow updates)"
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
  update_allowed postgresql "upgrading PostgreSQL from Rowsafe is not allowed on this server (allow it on the server with: sudo rowsafe-allow updates)"
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
  update_allowed postgresql "upgrading PostgreSQL from Rowsafe is not allowed on this server (allow it on the server with: sudo rowsafe-allow updates)"
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
  update_allowed postgresql "upgrading PostgreSQL from Rowsafe is not allowed on this server (allow it on the server with: sudo rowsafe-allow updates)"
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
  update_allowed security "installing security updates from Rowsafe is not allowed on this server (allow it on the server with: sudo rowsafe-allow security-updates)"
  cooldown security-updates 300
  : >"$work_log"
  apt_refresh
  # Upgrades of installed packages from a security origin. The database
  # servers' own packages are left alone (their upgrade would restart them):
  # PostgreSQL's go through Update PostgreSQL, which saves a Mark, restarts
  # in a controlled way and checks archiving; MySQL's, MariaDB's, MongoDB's,
  # ClickHouse's, Redis's and Valkey's aren't installed from Rowsafe yet.
  list=$(apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null |
    awk '/^Inst [^ ]+ \[/ && /-security|Debian-Security/ { print $2 }' | sort -u)
  db_pkgs='^(postgresql-[0-9]+(-.+)?|mysql-server(-.+)?|mysql-community-server(-.+)?|percona-server-server(-.+)?|mariadb-server(-.+)?|mongodb-org-server|mongodb-org-mongos|clickhouse-server|clickhouse-common-static|(redis|valkey)-(server|sentinel|tools))$'
  held=$(printf '%s\n' "$list" | grep -E "$db_pkgs" | tr '\n' ' ')
  pkgs=$(printf '%s\n' "$list" | grep -Ev "$db_pkgs" | grep . | tr '\n' ' ')
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
  update_allowed reboot "rebooting the server from Rowsafe is not allowed here (allow it on the server with: sudo rowsafe-allow reboot)"
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

# ---------------------------------------------------------------- other engines

# db_engine sets db_engine and db_main (the installed server package) for
# $unit, the allowed unit of $port.
db_engine() {
  case $unit in
    mongod.service | mongodb.service)
      db_engine=mongodb
      set -- mongodb-org-server
      ;;
    clickhouse-server.service)
      db_engine=clickhouse
      set -- clickhouse-server
      ;;
    mysql.service | mysqld.service | mariadb.service | mysql@*.service | mysqld@*.service | mariadb@*.service)
      if [ -n "$(pkg_version mariadb-server)" ]; then
        db_engine=mariadb
        set -- mariadb-server
      else
        db_engine=mysql
        set -- mysql-community-server mysql-server-8.4 mysql-server-8.0 mysql-server percona-server-server
      fi
      ;;
    *) refuse "$unit is not a MySQL, MariaDB, MongoDB or ClickHouse service" ;;
  esac
  db_main=''
  for p in "$@"; do
    if [ -n "$(pkg_version "$p")" ]; then
      db_main=$p
      break
    fi
  done
  [ -n "$db_main" ] || refuse "the $db_engine server on port $port isn't installed from packages here"
}

# db_patterns sets the engine's packages: locked ones move only within the
# installed series; free ones (tools versioned on their own) are upgraded
# as they come.
db_patterns() {
  case $db_engine in
    mysql) locked='mysql-community-* mysql-server* mysql-client* mysql-common percona-server-*' free='percona-xtrabackup-*' ;;
    mariadb) locked='mariadb-* libmariadb3 libmariadbd19' free='' ;;
    mongodb) locked='mongodb-org mongodb-org-*' free='mongodb-mongosh mongodb-database-tools' ;;
    clickhouse) locked='clickhouse-*' free='' ;;
  esac
}

# series VERSION prints the release series of a package version:
# "1:10.11.9+maria~deb12" -> 10.11, "8.0.40-1debian12" -> 8.0.
series() { printf '%s\n' "$1" | sed -E 's/^[0-9]+://' | sed -nE 's/^([0-9]+\.[0-9]+).*/\1/p'; }

# newest_in PKG SERIES prints the newest available version of PKG in SERIES.
newest_in() {
  best=''
  for v in $(apt-cache madison "$1" 2>/dev/null | awk -F'|' '{ gsub(/ /, "", $2); print $2 }'); do
    [ "$(series "$v")" = "$2" ] || continue
    if [ -z "$best" ] || dpkg --compare-versions "$v" gt "$best"; then best=$v; fi
  done
  printf '%s' "$best"
}

# db_port checks $port's allowed unit and sets unit, db_engine, db_main.
db_port() {
  check_root_file "$allow" "Rowsafe may not restart the database on this server, which updating it needs (allow it on the server with: sudo rowsafe-allow restart)"
  unit=$(allowed_unit "$port")
  [ -n "$unit" ] || refuse "port $port is not in $allow: Rowsafe may not restart it, which updating it needs"
  case $unit in postgresql@*) refuse "port $port is PostgreSQL's: use the pg-* requests" ;; esac
  db_engine
  db_patterns
}

act_db_minor_update() {
  update_allowed database "installing database updates from Rowsafe is not allowed on this server (allow it on the server with: sudo rowsafe-allow updates)"
  db_port
  before=$(pkg_version "$db_main")
  ser=$(series "$before")
  [ -n "$ser" ] || refuse "can't tell the release series of $db_main $before"
  : >"$work_log"
  t0=$(active_since "$unit")
  was_active=0
  "$systemctl" is-active --quiet "$unit" 2>/dev/null && was_active=1
  apt_refresh
  specs='' pkgs=''
  for pat in $locked; do
    for p in $(installed_pkgs "$pat"); do
      case " $pkgs " in *" $p "*) continue ;; esac
      v=$(newest_in "$p" "$ser")
      [ -n "$v" ] || continue # not of this series (a shared library, a tool)
      pkgs="$pkgs $p"
      if dpkg --compare-versions "$v" gt "$(pkg_version "$p")"; then specs="$specs $p=$v"; fi
    done
  done
  for pat in $free; do
    for p in $(installed_pkgs "$pat"); do pkgs="$pkgs $p" specs="$specs $p"; done
  done
  if [ -n "$specs" ]; then
    log "updating $db_engine $ser:$specs (request $id)"
    # shellcheck disable=SC2086 # package specs built above from dpkg and apt
    apt_run install -y --only-upgrade $specs || refuse "installing the update failed: $(tail_log)"
  fi
  after=$(pkg_version "$db_main")
  add engine "$db_engine"
  add series "$ser"
  add from_package "$before"
  add package "$after"
  add packages "$pkgs"
  restarted=0
  if [ "$after" != "$before" ] && [ "$was_active" = 1 ]; then
    if [ "$(active_since "$unit")" = "$t0" ]; then
      # The packages didn't restart it: start the new binaries now.
      out=$(timeout 300 "$systemctl" restart "$unit" 2>&1 </dev/null) ||
        refuse "the update is installed, but restarting $unit failed: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)"
    fi
    restarted=1
  fi
  add restarted "$restarted"
  ok=1
  log "$db_engine on port $port: $before -> $after (restarted: $restarted)"
}

# db_datadir sets datadir, the data directory of the server on $port, from
# the server's own configuration (never from the request), and checks it:
# a real directory owned by the unit's own user, not a system directory.
db_datadir() {
  case $db_engine in
    mysql | mariadb) datadir=$(my_print_defaults --mysqld 2>/dev/null | sed -n 's/^--datadir=//p' | tail -n 1) ;;
    mongodb) datadir=$(awk '/^[[:space:]]*dbPath:/ { sub(/^[[:space:]]*dbPath:[[:space:]]*/, ""); gsub(/["\047]/, ""); print; exit }' /etc/mongod.conf 2>/dev/null) ;;
    clickhouse) datadir=$(clickhouse extract-from-config --config-file /etc/clickhouse-server/config.xml --key path 2>/dev/null) ;;
  esac
  [ -n "$datadir" ] || case $db_engine in
    mysql | mariadb) datadir=/var/lib/mysql ;;
    mongodb) datadir=/var/lib/mongodb ;;
    clickhouse) datadir=/var/lib/clickhouse ;;
  esac
  datadir=${datadir%/}
  case $datadir in /*) ;; *) refuse "the data directory \"$datadir\" is not an absolute path" ;; esac
  [ "$(realpath -e -- "$datadir" 2>/dev/null)" = "$datadir" ] || refuse "the data directory $datadir is missing or its path goes through a symbolic link"
  case $datadir in
    / | /etc | /etc/* | /usr | /usr/* | /var | /var/lib | /var/log | /home | /root | /root/* | /boot | /boot/* | \
      /bin | /bin/* | /sbin | /sbin/* | /lib | /lib/* | /lib64 | /lib64/* | /proc | /proc/* | /sys | /sys/* | /dev | /dev/* | /run | /tmp | /opt | /srv | /mnt | /media | \
      /var/lib/rowsafe | /var/lib/rowsafe/* | "$state" | "$state"/*)
      refuse "the data directory $datadir is a system directory"
      ;;
  esac
  svc_user=$("$systemctl" show -p User --value "$unit" 2>/dev/null)
  owner=$(stat -c %U -- "$datadir")
  [ -n "$svc_user" ] && [ "$owner" = "$svc_user" ] && [ "$owner" != root ] ||
    refuse "the data directory $datadir isn't owned by $unit's user (${svc_user:-none})"
}

# db_stop / db_start stop and start the server, waiting for systemd.
db_stop() { timeout 300 "$systemctl" stop "$unit" >>"$work_log" 2>&1 </dev/null; }
db_start() {
  "$systemctl" is-active --quiet "$unit" 2>/dev/null && return 0
  timeout 600 "$systemctl" start "$unit" >>"$work_log" 2>&1 </dev/null
}

# db_restore_data FROM puts FROM's entries back into the data directory,
# setting the current ones aside in $rec/after-<time> (renames on the same
# filesystem, a copy otherwise).
db_restore_data() {
  aside=$rec/after-$(date -u +%Y%m%dT%H%M%SZ)
  mkdir -p "$aside" || return 1
  for e_ in "$datadir"/* "$datadir"/.[!.]* "$datadir"/..?*; do
    [ -e "$e_" ] || [ -L "$e_" ] || continue
    mv -f -- "$e_" "$aside"/ || return 1
  done
  cp -a --reflink=auto -- "$1"/. "$datadir"/ || return 1
}

act_db_upgrade() {
  update_allowed database "upgrading the database from Rowsafe is not allowed on this server (allow it on the server with: sudo rowsafe-allow updates)"
  db_port
  db_datadir
  before=$(pkg_version "$db_main")
  from=$(series "$before")
  dpkg --compare-versions "$series_to" gt "$from" || refuse "$db_engine $series_to is not newer than $from"
  rec=$state/dbupgrade-$port
  [ ! -e "$rec" ] || refuse "an earlier upgrade of port $port is still kept: undo it or delete it first"
  : >"$work_log"
  apt_refresh
  # The target versions, and the installed ones (kept as packages for undo).
  specs='' olds=''
  for pat in $locked; do
    for p in $(installed_pkgs "$pat"); do
      case " $olds " in *" $p="*) continue ;; esac
      [ "$(series "$(pkg_version "$p")")" = "$from" ] || continue # not of this series (a shared library)
      v=$(newest_in "$p" "$series_to")
      [ -n "$v" ] || continue
      olds="$olds $p=$(pkg_version "$p")"
      specs="$specs $p=$v"
    done
  done
  case " $specs " in *" $db_main="*) ;; *) refuse "this server's package sources don't offer $db_engine $series_to (add the vendor's repository for it first)" ;; esac
  for pat in $free; do
    for p in $(installed_pkgs "$pat"); do specs="$specs $p"; done
  done
  mkdir -m 0700 "$rec" && mkdir "$rec/debs" "$rec/data" || refuse "can't create $rec"
  # Undo needs the installed packages again: download them now.
  # shellcheck disable=SC2086 # package=version specs from dpkg and apt
  (cd "$rec/debs" && apt_run download $olds) || {
    rm -rf "$rec"
    refuse "the installed packages ($before) can't be downloaded again, so the upgrade couldn't be undone; nothing changed"
  }
  need=$(du -sk -- "$datadir" | awk '{ print $1 }')
  free=$(df -Pk -- "$rec" | awk 'NR == 2 { print $4 }')
  if [ "${need:-0}" -gt 0 ] && [ "$((need + need / 10 + 262144))" -gt "${free:-0}" ]; then
    rm -rf "$rec"
    refuse "not enough free disk to keep a copy of the data for undo: $((need / 1024)) MB needed, $((free / 1024)) MB free"
  fi
  {
    echo "engine=$db_engine"
    echo "unit=$unit"
    echo "datadir=$datadir"
    echo "from_package=$before"
    echo "from_series=$from"
    echo "to_series=$series_to"
    echo "status=in_progress"
    echo "created_at=$(date +%s)"
  } >"$rec/record"
  log "upgrading $db_engine on port $port from $from to $series_to (request $id)"
  t_stop=$(date +%s)
  db_stop || {
    db_start
    rm -rf "$rec"
    refuse "stopping $unit failed: $(tail_log)"
  }
  if ! cp -a --reflink=auto -- "$datadir"/. "$rec/data"/; then
    db_start
    rm -rf "$rec"
    refuse "copying the data directory for undo failed; $db_engine runs as before"
  fi
  # shellcheck disable=SC2086
  if ! apt_timeout=3600 apt_run install -y $specs; then
    err_=$(tail_log)
    db_rollback_upgrade
    refuse "installing $db_engine $series_to failed ($err_); $db_engine $from runs again"
  fi
  if ! db_start; then
    err_=$(tail_log)
    db_rollback_upgrade
    refuse "$db_engine $series_to didn't start ($err_); $db_engine $from runs again on its data"
  fi
  if [ "$db_engine" = mariadb ]; then
    command -v mariadb-upgrade >/dev/null 2>&1 && timeout 3600 mariadb-upgrade >>"$work_log" 2>&1 </dev/null ||
      log "mariadb-upgrade: $(tail_log)"
  fi
  after=$(pkg_version "$db_main")
  sed -i 's/^status=.*/status=upgraded/' "$rec/record"
  echo "to_package=$after" >>"$rec/record"
  add engine "$db_engine"
  add from_package "$before"
  add package "$after"
  add packages "$specs"
  add datadir "$datadir"
  add kept_bytes "$((need * 1024))"
  add downtime_seconds "$(($(date +%s) - t_stop))"
  ok=1
}

# db_rollback_upgrade puts the copied data and the old packages back and
# starts the server (an upgrade that failed half-way, or an undo).
db_rollback_upgrade() {
  db_stop || true
  db_restore_data "$rec/data" || log "putting the data back failed: the copy is in $rec/data"
  # shellcheck disable=SC2086
  apt_timeout=3600 apt_run install -y --allow-downgrades "$rec"/debs/*.deb || log "reinstalling the old packages failed: $(tail_log)"
  db_start || log "starting $unit again failed: $(tail_log)"
}

# db_record PORT reads the record of the upgrade kept for PORT.
db_record() {
  rec=$state/dbupgrade-$1
  [ -f "$rec/record" ] || refuse "no upgrade of port $1 is kept"
  r_() { awk -F= -v k="$1" '$1 == k { print substr($0, length(k) + 2); exit }' "$rec/record"; }
}

act_db_upgrade_undo() {
  update_allowed database "upgrading the database from Rowsafe is not allowed on this server (allow it on the server with: sudo rowsafe-allow updates)"
  db_port
  db_record "$port"
  [ "$(r_ status)" = upgraded ] || refuse "the upgrade of port $port was undone already"
  [ "$(r_ unit)" = "$unit" ] || refuse "port $port runs as $unit now, not $(r_ unit) as when it was upgraded"
  db_datadir
  [ "$(r_ datadir)" = "$datadir" ] || refuse "the data directory is now $datadir, not $(r_ datadir) as when it was upgraded"
  : >"$work_log"
  t_stop=$(date +%s)
  log "undoing the upgrade of $db_engine on port $port (request $id)"
  db_stop || refuse "stopping $unit failed: $(tail_log)"
  db_restore_data "$rec/data" || {
    db_start
    refuse "putting the old data back failed: $(tail_log)"
  }
  rm -rf "$rec/data"
  # shellcheck disable=SC2086
  apt_timeout=3600 apt_run install -y --allow-downgrades "$rec"/debs/*.deb || refuse "reinstalling $db_engine $(r_ from_series) failed: $(tail_log)"
  db_start || refuse "$db_engine $(r_ from_series) didn't start: $(tail_log)"
  sed -i 's/^status=.*/status=undone/' "$rec/record"
  add engine "$db_engine"
  add package "$(pkg_version "$db_main")"
  add downtime_seconds "$(($(date +%s) - t_stop))"
  ok=1
}

act_db_upgrade_cleanup() {
  update_allowed database "upgrading the database from Rowsafe is not allowed on this server (allow it on the server with: sudo rowsafe-allow updates)"
  rec=$state/dbupgrade-$port
  [ -d "$rec" ] || {
    add freed_bytes 0
    ok=1
    return 0
  }
  freed=$(du -sk -- "$rec" | awk '{ print $1 * 1024 }')
  rm -rf -- "$rec"
  add freed_bytes "$freed"
  ok=1
}

update_main() {
  result_name=update-result
  have_request "$dir/update-request" || exit 0
  mkdir -p "$state"
  line=$(read_request "$dir/update-request")
  port='' major='' method='' start='' series_to=''
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
  elif printf '%s\n' "$line" | grep -Eq "^$rid db-upgrade [0-9]{1,5} [1-9][0-9]{0,2}\.[0-9]{1,2}\$"; then
    # shellcheck disable=SC2086
    set -- $line
    id=$1 action=$2 port=$3 series_to=$4
  elif printf '%s\n' "$line" | grep -Eq "^$rid (db-minor-update|db-upgrade-undo|db-upgrade-cleanup) [0-9]{1,5}\$"; then
    # shellcheck disable=SC2086
    set -- $line
    id=$1 action=$2 port=$3
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
    db-minor-update) act_db_minor_update ;;
    db-upgrade) act_db_upgrade ;;
    db-upgrade-undo) act_db_upgrade_undo ;;
    db-upgrade-cleanup) act_db_upgrade_cleanup ;;
  esac
  answer
}

case $mode in
  update) update_main ;;
  files) files_main ;;
  *) restart_main ;;
esac
ROWSAFE_RESTART_HELPER_EOF
    HELPER_CHANGED=1
  fi
}

# agent_user_dropin UNIT gives a helper UNIT the agent's user when it isn't
# postgres (MySQL: mysql; MongoDB, ClickHouse: rowsafe): the helper reads
# and removes requests with that user's privileges. Returns 0 when the
# drop-in changed.
agent_user_dropin() {
  _dd=/etc/systemd/system/$1.d
  _df=$_dd/10-agent-user.conf
  if [ "$AGENT_USER" = postgres ]; then
    [ -e "$_df" ] || return 1
    rm -f "$_df"
    rmdir "$_dd" 2>/dev/null || true
    return 0
  fi
  install -d -m 0755 -o root -g root "$_dd"
  printf '# Written by the Rowsafe installer: the agent runs as %s on this server.\n[Service]\nEnvironment=ROWSAFE_AGENT_USER=%s\n' \
    "$AGENT_USER" "$AGENT_USER" | write_file "$_df" 0644 root:root
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
Unit=rowsafe-pg-restart.service

[Install]
WantedBy=multi-user.target
ROWSAFE_RESTART_PATH_EOF
    _changed=1
  fi
  if agent_user_dropin rowsafe-pg-restart.service; then _changed=1; fi
  if systemd_running; then
    [ "$_changed" = 0 ] || systemctl daemon-reload
    systemctl enable --now --quiet rowsafe-pg-restart.path
  else
    warn "systemd is not running here; the restart helper was installed but cannot be enabled"
  fi
}

remove_restart_helper() {
  remove_update_units # they run the same helper
  [ -e "$RESTART_PATH_FILE" ] || [ -e "$RESTART_SERVICE_FILE" ] || [ -e "$RESTART_HELPER" ] || return 0
  if systemd_running; then
    systemctl disable --now --quiet rowsafe-pg-restart.path 2>/dev/null || true
  fi
  rm -f "$RESTART_PATH_FILE" "$RESTART_SERVICE_FILE"
  rm -f /etc/systemd/system/rowsafe-pg-restart.service.d/10-agent-user.conf
  rmdir /etc/systemd/system/rowsafe-pg-restart.service.d 2>/dev/null || true
  [ -e "$POOLER_PATH_FILE" ] || [ -e "$FILES_PATH_FILE" ] || rm -f "$RESTART_HELPER" # PgBouncer or files still use it
  rmdir "${RESTART_HELPER%/*}" 2>/dev/null || true
  if systemd_running; then systemctl daemon-reload; fi
}

# restart_pairs prints "PORT UNIT" for the discovered clusters with a
# systemd unit (the ones a restart helper can restart).
restart_pairs() {
  if [ ! -f "$TMP/clusters" ]; then
    root_restart_pairs
    return 0
  fi
  [ -s "$TMP/clusters" ] || return 0
  awk -F '\t' -v re="$DB_UNIT_RE" '$1 ~ /^[1-9][0-9]*$/ && $12 ~ re &&
    (($14 == "" || $14 == "-" || $14 == "postgresql") == ($12 ~ /^postgresql@/)) { print $1, $12 }' "$TMP/clusters"
}

# root_restart_pairs prints "PORT UNIT" for the clusters root finds itself
# (pg_lsclusters, Debian's postgresql@MAJOR-NAME units), where the agent's
# discovery didn't run (--permissions; root never needs the agent for it).
root_restart_pairs() {
  if [ "$HOST_ENGINE" != postgresql ]; then
    # MySQL, MariaDB, MongoDB, ClickHouse: the agent's own discovery (as the
    # agent user), only the units the restart helper accepts.
    agent_run setup discover 2>/dev/null |
      awk -F '\t' -v re="$DB_UNIT_RE" '$1 ~ /^[1-9][0-9]*$/ && $12 ~ re && $12 !~ /^postgresql@/ { print $1, $12 }'
    return 0
  fi
  have pg_lsclusters || return 0
  pg_lsclusters -h 2>/dev/null |
    awk '$1 ~ /^[0-9]+$/ && $2 ~ /^[A-Za-z0-9_.-]+$/ && $3 ~ /^[1-9][0-9]*$/ { print $3, "postgresql@" $1 "-" $2 ".service" }'
}

# restart_allowed PORT: is PORT in the allow list?
restart_allowed() {
  [ -f "$RESTART_ALLOW_FILE" ] && awk -v p="$1" '$1 == p { f = 1 } END { exit !f }' "$RESTART_ALLOW_FILE"
}

allow_restarts() {
  _pairs=$(restart_pairs)
  if [ -z "$_pairs" ]; then
    warn "found no systemd service running $(engine_label) here, so restarting or stopping it from Rowsafe stays off"
    return 0
  fi
  {
    echo "# Databases ($(engine_label)) Rowsafe may restart or stop when someone asks"
    echo "# (Restart and Rewind in the dashboard, \`rowsafe restart\`), only when they"
    echo "# confirm. Written by the installer (root); turn this off with:"
    echo "# sudo rowsafe-allow --remove restart"
    echo "# PORT UNIT"
    printf '%s\n' "$_pairs"
  } | write_file "$RESTART_ALLOW_FILE" 0644 root:root || true
  install_restart_helper
  perm_ok "Rowsafe may restart or stop $(engine_label) when you ask (Restart, Rewind), only when someone confirms"
}

disallow_restarts() {
  create_clusters_allowed || remove_restart_helper # forks still use the helper
  rm -f "$UPDATES_ALLOW_FILE" # updates need the helper too
  if [ -d "$CONFIG_DIR" ]; then
    {
      echo "# Restarting or stopping the database from Rowsafe is off on this server."
      echo "# Turn it on with: sudo rowsafe-allow restart"
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
      perm_ok "restarting or stopping $(engine_label) from Rowsafe is off"
      ;;
    *)
      if [ -f "$RESTART_ALLOW_FILE" ]; then
        if grep -q '^[0-9]' "$RESTART_ALLOW_FILE"; then allow_restarts; fi
        return 0
      fi
      [ "$TTY" = 1 ] && [ -n "$(restart_pairs)" ] || return 0
      if perm_ask "Restart or stop $(engine_label), when someone clicks Restart or Rewind?" y; then
        allow_restarts
      else
        disallow_restarts
        perm_note "OK: Rowsafe can't restart or stop $(engine_label)"
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
    echo "# installer (root); turn this off with: sudo rowsafe-allow --remove create-cluster"
    echo "ports $CREATE_PORTS"
  } | write_file "$CREATE_ALLOW_FILE" 0644 root:root || true
  install_create_cluster
  install_restart_helper
  as_agent mkdir -p -m 0700 "$RESTART_DIR"
  perm_ok "Rowsafe may create a new PostgreSQL cluster (ports $CREATE_PORTS) when you fork a database here"
}

disallow_create_clusters() {
  remove_create_cluster
  if [ -d "$CONFIG_DIR" ]; then
    {
      echo "# Creating PostgreSQL clusters for forks is off on this server."
      echo "# Turn it on with: sudo rowsafe-allow create-cluster"
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
      perm_ok "creating PostgreSQL clusters for forks is off"
      ;;
    *)
      if [ -f "$CREATE_ALLOW_FILE" ]; then
        if create_clusters_allowed; then allow_create_clusters; fi
        return 0
      fi
      # Asked only where restarts are allowed: the created cluster is
      # stopped and started by the same helper.
      [ "$TTY" = 1 ] && command -v pg_createcluster >/dev/null 2>&1 && grep -qs '^[0-9]' "$RESTART_ALLOW_FILE" || return 0
      if perm_ask "Create a new PostgreSQL cluster here (ports $CREATE_PORTS), when someone forks a database to this server?" y; then
        allow_create_clusters
      else
        disallow_create_clusters
        perm_note "OK: forks to this server go into an empty cluster you create"
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
  if agent_user_dropin rowsafe-pg-update.service; then _changed=1; fi
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
  rm -f "$UPDATE_PATH_FILE" "$UPDATE_SERVICE_FILE" /etc/systemd/system/rowsafe-pg-update.service.d/10-agent-user.conf
  rmdir /etc/systemd/system/rowsafe-pg-update.service.d 2>/dev/null || true
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
      *yes*) warn "installing updates or rebooting from Rowsafe needs restarts allowed too (--allow-restart: the same helper does it); left off" ;;
    esac
    remove_update_units
    [ ! -f "$UPDATES_ALLOW_FILE" ] || rm -f "$UPDATES_ALLOW_FILE"
    return 0
  fi
  [ -f "$UPDATES_ALLOW_FILE" ] || [ "$TTY" = 1 ] || [ -n "$ALLOW_UPDATES$ALLOW_SECURITY$ALLOW_REBOOT" ] || return 0
  # (The questions run in subshells: the heading comes first, here.)
  if [ ! -f "$UPDATES_ALLOW_FILE" ] && [ "$TTY" = 1 ] && { [ -z "$ALLOW_UPDATES" ] || [ -z "$ALLOW_SECURITY" ]; }; then
    perm_intro
  fi
  # PostgreSQL's word is postgresql; MySQL's, MariaDB's, MongoDB's and
  # ClickHouse's is database (the helper's db-* requests).
  _uw=postgresql
  [ "$HOST_ENGINE" = postgresql ] || _uw=database
  case $HOST_ENGINE in
    redis | valkey) # not from Rowsafe yet (the helper's db-* requests don't cover them)
      _pg=no
      [ "$ALLOW_UPDATES" != yes ] || warn "Rowsafe doesn't install $(engine_label) updates yet; left off"
      ;;
    *) _pg=$(decide_update "$ALLOW_UPDATES" "$_uw" "Install $(engine_label) updates and upgrades, when someone clicks Update? A Mark is saved first." y) ;;
  esac
  _sec=$(decide_update "$ALLOW_SECURITY" security "Install this server's security updates, when someone clicks Install?" n)
  _reboot=no
  if [ "$_sec" = yes ]; then
    _reboot=$(decide_update "$ALLOW_REBOOT" reboot "Reboot this server, when someone clicks Reboot? A Mark is saved first." n)
  elif [ "$ALLOW_REBOOT" = yes ]; then
    warn "rebooting from Rowsafe goes with security updates (--allow-security-updates); left off"
  fi
  {
    echo "# What Rowsafe may install or do on this server when someone clicks it in"
    echo "# the dashboard and confirms. Written by the installer (root); change it"
    echo "# with sudo rowsafe-allow updates (security-updates, reboot), and"
    echo "# sudo rowsafe-allow --remove updates (...)."
    if [ "$_pg" = yes ]; then
      if [ "$_uw" = postgresql ]; then
        echo "postgresql   # PostgreSQL minor updates and major upgrades (clusters in restart-allowed)"
      else
        echo "database     # $(engine_label) updates and upgrades (the servers in restart-allowed)"
      fi
    fi
    [ "$_sec" != yes ] || echo "security     # security updates (the database servers' own packages excepted)"
    [ "$_reboot" != yes ] || echo "reboot       # rebooting the server"
  } | write_file "$UPDATES_ALLOW_FILE" 0644 root:root || true
  if [ "$_pg$_sec$_reboot" = nonono ]; then
    remove_update_units
    perm_note "OK: Rowsafe can't install updates or reboot here"
    return 0
  fi
  install_update_units
  [ "$_pg" != yes ] || perm_ok "Rowsafe may install $(engine_label) updates and upgrade $(engine_label) when you click Update or Upgrade and confirm"
  [ "$_sec" != yes ] || perm_ok "Rowsafe may install security updates when you click Install and confirm"
  [ "$_reboot" != yes ] || perm_ok "Rowsafe may reboot this server when you click Reboot and confirm"
}

# ------------------------------------------------------------------ tuning

# With root's permission (--allow-tuning, or yes at the question), a person
# can change MongoDB's or ClickHouse's settings from Tuning in the
# dashboard. The agent (unprivileged) writes a request to $TUNING_DIR;
# rowsafe-tuning.path starts rowsafe-tuning.service, which runs root's copy
# of the agent ($PERMISSIONS_HELPER tuning-apply). It accepts only a fixed
# list of settings with plain numbers or fixed words, and writes only
# ClickHouse's config.d/rowsafe-tuning.xml and users.d/rowsafe-tuning.xml,
# or those settings' keys in the MongoDB configuration file listed in
# $TUNING_ALLOW_FILE (a copy kept first; MongoDB reads it when it starts).

# mongodb_config_file prints mongod's configuration file (from its systemd
# unit, else /etc/mongod.conf), nothing when there is none.
mongodb_config_file() {
  _mc=''
  if have systemctl; then
    _mc=$(systemctl show -p ExecStart --value mongod 2>/dev/null | tr ' ;' '\n\n' | awk 'p { print; exit } /^(--config|-f)$/ { p = 1 } /^--config=/ { sub(/^--config=/, ""); print; exit }')
  fi
  [ -n "$_mc" ] || _mc=/etc/mongod.conf
  case $_mc in /*) ;; *) return 0 ;; esac
  [ -f "$_mc" ] && [ ! -L "$_mc" ] && printf '%s\n' "$_mc"
}

# tuning_target prints the allow file's line for this server.
tuning_target() {
  case $HOST_ENGINE in
    mongodb) _t=$(mongodb_config_file) && [ -n "$_t" ] && echo "mongodb $_t" ;;
    clickhouse) [ -f /etc/clickhouse-server/config.xml ] && echo "clickhouse /etc/clickhouse-server" ;;
  esac
}

install_tuning_helper() {
  [ -x "$PERMISSIONS_HELPER" ] || install_permissions_helper
  [ -x "$PERMISSIONS_HELPER" ] || { warn "Tuning needs root's copy of the agent ($PERMISSIONS_HELPER); run the installer again"; return 1; }
  as_agent mkdir -p -m 0700 "$TUNING_DIR"
  _where=$(awk 'NF == 2 && $1 !~ /^#/ { print $2; exit }' "$TUNING_ALLOW_FILE" 2>/dev/null)
  [ -n "$_where" ] || return 1
  _rw=$_where
  case $HOST_ENGINE in
    clickhouse)
      install -d -m 0755 -o root -g root "$_where/config.d" "$_where/users.d"
      _rw="$_where/config.d $_where/users.d"
      ;;
    *) _rw=${_where%/*} ;;
  esac
  _changed=0
  if sed -e "s/@AGENT_USER@/$AGENT_USER/" -e "s|@READ_WRITE@|$_rw|" <<'ROWSAFE_TUNING_SERVICE_EOF' | write_file "$TUNING_SERVICE_FILE" 0644 root:root; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-tuning.service: writes the MongoDB or ClickHouse settings a person
# changed in Rowsafe (Tuning) into Rowsafe's own files, only where root
# allowed it (/etc/rowsafe/tuning-allowed, sudo rowsafe-allow tuning).
# Started by rowsafe-tuning.path; installed by https://rowsafe.sh/install.

[Unit]
Description=Rowsafe: write the database settings a person changed (Tuning)
Documentation=https://rowsafe.sh/docs/guides/tuning
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/rowsafe/rowsafe-permissions tuning-apply
Environment=ROWSAFE_AGENT_USER=@AGENT_USER@
TimeoutStartSec=2min
RuntimeDirectory=rowsafe-tuning
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
StateDirectory=rowsafe-tuning
StateDirectoryMode=0700
UMask=0022
# It writes only the settings files root listed, and its own state.
ProtectSystem=strict
ReadWritePaths=@READ_WRITE@
NoNewPrivileges=yes
RestrictSUIDSGID=yes
ProtectHome=yes
PrivateTmp=yes
PrivateNetwork=yes
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
ROWSAFE_TUNING_SERVICE_EOF
    _changed=1
  fi
  if write_file "$TUNING_PATH_FILE" 0644 root:root <<'ROWSAFE_TUNING_PATH_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-tuning.path: starts rowsafe-tuning.service when the Rowsafe agent
# hands over a settings change (Tuning). Installed by
# https://rowsafe.sh/install only when root allowed it (--allow-tuning).

[Unit]
Description=Rowsafe: watch for database settings changes (Tuning)

[Path]
PathExists=/var/lib/rowsafe/tuning/request
Unit=rowsafe-tuning.service

[Install]
WantedBy=multi-user.target
ROWSAFE_TUNING_PATH_EOF
    _changed=1
  fi
  if systemd_running; then
    [ "$_changed" = 0 ] || systemctl daemon-reload
    systemctl enable --now --quiet rowsafe-tuning.path
  fi
}

remove_tuning_helper() {
  [ -e "$TUNING_PATH_FILE" ] || [ -e "$TUNING_SERVICE_FILE" ] || return 0
  if systemd_running; then systemctl disable --now --quiet rowsafe-tuning.path 2>/dev/null || true; fi
  rm -f "$TUNING_PATH_FILE" "$TUNING_SERVICE_FILE"
  rm -rf /run/rowsafe-tuning
  if systemd_running; then systemctl daemon-reload; fi
}

allow_tuning() {
  _why=$(perm_why tuning)
  if [ -n "$_why" ]; then
    warn "Tuning stays off for Rowsafe: $_why"
    return 0
  fi
  {
    echo "# The settings files Rowsafe may write when someone changes settings under"
    echo "# Tuning (only its own: ClickHouse's config.d and users.d rowsafe-tuning.xml,"
    echo "# or a few keys of MongoDB's configuration file). Written by the installer"
    echo "# (root); turn this off with: sudo rowsafe-allow --remove tuning"
    echo "# ENGINE PATH"
    tuning_target
  } | write_file "$TUNING_ALLOW_FILE" 0644 root:root || true
  install_tuning_helper || return 0
  perm_ok "Rowsafe may change $(engine_label)'s settings when you ask (Tuning), only in its own files"
}

disallow_tuning() {
  remove_tuning_helper
  if [ -d "$CONFIG_DIR" ]; then
    {
      echo "# Changing database settings from Rowsafe (Tuning) is off."
      echo "# Turn it on with: sudo rowsafe-allow tuning"
    } | write_file "$TUNING_ALLOW_FILE" 0644 root:root || true
  fi
}

# tuning_access applies --allow-tuning / --no-allow-tuning, or asks once on
# a terminal (default no) where it applies (MongoDB, ClickHouse).
tuning_access() {
  case $ALLOW_TUNING in
    yes) allow_tuning ;;
    no)
      disallow_tuning
      perm_ok "changing $(engine_label)'s settings from Rowsafe is off"
      ;;
    *)
      [ -z "$(perm_why tuning)" ] || return 0
      if [ "$(perm_state tuning)" = yes ]; then
        install_tuning_helper || true
        return 0
      fi
      [ -f "$TUNING_ALLOW_FILE" ] && return 0 # a no, kept
      [ "$TTY" = 1 ] || return 0
      if perm_ask "Let Rowsafe change $(engine_label)'s settings when someone picks them under Tuning? It writes only its own settings file." n; then
        allow_tuning
      else
        disallow_tuning
        perm_note "OK: Rowsafe won't change $(engine_label)'s settings"
      fi
      ;;
  esac
}

# ------------------------------------------------------------ sqlite-modes

# With root's permission (--allow-sqlite-modes, or yes at the question), a
# person can close the SQLite files to the server's other users from
# Security in the dashboard (Apply fix). The agent (unprivileged) writes a
# request to $SQLITE_MODES_DIR; rowsafe-sqlite-modes.path starts
# rowsafe-sqlite-modes.service, which runs root's copy of the agent
# ($PERMISSIONS_HELPER sqlite-modes-apply). It only removes other users'
# access (o-rwx on the files, o-w on the folder), and only from the files
# listed in $SQLITE_LIST, their -wal, -shm and -journal files, copies of
# them next to them (SQLite files named like them) and their folders:
# never an owner, a group or an ACL entry.

# sqlite_modes_dirs prints the folders of the listed SQLite files: the only
# places the helper may change (its unit's ReadWritePaths).
sqlite_modes_dirs() {
  [ -f "$SQLITE_LIST" ] || return 0
  while IFS= read -r _f; do
    sqlite_path_ok "$_f" || continue
    printf '%s\n' "${_f%/*}"
  done <"$SQLITE_LIST" | sort -u
}

install_sqlite_modes_helper() {
  [ -x "$PERMISSIONS_HELPER" ] || install_permissions_helper
  [ -x "$PERMISSIONS_HELPER" ] || { warn "closing SQLite files to other users needs root's copy of the agent ($PERMISSIONS_HELPER); run the installer again"; return 1; }
  as_agent mkdir -p -m 0700 "$SQLITE_MODES_DIR"
  _rw=''
  for _d in $(sqlite_modes_dirs); do _rw="$_rw -$_d"; done
  _rwline="# No SQLite file is listed yet, so it can change nothing."
  [ -z "$_rw" ] || _rwline="ReadWritePaths=${_rw# }"
  _changed=0
  if sed -e "s/@AGENT_USER@/$AGENT_USER/" -e "s|@READ_WRITE@|$_rwline|" <<'ROWSAFE_SQLITE_MODES_SERVICE_EOF' | write_file "$SQLITE_MODES_SERVICE_FILE" 0644 root:root; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-sqlite-modes.service: closes SQLite files to the server's other
# users when a person clicks Apply fix under Security in Rowsafe: only the
# files root listed in /etc/rowsafe/sqlite-paths, their -wal, -shm and
# -journal files, copies of them next to them and their folders, and only
# others' access (never an owner, a group or an ACL entry). Allowed by root
# (/etc/rowsafe/sqlite-modes-allowed, sudo rowsafe-allow sqlite-modes).
# Started by rowsafe-sqlite-modes.path; installed by https://rowsafe.sh/install.

[Unit]
Description=Rowsafe: close SQLite files to other users (Security)
Documentation=https://rowsafe.sh/docs/guides/security
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/rowsafe/rowsafe-permissions sqlite-modes-apply
Environment=ROWSAFE_AGENT_USER=@AGENT_USER@
TimeoutStartSec=2min
RuntimeDirectory=rowsafe-sqlite-modes
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
UMask=0022
# It changes permissions only in the listed SQLite files' folders.
ProtectSystem=strict
ProtectHome=read-only
@READ_WRITE@
NoNewPrivileges=yes
RestrictSUIDSGID=yes
PrivateTmp=yes
PrivateNetwork=yes
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
ROWSAFE_SQLITE_MODES_SERVICE_EOF
    _changed=1
  fi
  if write_file "$SQLITE_MODES_PATH_FILE" 0644 root:root <<'ROWSAFE_SQLITE_MODES_PATH_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-sqlite-modes.path: starts rowsafe-sqlite-modes.service when the
# Rowsafe agent asks to close SQLite files to other users. Installed by
# https://rowsafe.sh/install only when root allowed it (--allow-sqlite-modes).

[Unit]
Description=Rowsafe: watch for SQLite files to close to other users (Security)

[Path]
PathExists=/var/lib/rowsafe/sqlite-modes/request
Unit=rowsafe-sqlite-modes.service

[Install]
WantedBy=multi-user.target
ROWSAFE_SQLITE_MODES_PATH_EOF
    _changed=1
  fi
  if systemd_running; then
    [ "$_changed" = 0 ] || systemctl daemon-reload
    systemctl enable --now --quiet rowsafe-sqlite-modes.path
  fi
}

remove_sqlite_modes_helper() {
  [ -e "$SQLITE_MODES_PATH_FILE" ] || [ -e "$SQLITE_MODES_SERVICE_FILE" ] || return 0
  if systemd_running; then systemctl disable --now --quiet rowsafe-sqlite-modes.path 2>/dev/null || true; fi
  rm -f "$SQLITE_MODES_PATH_FILE" "$SQLITE_MODES_SERVICE_FILE"
  rm -rf /run/rowsafe-sqlite-modes
  if systemd_running; then systemctl daemon-reload; fi
}

allow_sqlite_modes() {
  _why=$(perm_why sqlite-modes)
  if [ -n "$_why" ]; then
    warn "closing SQLite files to other users stays off for Rowsafe: $_why"
    return 0
  fi
  {
    echo "# Rowsafe may close the SQLite files listed in $SQLITE_LIST to the server's"
    echo "# other users when someone clicks Apply fix under Security: others lose read"
    echo "# and write on the files, their -wal, -shm and -journal files and copies next"
    echo "# to them, and write on their folders. Owners, groups and ACLs stay."
    echo "# Written by the installer (root); turn this off with:"
    echo "# sudo rowsafe-allow --remove sqlite-modes"
    echo "sqlite-paths"
  } | write_file "$SQLITE_MODES_ALLOW_FILE" 0644 root:root || true
  install_sqlite_modes_helper || return 0
  perm_ok "Rowsafe may close the SQLite files to other users when you click Apply fix (Security)"
}

disallow_sqlite_modes() {
  remove_sqlite_modes_helper
  if [ -d "$CONFIG_DIR" ]; then
    {
      echo "# Closing SQLite files to other users from Rowsafe (Security) is off."
      echo "# Turn it on with: sudo rowsafe-allow sqlite-modes"
    } | write_file "$SQLITE_MODES_ALLOW_FILE" 0644 root:root || true
  fi
}

# sqlite_modes_access applies --allow-sqlite-modes / --no-allow-sqlite-modes,
# or asks once on a terminal (default yes) where SQLite files are listed. A
# yes kept refreshes the folders the helper may change (files listed since).
sqlite_modes_access() {
  case $ALLOW_SQLITE_MODES in
    yes) allow_sqlite_modes ;;
    no)
      disallow_sqlite_modes
      perm_ok "closing SQLite files to other users from Rowsafe is off"
      ;;
    *)
      [ -z "$(perm_why sqlite-modes)" ] || return 0
      if [ "$(perm_state sqlite-modes)" = yes ]; then
        install_sqlite_modes_helper || true
        return 0
      fi
      [ -f "$SQLITE_MODES_ALLOW_FILE" ] && return 0 # a no, kept
      [ "$TTY" = 1 ] || return 0
      if perm_ask "Let Rowsafe close the SQLite files to this server's other users when someone clicks Apply fix under Security? Only others' access goes; owners, groups and your app's access stay." y; then
        allow_sqlite_modes
      else
        disallow_sqlite_modes
        perm_note "OK: Rowsafe won't change the SQLite files' permissions"
      fi
      ;;
  esac
}

# ---------------------------------------------------------------- firewall

# With root's permission (--allow-firewall, or yes at the question), a
# person can have Rowsafe let only chosen addresses reach PostgreSQL's port
# (Security in the dashboard): the agent (unprivileged) writes a request to
# $FIREWALL_DIR, rowsafe-firewall.path starts the root helper, and the
# helper changes only its own nftables table, only for a port listed in
# $FIREWALL_ALLOW_FILE. It runs in a unit of its own: the restart helper's
# sandbox has no network access and stays that way.

# write_firewall_helper installs the helper itself (FW_HELPER_CHANGED=1
# when it changed).
write_firewall_helper() {
  install -d -m 0755 -o root -g root "${FIREWALL_HELPER%/*}"
  FW_HELPER_CHANGED=0
  if write_file "$FIREWALL_HELPER" 0755 root:root <<'ROWSAFE_FIREWALL_HELPER_EOF'; then
#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# rowsafe-firewall: lets only chosen addresses reach a database's port, when
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
# matches only the allowed database ports: connections to such a port
# from anywhere but the allowed addresses and the server itself are
# dropped; SSH (unless root allowed it, see "server" below) and every other
# port are never touched. The whole table is
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
#
# Servers Rowsafe creates in a cloud whose own firewall Rowsafe can't set
# (an OVHcloud project without security groups) get a firewall on the server
# itself: the installer's --firewall-ssh adds the line "ssh" to root's allow
# list, and only then the action "server" ("ID server PORT") sets both allow
# lists at once: /var/lib/rowsafe/firewall/addresses for PostgreSQL's PORT
# and /var/lib/rowsafe/firewall/ssh-addresses for SSH (the ports sshd uses,
# found here, never taken from the agent), 0 to 64 addresses each (none =
# closed to everyone; 0.0.0.0/0 and ::/0 = open to everyone). Connections
# from the server itself and replies to connections already made (the
# agent's own, which only dials out) are always let through; every other
# port, and outbound traffic, stay as they are. It is confirmed and rolled
# back like apply, and kept as ssh-allowed and ssh-ports next to port-PORT.

set -u
set -f
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
dir=${ROWSAFE_FIREWALL_DIR:-/var/lib/rowsafe/firewall}
out_dir=${RUNTIME_DIRECTORY:-/run/rowsafe-firewall}
allow=${ROWSAFE_FIREWALL_ALLOW:-/etc/rowsafe/firewall-allowed}
state=${STATE_DIRECTORY:-/var/lib/rowsafe-firewall}
agent_user=${ROWSAFE_AGENT_USER:-postgres}
# The users database servers run as (PostgreSQL's is the agent's own): a
# port is only accepted while one of them listens on it.
db_users=${ROWSAFE_DB_USERS:-"$agent_user postgres mysql mongodb mongod clickhouse redis valkey"}
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

# allow_ok: root's allow list is a regular file only root can write.
allow_ok() {
  [ -f "$allow" ] && [ ! -L "$allow" ] || return 1
  [ "$(stat -c '%u' "$allow")" = 0 ] || return 1
  case $(stat -c '%A' "$allow") in ?????w???? | ????????w?) return 1 ;; esac
}

# listed_port PORT: in root's allow list (ports compare as strings).
listed_port() {
  allow_ok || return 1
  awk -v p="$1" '$1 "" == p "" { f = 1 } END { exit !f }' "$allow"
}

# listed_ssh: root allowed SSH's allow list too (the line "ssh", written by
# the installer's --firewall-ssh on servers Rowsafe creates).
listed_ssh() {
  allow_ok || return 1
  awk '$1 == "ssh" { f = 1 } END { exit !f }' "$allow"
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

# ssh_ports prints the ports sshd uses (or is set to); 22 when none is
# found (sshd started by its socket unit shows up as systemd).
ssh_ports() {
  _sp=$({
    "$sshd" -T 2>/dev/null | awk '$1 == "port" { print $2 }'
    "$ss" -ltnHp 2>/dev/null | awk '/"sshd"/ { n = split($4, a, ":"); print a[n] }'
  } | grep -Ex '[1-9][0-9]{0,4}' | awk '$1 <= 65535' | sort -un)
  if [ -n "$_sp" ]; then printf '%s\n' "$_sp"; else echo 22; fi
}

# ssh_rule prints SSH's rule file (ssh-pending replaces ssh-allowed while it
# waits for its confirmation), or nothing when SSH is not Rowsafe's.
ssh_rule() {
  listed_ssh || return 0
  if [ -f "$state/ssh-pending" ]; then
    echo "$state/ssh-pending"
  elif [ -f "$state/ssh-allowed" ]; then
    echo "$state/ssh-allowed"
  fi
}

# rule_lines PORTS FILE prints the rules letting only FILE's addresses reach
# PORTS (one port, or several separated by commas).
rule_lines() {
  _d=$1
  case $_d in *,*) _d="{ $_d }" ;; esac
  v4=$(grep -v ':' "$2" | grep -vx '0.0.0.0/0' | paste -sd, -)
  v6=$(grep ':' "$2" | grep -vx '::/0' | paste -sd, -)
  if grep -qx '0.0.0.0/0' "$2"; then
    echo "    tcp dport $_d meta nfproto ipv4 accept"
  elif [ -n "$v4" ]; then
    echo "    tcp dport $_d ip saddr { $v4 } accept"
  fi
  if grep -qx '::/0' "$2"; then
    echo "    tcp dport $_d meta nfproto ipv6 accept"
  elif [ -n "$v6" ]; then
    echo "    tcp dport $_d ip6 saddr { $v6 } accept"
  fi
  echo "    tcp dport $_d drop"
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
  sf=$(ssh_rule)
  sp=$(paste -sd, - <"$state/ssh-ports" 2>/dev/null)
  if [ -n "$sf" ] && [ -n "$sp" ]; then
    # Replies to connections already made (the agent's, an SSH session).
    echo "    ct state established,related accept"
    rule_lines "$sp" "$sf"
  fi
  for f in $(rule_files); do
    p=${f##*/}
    p=${p#*-}
    valid_port "$p" || continue
    rule_lines "$p" "$f"
  done
  echo "  }"
  echo "}"
}

loaded() { "$nft" list table inet rowsafe >/dev/null 2>&1; }

# load applies the rules in $state (or removes the table when none are
# left), and checks nftables holds them.
load() {
  if [ -n "$(rule_files)$(ssh_rule)" ]; then
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
  find "$out_dir" -maxdepth 1 -type f \( -name 'port-*' -o -name ssh \) -exec rm -f {} + 2>/dev/null
  l=0
  if loaded; then l=1; fi
  if listed_ssh && [ -f "$state/ssh-allowed" ] && tmp=$(mktemp "$out_dir/.ssh.XXXXXX"); then
    printf 'addresses=%s\nports=%s\napplied_at=%s\nloaded=%s\n' "$(paste -sd, - <"$state/ssh-allowed")" \
      "$(paste -sd, - <"$state/ssh-ports" 2>/dev/null)" "$(stat -c '%Y' "$state/ssh-allowed")" "$l" >"$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$out_dir/ssh"
  fi
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
  find "$state" -maxdepth 1 -type f \( -name 'pending-*' -o -name ssh-pending \) -exec rm -f {} + 2>/dev/null
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
if printf '%s\n' "$line" | grep -Eq '^[A-Za-z0-9_-]{1,64} (apply|remove|status|server) [1-9][0-9]{0,4}$'; then
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
if [ "$action" = server ] && ! listed_ssh; then
  refuse "SSH's allow list isn't Rowsafe's on this server: only servers Rowsafe creates allow it (the installer's --firewall-ssh)"
fi

# Keep the current rules to go back to.
rm -rf "$state/previous"
mkdir -p "$state/previous"
for f in $(rule_files); do cp -p "$f" "$state/previous/"; done
for f in ssh-allowed ssh-ports; do
  if [ -f "$state/$f" ]; then cp -p "$state/$f" "$state/previous/"; fi
done

rollback() {
  find "$state" -maxdepth 1 -type f \( -name 'port-*' -o -name 'pending-*' -o -name 'ssh-*' \) -exec rm -f {} + 2>/dev/null
  find "$state/previous" -maxdepth 1 -type f -exec cp -p {} "$state/" \; 2>/dev/null
  if ! load; then
    publish
    return 1
  fi
  publish
}

# take_addresses FILE NEW MIN MAX [any]: the agent's addresses in FILE,
# checked, into NEW (root's); "any" also takes 0.0.0.0/0 and ::/0.
take_addresses() {
  addrs=$(read_agent_file "$dir/$1" 4096 | head -n "$(($4 + 1))")
  n=0
  : >"$2"
  for a in $addrs; do
    if [ "${5:-}" = any ] && { [ "$a" = 0.0.0.0/0 ] || [ "$a" = ::/0 ]; }; then
      :
    elif ! valid_cidr "$a"; then
      rm -f "$2"
      refuse "not an address or range: $(printf '%s' "$a" | cut -c1-60)"
    fi
    n=$((n + 1))
    printf '%s\n' "$a" >>"$2"
  done
  [ "$n" -ge "$3" ] && [ "$n" -le "$4" ] || {
    rm -f "$2"
    refuse "between $3 and $4 addresses are needed, got $n"
  }
}

if [ "$action" = apply ] || [ "$action" = server ]; then
  db_listens=0
  for u in $db_users; do
    uid=$(id -u "$u" 2>/dev/null) || continue
    if listen_ports "$uid" | grep -qx "$port"; then db_listens=1; fi
  done
  [ "$db_listens" = 1 ] ||
    refuse "no database server (PostgreSQL, MySQL, MariaDB, MongoDB, ClickHouse, Redis or Valkey) listens on port $port here (a port Docker publishes bypasses this firewall: limit it in the compose file instead)"
fi
if [ "$action" = apply ]; then
  take_addresses addresses "$state/new-$port" 1 32
  mv -f "$state/new-$port" "$state/pending-$port"
elif [ "$action" = server ]; then
  take_addresses addresses "$state/new-$port" 0 64 any
  take_addresses ssh-addresses "$state/ssh-new" 0 64 any
  ssh_ports >"$state/ssh-ports"
  mv -f "$state/new-$port" "$state/pending-$port"
  mv -f "$state/ssh-new" "$state/ssh-pending"
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

if [ "$action" = apply ] || [ "$action" = server ]; then
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
  if [ "$action" = server ]; then mv -f "$state/ssh-pending" "$state/ssh-allowed"; fi
fi
publish
ok=1
log "$action port $port: done"
answer
ROWSAFE_FIREWALL_HELPER_EOF
    FW_HELPER_CHANGED=1
  fi
}

install_firewall_helper() {
  write_firewall_helper
  _changed=$FW_HELPER_CHANGED
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

# firewall_ports prints the TCP ports database servers listen on, found by
# root itself (pg_lsclusters, and the listening sockets of the agent user and
# of the users MySQL, MariaDB, MongoDB and ClickHouse run as), never taken
# from the agent: 1024 to 65535, never one sshd uses.
firewall_ports() {
  {
    if command -v pg_lsclusters >/dev/null 2>&1; then pg_lsclusters -h 2>/dev/null | awk '{ print $3 }'; fi
    if command -v ss >/dev/null 2>&1; then
      for _u in "$AGENT_USER" postgres mysql mongodb mongod clickhouse redis valkey; do
        _uid=$(id -u "$_u" 2>/dev/null) || continue
        ss -ltnHe 2>/dev/null | awk -v u="$_uid" 'index($0, " uid:" u " ") { n = split($4, a, ":"); print a[n] }'
      done
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

# firewall_ssh_listed: the allow list has the line "ssh" (--firewall-ssh).
firewall_ssh_listed() { [ -f "$FIREWALL_ALLOW_FILE" ] && grep -qx ssh "$FIREWALL_ALLOW_FILE"; }

# write_firewall_allow PORTS...: the allow list, written by root. The line
# "ssh" (SSH's allow list is Rowsafe's too) comes with --firewall-ssh and
# stays until --no-firewall-ssh or --no-allow-firewall.
write_firewall_allow() {
  _fw_ssh=0
  if [ "$FIREWALL_SSH" = yes ] || { [ "$FIREWALL_SSH" != no ] && firewall_ssh_listed; }; then _fw_ssh=1; fi
  {
    echo "# Database ports whose firewall rule Rowsafe may set when someone asks"
    echo "# (Security in the dashboard): only the chosen addresses may reach the"
    if [ "$_fw_ssh" = 1 ]; then
      echo "# port. \"ssh\": a server Rowsafe created (--firewall-ssh), where Rowsafe"
      echo "# also sets who may reach SSH; other ports are never touched. Written by"
      echo "# the installer (root); turn SSH's part off with: --no-firewall-ssh"
    else
      echo "# port. SSH and other ports are never touched. Written by the installer"
      echo "# (root); turn this off with: sudo rowsafe-allow --remove firewall"
    fi
    echo "# PORT"
    printf '%s\n' "$@" | sort -un
    if [ "$_fw_ssh" = 1 ]; then echo ssh; fi
  } | write_file "$FIREWALL_ALLOW_FILE" 0644 root:root || true
}

# firewall_restore reloads Rowsafe's rules from what the helper keeps.
firewall_restore() {
  [ -x "$FIREWALL_HELPER" ] || return 0
  install -d -m 0700 -o root -g root /var/lib/rowsafe-firewall
  install -d -m 0755 -o root -g root /run/rowsafe-firewall
  STATE_DIRECTORY=/var/lib/rowsafe-firewall RUNTIME_DIRECTORY=/run/rowsafe-firewall "$FIREWALL_HELPER" --restore 2>"$TMP/firewall.err"
}

# firewall_close_early (--firewall-ssh, on servers Rowsafe creates): before
# PostgreSQL listens on public addresses, its port is closed to everyone
# but this server, until the agent applies who may connect (the helper's
# "server" action, when the person's choice arrives from the dashboard).
# SSH stays as it is until then. A re-run keeps the rules already there.
firewall_close_early() {
  have nft || apt_install nftables
  _ports=$(firewall_ports)
  [ -n "$_ports" ] || return 0
  [ -d "$CONFIG_DIR" ] || install -d -m 0750 -o root -g "$AGENT_USER" "$CONFIG_DIR"
  # shellcheck disable=SC2046,SC2086 # one port per word
  write_firewall_allow $(firewall_listed) $_ports
  write_firewall_helper
  install -d -m 0700 -o root -g root /var/lib/rowsafe-firewall
  for _p in $_ports; do
    [ -e "/var/lib/rowsafe-firewall/port-$_p" ] || [ -e "/var/lib/rowsafe-firewall/pending-$_p" ] ||
      : >"/var/lib/rowsafe-firewall/port-$_p"
  done
  if firewall_restore; then
    ok "PostgreSQL's port ($(printf '%s' "$_ports" | paste -sd, - | sed 's/,/, /g')) is closed to everyone but this server until Rowsafe applies who may connect"
  else
    sed 's/^/    /' "$TMP/firewall.err" >&2
    die "could not close PostgreSQL's port with the firewall (nftables), so PostgreSQL stays private"
  fi
}

# firewall_ssh_off is --no-firewall-ssh: Rowsafe's SSH rule goes, the
# PostgreSQL rules stay.
firewall_ssh_off() {
  firewall_ssh_listed || return 0
  grep -vx ssh "$FIREWALL_ALLOW_FILE" | write_file "$FIREWALL_ALLOW_FILE" 0644 root:root || true
  rm -f /var/lib/rowsafe-firewall/ssh-allowed /var/lib/rowsafe-firewall/ssh-pending /var/lib/rowsafe-firewall/ssh-ports
  firewall_restore || warn "could not reload Rowsafe's firewall rules: $(tr '\n' ' ' <"$TMP/firewall.err")"
  perm_ok "Rowsafe no longer limits who can reach SSH"
}

allow_firewall() {
  if [ "$FIREWALL_SSH" = yes ] && ! command -v nft >/dev/null 2>&1; then apt_install nftables; fi
  if ! command -v nft >/dev/null 2>&1; then
    warn "nftables isn't installed here (no nft command), so limiting who can reach $(engine_label) stays off. Install it (e.g. apt install nftables), then: sudo rowsafe-allow firewall"
    return 0
  fi
  _ports=$(firewall_ports)
  _listed=$(firewall_listed)
  if [ -z "$_ports$_listed" ]; then
    warn "found no database server listening here, so the firewall stays off for Rowsafe"
    return 0
  fi
  # shellcheck disable=SC2086 # one port per word
  write_firewall_allow $_listed $_ports
  install_firewall_helper
  if firewall_ssh_listed; then
    perm_ok "Rowsafe may limit who can reach $(engine_label)'s port ($(firewall_listed | paste -sd, - | sed 's/,/, /g')) and SSH, as set in the dashboard; never other ports"
  else
    perm_ok "Rowsafe may limit who can reach $(engine_label)'s port ($(firewall_listed | paste -sd, - | sed 's/,/, /g')) when you ask (Security), never SSH or other ports"
  fi
}

disallow_firewall() {
  remove_firewall_helper
  if [ -d "$CONFIG_DIR" ]; then
    {
      echo "# Limiting who can reach PostgreSQL with the firewall is off for Rowsafe."
      echo "# Turn it on with: sudo rowsafe-allow firewall"
    } | write_file "$FIREWALL_ALLOW_FILE" 0644 root:root || true
  fi
}

# firewall_access applies --allow-firewall / --no-allow-firewall, or asks
# once on a terminal (default no). A re-run keeps the allow list as it is,
# and adds a port it doesn't list only after a fresh yes.
firewall_access() {
  [ "$FIREWALL_SSH" != no ] || firewall_ssh_off
  case $ALLOW_FIREWALL in
    yes) allow_firewall ;;
    no)
      disallow_firewall
      perm_ok "limiting who can reach $(engine_label) with the firewall is off for Rowsafe"
      ;;
    *)
      if [ -n "$(firewall_listed)" ]; then
        install_firewall_helper
        _new=$(firewall_ports | grep -vxF "$(firewall_listed)" || true)
        [ -n "$_new" ] && [ "$TTY" = 1 ] || return 0
        if perm_ask "$(engine_label) also listens on port $(printf '%s' "$_new" | paste -sd, - | sed 's/,/, /g'). Allow Rowsafe's firewall rule for it too?" n; then
          # shellcheck disable=SC2046 # one port per word
          write_firewall_allow $(firewall_listed) $_new
        fi
        return 0
      fi
      [ -f "$FIREWALL_ALLOW_FILE" ] && return 0 # a no, kept
      [ "$TTY" = 1 ] && command -v nft >/dev/null 2>&1 || return 0
      _ports=$(firewall_ports)
      [ -n "$_ports" ] || return 0
      if perm_ask "Limit who can reach $(engine_label) (port $(printf '%s' "$_ports" | paste -sd, - | sed 's/,/, /g')) with the firewall, when someone picks the addresses? SSH and other ports are never touched." n; then
        allow_firewall
      else
        disallow_firewall
        perm_note "OK: Rowsafe won't change the firewall"
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

# pooler_name: PgBouncer in front of PostgreSQL, ProxySQL in front of MySQL
# and MariaDB.
pooler_name() {
  case $HOST_ENGINE in mysql | mariadb) echo ProxySQL ;; clickhouse) echo chproxy ;; *) echo PgBouncer ;; esac
}

# install_pooler_units_for_engine installs the engine's pooling helper.
install_pooler_units_for_engine() {
  case $HOST_ENGINE in
    mysql | mariadb) install_proxysql_units ;;
    clickhouse) install_chproxy_units ;;
    *) install_pooler_units ;;
  esac
}

# ProxySQL (MySQL, MariaDB): root's copy of the agent ($PERMISSIONS_HELPER
# proxysql-apply) installs and configures it when the agent asks
# ($POOLER_DIR/proxysql-request), only for ports in $POOLER_ALLOW_FILE.
PROXYSQL_SERVICE_FILE=/etc/systemd/system/rowsafe-proxysql.service
PROXYSQL_PATH_FILE=/etc/systemd/system/rowsafe-proxysql.path

# pooler_target_ok ADDRESS:PORT: an IPv4 or IPv6 address, or a host name,
# and a port (IPv6 in brackets: [fd00::6]:3306).
pooler_target_ok() {
  _pt_host=${1%:*} _pt_port=${1##*:}
  _pt_host=${_pt_host#[} _pt_host=${_pt_host%]}
  case $_pt_port in '' | *[!0-9]* | 0*) return 1 ;; esac
  [ "${#_pt_port}" -le 5 ] && [ "$_pt_port" -ge 1 ] && [ "$_pt_port" -le 65535 ] || return 1
  printf '%s\n' "$_pt_host" | grep -Eqx '[0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*|[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?'
}

# pooler_target_change applies --allow-pooler-target / --no-allow-pooler-
# target: the "target ADDRESS PORT" lines that let ProxySQL send
# connections to another server (the primary after a standby's promotion).
pooler_target_change() {
  case $HOST_ENGINE in mysql | mariadb) ;; *) perm_refuse "pooler-target is for ProxySQL, in front of MySQL or MariaDB" ;; esac
  [ -n "$(pooler_allowed_ports)" ] || perm_refuse "pooling isn't allowed on this server: allow it first (sudo rowsafe-allow pooler)"
  _pt=${POOLER_TARGET_ADD:-$POOLER_TARGET_DEL}
  _pt_host=${_pt%:*} _pt_port=${_pt##*:}
  _pt_host=${_pt_host#[} _pt_host=${_pt_host%]}
  _line="target $_pt_host $_pt_port"
  _rest=$(grep -vxF "$_line" "$POOLER_ALLOW_FILE" || true)
  if [ -n "$POOLER_TARGET_ADD" ]; then
    printf '%s\n%s\n' "$_rest" "$_line" | awk 'NF' | write_file "$POOLER_ALLOW_FILE" 0644 root:root || true
    perm_ok "ProxySQL may send connections to $_pt_host port $_pt_port (after a standby's promotion)"
  else
    printf '%s\n' "$_rest" | awk 'NF' | write_file "$POOLER_ALLOW_FILE" 0644 root:root || true
    perm_ok "ProxySQL no longer sends connections to $_pt_host port $_pt_port"
  fi
}

install_proxysql_units() {
  [ -x "$PERMISSIONS_HELPER" ] || install_permissions_helper
  [ -x "$PERMISSIONS_HELPER" ] || { warn "pooling needs root's copy of the agent ($PERMISSIONS_HELPER); run the installer again"; return 0; }
  as_agent mkdir -p -m 0700 "$POOLER_DIR"
  _changed=0
  if sed "s/@AGENT_USER@/$AGENT_USER/" <<'ROWSAFE_PROXYSQL_SERVICE_EOF' | write_file "$PROXYSQL_SERVICE_FILE" 0644 root:root; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-proxysql.service: installs, configures, points or turns off
# ProxySQL (connection pooling for MySQL and MariaDB) when someone turned
# pooling on or off in Rowsafe, only for the ports root allowed
# (/etc/rowsafe/pooler-allowed, sudo rowsafe-allow pooler). Started by
# rowsafe-proxysql.path; installed by https://rowsafe.sh/install.

[Unit]
Description=Rowsafe: manage ProxySQL (connection pooling), on request
Documentation=https://rowsafe.sh/docs/guides/connection-pooling
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/rowsafe/rowsafe-permissions proxysql-apply
Environment=ROWSAFE_AGENT_USER=@AGENT_USER@
TimeoutStartSec=15min
RuntimeDirectory=rowsafe-proxysql
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
StateDirectory=rowsafe-proxysql
StateDirectoryMode=0700
UMask=0022
# It installs a package (apt) and starts a service: no file system
# sandbox, but no new privileges and no kernel changes.
NoNewPrivileges=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
ROWSAFE_PROXYSQL_SERVICE_EOF
    _changed=1
  fi
  if write_file "$PROXYSQL_PATH_FILE" 0644 root:root <<'ROWSAFE_PROXYSQL_PATH_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-proxysql.path: starts rowsafe-proxysql.service when the Rowsafe
# agent asks for a pooling change. Installed by https://rowsafe.sh/install
# only when root allowed pooling (--allow-pooler).

[Unit]
Description=Rowsafe: watch for connection pooling requests (ProxySQL)

[Path]
PathExists=/var/lib/rowsafe/pooler/proxysql-request
Unit=rowsafe-proxysql.service

[Install]
WantedBy=multi-user.target
ROWSAFE_PROXYSQL_PATH_EOF
    _changed=1
  fi
  if systemd_running; then
    [ "$_changed" = 0 ] || systemctl daemon-reload
    systemctl enable --now --quiet rowsafe-proxysql.path
  fi
}

remove_proxysql_units() {
  [ -e "$PROXYSQL_PATH_FILE" ] || [ -e "$PROXYSQL_SERVICE_FILE" ] || return 0
  if systemd_running; then systemctl disable --now --quiet rowsafe-proxysql.path 2>/dev/null || true; fi
  rm -f "$PROXYSQL_PATH_FILE" "$PROXYSQL_SERVICE_FILE"
  if systemd_running; then systemctl daemon-reload; fi
}

# chproxy (ClickHouse): root's copy of the agent ($PERMISSIONS_HELPER
# chproxy-apply) installs chproxy (its release, checked against the SHA-256
# the agent pins) and runs it as rowsafe-chproxy.service when the agent asks
# ($POOLER_DIR/chproxy-request), only for ports in $POOLER_ALLOW_FILE.
CHPROXY_SERVICE_FILE=/etc/systemd/system/rowsafe-chproxy-apply.service
CHPROXY_PATH_FILE=/etc/systemd/system/rowsafe-chproxy-apply.path

install_chproxy_units() {
  [ -x "$PERMISSIONS_HELPER" ] || install_permissions_helper
  [ -x "$PERMISSIONS_HELPER" ] || { warn "pooling needs root's copy of the agent ($PERMISSIONS_HELPER); run the installer again"; return 0; }
  as_agent mkdir -p -m 0700 "$POOLER_DIR"
  _changed=0
  if sed "s/@AGENT_USER@/$AGENT_USER/" <<'ROWSAFE_CHPROXY_SERVICE_EOF' | write_file "$CHPROXY_SERVICE_FILE" 0644 root:root; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-chproxy-apply.service: installs, configures, points or turns off
# chproxy (connection pooling for ClickHouse's HTTP interface) when someone
# turned pooling on or off in Rowsafe, only for the ports root allowed
# (/etc/rowsafe/pooler-allowed, sudo rowsafe-allow pooler). chproxy itself
# runs as rowsafe-chproxy.service. Started by rowsafe-chproxy-apply.path;
# installed by https://rowsafe.sh/install.

[Unit]
Description=Rowsafe: manage chproxy (connection pooling), on request
Documentation=https://rowsafe.sh/docs/guides/connection-pooling
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/rowsafe/rowsafe-permissions chproxy-apply
Environment=ROWSAFE_AGENT_USER=@AGENT_USER@
TimeoutStartSec=15min
RuntimeDirectory=rowsafe-chproxy-apply
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
StateDirectory=rowsafe-chproxy-apply
StateDirectoryMode=0700
UMask=0022
# It downloads chproxy, writes its unit and starts it: no file system
# sandbox, but no new privileges and no kernel changes.
NoNewPrivileges=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
ROWSAFE_CHPROXY_SERVICE_EOF
    _changed=1
  fi
  if write_file "$CHPROXY_PATH_FILE" 0644 root:root <<'ROWSAFE_CHPROXY_PATH_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-chproxy-apply.path: starts rowsafe-chproxy-apply.service when the
# Rowsafe agent asks for a pooling change. Installed by
# https://rowsafe.sh/install only when root allowed pooling (--allow-pooler).

[Unit]
Description=Rowsafe: watch for connection pooling requests (chproxy)

[Path]
PathExists=/var/lib/rowsafe/pooler/chproxy-request
Unit=rowsafe-chproxy-apply.service

[Install]
WantedBy=multi-user.target
ROWSAFE_CHPROXY_PATH_EOF
    _changed=1
  fi
  if systemd_running; then
    [ "$_changed" = 0 ] || systemctl daemon-reload
    systemctl enable --now --quiet rowsafe-chproxy-apply.path
  fi
}

remove_chproxy_units() {
  [ -e "$CHPROXY_PATH_FILE" ] || [ -e "$CHPROXY_SERVICE_FILE" ] || return 0
  if systemd_running; then systemctl disable --now --quiet rowsafe-chproxy-apply.path 2>/dev/null || true; fi
  rm -f "$CHPROXY_PATH_FILE" "$CHPROXY_SERVICE_FILE"
  if systemd_running; then systemctl daemon-reload; fi
}

# pooler_ports prints the ports of this server's PostgreSQL clusters, found
# by root: pg_lsclusters (Debian and Ubuntu), else the TCP ports that
# processes of the agent user listen on. Never the agent's own discovery:
# the agent user owns the agent's binary.
pooler_ports() {
  case $HOST_ENGINE in
    mysql | mariadb) # ProxySQL: the ports mysqld or mariadbd (the mysql user) listen on
      _uid=$(id -u mysql 2>/dev/null) || return 0
      have ss || return 0
      ss -Hltne 2>/dev/null | awk -v u="uid:$_uid" '{ for (i = 1; i <= NF; i++) if ($i == u) { n = split($4, a, ":"); print a[n] } }' |
        awk '$1 ~ /^[0-9]+$/ && $1 != 33060' | sort -un
      return 0
      ;;
    clickhouse) # chproxy: ClickHouse's HTTP port (http_port; chproxy covers HTTP only)
      if have clickhouse; then
        clickhouse extract-from-config --config-file=/etc/clickhouse-server/config.xml --key=http_port 2>/dev/null |
          awk '$1 ~ /^[0-9]+$/ && $1 > 0 && $1 < 65536 { print $1 }' | sort -un
      fi
      return 0
      ;;
  esac
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
    echo "# Database ports Rowsafe may put $(pooler_name) (connection pooling) in"
    echo "# front of, when someone turns pooling on in Rowsafe and confirms."
    echo "# Written by the installer (root); turn this off with:"
    echo "# sudo rowsafe-allow --remove pooler. \"public\": the pooler may listen"
    echo "# on every address (sudo rowsafe-allow pooler-public)."
    echo "# PORT"
    printf '%s\n' "$1"
    if [ "$2" = 1 ]; then echo public; fi
    # Other servers ProxySQL may send connections to (rowsafe-allow pooler-target).
    grep -s '^target ' "$POOLER_ALLOW_FILE" || true
  } | write_file "$POOLER_ALLOW_FILE" 0644 root:root || true
}

# allow_pooler: --allow-pooler, or yes at the question: every cluster root
# finds, plus the ones allowed before.
allow_pooler() {
  _ports=$(printf '%s\n%s\n' "$(pooler_allowed_ports)" "$(pooler_ports)" | awk 'NF' | sort -un)
  if [ -z "$_ports" ]; then
    warn "found no database server here, so managing $(pooler_name) from Rowsafe stays off"
    return 0
  fi
  _public=$(pooler_public_wanted)
  write_pooler_allow "$_ports" "$_public"
  install_pooler_units_for_engine
  perm_ok "Rowsafe may install and manage $(pooler_name) when you turn pooling on, only when someone confirms"
  if [ "$_public" = 1 ]; then perm_note "$(pooler_name) may listen on public addresses when someone chooses that: put a firewall in front of it."; fi
}

# pooler_public_wanted prints 1 when PgBouncer may listen on every address:
# --allow-pooler-public, else what the allow list says
# (--no-allow-pooler-public: 0).
pooler_public_wanted() {
  case $ALLOW_POOLER_PUBLIC in
    yes) echo 1 ;;
    no) echo 0 ;;
    *) if grep -qsx public "$POOLER_ALLOW_FILE"; then echo 1; else echo 0; fi ;;
  esac
}

# refresh_pooler: a re-run keeps the allow list as it is and adds a cluster
# found since only when someone says yes on a terminal.
refresh_pooler() {
  _have=$(pooler_allowed_ports)
  _ports=$_have
  for _newport in $(pooler_ports); do
    printf '%s\n' "$_have" | grep -qx "$_newport" && continue
    # (confirm uses $_p itself.)
    if [ "$TTY" = 1 ] && perm_ask "Also allow $(pooler_name) for the $(engine_label) on port $_newport?" n; then
      _ports=$(printf '%s\n%s\n' "$_ports" "$_newport" | awk 'NF' | sort -un)
    fi
  done
  _public=$(pooler_public_wanted)
  _was_public=0
  if grep -qsx public "$POOLER_ALLOW_FILE"; then _was_public=1; fi
  if [ "$_ports" != "$_have" ] || [ "$_public" != "$_was_public" ]; then
    write_pooler_allow "$_ports" "$_public"
  fi
  install_pooler_units_for_engine
}

disallow_pooler() {
  remove_pooler_units
  remove_proxysql_units
  remove_chproxy_units
  if [ -d "$CONFIG_DIR" ]; then
    {
      echo "# Managing the connection pooler from Rowsafe is off on this server."
      echo "# Turn it on with: sudo rowsafe-allow pooler"
    } | write_file "$POOLER_ALLOW_FILE" 0644 root:root || true
  fi
  if [ -f /etc/systemd/system/rowsafe-chproxy.service ]; then
    perm_note "chproxy set up by Rowsafe keeps running for your apps; Rowsafe can no longer change it or turn it off (sudo systemctl disable --now rowsafe-chproxy)."
  fi
  if [ -f /etc/pgbouncer/pgbouncer.ini ] && [ "$(head -n 1 /etc/pgbouncer/pgbouncer.ini)" = ';; Managed by Rowsafe' ]; then
    perm_note "PgBouncer set up by Rowsafe keeps running for your apps; Rowsafe can no longer change it or turn it off."
  fi
}

# pooler_access applies --allow-pooler / --no-allow-pooler, or asks once on a
# terminal. A re-run keeps the earlier answer (and refreshes the list).
pooler_access() {
  case $ALLOW_POOLER in
    yes) allow_pooler ;;
    no)
      disallow_pooler
      perm_ok "managing $(pooler_name) from Rowsafe is off"
      ;;
    *)
      if [ -f "$POOLER_ALLOW_FILE" ]; then
        if grep -q '^[0-9]' "$POOLER_ALLOW_FILE"; then refresh_pooler; fi
        return 0
      fi
      [ "$TTY" = 1 ] && [ -n "$(pooler_ports)" ] || return 0
      if perm_ask "Install and manage $(pooler_name) (connection pooling), when someone turns pooling on? Nothing is installed now." y; then
        allow_pooler
      else
        disallow_pooler
        perm_note "OK: Rowsafe won't install or manage $(pooler_name)"
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
#   --allow-files      let Rowsafe put restored files back into exactly the
#                      folders protected with --files (as the folder's owner),
#                      listed with their owner in /etc/rowsafe/files-allowed,
#                      through rowsafe-files-helper.service; --no-allow-files
#                      turns it off
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
FILES_SERVICE_FILE=/etc/systemd/system/rowsafe-files-helper.service
FILES_PATH_FILE=/etc/systemd/system/rowsafe-files-helper.path
FILES_DROPIN_DIR=/etc/systemd/system/rowsafe-files-helper.service.d
FILES_DROPIN=$FILES_DROPIN_DIR/folders.conf
OLD_FILES_DROPIN=/etc/systemd/system/rowsafe-pg-restart.service.d/rowsafe-files.conf
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

# files_allowed_list prints the allowed folders' "PATH UID" lines.
files_allowed_list() { awk 'NF == 2 && $1 ~ /^\// && $2 ~ /^[0-9]+$/' "$FILES_ALLOW_FILE" 2>/dev/null || true; }

# acl_grant_read DIR USER WORKDIR lets USER read DIR and everything in it,
# now and later (default ACLs). Masks that were already there are put back
# as they were, so no other named entry gains rights; a new mask covers only
# the owning group and USER.
acl_grant_read() {
  getfacl -R -P -s -p -- "$1" >"$3/acl.before" 2>/dev/null || return 1
  setfacl -R -P -m "u:$2:rX" -- "$1" || return 1
  find -P "$1" -xdev -type d -exec setfacl -m "d:u:$2:rX" -- {} + || return 1
  [ -s "$3/acl.before" ] || return 0
  getfacl -R -P -s -p -- "$1" >"$3/acl.after" 2>/dev/null || return 1
  awk '
    FNR == 1 { pass++ }
    /^# file: / { f = substr($0, 9); if (pass == 1) had[f] = 1; else keep = (f in had) }
    pass == 1 { if ($0 ~ /^mask::/) m[f] = $0; else if ($0 ~ /^default:mask::/) dm[f] = $0; next }
    !keep || /^# (owner|group|flags):/ { next }
    /^mask::/ && (f in m) { print m[f]; next }
    /^default:mask::/ && (f in dm) { print dm[f]; next }
    { print }
  ' "$3/acl.before" "$3/acl.after" >"$3/acl.restore"
  [ ! -s "$3/acl.restore" ] || setfacl --restore="$3/acl.restore"
}

# acl_grant_x DIR USER lets USER through DIR, keeping DIR's mask if it has
# one.
acl_grant_x() {
  if getfacl -p -s -- "$1" 2>/dev/null | grep -q '^mask::'; then
    setfacl -n -m "u:$2:x" -- "$1"
  else
    setfacl -m "u:$2:x" -- "$1"
  fi
}

# files_grant_read gives the agent user read access to a folder the person
# chose to protect (POSIX ACLs; ownership and modes stay as they are).
files_grant_read() {
  have setfacl || apt_install acl
  mkdir -p "$TMP/acl"
  if ! acl_grant_read "$1" "$AGENT_USER" "$TMP/acl"; then
    warn "could not give the agent read access to $1 (see above); it is not protected"
    return 1
  fi
  _p=${1%/*}
  while [ -n "$_p" ]; do
    as_agent test -x "$_p" 2>/dev/null || acl_grant_x "$_p" "$AGENT_USER" || true
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
  if grep -qxF -- "$1" "$TMP/files-have"; then
    FILES_PROTECTED="$FILES_PROTECTED$1
"
    ok "$1 is already backed up with $FILES_DB_NAME"
    return 0
  fi
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
  printf '%s' "$FILES_PATHS" | awk 'NF && !seen[$0]++' >"$TMP/files-todo"
  while IFS= read -r _path <&4; do
    files_protect "$_path"
  done 4<"$TMP/files-todo"
  if [ -n "$FILES_PROTECTED" ]; then
    note "Files are encrypted on this server with a key derived from your backup passphrase: the same passphrase restores them."
  fi
  files_access
}

# files_access applies --allow-files / --no-allow-files, or asks on a
# terminal once a folder is protected. The question names exactly the
# folders it allows. A re-run keeps the earlier answer: after a yes, the
# folders protected with --files join the list (asked on a terminal).
files_access() {
  _new=$(printf '%s' "$FILES_PROTECTED" | while IFS= read -r _p; do
    [ -z "$_p" ] || files_allowed_list | awk -v p="$_p" '$1 == p { f = 1 } END { exit f }' && printf '%s\n' "$_p"
  done | awk 'NF' | paste -sd' ' -)
  case $ALLOW_FILES in
    yes) allow_files ;;
    no)
      disallow_files
      ok "putting restored files back from Rowsafe is off (restores wait next to the folder)"
      ;;
    *)
      if [ -f "$FILES_ALLOW_FILE" ]; then
        files_allowed || return 0
        if [ -n "$_new" ] && [ "$TTY" = 1 ]; then
          say ""
          if ! confirm "Also allow Rowsafe to put restored files back into $_new, as the folder's owner? Only when someone asks and confirms." y; then
            FILES_PROTECTED=''
          fi
        fi
        allow_files
        return 0
      fi
      [ "$TTY" = 1 ] && [ -n "$_new" ] || return 0
      say ""
      if confirm "Allow Rowsafe to put restored files back into $_new, as the folder's owner? Only these folders (add others later with --files), only when someone asks and confirms." y; then
        allow_files
      else
        disallow_files
        note "OK: restored files will wait next to the folder for you (change it with: sudo rowsafe-allow --files PATH)"
      fi
      ;;
  esac
}

# allow_files lists the protected folders in $FILES_ALLOW_FILE ("PATH UID",
# the owner now) and installs rowsafe-files-helper, whose sandbox may write
# only there. Folders allowed before keep their line; the ones protected by
# this run are (re)recorded with their owner now.
allow_files() {
  {
    printf '%s' "$FILES_PROTECTED" | while IFS= read -r _p; do
      [ -n "$_p" ] && [ -d "$_p" ] && [ ! -L "$_p" ] && printf '%s %s\n' "$_p" "$(stat -c '%u' -- "$_p")"
    done
    files_allowed_list
  } | awk '!seen[$1]++' >"$TMP/files-allow"
  if [ ! -s "$TMP/files-allow" ]; then
    disallow_files
    note "No folder to put restored files back into yet: protect one with --files PATH (and --allow-files)"
    return 0
  fi
  {
    echo "# The folders Rowsafe may read and put restored files back into, with the"
    echo "# uid that owned each when root allowed it (\"PATH UID\"). Only these exact"
    echo "# folders and the files inside them, only while that uid still owns them,"
    echo "# only when someone asks and confirms, never as root; never system,"
    echo "# database or home folders. Written by the installer (root): add a folder"
    echo "# with --files PATH, turn it all off with --no-allow-files."
    cat "$TMP/files-allow"
  } | write_file "$FILES_ALLOW_FILE" 0644 root:root || true
  install -d -m 0755 -o root -g root "$FILES_DROPIN_DIR"
  {
    echo "# Written by the Rowsafe installer (--allow-files): the helper may write"
    echo "# only into the folders listed in $FILES_ALLOW_FILE."
    echo "[Service]"
    awk '{ print "ReadWritePaths=-" $1 }' "$TMP/files-allow"
    if grep -q '^/home[/ ]' "$TMP/files-allow"; then echo "ProtectHome=no"; fi
  } | write_file "$FILES_DROPIN" 0644 root:root || true
  rm -f "$OLD_FILES_DROPIN"
  rmdir "${OLD_FILES_DROPIN%/*}" 2>/dev/null || true
  have setfacl || apt_install acl
  install_files_units
  ok "Rowsafe may put restored files back into $(cut -d' ' -f1 "$TMP/files-allow" | paste -sd' ' -), as the folder's owner, when someone asks (turn off: sudo rowsafe-allow --remove files)"
}

disallow_files() {
  remove_files_units
  if [ -d "$CONFIG_DIR" ]; then
    {
      echo "# Reading and restoring folders through Rowsafe's root helper is off."
      echo "# Turn it on with: sudo rowsafe-allow --files PATH"
    } | write_file "$FILES_ALLOW_FILE" 0644 root:root || true
  fi
}

install_files_units() {
  install_helper_script
  write_file "$FILES_SERVICE_FILE" 0644 root:root <<'ROWSAFE_FILES_SERVICE_EOF' || true
# SPDX-License-Identifier: Apache-2.0
# rowsafe-files-helper.service: gives the Rowsafe agent read access to a
# folder root allowed in /etc/rowsafe/files-allowed, or puts restored files
# back into it as the folder's owner, when the agent asks because a person
# did (see /usr/local/lib/rowsafe/rowsafe-pg-restart, files mode). Started
# by rowsafe-files-helper.path; installed by https://rowsafe.sh/install only
# when root allowed it (--allow-files). Its own unit, so the rights files
# need never widen rowsafe-pg-restart.service.

[Unit]
Description=Rowsafe: read or restore a protected folder on request
Documentation=https://rowsafe.sh/docs/guides/files

[Service]
Type=oneshot
ExecStart=/usr/local/lib/rowsafe/rowsafe-pg-restart
Environment=ROWSAFE_HELPER_MODE=files
TimeoutStartSec=3600
# The agent user, whose privileges read and remove the request and read the
# staged files.
Environment=ROWSAFE_AGENT_USER=postgres
# The answer: root's own directory, which the agent can read (shared with
# rowsafe-pg-restart.service).
RuntimeDirectory=rowsafe-pg-restart
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
# Root's private copy of the staged files and the cooldowns, out of the
# agent's reach.
StateDirectory=rowsafe-files-helper
StateDirectoryMode=0700
UMask=0022

# Hardening. CAP_SETUID/CAP_SETGID drop to the agent user (to read its
# files) and to the folder's owner (to write); CAP_FOWNER sets ACLs on files
# root doesn't own; CAP_DAC_READ_SEARCH lets root check the folder. Only the
# protected folders are writable (rowsafe-files-helper.service.d, written by
# the installer), and no set-user-ID file can be created.
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_FOWNER CAP_DAC_READ_SEARCH
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=-/var/lib/rowsafe/restart
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
ROWSAFE_FILES_SERVICE_EOF
  write_file "$FILES_PATH_FILE" 0644 root:root <<'ROWSAFE_FILES_PATH_EOF' || true
# SPDX-License-Identifier: Apache-2.0
# rowsafe-files-helper.path: starts rowsafe-files-helper.service when the
# Rowsafe agent asks for read access to a protected folder or to put
# restored files back (someone asked in the dashboard and confirmed).
# Installed by https://rowsafe.sh/install only when root allowed it; remove
# it with --no-allow-files.

[Unit]
Description=Rowsafe: watch for requests to read or restore a protected folder
Documentation=https://rowsafe.sh/docs/guides/files

[Path]
PathExists=/var/lib/rowsafe/restart/files-request
Unit=rowsafe-files-helper.service

[Install]
WantedBy=multi-user.target
ROWSAFE_FILES_PATH_EOF
  if systemd_running; then
    systemctl daemon-reload
    systemctl enable --now --quiet rowsafe-files-helper.path
  else
    warn "systemd is not running here; the files helper was installed but cannot be enabled"
  fi
}

remove_files_units() {
  rm -f "$OLD_FILES_DROPIN"
  rmdir "${OLD_FILES_DROPIN%/*}" 2>/dev/null || true
  if [ -e "$FILES_PATH_FILE" ] || [ -e "$FILES_SERVICE_FILE" ] || [ -d "$FILES_DROPIN_DIR" ]; then
    if systemd_running; then
      systemctl disable --now --quiet rowsafe-files-helper.path 2>/dev/null || true
    fi
    rm -f "$FILES_PATH_FILE" "$FILES_SERVICE_FILE" "$FILES_DROPIN"
    rmdir "$FILES_DROPIN_DIR" 2>/dev/null || true
  fi
  [ -e "$RESTART_PATH_FILE" ] || [ -e "$POOLER_PATH_FILE" ] || [ -e "$UPDATE_PATH_FILE" ] || rm -f "$RESTART_HELPER"
  if systemd_running; then systemctl daemon-reload; fi
}

# ---------------------------------------------------------------- permissions (rowsafe-allow)
# What Rowsafe may do on this server when someone clicks it in the dashboard
# and confirms (protocol/permissions.go): asked once on a terminal, set with
# --allow-X / --no-allow-X, shown at the end, and changed later with
# `sudo rowsafe-allow NAME`, which runs this installer's permissions-only
# mode (--permissions) from root's copy of it in $LIB_DIR, checked against
# the signed release manifest.
#
#   install.sh --permissions [--allow-X ...] [--no-allow-X ...] [--no-prompt]
#
# changes only the allow lists and their root helpers and units, exactly as
# an install does. It downloads nothing (rowsafe-permissions.service, which
# runs it for one-click changes, has no network), never touches the agent,
# its settings, the storage or the databases, and asks nothing. A permission that needs another one that
# stays off is refused (create-cluster, updates and security-updates need
# restart, reboot needs security-updates, pooler-public needs pooler);
# turning one off turns off what needs it. Exit status: 0 done (or nothing to
# change), 2 refused (nothing was changed: unknown option, a missing need,
# not possible on this server, Rowsafe not installed), 1 failed while
# changing. The output ends with what Rowsafe may do now, then (exit 1 or
# 2) the reason in one "error: ..." line.

PERMISSIONS="restart create-cluster updates security-updates reboot pooler pooler-public firewall tuning sqlite-modes"
PERM_QUIET=0 # 1: the summary says it all (the questions on a terminal, --permissions)
PERM_INTRO=0 # 1 once the questions' heading is shown

perm_ok() { [ "$PERM_QUIET" = 1 ] || ok "$@"; }
perm_note() { [ "$PERM_QUIET" = 1 ] || note "$@"; }

# perm_refuse MESSAGE: nothing was changed (exit status 2). In
# --permissions, what Rowsafe may do comes first, the reason last.
PERM_READY=0
perm_refuse() {
  if [ "$PERM_READY" = 1 ]; then perm_summary; fi
  printf '%serror:%s %s\n' "$RED" "$RESET" "$*" >&2
  exit 2
}

# perm_intro is the heading before the first question.
perm_intro() {
  [ "$PERM_INTRO" = 0 ] || return 0
  PERM_INTRO=1
  say ""
  step "What may Rowsafe do on this server?"
  note "Rowsafe only does these when someone clicks them in your dashboard and"
  note "confirms. You can change them any time with \`sudo rowsafe-allow\`."
}

# perm_ask QUESTION y|n: a permission question, under the heading.
perm_ask() {
  perm_intro
  confirm "$1" "$2"
}

# perm_var NAME prints the variable holding NAME's flag (yes, no or empty).
perm_var() {
  case $1 in
    restart) echo ALLOW_RESTART ;;
    create-cluster) echo ALLOW_CREATE_CLUSTER ;;
    updates) echo ALLOW_UPDATES ;;
    security-updates) echo ALLOW_SECURITY ;;
    reboot) echo ALLOW_REBOOT ;;
    pooler) echo ALLOW_POOLER ;;
    pooler-public) echo ALLOW_POOLER_PUBLIC ;;
    firewall) echo ALLOW_FIREWALL ;;
    tuning) echo ALLOW_TUNING ;;
    sqlite-modes) echo ALLOW_SQLITE_MODES ;;
    *) return 1 ;;
  esac
}
perm_flag() { eval "printf '%s' \"\$$(perm_var "$1")\""; }
perm_set() { eval "$(perm_var "$1")=\$2"; }

# perm_need NAME prints the permission NAME only works with.
perm_need() {
  case $1 in
    create-cluster | updates | security-updates) echo restart ;;
    reboot) echo security-updates ;;
    pooler-public) echo pooler ;;
  esac
}

perm_desc() {
  case $1 in
    restart) echo "restart or stop $(engine_label) (Restart, Rewind)" ;;
    create-cluster) echo "create a PostgreSQL cluster for a fork" ;;
    updates) echo "install $(engine_label) updates and upgrades" ;;
    security-updates) echo "install this server's security updates" ;;
    reboot) echo "reboot this server (after an update)" ;;
    pooler) echo "install and manage PgBouncer (pooling)" ;;
    pooler-public) echo "let PgBouncer listen on public addresses" ;;
    firewall) echo "limit who can reach the database (firewall)" ;;
    tuning) echo "change MongoDB's or ClickHouse's settings (Tuning)" ;;
    sqlite-modes) echo "close the SQLite files to other users (Security)" ;;
  esac
}

# perm_state NAME prints yes or no, as root answered, or nothing (never
# asked). The agent reads the same files (internal/agent/permissions.go).
perm_state() {
  case $1 in
    restart) _sf=$RESTART_ALLOW_FILE ;;
    create-cluster) _sf=$CREATE_ALLOW_FILE ;;
    pooler | pooler-public) _sf=$POOLER_ALLOW_FILE ;;
    firewall) _sf=$FIREWALL_ALLOW_FILE ;;
    tuning) _sf=$TUNING_ALLOW_FILE ;;
    sqlite-modes) _sf=$SQLITE_MODES_ALLOW_FILE ;;
    *) _sf=$UPDATES_ALLOW_FILE ;;
  esac
  [ -f "$_sf" ] || return 0
  case $1 in
    restart | pooler | firewall) _sy=$(grep -c '^[1-9]' "$_sf" || true) ;;
    tuning) _sy=$(grep -Ec '^(mongodb|clickhouse) /' "$_sf" || true) ;;
    sqlite-modes) _sy=$(grep -cx 'sqlite-paths' "$_sf" || true) ;;
    create-cluster) _sy=$(grep -c '^ports ' "$_sf" || true) ;;
    pooler-public) _sy=$(grep -qs '^[1-9]' "$_sf" && grep -cx public "$_sf" || true) ;;
    updates) _sy=$(grep -c '^\(postgresql\|database\)\([[:space:]#]\|$\)' "$_sf" || true) ;;
    security-updates) _sy=$(grep -c '^security\([[:space:]#]\|$\)' "$_sf" || true) ;;
    reboot) _sy=$(grep -c '^reboot\([[:space:]#]\|$\)' "$_sf" || true) ;;
  esac
  if [ "${_sy:-0}" -gt 0 ]; then echo yes; else echo no; fi
}

perm_has_postgres() {
  for _pb in /usr/lib/postgresql/*/bin/postgres; do
    [ -x "$_pb" ] && return 0
  done
  return 1
}

# perm_why NAME prints why this server can't have NAME (nothing when it
# can). The agent reports the same reasons.
perm_why() {
  if [ "$HOST_ENGINE" != postgresql ] || ! perm_has_postgres; then
    # Another engine (or none yet): restarts, the server's own updates, the
    # firewall and tuning work for every engine, pooling for MySQL,
    # MariaDB (ProxySQL) and ClickHouse (chproxy); the rest is PostgreSQL's.
    case $1 in
      restart)
        [ -n "$(restart_pairs)" ] || echo "found no $(engine_label) service (systemd) on this server"
        return 0
        ;;
      updates | security-updates | reboot)
        if [ "$1" = updates ] && { [ "$HOST_ENGINE" = redis ] || [ "$HOST_ENGINE" = valkey ]; }; then
          echo "Rowsafe doesn't install $(engine_label) updates yet"
          return 0
        fi
        have apt-get || echo "Rowsafe installs updates with apt (Debian and Ubuntu)"
        return 0
        ;;
      firewall | tuning | sqlite-modes) ;; # every engine's port; MongoDB's and ClickHouse's settings; SQLite files
      pooler | pooler-public) case $HOST_ENGINE in mysql | mariadb | clickhouse) ;; *)
        echo "Rowsafe pools PostgreSQL (PgBouncer), MySQL or MariaDB (ProxySQL) and ClickHouse (chproxy), and none is on this server"
        return 0
        ;;
      esac ;;
      *)
        echo "Rowsafe does this for PostgreSQL, and there is no PostgreSQL on this server"
        return 0
        ;;
    esac
  fi
  _w=''
  case $1 in
    restart) [ -n "$(restart_pairs)" ] || _w="found no PostgreSQL service (systemd) on this server" ;;
    create-cluster) have pg_createcluster || _w="pg_createcluster isn't installed (Debian and Ubuntu's postgresql-common)" ;;
    updates | security-updates | reboot) have apt-get || _w="Rowsafe installs updates with apt (Debian and Ubuntu)" ;;
    pooler | pooler-public) [ -n "$(pooler_ports)$(pooler_allowed_ports)" ] || _w="found no $(engine_label) here" ;;
    tuning)
      case $HOST_ENGINE in
        mongodb) [ -n "$(mongodb_config_file)" ] || _w="found no MongoDB configuration file (/etc/mongod.conf)" ;;
        clickhouse) [ -f /etc/clickhouse-server/config.xml ] || _w="found no ClickHouse configuration (/etc/clickhouse-server)" ;;
        *) _w="Rowsafe changes $(engine_label)'s settings without it" ;;
      esac
      ;;
    sqlite-modes) [ -n "$(sqlite_modes_dirs)" ] || _w="Rowsafe needs this only for SQLite files, and none is listed here" ;;
    firewall)
      if ! have nft; then
        _w="nftables isn't installed (apt install nftables)"
      elif [ -z "$(firewall_ports)$(firewall_listed)" ]; then
        _w="found no database server listening here"
      fi
      ;;
  esac
  _n=$(perm_need "$1")
  if [ -z "$_w" ] && [ -n "$_n" ] && [ -n "$(perm_why "$_n")" ]; then
    _w="it needs $_n, which this server can't have"
  fi
  [ -z "$_w" ] || echo "$_w"
}

# perm_on NAME: NAME is allowed, or being allowed now.
perm_on() {
  [ "$(perm_flag "$1")" = yes ] || { [ "$(perm_flag "$1")" != no ] && [ "$(perm_state "$1")" = yes ]; }
}

# perm_chain NAME prints NAME after the permissions it needs that are off.
perm_chain() {
  _c=$1
  _n=$(perm_need "$1")
  while [ -n "$_n" ] && ! perm_on "$_n"; do
    _c="$_n $_c"
    _n=$(perm_need "$_n")
  done
  echo "$_c"
}

# perm_cascade: --no-allow-X turns off what needs X (in --permissions, only
# what is on: the rest stays as it is); --allow-Y with --no-allow-(what Y
# needs) contradicts itself. PERM_ALSO_OFF lists what was turned off this way.
PERM_ALSO_OFF=''
perm_cascade() {
  for _p in $PERMISSIONS; do
    _n=$(perm_need "$_p")
    [ -n "$_n" ] && [ "$(perm_flag "$_n")" = no ] || continue
    case $(perm_flag "$_p") in
      yes) perm_refuse "$_p needs $_n, so it can't be allowed while $_n is turned off" ;;
      no) ;;
      *)
        [ "${1:-}" != permissions ] || [ "$(perm_state "$_p")" = yes ] || continue
        perm_set "$_p" no
        [ "$(perm_state "$_p")" != yes ] || PERM_ALSO_OFF="$PERM_ALSO_OFF $_p"
        ;;
    esac
  done
}

# perm_summary prints what Rowsafe may do here now, and how to change it.
perm_summary() {
  say ""
  _any=''
  for _p in $PERMISSIONS; do [ -n "$(perm_why "$_p")" ] || _any=1; done
  if [ -z "$_any" ] && { [ "$HOST_ENGINE" != postgresql ] || ! perm_has_postgres; }; then
    step "What Rowsafe may do on $(uname -n)"
    note "Nothing to allow here: none of these permissions apply to this server"
    note "(no database service under systemd, no apt, no nftables)."
    return 0
  fi
  step "What Rowsafe may do on $(uname -n), only when someone clicks it and confirms"
  _first_on='' _first_off='' _rows_off='' _rows_na=''
  for _p in $PERMISSIONS; do
    if [ "$_p" = pooler-public ] && [ "$(perm_state pooler)" != yes ]; then continue; fi
    if [ "$(perm_state "$_p")" = yes ]; then
      printf '    %-12s %-17s %s\n' allowed "$_p" "$(perm_desc "$_p")"
      _first_on=${_first_on:-$_p}
      continue
    fi
    _why=$(perm_why "$_p")
    if [ -n "$_why" ]; then
      _rows_na="$_rows_na$(printf '    %-12s %-17s %s' unavailable "$_p" "$_why")
"
    else
      _rows_off="$_rows_off$(printf '    %-12s %-17s %s' 'not allowed' "$_p" "$(perm_desc "$_p")")
"
      _first_off=${_first_off:-$_p}
    fi
  done
  printf '%s%s' "$_rows_off" "$_rows_na"
  [ -z "$_first_off" ] || note "Allow one:          sudo rowsafe-allow $(perm_chain "$_first_off")"
  [ -z "$_first_on" ] || note "Stop allowing one:  sudo rowsafe-allow --remove $_first_on"
  return 0
}

# install_allow_command installs `rowsafe-allow` (root's, 0755).
install_allow_command() {
  install -d -m 0755 -o root -g root "${ALLOW_COMMAND%/*}"
  write_file "$ALLOW_COMMAND" 0755 root:root <<'ROWSAFE_ALLOW_EOF' || true
#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# rowsafe-allow: change what Rowsafe may do on this server.
#
# Installed by https://rowsafe.sh/install as /usr/local/sbin/rowsafe-allow
# (root, 0755). Rowsafe only restarts PostgreSQL, installs updates, reboots,
# manages PgBouncer or the firewall when someone clicks that in the
# dashboard and confirms, and only what root allowed on the server. This is
# how root changes that after the install:
#
#   sudo rowsafe-allow                      what Rowsafe may do here
#   sudo rowsafe-allow restart reboot       allow these
#   sudo rowsafe-allow --remove reboot      stop allowing these
#
# Changes run the installer's permissions-only mode (--permissions) from the
# copy the installer keeps in /usr/local/lib/rowsafe, checked against the
# signed release when it was put there. Passkeys (--add-owner) run root's
# copy of the agent there too (rowsafe-permissions), never the binary in
# /opt/rowsafe, which the agent's user owns.

set -u
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
installer=/usr/local/lib/rowsafe/install.sh
helper=/usr/local/lib/rowsafe/rowsafe-permissions
owners=/etc/rowsafe/owners
update='curl -fsSL https://rowsafe.sh | sudo sh'
names='restart create-cluster updates security-updates reboot pooler pooler-public firewall tuning sqlite-modes'

usage() {
  cat <<'EOF'
rowsafe-allow: change what Rowsafe may do on this server.

Rowsafe only does these when someone clicks them in your dashboard and
confirms. Root decides here which ones it may do at all.

  sudo rowsafe-allow                       show what Rowsafe may do here
  sudo rowsafe-allow NAME...               allow these, e.g.
                                             sudo rowsafe-allow restart security-updates
  sudo rowsafe-allow --remove NAME...      stop allowing these, e.g.
                                             sudo rowsafe-allow --remove reboot
  sudo rowsafe-allow --files PATH          back up a folder (uploads) with its database
                                           and let Rowsafe put restored files back there
  sudo rowsafe-allow --remove files        stop putting restored files back

Names:
  restart            restart or stop PostgreSQL (Restart, Rewind in place)
  create-cluster     create a PostgreSQL cluster here for a fork (needs restart)
  updates            install PostgreSQL updates and upgrades (needs restart)
  security-updates   install this server's security updates (needs restart)
  reboot             reboot this server after an update (needs security-updates)
  pooler             install and manage PgBouncer (connection pooling)
  pooler-public      let PgBouncer listen on public addresses (needs pooler)
  firewall           limit who can reach the database's port (never SSH or other ports)
  tuning             change MongoDB's or ClickHouse's settings, in Rowsafe's own file
  sqlite-modes       close the listed SQLite files to other users (owners and ACLs stay)

  sudo rowsafe-allow pooler-target ADDRESS PORT
                           let ProxySQL send connections to the MySQL on another
                           server (the new primary after a standby's promotion)
  sudo rowsafe-allow --remove pooler-target ADDRESS PORT   stop that

Turning one off also turns off what needs it.
EOF
  if passkeys; then
    cat <<'EOF'

One-click changes from the dashboard, signed with a passkey you pair here:
  sudo rowsafe-allow --add-owner           pair a passkey (prints a link to open in your browser)
  sudo rowsafe-allow --owners              list the paired passkeys
  sudo rowsafe-allow --remove-owner FINGERPRINT   unpair one
EOF
  fi
}

fail() {
  printf 'rowsafe-allow: %s\n' "$1" >&2
  exit "${2:-1}"
}

# root_file PATH: a regular file that root owns and only root can change.
root_file() {
  [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c '%u' "$1")" = 0 ] || return 1
  case $(stat -c '%A' "$1") in
    ?????w???? | ????????w?) return 1 ;;
  esac
}

# installer_ok: root's installer copy is there and has --permissions.
installer_ok() {
  root_file "$installer" && grep -q -- '--permissions)' "$installer"
}

need_installer() {
  installer_ok || fail "Rowsafe on this server is too old for this (or isn't installed). Update it first: $update"
}

# passkeys: root's copy of the agent is there and can pair passkeys.
passkeys() {
  root_file "$helper" && "$helper" --help >/dev/null 2>&1
}

owner_cmd() {
  passkeys || fail "Rowsafe on this server is too old for passkeys. Update it first: $update"
  exec "$helper" "$@"
}

# installed_version: the agent's version, so a change never updates Rowsafe
# on the side.
installed_version() {
  _l=$(readlink /opt/rowsafe/rowsafe-agent 2>/dev/null) || return 0
  case $_l in
    versions/*/rowsafe-agent) _l=${_l#versions/} && printf '%s\n' "${_l%/rowsafe-agent}" ;;
  esac
}

# list_owners prints the paired passkeys (/etc/rowsafe/owners, root's).
list_owners() {
  passkeys || return 0
  echo ""
  if ! root_file "$owners" || ! grep -q '"credential_id"' "$owners"; then
    echo "One-click changes from the dashboard: pair a passkey with sudo rowsafe-allow --add-owner"
    return 0
  fi
  echo "Passkeys that can change these with one click in the dashboard:"
  { tr -d '\r\n' <"$owners" && echo; } | sed 's/}[[:space:]]*,[[:space:]]*{/}\n{/g' | while IFS= read -r _o; do
    _fp=$(printf '%s\n' "$_o" | sed -n 's/.*"fingerprint"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    _name=$(printf '%s\n' "$_o" | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    _at=$(printf '%s\n' "$_o" | sed -n 's/.*"added_at"[[:space:]]*:[[:space:]]*"\([0-9-]\{10\}\).*/\1/p')
    [ -n "$_fp" ] || continue
    printf '    %s  %s%s\n' "$_fp" "${_name:-(no name)}" "${_at:+, added $_at}"
  done
  echo "    Unpair one: sudo rowsafe-allow --remove-owner FINGERPRINT"
}

case ${1:-} in
  -h | --help | help)
    usage
    exit 0
    ;;
esac

if [ "$(id -u)" != 0 ]; then
  fail "only root can see or change what Rowsafe may do on this server. Run it with sudo: sudo rowsafe-allow${*:+ $*}"
fi

case ${1:-} in
  '')
    need_installer
    "$installer" --permissions || exit $?
    list_owners
    exit 0
    ;;
  --add-owner)
    shift
    owner_cmd pair "$@"
    ;;
  --owners)
    [ $# = 1 ] || fail "--owners takes nothing else" 2
    owner_cmd owners
    ;;
  --remove-owner)
    [ $# = 2 ] || fail "which passkey? sudo rowsafe-allow --remove-owner FINGERPRINT (sudo rowsafe-allow --owners lists them)" 2
    owner_cmd remove-owner "$2"
    ;;
  --files)
    need_installer
    set -- "$@" --end
    _args=''
    while [ "$1" != --end ]; do
      [ "$1" = --files ] && [ "$2" != --end ] || fail "use: sudo rowsafe-allow --files /path/to/folder [--files /another/folder]" 2
      case $2 in
        /*) ;;
        *) fail "--files needs the folder's full path, e.g. /var/www/uploads" 2 ;;
      esac
      _args="$_args --files $2"
      shift 2
    done
    # The installer's files flow, on the installed version, without the
    # database questions. (Paths have no spaces: the installer refuses them.)
    # shellcheck disable=SC2086 # one word per argument
    exec env ROWSAFE_VERSION="$(installed_version)" "$installer" --no-setup $_args --allow-files
    ;;
esac

# pooler-target ADDRESS PORT (ProxySQL may send connections to another server).
case "${1:-} ${2:-}" in
  "pooler-target "* | "--remove pooler-target")
    _flag=--allow-pooler-target
    if [ "$1" = --remove ]; then
      _flag=--no-allow-pooler-target
      shift
    fi
    [ $# = 3 ] || fail "use: sudo rowsafe-allow pooler-target ADDRESS PORT, e.g. sudo rowsafe-allow pooler-target 10.0.0.6 3306" 2
    printf '%s\n' "$2" | grep -Eqx '[0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*|[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?' ||
      fail "'$2' isn't an address: give the other server's IP address or host name" 2
    case $3 in '' | *[!0-9]* | 0*) fail "'$3' isn't a port" 2 ;; esac
    [ "${#3}" -le 5 ] && [ "$3" -le 65535 ] || fail "'$3' isn't a port" 2
    _target=$2:$3
    case $2 in *:*) _target="[$2]:$3" ;; esac
    need_installer
    exec "$installer" --permissions --no-prompt "$_flag" "$_target"
    ;;
esac

_flags='' _off=0 _any=0
for _a in "$@"; do
  case $_a in
    --remove)
      _off=1
      continue
      ;;
    files)
      [ "$_off" = 1 ] || fail "name the folder: sudo rowsafe-allow --files /var/www/uploads" 2
      _flags="$_flags --no-allow-files"
      ;;
    -*) fail "unknown option $_a (see sudo rowsafe-allow --help)" 2 ;;
    *)
      case " $names " in
        *" $_a "*) ;;
        *) fail "there is no permission called '$_a'. The names: $(echo "$names" | sed 's/ /, /g')" 2 ;;
      esac
      if [ "$_off" = 1 ]; then _flags="$_flags --no-allow-$_a"; else _flags="$_flags --allow-$_a"; fi
      ;;
  esac
  _any=1
done
[ "$_any" = 1 ] || fail "--remove needs a name, e.g. sudo rowsafe-allow --remove reboot" 2
need_installer
# shellcheck disable=SC2086 # one word per flag
exec "$installer" --permissions --no-prompt $_flags
ROWSAFE_ALLOW_EOF
}

# installer_entry MANIFEST reads the installer's entry of the verified
# manifest into INST_URL, INST_SHA and INST_SIZE; it fails for releases from
# before the manifest listed the installer.
installer_entry() {
  _e=$(tr -d ' \t\r\n' <"$1" | sed -n 's|.*"install\.sh":{\([^}]*\)}.*|\1|p')
  [ -n "$_e" ] || return 1
  INST_URL=$(printf '%s\n' "$_e" | sed -n 's/.*"url":"\([^"]*\)".*/\1/p')
  INST_SHA=$(printf '%s\n' "$_e" | sed -n 's/.*"sha256":"\([^"]*\)".*/\1/p')
  INST_SIZE=$(printf '%s\n' "$_e" | sed -n 's/.*"size":\([0-9]*\).*/\1/p')
  printf '%s\n' "$INST_URL" | grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._~/%+-]*/install\.sh$' &&
    printf '%s\n' "$INST_SHA" | grep -Eq '^[0-9a-f]{64}$' &&
    printf '%s\n' "$INST_SIZE" | grep -Eq '^[1-9][0-9]{0,6}$' && [ "$INST_SIZE" -le 4194304 ] || {
    warn "the signed manifest's entry for the installer is malformed; not keeping a copy of it"
    return 1
  }
}

# install_installer_copy leaves the installer of the release in
# $TMP/manifest.json (verified) at $INSTALLER_COPY, root's, for
# `sudo rowsafe-allow`: this very script when it is that installer, else a
# download. Its SHA-256 and size must match the signed manifest; an
# unverified copy is never installed.
install_installer_copy() {
  # A newer version than the channel's stays installed: so does its installer.
  [ "$KEEP_INSTALLED" = 0 ] || [ ! -f "$INSTALLER_COPY" ] || return 0
  installer_entry "$TMP/manifest.json" || {
    [ -f "$INSTALLER_COPY" ] || note "release $REL_VERSION predates \`sudo rowsafe-allow\`; it works once Rowsafe is updated"
    return 0
  }
  if [ -f "$INSTALLER_COPY" ] && [ "$(sha256_of "$INSTALLER_COPY")" = "$INST_SHA" ]; then
    return 0
  fi
  rm -f "$TMP/install.sh"
  # Run from a file (sh install.sh, or the copy itself): that file, when it
  # is the signed one. Piped from curl: the release's own copy.
  if ! { [ -f "$0" ] && cat -- "$0" >"$TMP/install.sh" 2>/dev/null && [ "$(sha256_of "$TMP/install.sh")" = "$INST_SHA" ]; }; then
    rm -f "$TMP/install.sh"
    fetch "$INST_URL" "$TMP/install.sh" || {
      warn "could not download $INST_URL, so \`sudo rowsafe-allow\` can't change anything yet; run the installer again later"
      return 0
    }
  fi
  if [ "$(size_of "$TMP/install.sh")" != "$INST_SIZE" ] || [ "$(sha256_of "$TMP/install.sh")" != "$INST_SHA" ]; then
    warn "the installer downloaded from $INST_URL doesn't match the signed manifest; not keeping it"
    return 0
  fi
  install -m 0755 -o root -g root "$TMP/install.sh" "$INSTALLER_COPY.rowsafe-new"
  mv -f "$INSTALLER_COPY.rowsafe-new" "$INSTALLER_COPY"
  ok "installer $REL_VERSION kept at $INSTALLER_COPY for \`sudo rowsafe-allow\` (checked against the signed manifest)"
}

# permissions_main is --permissions.
permissions_main() {
  require_root
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
  [ -f "$ENV_FILE" ] && [ -e "$INSTALL_DIR/rowsafe-agent" ] ||
    perm_refuse "Rowsafe isn't installed on this server. Install it first: curl -fsSL https://rowsafe.sh | sudo sh"
  # The agent's user and engine, as the install set them up.
  AGENT_USER=$(stat -c '%U' "$ENV_FILE")
  case $AGENT_USER in
    postgres) HOST_ENGINE=postgresql AGENT_HOME=/var/lib/postgresql ;;
    mysql) HOST_ENGINE=mysql AGENT_HOME=$STATE_DIR ;;
    *)
      HOST_ENGINE=mongodb AGENT_HOME=$STATE_DIR
      [ ! -f "/etc/systemd/system/$SERVICE.d/10-clickhouse.conf" ] || HOST_ENGINE=clickhouse
      if [ -f "/etc/systemd/system/$SERVICE.d/10-redis.conf" ]; then # redis
        HOST_ENGINE=redis
        ! grep -q 'runs Valkey' "/etc/systemd/system/$SERVICE.d/10-redis.conf" || HOST_ENGINE=valkey
      fi
      ;;
  esac
  PERM_READY=1
  # One change at a time (the dashboard's and the terminal's).
  if have flock && (: >>/run/rowsafe-permissions.lock) 2>/dev/null; then
    exec 9>>/run/rowsafe-permissions.lock
    flock -w 120 9 || die "another change to what Rowsafe may do is running; try again in a minute"
  fi
  PERM_QUIET=1
  _want=''
  for _p in $PERMISSIONS; do [ -z "$(perm_flag "$_p")" ] || _want=1; done
  if [ -z "$_want" ] && [ "$ALLOW_FILES" != no ]; then
    perm_summary
    return 0
  fi
  perm_cascade permissions
  # Check everything first: refused means nothing changed.
  for _p in $PERMISSIONS; do
    [ "$(perm_flag "$_p")" = yes ] || continue
    _n=$(perm_need "$_p")
    if [ -n "$_n" ] && ! perm_on "$_n"; then
      perm_refuse "$_p only works with $_n allowed too. Allow them together: sudo rowsafe-allow $(perm_chain "$_p")"
    fi
    [ "$(perm_state "$_p")" != yes ] || continue
    _why=$(perm_why "$_p")
    [ -z "$_why" ] || perm_refuse "Rowsafe can't $(perm_desc "$_p" | sed 's/ (.*//') on this server: $_why"
  done
  _before=''
  for _p in $PERMISSIONS; do _before="$_before $_p=$(perm_state "$_p")"; done

  if [ -d "$STATE_DIR" ]; then as_agent mkdir -p -m 0700 "$RESTART_DIR" "$POOLER_DIR" 2>/dev/null || true; fi
  [ "$ALLOW_RESTART" != yes ] || allow_restarts
  case $ALLOW_CREATE_CLUSTER in
    yes) allow_create_clusters ;;
    no) disallow_create_clusters ;;
  esac
  [ -z "$ALLOW_UPDATES$ALLOW_SECURITY$ALLOW_REBOOT" ] || update_access
  case $ALLOW_POOLER in
    yes) allow_pooler ;;
    no) disallow_pooler ;;
    *) if [ -n "$ALLOW_POOLER_PUBLIC" ] && [ "$(perm_state pooler)" = yes ]; then refresh_pooler; fi ;;
  esac
  case $ALLOW_FIREWALL in
    yes) allow_firewall ;;
    no) disallow_firewall ;;
  esac
  case $ALLOW_TUNING in
    yes) allow_tuning ;;
    no) disallow_tuning ;;
  esac
  case $ALLOW_SQLITE_MODES in
    yes) allow_sqlite_modes ;;
    no) disallow_sqlite_modes ;;
  esac
  [ -z "$POOLER_TARGET_ADD$POOLER_TARGET_DEL" ] || pooler_target_change
  [ "$ALLOW_RESTART" != no ] || disallow_restarts
  if [ "$ALLOW_FILES" = no ]; then
    disallow_files
    ok "putting restored files back from Rowsafe is off (restores wait next to the folder)"
  fi
  install_allow_command

  say ""
  for _p in $PERMISSIONS; do
    _was=$(printf '%s\n' "$_before" | tr ' ' '\n' | sed -n "s/^$_p=//p")
    _now=$(perm_state "$_p")
    [ "$_was" != "$_now" ] || [ "$(perm_flag "$_p")" = yes ] || continue
    case $_now in
      yes) ok "$_p: allowed" ;;
      *)
        case " $PERM_ALSO_OFF " in
          *" $_p "*) ok "$_p: not allowed any more (it needs $(perm_need "$_p"))" ;;
          *) ok "$_p: not allowed" ;;
        esac
        ;;
    esac
  done
  _failed=''
  for _p in $PERMISSIONS; do
    if [ "$(perm_flag "$_p")" = yes ] && [ "$(perm_state "$_p")" != yes ]; then _failed="$_failed $_p"; fi
  done
  perm_summary
  if [ -n "$_failed" ]; then
    printf '%serror:%s could not allow%s (see above)\n' "$RED" "$RESET" "$_failed" >&2
    exit 1
  fi
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

# ---------------------------------------------------------------- connect in the browser

# json_str KEY FILE prints the first string value of "KEY" in a one-line JSON
# document (the control plane's answers); json_num the same for a number.
json_str() { sed -n 's/.*"'"$1"'":"\([^"]*\)".*/\1/p' "$2" 2>/dev/null | head -n 1; }
json_num() { sed -n 's/.*"'"$1"'":\([0-9][0-9]*\).*/\1/p' "$2" 2>/dev/null | head -n 1; }

# api_post URL JSON OUT posts JSON to the control plane, keeps the answer in
# OUT (readable by root only: it may hold a token) and its HTTP status in
# API_STATUS (000 when the request itself failed).
api_post() {
  API_STATUS=$(
    umask 077
    curl -sS --proto-redir '=https' --connect-timeout 15 --max-time 30 \
      -H 'Content-Type: application/json' --data "$2" -o "$3" -w '%{http_code}' "$1" </dev/null 2>/dev/null
  ) || API_STATUS=000
  [ "$API_STATUS" != 000 ]
}

# connect_in_browser runs when this server isn't enrolled yet, has no
# enrollment token, and someone is at the terminal. It asks the control
# plane for a code, prints a link that opens the approval page with the code
# filled in, and waits while someone who can add servers approves it in the
# dashboard. Approving returns a single-use enrollment token for this server
# only (never an API key); from there the install goes on as with rse_...
# Nothing on the host has changed yet when this runs.
connect_in_browser() {
  [ ! -f "$STATE_DIR/agent.json" ] || return 0
  [ -z "$(s_get ROWSAFE_ENROLL_TOKEN)" ] || return 0
  [ "$TTY" = 1 ] || return 0
  _api=$(s_get ROWSAFE_URL)
  [ -n "$_api" ] || _api=https://api.rowsafe.sh
  _api=${_api%/}
  _name=$(uname -n | tr -cd 'A-Za-z0-9._-' | cut -c1-100)
  [ -n "$_name" ] || _name=server
  _os=$(printf '%s' "$OS_NAME" | tr -d '"\\' | tr -cd '[:print:]' | cut -c1-100)

  step "Connecting this server to your Rowsafe account"
  if ! api_post "$_api/v1/auth/device" "{\"client_name\":\"$_name\",\"purpose\":\"host\",\"os\":\"$_os\"}" "$TMP/device.json" ||
    [ "$API_STATUS" != 200 ]; then
    # Unreachable, or an older control plane: fall back to a token.
    _why=$(json_str error "$TMP/device.json")
    if [ -z "$_why" ]; then
      if [ "$API_STATUS" = 000 ]; then _why="could not reach $_api"; else _why="HTTP $API_STATUS"; fi
    fi
    rm -f "$TMP/device.json"
    warn "could not start the approval in the browser ($_why)"
    return 0
  fi
  _device=$(json_str device_code "$TMP/device.json")
  _code=$(json_str user_code "$TMP/device.json")
  _link=$(json_str verification_uri_complete "$TMP/device.json")
  _interval=$(json_num interval "$TMP/device.json")
  _expires=$(json_num expires_in "$TMP/device.json")
  rm -f "$TMP/device.json"
  if [ -z "$_device" ] || [ -z "$_code" ]; then
    warn "the control plane's answer had no code; continuing without it"
    return 0
  fi
  case $_link in https://* | http://localhost* | http://127.0.0.1*) ;; *) die "the control plane sent an unexpected approval link" ;; esac
  [ -n "$_interval" ] || _interval=3
  [ -n "$_expires" ] || _expires=600

  say ""
  say "    Open this link and approve the server:"
  say ""
  say "      ${BOLD}$_link${RESET}"
  say ""
  say "    The page shows the code ${BOLD}$_code${RESET}: it should match. Waiting for your approval..."
  _waited=0
  while [ "$_waited" -lt "$_expires" ]; do
    sleep "$_interval"
    _waited=$((_waited + _interval))
    api_post "$_api/v1/auth/device/token" "{\"device_code\":\"$_device\"}" "$TMP/device-token.json" || continue # a network blip: keep waiting
    case $API_STATUS in
      200)
        _tok=$(json_str enroll_token "$TMP/device-token.json")
        _org=$(json_str name "$TMP/device-token.json" | tr -cd '[:print:]')
        rm -f "$TMP/device-token.json"
        case $_tok in rse_*) ;; *) die "the approval did not return an enrollment token; run the installer again" ;; esac
        # Never echo the token, not even in errors.
        ROWSAFE_ENROLL_TOKEN=$_tok
        export ROWSAFE_ENROLL_TOKEN
        ok "approved${_org:+: this server joins $_org}"
        return 0
        ;;
      400)
        case $(json_str error "$TMP/device-token.json") in
          authorization_pending) ;;
          slow_down) _interval=$((_interval + 5)) ;;
          access_denied) die "the connection was declined in the browser; nothing was changed on this server" ;;
          expired_token) die "the code expired before it was approved; run the installer again for a new one" ;;
          *) die "the control plane refused the approval: $(json_str error "$TMP/device-token.json")" ;;
        esac
        ;;
      429 | 5??) ;; # busy or restarting: keep waiting
      *) die "the control plane answered HTTP $API_STATUS while waiting for the approval" ;;
    esac
  done
  rm -f "$TMP/device-token.json"
  die "the code expired before it was approved; run the installer again for a new one"
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
  if [ "$C_ENGINE" = sqlite ]; then # sqlite: a file
    printf 'SQLite database %s (%s)' "$C_SOCK" "$C_SIZE"
    return 0
  fi
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
  if [ "$C_ENGINE" = clickhouse ] && ! clickhouse_prepare; then
    note "Backups for $C_NAME are not on yet. Run this installer again when you're ready."
    return 0
  fi
  if { [ "$C_ENGINE" = redis ] || [ "$C_ENGINE" = valkey ]; } && ! redis_prepare; then
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
    note "No running $(engine_label) found that the agent can reach. Once it runs, run this installer again."
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
        if [ "$C_ENGINE" = mongodb ] && [ "$C_DBS" = - ] &&
          { [ "$M_CLONES" = yes ] || [ "$MONGODB_STANDBY" = yes ] ||
            { [ "$TTY" = 1 ] && confirm "It has no databases. Keep it empty, ready to become another server's standby or to receive clones?" n && MONGODB_STANDBY=yes; }; }; then
          M_CLONES=yes
          # No replica set of its own: a standby joins the primary's set.
          M_ADMIN='' M_ADMIN_PW=''
          if mongodb_status && mongodb_login; then
            [ "$MONGODB_STANDBY" != yes ] || mongodb_standby_allow || true
            ok "MongoDB on port $C_PORT is ready to receive clones${MONGODB_STANDBY:+ or become a standby}: pick this server in the dashboard"
          fi
          continue
        fi
        if [ "$C_ENGINE" = clickhouse ] && { [ "$C_DBS" = - ] || [ "$C_DBS" = default ]; } &&
          { [ "$CH_CLONES" = yes ] || { [ "$TTY" = 1 ] && confirm "It has no databases. Keep it empty, ready to receive clones of a ClickHouse database from another server?" n; }; }; then
          CH_CLONES=yes
          if clickhouse_prepare; then
            ok "ClickHouse on port $C_PORT is ready to receive clones: pick this server when you fork a ClickHouse database in the dashboard"
          fi
          continue
        fi
        if { [ "$C_ENGINE" = mysql ] || [ "$C_ENGINE" = mariadb ]; } && [ "$C_DBS" = - ] && [ "$MYSQL_STANDBY" != no ] && # mysql
          { [ "$MYSQL_STANDBY" = yes ] || { [ "$TTY" = 1 ] && confirm "It has no databases. Keep it empty, ready to become the standby of a database on another server?" n; }; }; then
          MYSQL_STANDBY=yes
          if mysql_account; then
            ok "$(engine_label "$C_ENGINE") on port $C_PORT is ready to hold a standby: pick this server under Standby in the dashboard"
          fi
          continue
        fi
        if [ "$_count" -gt 1 ] && [ "$C_ENGINE" != sqlite ] && ! confirm "Set up backups for it?" y; then
          continue
        fi
        ask_name
        ;;
    esac
    protect_cluster
  done 4<"$TMP/clusters"
}

# protect_unattended is --protect NAME: no questions, and no restart, except
# of the PostgreSQL --install-postgres installed (a new, empty server).
protect_unattended() {
  step "Turning on backups for $PROTECT_NAME"
  _sqlite=$(printf '%s' "$SQLITE_PATHS" | head -n 1) # sqlite
  if [ -n "$_sqlite" ]; then
    _real=$(readlink -f -- "$_sqlite" 2>/dev/null || printf '%s' "$_sqlite")
    _line=$(awk -F '\t' -v p="$_sqlite" -v r="$_real" '$14 == "sqlite" && ($2 == p || $2 == r)' "$TMP/clusters" | head -n 1)
    [ -n "$_line" ] || die "the agent can't use the SQLite file $_sqlite (see above)"
  elif [ -n "$PROTECT_PORT" ]; then
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
  if [ "$C_ENGINE" = clickhouse ]; then
    clickhouse_prepare || die "ClickHouse on port $C_PORT isn't ready for backups (see above)"
  fi
  if [ "$C_ENGINE" = redis ] || [ "$C_ENGINE" = valkey ]; then
    redis_prepare || die "$(engine_label "$C_ENGINE") on port $C_PORT isn't ready for backups (see above)"
  fi
  _prc=0
  plan_cluster || _prc=$?
  case $_prc in
    0) ;;
    5) return 0 ;;
    10)
      restart_new_or_later
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
    10) restart_new_or_later ;;
    *) die "turning on backups for $PROTECT_NAME failed (see above)" ;;
  esac
}

# restart_new_or_later: backups wait for a restart. The PostgreSQL that
# --install-postgres installed in this run (or an earlier one) is restarted
# right away; any other is left for a person to restart.
restart_new_or_later() {
  if [ "$PG_OURS" = 1 ] && [ "$C_ENGINE" = postgresql ] && [ "$C_MAJOR" = "$INSTALL_PG" ] && [ "$C_CLUSTER" = main ] &&
    restart_postgres; then
    finish_setup 3m
    return 0
  fi
  restart_later
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
  [ "$ALLOW_TUNING" != no ] || disallow_tuning
  [ "$ALLOW_SQLITE_MODES" != no ] || disallow_sqlite_modes
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
    [ "$ALLOW_TUNING" = yes ] || [ "$ALLOW_SQLITE_MODES" = yes ] || grep -qsx 'sqlite-paths' "$SQLITE_MODES_ALLOW_FILE" ||
    [ "$ALLOW_POOLER" = yes ] || grep -qs '^[0-9]' "$POOLER_ALLOW_FILE"; then
    say ""
    step "Looking for $(engine_label) on this server"
    if ! discover; then
      [ -z "$PROTECT_NAME" ] || die "could not look for PostgreSQL (see above)"
      next_steps
      return 0
    fi
    PERM_QUIET=$TTY # on a terminal, the summary below says it all
    restart_access
    [ -n "$ALLOW_CREATE_CLUSTER" ] || create_cluster_access # forks
    update_access
    pooler_access
    firewall_access
    tuning_access
    sqlite_modes_access
    PERM_QUIET=0
  fi
  perm_summary # permissions section
  offer_passkey
  if [ -n "$PROTECT_NAME" ]; then
    protect_unattended
  elif [ "$interactive" = 1 ]; then
    setup_databases
  elif [ "$NO_SETUP" = 0 ] || [ -z "$FILES_PATHS" ]; then
    next_steps
  fi
  files_setup # files section
}

# --- permissions helper (permit-host) ---
#
# One-click permission changes. Root pairs a passkey at the terminal
# (`sudo rowsafe-allow --add-owner`); afterwards a person can change what
# Rowsafe may do here from the dashboard, each change signed in the browser
# with that passkey. The agent (unprivileged) writes the signed change to
# $PERMISSIONS_DIR; rowsafe-permissions.path starts
# rowsafe-permissions.service (root), which runs root's own copy of the
# agent binary ($PERMISSIONS_HELPER apply): it reads the request as the
# agent user, checks the signature against the passkeys root paired
# ($CONFIG_DIR/owners) and this server's Rowsafe ID, and only then runs
# root's copy of this installer in its permissions-only mode. Installed on
# every server: with no paired passkey it refuses every request, so it
# grants nothing by itself.
PERMISSIONS_HELPER=$LIB_DIR/rowsafe-permissions
PERMISSIONS_SERVICE_FILE=/etc/systemd/system/rowsafe-permissions.service
PERMISSIONS_PATH_FILE=/etc/systemd/system/rowsafe-permissions.path
PERMISSIONS_DIR=$STATE_DIR/permissions

# offer_passkey: on a terminal, offer once to pair a passkey, so what
# Rowsafe may do here changes with one click in the dashboard, signed by the
# person (root compares a code here first). A "no" is remembered; pairing
# stays one command away (sudo rowsafe-allow --add-owner).
offer_passkey() {
  [ "$TTY" = 1 ] && [ "$PROMPT" != never ] || return 0
  [ "$HOST_ENGINE" = postgresql ] && perm_has_postgres || return 0
  [ -x "$PERMISSIONS_HELPER" ] && [ ! -L "$PERMISSIONS_HELPER" ] && [ "$(stat -c %u "$PERMISSIONS_HELPER" 2>/dev/null)" = 0 ] || return 0
  ! grep -qs '"credential_id"' "$CONFIG_DIR/owners" || return 0
  [ ! -e "$CONFIG_DIR/passkey-declined" ] || return 0
  say ""
  step "Change these from your dashboard"
  note "Pair your passkey (Face ID, Touch ID or a security key) with this server:"
  note "then you can allow or stop any of the above with one click in Rowsafe,"
  note "signed by you. Rowsafe itself can't change them."
  if confirm "Pair a passkey now?" y; then
    "$PERMISSIONS_HELPER" pair </dev/tty >&3 2>&3 || note "Not paired. Pair any time with: sudo rowsafe-allow --add-owner"
  else
    write_file "$CONFIG_DIR/passkey-declined" 0644 root:root <<'EOF_DECLINED' || true
# Pairing a passkey was declined at install; it isn't offered again.
# Pair one any time with: sudo rowsafe-allow --add-owner
EOF_DECLINED
    note "Pair one any time with: sudo rowsafe-allow --add-owner"
  fi
}

install_permissions_helper() {
  # Root runs only root's files: a copy of rowsafe-agent checked against the
  # signed manifest, never the one in $INSTALL_DIR (the agent user's).
  _src=''
  if [ -f "$TMP/rowsafe-agent" ]; then
    _src=$TMP/rowsafe-agent # downloaded and checked just now
  elif [ "$KEEP_INSTALLED" = 0 ] && as_agent cat "$STAGED" >"$TMP/rowsafe-permissions" 2>/dev/null; then
    _src=$TMP/rowsafe-permissions # read as the agent user, checked below
  fi
  if [ -n "$_src" ] && [ "$(sha256_of "$_src")" = "$REL_SHA" ]; then
    if [ ! -f "$PERMISSIONS_HELPER" ] || ! cmp -s "$_src" "$PERMISSIONS_HELPER"; then
      install -m 0755 -o root -g root "$_src" "$PERMISSIONS_HELPER.rowsafe-new"
      mv -f "$PERMISSIONS_HELPER.rowsafe-new" "$PERMISSIONS_HELPER"
    fi
  elif [ ! -f "$PERMISSIONS_HELPER" ]; then
    warn "one-click permission changes are not set up: no checked copy of rowsafe-agent $REL_VERSION (run the installer again)"
    return 0
  fi
  as_agent mkdir -p -m 0700 "$PERMISSIONS_DIR"
  _changed=0
  if sed "s/@AGENT_USER@/$AGENT_USER/" <<'ROWSAFE_PERMISSIONS_SERVICE_EOF' | write_file "$PERMISSIONS_SERVICE_FILE" 0644 root:root; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-permissions.service: applies a permission change a person made in
# the Rowsafe dashboard, signed with a passkey root paired with this server
# (sudo rowsafe-allow --add-owner). Started by rowsafe-permissions.path when
# the agent hands over a request; installed by https://rowsafe.sh/install.
#
# /usr/local/lib/rowsafe/rowsafe-permissions (root's copy of rowsafe-agent)
# reads the request as the agent user, verifies the WebAuthn signature
# against /etc/rowsafe/owners and this server's Rowsafe ID, refuses a
# request used before or expired, and only then runs root's copy of the
# installer (/usr/local/lib/rowsafe/install.sh --permissions --no-prompt
# --allow-X/--no-allow-X). With no paired passkey it refuses everything.

[Unit]
Description=Rowsafe: apply a permission change signed with an owner's passkey
Documentation=https://rowsafe.sh/docs/guides/permissions
# No start limit: a burst of requests (each refused in milliseconds unless
# signed) must not leave rowsafe-permissions.path stopped until a reboot.
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/lib/rowsafe/rowsafe-permissions apply
# The agent user, whose privileges read and remove the request.
Environment=ROWSAFE_AGENT_USER=@AGENT_USER@
TimeoutStartSec=15min
# The answer: root's own directory, which the agent can read.
RuntimeDirectory=rowsafe-permissions
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
# The requests already applied (each applies once), out of the agent's reach.
StateDirectory=rowsafe-permissions
StateDirectoryMode=0700
UMask=0022

# The installer it runs writes root's allow lists (/etc/rowsafe), helper
# units (/etc/systemd/system) and helper scripts (/usr/local/lib/rowsafe),
# and enables them, so the file system can't be read-only and capabilities
# stay. What it can't do: reach the network beyond this server (the
# permissions-only mode downloads nothing), gain privileges, make
# set-user-ID files, or touch kernel settings and modules.
NoNewPrivileges=yes
RestrictSUIDSGID=yes
ProtectHome=read-only
PrivateTmp=yes
IPAddressDeny=any
IPAddressAllow=localhost
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
RestrictRealtime=yes
SystemCallArchitectures=native
ROWSAFE_PERMISSIONS_SERVICE_EOF
    _changed=1
  fi
  if write_file "$PERMISSIONS_PATH_FILE" 0644 root:root <<'ROWSAFE_PERMISSIONS_PATH_EOF'; then
# SPDX-License-Identifier: Apache-2.0
# rowsafe-permissions.path: starts rowsafe-permissions.service when the
# Rowsafe agent hands over a permission change signed with a passkey root
# paired with this server. Installed by https://rowsafe.sh/install.

[Unit]
Description=Rowsafe: watch for permission changes signed with an owner's passkey
Documentation=https://rowsafe.sh/docs/guides/permissions

[Path]
PathExists=/var/lib/rowsafe/permissions/request
Unit=rowsafe-permissions.service

[Install]
WantedBy=multi-user.target
ROWSAFE_PERMISSIONS_PATH_EOF
    _changed=1
  fi
  if systemd_running; then
    [ "$_changed" = 0 ] || systemctl daemon-reload
    systemctl enable --now --quiet rowsafe-permissions.path
  else
    warn "systemd is not running here; the permissions helper was installed but cannot be enabled"
  fi
}

remove_permissions_helper() {
  [ -e "$PERMISSIONS_PATH_FILE" ] || [ -e "$PERMISSIONS_SERVICE_FILE" ] || [ -e "$PERMISSIONS_HELPER" ] || return 0
  if systemd_running; then
    systemctl disable --now --quiet rowsafe-permissions.path 2>/dev/null || true
  fi
  rm -rf /var/lib/rowsafe-permissions /run/rowsafe-permissions
  rm -f "$PERMISSIONS_PATH_FILE" "$PERMISSIONS_SERVICE_FILE" "$PERMISSIONS_HELPER"
  if systemd_running; then systemctl daemon-reload; fi
}
# --- end permissions helper ---

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
  [ "$HOST_ENGINE" != mongodb ] || TOOLS_SUMMARY="mongodump and the oplog, encrypted by the agent"
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
  [ "$M_LOGIN" = ok ] && [ -z "$M_CLONES" ] && [ -z "$MONGODB_STANDBY" ] && return 0
  _rc=0
  mongodb_as_admin login ${M_CLONES:+--clones} ${MONGODB_STANDBY:+--standby} >"$TMP/mlogin" 2>&1 || _rc=$?
  while [ "$_rc" = 11 ] || [ "$_rc" = 12 ]; do
    [ "$_rc" = 12 ] && { tty_bad "MongoDB refused that login."; M_ADMIN=''; }
    [ "$_rc" = 11 ] && [ -n "$M_ADMIN" ] && { tty_bad "That user can't create users."; M_ADMIN=''; }
    mongodb_admin || { warn "MongoDB has access control on: set ROWSAFE_MONGODB_ADMIN_USER and ROWSAFE_MONGODB_ADMIN_PASSWORD (used once, never saved), or run the installer on a terminal"; return 1; }
    [ -n "${ROWSAFE_MONGODB_ADMIN_USER:-}" ] && [ "$_rc" = 12 ] && return 1
    _rc=0
    mongodb_as_admin login ${M_CLONES:+--clones} ${MONGODB_STANDBY:+--standby} >"$TMP/mlogin" 2>&1 || _rc=$?
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

MONGODB_STANDBY_ALLOW_FILE=$CONFIG_DIR/mongodb-standby-allowed

# mongodb_standby_allow lists the MongoDB on C_PORT in the standby allow
# list ("PORT UNIT CONFIG"): root's helper may then hand out its replica
# set key file, or add replSetName, keyFile and an address to its
# configuration (keeping a copy). It restarts nothing by itself.
mongodb_standby_allow() {
  if [ -z "$M_CONFIG" ] || [ "$M_CONFIG" = - ] || [ ! -f "$M_CONFIG" ] || [ -z "$M_UNIT" ]; then
    warn "MongoDB on port $C_PORT isn't started from a configuration file by a systemd unit the installer knows, so standby servers stay off for it"
    return 1
  fi
  {
    echo "# MongoDB servers Rowsafe may make part of a standby pair (written by the installer, root's)."
    echo "# PORT UNIT CONFIG"
    grep -s '^[0-9]' "$MONGODB_STANDBY_ALLOW_FILE" | awk -v p="$C_PORT" '$1 != p'
    echo "$C_PORT $M_UNIT $M_CONFIG"
  } >"$TMP/mstandby"
  write_file "$MONGODB_STANDBY_ALLOW_FILE" 0644 root:root <"$TMP/mstandby" || true
  restart_allowed "$C_PORT" || warn "standby servers also need Rowsafe to restart MongoDB here when someone confirms: run the installer with --allow-restart"
  perm_ok "Rowsafe may set up standby servers with MongoDB on port $C_PORT (it restarts it only when someone confirms)"
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
  [ "$MONGODB_STANDBY" != yes ] || mongodb_standby_allow || true
}

# ---------------------------------------------------------------- ClickHouse
#
# ClickHouse servers are found by `rowsafe-agent setup discover` like
# PostgreSQL clusters (engine column "clickhouse"). Backups go through
# ClickHouse's own BACKUP command, so no backup tool is installed; Proof and
# Rewind copies run the server's own `clickhouse` program. Before their
# plan, Rowsafe gets its own ClickHouse user ("rowsafe", random password
# saved for the agent only):
#   - preferably as root: the agent prints a users.d file (password hash
#     only, 127.0.0.1 and ::1 only) that root installs next to the server's
#     users.xml; ClickHouse loads it by itself within seconds, no restart;
#   - otherwise with an administrator's login, once (CREATE USER and GRANT;
#     the password is never stored).

CLICKHOUSE_USERS_DIR=/etc/clickhouse-server/users.d
CLICKHOUSE_USERS_FILE=$CLICKHOUSE_USERS_DIR/rowsafe.xml

clickhouse_present() {
  have clickhouse-server || [ -x /usr/bin/clickhouse-server ] ||
    [ -f /lib/systemd/system/clickhouse-server.service ] || [ -f /etc/systemd/system/clickhouse-server.service ] ||
    { have pgrep && pgrep -x 'clickhouse-serv(er)?' >/dev/null 2>&1; }
}

# check_clickhouse_program: Proof and Rewind copies start a temporary
# ClickHouse with the server's own program, which ships with its package.
check_clickhouse_program() {
  clickhouse_present || return 0
  [ "$HOST_ENGINE" != clickhouse ] || TOOLS_SUMMARY="ClickHouse's own BACKUP, encrypted by the agent"
  if have clickhouse || [ -x /usr/bin/clickhouse ]; then
    ok "ClickHouse program at $(command -v clickhouse || echo /usr/bin/clickhouse) (Proof and Rewind copies use it)"
  else
    warn "the clickhouse program isn't on this server: backups work, but Proof (the weekly restore test) and Rewind copies need it. It comes with ClickHouse's own packages (clickhouse-common-static, installed with clickhouse-server)."
  fi
}

# clickhouse_status reads `rowsafe-agent clickhouse status` into CH_* variables.
CH_LOGIN='' CH_USERSD='' CH_BINARY='' CH_DOCKER=''
clickhouse_status() {
  agent_run clickhouse status --port "$C_PORT" >"$TMP/chstatus" 2>"$TMP/chstatus.err" || return 1
  _k() { sed -n "s/^$1=//p" "$TMP/chstatus" | head -n 1; }
  CH_LOGIN=$(_k login) CH_USERSD=$(_k usersd) CH_BINARY=$(_k binary)
  CH_DOCKER=$(_k docker)
  [ "$CH_USERSD" != - ] || CH_USERSD=''
  [ "$CH_BINARY" != - ] || CH_BINARY=''
}

# clickhouse_users_file adds Rowsafe's ClickHouse user as root: the agent
# makes the password (saved for the agent only) and prints the users.d file,
# root installs it (root:clickhouse 0640), then waits up to 30 seconds for
# ClickHouse to load it. Fails, removing the file, when it can't.
clickhouse_users_file() {
  [ "$CH_DOCKER" != yes ] || return 1 # its users.d is inside the container
  _dir=${CH_USERSD:-$CLICKHOUSE_USERS_DIR}
  if [ ! -d "$_dir" ]; then
    # ClickHouse reads users.d next to its users.xml even when the package made none.
    [ -f "${_dir%/*}/users.xml" ] || return 1
    install -d -m 0755 -o root -g root "$_dir"
  fi
  # Readable by ClickHouse only: its group from the packages, else users.xml's.
  _grp=clickhouse
  getent group clickhouse >/dev/null 2>&1 || _grp=$(stat -c %G "${_dir%/*}/users.xml" 2>/dev/null || echo root)
  if ! agent_run clickhouse login --port "$C_PORT" --users-xml ${CH_CLONES:+--clones} >"$TMP/chusers.xml" 2>"$TMP/chlogin.err" ||
    ! grep -q '<clickhouse>' "$TMP/chusers.xml"; then
    sed 's/^/    /' "$TMP/chlogin.err" >&2
    return 1
  fi
  _mode=0640
  [ "$_grp" != root ] || _mode=0644 # a hash of a long random password, nothing more
  write_file "$_dir/rowsafe.xml" "$_mode" "root:$_grp" <"$TMP/chusers.xml" || true
  rm -f "$TMP/chusers.xml"
  _i=0
  until clickhouse_status && [ "$CH_LOGIN" = ok ]; do
    if [ $_i -ge 30 ]; then
      rm -f "$_dir/rowsafe.xml"
      warn "ClickHouse didn't load $_dir/rowsafe.xml within 30 seconds (its users may come from elsewhere); removed it"
      return 1
    fi
    sleep 1
    _i=$((_i + 1))
  done
  ok "$_dir/rowsafe.xml: Rowsafe's own ClickHouse user, rowsafe (ClickHouse loaded it by itself, without a restart)"
}

# clickhouse_admin asks for (or takes from the environment) an
# administrator's login, into CH_ADMIN and CH_ADMIN_PW. Never stored.
CH_ADMIN='' CH_ADMIN_PW=''
clickhouse_admin() {
  [ -z "$CH_ADMIN" ] || return 0
  if [ -n "${ROWSAFE_CLICKHOUSE_ADMIN_USER:-}" ]; then
    CH_ADMIN=$ROWSAFE_CLICKHOUSE_ADMIN_USER CH_ADMIN_PW=${ROWSAFE_CLICKHOUSE_ADMIN_PASSWORD:-}
    return 0
  fi
  [ "$TTY" = 1 ] || return 1
  tty_say ""
  tty_say "To create Rowsafe's own ClickHouse user, an administrator signs in once (a user"
  tty_say "allowed to create users and grant access). The password is used for this only"
  tty_say "and never saved."
  ask CH_ADMIN "ClickHouse administrator user" default
  ask_secret CH_ADMIN_PW "Password for $CH_ADMIN"
}

# clickhouse_as_admin CMD...: run an agent clickhouse command, as an
# administrator when one signed in. Its exit status is the command's.
clickhouse_as_admin() {
  if [ -n "$CH_ADMIN" ]; then
    printf '%s\n' "$CH_ADMIN_PW" | agent_in clickhouse "$@" --port "$C_PORT" --admin-user "$CH_ADMIN"
  else
    agent_run clickhouse "$@" --port "$C_PORT"
  fi
}

# clickhouse_login creates Rowsafe's ClickHouse user with SQL: first as
# "default" without a password (a new server), then as an administrator.
clickhouse_login() {
  _rc=0
  clickhouse_as_admin login ${CH_CLONES:+--clones} >"$TMP/chlogin" 2>&1 || _rc=$?
  while [ "$_rc" = 11 ] || [ "$_rc" = 12 ] || [ "$_rc" = 13 ]; do
    if [ -n "$CH_ADMIN" ]; then
      # That administrator didn't do: refused (12) or can't create users (13).
      if [ -n "${ROWSAFE_CLICKHOUSE_ADMIN_USER:-}" ] || [ "$TTY" != 1 ]; then
        sed 's/^/    /' "$TMP/chlogin" >&2
        return 1
      fi
      case $_rc in
        12) tty_bad "ClickHouse refused that login." ;;
        *) tty_bad "That user can't create users in ClickHouse." ;;
      esac
      CH_ADMIN=''
    fi
    clickhouse_admin || {
      warn "Rowsafe needs its own ClickHouse user: set ROWSAFE_CLICKHOUSE_ADMIN_USER and ROWSAFE_CLICKHOUSE_ADMIN_PASSWORD (used once, never saved), or run the installer on a terminal"
      return 1
    }
    _rc=0
    clickhouse_as_admin login ${CH_CLONES:+--clones} >"$TMP/chlogin" 2>&1 || _rc=$?
  done
  sed 's/^/    /' "$TMP/chlogin"
  [ "$_rc" = 0 ]
}

# clickhouse_prepare gets a ClickHouse server ready for its plan: Rowsafe's
# own user, root's way first. Nothing restarts.
clickhouse_prepare() {
  CH_ADMIN='' CH_ADMIN_PW=''
  if ! clickhouse_status; then
    sed 's/^/    /' "$TMP/chstatus.err" >&2
    warn "could not reach ClickHouse on port $C_PORT (its HTTP interface)"
    return 1
  fi
  [ -n "$CH_BINARY" ] || note "Proof and Rewind copies need the clickhouse program, which comes with ClickHouse's server package; it isn't on this server."
  [ "$CH_LOGIN" = ok ] && [ -z "$CH_CLONES" ] && return 0
  say ""
  note "Rowsafe needs its own ClickHouse user, rowsafe, to take backups and watch the"
  note "server's health. Its password is random and saved for the agent only."
  clickhouse_users_file && return 0
  clickhouse_login
}

# ---------------------------------------------------------------- Redis and Valkey
#
# Redis and Valkey servers are found by `rowsafe-agent setup discover` like
# PostgreSQL clusters (engine column "redis" or "valkey"). Backups come from
# the server itself over its replication link (a snapshot, then the stream
# of changes), so no backup tool is installed and nothing restarts; Proof
# and Rewind copies run the server's own program (redis-server or
# valkey-server). Before their plan, Rowsafe gets its own ACL user
# ("rowsafe", random password saved for the agent only): as the default
# user when that needs no password, otherwise with an administrator's login
# once (never stored). The server keeps the user in its ACL file or its
# configuration file; when it can't write them, root adds the user's line
# (the password's hash, never the password) to the configuration file.

redis_present() {
  if have redis-server || have valkey-server || [ -x /usr/bin/redis-server ] || [ -x /usr/bin/valkey-server ]; then
    return 0
  fi
  for _d in /lib/systemd/system /usr/lib/systemd/system /etc/systemd/system; do
    for _u in redis-server redis valkey-server valkey redis-server@ valkey-server@; do
      [ ! -f "$_d/$_u.service" ] || return 0
    done
  done
  have pgrep && pgrep -x 'redis-server|valkey-server' >/dev/null 2>&1
}

# redis_find_program sets REDIS_BIN, REDIS_FOUND_ENGINE (redis or valkey)
# and REDIS_VERSION from the first server program that says what it is
# (`redis-server --version`; Debian's valkey-redis-compat names Valkey's
# program redis-server too). Fails when there is none.
REDIS_BIN='' REDIS_FOUND_ENGINE='' REDIS_VERSION=''
redis_find_program() {
  REDIS_BIN='' REDIS_FOUND_ENGINE='' REDIS_VERSION=''
  for _b in "$(command -v redis-server 2>/dev/null)" "$(command -v valkey-server 2>/dev/null)" \
    /usr/bin/redis-server /usr/bin/valkey-server /usr/local/bin/redis-server /usr/local/bin/valkey-server; do
    [ -n "$_b" ] && [ -f "$_b" ] && [ -x "$_b" ] || continue
    _v=$("$_b" --version 2>/dev/null | sed -En 's/^(Redis|Valkey) server v=([0-9]+\.[0-9]+\.[0-9]+).*/\1 \2/p' | head -n 1 | tr '[:upper:]' '[:lower:]')
    [ -n "$_v" ] || continue
    REDIS_BIN=$_b REDIS_FOUND_ENGINE=${_v%% *} REDIS_VERSION=${_v#* }
    return 0
  done
  return 1
}

# redis_too_old ENGINE VERSION prints why that server is too old for
# Rowsafe (Redis 7.0, Valkey 7.2), nothing when it isn't.
redis_too_old() {
  _maj=${2%%.*} _min=${2#*.}
  _min=${_min%%.*}
  case $_maj$_min in '' | *[!0-9]*) return 0 ;; esac
  if [ "$1" = valkey ]; then
    if [ "$_maj" -lt 7 ] || { [ "$_maj" -eq 7 ] && [ "$_min" -lt 2 ]; }; then
      echo "Valkey $2 is too old: Rowsafe needs Valkey 7.2 or newer"
    fi
  elif [ "$_maj" -lt 7 ]; then
    echo "Redis $2 is too old: Rowsafe needs Redis 7.0 or newer (Redis's own packages, from packages.redis.io, have it for ${OS_NAME:-this system})"
  fi
}

# check_redis_program: Proof and Rewind copies start a temporary server with
# the server's own program, which ships with its package.
check_redis_program() {
  redis_present || return 0
  case $HOST_ENGINE in redis | valkey) TOOLS_SUMMARY="$(engine_label)'s own replication stream, encrypted by the agent" ;; esac
  if redis_find_program; then
    ok "$(engine_label "$REDIS_FOUND_ENGINE") program at $REDIS_BIN ($REDIS_VERSION; Proof and Rewind copies use it)"
  else
    warn "the redis-server (or valkey-server) program isn't on this server: backups work, but Proof (the weekly restore test) and Rewind copies need it. It comes with the server's own package (redis-server or valkey-server)."
  fi
}

# redis_status reads `rowsafe-agent redis status` into RD_* variables ("-"
# becomes empty).
RD_LOGIN='' RD_VERSION='' RD_CONFIG='' RD_ACLFILE='' RD_DATADIR='' RD_DBFILE='' RD_DOCKER='' RD_CLUSTER='' RD_BINARY=''
redis_status() {
  agent_run redis status --port "$C_PORT" --engine "$C_ENGINE" >"$TMP/rdstatus" 2>"$TMP/rdstatus.err" || return 1
  _rk() { sed -n "s/^$1=//p" "$TMP/rdstatus" | head -n 1 | sed 's/^-$//'; }
  RD_LOGIN=$(_rk login) RD_VERSION=$(_rk version) RD_CONFIG=$(_rk config) RD_ACLFILE=$(_rk aclfile)
  RD_DATADIR=$(_rk datadir) RD_DBFILE=$(_rk dbfilename) RD_DOCKER=$(_rk docker) RD_CLUSTER=$(_rk cluster)
  RD_BINARY=$(_rk binary)
}

# redis_supported says why Rowsafe can't protect the server on $C_PORT
# (Redis Cluster, too old), and fails then. The agent's plan refuses the
# same; this says it before anything is asked.
redis_supported() {
  if [ "$RD_CLUSTER" = yes ]; then
    warn "$(engine_label "$C_ENGINE") on port $C_PORT runs in cluster mode (Redis Cluster), which Rowsafe doesn't protect yet: only standalone servers, with or without replicas"
    return 1
  fi
  [ -n "$RD_VERSION" ] || return 0
  _why=$(redis_too_old "$C_ENGINE" "$RD_VERSION")
  [ -z "$_why" ] || {
    warn "$_why"
    return 1
  }
}

# redis_admin asks for (or takes from the environment) an administrator's
# login, into RD_ADMIN and RD_ADMIN_PW. Never stored.
RD_ADMIN='' RD_ADMIN_PW=''
redis_admin() {
  [ -z "$RD_ADMIN" ] || return 0
  if [ -n "${ROWSAFE_REDIS_ADMIN_USER:-}" ]; then
    RD_ADMIN=$ROWSAFE_REDIS_ADMIN_USER RD_ADMIN_PW=${ROWSAFE_REDIS_ADMIN_PASSWORD:-}
    return 0
  fi
  [ "$TTY" = 1 ] || return 1
  tty_say ""
  tty_say "$(engine_label "$C_ENGINE") asks for a password. To create Rowsafe's own user, an administrator"
  tty_say "signs in once (a user allowed to create users; on a server with only a"
  tty_say "password, the user is default). The password is used for this only and never saved."
  ask RD_ADMIN "$(engine_label "$C_ENGINE") administrator user" default
  ask_secret RD_ADMIN_PW "Password for $RD_ADMIN"
}

# redis_as_admin CMD...: run an agent redis command, as an administrator
# when one signed in. Its exit status is the command's.
redis_as_admin() {
  if [ -n "$RD_ADMIN" ]; then
    printf '%s\n' "$RD_ADMIN_PW" | agent_in redis "$@" --port "$C_PORT" --engine "$C_ENGINE" --admin-user "$RD_ADMIN"
  else
    agent_run redis "$@" --port "$C_PORT" --engine "$C_ENGINE"
  fi
}

# redis_login creates (or refreshes) Rowsafe's ACL user: first as the
# default user without a password, then as an administrator (exit 11: a
# login is needed, 12: refused, 13: that user can't create users).
redis_login() {
  _name=$(engine_label "$C_ENGINE")
  _rc=0
  redis_as_admin login >"$TMP/rdlogin" 2>"$TMP/rdlogin.err" || _rc=$?
  while [ "$_rc" = 11 ] || [ "$_rc" = 12 ] || [ "$_rc" = 13 ]; do
    if [ -n "$RD_ADMIN" ]; then
      if [ -n "${ROWSAFE_REDIS_ADMIN_USER:-}" ] || [ "$TTY" != 1 ]; then
        sed 's/^/    /' "$TMP/rdlogin.err" >&2
        return 1
      fi
      case $_rc in
        13) tty_bad "That user can't create users in $_name (it needs the ACL command)." ;;
        *) tty_bad "$_name refused that login." ;;
      esac
      RD_ADMIN='' RD_ADMIN_PW=''
    fi
    redis_admin || {
      warn "Rowsafe needs its own $_name user: set ROWSAFE_REDIS_ADMIN_USER and ROWSAFE_REDIS_ADMIN_PASSWORD (used once, never saved), or run the installer on a terminal"
      return 1
    }
    _rc=0
    redis_as_admin login >"$TMP/rdlogin" 2>"$TMP/rdlogin.err" || _rc=$?
  done
  RD_ADMIN='' RD_ADMIN_PW=''
  if [ "$_rc" != 0 ]; then
    sed 's/^/    /' "$TMP/rdlogin.err" >&2
    return 1
  fi
  redis_keep_login
}

# redis_keep_login makes sure Rowsafe's user survives a restart: the server
# kept it itself (ACL file, configuration file), or root adds the user's
# line from the agent (the password's hash only) to the configuration file.
redis_keep_login() {
  _name=$(engine_label "$C_ENGINE")
  _persisted=$(sed -n 's/^persisted=//p' "$TMP/rdlogin" | head -n 1)
  _why=$(sed -n 's/^why=//p' "$TMP/rdlogin" | head -n 1)
  _line=$(sed -n 's/^acl_line=//p' "$TMP/rdlogin" | head -n 1)
  rm -f "$TMP/rdlogin"
  case $_persisted in
    aclfile)
      ok "Rowsafe's own $_name user, rowsafe, is ready ($_name keeps it in its ACL file)"
      return 0
      ;;
    config)
      ok "Rowsafe's own $_name user, rowsafe, is ready ($_name keeps it in its configuration file)"
      return 0
      ;;
  esac
  ok "Rowsafe's own $_name user, rowsafe, is ready"
  redis_status || true
  if [ -n "$RD_CONFIG" ] && [ -z "$RD_ACLFILE" ] && [ "$RD_DOCKER" != yes ] && redis_conf_add "$RD_CONFIG" "$_line"; then
    ok "added it to $RD_CONFIG, so $_name keeps it when it restarts"
    return 0
  fi
  warn "$_name forgets Rowsafe's user when it restarts${_why:+ ($_why)}. To keep it, give $_name an ACL file (the aclfile setting) or a configuration file it can write, then run this installer again."
}

# redis_conf_add FILE LINE puts the agent's "user rowsafe on #<sha256> ..."
# line in the server's configuration file (replacing an earlier one),
# keeping its owner and mode. Only a well-formed line, in a regular file.
redis_conf_add() {
  matches "$2" '^user rowsafe on #[0-9a-f]{64}( [-+~@|*a-z0-9]+)+$' || return 1
  case $1 in /*) ;; *) return 1 ;; esac
  [ -f "$1" ] && [ ! -L "$1" ] || return 1
  _own=$(stat -c '%U:%G' "$1") && _mode=$(stat -c '%a' "$1") || return 1
  {
    grep -Ev '^[[:space:]]*user[[:space:]]+rowsafe([[:space:]]|$)' "$1" || true
    printf '%s\n' "$2"
  } | write_file "$1" "$_mode" "$_own" || true
  grep -qxF -- "$2" "$1"
}

# redis_snapshot_note says when the agent can't read the server's snapshot
# file. It needs it only when the server refuses to send a copy over
# replication; nothing is changed for it.
redis_snapshot_note() {
  [ "$RD_DOCKER" != yes ] && [ -n "$RD_DATADIR" ] && [ -n "$RD_DBFILE" ] && have setpriv || return 0
  _f=$RD_DATADIR/$RD_DBFILE
  case $_f in /*) ;; *) return 0 ;; esac
  [ -e "$_f" ] || return 0
  _gs=$(id -G "$AGENT_USER" 2>/dev/null | tr ' ' ',')
  if [ "$AGENT_USER" = rowsafe ]; then
    _g=$(redis_group)
    [ -z "$_g" ] || _gs="$_gs,$(getent group "$_g" | cut -d: -f3)"
  fi
  [ -n "$_gs" ] || return 0
  setpriv --reuid="$AGENT_USER" --regid="$AGENT_USER" --groups="$_gs" -- test -r "$_f" 2>/dev/null && return 0
  note "Rowsafe can't read $(engine_label "$C_ENGINE")'s snapshot file ($_f). It only needs it when"
  note "$(engine_label "$C_ENGINE") refuses to send Rowsafe a copy over replication; backups don't use it otherwise."
}

# redis_prepare gets a Redis or Valkey server ready for its plan: supported,
# and Rowsafe's own user. Nothing restarts.
redis_prepare() {
  RD_ADMIN='' RD_ADMIN_PW=''
  _name=$(engine_label "$C_ENGINE")
  if ! redis_status; then
    sed 's/^/    /' "$TMP/rdstatus.err" >&2
    warn "could not reach $_name on port $C_PORT"
    return 1
  fi
  redis_supported || return 1
  if [ "$RD_LOGIN" != ok ]; then
    say ""
    note "Rowsafe needs its own $_name user, rowsafe, to take backups and watch the"
    note "server's health. Its password is random and saved for the agent only."
    redis_login || return 1
    redis_status || true
    redis_supported || return 1
  fi
  if [ -z "$RD_BINARY" ]; then
    note "Proof and Rewind copies need the $C_ENGINE-server program, which comes with $_name's server package; it isn't on this server."
  fi
  redis_snapshot_note
}

# ---------------------------------------------------------------- modes

# >>> sqlite: a SQLite database is a file an app opens itself. The agent
# runs as rowsafe on a server without another database (as postgres next to
# PostgreSQL), and root gives it read and write access to each file it
# protects (sqlite_grant). The agent's list of files is $SQLITE_LIST.

# sqlite_path_ok PATH: an absolute path to a database file (not a side file).
sqlite_path_ok() {
  printf '%s\n' "$1" | grep -Eq '^/[A-Za-z0-9._@+,=/-]+$' || return 1
  case $1 in *-wal | *-shm | *-journal | */ | *//* | */../* | */./*) return 1 ;; esac
  return 0
}

# detect_sqlite_host: without PostgreSQL, MySQL/MariaDB, MongoDB and
# ClickHouse, the server's databases are SQLite files.
detect_sqlite_host() {
  [ "$HOST_ENGINE" = postgresql ] || return 0
  id -u postgres >/dev/null 2>&1 && return 0
  mongodb_present && return 0
  clickhouse_present && return 0
  HOST_ENGINE=sqlite
  use_rowsafe_user
  AGENT_HOME=$STATE_DIR
}

# sqlite_netfs DIR names DIR's filesystem when it is a network one.
sqlite_netfs() {
  _t=$(stat -f -c %T -- "$1" 2>/dev/null || true)
  case $_t in nfs* | cifs | smb* | fuse* | 9p | ceph | afs | lustre | gpfs) printf '%s' "$_t" ;; esac
}

# sqlite_grant FILE gives the agent's user read and write access to FILE,
# its -wal, -shm and -journal files and its folder, without changing owners,
# groups or anyone else's access: a POSIX ACL entry for the agent (the
# file's group bits then show the ACL mask, which SQLite copies to the side
# files it creates), and a default ACL on the folder so side files created
# later work for the agent and the file's owner. Folders above get "x" for
# the agent where it can't pass. It prints what changed.
sqlite_grant() {
  _f=$1
  _d=$(dirname -- "$_f")
  if [ ! -f "$_f" ]; then
    warn "$_f doesn't exist (or isn't a regular file); skipped"
    return 1
  fi
  _fs=$(sqlite_netfs "$_d")
  if [ -n "$_fs" ]; then
    warn "$_f is on a network filesystem ($_fs): SQLite's locking isn't reliable there, so Rowsafe doesn't protect it. Move it to a local disk."
    return 1
  fi
  _uid=$(stat -c %u -- "$_f")
  _owner=$(stat -c %U -- "$_f")
  _mode=$(stat -c %a -- "$_f")
  if [ "$_uid" = "$(id -u "$AGENT_USER")" ]; then
    ok "$_f belongs to $AGENT_USER already"
    return 0
  fi
  have setfacl || apt_install acl
  _g=$(( (0$_mode / 8) % 8 ))
  _o=$(( 0$_mode % 8 ))
  _perm() { case $1 in 7) echo rwx ;; 6) echo rw- ;; 5) echo r-x ;; 4) echo r-- ;; 3) echo -wx ;; 2) echo -w- ;; 1) echo --x ;; *) echo --- ;; esac; }
  if setfacl -m "u:$AGENT_USER:rw" -- "$_f" 2>"$TMP/acl.err"; then
    for _s in -wal -shm -journal; do
      [ ! -f "$_f$_s" ] || setfacl -m "u:$AGENT_USER:rw" -- "$_f$_s" || true
    done
    setfacl -m "u:$AGENT_USER:rwx" -- "$_d" &&
      setfacl -d -m "u::rw-,g::$(_perm "$_g"),o::$(_perm "$_o"),u:$AGENT_USER:rw-,u:$_owner:rw-" -- "$_d" || {
      warn "could not set the ACL on $_d: $(head -n 1 "$TMP/acl.err" 2>/dev/null)"
      return 1
    }
    _p=${_d%/*}
    while [ -n "$_p" ]; do
      as_agent test -x "$_p" 2>/dev/null || acl_grant_x "$_p" "$AGENT_USER" || true
      _p=${_p%/*}
    done
    ok "gave the agent ($AGENT_USER) read and write access to $_f, its -wal/-shm files and $_d (ACLs; owner, group and others' access unchanged)"
    return 0
  fi
  # No ACLs on this filesystem: the file's group, when it is its owner's
  # own group (nobody else is in it) and can already write.
  _group=$(stat -c %G -- "$_f")
  if [ "$_group" = "$_owner" ] && [ "$_g" -ge 6 ] && [ "$(( (0$(stat -c %a -- "$_d") / 8) % 8 ))" -ge 7 ]; then
    usermod -a -G "$_group" "$AGENT_USER" || return 1
    SQLITE_GROUPS="$SQLITE_GROUPS $_group"
    ok "added $AGENT_USER to the group $_group, which owns $_f and can write it (this filesystem has no ACLs)"
    return 0
  fi
  warn "can't give the agent access to $_f: this filesystem has no ACLs ($(head -n 1 "$TMP/acl.err" 2>/dev/null)), and its group ($_group) isn't $_owner's own group with write access. Make the file and its folder group-writable by a group only $_owner is in, then run the installer again."
  return 1
}
SQLITE_GROUPS=''

# sqlite_files decides which SQLite files the agent protects: the ones
# given with --sqlite, and (on a terminal) the ones running programs have
# open that the person picks; each gets access (sqlite_grant) and goes to
# $SQLITE_LIST.
sqlite_files() {
  [ "$NO_SETUP" = 0 ] || [ -n "$SQLITE_PATHS" ] || return 0
  _bin=$STAGED
  [ -x "$_bin" ] || _bin=$INSTALL_DIR/rowsafe-agent
  : >"$TMP/sqlite-chosen"
  printf '%s' "$SQLITE_PATHS" | while IFS= read -r _f; do
    [ -n "$_f" ] && printf '%s\n' "$_f" >>"$TMP/sqlite-chosen"
  done
  if [ "$TTY" = 1 ] && [ -z "$PROTECT_NAME" ] && [ -x "$_bin" ]; then
    "$_bin" sqlite find >"$TMP/sqlite-found" 2>/dev/null || : >"$TMP/sqlite-found"
    if [ -s "$TMP/sqlite-found" ]; then
      say ""
      step "Looking for SQLite databases that apps on this server have open"
      while IFS="$(printf '\t')" read -r _path _size _journal _pid _prog _ctr _cpath _uid _gid _sugg <&4; do
        if [ "$_path" = - ]; then
          note "Found $_cpath in container $_ctr ($_prog): it lives in the container's own layer, not in a volume, so the agent can't reach it. Put it in a volume to protect it."
          continue
        fi
        grep -qxF -- "$_path" "$TMP/sqlite-chosen" 2>/dev/null && continue
        grep -qxF -- "$_path" "$SQLITE_LIST" 2>/dev/null && { ok "$_path is already in Rowsafe's list"; continue; }
        _where="opened by $_prog"
        [ "$_ctr" = - ] || _where="$_where in container $_ctr ($_cpath)"
        _jm="continuous backups possible (WAL)"
        [ "$_journal" = wal ] || _jm="rollback journal: daily backups (Pulse can turn on WAL later)"
        if confirm "Protect $_path ($(numfmt --to=iec "$_size" 2>/dev/null || printf '%s bytes' "$_size"), $_where; $_jm)?" y; then
          printf '%s\n' "$_path" >>"$TMP/sqlite-chosen"
        fi
      done 4<"$TMP/sqlite-found"
    elif [ "$HOST_ENGINE" = sqlite ] && [ -z "$SQLITE_PATHS" ]; then
      note "No running app has a SQLite database open right now. Run the installer again with --sqlite /path/to/database.sqlite3 to add one."
    fi
  fi
  [ -s "$TMP/sqlite-chosen" ] || return 0
  step "Giving the agent access to the SQLite files"
  install -d -m 0755 "$CONFIG_DIR"
  [ -f "$SQLITE_LIST" ] || { : >"$SQLITE_LIST"; chmod 0644 "$SQLITE_LIST"; }
  while IFS= read -r _f; do
    _real=$(readlink -f -- "$_f" 2>/dev/null || printf '%s' "$_f")
    if sqlite_grant "$_real"; then
      grep -qxF -- "$_f" "$SQLITE_LIST" || printf '%s\n' "$_f" >>"$SQLITE_LIST"
    fi
  done <"$TMP/sqlite-chosen"
  chmod 0644 "$SQLITE_LIST"
  CHANGED=1
}

# sqlite_setup: a drop-in runs the agent as rowsafe on a SQLite server, in
# the groups sqlite_grant used, and lets it reach database folders under
# /home and /root, which the unit otherwise hides (ProtectHome).
sqlite_setup() {
  _dropin=/etc/systemd/system/$SERVICE.d
  _conf=''
  if [ "$HOST_ENGINE" = sqlite ]; then
    _conf="[Unit]\nAfter=network-online.target\n[Service]\nUser=rowsafe\nGroup=rowsafe\n"
  fi
  _groups=$(for _g in $SQLITE_GROUPS $(sed -n 's/^SupplementaryGroups=//p' "$_dropin/20-sqlite.conf" 2>/dev/null); do echo "$_g"; done | sort -u | tr '\n' ' ')
  _binds=''
  if [ -f "$SQLITE_CLONE_LIST" ]; then # clone folders under /home (sqlite_clone_dirs)
    while IFS= read -r _d; do
      case $_d in /home/* | /root/* | /run/user/*) [ ! -d "$_d" ] || _binds="$_binds $_d" ;; esac
    done <"$SQLITE_CLONE_LIST"
  fi
  if [ -f "$SQLITE_LIST" ]; then
    while IFS= read -r _f; do
      case $_f in /home/* | /root/* | /run/user/*)
        _d=$(dirname -- "$(readlink -f -- "$_f" 2>/dev/null || printf '%s' "$_f")")
        case " $_binds " in *" $_d "*) ;; *) _binds="$_binds $_d" ;; esac
        ;;
      esac
    done <"$SQLITE_LIST"
  fi
  [ -z "$_groups" ] || _conf="${_conf}[Service]\nSupplementaryGroups=${_groups% }\n"
  [ -z "$_binds" ] || _conf="${_conf}[Service]\nProtectHome=tmpfs\nBindPaths=${_binds# }\n"
  if [ -z "$_conf" ]; then
    for _old in 10-sqlite.conf 20-sqlite.conf; do
      [ ! -f "$_dropin/$_old" ] || { rm -f "$_dropin/$_old"; UNIT_CHANGED=1; CHANGED=1; }
    done
    return 0
  fi
  install -d -m 0755 "$_dropin"
  _name=20-sqlite.conf
  if [ "$HOST_ENGINE" = sqlite ]; then _name=10-sqlite.conf; rm -f "$_dropin/20-sqlite.conf"; else rm -f "$_dropin/10-sqlite.conf"; fi
  if printf "# Written by the Rowsafe installer: SQLite databases on this server.\n${_conf}" |
    write_file "$_dropin/$_name" 0644 root:root; then
    UNIT_CHANGED=1 CHANGED=1
  fi
}
# <<< sqlite

# >>> sqlite clones: folders root allows for SQLite clones (Fork), opt-in.
# The agent writes a clone as a new file there (never over an existing one)
# and lists the folders it may use from $SQLITE_CLONE_LIST.

# sqlite_clone_grant DIR gives the agent's user write access to DIR (made
# when missing): an ACL entry, and a default ACL so the new files work for
# the agent and the folder's owner; "x" on the folders above where needed.
sqlite_clone_grant() {
  _d=$1
  case $_d in /etc | /etc/* | /usr | /usr/* | /boot | /boot/* | /proc/* | /sys/* | /dev/* | /run | /run/* | /var/lib/rowsafe | /var/lib/rowsafe/*)
    warn "$_d can't hold clones (a system folder); skipped"
    return 1
    ;;
  esac
  if [ ! -e "$_d" ]; then
    install -d -m 0750 -- "$_d" || return 1
    ok "created $_d"
  fi
  if [ ! -d "$_d" ] || [ -L "$_d" ] || [ "$(readlink -f -- "$_d")" != "$_d" ]; then
    warn "$_d isn't a folder (or goes through a symbolic link): give the real folder's path; skipped"
    return 1
  fi
  _fs=$(sqlite_netfs "$_d")
  if [ -n "$_fs" ]; then
    warn "$_d is on a network filesystem ($_fs): SQLite's locking isn't reliable there; skipped"
    return 1
  fi
  if [ "$(stat -c %u -- "$_d")" = "$(id -u "$AGENT_USER")" ]; then
    ok "$_d belongs to $AGENT_USER already"
    return 0
  fi
  have setfacl || apt_install acl
  _owner=$(stat -c %U -- "$_d")
  _def="u::rw-,g::rw-,o::---,u:$AGENT_USER:rw-"
  [ "$_owner" = root ] || [ "$_owner" = "$AGENT_USER" ] || _def="$_def,u:$_owner:rw-"
  if setfacl -m "u:$AGENT_USER:rwx" -- "$_d" 2>"$TMP/acl.err" && setfacl -d -m "$_def" -- "$_d" 2>>"$TMP/acl.err"; then
    _p=${_d%/*}
    while [ -n "$_p" ]; do
      as_agent test -x "$_p" 2>/dev/null || acl_grant_x "$_p" "$AGENT_USER" || true
      _p=${_p%/*}
    done
    ok "the agent ($AGENT_USER) may write SQLite clones into $_d (ACLs; owner, group and others' access unchanged)"
    return 0
  fi
  warn "can't give the agent write access to $_d: $(head -n 1 "$TMP/acl.err" 2>/dev/null) (this filesystem may have no ACLs: make the folder belong to $AGENT_USER instead)"
  return 1
}

# sqlite_clone_dirs: the folders given with --sqlite-clone-dir and, on a
# terminal on a server with SQLite databases, one the person names when
# none is allowed yet; each gets access and goes to $SQLITE_CLONE_LIST.
sqlite_clone_dirs() {
  _chosen=$SQLITE_CLONE_DIRS
  if [ -z "$_chosen" ] && [ "$TTY" = 1 ] && [ -z "$PROTECT_NAME" ] && [ ! -s "$SQLITE_CLONE_LIST" ] &&
    { [ "$HOST_ENGINE" = sqlite ] || [ -s "$SQLITE_LIST" ]; }; then
    say ""
    if confirm "Allow Rowsafe to make clones of your SQLite databases (new files for staging or tests, never over an existing file) in a folder you pick?" n; then
      _cd=''
      while :; do
        ask _cd "Folder for the clones" /srv/sqlite-clones
        sqlite_path_ok "$_cd" && [ "$_cd" != / ] && break
        tty_hint "Give an absolute folder path (letters, digits and ._@+,=- only)."
      done
      _chosen="$_cd
"
    fi
  fi
  [ -n "$_chosen" ] || return 0
  step "Allowing folders for SQLite clones"
  install -d -m 0755 "$CONFIG_DIR"
  [ -f "$SQLITE_CLONE_LIST" ] || { : >"$SQLITE_CLONE_LIST"; chmod 0644 "$SQLITE_CLONE_LIST"; }
  printf '%s' "$_chosen" | while IFS= read -r _d; do
    [ -n "$_d" ] || continue
    if sqlite_clone_grant "$_d"; then
      grep -qxF -- "$_d" "$SQLITE_CLONE_LIST" || printf '%s\n' "$_d" >>"$SQLITE_CLONE_LIST"
    fi
  done
  chmod 0644 "$SQLITE_CLONE_LIST"
  CHANGED=1
}
# <<< sqlite clones

install_agent() {
  require_root
  detect_os
  detect_arch
  # Servers Rowsafe creates: PostgreSQL first, then the agent protects it.
  [ -z "$INSTALL_PG" ] || install_postgres
  [ "$FIREWALL_SSH" != yes ] || firewall_close_early
  [ "$LISTEN_PUBLIC" = 0 ] || listen_public
  detect_host_engine # mysql
  detect_mongodb_host # mongodb
  detect_clickhouse_host # clickhouse
  detect_redis_host # redis
  detect_sqlite_host # sqlite
  check_postgres
  if [ "$HOST_ENGINE" = sqlite ]; then
    say "${BOLD}Rowsafe agent installer${RESET}: backups, restore to any second and weekly"
    say "restore tests for the SQLite databases on this server. Nothing changes without your yes."
  elif [ "$HOST_ENGINE" = clickhouse ]; then
    say "${BOLD}Rowsafe agent installer${RESET}: backups, Marks and weekly restore tests for"
    say "the ClickHouse on this server. Nothing changes without your yes."
  else
    say "${BOLD}Rowsafe agent installer${RESET}: backups, restore to any second and weekly"
    say "restore tests for the $(engine_label) on this server. Nothing changes without your yes."
  fi
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

  # No enrollment token: have someone approve this server in the browser.
  connect_in_browser

  # 2. Dependencies and layout.
  # MongoDB, ClickHouse, Redis, Valkey and SQLite back up with their own tools: no pgBackRest.
  case $HOST_ENGINE in mysql | mariadb) ensure_mysql_tools ;; mongodb | clickhouse | redis | valkey | sqlite) ;; *) ensure_pgbackrest ;; esac # mysql
  ensure_mongodb_tools # mongodb (only where MongoDB runs)
  check_clickhouse_program # clickhouse (only where ClickHouse runs)
  check_redis_program # redis (only where Redis or Valkey runs)
  ensure_restic # files section
  step "Installing into $INSTALL_DIR"
  make_dirs
  [ "$need_binary" = 0 ] || install_binary
  install_installer_copy   # permissions section
  install_allow_command    # permissions section
  install_guard
  install_permissions_helper # permit-host: one-click permission changes
  sqlite_files # sqlite: which files, and the agent's access to them
  sqlite_clone_dirs # sqlite clones: folders root allows for them
  UNIT_CHANGED=0
  install_unit
  mysql_setup # mysql
  mongodb_setup # mongodb
  clickhouse_setup # clickhouse
  redis_setup # redis
  sqlite_setup # sqlite
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
    say "  - ROWSAFE_ENROLL_TOKEN comes from \`rowsafe hosts enroll-token\`, or run this"
    say "    installer from a terminal and approve the server in your browser instead."
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
  remove_files_units # files section
  rm -f "$FILES_ALLOW_FILE" "$RESTIC_BIN"
  remove_pooler_units
  remove_proxysql_units
  remove_chproxy_units
  remove_restart_helper
  remove_create_cluster
  remove_firewall_helper
  remove_sqlite_modes_helper
  remove_permissions_helper # permit-host
  rm -f "$GUARD_FILE" "$INSTALLER_COPY" "$ALLOW_COMMAND" # permissions section
  rmdir "$LIB_DIR" 2>/dev/null || true
  if systemd_running; then systemctl daemon-reload; fi
  rm -rf "$INSTALL_DIR"
  ok "service and $INSTALL_DIR removed"
  rm -f "/etc/systemd/system/$SERVICE.d/10-mysql.conf" # mysql
  rm -f "/etc/systemd/system/$SERVICE.d/10-mongodb.conf" "/etc/systemd/system/$SERVICE.d/10-clickhouse.conf"
  rm -f "/etc/systemd/system/$SERVICE.d/10-redis.conf" # redis
  if [ "$purge" = 1 ]; then
    if [ -L "$MYSQL_CONF_LINK" ]; then # mysql: keep the server's binary log settings
      cp "$CONFIG_DIR/mysql/server.cnf" "$MYSQL_CONF_LINK.rowsafe-new" 2>/dev/null &&
        mv -f "$MYSQL_CONF_LINK.rowsafe-new" "$MYSQL_CONF_LINK" || rm -f "$MYSQL_CONF_LINK"
    fi
    rm -rf "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR" "$LOGROTATE_FILE"
    ok "$CONFIG_DIR, $STATE_DIR, $LOG_DIR and $LOGROTATE_FILE deleted"
    if [ -f "$CLICKHOUSE_USERS_FILE" ]; then # clickhouse: its password went with $STATE_DIR
      rm -f "$CLICKHOUSE_USERS_FILE"
      ok "$CLICKHOUSE_USERS_FILE deleted (Rowsafe's ClickHouse user)"
    fi
    if redis_present; then # redis: its password went with $STATE_DIR
      note "Rowsafe's Redis or Valkey user, rowsafe, stays in the server (its password was deleted with the agent's settings)."
      note "To remove it: redis-cli ACL DELUSER rowsafe (or valkey-cli), then delete any 'user rowsafe' line in its configuration file."
    fi
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
      --mysql-standby) MYSQL_STANDBY=yes ;;
      --clickhouse-clones) CH_CLONES=yes ;;
      --mongodb-clones) M_CLONES=yes ;;
      --mongodb-standby) MONGODB_STANDBY=yes ;;
      --no-mysql-standby) MYSQL_STANDBY=no ;;
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
      --allow-tuning) ALLOW_TUNING=yes ;;
      --no-allow-tuning) ALLOW_TUNING=no ;;
      --allow-sqlite-modes) ALLOW_SQLITE_MODES=yes ;;
      --no-allow-sqlite-modes) ALLOW_SQLITE_MODES=no ;;
      --allow-pooler-target | --no-allow-pooler-target)
        [ $# -ge 2 ] || die "$1 needs ADDRESS:PORT"
        pooler_target_ok "$2" || die "$1: give the other server's address and MySQL port, e.g. 10.0.0.6:3306"
        if [ "$1" = --allow-pooler-target ]; then POOLER_TARGET_ADD=$2; else POOLER_TARGET_DEL=$2; fi
        shift
        ;;
      --firewall-ssh) FIREWALL_SSH=yes ;;
      --no-firewall-ssh) FIREWALL_SSH=no ;;
      --allow-pooler) ALLOW_POOLER=yes ;;
      --no-allow-pooler) ALLOW_POOLER=no ;;
      --allow-pooler-public) ALLOW_POOLER_PUBLIC=yes ;;
      --no-allow-pooler-public) ALLOW_POOLER_PUBLIC=no ;;
      --permissions) mode=permissions ;;
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
      --sqlite) # sqlite
        [ $# -ge 2 ] || die "--sqlite needs the database file's path"
        sqlite_path_ok "$2" || die "--sqlite: give the database file's absolute path (letters, digits and ._@+,=- only), not its -wal or -shm file"
        SQLITE_PATHS="$SQLITE_PATHS$2
"
        shift
        ;;
      --sqlite-clone-dir) # sqlite clones
        [ $# -ge 2 ] || die "--sqlite-clone-dir needs a folder's path"
        { sqlite_path_ok "$2" && [ "$2" != / ]; } || die "--sqlite-clone-dir: give the folder's absolute path (letters, digits and ._@+,=- only)"
        SQLITE_CLONE_DIRS="$SQLITE_CLONE_DIRS$2
"
        shift
        ;;
      --protect-port)
        [ $# -ge 2 ] || die "--protect-port needs a port"
        printf '%s\n' "$2" | grep -Eq '^[1-9][0-9]{0,4}$' || die "--protect-port needs a port number"
        PROTECT_PORT=$2
        shift
        ;;
      --install-postgres)
        [ $# -ge 2 ] || die "--install-postgres needs a PostgreSQL version (13-18)"
        case $2 in
          13 | 14 | 15 | 16 | 17 | 18) INSTALL_PG=$2 ;;
          *) die "--install-postgres: give a PostgreSQL major version from 13 to 18 (e.g. --install-postgres 17)" ;;
        esac
        shift
        ;;
      --listen-public) LISTEN_PUBLIC=1 ;;
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
  if [ "$mode" = permissions ]; then
    if [ "$NO_SETUP" = 1 ] || [ -n "$PROTECT_NAME$PROTECT_PORT$FILES_PATHS$MONGODB_REPLSET" ] || [ "$ALLOW_FILES" = yes ] || [ "$NO_FILES" = 1 ] || [ "$purge" = 1 ]; then
      perm_refuse "--permissions only changes what Rowsafe may do here: --allow-NAME, --no-allow-NAME and --no-allow-files (see --help)"
    fi
  elif [ "$mode" != install ] && { [ "$NO_SETUP" = 1 ] || [ -n "$PROTECT_NAME" ] || [ -n "$ALLOW_RESTART$ALLOW_UPDATES$ALLOW_SECURITY$ALLOW_REBOOT$ALLOW_FIREWALL$ALLOW_TUNING$ALLOW_SQLITE_MODES$ALLOW_POOLER$ALLOW_POOLER_PUBLIC$ALLOW_CREATE_CLUSTER$POOLER_TARGET_ADD$POOLER_TARGET_DEL" ]; }; then
    die "--no-setup, --protect and the --allow- options only go with an install"
  fi
  if [ "$mode" != install ] && [ "$mode" != permissions ] && { [ -n "$FILES_PATHS" ] || [ -n "$ALLOW_FILES" ] || [ "$NO_FILES" = 1 ]; }; then
    die "--files, --allow-files and --no-files only go with an install"
  fi
  if [ "$mode" != install ] && { [ -n "$INSTALL_PG" ] || [ "$LISTEN_PUBLIC" = 1 ]; }; then
    die "--install-postgres and --listen-public only go with an install"
  fi
  [ "$mode" = install ] || [ -z "$FIREWALL_SSH" ] || die "--firewall-ssh and --no-firewall-ssh only go with an install"
  if [ "$FIREWALL_SSH" = yes ]; then
    [ "$ALLOW_FIREWALL" != no ] || die "--firewall-ssh needs the firewall: it can't go with --no-allow-firewall"
    ALLOW_FIREWALL=yes
  fi
  # A permission that needs another one turned off: off too (permissions
  # section; --permissions does it once it knows the server).
  if [ "$mode" = install ]; then perm_cascade install; fi
  [ -z "$PROTECT_PORT" ] || [ -n "$PROTECT_NAME" ] || die "--protect-port only goes with --protect"
  if [ -n "$SQLITE_PATHS" ]; then # sqlite
    [ "$mode" = install ] || die "--sqlite only goes with an install"
    if [ -n "$PROTECT_NAME" ] && [ "$(printf '%s' "$SQLITE_PATHS" | grep -c .)" != 1 ]; then
      die "--protect turns on backups for one database: give exactly one --sqlite file with it"
    fi
  fi
  [ -z "$SQLITE_CLONE_DIRS" ] || [ "$mode" = install ] || die "--sqlite-clone-dir only goes with an install" # sqlite clones
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
    permissions) permissions_main ;;
  esac
}

main "$@"
