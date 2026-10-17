#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test the security check on a server on its own (the installer's
# --no-account), for real: a Debian server with systemd as PID 1 and a
# PostgreSQL left open the way many are (listening on every address, a
# pg_hba.conf rule that lets every address try passwords, new passwords
# hashed with MD5). The agent runs as its systemd unit with its own control
# plane (internal/localcp) on its Unix socket:
#
#   sudo rowsafe add saves shop on the server, sudo rowsafe security check
#   shows the findings in plain words with their fixes; a fix asks for the
#   database's name and changes nothing without it (no terminal, a wrong
#   name); typed right, the agent rewrites pg_hba.conf (a backup kept) so
#   only the allowed network may log in, and the app still can; MD5 hashing
#   becomes SCRAM; undo puts the old rules back; the firewall, which touches
#   the server itself, waits for root's yes (rowsafe-allow).
#
# Usage: sh scripts/test-no-account-security.sh [debian:trixie]   (needs Docker, ~2 min)

set -eu

fail() {
  echo "test-no-account-security: $*" >&2
  echo "---- agent journal" >&2
  journalctl -u rowsafe-agent --no-pager -n 80 >&2 || true
  exit 1
}

# until_ok SECONDS DESCRIPTION COMMAND...: retry COMMAND every 3 seconds.
until_ok() {
  _limit=$1 _what=$2
  shift 2
  _i=0
  until "$@" >/tmp/until.out 2>&1; do
    _i=$((_i + 3))
    [ "$_i" -lt "$_limit" ] || {
      cat /tmp/until.out >&2
      fail "timed out after ${_limit}s: $_what"
    }
    sleep 3
  done
  echo "  ok: $_what"
}

# typed ANSWER COMMAND: COMMAND at a terminal, with ANSWER typed in.
typed() {
  _answer=$1
  shift
  printf '%s\n' "$_answer" | script -qec "$*" /dev/null
}

in_container() {
  export DEBIAN_FRONTEND=noninteractive
  W=/w
  major=$(ls /usr/lib/postgresql)
  unit=postgresql@$major-main.service
  hba=/etc/postgresql/$major/main/pg_hba.conf

  # What the installer puts in place: the binaries, the agent's directories
  # and unit (restarts and the firewall not allowed).
  install -d -m 0755 /opt/rowsafe /usr/local/lib/rowsafe /etc/rowsafe
  install -m 0755 "$W/rowsafe-agent" /opt/rowsafe/rowsafe-agent
  install -m 0755 "$W/rowsafe" /usr/local/bin/rowsafe
  install -m 0755 /src/scripts/rowsafe-agent-guard /usr/local/lib/rowsafe/rowsafe-agent-guard
  install -m 0644 /src/deploy/systemd/rowsafe-agent.service /etc/systemd/system/
  install -d -m 0700 -o postgres -g postgres /var/lib/rowsafe /etc/rowsafe/pgbackrest /var/log/rowsafe
  umask 077
  cat >/etc/rowsafe/agent.env <<EOF
ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock
ROWSAFE_AUTO_UPDATE=false
ROWSAFE_HEARTBEAT_INTERVAL=5s
ROWSAFE_POLL_INTERVAL=2s
# Storage the agent needs to start; this test never backs up.
ROWSAFE_REPO_S3_ENDPOINT=storage.invalid
ROWSAFE_REPO_S3_BUCKET=rowsafe
ROWSAFE_REPO_S3_KEY=unused
ROWSAFE_REPO_S3_KEY_SECRET=unused
ROWSAFE_REPO_CIPHER_PASS=unused-unused-unused
EOF
  chown root:postgres /etc/rowsafe/agent.env
  chmod 0640 /etc/rowsafe/agent.env
  umask 022

  # The app's role (its password hashed with SCRAM, as Debian's rules for
  # this server want), then PostgreSQL opened the way many servers are.
  systemctl start "$unit"
  runuser -u postgres -- psql -qX -c "CREATE ROLE app LOGIN PASSWORD 'app-pw'" -c "CREATE DATABASE shop OWNER app" ||
    fail "the app role and database"
  runuser -u postgres -- psql -qX -c "ALTER SYSTEM SET listen_addresses = '*'" -c "ALTER SYSTEM SET password_encryption = 'md5'" ||
    fail "the weak settings"
  echo "host all all 0.0.0.0/0 md5" >>"$hba"
  systemctl restart "$unit"
  psql_app() { PGPASSWORD=app-pw psql -qAtX -h 127.0.0.1 -U app -d shop "$@"; }
  [ "$(psql_app -c 'SELECT 1')" = 1 ] || fail "the app can't log in"

  systemctl daemon-reload
  systemctl enable --now --quiet rowsafe-agent
  until_ok 30 "the agent's control plane listens" test -S /var/lib/rowsafe/control.sock
  echo "PostgreSQL $major (open to every address, MD5) and the agent (no account) are running"

  # Saved and registered on its server (backups not turned on: no terminal).
  rowsafe add shop "postgres://app:app-pw@localhost:5432/shop" </dev/null >/tmp/add.out 2>&1 || { cat /tmp/add.out; fail "rowsafe add"; }
  until_ok 30 "shop is on this server" sh -c "rowsafe ls | grep -q shop"

  # The check: findings in plain words, each with its fix.
  until_ok 60 "rowsafe security check shop" rowsafe security check shop
  cp /tmp/until.out /tmp/check.out
  cat /tmp/check.out
  grep -q "Access rules let every address try to log in" /tmp/check.out || fail "no finding for the open pg_hba rule"
  grep -q "New passwords are stored with old MD5 hashing" /tmp/check.out || fail "no finding for MD5 hashing"
  grep -q "Fix it: rowsafe security fix shop security_open_rules" /tmp/check.out || fail "the open rule's fix isn't shown"
  grep -q "from the internet runs from Rowsafe's own servers" /tmp/check.out || fail "the internet line doesn't say why it isn't checked"
  rowsafe security shop --json | grep -q '"grade": "C"\|"grade": "D"\|"grade": "B"' || fail "no grade"
  echo "  ok: the findings, in plain words, with their fixes"

  # No confirmation, or the wrong name: nothing changes.
  ! rowsafe security fix shop security_open_rules --allow 10.0.0.0/8 </dev/null >/tmp/nofix.out 2>&1 || fail "fixed without a confirmation"
  grep -q -- "--yes" /tmp/nofix.out || { cat /tmp/nofix.out; fail "no word on how to confirm"; }
  ! typed nope "rowsafe security fix shop security_open_rules --allow 10.0.0.0/8" >/tmp/wrong.out 2>&1 || fail "fixed with the wrong name"
  grep -q "0.0.0.0/0" "$hba" || fail "pg_hba.conf changed without a confirmation"
  echo "  ok: nothing changes without the database's name"

  # Typed right: only 10.0.0.0/8 may log in from the network; this server still can.
  typed shop "rowsafe security fix shop security_open_rules --allow 10.0.0.0/8" | tee /tmp/fix.out || fail "the fix after the confirmation"
  ! grep -q "^host.*0\.0\.0\.0/0" "$hba" || { cat "$hba"; fail "the open rule is still in pg_hba.conf"; }
  grep -q "10.0.0.0/8" "$hba" || { cat "$hba"; fail "the allowed network isn't in pg_hba.conf"; }
  backup=$(rowsafe security shop --json | grep -A1 '"hba_backups"' | tail -1 | sed 's/^ *"\(.*\)",*$/\1/')
  [ -n "$backup" ] && [ -f "$backup" ] || fail "no backup of pg_hba.conf ($backup)"
  [ "$(psql_app -c 'SELECT 1')" = 1 ] || fail "the app can't log in from this server after the fix"
  rowsafe security shop >/tmp/after.out 2>&1
  ! grep -q "security_open_rules" /tmp/after.out || { cat /tmp/after.out; fail "the finding is still there"; }
  echo "  ok: only the allowed network may log in now; the app still can"

  # MD5 hashing becomes SCRAM (--yes confirms with the name in scripts).
  rowsafe security fix shop security_password_encryption --yes || fail "the SCRAM fix"
  [ "$(runuser -u postgres -- psql -qAtX -c 'SHOW password_encryption')" = scram-sha-256 ] || fail "password_encryption isn't scram-sha-256"
  rowsafe security shop | grep -q security_password_encryption && fail "the MD5 finding is still there"
  echo "  ok: new passwords are hashed with SCRAM"

  # Undo puts the old rules back.
  rowsafe security fix shop undo_restrict_access --yes || fail "undo"
  grep -q "^host.*0\.0\.0\.0/0" "$hba" || { cat "$hba"; fail "undo didn't put the old rules back"; }
  until_ok 30 "the finding is back after undo" sh -c "rowsafe security shop | grep -q security_open_rules"

  # The firewall touches the server itself: root hasn't allowed it here.
  ! rowsafe security fix shop firewall --allow 10.0.0.5 --yes >/tmp/fw.out 2>&1 || fail "the firewall changed without root's yes"
  grep -q "rowsafe-allow firewall" /tmp/fw.out || { cat /tmp/fw.out; fail "no word on root's yes"; }
  echo "  ok: the firewall waits for root's yes"
  # And checks from the internet aren't here.
  ! rowsafe security set shop --outside-check on >/tmp/outside.out 2>&1 || fail "checks from the internet turned on"
  grep -q "rowsafe login" /tmp/outside.out || { cat /tmp/outside.out; fail "no pointer to rowsafe login"; }
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-no-account-security: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-security.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-security-$$
  cleanup() {
    docker rm -f "$name-pg" >/dev/null 2>&1 || true
    docker volume rm "$name-pgdata" >/dev/null 2>&1 || true
    rm -rf "$W"
  }
  trap cleanup EXIT INT TERM

  echo "building rowsafe-agent and rowsafe (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe-agent" ./cmd/rowsafe-agent &&
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe" ./cmd/rowsafe)

  tag=rowsafe-test/security:$(echo "$image" | tr ':/' '--')
  echo "building $tag"
  docker build -q -t "$tag" - >/dev/null <<EOF
FROM $image
ENV container=docker
RUN apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus ca-certificates procps util-linux \\
      postgresql pgbackrest >/dev/null && \\
    rm -f /lib/systemd/system/multi-user.target.wants/getty* && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN ln -sf /dev/null /etc/systemd/system/systemd-binfmt.service && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.automount && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.mount
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
  docker run -d --name "$name-pg" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --shm-size 256m \
    -v "$name-pgdata:/var/lib/postgresql" -v "$root:/src:ro" -v "$W:/w" "$tag" >/dev/null
  i=0
  until docker exec "$name-pg" systemctl is-system-running --wait >/dev/null 2>&1 ||
    [ "$(docker exec "$name-pg" systemctl is-system-running 2>/dev/null)" = degraded ]; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || {
      echo "test-no-account-security: systemd did not start in the container" >&2
      exit 1
    }
    sleep 1
  done
  docker exec "$name-pg" sh /src/scripts/test-no-account-security.sh --in-container
  echo "test-no-account-security: passed on $image"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
