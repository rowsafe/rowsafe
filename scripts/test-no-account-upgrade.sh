#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test a major PostgreSQL upgrade on a server on its own (the installer's
# --no-account), for real: a Debian server with systemd as PID 1, PostgreSQL
# 16 from apt.postgresql.org, pgBackRest, a MinIO bucket, the agent as its
# systemd unit with its own control plane (internal/localcp) and the root
# helper root allowed restarts and updates for (rowsafe-allow restart
# updates). Everything goes through the rowsafe CLI on the server:
#
#   rowsafe add (backups on, the first backup and Proof); the software
#   report (17 and 18 offered); the check and the rehearsal on a restored
#   copy (production untouched, still 16); the upgrade refused without a
#   terminal and cancelled when the wrong name is typed; then, with the
#   name typed, a Mark and the upgrade to 17 (the rows and their checksum
#   intact, a full backup and a Proof on 17); undo (back on 16 with the
#   rows); removing the kept 17; the server's security updates after a
#   Mark; a reboot root didn't allow, refused.
#
# Usage: sh scripts/test-no-account-upgrade.sh [debian:trixie]   (needs
# Docker and the network for apt.postgresql.org; ~10 min)

set -eu

FROM=${FROM:-16}
TO=${TO:-17}

fail() {
  echo "test-no-account-upgrade: $*" >&2
  echo "---- agent journal" >&2
  journalctl -u rowsafe-agent --no-pager -n 150 >&2 || true
  echo "---- helper" >&2
  journalctl -u rowsafe-pg-update.service --no-pager -n 60 >&2 || true
  tail -n 60 /var/lib/rowsafe-pg-restart/update.log >&2 2>/dev/null || true
  pg_lsclusters >&2 || true
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

# protected WHEN: rowsafe status shop says protected, or its only problem is
# the change log push that failed while the new version waited for its
# backups to move to it (counted for 15 minutes, as with an account).
protected() {
  rowsafe status shop >/tmp/status.out 2>&1 && return
  cat /tmp/status.out
  ! grep '^  - ' /tmp/status.out | grep -qv 'WAL archiving failed at' || fail "not protected $1"
  grep -q 'Last WAL archived' /tmp/status.out || fail "no WAL archived $1"
  echo "  ok: protected $1 but for one change log push that failed while the backups moved to the running version"
}

# typed NAME COMMAND...: run COMMAND on a terminal and type NAME at its question.
typed() {
  _name=$1
  shift
  printf '%s\n' "$_name" | script -qec "$*" /dev/null
}

in_container() {
  export DEBIAN_FRONTEND=noninteractive
  W=/w
  unit=postgresql@$FROM-main.service

  # What the installer puts in place: the binaries, the root helper with
  # restarts and PostgreSQL updates allowed for this cluster, the agent's
  # directories and unit, with its control plane on this server.
  install -d -m 0755 /opt/rowsafe /usr/local/lib/rowsafe /etc/rowsafe
  install -m 0755 "$W/rowsafe-agent" /opt/rowsafe/rowsafe-agent
  install -m 0755 "$W/rowsafe" /usr/local/bin/rowsafe
  install -m 0755 /src/scripts/rowsafe-agent-guard /usr/local/lib/rowsafe/rowsafe-agent-guard
  install -m 0755 /src/scripts/rowsafe-pg-restart /usr/local/lib/rowsafe/rowsafe-pg-restart
  install -m 0644 /src/deploy/systemd/rowsafe-pg-restart.service /src/deploy/systemd/rowsafe-pg-restart.path \
    /src/deploy/systemd/rowsafe-pg-update.service /src/deploy/systemd/rowsafe-pg-update.path \
    /src/deploy/systemd/rowsafe-agent.service /etc/systemd/system/
  printf '# test\n5432 %s\n' "$unit" >/etc/rowsafe/restart-allowed
  printf '# test\npostgresql\nsecurity\n' >/etc/rowsafe/updates-allowed
  chmod 0644 /etc/rowsafe/restart-allowed /etc/rowsafe/updates-allowed
  install -d -m 0700 -o postgres -g postgres /var/lib/rowsafe /var/lib/rowsafe/restart /etc/rowsafe/pgbackrest /var/log/rowsafe
  umask 077
  cat >/etc/rowsafe/agent.env <<EOF
ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock
ROWSAFE_AUTO_UPDATE=false
ROWSAFE_HEARTBEAT_INTERVAL=5s
ROWSAFE_POLL_INTERVAL=2s
ROWSAFE_REPO_S3_ENDPOINT=minio
ROWSAFE_REPO_S3_PORT=9000
ROWSAFE_REPO_S3_REGION=us-east-1
ROWSAFE_REPO_S3_BUCKET=rowsafe
ROWSAFE_REPO_S3_KEY=rowsafe-test
ROWSAFE_REPO_S3_KEY_SECRET=$S3_SECRET
ROWSAFE_REPO_CIPHER_PASS=$CIPHER_PASS
ROWSAFE_REPO_S3_CA_FILE=$W/certs/ca.crt
EOF
  chown root:postgres /etc/rowsafe/agent.env
  chmod 0640 /etc/rowsafe/agent.env
  umask 022
  # A real server creates "main" for every newly installed major, which the
  # helper must handle.
  sed -i '/^create_main_cluster = false$/d' /etc/postgresql-common/createcluster.conf
  pg_createcluster "$FROM" main >/dev/null
  systemctl daemon-reload
  systemctl enable --now --quiet rowsafe-pg-restart.path rowsafe-pg-update.path
  systemctl start "$unit"
  systemctl enable --now --quiet rowsafe-agent
  echo "PostgreSQL $(dpkg-query -W -f='${Version}' "postgresql-$FROM") and the agent (no account) are running"
  until_ok 30 "the agent's control plane listens" test -S /var/lib/rowsafe/control.sock

  runuser -u postgres -- psql -qX -c "CREATE ROLE app LOGIN SUPERUSER PASSWORD 'app-pw'" -c "CREATE DATABASE shop OWNER app" ||
    fail "the app role and database"
  psql_app() { PGPASSWORD=app-pw psql -qAtX -h localhost -U app -d shop "$@"; }
  psql_app -c "CREATE TABLE orders (id int PRIMARY KEY, note text, at timestamptz DEFAULT now());
    INSERT INTO orders (id, note) SELECT g, md5(g::text) FROM generate_series(1, 20000) g;
    CREATE INDEX ON orders (note); CREATE VIEW recent AS SELECT * FROM orders WHERE id > 19990" || fail "the orders table"
  sum() { psql_app -c "SELECT count(*) || ':' || md5(string_agg(id || note, ',' ORDER BY id)) FROM orders"; }
  before=$(sum)

  rowsafe add shop "postgres://app:app-pw@localhost:5432/shop" --yes >/tmp/add.out 2>&1 || { cat /tmp/add.out; fail "rowsafe add"; }
  until_ok 60 "restarts are allowed" sh -c "rowsafe show shop --json | grep -q '\"can_restart\": true'"
  rowsafe restart shop --yes >/dev/null || fail "rowsafe restart"
  until_ok 180 "shop is active (archiving proven)" sh -c "rowsafe ls | grep shop | grep -q active"
  until_ok 420 "rowsafe status shop: protected (first backup and Proof)" rowsafe status shop

  # The agent looks at the server's packages: newer majors are offered.
  until_ok 120 "rowsafe upgrade shop lists PostgreSQL $TO" sh -c "rowsafe upgrade shop | grep -q 'Newer majors:.*$TO'"
  rowsafe upgrade shop

  # The check and the rehearsal on a restored copy: production untouched.
  rowsafe upgrade shop --to "$TO" --rehearse-only >/tmp/rehearse.out 2>&1 || { cat /tmp/rehearse.out; fail "the rehearsal"; }
  cat /tmp/rehearse.out
  grep -q "Rehearsal of .* -> $TO.*: passed" /tmp/rehearse.out || fail "the rehearsal didn't pass"
  [ "$(psql_app -c 'SHOW server_version_num' | cut -c1-2)" = "$FROM" ] || fail "the rehearsal changed production's version"
  [ "$(sum)" = "$before" ] || fail "the rehearsal changed production's rows"
  echo "  ok: the rehearsal passed; production is still PostgreSQL $FROM with its rows"

  newest_full() { rowsafe backups shop --json | grep -o '"label": *"[^"]*F"' | head -1 | sed 's/.*: *"\(.*\)"/\1/'; }
  full0=$(newest_full)
  [ -n "$full0" ] || fail "no full backup listed"

  # The upgrade asks for the database's name.
  ! rowsafe upgrade shop --to "$TO" </dev/null >/tmp/noterm.out 2>&1 || fail "upgraded without a confirmation"
  grep -q -- "--yes" /tmp/noterm.out || { cat /tmp/noterm.out; fail "no word on --yes without a terminal"; }
  typed nope rowsafe upgrade shop --to "$TO" >/tmp/wrong.out 2>&1 || true
  rowsafe upgrade shop --json | grep -q '"type": "upgrade"' && fail "an upgrade was queued after the wrong name"
  [ "$(psql_app -c 'SHOW server_version_num' | cut -c1-2)" = "$FROM" ] || fail "the wrong name upgraded it"
  echo "  ok: refused without a terminal, cancelled when the wrong name is typed"

  typed shop rowsafe upgrade shop --to "$TO" >/tmp/upgrade.out 2>&1 || { cat /tmp/upgrade.out; fail "the upgrade"; }
  cat /tmp/upgrade.out
  grep -q "Mark saved first: before-upgrade-$TO-" /tmp/upgrade.out || fail "no Mark before the upgrade"
  [ "$(psql_app -c 'SHOW server_version_num' | cut -c1-2)" = "$TO" ] || fail "not running PostgreSQL $TO"
  [ "$(sum)" = "$before" ] || fail "the rows changed in the upgrade: $(sum), want $before"
  [ "$(psql_app -c 'SELECT count(*) FROM recent')" = 10 ] || fail "the view after the upgrade"
  rowsafe marks shop | grep -q "before-upgrade-$TO-" || fail "rowsafe marks doesn't list the Mark"
  echo "  ok: PostgreSQL $TO runs with all 20000 rows (same checksum); a Mark was saved first"
  # The agent reports the upgrade (and the running version) within a few heartbeats.
  until_ok 120 "rowsafe upgrade shows the upgrade" sh -c "rowsafe upgrade shop | grep -q 'Upgraded from $FROM to $TO'"
  rowsafe upgrade shop

  # Backups go on, on the new version: a full backup and a Proof.
  full_changed() { [ "$(newest_full)" != "$full0" ]; }
  until_ok 300 "a full backup of PostgreSQL $TO" full_changed
  full1=$(newest_full)
  proven() { rowsafe proofs shop --json | tr -d ' \n' | grep -q "\"passed\":true,\"backup_label\":\"$full1\""; }
  until_ok 600 "a Proof of it passed" proven
  rowsafe backups shop | head -5
  protected "after the upgrade"
  psql_app -c "INSERT INTO orders (id, note) VALUES (30001, 'on $TO')" || fail "writing on $TO"

  # Undo: back on the old version, with its rows; what was written on the
  # new one stays in the kept new version.
  typed shop rowsafe upgrade undo shop >/tmp/undo.out 2>&1 || { cat /tmp/undo.out; fail "the undo"; }
  cat /tmp/undo.out
  [ "$(psql_app -c 'SHOW server_version_num' | cut -c1-2)" = "$FROM" ] || fail "not back on PostgreSQL $FROM"
  [ "$(sum)" = "$before" ] || fail "the rows after the undo: $(sum), want $before"
  echo "  ok: back on PostgreSQL $FROM with its rows"
  until_ok 120 "the undo is reported" sh -c "rowsafe upgrade shop | grep -q 'was undone'"
  typed shop rowsafe upgrade cleanup shop >/tmp/cleanup.out 2>&1 || { cat /tmp/cleanup.out; fail "removing the kept version"; }
  cat /tmp/cleanup.out
  until_ok 120 "the kept PostgreSQL $TO is gone" sh -c "! pg_lsclusters -h | grep -q '^$TO '"
  protected "after the undo"
  echo "  ok: the kept PostgreSQL $TO is removed; shop is still protected"

  # The server's security updates (allowed), after a Mark; PostgreSQL
  # keeps running. Reboots weren't allowed: it says how.
  if rowsafe upgrade shop | grep -q "security updates waiting"; then
    typed shop rowsafe security-updates shop >/tmp/security.out 2>&1 || { cat /tmp/security.out; fail "the security updates"; }
    cat /tmp/security.out
    rowsafe marks shop | grep -q "before-security-updates-" || fail "no Mark before the security updates"
    [ "$(psql_app -c 'SELECT count(*) FROM orders')" = 20000 ] || fail "PostgreSQL after the security updates"
    echo "  ok: security updates installed after a Mark; PostgreSQL kept running"
  else
    echo "  (no security updates waiting in this image: skipped)"
  fi
  ! rowsafe reboot shop --yes >/tmp/reboot.out 2>&1 || fail "rebooted without root's yes"
  grep -q "sudo rowsafe-allow reboot" /tmp/reboot.out || { cat /tmp/reboot.out; fail "the reboot refusal doesn't say how to allow it"; }
  echo "  ok: a reboot root didn't allow is refused, saying how to allow it"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-no-account-upgrade: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-noaccount-upgrade.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-noaccount-upgrade-$$
  cleanup() {
    [ "${KEEP:-0}" = 1 ] && return
    docker rm -f "$name-pg" "$name-minio" >/dev/null 2>&1 || true
    docker volume rm "$name-pgdata" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
    rm -rf "$W"
  }
  trap cleanup EXIT INT TERM

  echo "building rowsafe-agent and rowsafe (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe-agent" ./cmd/rowsafe-agent &&
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe" ./cmd/rowsafe)

  mkdir -p "$W/certs" "$W/minio-certs"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=rowsafe test CA" \
    -keyout "$W/certs/ca.key" -out "$W/certs/ca.crt" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=minio" -keyout "$W/minio-certs/private.key" -out "$W/minio.csr" 2>/dev/null
  printf 'subjectAltName=DNS:minio\n' >"$W/san.ext"
  openssl x509 -req -in "$W/minio.csr" -CA "$W/certs/ca.crt" -CAkey "$W/certs/ca.key" -CAcreateserial -days 2 \
    -extfile "$W/san.ext" -out "$W/minio-certs/public.crt" 2>/dev/null
  chmod 0644 "$W/minio-certs/private.key" "$W/certs/ca.crt"
  secret=$(openssl rand -hex 16)
  cipher=$(openssl rand -hex 24)

  docker network create "$name" >/dev/null
  docker run -d --name "$name-minio" --network "$name" --network-alias minio \
    -e MINIO_ROOT_USER=rowsafe-test -e MINIO_ROOT_PASSWORD="$secret" \
    -v "$W/minio-certs:/certs:ro" minio/minio server /data --address :9000 --certs-dir /certs >/dev/null
  i=0
  until docker run --rm --network "$name" --entrypoint sh minio/minio -c \
    "mc alias set m https://minio:9000 rowsafe-test $secret --insecure >/dev/null && mc mb --insecure --ignore-existing m/rowsafe >/dev/null" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || {
      docker logs "$name-minio" >&2
      echo "test-no-account-upgrade: MinIO did not come up" >&2
      exit 1
    }
    sleep 1
  done

  # PostgreSQL $FROM from apt.postgresql.org, which offers the newer majors.
  tag=rowsafe-test/no-account-upgrade:$(echo "$image" | tr ':/' '--')-pg$FROM
  echo "building $tag"
  docker build -q -t "$tag" - >/dev/null <<EOF
FROM $image
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus ca-certificates procps util-linux curl >/dev/null && \\
    rm -f /lib/systemd/system/multi-user.target.wants/getty* && \\
    install -d /usr/share/postgresql-common/pgdg && \\
    curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc && \\
    . /etc/os-release && \\
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt \$VERSION_CODENAME-pgdg main" \\
      >/etc/apt/sources.list.d/pgdg.list && \\
    apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends postgresql-common libpq5 pgbackrest >/dev/null && \\
    echo 'create_main_cluster = false' >>/etc/postgresql-common/createcluster.conf && \\
    apt-get install -y -qq --no-install-recommends postgresql-$FROM postgresql-client-$FROM >/dev/null && apt-get clean
RUN ln -sf /dev/null /etc/systemd/system/systemd-binfmt.service && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.automount && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.mount
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
  docker run -d --name "$name-pg" --network "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --shm-size 256m \
    -v "$name-pgdata:/var/lib/postgresql" -v "$root:/src:ro" -v "$W:/w" \
    -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" -e FROM="$FROM" -e TO="$TO" "$tag" >/dev/null
  i=0
  until docker exec "$name-pg" systemctl is-system-running --wait >/dev/null 2>&1 ||
    [ "$(docker exec "$name-pg" systemctl is-system-running 2>/dev/null)" = degraded ]; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || {
      echo "test-no-account-upgrade: systemd did not start in the container" >&2
      exit 1
    }
    sleep 1
  done
  docker exec -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" -e FROM="$FROM" -e TO="$TO" "$name-pg" \
    sh /src/scripts/test-no-account-upgrade.sh --in-container
  echo "test-no-account-upgrade: passed on $image ($FROM -> $TO)"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
