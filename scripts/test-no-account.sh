#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test Rowsafe on a server on its own (the installer's --no-account), for
# real: a Debian server with systemd as PID 1, PostgreSQL, pgBackRest and a
# MinIO bucket. The agent runs as its systemd unit with
# ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock, so its own control plane
# (internal/localcp) runs inside it, and the rowsafe CLI on the server finds
# it by itself:
#
#   sudo rowsafe add (saves the connection string, plans and turns on
#   backups), the restart through the root helper (rowsafe restart), the
#   check, the first full backup and the first Proof (rowsafe status says
#   protected), a Mark, a differential backup, the agent restarting (the
#   state is kept), Rewind (a copy restored to the Mark has the rows deleted
#   since; compare; bring them back), and a command that needs the
#   dashboard saying so.
#
# Usage: sh scripts/test-no-account.sh [debian:trixie]   (needs Docker, ~4 min)

set -eu

fail() {
  echo "test-no-account: $*" >&2
  echo "---- agent journal" >&2
  journalctl -u rowsafe-agent --no-pager -n 120 >&2 || true
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

in_container() {
  export DEBIAN_FRONTEND=noninteractive
  W=/w
  major=$(ls /usr/lib/postgresql)
  unit=postgresql@$major-main.service

  # What the installer puts in place: the binaries, the root helper for
  # restarts (allowed for this cluster), the agent's directories and unit.
  install -d -m 0755 /opt/rowsafe /usr/local/lib/rowsafe /etc/rowsafe
  install -m 0755 "$W/rowsafe-agent" /opt/rowsafe/rowsafe-agent
  install -m 0755 "$W/rowsafe" /usr/local/bin/rowsafe
  install -m 0755 /src/scripts/rowsafe-agent-guard /usr/local/lib/rowsafe/rowsafe-agent-guard
  install -m 0755 /src/scripts/rowsafe-pg-restart /usr/local/lib/rowsafe/rowsafe-pg-restart
  install -m 0644 /src/deploy/systemd/rowsafe-pg-restart.service /src/deploy/systemd/rowsafe-pg-restart.path /etc/systemd/system/
  install -m 0644 /src/deploy/systemd/rowsafe-agent.service /etc/systemd/system/
  printf '# test\n5432 %s\n' "$unit" >/etc/rowsafe/restart-allowed
  chmod 0644 /etc/rowsafe/restart-allowed
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
  systemctl daemon-reload
  systemctl enable --now --quiet rowsafe-pg-restart.path
  systemctl start "$unit"
  systemctl enable --now --quiet rowsafe-agent
  echo "PostgreSQL $major and the agent (no account) are running"

  until_ok 30 "the agent's control plane listens" test -S /var/lib/rowsafe/control.sock
  # Not root, not the agent's user: the socket isn't theirs.
  ! runuser -u nobody -- /usr/local/bin/rowsafe ls >/tmp/nobody.out 2>&1 || fail "nobody could use the socket"
  grep -q "sudo rowsafe" /tmp/nobody.out || { cat /tmp/nobody.out; fail "no plain answer for a user without access"; }
  echo "  ok: other users get a plain 'sudo rowsafe' answer"

  # An app's role (root can't sign in as postgres), and rows to lose later.
  runuser -u postgres -- psql -qX -c "CREATE ROLE app LOGIN SUPERUSER PASSWORD 'app-pw'" -c "CREATE DATABASE shop OWNER app" ||
    fail "the app role and database"
  psql_app() { PGPASSWORD=app-pw psql -qAtX -h localhost -U app -d shop "$@"; }
  psql_app -c "CREATE TABLE orders (id int PRIMARY KEY, note text); INSERT INTO orders SELECT g, 'order ' || g FROM generate_series(1, 5) g" ||
    fail "the orders table"

  # rowsafe add saves the database and, on its own server, protects it: the
  # plan, then backups on (--yes answers the question).
  rowsafe add shop "postgres://app:app-pw@localhost:5432/shop" --yes | tee /tmp/add.out || fail "rowsafe add"
  grep -q "Saved shop" /tmp/add.out || fail "rowsafe add didn't save shop"
  grep -q "needs a quick restart" /tmp/add.out || fail "rowsafe add didn't say PostgreSQL needs a restart"
  rowsafe ls | tee /tmp/ls.out
  grep -q "shop" /tmp/ls.out || fail "rowsafe ls doesn't show shop"
  # Adding it again finds it.
  rowsafe add shop "postgres://app:app-pw@localhost:5432/shop" --yes | grep -q "protected on this server" ||
    fail "rowsafe add twice"

  # The archiving settings need a restart: through the root helper.
  until_ok 60 "the agent reports that restarts are allowed" sh -c "rowsafe show shop --json 2>/dev/null | grep -q '\"can_restart\": true' || rowsafe show shop | grep -qi restart"
  rowsafe restart shop --yes || fail "rowsafe restart"
  until_ok 180 "the database is active (archiving proven)" sh -c "rowsafe ls | grep shop | grep -q active"

  # The first full backup and the first Proof run by themselves.
  until_ok 420 "rowsafe status shop: protected" rowsafe status shop
  rowsafe backups shop
  rowsafe proofs shop

  # A Mark, then rows deleted by mistake, then a differential backup.
  rowsafe mark shop before-drop --json | tee /tmp/mark.json
  grep -q '"before-drop"' /tmp/mark.json || fail "the Mark"
  psql_app -c "DELETE FROM orders WHERE id > 2" || fail "deleting rows"
  [ "$(psql_app -c 'SELECT count(*) FROM orders')" = 2 ] || fail "the rows weren't deleted"
  rowsafe marks shop | grep -q before-drop || fail "rowsafe marks"
  rowsafe backup shop --type diff || fail "rowsafe backup"
  rowsafe backups shop | tee /tmp/backups.out
  grep -qi diff /tmp/backups.out || fail "no differential backup listed"

  # The agent restarts: its control plane keeps everything.
  systemctl restart rowsafe-agent
  until_ok 30 "the control plane is back" test -S /var/lib/rowsafe/control.sock
  until_ok 30 "still active after the agent restarted" sh -c "rowsafe ls | grep shop | grep -q active"
  rowsafe marks shop | grep -q before-drop || fail "the Mark is gone after a restart"

  # Rewind: a copy as it was at the Mark, next to production, with the rows.
  rowsafe restore shop --to before-drop | tee /tmp/restore.out || fail "rowsafe restore"
  rowsafe restores shop | grep -q ready || fail "rowsafe restores doesn't show the copy ready"
  rowsafe tasks shop --type rewind_copy --json >/tmp/copy.json || fail "the copy's task"
  copy_sock=$(grep -o '"socket_dir": *"[^"]*"' /tmp/copy.json | head -1 | sed 's/.*: *"\(.*\)"/\1/')
  copy_port=$(grep -o '"port": *[0-9]*' /tmp/copy.json | head -1 | sed 's/.*: *//')
  [ -n "$copy_sock" ] && [ -n "$copy_port" ] || { cat /tmp/copy.json; fail "where the copy listens"; }
  n=$(runuser -u postgres -- psql -qAtX -h "$copy_sock" -p "$copy_port" -d shop -c 'SELECT count(*) FROM orders') ||
    fail "reading the copy"
  [ "$n" = 5 ] || fail "the copy has $n orders, want 5 (as at the Mark)"
  [ "$(psql_app -c 'SELECT count(*) FROM orders')" = 2 ] || fail "restoring a copy changed production"
  echo "  ok: the copy at the Mark has the 5 orders; production still has 2"
  rowsafe rewind compare shop public.orders | tee /tmp/compare.out || fail "rowsafe rewind compare"
  grep -q "orders" /tmp/compare.out || fail "the comparison doesn't list orders"
  ! rowsafe rewind rows shop public.orders </dev/null >/tmp/rows.out 2>&1 || fail "rows came back without a confirmation"
  rowsafe rewind rows shop public.orders --yes || fail "rowsafe rewind rows"
  [ "$(psql_app -c 'SELECT count(*) FROM orders')" = 5 ] || fail "the rows didn't come back"
  rowsafe marks shop | grep -q before-rewind-rows || fail "no Mark before bringing rows back"
  echo "  ok: the deleted rows are back, after a Mark"
  ! rowsafe rewind database shop --mark before-drop --yes >/tmp/inplace.out 2>&1 || fail "rewound in place"
  grep -q "rowsafe login" /tmp/inplace.out || { cat /tmp/inplace.out; fail "rewinding in place doesn't say why not"; }
  rowsafe rewind drop shop --yes || fail "rowsafe rewind drop"
  until_ok 60 "the copy is gone" sh -c "! rowsafe restores shop | grep -q ready"

  # What needs the dashboard says so.
  ! rowsafe alerts >/tmp/alerts.out 2>&1 || fail "alerts worked on the server alone?"
  grep -q "rowsafe login" /tmp/alerts.out || { cat /tmp/alerts.out; fail "no pointer to rowsafe login"; }
  echo "  ok: what needs the dashboard points to rowsafe login"
  # Direct commands use the saved connection string.
  rowsafe pulse shop >/tmp/pulse-saved.out 2>&1 || true
  grep -q "/100" /tmp/pulse-saved.out || { cat /tmp/pulse-saved.out; fail "rowsafe pulse shop"; }
  echo "  ok: rowsafe pulse shop uses the saved connection string"
  # And the connection string mode still works on the same server.
  runuser -u postgres -- /usr/local/bin/rowsafe pulse "postgresql:///postgres?host=/var/run/postgresql" >/tmp/pulse.out 2>&1 || true
  grep -q "/100" /tmp/pulse.out || { cat /tmp/pulse.out; fail "rowsafe pulse on a connection string"; }
  echo "  ok: rowsafe pulse postgres://... works next to it"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-no-account: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-noaccount.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-noaccount-$$
  cleanup() {
    docker rm -f "$name-pg" "$name-minio" >/dev/null 2>&1 || true
    docker volume rm "$name-pgdata" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
    rm -rf "$W"
  }
  trap cleanup EXIT INT TERM

  echo "building rowsafe-agent and rowsafe (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe-agent" ./cmd/rowsafe-agent &&
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe" ./cmd/rowsafe)

  # A test CA and a certificate for MinIO (pgBackRest's S3 client needs TLS).
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
      echo "test-no-account: MinIO did not come up" >&2
      exit 1
    }
    sleep 1
  done

  tag=rowsafe-test/rewind:$(echo "$image" | tr ':/' '--')
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
  docker run -d --name "$name-pg" --network "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --shm-size 256m \
    -v "$name-pgdata:/var/lib/postgresql" -v "$root:/src:ro" -v "$W:/w" \
    -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" "$tag" >/dev/null
  i=0
  until docker exec "$name-pg" systemctl is-system-running --wait >/dev/null 2>&1 ||
    [ "$(docker exec "$name-pg" systemctl is-system-running 2>/dev/null)" = degraded ]; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || {
      echo "test-no-account: systemd did not start in the container" >&2
      exit 1
    }
    sleep 1
  done
  docker exec -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" "$name-pg" sh /src/scripts/test-no-account.sh --in-container
  echo "test-no-account: passed on $image"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
