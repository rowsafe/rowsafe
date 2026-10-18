#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test Guard on a server Rowsafe protects on its own (the installer's
# --no-account), for real: a Debian server with systemd as PID 1,
# PostgreSQL, pgBackRest and a MinIO bucket, the agent running its own
# control plane (internal/localcp).
#
#   A migration that only fails on the real data (a text column with one
#   value that isn't a number, turned into an integer) passes the
#   schema-only check on a connection string, and fails in
#   `sudo rowsafe preview shop FILE`, which runs it on a full copy restored
#   from the backups. rowsafe guard stops it before it runs (exit 2), and
#   the local MCP's check_migration reports it. Production never changes.
#   Then `sudo rowsafe copies create shop --masked --port 55450`: a copy on
#   localhost only, with every row and none of the real emails, deleted on
#   request (and by itself when it expires).
#
# Usage: sh scripts/test-no-account-guard.sh [debian:trixie]   (needs Docker, ~5 min)

set -eu
# The MinIO test image (built once from source: scripts/minio).
MINIO_SH=$(cd "$(dirname "$0")" && pwd)/minio/image.sh

fail() {
  echo "test-no-account-guard: $*" >&2
  echo "---- agent journal" >&2
  journalctl -u rowsafe-agent --no-pager -n 150 >&2 || true
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

  # What the installer puts in place (as in test-no-account.sh).
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

  # The app's database: users with real-looking emails, and a zip column
  # whose values are all numbers but one.
  runuser -u postgres -- psql -qX -c "CREATE ROLE app LOGIN SUPERUSER PASSWORD 'app-pw'" -c "CREATE DATABASE shop OWNER app" ||
    fail "the app role and database"
  psql_app() { PGPASSWORD=app-pw psql -qAtX -h localhost -U app -d shop "$@"; }
  psql_app -c "CREATE TABLE users (id int PRIMARY KEY, name text NOT NULL, email text NOT NULL UNIQUE, zip text);
    INSERT INTO users SELECT g, 'Person ' || g, 'person' || g || '@realmail.example', lpad((10000 + g)::text, 5, '0') FROM generate_series(1, 1000) g;
    UPDATE users SET zip = 'N/A' WHERE id = 734;" || fail "the users table"

  rowsafe add shop "postgres://app:app-pw@localhost:5432/shop" --yes >/tmp/add.out 2>&1 || { cat /tmp/add.out; fail "rowsafe add"; }
  until_ok 60 "the agent reports that restarts are allowed" sh -c "rowsafe show shop --json 2>/dev/null | grep -q '\"can_restart\": true'"
  rowsafe restart shop --yes || fail "rowsafe restart"
  until_ok 180 "the database is active (archiving proven)" sh -c "rowsafe ls | grep shop | grep -q active"
  until_ok 300 "the first full backup" sh -c "rowsafe backups shop | grep -qi full"

  cat >/tmp/0042_zip_integer.sql <<'SQL'
ALTER TABLE users ALTER COLUMN zip TYPE integer USING zip::integer;
SQL

  # Elsewhere (a connection string): an empty copy of the schema, which
  # can't see the data.
  rowsafe preview "postgres://app:app-pw@localhost:5432/shop" /tmp/0042_zip_integer.sql --json >/tmp/schema.json 2>/tmp/schema.err ||
    { cat /tmp/schema.err /tmp/schema.json; fail "the schema-only preview"; }
  grep -q '"checked": "schema_copy"' /tmp/schema.json || { cat /tmp/schema.json; fail "the connection string didn't get the schema-only check"; }
  ! grep -q '"verdict": "failed"' /tmp/schema.json || { cat /tmp/schema.json; fail "the schema-only check saw the data"; }
  echo "  ok: on an empty copy of the schema the migration passes"

  # On this server, by name: a full copy restored from the backups.
  rc=0
  rowsafe preview shop /tmp/0042_zip_integer.sql --json --fail-on dangerous >/tmp/full.json 2>/tmp/full.err || rc=$?
  [ "$rc" = 2 ] || { cat /tmp/full.err /tmp/full.json; fail "rowsafe preview shop exited $rc, want 2 (the migration fails)"; }
  grep -q '"verdict": "failed"' /tmp/full.json || { cat /tmp/full.json; fail "the full-copy preview didn't fail"; }
  grep -q '22P02' /tmp/full.json || { cat /tmp/full.json; fail "no invalid-integer error"; }
  ! grep -q '"checked"' /tmp/full.json || { cat /tmp/full.json; fail "the preview didn't run on a full copy"; }
  ! grep -q 'N/A\|realmail' /tmp/full.json || { cat /tmp/full.json; fail "values from the data in the report"; }
  [ "$(psql_app -c "SELECT data_type FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'zip'")" = text ] ||
    fail "the preview changed production"
  rowsafe previews shop | grep -q 0042_zip_integer.sql || fail "rowsafe previews doesn't list it"
  echo "  ok: on a full copy of the data the migration fails (22P02); production unchanged"

  # rowsafe guard (the Claude Code hook) stops it before it runs.
  mkdir -p /tmp/app
  printf '{"tool_name":"Bash","cwd":"/tmp/app","tool_input":{"command":"psql -c \\"ALTER TABLE users ALTER COLUMN zip TYPE integer USING zip::integer\\""}}' >/tmp/event.json
  rc=0
  rowsafe guard </tmp/event.json >/tmp/guard.out 2>/tmp/guard.err || rc=$?
  [ "$rc" = 2 ] || { cat /tmp/guard.out /tmp/guard.err; fail "rowsafe guard exited $rc, want 2 (blocked)"; }
  grep -q "fails on a full copy of shop" /tmp/guard.err || { cat /tmp/guard.err; fail "guard didn't say why"; }
  grep -q "Restore point agent-" /tmp/guard.err || { cat /tmp/guard.err; fail "guard didn't save a restore point"; }
  echo "  ok: rowsafe guard blocks it, after a restore point"
  # A migration that works runs, with the verdict.
  printf '{"tool_name":"Bash","cwd":"/tmp/app","tool_input":{"command":"psql -c \\"ALTER TABLE users ALTER COLUMN name TYPE varchar(200)\\""}}' >/tmp/event.json
  rowsafe guard </tmp/event.json >/tmp/guard.out 2>/tmp/guard.err || { cat /tmp/guard.out /tmp/guard.err; fail "rowsafe guard on a migration that works"; }
  grep -q "Preview on a full copy of the data" /tmp/guard.out || { cat /tmp/guard.out; fail "guard didn't preview it"; }
  echo "  ok: a migration that works goes on, with the preview's verdict"

  # The local MCP's check_migration runs it on a full copy too.
  {
    echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}'
    echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check_migration","arguments":{"sql":"ALTER TABLE users ALTER COLUMN zip TYPE integer USING zip::integer;"}}}'
    sleep 120
  } | timeout 120 rowsafe mcp shop >/tmp/mcp.out 2>/tmp/mcp.err &
  until_ok 120 "check_migration answers" grep -q '"id":2' /tmp/mcp.out
  grep '"id":2' /tmp/mcp.out | grep -q 'invalid input syntax for type integer' || { cat /tmp/mcp.out /tmp/mcp.err; fail "check_migration didn't run on the data"; }
  echo "  ok: the MCP's check_migration fails it on the data too"

  # A masked copy, on localhost, on the port asked for.
  until_ok 60 "the masking reads the tables" sh -c "rowsafe masking shop | grep -q users.email"
  rowsafe masking shop | tee /tmp/masking.out
  rowsafe copies create shop --masked --port 55450 --hours 2 --json >/tmp/copy.json 2>/tmp/copy.err || { cat /tmp/copy.err /tmp/copy.json; fail "rowsafe copies create"; }
  conn=$(grep -o '"connection_string": *"[^"]*"' /tmp/copy.json | tail -1 | sed 's/.*: *"\(.*\)"/\1/')
  case $conn in
    postgresql://*@127.0.0.1:55450/shop?sslmode=require) ;;
    *) cat /tmp/copy.json; fail "the copy's connection string: $conn" ;;
  esac
  [ "$(psql "$conn" -qAtX -c 'SELECT count(*) FROM users')" = 1000 ] || fail "the copy hasn't every row"
  [ "$(psql "$conn" -qAtX -c "SELECT count(*) FROM users WHERE email LIKE '%realmail%'")" = 0 ] || fail "the copy has real emails"
  [ "$(psql_app -c "SELECT count(*) FROM users WHERE email LIKE '%realmail%'")" = 1000 ] || fail "masking changed production"
  psql "$conn" -qAtX -c "UPDATE users SET name = 'x' WHERE id = 1" >/dev/null || fail "the copy isn't writable"
  [ "$(psql_app -c "SELECT name FROM users WHERE id = 1")" = "Person 1" ] || fail "a write to the copy reached production"
  ip=$(hostname -i | awk '{print $1}')
  ! PGCONNECT_TIMEOUT=3 psql "$(echo "$conn" | sed "s/127.0.0.1/$ip/")" -qAtX -c 'SELECT 1' >/dev/null 2>&1 ||
    fail "the copy answers on $ip, not only localhost"
  echo "  ok: a masked copy on 127.0.0.1:55450 has every row and no real email; production unchanged"
  rowsafe copies shop | tee /tmp/copies.out
  grep -q "ready" /tmp/copies.out || fail "rowsafe copies doesn't show it ready"
  id=$(grep -o '"id": *"sc_[a-z0-9]*"' /tmp/copy.json | head -1 | sed 's/.*"\(sc_[a-z0-9]*\)"/\1/')
  rowsafe copies delete shop "$id" --yes || fail "rowsafe copies delete"
  until_ok 60 "the copy is gone" sh -c "! psql '$conn' -qAtX -c 'SELECT 1'"
  until_ok 30 "rowsafe copies says removed" sh -c "rowsafe copies shop | grep -q removed"
  echo "  ok: deleted, and gone from the server"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-no-account-guard: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-noaccount-guard.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-noaccount-guard-$$
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
    -v "$W/minio-certs:/certs:ro" "$(sh "$MINIO_SH")" server /data --address :9000 --certs-dir /certs >/dev/null
  i=0
  until docker run --rm --network "$name" --entrypoint sh "$(sh "$MINIO_SH")" -c \
    "mc alias set m https://minio:9000 rowsafe-test $secret --insecure >/dev/null && mc mb --insecure --ignore-existing m/rowsafe >/dev/null" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || {
      docker logs "$name-minio" >&2
      echo "test-no-account-guard: MinIO did not come up" >&2
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
      echo "test-no-account-guard: systemd did not start in the container" >&2
      exit 1
    }
    sleep 1
  done
  docker exec -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" "$name-pg" sh /src/scripts/test-no-account-guard.sh --in-container
  echo "test-no-account-guard: passed on $image"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
