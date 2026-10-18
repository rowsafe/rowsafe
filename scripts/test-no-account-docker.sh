#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test Rowsafe with PostgreSQL in Docker and no account, for real: the
# documented deploy/docker/compose.no-account.yml (the official postgres:17
# image, unmodified, and the agent image built from this checkout as the
# rowsafe service, running its own control plane), a MinIO bucket over TLS
# and a webhook receiver, all driven with `docker compose exec rowsafe
# rowsafe ...` as a person would:
#
#   rowsafe add with the postgres service's connection string (it finds the
#   PostgreSQL behind the shared socket; another server is left alone),
#   Rowsafe never restarting PostgreSQL by itself (the person restarts the
#   container), the first full backup and the first Proof (rowsafe status
#   says protected), a Mark, a differential backup, the rowsafe container
#   restarting (the state is kept), a copy restored as it was at the Mark,
#   compare, bring the deleted rows back, alerts to a signed webhook, and
#   rowsafe pulse on the saved name, and rowsafe login saying it can't
#   connect the container to the dashboard yet.
#
# Usage: sh scripts/test-no-account-docker.sh   (needs Docker, ~8 min the first time)

set -eu
# The MinIO test image (built once from source: scripts/minio).
MINIO_SH=$(cd "$(dirname "$0")" && pwd)/minio/image.sh

root=$(cd "$(dirname "$0")/.." && pwd)
docker info >/dev/null 2>&1 || {
  echo "test-no-account-docker: Docker is not available" >&2
  exit 1
}
W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-noaccount-docker.XXXXXX")
chmod 0755 "$W"
name=rowsafe-noacct-docker-$$
pw=$(openssl rand -hex 12)
secret=$(openssl rand -hex 16)
cipher=$(openssl rand -hex 24)

dc() { docker compose --project-directory "$W" -p "$name" -f "$W/compose.yml" -f "$W/compose.override.yml" "$@"; }
rs() { dc exec -T rowsafe rowsafe "$@"; }
psql_pg() { dc exec -T -u postgres postgres psql -qAtX -v ON_ERROR_STOP=1 "$@"; }
psql_shop() { psql_pg -d shop "$@"; }
started() { psql_pg -c 'SELECT pg_postmaster_start_time()'; }
shop_active() { rs ls | grep shop | grep -q active; }
copy_gone() { ! rs restores shop | grep -q ready; }
hook_got_test() { dc logs hook | grep -q 'X-Rowsafe-Signature: t=.*,v1=.*"event": *"test"'; }

cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$W"
}
trap cleanup EXIT INT TERM

fail() {
  echo "test-no-account-docker: $*" >&2
  echo "---- rowsafe container log" >&2
  dc logs --no-log-prefix --tail 150 rowsafe >&2 || true
  exit 1
}

# until_ok SECONDS DESCRIPTION COMMAND...: retry COMMAND every 3 seconds.
until_ok() {
  _limit=$1 _what=$2
  shift 2
  _i=0
  until "$@" >"$W/until.out" 2>&1; do
    _i=$((_i + 3))
    [ "$_i" -lt "$_limit" ] || {
      cat "$W/until.out" >&2
      fail "timed out after ${_limit}s: $_what"
    }
    sleep 3
  done
  echo "  ok: $_what"
}

image=rowsafe-test/agent:pg17
echo "building $image from this checkout"
docker build -q -f "$root/deploy/docker/agent.Dockerfile" --build-arg PG_MAJOR=17 --build-arg VERSION=0.0.0-test \
  -t "$image" "$root" >/dev/null

# A test CA and a certificate for MinIO (pgBackRest's S3 client needs TLS).
mkdir -p "$W/certs" "$W/minio-certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=rowsafe test CA" \
  -keyout "$W/certs/ca.key" -out "$W/certs/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=minio" -keyout "$W/minio-certs/private.key" -out "$W/minio.csr" 2>/dev/null
printf 'subjectAltName=DNS:minio\n' >"$W/san.ext"
openssl x509 -req -in "$W/minio.csr" -CA "$W/certs/ca.crt" -CAkey "$W/certs/ca.key" -CAcreateserial -days 2 \
  -extfile "$W/san.ext" -out "$W/minio-certs/public.crt" 2>/dev/null
rm -f "$W/certs/ca.key"
chmod 0644 "$W/minio-certs/private.key" "$W/certs/ca.crt"

# A webhook receiver for alerts: prints each request's signature and body.
cat >"$W/hook.py" <<'PY'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        print("X-Rowsafe-Signature: %s %s" % (self.headers.get("X-Rowsafe-Signature"), body), flush=True)
        self.send_response(204)
        self.end_headers()
http.server.HTTPServer(("", 8080), H).serve_forever()
PY

# The documented compose file as is, and next to it what a person brings:
# rowsafe.env, their bucket (MinIO here), plus a second PostgreSQL that
# isn't the one behind the shared socket.
cp "$root/deploy/docker/compose.no-account.yml" "$W/compose.yml"
umask 077
cat >"$W/rowsafe.env" <<EOF
ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock
ROWSAFE_REPO_S3_ENDPOINT=minio
ROWSAFE_REPO_S3_PORT=9000
ROWSAFE_REPO_S3_REGION=us-east-1
ROWSAFE_REPO_S3_BUCKET=rowsafe
ROWSAFE_REPO_S3_KEY=rowsafe-test
ROWSAFE_REPO_S3_KEY_SECRET=$secret
ROWSAFE_REPO_CIPHER_PASS=$cipher
ROWSAFE_REPO_S3_CA_FILE=/certs/ca.crt
ROWSAFE_HEARTBEAT_INTERVAL=5s
ROWSAFE_POLL_INTERVAL=2s
EOF
chmod 0644 "$W/rowsafe.env" # the test's own throwaway secrets; read by Docker
umask 022
cat >"$W/compose.override.yml" <<EOF
services:
  rowsafe:
    image: $image
    depends_on:
      - minio
    volumes:
      - $W/certs/ca.crt:/certs/ca.crt:ro
  minio:
    image: $(sh "$MINIO_SH")
    command: server /data --address :9000 --certs-dir /certs
    environment:
      MINIO_ROOT_USER: rowsafe-test
      MINIO_ROOT_PASSWORD: $secret
    volumes:
      - $W/minio-certs:/certs:ro
  hook:
    image: python:3.13-alpine
    command: python3 -u /hook.py
    volumes:
      - $W/hook.py:/hook.py:ro
  other:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: $pw
EOF
export POSTGRES_PASSWORD="$pw"

dc up -d minio hook postgres other >/dev/null 2>&1 || { dc up -d minio hook postgres other; fail "starting the services"; }
until_ok 60 "MinIO has the bucket" dc exec -T minio sh -c \
  "mc alias set m https://localhost:9000 rowsafe-test $secret --insecure >/dev/null && mc mb --insecure --ignore-existing m/rowsafe >/dev/null"
until_ok 60 "postgres:17 accepts connections" psql_pg -c 'SELECT 1'
# An app's database, and rows to lose later.
psql_pg -c "CREATE DATABASE shop" || fail "the shop database"
psql_shop -c "CREATE TABLE orders (id int PRIMARY KEY, note text); INSERT INTO orders SELECT g, 'order ' || g FROM generate_series(1, 5) g" ||
  fail "the orders table"
before=$(started)

dc up -d rowsafe >/dev/null 2>&1 || { dc up -d rowsafe; fail "starting rowsafe"; }
until_ok 60 "Rowsafe's control plane listens in its container" dc exec -T rowsafe test -S /var/lib/rowsafe/control.sock
[ "$(dc exec -T rowsafe id -u):$(dc exec -T rowsafe id -g)" = 999:999 ] || fail "the rowsafe container doesn't run as 999:999"
until_ok 60 "the agent enrolled with its own control plane" rs ls

# rowsafe add with the compose service's connection string: saved, the
# plan, then backups on (--yes answers the question). Rowsafe doesn't restart
# PostgreSQL: it says to restart the container.
rs add shop "postgres://postgres:$pw@postgres:5432/shop" --yes >"$W/add.out" 2>&1 || { cat "$W/add.out"; fail "rowsafe add"; }
cat "$W/add.out"
grep -q "Saved shop" "$W/add.out" || fail "rowsafe add didn't save shop"
grep -q "docker compose restart" "$W/add.out" || fail "rowsafe add didn't say to restart the postgres container"
! grep -q "sudo" "$W/add.out" || fail "rowsafe add in the container says sudo"
rs ls | tee "$W/ls.out"
grep -q "shop" "$W/ls.out" || fail "rowsafe ls doesn't show shop"
dc exec -T -u postgres postgres grep -q "/rowsafe-spool/shop" /var/lib/postgresql/data/postgresql.auto.conf ||
  fail "archive_command isn't the spool's (ALTER SYSTEM)"
# Adding it again finds it, and another server isn't taken for this one.
rs add shop "postgres://postgres:$pw@postgres:5432/shop" --yes | grep -q "protected on this server" || fail "rowsafe add twice"
rs add other "postgres://postgres:$pw@other:5432/postgres" --yes >"$W/other.out" 2>&1 || { cat "$W/other.out"; fail "rowsafe add other"; }
grep -q "isn't the PostgreSQL this container shares a socket with" "$W/other.out" || { cat "$W/other.out"; fail "another server was taken for this one"; }
! rs ls | grep -q "other" || fail "the other server is protected"
echo "  ok: another PostgreSQL is saved but not protected here"

sleep 15
[ "$(started)" = "$before" ] || fail "PostgreSQL restarted without anyone asking"
rs show shop | grep -qi "restart" || fail "rowsafe show doesn't say PostgreSQL waits for a restart"
echo "  ok: Rowsafe didn't restart PostgreSQL; it waits for the person"

# The person restarts the container when it suits them.
dc restart postgres >/dev/null 2>&1 || fail "docker compose restart postgres"
until_ok 180 "the database is active (archiving proven)" shop_active

# The first full backup and the first Proof run by themselves.
until_ok 480 "rowsafe status shop: protected" rs status shop
rs status shop
rs backups shop
rs proofs shop | tee "$W/proofs.out"
grep -qi "pass" "$W/proofs.out" || fail "no Proof passed"

# A Mark, then rows deleted by mistake, then a differential backup.
rs mark shop before-drop --json | tee "$W/mark.json"
grep -q '"before-drop"' "$W/mark.json" || fail "the Mark"
psql_shop -c "DELETE FROM orders WHERE id > 2" || fail "deleting rows"
[ "$(psql_shop -c 'SELECT count(*) FROM orders')" = 2 ] || fail "the rows weren't deleted"
rs marks shop | grep -q before-drop || fail "rowsafe marks"
rs backup shop --type diff || fail "rowsafe backup"
rs backups shop | tee "$W/backups.out"
grep -qi diff "$W/backups.out" || fail "no differential backup listed"

# The rowsafe container restarts: its control plane keeps everything.
dc restart rowsafe >/dev/null 2>&1 || fail "docker compose restart rowsafe"
until_ok 60 "the control plane is back" dc exec -T rowsafe test -S /var/lib/rowsafe/control.sock
until_ok 60 "still active after Rowsafe restarted" shop_active
rs marks shop | grep -q before-drop || fail "the Mark is gone after a restart"

# Rewind: a copy as it was at the Mark, in the rowsafe container, with the rows.
rs restore shop --to before-drop | tee "$W/restore.out" || fail "rowsafe restore"
rs restores shop | grep -q ready || fail "rowsafe restores doesn't show the copy ready"
rs tasks shop --type rewind_copy --json >"$W/copy.json" || fail "the copy's task"
copy_sock=$(grep -o '"socket_dir": *"[^"]*"' "$W/copy.json" | head -1 | sed 's/.*: *"\(.*\)"/\1/')
copy_port=$(grep -o '"port": *[0-9]*' "$W/copy.json" | head -1 | sed 's/.*: *//')
[ -n "$copy_sock" ] && [ -n "$copy_port" ] || { cat "$W/copy.json"; fail "where the copy listens"; }
n=$(dc exec -T rowsafe psql -qAtX -h "$copy_sock" -p "$copy_port" -d shop -c 'SELECT count(*) FROM orders') ||
  fail "reading the copy"
[ "$n" = 5 ] || fail "the copy has $n orders, want 5 (as at the Mark)"
[ "$(psql_shop -c 'SELECT count(*) FROM orders')" = 2 ] || fail "restoring a copy changed production"
echo "  ok: the copy at the Mark has the 5 orders; production still has 2"
rs rewind compare shop public.orders | tee "$W/compare.out" || fail "rowsafe rewind compare"
grep -q "orders" "$W/compare.out" || fail "the comparison doesn't list orders"
! rs rewind rows shop public.orders </dev/null >"$W/rows.out" 2>&1 || fail "rows came back without a confirmation"
rs rewind rows shop public.orders --yes || fail "rowsafe rewind rows"
[ "$(psql_shop -c 'SELECT count(*) FROM orders')" = 5 ] || fail "the rows didn't come back"
rs marks shop | grep -q before-rewind-rows || fail "no Mark before bringing rows back"
echo "  ok: the deleted rows are back, after a Mark"
rs rewind drop shop --yes || fail "rowsafe rewind drop"
until_ok 60 "the copy is gone" copy_gone

# Alerts: a webhook next to it gets a signed test notification.
rs channels list | grep -q "No notification channels" || fail "rowsafe channels list"
rs channels add --type webhook --name ops --url http://hook:8080/rowsafe >"$W/chan.out" 2>&1 || { cat "$W/chan.out"; fail "rowsafe channels add"; }
grep -q "whsec_" "$W/chan.out" || { cat "$W/chan.out"; fail "no signing secret"; }
rs channels test ops >"$W/chantest.out" 2>&1 || { cat "$W/chantest.out"; fail "rowsafe channels test"; }
until_ok 30 "the webhook got a signed test notification" hook_got_test
rs alerts >"$W/alerts.out" 2>&1 || { cat "$W/alerts.out"; fail "rowsafe alerts"; }
! grep -q "backup_stale\|postgres_unreachable\|wal_archiving_failing" "$W/alerts.out" || { cat "$W/alerts.out"; fail "an alert fires on a healthy server"; }
echo "  ok: alerts go to a webhook; none fire on a healthy server"

# Connecting to the dashboard from the container isn't there yet: it says so.
! rs login --yes </dev/null >"$W/login.out" 2>&1 || fail "rowsafe login in the container"
grep -q "isn't supported yet" "$W/login.out" || { cat "$W/login.out"; fail "rowsafe login doesn't say why not"; }
echo "  ok: rowsafe login in the container says it isn't supported yet"

# Direct commands use the saved connection string.
rs pulse shop >"$W/pulse.out" 2>&1 || true
grep -q "/100" "$W/pulse.out" || { cat "$W/pulse.out"; fail "rowsafe pulse shop"; }
echo "  ok: rowsafe pulse shop uses the saved connection string"

# Through all of it, PostgreSQL restarted only when the person did.
[ "$(dc ps -q postgres | xargs docker inspect -f '{{.RestartCount}}')" = 0 ] || fail "the postgres container restarted by itself"
echo "test-no-account-docker: passed"
