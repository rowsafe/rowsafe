#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Rowsafe without an account (rowsafe pulse postgres://...) through a real
# connection pooler: PostgreSQL in Docker with pg_stat_statements, and
# PgBouncer (Debian 12's, 1.18: no prepared statements, refuses unknown
# startup parameters) in front of it in transaction mode. The local
# package's tests run against both (local/pooler_test.go): Pulse, tables
# and indexes, top queries, activity and settings through the pooler, no
# setting left behind on its server connections, fixes that need their own
# session refused with the reason, and the same fix working on the direct
# connection.
#
# Usage: sh scripts/test-no-account-pooler.sh [postgres:17]   (needs Docker, ~1 min)

set -eu
cd "$(dirname "$0")/.."
image=${1:-postgres:17}
proj=rowsafe-pooler-it-$$
net=$proj

cleanup() {
  docker ps -aq --filter "label=$proj" | xargs docker rm -f >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker network create --label "$proj" "$net" >/dev/null
echo "==> $image"
docker run -d --label "$proj" --network "$net" --name "$proj-pg" -p 127.0.0.1::5432 \
  -e POSTGRES_PASSWORD=test -e POSTGRES_DB=shop \
  "$image" -c shared_preload_libraries=pg_stat_statements >/dev/null

echo "==> PgBouncer (transaction mode)"
docker run -d --label "$proj" --network "$net" --name "$proj-bouncer" -p 127.0.0.1::6432 debian:12 sh -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null && apt-get install -y -qq pgbouncer >/dev/null
  cat >/etc/pgbouncer/pgbouncer.ini <<EOF
[databases]
* = host='"$proj-pg"' port=5432
[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = plain
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
default_pool_size = 5
ignore_startup_parameters = extra_float_digits
EOF
  echo "\"postgres\" \"test\"" >/etc/pgbouncer/userlist.txt
  chown -R postgres /etc/pgbouncer
  echo ready
  exec su postgres -s /bin/sh -c "pgbouncer /etc/pgbouncer/pgbouncer.ini"
' >/dev/null

port() { docker port "$1" "$2" | head -n1 | sed 's/.*://'; }
pgport=$(port "$proj-pg" 5432/tcp)
bport=$(port "$proj-bouncer" 6432/tcp)
direct="postgres://postgres:test@127.0.0.1:$pgport/shop?sslmode=disable"
pooled="postgres://postgres:test@127.0.0.1:$bport/shop?sslmode=disable"

i=0
until docker exec "$proj-pg" pg_isready -U postgres -d shop >/dev/null 2>&1 &&
  docker logs "$proj-bouncer" 2>&1 | grep -q ready && nc -z 127.0.0.1 "$bport" 2>/dev/null; do
  i=$((i + 1))
  [ "$i" -lt 120 ] || { docker logs "$proj-bouncer"; echo "PgBouncer didn't start" >&2; exit 1; }
  sleep 1
done
sleep 1
docker exec "$proj-pg" psql -U postgres -d shop -qc 'CREATE EXTENSION IF NOT EXISTS pg_stat_statements' >/dev/null

echo "==> tests through PgBouncer (127.0.0.1:$bport) and directly (127.0.0.1:$pgport)"
ROWSAFE_TEST_POOLER_URL=$pooled ROWSAFE_TEST_DIRECT_URL=$direct \
  go test -count=1 -run 'TestThroughPooler|TestSessionCarriesSettings' -v ./local/ ./collect/

echo "==> the CLI through PgBouncer"
bin=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-pooler-it.XXXXXX")
go build -o "$bin/rowsafe" ./cmd/rowsafe
for cmd in pulse insights top activity settings; do
  out=$("$bin/rowsafe" "$cmd" "$pooled" 2>&1) || {
    # pulse says how healthy the database is with its exit status too.
    case $cmd:$out in pulse:*Score* | pulse:*score*) ;; *) printf 'rowsafe %s failed:\n%s\n' "$cmd" "$out" >&2; rm -rf "$bin"; exit 1 ;; esac
  }
  if printf '%s' "$out" | grep -qi 'unsupported startup parameter\|prepared statement'; then
    printf 'rowsafe %s:\n%s\n' "$cmd" "$out" >&2; rm -rf "$bin"; exit 1
  fi
  echo "rowsafe $cmd: ok"
done
rm -rf "$bin"
