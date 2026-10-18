#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test ClickHouse on a server on its own (the installer's --no-account),
# for real, in Docker: the official clickhouse-server image, the agent next
# to it in the same image (restore tests and copies run the server's own
# clickhouse program; BACKUP goes to the agent's encrypting gateway on
# 127.0.0.1) running its own control plane
# (ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock, internal/localcp), a
# MinIO bucket behind TLS, and the rowsafe CLI next to the agent, as root:
#
#   the installer's steps (Rowsafe's own ClickHouse user with SQL, the
#   plan, turning backups on), the check, the first backup and the first
#   Proof (rowsafe status says protected), a Mark, rows deleted by mistake,
#   another backup, the agent restarting (the state is kept), a copy
#   restored to the Mark next to production, compare and the rows brought
#   back (after a Mark), the copy deleted.
#
# Usage: sh scripts/test-no-account-clickhouse.sh           # clickhouse-server:26.8
#        NOACCOUNT_CLICKHOUSE=25.8 sh scripts/test-no-account-clickhouse.sh
# (needs Docker, ~5 min)
set -eu
# The MinIO test image (built once from source: scripts/minio).
MINIO_SH=$(cd "$(dirname "$0")" && pwd)/minio/image.sh
cd "$(dirname "$0")/.."
version=${NOACCOUNT_CLICKHOUSE:-26.8}
image=clickhouse/clickhouse-server:$version
proj=rowsafe-noaccount-ch-$$
work=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-noaccount-ch.XXXXXX")
chmod 0755 "$work"
arch=$(docker version --format '{{.Server.Arch}}')
net=$proj
name=$proj-server
agent=$proj-agent

cleanup() {
  docker ps -aq --filter "label=$proj" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker volume ls -q --filter "label=$proj" | xargs -r docker volume rm >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

fail() {
  echo "test-no-account-clickhouse ($version): $*" >&2
  echo "---- agent log" >&2
  docker logs "$agent" 2>&1 | tail -80 >&2 || true
  exit 1
}

# until_ok SECONDS DESCRIPTION COMMAND...: retry COMMAND every 3 seconds.
until_ok() {
  _limit=$1 _what=$2
  shift 2
  _i=0
  until "$@" >"$work/until.out" 2>&1; do
    _i=$((_i + 3))
    [ "$_i" -lt "$_limit" ] || {
      cat "$work/until.out" >&2
      fail "timed out after ${_limit}s: $_what"
    }
    sleep 3
  done
  echo "  ok: $_what"
}

# rs runs the rowsafe CLI next to the agent, as root (sudo rowsafe); ra the
# agent's own helper as the agent's user (as the installer does); q runs
# SQL on production.
rs() { docker exec -u 0 -e HOME=/tmp/cli -e NO_COLOR=1 "$agent" /it/rowsafe "$@"; }
ra() { docker exec -u clickhouse "$agent" /opt/rowsafe/rowsafe-agent "$@"; }
q() { docker exec "$name" clickhouse-client -q "$1"; }

echo "==> rowsafe and rowsafe-agent (linux/$arch)"
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$work/rowsafe" ./cmd/rowsafe
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$work/rowsafe-agent" ./cmd/rowsafe-agent
chmod 0755 "$work/rowsafe" "$work/rowsafe-agent"

echo "==> MinIO with TLS"
docker network create --label "$proj" "$net" >/dev/null
mkdir -p "$work/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=minio" -addext "subjectAltName=DNS:minio" \
  -keyout "$work/certs/private.key" -out "$work/certs/public.crt" >/dev/null 2>&1
chmod 0644 "$work/certs/private.key" "$work/certs/public.crt"
secret=$(openssl rand -hex 16)
docker run -d --label "$proj" --network "$net" --network-alias minio --name "$proj-minio" \
  -e MINIO_ROOT_USER=rowsafe -e MINIO_ROOT_PASSWORD="$secret" \
  -v "$work/certs:/root/.minio/certs:ro" "$(sh "$MINIO_SH")" server /data >/dev/null
for _ in $(seq 1 30); do
  docker run --rm --label "$proj" --network "$net" --entrypoint sh "$(sh "$MINIO_SH")" -c \
    "mc --insecure alias set m https://minio:9000 rowsafe $secret >/dev/null && mc --insecure mb -p m/backups >/dev/null" \
    >/dev/null 2>&1 && break
  sleep 1
done

echo "==> ClickHouse $version"
for v in data state; do docker volume create --label "$proj" "$proj-$v" >/dev/null; done
docker run -d --label "$proj" --network "$net" --name "$name" -v "$proj-data:/var/lib/clickhouse" \
  -e CLICKHOUSE_SKIP_USER_SETUP=1 -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 "$image" >/dev/null
until_ok 120 "ClickHouse answers" q "SELECT 1"
q "CREATE DATABASE analytics" || fail "the database"
q "CREATE TABLE analytics.hits (id UInt64, note String) ENGINE = MergeTree ORDER BY id" || fail "the table"
q "INSERT INTO analytics.hits SELECT number + 1, concat('hit ', toString(number + 1)) FROM numbers(5)" || fail "the rows"

# The agent without an account, in ClickHouse's own image, on the server
# container's network (ClickHouse on 127.0.0.1, as on a server): its own
# control plane on its socket.
docker run --rm --label "$proj" -v "$proj-state:/var/lib/rowsafe" --entrypoint chown "$image" clickhouse:clickhouse /var/lib/rowsafe
docker run -d --label "$proj" --network "container:$name" --name "$agent" --user clickhouse \
  -v "$proj-state:/var/lib/rowsafe" -v "$proj-data:/var/lib/clickhouse:ro" -v "$work/rowsafe-agent:/opt/rowsafe/rowsafe-agent:ro" \
  -v "$work/rowsafe:/it/rowsafe:ro" -v "$work/certs/public.crt:/it/ca.crt:ro" \
  -e ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock -e ROWSAFE_HEARTBEAT_INTERVAL=5s -e ROWSAFE_POLL_INTERVAL=2s \
  -e ROWSAFE_MODE=native -e ROWSAFE_AUTO_UPDATE=false -e ROWSAFE_STATE_DIR=/var/lib/rowsafe \
  -e ROWSAFE_CONFIG_DIR=/var/lib/rowsafe/config -e ROWSAFE_DRILL_DIR=/var/lib/rowsafe/drills \
  -e ROWSAFE_REWIND_DIR=/var/lib/rowsafe/rewind -e ROWSAFE_LOG_DIR=/var/lib/rowsafe/log \
  -e ROWSAFE_REPO_S3_ENDPOINT=minio -e ROWSAFE_REPO_S3_PORT=9000 -e ROWSAFE_REPO_S3_REGION=us-east-1 \
  -e ROWSAFE_REPO_S3_BUCKET=backups -e ROWSAFE_REPO_S3_KEY=rowsafe -e ROWSAFE_REPO_S3_KEY_SECRET="$secret" \
  -e ROWSAFE_REPO_CIPHER_PASS="cipher-$secret" -e ROWSAFE_REPO_S3_CA_FILE=/it/ca.crt \
  --entrypoint /opt/rowsafe/rowsafe-agent "$image" run >/dev/null
until_ok 60 "the agent's control plane listens" docker exec "$agent" test -S /var/lib/rowsafe/control.sock
docker exec -u 0 "$agent" mkdir -p /tmp/cli

# The installer's steps: Rowsafe's own user, the plan, backups on.
ra clickhouse login --port 8123 </dev/null || fail "Rowsafe's ClickHouse user"
ra setup plan --name events --port 8123 --engine clickhouse --id-file /var/lib/rowsafe/events.id || fail "setup plan"
ra setup apply --database "$(docker exec "$agent" cat /var/lib/rowsafe/events.id)" || fail "setup apply"
until_ok 180 "the database is active (its changes reach the bucket)" sh -c "docker exec -u 0 -e HOME=/tmp/cli $agent /it/rowsafe ls | grep events | grep -q active"
until_ok 600 "rowsafe status events: protected (first backup and Proof)" rs status events
rs backups events
rs proofs events

# A Mark, then rows deleted by mistake, then another backup.
rs mark events before-drop --json >"$work/mark.json" 2>&1 || { cat "$work/mark.json"; fail "rowsafe mark"; }
grep -q '"before-drop"' "$work/mark.json" || { cat "$work/mark.json"; fail "the Mark"; }
q "ALTER TABLE analytics.hits DELETE WHERE id > 2 SETTINGS mutations_sync = 1" || fail "deleting rows"
[ "$(q 'SELECT count() FROM analytics.hits')" = 2 ] || fail "the rows weren't deleted"
rs backup events || fail "rowsafe backup"

# The agent restarts: its control plane keeps everything.
docker restart "$agent" >/dev/null
until_ok 60 "the control plane is back" docker exec "$agent" test -S /var/lib/rowsafe/control.sock
until_ok 60 "still active after the agent restarted" sh -c "docker exec -u 0 -e HOME=/tmp/cli $agent /it/rowsafe ls | grep events | grep -q active"
rs marks events | grep -q before-drop || fail "the Mark is gone after a restart"

# Rewind: a copy as it was at the Mark, next to production; compare;
# bring the rows back.
until_ok 300 "rowsafe restore events --to before-drop (the copy is ready)" rs restore events --to before-drop
[ "$(q 'SELECT count() FROM analytics.hits')" = 2 ] || fail "restoring a copy changed production"
rs rewind compare events analytics:hits | tee "$work/compare.out" || fail "rowsafe rewind compare"
grep -q "hits" "$work/compare.out" || fail "the comparison doesn't list hits"
rs rewind rows events analytics:hits --yes || fail "rowsafe rewind rows"
[ "$(q 'SELECT count() FROM analytics.hits')" = 5 ] || fail "the rows didn't come back"
rs marks events | grep -q before-rewind-rows || fail "no Mark before bringing rows back"
echo "  ok: the deleted rows are back from the copy at the Mark, after a Mark"
rs rewind drop events --yes || fail "rowsafe rewind drop"
until_ok 120 "the copy is gone" sh -c "! docker exec -u 0 -e HOME=/tmp/cli $agent /it/rowsafe restores events | grep -q ready"
rs status events || fail "not protected at the end"
echo "test-no-account-clickhouse: passed on ClickHouse $version"
