#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test SQLite on a server on its own (the installer's --no-account
# --sqlite PATH), for real, in Docker: an app's SQLite file in WAL mode, the
# agent running its own control plane (ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock,
# internal/localcp) as the file's user, a MinIO bucket behind TLS, and the
# rowsafe CLI next to the agent, as root:
#
#   the installer's registration (rowsafe-agent setup plan and apply), the
#   check, the first backup and the first Proof (rowsafe status says
#   protected), a Mark, rows deleted by mistake, another backup, the agent
#   restarting (the state is kept), a copy restored to the Mark next to the
#   live file, compare and the rows brought back (after a Mark), the copy
#   deleted.
#
# Usage: sh scripts/test-no-account-sqlite.sh   (needs Docker, ~3 min)
set -eu
cd "$(dirname "$0")/.."
image=${NOACCOUNT_SQLITE_IMAGE:-python:3.13-alpine} # Python's sqlite3 plays the app
proj=rowsafe-noaccount-sqlite-$$
work=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-noaccount-sqlite.XXXXXX")
chmod 0755 "$work"
arch=$(docker version --format '{{.Server.Arch}}')
net=$proj
agent=$proj-agent
db=/srv/app/app.db

cleanup() {
  docker ps -aq --filter "label=$proj" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker volume ls -q --filter "label=$proj" | xargs -r docker volume rm >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

fail() {
  echo "test-no-account-sqlite: $*" >&2
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
# agent's own helper as the agent's user (as the installer does); sql runs
# SQL on the live file, as the app.
rs() { docker exec -u 0 -e HOME=/tmp/cli -e NO_COLOR=1 "$agent" /it/rowsafe "$@"; }
ra() { docker exec -u 1000 "$agent" /opt/rowsafe/rowsafe-agent "$@"; }
sql() {
  docker exec -u 1000 "$agent" python3 -c 'import sqlite3, sys
c = sqlite3.connect(sys.argv[1], timeout=30)
r = c.execute(sys.argv[2]).fetchall()
c.commit()
print("\n".join(str(x[0]) for x in r))' "$db" "$1"
}

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
  -v "$work/certs:/root/.minio/certs:ro" minio/minio:latest server /data >/dev/null
for _ in $(seq 1 30); do
  docker run --rm --label "$proj" --network "$net" --entrypoint sh minio/minio:latest -c \
    "mc --insecure alias set m https://minio:9000 rowsafe $secret >/dev/null && mc --insecure mb -p m/backups >/dev/null" \
    >/dev/null 2>&1 && break
  sleep 1
done

echo "==> the app's SQLite file (WAL mode)"
for v in state data; do docker volume create --label "$proj" "$proj-$v" >/dev/null; done
docker run --rm --label "$proj" -v "$proj-state:/var/lib/rowsafe" -v "$proj-data:/srv/app" --entrypoint chown "$image" 1000:1000 /var/lib/rowsafe /srv/app
docker run --rm --label "$proj" --user 1000 -v "$proj-data:/srv/app" "$image" python3 -c 'import sqlite3
c = sqlite3.connect("/srv/app/app.db")
c.execute("PRAGMA journal_mode=WAL")
c.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, note TEXT)")
c.executemany("INSERT INTO orders VALUES (?, ?)", [(i, "order %d" % i) for i in range(1, 6)])
c.commit()'

# The agent without an account, as the file's user (the installer gives
# the agent access with an ACL instead), allowed to protect that file (the
# installer lists it in /etc/rowsafe/sqlite-paths): its own control plane
# on its socket.
docker run -d --label "$proj" --network "$net" --name "$agent" --user 1000 \
  -v "$proj-state:/var/lib/rowsafe" -v "$proj-data:/srv/app" -v "$work/rowsafe-agent:/opt/rowsafe/rowsafe-agent:ro" \
  -v "$work/rowsafe:/it/rowsafe:ro" -v "$work/certs/public.crt:/it/ca.crt:ro" \
  -e ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock -e ROWSAFE_HEARTBEAT_INTERVAL=5s -e ROWSAFE_POLL_INTERVAL=2s \
  -e ROWSAFE_MODE=native -e ROWSAFE_AUTO_UPDATE=false -e ROWSAFE_STATE_DIR=/var/lib/rowsafe \
  -e ROWSAFE_CONFIG_DIR=/var/lib/rowsafe/config -e ROWSAFE_DRILL_DIR=/var/lib/rowsafe/drills \
  -e ROWSAFE_REWIND_DIR=/var/lib/rowsafe/rewind -e ROWSAFE_LOG_DIR=/var/lib/rowsafe/log \
  -e ROWSAFE_REPO_S3_ENDPOINT=minio -e ROWSAFE_REPO_S3_PORT=9000 -e ROWSAFE_REPO_S3_REGION=us-east-1 \
  -e ROWSAFE_REPO_S3_BUCKET=backups -e ROWSAFE_REPO_S3_KEY=rowsafe -e ROWSAFE_REPO_S3_KEY_SECRET="$secret" \
  -e ROWSAFE_REPO_CIPHER_PASS="cipher-$secret" -e ROWSAFE_REPO_S3_CA_FILE=/it/ca.crt \
  -e ROWSAFE_SQLITE_PATHS="$db" \
  --entrypoint /opt/rowsafe/rowsafe-agent "$image" run >/dev/null
until_ok 60 "the agent's control plane listens" docker exec "$agent" test -S /var/lib/rowsafe/control.sock
docker exec -u 0 "$agent" mkdir -p /tmp/cli

# The installer's registration: the plan, then turning backups on.
ra setup plan --name app --socket-dir "$db" --engine sqlite --id-file /var/lib/rowsafe/app.id || fail "setup plan"
ra setup apply --database "$(docker exec "$agent" cat /var/lib/rowsafe/app.id)" || fail "setup apply"
rs add app "$db" 2>&1 | grep -q -- "--no-account --sqlite $db" || fail "rowsafe add with a SQLite file doesn't point to the installer"
until_ok 120 "the database is active (its changes reach the bucket)" sh -c "docker exec -u 0 -e HOME=/tmp/cli $agent /it/rowsafe ls | grep app | grep -q active"
until_ok 300 "rowsafe status app: protected (first backup and Proof)" rs status app
rs backups app
rs proofs app

# A Mark, then rows deleted by mistake, then another backup.
rs mark app before-drop --json >"$work/mark.json" 2>&1 || { cat "$work/mark.json"; fail "rowsafe mark"; }
grep -q '"before-drop"' "$work/mark.json" || { cat "$work/mark.json"; fail "the Mark"; }
sql "DELETE FROM orders WHERE id > 2" >/dev/null || fail "deleting rows"
[ "$(sql 'SELECT count(*) FROM orders')" = 2 ] || fail "the rows weren't deleted"
rs backup app || fail "rowsafe backup"

# The agent restarts: its control plane keeps everything.
docker restart "$agent" >/dev/null
until_ok 60 "the control plane is back" docker exec "$agent" test -S /var/lib/rowsafe/control.sock
until_ok 60 "still active after the agent restarted" sh -c "docker exec -u 0 -e HOME=/tmp/cli $agent /it/rowsafe ls | grep app | grep -q active"
rs marks app | grep -q before-drop || fail "the Mark is gone after a restart"

# Rewind: a copy as it was at the Mark, next to the live file; compare;
# bring the rows back.
until_ok 180 "rowsafe restore app --to before-drop (the copy is ready)" rs restore app --to before-drop
[ "$(sql 'SELECT count(*) FROM orders')" = 2 ] || fail "restoring a copy changed the live file"
rs rewind compare app main:orders | tee "$work/compare.out" || fail "rowsafe rewind compare"
grep -q "orders" "$work/compare.out" || fail "the comparison doesn't list orders"
rs rewind rows app main:orders --yes || fail "rowsafe rewind rows"
[ "$(sql 'SELECT count(*) FROM orders')" = 5 ] || fail "the rows didn't come back"
rs marks app | grep -q before-rewind-rows || fail "no Mark before bringing rows back"
echo "  ok: the deleted rows are back from the copy at the Mark, after a Mark"
rs rewind drop app --yes || fail "rowsafe rewind drop"
until_ok 120 "the copy is gone" sh -c "! docker exec -u 0 -e HOME=/tmp/cli $agent /it/rowsafe restores app | grep -q ready"
rs status app || fail "not protected at the end"
echo "test-no-account-sqlite: passed"
