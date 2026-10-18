#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test MongoDB on a server on its own (the installer's --no-account), for
# real, in Docker: the official mongo image as a single-member replica set
# (as the installer sets it up), the agent next to it in the same image (so
# mongodump, mongorestore and mongod are MongoDB's own, as in
# deploy/docker/agent-mongodb.Dockerfile) running its own control plane
# (ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock, internal/localcp), a
# MinIO bucket behind TLS, and the rowsafe CLI next to the agent:
#
#   rowsafe add (saves the connection string, plans and turns on backups:
#   nothing restarts), the check, the first full backup and the first Proof
#   (rowsafe status says protected), a Mark, documents deleted by mistake,
#   another backup, the agent restarting (the state is kept), a copy
#   restored to the Mark next to production, compare and the documents
#   brought back (after a Mark), the copy deleted.
#
# Usage: sh scripts/test-no-account-mongodb.sh            # mongo:8.0
#        NOACCOUNT_MONGO="7.0" sh scripts/test-no-account-mongodb.sh
# (needs Docker, ~10 min)
set -eu
# The MinIO test image (built once from source: scripts/minio).
MINIO_SH=$(cd "$(dirname "$0")" && pwd)/minio/image.sh
cd "$(dirname "$0")/.."
versions=${NOACCOUNT_MONGO:-8.0}
proj=rowsafe-noaccount-mongo-$$
work=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-noaccount-mongo.XXXXXX")
chmod 0755 "$work"
arch=$(docker version --format '{{.Server.Arch}}')
net=$proj

cleanup() {
  docker ps -aq --filter "label=$proj" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker volume ls -q --filter "label=$proj" | xargs -r docker volume rm >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

fail() {
  echo "test-no-account-mongodb ($version): $*" >&2
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

# rs runs the rowsafe CLI next to the agent (as its user, mongodb: the
# control plane's socket is theirs).
rs() { docker exec -e HOME=/tmp/cli -e NO_COLOR=1 "$agent" /it/rowsafe "$@"; }
# js runs JavaScript in shop on production.
js() { docker exec "$name" mongosh --quiet shop --eval "$1"; }

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

for version in $versions; do
  echo "==> mongo $version"
  name=$proj-mongo$version
  agent=$name-agent
  docker volume create --label "$proj" "$name-state" >/dev/null
  docker run -d --label "$proj" --network "$net" --name "$name" "mongo:$version" --replSet rs0 --bind_ip_all >/dev/null
  until_ok 120 "mongod answers" js "db.runCommand({ping: 1}).ok"
  js 'rs.initiate({_id: "rs0", members: [{_id: 0, host: "127.0.0.1:27017"}]})' >/dev/null || fail "rs.initiate"
  until_ok 60 "the replica set has a primary" sh -c "docker exec $name mongosh --quiet --eval 'db.hello().isWritablePrimary' | grep -q true"
  js 'db.orders.insertMany([1, 2, 3, 4, 5].map(i => ({_id: i, note: "order " + i})))' >/dev/null || fail "the orders"

  # The agent without an account, in MongoDB's own image, on the database
  # container's network (MongoDB on 127.0.0.1, as on a server): its own
  # control plane on its socket.
  docker run --rm --label "$proj" -v "$name-state:/var/lib/rowsafe" --entrypoint chown "mongo:$version" mongodb:mongodb /var/lib/rowsafe
  docker run -d --label "$proj" --network "container:$name" --name "$agent" --user mongodb \
    -v "$name-state:/var/lib/rowsafe" -v "$work/rowsafe-agent:/usr/local/bin/rowsafe-agent:ro" \
    -v "$work/rowsafe:/it/rowsafe:ro" -v "$work/certs/public.crt:/it/ca.crt:ro" \
    -e ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock -e ROWSAFE_HEARTBEAT_INTERVAL=5s -e ROWSAFE_POLL_INTERVAL=2s \
    -e ROWSAFE_MODE=native -e ROWSAFE_AUTO_UPDATE=false -e ROWSAFE_STATE_DIR=/var/lib/rowsafe \
    -e ROWSAFE_CONFIG_DIR=/var/lib/rowsafe/config -e ROWSAFE_DRILL_DIR=/var/lib/rowsafe/drills \
    -e ROWSAFE_REWIND_DIR=/var/lib/rowsafe/rewind -e ROWSAFE_LOG_DIR=/var/lib/rowsafe/log \
    -e ROWSAFE_REPO_S3_ENDPOINT=minio -e ROWSAFE_REPO_S3_PORT=9000 -e ROWSAFE_REPO_S3_REGION=us-east-1 \
    -e ROWSAFE_REPO_S3_BUCKET=backups -e ROWSAFE_REPO_S3_KEY=rowsafe -e ROWSAFE_REPO_S3_KEY_SECRET="$secret" \
    -e ROWSAFE_REPO_CIPHER_PASS="cipher-$secret" -e ROWSAFE_REPO_S3_CA_FILE=/it/ca.crt \
    --entrypoint /usr/local/bin/rowsafe-agent "mongo:$version" run >/dev/null
  until_ok 60 "the agent's control plane listens" docker exec "$agent" test -S /var/lib/rowsafe/control.sock
  docker exec "$agent" mkdir -p /tmp/cli

  # rowsafe add saves the database and, on its own server, protects it.
  url="mongodb://127.0.0.1:27017/shop?directConnection=true"
  rs add shop "$url" --yes >"$work/add.out" 2>&1 || { cat "$work/add.out"; fail "rowsafe add"; }
  cat "$work/add.out"
  grep -q "Saved shop" "$work/add.out" || fail "rowsafe add didn't save shop"
  rs add shop "$url" --yes 2>&1 | grep -q "protected on this server" || fail "rowsafe add twice"
  rs show shop --json >"$work/show.json" 2>&1 || true
  grep -q '"engine": *"mongodb"' "$work/show.json" || { cat "$work/show.json"; fail "shop isn't a MongoDB database"; }
  rs pulse shop >"$work/pulse.out" 2>&1 || true
  grep -q "Change log (oplog)" "$work/pulse.out" || { cat "$work/pulse.out"; fail "rowsafe pulse shop"; }

  until_ok 240 "the database is active (the oplog reaches the bucket)" sh -c "docker exec -e HOME=/tmp/cli $agent /it/rowsafe ls | grep shop | grep -q active"
  until_ok 600 "rowsafe status shop: protected (first full backup and Proof)" rs status shop
  rs backups shop
  rs proofs shop

  # A Mark, then documents deleted by mistake, then another backup.
  rs mark shop before-drop --json >"$work/mark.json" 2>&1 || { cat "$work/mark.json"; fail "rowsafe mark"; }
  grep -q '"before-drop"' "$work/mark.json" || { cat "$work/mark.json"; fail "the Mark"; }
  js 'db.orders.deleteMany({_id: {$gt: 2}})' >/dev/null || fail "deleting documents"
  [ "$(js 'db.orders.countDocuments()')" = 2 ] || fail "the documents weren't deleted"
  rs marks shop | grep -q before-drop || fail "rowsafe marks"
  rs backup shop || fail "rowsafe backup"
  rs backups shop >"$work/backups.out"
  cat "$work/backups.out"
  [ "$(grep -c ' full ' "$work/backups.out" || true)" -ge 2 ] || fail "no second backup listed"

  # The agent restarts: its control plane keeps everything.
  docker restart "$agent" >/dev/null
  until_ok 60 "the control plane is back" docker exec "$agent" test -S /var/lib/rowsafe/control.sock
  until_ok 60 "still active after the agent restarted" sh -c "docker exec -e HOME=/tmp/cli $agent /it/rowsafe ls | grep shop | grep -q active"
  rs marks shop | grep -q before-drop || fail "the Mark is gone after a restart"

  # Rewind: a copy as it was at the Mark, next to production; compare;
  # bring the documents back.
  until_ok 300 "rowsafe restore shop --to before-drop (the copy is ready)" rs restore shop --to before-drop
  rs restores shop | grep -q ready || fail "rowsafe restores doesn't show the copy ready"
  [ "$(js 'db.orders.countDocuments()')" = 2 ] || fail "restoring a copy changed production"
  rs rewind compare shop shop:orders | tee "$work/compare.out" || fail "rowsafe rewind compare"
  grep -q "orders" "$work/compare.out" || fail "the comparison doesn't list orders"
  ! rs rewind rows shop shop:orders </dev/null >"$work/rows.out" 2>&1 || fail "documents came back without a confirmation"
  rs rewind rows shop shop:orders --yes || fail "rowsafe rewind rows"
  [ "$(js 'db.orders.countDocuments()')" = 5 ] || fail "the documents didn't come back"
  rs marks shop | grep -q before-rewind-rows || fail "no Mark before bringing documents back"
  echo "  ok: the deleted documents are back from the copy at the Mark, after a Mark"
  rs rewind drop shop --yes || fail "rowsafe rewind drop"
  until_ok 120 "the copy is gone" sh -c "! docker exec -e HOME=/tmp/cli $agent /it/rowsafe restores shop | grep -q ready"
  rs status shop || fail "not protected at the end"
  echo "test-no-account-mongodb: passed on mongo $version"
  docker rm -f "$agent" "$name" >/dev/null
done
