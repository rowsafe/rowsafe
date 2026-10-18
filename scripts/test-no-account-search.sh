#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test OpenSearch, Qdrant and Meilisearch on a server on its own (the
# installer's --no-account), for real, in Docker: each server's official
# image, the agent next to it in the same image (restore tests and copies
# run the server's own program) running its own control plane
# (ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock, internal/localcp), a
# MinIO bucket behind TLS, and the rowsafe CLI next to the agent, as root.
# These engines keep no log of their changes: backups are snapshots, and a
# Mark is a snapshot taken then.
#
#   the installer's steps (Rowsafe's own key or login, the plan, turning
#   backups on), the check, the first snapshot and the first Proof
#   (rowsafe status says protected), a Mark, documents deleted by mistake,
#   another snapshot, the agent restarting (the state is kept), a copy
#   restored to the Mark next to production, the copy deleted.
#
# Usage: sh scripts/test-no-account-search.sh               # qdrant meilisearch opensearch
#        NOACCOUNT_SEARCH="qdrant" sh scripts/test-no-account-search.sh
# (needs Docker, ~5 min; OpenSearch needs about 2 GB of memory)
set -eu
# The MinIO test image (built once from source: scripts/minio).
MINIO_SH=$(cd "$(dirname "$0")" && pwd)/minio/image.sh
cd "$(dirname "$0")/.."
engines=${NOACCOUNT_SEARCH:-"qdrant meilisearch opensearch"}
proj=rowsafe-noaccount-search-$$
work=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-noaccount-search.XXXXXX")
chmod 0755 "$work"
arch=$(docker version --format '{{.Server.Arch}}')
net=$proj
py=python:3.13-alpine # HTTP requests to the servers
mkey=rowsafe-test-master-key-0123456789abcdef

cleanup() {
  docker ps -aq --filter "label=$proj" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker volume ls -q --filter "label=$proj" | xargs -r docker volume rm >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

fail() {
  echo "test-no-account-search ($engine): $*" >&2
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
# agent's own helper as the agent's user (as the installer does).
rs() { docker exec -u 0 -e HOME=/tmp/cli -e NO_COLOR=1 "$agent" /it/rowsafe "$@"; }
ra() { docker exec -i -u "$auser" "$agent" /opt/rowsafe/rowsafe-agent "$@"; }
# http METHOD PATH [JSON]: a request to production on 127.0.0.1:$port; it
# prints the answer.
http() {
  docker run --rm --label "$proj" --network "container:$name" "$py" python3 -c 'import json, sys, urllib.request
m, url, body, key = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
r = urllib.request.Request(url, method=m, data=body.encode() if body else None, headers={"Content-Type": "application/json"})
if key:
    r.add_header("Authorization", "Bearer " + key)
print(urllib.request.urlopen(r, timeout=60).read().decode())' "$1" "http://127.0.0.1:$port$2" "${3:-}" "$hkey"
}
num() { sed -n "s/.*\"$1\": *\([0-9][0-9]*\).*/\1/p" | head -n 1; }

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

for engine in $engines; do
  name=$proj-$engine
  # A bucket of its own: each engine's database is called search, and a
  # bucket folder holds one database's backups and Marks.
  bucket=backups-$engine
  docker run --rm --label "$proj" --network "$net" --entrypoint sh "$(sh "$MINIO_SH")" -c \
    "mc --insecure alias set m https://minio:9000 rowsafe $secret >/dev/null && mc --insecure mb -p m/$bucket >/dev/null"
  agent=$name-agent
  docker volume create --label "$proj" "$name-state" >/dev/null
  docker volume create --label "$proj" "$name-snap" >/dev/null
  hkey='' extra=''
  case $engine in
    qdrant)
      image=qdrant/qdrant:v1.19.2 port=6333 auser=1000 snapdir=/qdrant/snapshots
      extra="-e ROWSAFE_QDRANT_BIN=/qdrant/qdrant -e ROWSAFE_QDRANT_CONFIG=/qdrant/config/config.yaml"
      docker run -d --label "$proj" --network "$net" --name "$name" -v "$name-snap:$snapdir" "$image" >/dev/null
      ;;
    meilisearch)
      image=getmeili/meilisearch:v1.54.3 port=7700 auser=1000 snapdir=/meili_data/snapshots hkey=$mkey
      docker run -d --label "$proj" --network "$net" --name "$name" -v "$name-snap:$snapdir" -e MEILI_MASTER_KEY="$mkey" \
        -e MEILI_NO_ANALYTICS=true "$image" meilisearch --snapshot-dir "$snapdir" >/dev/null
      ;;
    opensearch)
      image=opensearchproject/opensearch:2.19.6 port=9200 auser=1000 snapdir=/var/lib/rowsafe-opensearch/snapshots
      docker run -d --label "$proj" --network "$net" --name "$name" -v "$name-snap:$snapdir" \
        -e discovery.type=single-node -e DISABLE_SECURITY_PLUGIN=true -e DISABLE_INSTALL_DEMO_CONFIG=true \
        -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" -e path.repo="$snapdir" "$image" >/dev/null
      ;;
  esac
  echo "==> $engine ($image)"
  docker run --rm --label "$proj" -u 0 -v "$name-state:/var/lib/rowsafe" -v "$name-snap:/snap" --entrypoint sh "$image" -c \
    "chown $auser /var/lib/rowsafe && chmod 0777 /snap"
  until_ok 180 "$engine answers" http GET /

  # Documents: 5 of them.
  case $engine in
    qdrant)
      http PUT /collections/docs '{"vectors": {"size": 4, "distance": "Cosine"}}' >/dev/null
      http PUT '/collections/docs/points?wait=true' '{"points": [{"id": 1, "vector": [0.1,0.2,0.3,0.4]}, {"id": 2, "vector": [0.2,0.2,0.3,0.4]}, {"id": 3, "vector": [0.3,0.2,0.3,0.4]}, {"id": 4, "vector": [0.4,0.2,0.3,0.4]}, {"id": 5, "vector": [0.5,0.2,0.3,0.4]}]}' >/dev/null
      count() { http POST /collections/docs/points/count '{"exact": true}' | num count; }
      drop() { http POST '/collections/docs/points/delete?wait=true' '{"points": [3, 4, 5]}' >/dev/null; }
      ;;
    meilisearch)
      http POST /indexes/products/documents '[{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5}]' >/dev/null
      count() { http GET /indexes/products/stats | num numberOfDocuments; }
      drop() { http POST /indexes/products/documents/delete-batch '[3, 4, 5]' >/dev/null; sleep 3; }
      ;;
    opensearch)
      for i in 1 2 3 4 5; do http PUT "/products/_doc/$i" "{\"n\": $i}" >/dev/null; done
      http POST /products/_refresh >/dev/null
      count() { http GET /products/_count | num count; }
      drop() { http POST '/products/_delete_by_query?refresh=true' '{"query": {"terms": {"n": [3, 4, 5]}}}' >/dev/null; }
      ;;
  esac
  five() { [ "$(count)" = 5 ]; }
  until_ok 60 "5 documents are in" five

  # The agent without an account, in the server's own image, on the server
  # container's network (the server on 127.0.0.1, as on a server), with its
  # snapshot folder: its own control plane on its socket.
  # shellcheck disable=SC2086
  docker run -d --label "$proj" --network "container:$name" --name "$agent" --user "$auser" \
    -v "$name-state:/var/lib/rowsafe" -v "$name-snap:$snapdir" -v "$work/rowsafe-agent:/opt/rowsafe/rowsafe-agent:ro" \
    -v "$work/rowsafe:/it/rowsafe:ro" -v "$work/certs/public.crt:/it/ca.crt:ro" \
    -e ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock -e ROWSAFE_HEARTBEAT_INTERVAL=5s -e ROWSAFE_POLL_INTERVAL=2s \
    -e ROWSAFE_MODE=native -e ROWSAFE_AUTO_UPDATE=false -e ROWSAFE_STATE_DIR=/var/lib/rowsafe -e HOME=/var/lib/rowsafe \
    -e ROWSAFE_CONFIG_DIR=/var/lib/rowsafe/config -e ROWSAFE_DRILL_DIR=/var/lib/rowsafe/drills \
    -e ROWSAFE_REWIND_DIR=/var/lib/rowsafe/rewind -e ROWSAFE_LOG_DIR=/var/lib/rowsafe/log \
    -e ROWSAFE_REPO_S3_ENDPOINT=minio -e ROWSAFE_REPO_S3_PORT=9000 -e ROWSAFE_REPO_S3_REGION=us-east-1 \
    -e ROWSAFE_REPO_S3_BUCKET="$bucket" -e ROWSAFE_REPO_S3_KEY=rowsafe -e ROWSAFE_REPO_S3_KEY_SECRET="$secret" \
    -e ROWSAFE_REPO_CIPHER_PASS="cipher-$secret" -e ROWSAFE_REPO_S3_CA_FILE=/it/ca.crt $extra \
    --entrypoint /opt/rowsafe/rowsafe-agent "$image" run >/dev/null
  until_ok 60 "the agent's control plane listens" docker exec "$agent" test -S /var/lib/rowsafe/control.sock
  docker exec -u 0 "$agent" mkdir -p /tmp/cli

  # The installer's steps: Rowsafe's own key or login, the plan, backups on.
  case $engine in
    meilisearch) echo "$mkey" | ra meilisearch login --port 7700 --binary /bin/meilisearch --snapshot-dir "$snapdir" || fail "Rowsafe's key" ;;
    opensearch) ra opensearch login --port 9200 --admin-user admin </dev/null || fail "Rowsafe's login" ;;
  esac
  ra setup plan --name search --port "$port" --engine "$engine" --id-file /var/lib/rowsafe/search.id || fail "setup plan"
  ra setup apply --database "$(docker exec "$agent" cat /var/lib/rowsafe/search.id)" || fail "setup apply"
  until_ok 180 "the database is active" sh -c "docker exec -u 0 -e HOME=/tmp/cli $agent /it/rowsafe ls | grep search | grep -q active"
  until_ok 600 "rowsafe status search: protected (first snapshot and Proof)" rs status search
  rs status search | grep -q "Last change copied" && fail "rowsafe status speaks of a change log $engine doesn't keep"
  rs backups search
  rs proofs search

  # A Mark (a snapshot), documents deleted by mistake, another snapshot.
  rs mark search before-drop --json >"$work/mark.json" 2>&1 || { cat "$work/mark.json"; fail "rowsafe mark"; }
  grep -q '"before-drop"' "$work/mark.json" || { cat "$work/mark.json"; fail "the Mark"; }
  drop
  [ "$(count)" = 2 ] || fail "the documents weren't deleted"
  rs backup search || fail "rowsafe backup"

  # The agent restarts: its control plane keeps everything.
  docker restart "$agent" >/dev/null
  until_ok 60 "the control plane is back" docker exec "$agent" test -S /var/lib/rowsafe/control.sock
  until_ok 60 "still active after the agent restarted" sh -c "docker exec -u 0 -e HOME=/tmp/cli $agent /it/rowsafe ls | grep search | grep -q active"
  rs marks search | grep -q before-drop || fail "the Mark is gone after a restart"

  # Rewind: a copy as it was at the Mark, next to production.
  until_ok 300 "rowsafe restore search --to before-drop (the copy is ready)" rs restore search --to before-drop
  rs restores search | grep -q ready || fail "rowsafe restores doesn't show the copy ready"
  [ "$(count)" = 2 ] || fail "restoring a copy changed production"
  rs rewind drop search --yes || fail "rowsafe rewind drop"
  until_ok 120 "the copy is gone" sh -c "! docker exec -u 0 -e HOME=/tmp/cli $agent /it/rowsafe restores search | grep -q ready"
  rs status search || fail "not protected at the end"
  echo "test-no-account-search: passed on $engine"
  docker rm -f "$agent" "$name" >/dev/null
done
