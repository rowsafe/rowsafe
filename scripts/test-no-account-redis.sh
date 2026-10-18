#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test Redis and Valkey on a server on its own (the installer's
# --no-account), for real, in Docker: the official redis / valkey image,
# the agent next to it in the same image (so restore tests and copies run
# the server's own program) running its own control plane
# (ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock, internal/localcp), a
# MinIO bucket behind TLS, and the rowsafe CLI next to the agent, as root:
#
#   rowsafe add (saves the connection string, creates Rowsafe's own ACL
#   user, plans and turns on backups: nothing restarts), the check, the
#   first snapshot and the first Proof (rowsafe status says protected), a
#   Mark, keys deleted by mistake, another snapshot, the agent restarting
#   (the state is kept), a copy restored to the Mark next to production,
#   compare and the keys brought back (after a Mark), the copy deleted.
#
# Usage: sh scripts/test-no-account-redis.sh              # redis:7-alpine and valkey/valkey:8-alpine
#        NOACCOUNT_REDIS="valkey/valkey:8-alpine" sh scripts/test-no-account-redis.sh
# (needs Docker, ~5 min)
set -eu
cd "$(dirname "$0")/.."
images=${NOACCOUNT_REDIS:-"redis:7-alpine valkey/valkey:8-alpine"}
proj=rowsafe-noaccount-redis-$$
work=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-noaccount-redis.XXXXXX")
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
  echo "test-no-account-redis ($image): $*" >&2
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

# rs runs the rowsafe CLI next to the agent, as root (sudo rowsafe).
rs() { docker exec -u 0 -e HOME=/tmp/cli -e NO_COLOR=1 "$agent" /it/rowsafe "$@"; }
# cli runs redis-cli (or valkey-cli) on production.
cli() { docker exec "$name" "$client" "$@"; }

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

for image in $images; do
  echo "==> $image"
  case $image in
    *valkey*) engine=valkey client=valkey-cli user=valkey ;;
    *) engine=redis client=redis-cli user=redis ;;
  esac
  name=$proj-$engine
  agent=$name-agent
  docker volume create --label "$proj" "$name-state" >/dev/null
  docker run -d --label "$proj" --network "$net" --name "$name" "$image" >/dev/null
  until_ok 60 "$engine answers" cli PING
  for i in 1 2 3 4 5; do cli SET "user:$i" "name $i" >/dev/null; done

  # The agent without an account, in the server's own image, on the
  # database container's network (the server on 127.0.0.1, as on a
  # server): its own control plane on its socket.
  docker run --rm --label "$proj" -v "$name-state:/var/lib/rowsafe" --entrypoint chown "$image" "$user:$user" /var/lib/rowsafe
  docker run -d --label "$proj" --network "container:$name" --name "$agent" --user "$user" \
    -v "$name-state:/var/lib/rowsafe" -v "$work/rowsafe-agent:/opt/rowsafe/rowsafe-agent:ro" \
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

  # rowsafe add saves the database and, on its own server, creates
  # Rowsafe's user and protects it.
  url="$engine://localhost:6379"
  rs add cache "$url" --yes >"$work/add.out" 2>&1 || { cat "$work/add.out"; fail "rowsafe add"; }
  cat "$work/add.out"
  grep -q "Saved cache" "$work/add.out" || fail "rowsafe add didn't save cache"
  grep -q "user, rowsafe, is ready" "$work/add.out" || fail "Rowsafe's user wasn't created"
  docker exec "$agent" test -s "/var/lib/rowsafe/engines/$engine/logins/6379.json" || fail "the login isn't the agent's"
  rs add cache "$url" --yes 2>&1 | grep -q "protected on this server" || fail "rowsafe add twice"
  rs show cache --json >"$work/show.json" 2>&1 || true
  grep -q "\"engine\": *\"$engine\"" "$work/show.json" || { cat "$work/show.json"; fail "cache isn't a $engine database"; }

  until_ok 240 "the database is active (its changes reach the bucket)" sh -c "docker exec -u 0 -e HOME=/tmp/cli $agent /it/rowsafe ls | grep cache | grep -q active"
  until_ok 600 "rowsafe status cache: protected (first snapshot and Proof)" rs status cache
  rs backups cache
  rs proofs cache

  # A Mark, then keys deleted by mistake, then another snapshot.
  rs mark cache before-drop --json >"$work/mark.json" 2>&1 || { cat "$work/mark.json"; fail "rowsafe mark"; }
  grep -q '"before-drop"' "$work/mark.json" || { cat "$work/mark.json"; fail "the Mark"; }
  cli DEL user:3 user:4 user:5 >/dev/null || fail "deleting keys"
  [ "$(cli DBSIZE)" = 2 ] || fail "the keys weren't deleted"
  rs backup cache || fail "rowsafe backup"

  # The agent restarts: its control plane keeps everything.
  docker restart "$agent" >/dev/null
  until_ok 60 "the control plane is back" docker exec "$agent" test -S /var/lib/rowsafe/control.sock
  until_ok 60 "still active after the agent restarted" sh -c "docker exec -u 0 -e HOME=/tmp/cli $agent /it/rowsafe ls | grep cache | grep -q active"
  rs marks cache | grep -q before-drop || fail "the Mark is gone after a restart"

  # Rewind: a copy as it was at the Mark, next to production; compare;
  # bring the keys back.
  until_ok 300 "rowsafe restore cache --to before-drop (the copy is ready)" rs restore cache --to before-drop
  [ "$(cli DBSIZE)" = 2 ] || fail "restoring a copy changed production"
  rs rewind compare cache '0:user:*' | tee "$work/compare.out" || fail "rowsafe rewind compare"
  rs rewind rows cache '0:user:*' --yes || fail "rowsafe rewind rows"
  [ "$(cli DBSIZE)" = 5 ] || fail "the keys didn't come back"
  [ "$(cli GET user:4)" = "name 4" ] || fail "user:4 isn't as it was"
  rs marks cache | grep -q before-rewind-rows || fail "no Mark before bringing keys back"
  echo "  ok: the deleted keys are back from the copy at the Mark, after a Mark"
  rs rewind drop cache --yes || fail "rowsafe rewind drop"
  until_ok 120 "the copy is gone" sh -c "! docker exec -u 0 -e HOME=/tmp/cli $agent /it/rowsafe restores cache | grep -q ready"
  rs status cache || fail "not protected at the end"
  echo "test-no-account-redis: passed on $image"
  docker rm -f "$agent" "$name" >/dev/null
done
