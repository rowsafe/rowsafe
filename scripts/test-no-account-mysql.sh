#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test MySQL and MariaDB on a server on its own (the installer's
# --no-account), for real, in Docker: the official mysql / mariadb image,
# the agent's sidecar image (the same server version plus the backup tools)
# running its own control plane (ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock,
# internal/localcp), a MinIO bucket behind TLS, and the rowsafe CLI next to
# the agent:
#
#   rowsafe add (saves the connection string, plans and turns on backups;
#   the agent creates its own MySQL account), the check, the first full
#   backup and the first Proof (rowsafe status says protected), a Mark,
#   rows deleted by mistake, another backup, the agent restarting (the
#   state is kept), a copy restored to the Mark next to production, compare
#   and the rows brought back (after a Mark), the copy deleted.
#
# Usage: sh scripts/test-no-account-mysql.sh                 # mysql:8.4 and mariadb:11.4
#        NOACCOUNT_MYSQL="mariadb:11.4" sh scripts/test-no-account-mysql.sh
# (needs Docker, ~10 min)
set -eu
cd "$(dirname "$0")/.."
targets=${NOACCOUNT_MYSQL:-"mysql:8.4 mariadb:11.4"}
proj=rowsafe-noaccount-mysql-$$
work=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-noaccount-mysql.XXXXXX")
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
  echo "test-no-account-mysql ($target): $*" >&2
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

# rs runs the rowsafe CLI next to the agent (as its user, mysql: the
# control plane's socket is theirs).
rs() { docker exec -e HOME=/tmp/cli -e NO_COLOR=1 "$agent" /it/rowsafe "$@"; }
# q runs SQL in shop on production, as root.
q() { docker exec -e MYSQL_PWD="$rootpw" "$name" "$client" -uroot -N -B shop -e "$1"; }

echo "==> rowsafe (linux/$arch)"
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$work/rowsafe" ./cmd/rowsafe
chmod 0755 "$work/rowsafe"

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

rootpw=root-$(openssl rand -hex 8)
printf '%s' "$rootpw" >"$work/rootpw"
chmod 0644 "$work/rootpw"

for target in $targets; do
  image=${target%%:*}
  version=${target#*:}
  echo "==> $image $version"
  if [ "$image" = mysql ]; then
    docker build -q -f deploy/docker/agent-mysql.Dockerfile --build-arg MYSQL_VERSION="$version" -t "rowsafe-agent:mysql$version" . >/dev/null
    server_args="--server-id=1"
    envpre=MYSQL client=mysql sockdir=/var/run/mysqld
  else
    docker build -q -f deploy/docker/agent-mariadb.Dockerfile --build-arg MARIADB_VERSION="$version" -t "rowsafe-agent:mariadb$version" . >/dev/null
    server_args="--log-bin=mysql-bin --binlog-format=ROW --server-id=1"
    envpre=MARIADB client=mariadb sockdir=/run/mysqld
  fi
  name=$proj-$image
  agent=$name-agent
  for v in data sock state; do docker volume create --label "$proj" "$name-$v" >/dev/null; done
  # shellcheck disable=SC2086
  docker run -d --label "$proj" --network "$net" --name "$name" -e "${envpre}_ROOT_PASSWORD=$rootpw" -e "${envpre}_DATABASE=shop" \
    -v "$name-data:/var/lib/mysql" -v "$name-sock:$sockdir" "$image:$version" $server_args >/dev/null
  for _ in $(seq 1 90); do
    docker logs "$name" 2>&1 | grep -q "port: 3306" && break
    sleep 2
  done
  until_ok 120 "$image accepts connections" q "SELECT 1"
  q "CREATE TABLE orders (id int PRIMARY KEY, note text); INSERT INTO orders VALUES (1,'order 1'),(2,'order 2'),(3,'order 3'),(4,'order 4'),(5,'order 5')" ||
    fail "the orders table"

  # The agent without an account: its own control plane on its socket.
  docker run -d --label "$proj" --network "$net" --name "$agent" --hostname db-1 \
    -v "$name-data:/var/lib/mysql:ro" -v "$name-sock:$sockdir" -v "$name-state:/var/lib/rowsafe" \
    -v "$work/rowsafe:/it/rowsafe:ro" -v "$work/rootpw:/it/rootpw:ro" -v "$work/certs/public.crt:/it/ca.crt:ro" \
    -e ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock -e ROWSAFE_HEARTBEAT_INTERVAL=5s -e ROWSAFE_POLL_INTERVAL=2s \
    -e ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE=/it/rootpw \
    -e ROWSAFE_REPO_S3_ENDPOINT=minio -e ROWSAFE_REPO_S3_PORT=9000 -e ROWSAFE_REPO_S3_REGION=us-east-1 \
    -e ROWSAFE_REPO_S3_BUCKET=backups -e ROWSAFE_REPO_S3_KEY=rowsafe -e ROWSAFE_REPO_S3_KEY_SECRET="$secret" \
    -e ROWSAFE_REPO_CIPHER_PASS="cipher-$secret" -e ROWSAFE_REPO_S3_CA_FILE=/it/ca.crt \
    "rowsafe-agent:$image$version" >/dev/null
  until_ok 60 "the agent's control plane listens" docker exec "$agent" test -S /var/lib/rowsafe/control.sock
  docker exec "$agent" mkdir -p /tmp/cli

  # rowsafe add saves the database and, on its own server, protects it.
  url="mysql://root:$rootpw@localhost/shop?socket=$sockdir/mysqld.sock"
  rs add shop "$url" --yes >"$work/add.out" 2>&1 || { cat "$work/add.out"; fail "rowsafe add"; }
  cat "$work/add.out"
  grep -q "Saved shop" "$work/add.out" || fail "rowsafe add didn't save shop"
  rs ls >"$work/ls.out" 2>&1 || true
  grep -q "shop" "$work/ls.out" || { cat "$work/ls.out"; fail "rowsafe ls doesn't show shop"; }
  rs add shop "$url" --yes 2>&1 | grep -q "protected on this server" || fail "rowsafe add twice"
  rs show shop --json >"$work/show.json" 2>&1 || true
  grep -q "\"engine\": *\"$image\"" "$work/show.json" || { cat "$work/show.json"; fail "shop isn't a $image database"; }

  until_ok 240 "the database is active (the binary log reaches the bucket)" sh -c "docker exec -e HOME=/tmp/cli $agent /it/rowsafe ls | grep shop | grep -q active"
  until_ok 600 "rowsafe status shop: protected (first full backup and Proof)" rs status shop
  rs backups shop
  rs proofs shop

  # A Mark, then rows deleted by mistake, then another backup.
  rs mark shop before-drop --json >"$work/mark.json" 2>&1 || { cat "$work/mark.json"; fail "rowsafe mark"; }
  grep -q '"before-drop"' "$work/mark.json" || { cat "$work/mark.json"; fail "the Mark"; }
  q "DELETE FROM orders WHERE id > 2" || fail "deleting rows"
  [ "$(q 'SELECT count(*) FROM orders')" = 2 ] || fail "the rows weren't deleted"
  rs marks shop | grep -q before-drop || fail "rowsafe marks"
  rs backup shop --type diff || fail "rowsafe backup"
  rs backups shop >"$work/backups.out"
  cat "$work/backups.out"
  [ "$(grep -c '^ *[0-9]\{8\}' "$work/backups.out" || true)" -ge 2 ] || grep -qi "incr\|diff" "$work/backups.out" || fail "no second backup listed"

  # The agent restarts: its control plane keeps everything.
  docker restart "$agent" >/dev/null
  until_ok 60 "the control plane is back" docker exec "$agent" test -S /var/lib/rowsafe/control.sock
  until_ok 60 "still active after the agent restarted" sh -c "docker exec -e HOME=/tmp/cli $agent /it/rowsafe ls | grep shop | grep -q active"
  rs marks shop | grep -q before-drop || fail "the Mark is gone after a restart"

  # Rewind: a copy as it was at the Mark, next to production; compare;
  # bring the rows back.
  until_ok 180 "rowsafe restore shop --to before-drop (the copy is ready)" rs restore shop --to before-drop
  rs restores shop | grep -q ready || fail "rowsafe restores doesn't show the copy ready"
  [ "$(q 'SELECT count(*) FROM orders')" = 2 ] || fail "restoring a copy changed production"
  rs rewind compare shop shop:orders | tee "$work/compare.out" || fail "rowsafe rewind compare"
  grep -q "orders" "$work/compare.out" || fail "the comparison doesn't list orders"
  ! rs rewind rows shop shop:orders </dev/null >"$work/rows.out" 2>&1 || fail "rows came back without a confirmation"
  rs rewind rows shop shop:orders --yes || fail "rowsafe rewind rows"
  [ "$(q 'SELECT count(*) FROM orders')" = 5 ] || fail "the rows didn't come back"
  rs marks shop | grep -q before-rewind-rows || fail "no Mark before bringing rows back"
  echo "  ok: the deleted rows are back from the copy at the Mark, after a Mark"
  rs rewind drop shop --yes || fail "rowsafe rewind drop"
  until_ok 120 "the copy is gone" sh -c "! docker exec -e HOME=/tmp/cli $agent /it/rowsafe restores shop | grep -q ready"
  rs status shop || fail "not protected at the end"
  echo "test-no-account-mysql: passed on $image $version"
  docker rm -f "$agent" "$name" >/dev/null
done
