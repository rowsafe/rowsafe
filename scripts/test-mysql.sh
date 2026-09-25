#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Integration test of the MySQL and MariaDB engine against real servers in
# Docker: the official mysql / mariadb image, the agent's sidecar image
# (the same server version plus the backup tools) running the engine's
# tests, and a MinIO bucket behind TLS.
#
#   sh scripts/test-mysql.sh                 # mysql 8.4 and mariadb 11.4
#   MYSQL_IT="mysql:8.4 mariadb:10.6" sh scripts/test-mysql.sh
set -eu
cd "$(dirname "$0")/.."
targets=${MYSQL_IT:-"mysql:8.4 mariadb:11.4"}
proj=rowsafe-mysql-it-$$
work=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-mysql-it.XXXXXX")
arch=$(docker version --format '{{.Server.Arch}}')
net=$proj

cleanup() {
  docker ps -aq --filter "label=$proj" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker volume ls -q --filter "label=$proj" | xargs -r docker volume rm >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

echo "==> test binary (linux/$arch)"
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go test -c -o "$work/mysql.test" ./internal/engine/mysql
chmod 0755 "$work/mysql.test"

echo "==> MinIO with TLS"
docker network create --label "$proj" "$net" >/dev/null
mkdir -p "$work/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=minio" -addext "subjectAltName=DNS:minio" \
  -keyout "$work/certs/private.key" -out "$work/certs/public.crt" >/dev/null 2>&1
chmod 0644 "$work/certs/private.key" "$work/certs/public.crt"
docker run -d --label "$proj" --network "$net" --network-alias minio --name "$proj-minio" \
  -e MINIO_ROOT_USER=rowsafe -e MINIO_ROOT_PASSWORD=rowsafe-secret-key \
  -v "$work/certs:/root/.minio/certs:ro" minio/minio:latest server /data >/dev/null
for i in $(seq 1 30); do
  docker run --rm --label "$proj" --network "$net" --entrypoint sh minio/mc:latest -c \
    'mc --insecure alias set m https://minio:9000 rowsafe rowsafe-secret-key >/dev/null && mc --insecure mb -p m/backups >/dev/null' \
    >/dev/null 2>&1 && break
  sleep 1
done

status=0
for target in $targets; do
  image=${target%%:*}
  version=${target#*:}
  echo "==> $image $version"
  if [ "$image" = mysql ]; then
    docker build -q -f deploy/docker/agent-mysql.Dockerfile --build-arg MYSQL_VERSION="$version" -t "rowsafe-agent:mysql$version" . >/dev/null
    agent_image=rowsafe-agent:mysql$version
    server_args="--server-id=1"
    envpw=MYSQL_ROOT_PASSWORD
  else
    docker build -q -f deploy/docker/agent-mariadb.Dockerfile --build-arg MARIADB_VERSION="$version" -t "rowsafe-agent:mariadb$version" . >/dev/null
    agent_image=rowsafe-agent:mariadb$version
    server_args="--log-bin=mysql-bin --binlog-format=ROW --server-id=1"
    envpw=MARIADB_ROOT_PASSWORD
  fi
  name=$proj-$image
  data=$name-data
  sock=$name-sock
  docker volume create --label "$proj" "$data" >/dev/null
  docker volume create --label "$proj" "$sock" >/dev/null
  printf 'root-secret-%s' "$$" >"$work/rootpw"
  chmod 0644 "$work/rootpw"
  # shellcheck disable=SC2086
  docker run -d --label "$proj" --network "$net" --name "$name" -e "$envpw=root-secret-$$" \
    -v "$data:/var/lib/mysql" -v "$sock:/var/run/mysqld" "$image:$version" $server_args >/dev/null
  for i in $(seq 1 90); do
    docker logs "$name" 2>&1 | grep -q "port: 3306" && break
    sleep 2
  done
  sleep 3
  if ! docker run --rm --label "$proj" --network "$net" \
    -v "$data:/var/lib/mysql:ro" -v "$sock:/var/run/mysqld" \
    -v "$work/mysql.test:/it/mysql.test:ro" -v "$work/rootpw:/it/rootpw:ro" -v "$work/certs/public.crt:/it/ca.crt:ro" \
    -e ROWSAFE_MYSQL_IT="$image" -e ROWSAFE_MYSQL_IT_SOCKET=/var/run/mysqld/mysqld.sock \
    -e ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE=/it/rootpw \
    -e ROWSAFE_REPO_S3_ENDPOINT=minio -e ROWSAFE_REPO_S3_PORT=9000 -e ROWSAFE_REPO_S3_BUCKET=backups \
    -e ROWSAFE_REPO_S3_KEY=rowsafe -e ROWSAFE_REPO_S3_KEY_SECRET=rowsafe-secret-key \
    -e ROWSAFE_REPO_CIPHER_PASS=it-passphrase-0123456789abcdef -e ROWSAFE_REPO_S3_CA_FILE=/it/ca.crt \
    --entrypoint /it/mysql.test "$agent_image" -test.run 'TestIntegration' -test.v -test.timeout 30m; then
    status=1
    echo "--- server log ($image $version)"
    docker logs "$name" 2>&1 | tail -40
  fi
  docker rm -f "$name" >/dev/null
done
exit $status
