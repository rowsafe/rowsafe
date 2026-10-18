#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Integration test of the MySQL and MariaDB engine against real servers in
# Docker: the official mysql / mariadb image, the agent's sidecar image
# (the same server version plus the backup tools) running the engine's
# tests, and a MinIO bucket behind TLS.
#
#   sh scripts/test-mysql.sh                 # mysql 8.4 and mariadb 11.4
#   MYSQL_IT="mysql:8.4 mariadb:10.6" sh scripts/test-mysql.sh
#   MYSQL_IT_RUN=Standby sh scripts/test-mysql.sh   # standby servers (a second, empty server)
#   MYSQL_IT_RUN=Standby MYSQL_IT_GTID=1 sh scripts/test-mysql.sh      # ... following by GTID (MySQL: gtid_mode ON;
#                                                     MariaDB: log_slave_updates on), there and back
#   MYSQL_IT_RUN=Standby MYSQL_IT_GTID=mixed sh scripts/test-mysql.sh  # ... the primary set up for GTIDs, the
#                                                     empty server not (MySQL: Rowsafe switches its gtid_mode)
#   (the standby runs: GTID 1 serves self-signed certificates from Rowsafe's files, mixed
#    a CA's chain for a name, reached by address; MYSQL_IT_TLS=self|ca|none picks)
#   MYSQL_IT_RUN=Clone sh scripts/test-mysql.sh     # clones into a second, empty server
#   MYSQL_IT_RUN=MoveIn sh scripts/test-mysql.sh    # move in from the first server into the second
#   MYSQL_IT_RUN=Certificate sh scripts/test-mysql.sh  # the agent installs a CA's certificate for a name
#                                                     on a server serving the installer's self-signed one
set -eu
# The MinIO test image (built once from source: scripts/minio).
MINIO_SH=$(cd "$(dirname "$0")" && pwd)/minio/image.sh
cd "$(dirname "$0")/.."
targets=${MYSQL_IT:-"mysql:8.4 mariadb:11.4"}
run=${MYSQL_IT_RUN:-Integration}
gtid=${MYSQL_IT_GTID:-}
case ${MYSQL_IT_TLS:-$gtid} in
  self | 1) tls=self ;;
  ca | mixed) tls=ca ;;
  *) tls='' ;;
esac
[ "$run" != Certificate ] || tls=self # the installer's certificate; the test CA signs the new one
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
  -v "$work/certs:/root/.minio/certs:ro" "$(sh "$MINIO_SH")" server /data >/dev/null
for _ in $(seq 1 30); do
  docker run --rm --label "$proj" --network "$net" --entrypoint sh "$(sh "$MINIO_SH")" -c \
    'mc --insecure alias set m https://minio:9000 rowsafe rowsafe-secret-key >/dev/null && mc --insecure mb -p m/backups >/dev/null' \
    >/dev/null 2>&1 && break
  sleep 1
done

# Certificates as Rowsafe's servers serve them (P-256 keys in
# /etc/mysql/rowsafe-tls): self-signed (as the installer makes), or a CA's
# chain for a name (as a Rowsafe Cloud name's), one per server.
server_tls() { # dir name: the server's own name (with the pair's)
  mkdir -p "$1"
  if [ "$tls" = self ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=rowsafe \
      -keyout "$1/rowsafe-server.key" -out "$1/rowsafe-server.crt" >/dev/null 2>&1
  else
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=db.cloud.example \
      -keyout "$1/rowsafe-server.key" -out "$1/leaf.csr" >/dev/null 2>&1
    printf 'subjectAltName=DNS:db.cloud.example,DNS:%s\n' "$2" >"$1/ext"
    openssl x509 -req -in "$1/leaf.csr" -CA "$work/tlsca/inter.crt" -CAkey "$work/tlsca/inter.key" -CAcreateserial -days 2 \
      -extfile "$1/ext" -out "$1/leaf.crt" >/dev/null 2>&1
    cat "$1/leaf.crt" "$work/tlsca/inter.crt" >"$1/rowsafe-server.crt"
  fi
  chmod 0755 "$1"
  chmod 0644 "$1"/*
}
if [ "$tls" = ca ] || [ "$run" = Certificate ]; then
  mkdir -p "$work/tlsca"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=Test Root" \
    -addext basicConstraints=critical,CA:TRUE -keyout "$work/tlsca/root.key" -out "$work/tlsca/root.crt" >/dev/null 2>&1
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=Test Intermediate" \
    -keyout "$work/tlsca/inter.key" -out "$work/tlsca/inter.csr" >/dev/null 2>&1
  printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n' >"$work/tlsca/ext"
  openssl x509 -req -in "$work/tlsca/inter.csr" -CA "$work/tlsca/root.crt" -CAkey "$work/tlsca/root.key" -CAcreateserial -days 2 \
    -extfile "$work/tlsca/ext" -out "$work/tlsca/inter.crt" >/dev/null 2>&1
  chmod 0644 "$work/tlsca/root.crt" "$work/tlsca/inter.crt" "$work/tlsca/inter.key"
fi

status=0
for target in $targets; do
  image=${target%%:*}
  version=${target#*:}
  echo "==> $image $version"
  if [ "$image" = mysql ]; then
    docker build -q -f deploy/docker/agent-mysql.Dockerfile --build-arg MYSQL_VERSION="$version" -t "rowsafe-agent:mysql$version" . >/dev/null
    agent_image=rowsafe-agent:mysql$version
    server_args="--server-id=1"
    gtid_args="--gtid-mode=ON --enforce-gtid-consistency=ON"
    envpw=MYSQL_ROOT_PASSWORD
    sockdir=/var/run/mysqld
  else
    docker build -q -f deploy/docker/agent-mariadb.Dockerfile --build-arg MARIADB_VERSION="$version" -t "rowsafe-agent:mariadb$version" . >/dev/null
    agent_image=rowsafe-agent:mariadb$version
    server_args="--log-bin=mysql-bin --binlog-format=ROW --server-id=1"
    gtid_args="--log-slave-updates=ON"
    envpw=MARIADB_ROOT_PASSWORD
    sockdir=/run/mysqld # /var/run is not /run in the Ubuntu 22.04 based images (10.6, 10.11)
  fi
  name=$proj-$image
  data=$name-data
  sock=$name-sock
  docker volume create --label "$proj" "$data" >/dev/null
  docker volume create --label "$proj" "$sock" >/dev/null
  printf 'root-secret-%s' "$$" >"$work/rootpw"
  chmod 0644 "$work/rootpw"
  primary_args=$server_args sb_args=$server_args
  case $gtid in
    '') ;;
    mixed) primary_args="$server_args $gtid_args" ;;
    *) primary_args="$server_args $gtid_args" sb_args="$server_args $gtid_args" ;;
  esac
  tls_a='' tls_b='' tls_it=''
  if [ "$run" = Standby ] && [ -n "$tls" ]; then
    server_tls "$work/tls-$image-a" "$name"
    server_tls "$work/tls-$image-b" "$name-sb"
    certargs="--ssl-cert=/etc/mysql/rowsafe-tls/rowsafe-server.crt --ssl-key=/etc/mysql/rowsafe-tls/rowsafe-server.key"
    primary_args="$primary_args $certargs" sb_args="$sb_args $certargs"
    tls_a="-v $work/tls-$image-a:/etc/mysql/rowsafe-tls:ro" tls_b="-v $work/tls-$image-b:/etc/mysql/rowsafe-tls:ro"
    if [ "$tls" = ca ]; then
      tls_it="-v $work/tlsca/root.crt:/it/tlsroot.crt:ro -e SSL_CERT_FILE=/it/tlsroot.crt"
      if [ "$image" = mariadb ]; then
        # The servers trust the root too, as hosts trust Let's Encrypt's:
        # MASTER_SSL_VERIFY_SERVER_CERT then checks the name, which an
        # address never passes.
        docker run --rm --entrypoint cat "$image:$version" /etc/ssl/certs/ca-certificates.crt >"$work/bundle-$image.crt"
        cat "$work/tlsca/root.crt" >>"$work/bundle-$image.crt"
        chmod 0644 "$work/bundle-$image.crt"
        tls_a="$tls_a -v $work/bundle-$image.crt:/etc/ssl/certs/ca-certificates.crt:ro"
        tls_b="$tls_b -v $work/bundle-$image.crt:/etc/ssl/certs/ca-certificates.crt:ro"
      fi
    fi
  fi
  if [ "$run" = Certificate ]; then
    # The server serves the installer's files, which the agent (the test,
    # as the same mysql user) replaces in place.
    server_tls "$work/tls-$image-a" "$name"
    chmod 0777 "$work/tls-$image-a"
    primary_args="$primary_args --ssl-cert=/etc/mysql/rowsafe-tls/rowsafe-server.crt --ssl-key=/etc/mysql/rowsafe-tls/rowsafe-server.key"
    tls_a="-v $work/tls-$image-a:/etc/mysql/rowsafe-tls"
    tls_it="$tls_a -v $work/tlsca:/it/tlsca:ro -e ROWSAFE_MYSQL_IT_TLSCA=/it/tlsca -e SSL_CERT_FILE=/it/tlsca/root.crt"
  fi
  docker volume create --label "$proj" "$name-ca" >/dev/null
  docker run --rm --label "$proj" -v "$name-ca:/c" --entrypoint chmod "$image:$version" 0777 /c
  # shellcheck disable=SC2086
  docker run -d --label "$proj" --network "$net" --name "$name" -e "$envpw=root-secret-$$" $tls_a -v "$name-ca:/it-ca:ro" \
    -v "$data:/var/lib/mysql" -v "$sock:$sockdir" "$image:$version" $primary_args >/dev/null
  sbargs=''
  if [ "$run" = Standby ] || [ "$run" = Clone ] || [ "$run" = MoveIn ]; then
    # The standby: an empty server of the same version, same server_id
    # (Rowsafe changes it).
    # Its data in a folder of its own name: the test reads both servers'
    # binary logs (as each one's agent does on its own server).
    docker volume create --label "$proj" "$sock-sb" >/dev/null
    docker volume create --label "$proj" "$data-sb" >/dev/null
    # shellcheck disable=SC2086
    docker run -d --label "$proj" --network "$net" --name "$name-sb" -e "$envpw=root-secret-$$" $tls_b -v "$name-ca:/it-ca:ro" \
      -v "$sock-sb:$sockdir" -v "$data-sb:/var/lib/mysql-sb" "$image:$version" $sb_args --datadir=/var/lib/mysql-sb >/dev/null
    sbargs="-e ROWSAFE_MYSQL_IT_TLS=$tls -e ROWSAFE_MYSQL_IT_CA_DIR=/it-ca -v $name-ca:/it-ca $tls_it -e ROWSAFE_MYSQL_IT_GTID=$gtid -v $data-sb:/var/lib/mysql-sb:ro -v $sock-sb:/sbsock -e ROWSAFE_MYSQL_IT_STANDBY_SOCKET=/sbsock/mysqld.sock -e ROWSAFE_MYSQL_IT_PRIMARY_HOST=$name -e ROWSAFE_MYSQL_IT_STANDBY_HOST=$name-sb"
  fi
  for n in "$name" ${sbargs:+"$name-sb"}; do
    for _ in $(seq 1 90); do
      docker logs "$n" 2>&1 | grep -q "port: 3306" && break
      sleep 2
    done
  done
  sleep 3
  itargs=$sbargs itnet=$net
  # The agent checks the served certificate on 127.0.0.1: the server's network.
  [ "$run" != Certificate ] || itargs=$tls_it itnet=container:$name
  # shellcheck disable=SC2086
  if ! docker run --rm --label "$proj" --network "$itnet" $itargs \
    -v "$data:/var/lib/mysql:ro" -v "$sock:$sockdir" \
    -v "$work/mysql.test:/it/mysql.test:ro" -v "$work/rootpw:/it/rootpw:ro" -v "$work/certs/public.crt:/it/ca.crt:ro" \
    -e ROWSAFE_MYSQL_IT="$image" -e ROWSAFE_MYSQL_IT_SOCKET=$sockdir/mysqld.sock \
    -e ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE=/it/rootpw \
    -e ROWSAFE_REPO_S3_ENDPOINT=minio -e ROWSAFE_REPO_S3_PORT=9000 -e ROWSAFE_REPO_S3_BUCKET=backups \
    -e ROWSAFE_REPO_S3_KEY=rowsafe -e ROWSAFE_REPO_S3_KEY_SECRET=rowsafe-secret-key \
    -e ROWSAFE_REPO_CIPHER_PASS=it-passphrase-0123456789abcdef -e ROWSAFE_REPO_S3_CA_FILE=/it/ca.crt \
    --entrypoint /it/mysql.test "$agent_image" -test.run "Test$run" -test.v -test.timeout 30m; then
    status=1
    echo "--- server log ($image $version)"
    docker logs "$name" 2>&1 | tail -40
  fi
  docker rm -f "$name" >/dev/null
  [ -z "$sbargs" ] || docker rm -f "$name-sb" >/dev/null
done
exit $status
