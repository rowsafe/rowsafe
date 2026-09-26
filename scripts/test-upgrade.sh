#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test PostgreSQL updates and upgrades for real: a Debian server with
# systemd as PID 1, PostgreSQL 16 from apt.postgresql.org (one minor release
# behind, from its archive) with pg_cron, pgBackRest and a MinIO
# repository, with the root helper (scripts/rowsafe-pg-restart and its
# restart and update units) installed from this repository. The agent's own
# code runs every step (internal/agent/upgrade_e2e_test.go, built with -tags
# upgrade_e2e) as the postgres user; every package change goes through the
# helper:
#
#   adopt, backup; the software report (installed, newest minor, newer
#   majors); a minor update (apt, restart, archiving checked); the upgrade
#   preflight; a rehearsal to 18 on a restored copy (installs 18 and its
#   pg_cron, drops the cluster the package creates); a Safe upgrade (data
#   intact, backups on 18), its undo (16 back, backups on 16 again),
#   removing the kept 18; a Fast upgrade and its undo, restoring 16 from the
#   backup at the Mark; a restore test; security updates.
#
# Usage: sh scripts/test-upgrade.sh [debian:trixie]   (needs Docker and the
# network for apt.postgresql.org; ~10 min)

set -eu

in_container() {
  export DEBIAN_FRONTEND=noninteractive
  W=/w
  install -d -m 0755 /usr/local/lib/rowsafe /etc/rowsafe
  install -m 0755 /src/scripts/rowsafe-pg-restart /usr/local/lib/rowsafe/rowsafe-pg-restart
  install -m 0644 /src/deploy/systemd/rowsafe-pg-restart.service /src/deploy/systemd/rowsafe-pg-restart.path \
    /src/deploy/systemd/rowsafe-pg-update.service /src/deploy/systemd/rowsafe-pg-update.path /etc/systemd/system/
  printf '# test\n5432 postgresql@16-main.service\n' >/etc/rowsafe/restart-allowed
  printf '# test\npostgresql\nsecurity\n' >/etc/rowsafe/updates-allowed
  chmod 0644 /etc/rowsafe/restart-allowed /etc/rowsafe/updates-allowed
  install -d -m 0700 -o postgres -g postgres /var/lib/rowsafe /var/lib/rowsafe/restart /etc/rowsafe/pgbackrest /var/log/rowsafe
  # The image kept postgresql-common from creating clusters; a real server
  # creates "main" for every newly installed major, which the helper must
  # handle.
  sed -i '/^create_main_cluster = false$/d' /etc/postgresql-common/createcluster.conf
  pg_createcluster 16 main >/dev/null
  printf "shared_preload_libraries = 'pg_cron'\ncron.database_name = 'shop'\n" >/etc/postgresql/16/main/conf.d/cron.conf
  systemctl daemon-reload
  systemctl enable --now --quiet rowsafe-pg-restart.path rowsafe-pg-update.path
  systemctl start postgresql@16-main.service
  systemctl is-active --quiet postgresql@16-main.service || {
    systemctl status postgresql@16-main.service --no-pager >&2
    exit 1
  }
  echo "PostgreSQL $(dpkg-query -W -f='${Version}' postgresql-16) is running; the helper watches /var/lib/rowsafe/restart"

  status=0
  runuser -u postgres -- env \
    ROWSAFE_AUTO_UPDATE=false \
    ROWSAFE_REPO_S3_ENDPOINT=minio ROWSAFE_REPO_S3_PORT=9000 ROWSAFE_REPO_S3_REGION=us-east-1 \
    ROWSAFE_REPO_S3_BUCKET=rowsafe ROWSAFE_REPO_S3_KEY=rowsafe-test ROWSAFE_REPO_S3_KEY_SECRET="$S3_SECRET" \
    ROWSAFE_REPO_CIPHER_PASS="$CIPHER_PASS" ROWSAFE_REPO_S3_CA_FILE=$W/certs/ca.crt \
    ROWSAFE_RESTORE_POINT_TIMEOUT=2m UPGRADE_TO="${UPGRADE_TO:-18}" \
    "$W/upgrade-e2e.test" -test.run '^TestRealUpgrade$' -test.v -test.timeout 45m || status=$?
  if [ "$status" != 0 ]; then
    echo "---- journal (helper and PostgreSQL)" >&2
    journalctl -u rowsafe-pg-restart.service -u rowsafe-pg-update.service -u 'postgresql@*' --no-pager -n 120 >&2 || true
    tail -n 60 /var/lib/rowsafe-pg-restart/update.log >&2 2>/dev/null || true
    tail -n 40 /var/log/postgresql/*.log >&2 2>/dev/null || true
    pg_lsclusters >&2 || true
  fi
  exit "$status"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-upgrade: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-upgrade.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-upgrade-$$
  cleanup() {
    [ "${KEEP:-0}" = 1 ] && return
    docker rm -f "$name-pg" "$name-minio" >/dev/null 2>&1 || true
    docker volume rm "$name-pgdata" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
    rm -rf "$W"
  }
  trap cleanup EXIT INT TERM

  echo "building the test (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go test -c -tags upgrade_e2e -o "$W/upgrade-e2e.test" ./internal/agent)

  mkdir -p "$W/certs" "$W/minio-certs"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=rowsafe test CA" \
    -keyout "$W/certs/ca.key" -out "$W/certs/ca.crt" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=minio" -keyout "$W/minio-certs/private.key" -out "$W/minio.csr" 2>/dev/null
  printf 'subjectAltName=DNS:minio\n' >"$W/san.ext"
  openssl x509 -req -in "$W/minio.csr" -CA "$W/certs/ca.crt" -CAkey "$W/certs/ca.key" -CAcreateserial -days 2 \
    -extfile "$W/san.ext" -out "$W/minio-certs/public.crt" 2>/dev/null
  chmod 0644 "$W/minio-certs/private.key" "$W/certs/ca.crt"
  secret=$(openssl rand -hex 16)
  cipher=$(openssl rand -hex 24)

  docker network create "$name" >/dev/null
  docker run -d --name "$name-minio" --network "$name" --network-alias minio \
    -e MINIO_ROOT_USER=rowsafe-test -e MINIO_ROOT_PASSWORD="$secret" \
    -v "$W/minio-certs:/certs:ro" minio/minio server /data --address :9000 --certs-dir /certs >/dev/null
  i=0
  until docker run --rm --network "$name" --entrypoint sh minio/mc -c \
    "mc alias set m https://minio:9000 rowsafe-test $secret --insecure >/dev/null && mc mb --insecure --ignore-existing m/rowsafe >/dev/null" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || {
      docker logs "$name-minio" >&2
      echo "test-upgrade: MinIO did not come up" >&2
      exit 1
    }
    sleep 1
  done

  # PostgreSQL 16 one minor release behind the newest, from the PGDG
  # archive; then only the regular repository, so the newest is an update.
  tag=rowsafe-test/upgrade:$(echo "$image" | tr ':/' '--')
  echo "building $tag"
  docker build -q -t "$tag" - >/dev/null <<EOF
FROM $image
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus ca-certificates procps util-linux curl >/dev/null && \\
    rm -f /lib/systemd/system/multi-user.target.wants/getty* && \\
    install -d /usr/share/postgresql-common/pgdg && \\
    curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc && \\
    . /etc/os-release && \\
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt \$VERSION_CODENAME-pgdg main" \\
      >/etc/apt/sources.list.d/pgdg.list && \\
    apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends postgresql-common libpq5 pgbackrest >/dev/null && \\
    echo 'create_main_cluster = false' >>/etc/postgresql-common/createcluster.conf && \\
    newest=\$(apt-cache policy postgresql-16 | awk '\$1 == "Candidate:" { print \$2 }') && \\
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt-archive.postgresql.org/pub/repos/apt \$VERSION_CODENAME-pgdg-archive main" \\
      >/etc/apt/sources.list.d/pgdg-archive.list && \\
    apt-get update -qq && \\
    older=\$(apt-cache madison postgresql-16 | awk -v n="\$newest" '\$3 != n { print \$3 }' | sort -uVr | head -n 1) && \\
    echo "PostgreSQL 16: installing \$older, newest \$newest" && \\
    apt-get install -y -qq --no-install-recommends postgresql-16=\$older postgresql-client-16=\$older postgresql-16-cron >/dev/null && \\
    rm /etc/apt/sources.list.d/pgdg-archive.list && apt-get update -qq && apt-get clean
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
  docker run -d --name "$name-pg" --network "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --shm-size 256m \
    -v "$name-pgdata:/var/lib/postgresql" -v "$root:/src:ro" -v "$W:/w" \
    -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" "$tag" >/dev/null
  i=0
  until docker exec "$name-pg" systemctl is-system-running --wait >/dev/null 2>&1 ||
    [ "$(docker exec "$name-pg" systemctl is-system-running 2>/dev/null)" = degraded ]; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || {
      echo "test-upgrade: systemd did not start in the container" >&2
      exit 1
    }
    sleep 1
  done
  docker exec -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" -e UPGRADE_TO="${UPGRADE_TO:-18}" "$name-pg" sh /src/scripts/test-upgrade.sh --in-container
  echo "test-upgrade: passed on $image"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
