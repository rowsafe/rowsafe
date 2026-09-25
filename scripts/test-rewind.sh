#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test Rewind for real: a Debian server with systemd as PID 1, PostgreSQL
# (Debian's), pgBackRest and a MinIO repository, with the root helper
# (scripts/rowsafe-pg-restart and its units) installed from this repository.
# The agent's own code runs every step (internal/agent/rewind_e2e_test.go,
# built with -tags rewind_e2e) as the postgres user:
#
#   adopt, restart through the helper, check, a full backup; rows written
#   before and after a point in time, then a mistake (rows deleted); a copy
#   restored at that point (isolated, socket only, no archiving), compare,
#   bring the deleted rows back; a rewind in place to before the backup
#   (fails, rolled back automatically); a rewind in place to the point (the
#   later rows are gone, a new timeline archives to the repository); undo
#   (they are back); cleanup; drop the copy. Then Find the moment
#   (rewind_moment_e2e_test.go): deletes, updates, a TRUNCATE and a DROP,
#   found in the repository's WAL with their transaction IDs.
#
# Usage: sh scripts/test-rewind.sh [debian:trixie]   (needs Docker, ~3 min; the image
# needs pgBackRest 2.46 or newer, as Rowsafe installs)

set -eu

in_container() {
  export DEBIAN_FRONTEND=noninteractive
  W=/w
  # The root helper and its units, exactly as in the repository.
  install -d -m 0755 /usr/local/lib/rowsafe /etc/rowsafe
  install -m 0755 /src/scripts/rowsafe-pg-restart /usr/local/lib/rowsafe/rowsafe-pg-restart
  install -m 0644 /src/deploy/systemd/rowsafe-pg-restart.service /src/deploy/systemd/rowsafe-pg-restart.path /etc/systemd/system/
  major=$(ls /usr/lib/postgresql)
  unit=postgresql@$major-main.service
  printf '# test\n5432 %s\n' "$unit" >/etc/rowsafe/restart-allowed
  chmod 0644 /etc/rowsafe/restart-allowed
  install -d -m 0700 -o postgres -g postgres /var/lib/rowsafe /var/lib/rowsafe/restart /etc/rowsafe/pgbackrest /var/log/rowsafe
  systemctl daemon-reload
  systemctl enable --now --quiet rowsafe-pg-restart.path
  systemctl start "$unit"
  systemctl is-active --quiet "$unit" || {
    systemctl status "$unit" --no-pager >&2
    exit 1
  }
  echo "PostgreSQL $major ($unit) is running; the helper watches /var/lib/rowsafe/restart"

  status=0
  runuser -u postgres -- env \
    ROWSAFE_AUTO_UPDATE=false \
    ROWSAFE_REPO_S3_ENDPOINT=minio ROWSAFE_REPO_S3_PORT=9000 ROWSAFE_REPO_S3_REGION=us-east-1 \
    ROWSAFE_REPO_S3_BUCKET=rowsafe ROWSAFE_REPO_S3_KEY=rowsafe-test ROWSAFE_REPO_S3_KEY_SECRET="$S3_SECRET" \
    ROWSAFE_REPO_CIPHER_PASS="$CIPHER_PASS" ROWSAFE_REPO_S3_CA_FILE=$W/certs/ca.crt \
    ROWSAFE_RESTORE_POINT_TIMEOUT=2m \
    "$W/rewind-e2e.test" -test.run '^TestReal(Rewind|FindMoment)$' -test.v -test.timeout 25m || status=$?
  if [ "$status" != 0 ]; then
    echo "---- journal (helper and PostgreSQL)" >&2
    journalctl -u rowsafe-pg-restart.service -u "$unit" --no-pager -n 80 >&2 || true
    tail -n 60 /var/log/postgresql/*.log >&2 2>/dev/null || true
    tail -n 60 /var/lib/rowsafe/rewind/inplace.log >&2 2>/dev/null || true
  fi
  exit "$status"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-rewind: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-rewind.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-rewind-$$
  cleanup() {
    docker rm -f "$name-pg" "$name-minio" >/dev/null 2>&1 || true
    docker volume rm "$name-pgdata" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
    rm -rf "$W"
  }
  trap cleanup EXIT INT TERM

  echo "building the test (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go test -c -tags rewind_e2e -o "$W/rewind-e2e.test" ./internal/agent)

  # A test CA and a certificate for MinIO (pgBackRest's S3 client needs TLS).
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
      echo "test-rewind: MinIO did not come up" >&2
      exit 1
    }
    sleep 1
  done

  tag=rowsafe-test/rewind:$(echo "$image" | tr ':/' '--')
  echo "building $tag"
  docker build -q -t "$tag" - >/dev/null <<EOF
FROM $image
ENV container=docker
RUN apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus ca-certificates procps util-linux \\
      postgresql pgbackrest >/dev/null && \\
    rm -f /lib/systemd/system/multi-user.target.wants/getty* && apt-get clean && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
  # The data directory lives on a volume, as on a real server: overlayfs
  # can't rename a directory from the image (EXDEV).
  docker run -d --name "$name-pg" --network "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --shm-size 256m \
    -v "$name-pgdata:/var/lib/postgresql" -v "$root:/src:ro" -v "$W:/w" \
    -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" "$tag" >/dev/null
  i=0
  until docker exec "$name-pg" systemctl is-system-running --wait >/dev/null 2>&1 ||
    [ "$(docker exec "$name-pg" systemctl is-system-running 2>/dev/null)" = degraded ]; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || {
      echo "test-rewind: systemd did not start in the container" >&2
      exit 1
    }
    sleep 1
  done
  docker exec -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" "$name-pg" sh /src/scripts/test-rewind.sh --in-container
  echo "test-rewind: passed on $image"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
