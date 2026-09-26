#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test connection pooling for real: a Debian server with systemd as PID 1 and
# PostgreSQL (Debian's), with the root helper (scripts/rowsafe-pg-restart and
# the rowsafe-pooler units) installed from this repository and PgBouncer
# installed by the helper from apt. The agent's own code runs every step
# (internal/agent/pooling_e2e_test.go, built with -tags pooling_e2e) as the
# postgres user:
#
#   turn pooling on (the helper installs pgbouncer, writes its configuration
#   as root, starts it under systemd), log in through port 6432 with an app's
#   own password (scram-sha-256 through auth_query), a light load, PgBouncer's
#   stats, a switch to another PostgreSQL under load with no failed query,
#   a settings change (reload, no restart), and turning it off (package
#   removed, the lookup role dropped).
#
# Usage: sh scripts/test-pooling.sh [debian:trixie]   (needs Docker and network, ~3 min)

set -eu

in_container() {
  export DEBIAN_FRONTEND=noninteractive
  install -d -m 0755 /usr/local/lib/rowsafe /etc/rowsafe
  install -m 0755 /src/scripts/rowsafe-pg-restart /usr/local/lib/rowsafe/rowsafe-pg-restart
  install -m 0644 /src/deploy/systemd/rowsafe-pooler.service /src/deploy/systemd/rowsafe-pooler.path \
    /src/deploy/systemd/rowsafe-pooler-apt@.service /etc/systemd/system/
  install -d -m 0755 /etc/systemd/system/pgbouncer.service.d
  printf '# test\n5432\n5433\n' >/etc/rowsafe/pooler-allowed
  chmod 0644 /etc/rowsafe/pooler-allowed
  install -d -m 0700 -o postgres -g postgres /var/lib/rowsafe /var/lib/rowsafe/pooler
  major=$(ls /usr/lib/postgresql)
  pg_createcluster "$major" other --port 5433 >/dev/null
  systemctl daemon-reload
  systemctl enable --now --quiet rowsafe-pooler.path
  systemctl start "postgresql@$major-main.service" "postgresql@$major-other.service"
  echo "PostgreSQL $major on 5432 and 5433; the helper watches /var/lib/rowsafe/pooler"

  status=0
  runuser -u postgres -- "/w/pooling-e2e.test" -test.run '^TestRealPooling$' -test.v -test.timeout 20m || status=$?
  if [ "$status" != 0 ]; then
    echo "---- journal (helper and PgBouncer)" >&2
    journalctl -u rowsafe-pooler.service -u pgbouncer.service --no-pager -n 80 >&2 || true
    cat /var/lib/rowsafe-pooler/apt.log >&2 2>/dev/null || true
  fi
  # The helper never left files of root's in the agent's directory.
  if [ -n "$(find /var/lib/rowsafe/pooler -user root)" ]; then
    echo "root left files in /var/lib/rowsafe/pooler" >&2
    status=1
  fi
  exit "$status"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-pooling: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-pooling.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-pooling-$$
  cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$W"
  }
  trap cleanup EXIT INT TERM

  echo "building the test (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go test -c -tags pooling_e2e -o "$W/pooling-e2e.test" ./internal/agent)
  chmod 0755 "$W/pooling-e2e.test"

  tag=rowsafe-test/pooling:$(echo "$image" | tr ':/' '--')
  echo "building $tag"
  docker build -q -t "$tag" - >/dev/null <<EOF
FROM $image
ENV container=docker
RUN apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus ca-certificates procps util-linux postgresql >/dev/null && \\
    rm -f /lib/systemd/system/multi-user.target.wants/getty* && apt-get clean && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
  docker run -d --name "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --shm-size 256m \
    -v "$root:/src:ro" -v "$W:/w" "$tag" >/dev/null
  i=0
  until docker exec "$name" systemctl is-system-running --wait >/dev/null 2>&1 ||
    [ "$(docker exec "$name" systemctl is-system-running 2>/dev/null)" = degraded ]; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || {
      echo "test-pooling: systemd did not start in the container" >&2
      exit 1
    }
    sleep 1
  done
  docker exec "$name" sh /src/scripts/test-pooling.sh --in-container
  echo "test-pooling: passed on $image"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
