#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test the second backup copy for real: a Debian container with PostgreSQL
# (Debian's) and pgBackRest, and two local repositories standing in for two
# storage providers. The agent's own code runs every step
# (internal/agent/secondcopy_e2e_test.go, built with -tags secondcopy_e2e)
# as the postgres user: WAL to both storages, a full backup to each, the
# second storage going away while PostgreSQL keeps archiving, catching up,
# Proof and a Rewind copy from the second copy, storage use, a gap closed by
# a full backup, and removing the second copy.
#
# Usage: sh scripts/test-secondcopy.sh [debian:trixie]   (needs Docker, ~2 min)

set -eu

in_container() {
  major=$(ls /usr/lib/postgresql)
  conf=/etc/postgresql/$major/main
  # Archiving on from the start, so adopt needs no restart.
  cat >>"$conf/postgresql.conf" <<EOF
wal_level = replica
archive_mode = on
archive_command = ''
max_wal_size = 256MB
EOF
  pg_ctlcluster "$major" main start
  install -d -m 0700 -o postgres -g postgres /w
  status=0
  runuser -u postgres -- env SC_WORK=/w /t/secondcopy-e2e.test -test.run '^TestRealSecondCopy$' -test.v -test.timeout 15m || status=$?
  if [ "$status" != 0 ]; then
    echo "---- PostgreSQL log" >&2
    tail -n 60 /var/log/postgresql/*.log >&2 2>/dev/null || true
  fi
  exit "$status"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-secondcopy: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  T=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-secondcopy.XXXXXX")
  chmod 0755 "$T"
  name=rowsafe-secondcopy-$$
  cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$T"
  }
  trap cleanup EXIT INT TERM

  echo "building the test (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go test -c -tags secondcopy_e2e -o "$T/secondcopy-e2e.test" ./internal/agent)
  chmod 0755 "$T/secondcopy-e2e.test"

  tag=rowsafe-test/secondcopy:$(echo "$image" | tr ':/' '--')
  echo "building $tag"
  docker build -q -t "$tag" - >/dev/null <<EOF
FROM $image
RUN apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends ca-certificates procps util-linux postgresql pgbackrest >/dev/null && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*
EOF
  docker run --rm --name "$name" --shm-size 256m -v "$root:/src:ro" -v "$T:/t:ro" "$tag" sh /src/scripts/test-secondcopy.sh --in-container
  echo "test-secondcopy: passed on $image"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
