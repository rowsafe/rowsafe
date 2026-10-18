#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test the second copy on a server on its own (the installer's --no-account),
# for real: a Debian server with systemd as PID 1, PostgreSQL, pgBackRest
# and two MinIO servers standing in for two storage providers, each with its
# own bucket and key. The agent runs as its systemd unit with its own
# control plane (internal/localcp):
#
#   sudo rowsafe add protects shop (first bucket); sudo rowsafe secondcopy add
#   tests the second bucket, writes its key and a new passphrase to
#   /etc/rowsafe/agent.env and restarts the agent, which sets it up; the
#   first full backup goes to it; rowsafe status shows it; a Mark reaches it;
#   then the FIRST BUCKET IS DELETED, and rowsafe restore --second-copy
#   restores a copy as it was at the Mark from the second bucket alone.
#   Last, sudo rowsafe secondcopy remove turns it off.
#
# Usage: sh scripts/test-no-account-secondcopy.sh [debian:trixie]   (needs Docker, ~5 min)

set -eu

fail() {
  echo "test-no-account-secondcopy: $*" >&2
  echo "---- agent journal" >&2
  journalctl -u rowsafe-agent --no-pager -n 150 >&2 || true
  exit 1
}

# until_ok SECONDS DESCRIPTION COMMAND...: retry COMMAND every 3 seconds.
until_ok() {
  _limit=$1 _what=$2
  shift 2
  _i=0
  until "$@" >/tmp/until.out 2>&1; do
    _i=$((_i + 3))
    [ "$_i" -lt "$_limit" ] || {
      cat /tmp/until.out >&2
      fail "timed out after ${_limit}s: $_what"
    }
    sleep 3
  done
  echo "  ok: $_what"
}

psql_app() { PGPASSWORD=app-pw psql -qAtX -h localhost -U app -d shop "$@"; }

# json_time KEY: the first KEY's time in JSON on stdin, to the second
# (YYYY-MM-DDTHH:MM:SS, UTC), for comparing as text.
json_time() { grep -o "\"$1\": *\"[^\"]*\"" | head -1 | sed 's/.*: *"\([0-9T:-]\{19\}\).*/\1/'; }

# The Mark's change reached the second copy: nothing waits to be sent, and
# the newest file sent left after the Mark was confirmed in the first bucket.
mark_in_second_copy() {
  archived=$(rowsafe marks shop --json | json_time archived_at)
  rowsafe secondcopy shop --json >/tmp/sc.json
  sent=$(json_time last_sent_at </tmp/sc.json)
  grep -q '"queued_files": 0' /tmp/sc.json && [ -n "$archived" ] && [ -n "$sent" ] && ! expr "$sent" \< "$archived" >/dev/null
}

phase1() {
  export DEBIAN_FRONTEND=noninteractive
  W=/w
  major=$(ls /usr/lib/postgresql)
  unit=postgresql@$major-main.service

  # What the installer puts in place (as in test-no-account.sh).
  install -d -m 0755 /opt/rowsafe /usr/local/lib/rowsafe /etc/rowsafe
  install -m 0755 "$W/rowsafe-agent" /opt/rowsafe/rowsafe-agent
  install -m 0755 "$W/rowsafe" /usr/local/bin/rowsafe
  install -m 0755 /src/scripts/rowsafe-agent-guard /usr/local/lib/rowsafe/rowsafe-agent-guard
  install -m 0755 /src/scripts/rowsafe-pg-restart /usr/local/lib/rowsafe/rowsafe-pg-restart
  install -m 0644 /src/deploy/systemd/rowsafe-pg-restart.service /src/deploy/systemd/rowsafe-pg-restart.path /etc/systemd/system/
  install -m 0644 /src/deploy/systemd/rowsafe-agent.service /etc/systemd/system/
  printf '# test\n5432 %s\n' "$unit" >/etc/rowsafe/restart-allowed
  chmod 0644 /etc/rowsafe/restart-allowed
  install -d -m 0700 -o postgres -g postgres /var/lib/rowsafe /var/lib/rowsafe/restart /etc/rowsafe/pgbackrest /var/log/rowsafe
  umask 077
  cat >/etc/rowsafe/agent.env <<EOF
ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock
ROWSAFE_AUTO_UPDATE=false
ROWSAFE_HEARTBEAT_INTERVAL=5s
ROWSAFE_POLL_INTERVAL=2s
ROWSAFE_REPO_S3_ENDPOINT=minio
ROWSAFE_REPO_S3_PORT=9000
ROWSAFE_REPO_S3_REGION=us-east-1
ROWSAFE_REPO_S3_BUCKET=rowsafe
ROWSAFE_REPO_S3_KEY=rowsafe-test
ROWSAFE_REPO_S3_KEY_SECRET=$S3_SECRET
ROWSAFE_REPO_CIPHER_PASS=$CIPHER_PASS
ROWSAFE_REPO_S3_CA_FILE=$W/certs/ca.crt
EOF
  chown root:postgres /etc/rowsafe/agent.env
  chmod 0640 /etc/rowsafe/agent.env
  umask 022
  systemctl daemon-reload
  systemctl enable --now --quiet rowsafe-pg-restart.path
  systemctl start "$unit"
  systemctl enable --now --quiet rowsafe-agent
  until_ok 30 "the agent's control plane listens" test -S /var/lib/rowsafe/control.sock

  runuser -u postgres -- psql -qX -c "CREATE ROLE app LOGIN SUPERUSER PASSWORD 'app-pw'" -c "CREATE DATABASE shop OWNER app" ||
    fail "the app role and database"
  psql_app -c "CREATE TABLE orders (id int PRIMARY KEY, note text); INSERT INTO orders SELECT g, 'order ' || g FROM generate_series(1, 5) g" ||
    fail "the orders table"

  # Protected in the first bucket.
  rowsafe add shop "postgres://app:app-pw@localhost:5432/shop" --yes >/tmp/add.out || { cat /tmp/add.out; fail "rowsafe add"; }
  until_ok 60 "the agent reports that restarts are allowed" sh -c "rowsafe show shop --json 2>/dev/null | grep -q '\"can_restart\": true'"
  rowsafe restart shop --yes || fail "rowsafe restart"
  until_ok 420 "rowsafe status shop: protected" rowsafe status shop
  rowsafe secondcopy shop | tee /tmp/none.out
  grep -q "sudo rowsafe secondcopy add shop" /tmp/none.out || fail "no pointer to rowsafe secondcopy add"

  # Not as another user, and not with a bucket that doesn't work.
  ! runuser -u nobody -- /usr/local/bin/rowsafe secondcopy add shop --endpoint minio2:9000 --bucket rowsafe-copy2 --yes >/tmp/nobody.out 2>&1 ||
    fail "a user who isn't root added a second copy"
  cp /etc/rowsafe/agent.env /tmp/env.before
  ! ROWSAFE_REPO2_S3_KEY=rowsafe-copy2 ROWSAFE_REPO2_S3_KEY_SECRET=wrong-secret \
    rowsafe secondcopy add shop --endpoint minio2:9000 --bucket rowsafe-copy2 --region us-east-1 --ca-file "$W/certs/ca.crt" --yes >/tmp/bad.out 2>&1 ||
    fail "a second copy with a wrong secret was saved"
  grep -q "Nothing was saved" /tmp/bad.out || { cat /tmp/bad.out; fail "the failed bucket test doesn't say nothing was saved"; }
  cmp -s /etc/rowsafe/agent.env /tmp/env.before || fail "agent.env changed after a failed bucket test"
  echo "  ok: a bucket that doesn't work is refused, nothing saved: $(grep -v '^Testing' /tmp/bad.out | head -1)"

  # The second copy: tested, saved on the server only, set up, first full backup.
  ROWSAFE_REPO2_S3_KEY=rowsafe-copy2 ROWSAFE_REPO2_S3_KEY_SECRET="$S3_SECRET2" \
    rowsafe secondcopy add shop --endpoint minio2:9000 --bucket rowsafe-copy2 --region us-east-1 --ca-file "$W/certs/ca.crt" --yes |
    tee /tmp/sc-add.out || fail "rowsafe secondcopy add"
  grep -q "Second copy on" /tmp/sc-add.out || fail "rowsafe secondcopy add didn't finish"
  grep -q "password manager" /tmp/sc-add.out || fail "the new passphrase wasn't shown"
  grep -q "^ROWSAFE_REPO2_S3_KEY_SECRET='$S3_SECRET2'" /etc/rowsafe/agent.env || fail "the key isn't in agent.env"
  [ "$(stat -c '%U:%G %a' /etc/rowsafe/agent.env)" = "root:postgres 640" ] || fail "agent.env's owner or mode changed"
  ! grep -rq "$S3_SECRET2" /var/lib/rowsafe/local-control.json || fail "the second bucket's secret is in the control plane's state"
  pass2=$(sed -n "s/^ROWSAFE_REPO2_CIPHER_PASS='\(.*\)'$/\1/p" /etc/rowsafe/agent.env)
  [ -n "$pass2" ] && ! grep -rq "$pass2" /var/lib/rowsafe/local-control.json || fail "the second copy's passphrase is in the control plane's state"
  echo "  ok: the second copy's key and passphrase are only in agent.env"
  rowsafe status shop | tee /tmp/status.out
  grep -q "Second copy: *Up to date in bucket rowsafe-copy2" /tmp/status.out || fail "rowsafe status doesn't show the second copy up to date"
  rowsafe backups shop --second-copy | grep -q full || fail "no full backup in the second copy"
  rowsafe secondcopy shop || fail "rowsafe secondcopy shop"

  # New rows, a Mark, then rows deleted by mistake.
  psql_app -c "INSERT INTO orders SELECT g, 'order ' || g FROM generate_series(6, 8) g" || fail "more orders"
  rowsafe mark shop after-copy --json >/tmp/mark.json || { cat /tmp/mark.json; fail "the Mark"; }
  psql_app -c "DELETE FROM orders WHERE id > 2" || fail "deleting rows"
  until_ok 180 "the Mark reached the second copy" mark_in_second_copy
}

phase2() {
  # The first bucket is gone (the host deleted it).
  rowsafe restore shop --to after-copy --second-copy | tee /tmp/restore.out || fail "rowsafe restore --second-copy"
  grep -q "from the second copy" /tmp/restore.out || fail "the restore doesn't say it is from the second copy"
  rowsafe tasks shop --type rewind_copy --json >/tmp/copy.json || fail "the copy's task"
  copy_sock=$(grep -o '"socket_dir": *"[^"]*"' /tmp/copy.json | head -1 | sed 's/.*: *"\(.*\)"/\1/')
  copy_port=$(grep -o '"port": *[0-9]*' /tmp/copy.json | head -1 | sed 's/.*: *//')
  [ -n "$copy_sock" ] && [ -n "$copy_port" ] || { cat /tmp/copy.json; fail "where the copy listens"; }
  n=$(runuser -u postgres -- psql -qAtX -h "$copy_sock" -p "$copy_port" -d shop -c 'SELECT count(*) FROM orders') || fail "reading the copy"
  [ "$n" = 8 ] || fail "the copy has $n orders, want 8 (as at the Mark)"
  [ "$(psql_app -c 'SELECT count(*) FROM orders')" = 2 ] || fail "production changed"
  echo "  ok: with the first bucket deleted, the copy from the second bucket has the 8 orders of the Mark"
  rowsafe rewind drop shop --yes || fail "rowsafe rewind drop"
  until_ok 60 "the copy is gone" sh -c "! rowsafe restores shop | grep -q ready"

  # Turned off: the settings leave agent.env; the second bucket stays.
  rowsafe secondcopy remove --yes | tee /tmp/remove.out || fail "rowsafe secondcopy remove"
  ! grep -q '^ROWSAFE_REPO2_' /etc/rowsafe/agent.env || fail "agent.env still has the second copy"
  until_ok 200 "the second copy is off (the agent no longer reports it)" sh -c "rowsafe secondcopy shop | grep -q 'has no second copy'"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-no-account-secondcopy: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-nasc.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-nasc-$$
  cleanup() {
    docker rm -f "$name-pg" "$name-minio" "$name-minio2" >/dev/null 2>&1 || true
    docker volume rm "$name-pgdata" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
    rm -rf "$W"
  }
  trap cleanup EXIT INT TERM

  echo "building rowsafe-agent and rowsafe (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe-agent" ./cmd/rowsafe-agent &&
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe" ./cmd/rowsafe)

  # A test CA and one certificate for both MinIO servers.
  mkdir -p "$W/certs" "$W/minio-certs"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=rowsafe test CA" \
    -keyout "$W/certs/ca.key" -out "$W/certs/ca.crt" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=minio" -keyout "$W/minio-certs/private.key" -out "$W/minio.csr" 2>/dev/null
  printf 'subjectAltName=DNS:minio,DNS:minio2\n' >"$W/san.ext"
  openssl x509 -req -in "$W/minio.csr" -CA "$W/certs/ca.crt" -CAkey "$W/certs/ca.key" -CAcreateserial -days 2 \
    -extfile "$W/san.ext" -out "$W/minio-certs/public.crt" 2>/dev/null
  chmod 0644 "$W/minio-certs/private.key" "$W/certs/ca.crt"
  secret=$(openssl rand -hex 16)
  secret2=$(openssl rand -hex 16)
  cipher=$(openssl rand -hex 24)

  docker network create "$name" >/dev/null
  # Two providers: their own server, bucket and key.
  docker run -d --name "$name-minio" --network "$name" --network-alias minio \
    -e MINIO_ROOT_USER=rowsafe-test -e MINIO_ROOT_PASSWORD="$secret" \
    -v "$W/minio-certs:/certs:ro" minio/minio server /data --address :9000 --certs-dir /certs >/dev/null
  docker run -d --name "$name-minio2" --network "$name" --network-alias minio2 \
    -e MINIO_ROOT_USER=rowsafe-copy2 -e MINIO_ROOT_PASSWORD="$secret2" \
    -v "$W/minio-certs:/certs:ro" minio/minio server /data --address :9000 --certs-dir /certs >/dev/null
  mc() { docker run --rm --network "$name" --entrypoint sh minio/minio -c "$1"; }
  i=0
  until mc "mc alias set m https://minio:9000 rowsafe-test $secret --insecure >/dev/null && mc mb --insecure --ignore-existing m/rowsafe >/dev/null &&
    mc alias set n https://minio2:9000 rowsafe-copy2 $secret2 --insecure >/dev/null && mc mb --insecure --ignore-existing n/rowsafe-copy2 >/dev/null" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || {
      docker logs "$name-minio" >&2
      echo "test-no-account-secondcopy: MinIO did not come up" >&2
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
RUN ln -sf /dev/null /etc/systemd/system/systemd-binfmt.service && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.automount && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.mount
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
  docker run -d --name "$name-pg" --network "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --shm-size 256m \
    -v "$name-pgdata:/var/lib/postgresql" -v "$root:/src:ro" -v "$W:/w" "$tag" >/dev/null
  i=0
  until docker exec "$name-pg" systemctl is-system-running --wait >/dev/null 2>&1 ||
    [ "$(docker exec "$name-pg" systemctl is-system-running 2>/dev/null)" = degraded ]; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || {
      echo "test-no-account-secondcopy: systemd did not start in the container" >&2
      exit 1
    }
    sleep 1
  done
  docker exec -e S3_SECRET="$secret" -e S3_SECRET2="$secret2" -e CIPHER_PASS="$cipher" "$name-pg" \
    sh /src/scripts/test-no-account-secondcopy.sh --phase1

  # Lose the first bucket: everything in it, and the bucket itself.
  mc "mc alias set m https://minio:9000 rowsafe-test $secret --insecure >/dev/null && mc rb --insecure --force m/rowsafe >/dev/null" ||
    { echo "test-no-account-secondcopy: deleting the first bucket failed" >&2; exit 1; }
  ! mc "mc alias set m https://minio:9000 rowsafe-test $secret --insecure >/dev/null && mc ls --insecure m/rowsafe" >/dev/null 2>&1 ||
    { echo "test-no-account-secondcopy: the first bucket is still there" >&2; exit 1; }
  echo "  ok: the first bucket is deleted"

  docker exec "$name-pg" sh /src/scripts/test-no-account-secondcopy.sh --phase2
  echo "test-no-account-secondcopy: passed on $image"
}

case ${1:-} in
  --phase1) phase1 ;;
  --phase2) phase2 ;;
  *) host "$@" ;;
esac
