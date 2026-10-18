#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test a standby on a second server without an account, for real: two
# Debian servers with systemd as PID 1, PostgreSQL, pgBackRest and the agent
# running its own control plane (--no-account), both set up with the same
# MinIO bucket and passphrase. They never talk through Rowsafe:
#
#   pg1 protects shop (rowsafe add) and lets the standby stream (standby
#   link); pg2 creates the standby from the bucket (standby create) and
#   follows by streaming; rows written on pg1 show up on pg2 and both
#   servers report the lag. A switchover: pg1 is fenced (stopped for good,
#   the bucket says where its last change is), pg2 promotes without losing
#   a row and backs up; pg1 started by hand is stopped again by its agent.
#   Then pg1 is rebuilt as pg2's standby, and a failover with pg2 only cut
#   off (its agent stopped, PostgreSQL still running): pg1 promotes with
#   --primary-down, and when pg2's agent comes back it reads the bucket and
#   stops PostgreSQL there by itself. Automatic failover is refused.
#
# Usage: sh scripts/test-no-account-standby.sh [debian:trixie]   (needs Docker, ~8 min)

set -eu
# The MinIO test image (built once from source: scripts/minio).
MINIO_SH=$(cd "$(dirname "$0")" && pwd)/minio/image.sh

fail() {
  echo "test-no-account-standby ($(hostname)): $*" >&2
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
  echo "  ok ($(hostname)): $_what"
}

major() { ls /usr/lib/postgresql; }
unit() { echo "postgresql@$(major)-main.service"; }
psql_local() { runuser -u postgres -- psql -qAtX -d "${DB:-postgres}" "$@"; }
pg_running() { runuser -u postgres -- pg_isready -q -h /var/run/postgresql -p 5432; }
in_recovery() { [ "$(psql_local -c 'SELECT pg_is_in_recovery()')" = t ]; }

# setup_server: what the installer puts in place without an account, with
# restarts allowed for the main cluster, which listens on the network.
setup_server() {
  export DEBIAN_FRONTEND=noninteractive
  W=/w
  install -d -m 0755 /opt/rowsafe /usr/local/lib/rowsafe /etc/rowsafe
  install -m 0755 "$W/rowsafe-agent" /opt/rowsafe/rowsafe-agent
  install -m 0755 "$W/rowsafe" /usr/local/bin/rowsafe
  install -m 0755 /src/scripts/rowsafe-agent-guard /usr/local/lib/rowsafe/rowsafe-agent-guard
  install -m 0755 /src/scripts/rowsafe-pg-restart /usr/local/lib/rowsafe/rowsafe-pg-restart
  install -m 0644 /src/deploy/systemd/rowsafe-pg-restart.service /src/deploy/systemd/rowsafe-pg-restart.path /etc/systemd/system/
  install -m 0644 /src/deploy/systemd/rowsafe-agent.service /etc/systemd/system/
  printf '# test\n5432 %s\n' "$(unit)" >/etc/rowsafe/restart-allowed
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
  # Streaming needs PostgreSQL to listen on the servers' network.
  echo "listen_addresses = '*'" >"/etc/postgresql/$(major)/main/conf.d/listen.conf"
  systemctl daemon-reload
  systemctl enable --now --quiet rowsafe-pg-restart.path
  systemctl start "$(unit)"
  systemctl enable --now --quiet rowsafe-agent
  until_ok 30 "the agent's control plane listens" test -S /var/lib/rowsafe/control.sock
}

# primary: shop protected, with rows, and its first full backup.
primary() {
  setup_server
  runuser -u postgres -- psql -qX -c "CREATE ROLE app LOGIN SUPERUSER PASSWORD 'app-pw'" -c "CREATE DATABASE shop OWNER app" ||
    fail "the app role and database"
  DB=shop psql_local -c "CREATE TABLE orders (id int PRIMARY KEY, note text); INSERT INTO orders SELECT g, 'order ' || g FROM generate_series(1, 5) g" ||
    fail "the orders table"
  rowsafe add shop "postgres://app:app-pw@localhost:5432/shop" --yes >/tmp/add.out 2>&1 || { cat /tmp/add.out; fail "rowsafe add"; }
  until_ok 60 "restarts are allowed" sh -c "rowsafe show shop --json 2>/dev/null | grep -q '\"can_restart\": true'"
  rowsafe restart shop --yes >/dev/null || fail "rowsafe restart"
  until_ok 180 "shop is active (archiving proven)" sh -c "rowsafe ls | grep shop | grep -q active"
  until_ok 300 "the first full backup" sh -c "rowsafe backups shop | grep -qi full"
  # Nothing to show yet, and the standby's commands say where to run them.
  rowsafe standby shop | tee /tmp/sb.out
  grep -q "this server is the primary" /tmp/sb.out || fail "rowsafe standby on the primary"
  ! rowsafe standby failover shop --on >/tmp/fo.out 2>&1 || fail "automatic failover was turned on"
  grep -q "witness" /tmp/fo.out || { cat /tmp/fo.out; fail "automatic failover refused without the reason"; }
  echo "  ok: automatic failover is refused, with the reason"
}

# link ADDRESS: let the standby at ADDRESS stream (on the primary).
link() {
  rowsafe standby link shop --address "$1" | tee /tmp/link.out || fail "rowsafe standby link"
  grep -q "may stream" /tmp/link.out || fail "the standby may not stream"
  grep -q "sudo rowsafe standby create shop --primary" /tmp/link.out || fail "link didn't say what to run on the standby"
}

# standby PRIMARY: this server's empty cluster becomes shop's standby.
standby() {
  setup_server
  ! rowsafe standby create shop --primary "$1" </dev/null >/tmp/create.out 2>&1 || fail "created a standby without a confirmation"
  rowsafe standby create shop --primary "$1" --port 5432 --yes | tee /tmp/create.out || fail "rowsafe standby create"
  until_ok 120 "the standby streams from the primary" sh -c "rowsafe standby shop | grep -q 'in sync (streaming)'"
  in_recovery || fail "the standby isn't in recovery"
  [ "$(DB=shop psql_local -c 'SELECT count(*) FROM orders')" = 5 ] || fail "the standby doesn't have the 5 orders"
  ! DB=shop psql_local -c "INSERT INTO orders VALUES (99, 'x')" 2>/dev/null || fail "the standby took a write"
  echo "  ok: the standby has the rows and is read-only"
}

# write N: rows on the primary.
write() {
  DB=shop psql_local -c "INSERT INTO orders SELECT g, 'order ' || g FROM generate_series($1, $2) g" || fail "writing rows"
}

# has N: the standby replayed N orders.
has() {
  until_ok 60 "this server has $1 orders" sh -c "[ \"\$(runuser -u postgres -- psql -qAtX -d shop -c 'SELECT count(*) FROM orders')\" = $1 ]"
}

# lag_primary: the primary sees the stream and how far behind it is.
lag_primary() {
  until_ok 60 "the primary sees the standby streaming" sh -c "rowsafe standby shop | grep -q 'in sync (streaming)'"
  rowsafe standby shop --json >/tmp/sb.json
  grep -q '"mode": "streaming"' /tmp/sb.json || { cat /tmp/sb.json; fail "the primary's view"; }
  grep -q '"lag_bytes"' /tmp/sb.json || { cat /tmp/sb.json; fail "no lag on the primary"; }
  rowsafe standby shop
}

lag_standby() {
  rowsafe standby shop | tee /tmp/sb.out
  grep -q "Behind:" /tmp/sb.out || fail "no lag on the standby"
  grep -q "primary didn't\|fence shop" /tmp/sb.out || fail "the standby doesn't say how to switch over"
  # Without the primary stopping, promoting needs the typed "is down".
  ! rowsafe standby promote shop --yes >/tmp/promote.out 2>&1 || fail "promoted without the primary stopping"
  grep -q "primary-down" /tmp/promote.out || { cat /tmp/promote.out; fail "no pointer to --primary-down"; }
  echo "  ok: promoting before the primary stopped is refused"
}

fence() {
  rowsafe standby fence shop --yes | tee /tmp/fence.out || fail "rowsafe standby fence"
  grep -q "sudo rowsafe standby promote shop$" /tmp/fence.out || fail "the fence didn't say the bucket knows"
  ! pg_running || fail "PostgreSQL still runs after the fence"
  [ -f "/var/lib/postgresql/$(major)/main/standby.signal" ] || fail "no standby.signal"
  rowsafe standby shop | grep -q "old primary, stopped" || fail "rowsafe standby after the fence"
}

promote() {
  until_ok 60 "the standby reads in the bucket that the primary stopped" sh -c "rowsafe standby shop | grep -q 'stopped for a switchover: promote'"
  rowsafe standby promote shop --yes | tee /tmp/promote.out || fail "rowsafe standby promote"
  grep -q "replayed everything the old primary wrote" /tmp/promote.out || fail "the promotion may have lost changes"
  ! in_recovery || fail "still in recovery after the promotion"
  until_ok 30 "shop is active here" sh -c "rowsafe ls | grep shop | grep -q active"
}

# backs_up: the new primary archives and backs up to the same bucket.
backs_up() {
  DB=shop psql_local -c "INSERT INTO orders VALUES (1000, 'after the switch')" || fail "a write on the new primary"
  until_ok 300 "a full backup from the new primary" sh -c "rowsafe backups shop | grep -qi full"
}

# fence_holds: PostgreSQL started by hand on the fenced old primary comes
# up read-only and its agent stops it again.
fence_holds() {
  systemctl start "$(unit)" || true
  if pg_running; then
    ! in_recovery || echo "  ok: started by hand, it came up read-only (standby.signal)"
  fi
  until_ok 90 "the agent stops the fenced PostgreSQL again" sh -c "! runuser -u postgres -- pg_isready -q -h /var/run/postgresql -p 5432"
}

# rebuild PRIMARY: the fenced old primary becomes the new primary's standby.
rebuild() {
  rowsafe standby create shop --primary "$1" --yes | tee /tmp/rebuild.out || fail "rebuilding the old primary"
  until_ok 120 "the old primary follows the new one" sh -c "rowsafe standby shop | grep -q 'in sync'"
  in_recovery || fail "the rebuilt old primary isn't in recovery"
}

# promote_down: the primary is cut off; promote with --primary-down.
promote_down() {
  rowsafe standby promote shop --primary-down --yes | tee /tmp/promote.out || fail "promoting with --primary-down"
  ! in_recovery || fail "still in recovery"
}

# superseded: this server came back after another was promoted: its agent
# reads the bucket and Rowsafe stops PostgreSQL here.
superseded() {
  systemctl start rowsafe-agent
  until_ok 120 "PostgreSQL is stopped here: another server took over" sh -c "! runuser -u postgres -- pg_isready -q -h /var/run/postgresql -p 5432"
  rowsafe standby shop | tee /tmp/sb.out
  grep -q "old primary, stopped" /tmp/sb.out || fail "not shown as fenced"
  ! rowsafe standby unfence shop --yes >/tmp/unfence.out 2>&1 || fail "started again after another server took over"
  until_ok 60 "the standby_promoted alert fires" sh -c "rowsafe alerts | grep -q 'took over'"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-no-account-standby: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-standby.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-standby-$$
  cleanup() {
    docker rm -f "$name-pg1" "$name-pg2" "$name-minio" >/dev/null 2>&1 || true
    docker volume rm "$name-pg1" "$name-pg2" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
    rm -rf "$W"
  }
  trap cleanup EXIT INT TERM

  echo "building rowsafe-agent and rowsafe (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe-agent" ./cmd/rowsafe-agent &&
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe" ./cmd/rowsafe)

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
    -v "$W/minio-certs:/certs:ro" "$(sh "$MINIO_SH")" server /data --address :9000 --certs-dir /certs >/dev/null
  i=0
  until docker run --rm --network "$name" --entrypoint sh "$(sh "$MINIO_SH")" -c \
    "mc alias set m https://minio:9000 rowsafe-test $secret --insecure >/dev/null && mc mb --insecure --ignore-existing m/rowsafe >/dev/null" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || {
      docker logs "$name-minio" >&2
      echo "test-no-account-standby: MinIO did not come up" >&2
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
  for n in pg1 pg2; do
    docker run -d --name "$name-$n" --hostname "$n" --network "$name" --privileged --cgroupns=host \
      -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --shm-size 256m \
      -v "$name-$n:/var/lib/postgresql" -v "$root:/src:ro" -v "$W:/w" "$tag" >/dev/null
  done
  for n in pg1 pg2; do
    i=0
    until docker exec "$name-$n" systemctl is-system-running --wait >/dev/null 2>&1 ||
      [ "$(docker exec "$name-$n" systemctl is-system-running 2>/dev/null)" = degraded ]; do
      i=$((i + 1))
      [ "$i" -lt 60 ] || {
        echo "test-no-account-standby: systemd did not start in $n" >&2
        exit 1
      }
      sleep 1
    done
  done
  ip1=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$name\").IPAddress}}" "$name-pg1")
  ip2=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$name\").IPAddress}}" "$name-pg2")
  on() {
    _n=$1
    shift
    docker exec -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" "$name-$_n" sh /src/scripts/test-no-account-standby.sh --in-container "$@"
  }

  echo "== pg1: shop protected"
  on pg1 primary
  echo "== a standby on pg2 that streams from pg1"
  on pg1 link "$ip2"
  on pg2 standby "$ip1"
  on pg1 write 6 50
  on pg2 has 50
  on pg1 lag_primary
  on pg2 lag_standby
  echo "== switchover: pg1 fenced, pg2 promoted"
  on pg1 write 51 60
  on pg1 fence
  on pg2 promote
  on pg2 has 60
  echo "  ok: nothing lost in the switchover"
  on pg2 backs_up
  on pg1 fence_holds
  echo "== pg1 rebuilt as pg2's standby"
  on pg2 link "$ip1"
  on pg1 rebuild "$ip2"
  on pg1 has 61
  echo "== failover: pg2 cut off (agent stopped, PostgreSQL running), pg1 promoted"
  docker exec "$name-pg2" systemctl stop rowsafe-agent
  on pg1 promote_down
  on pg2 superseded
  echo "test-no-account-standby: passed on $image"
}

case ${1:-} in
  --in-container)
    shift
    "$@"
    ;;
  *) host "$@" ;;
esac
