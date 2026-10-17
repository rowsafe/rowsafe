#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test restoring a database onto another server from the bucket, on servers
# on their own (the installer's --no-account), for real: two Debian servers
# with systemd as PID 1, PostgreSQL and pgBackRest, installed with the same
# MinIO bucket and backup passphrase, each with its agent and its own control
# plane (internal/localcp). Everything goes through the rowsafe CLI:
#
#   server A: rowsafe add shop (backups on, the first backup and Proof),
#   rows, a Mark (everything until then is in the bucket); then A is lost
#   (stopped). Server B, with an empty PostgreSQL: with a wrong passphrase
#   the restore fails plainly and the empty cluster runs as before; without
#   a terminal it is refused; with the name typed, sudo rowsafe restore shop
#   --from-bucket restores shop into it with every row (same checksum), and
#   protects it (a full backup and a Proof, in a new folder; A's backups stay
#   as they were).
#
# Usage: sh scripts/test-no-account-restore.sh [debian:trixie]   (needs Docker, ~8 min)

set -eu

fail() {
  echo "test-no-account-restore ($ROLE): $*" >&2
  echo "---- agent journal" >&2
  journalctl -u rowsafe-agent --no-pager -n 150 >&2 || true
  pg_lsclusters >&2 || true
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
  echo "  ok ($ROLE): $_what"
}

# typed NAME COMMAND...: run COMMAND on a terminal and type NAME at its question.
typed() {
  _name=$1
  shift
  printf '%s\n' "$_name" | script -qec "$*" /dev/null
}

# install_agent: what the installer puts in place, with the bucket and
# passphrase in agent.env ($CIPHER_PASS).
install_agent() {
  W=/w
  major=$(ls /usr/lib/postgresql)
  unit=postgresql@$major-main.service
  install -d -m 0755 /opt/rowsafe /usr/local/lib/rowsafe /etc/rowsafe
  install -m 0755 "$W/rowsafe-agent" /opt/rowsafe/rowsafe-agent
  install -m 0755 "$W/rowsafe" /usr/local/bin/rowsafe
  install -m 0755 /src/scripts/rowsafe-agent-guard /usr/local/lib/rowsafe/rowsafe-agent-guard
  install -m 0755 /src/scripts/rowsafe-pg-restart /usr/local/lib/rowsafe/rowsafe-pg-restart
  install -m 0644 /src/deploy/systemd/rowsafe-pg-restart.service /src/deploy/systemd/rowsafe-pg-restart.path \
    /src/deploy/systemd/rowsafe-agent.service /etc/systemd/system/
  printf '# test\n5432 %s\n' "$unit" >/etc/rowsafe/restart-allowed
  chmod 0644 /etc/rowsafe/restart-allowed
  install -d -m 0700 -o postgres -g postgres /var/lib/rowsafe /var/lib/rowsafe/restart /etc/rowsafe/pgbackrest /var/log/rowsafe
  write_env "$CIPHER_PASS"
  systemctl daemon-reload
  systemctl enable --now --quiet rowsafe-pg-restart.path
  systemctl start "$unit"
  systemctl enable --now --quiet rowsafe-agent
  until_ok 30 "the agent's control plane listens" test -S /var/lib/rowsafe/control.sock
}

write_env() {
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
ROWSAFE_REPO_CIPHER_PASS=$1
ROWSAFE_REPO_S3_CA_FILE=/w/certs/ca.crt
EOF
  chown root:postgres /etc/rowsafe/agent.env
  chmod 0640 /etc/rowsafe/agent.env
  umask 022
}

orders_sum() {
  PGPASSWORD=app-pw psql -qAtX -h localhost -U app -d shop -c "SELECT count(*) || ':' || md5(string_agg(id || note, ',' ORDER BY id)) FROM orders"
}

# server_a: the database's own server, until it is lost.
server_a() {
  export DEBIAN_FRONTEND=noninteractive
  install_agent
  runuser -u postgres -- psql -qX -c "CREATE ROLE app LOGIN SUPERUSER PASSWORD 'app-pw'" -c "CREATE DATABASE shop OWNER app" ||
    fail "the app role and database"
  PGPASSWORD=app-pw psql -qX -h localhost -U app -d shop -c "CREATE TABLE orders (id int PRIMARY KEY, note text);
    INSERT INTO orders SELECT g, md5(g::text) FROM generate_series(1, 5000) g" || fail "the orders table"
  rowsafe add shop "postgres://app:app-pw@localhost:5432/shop" --yes >/tmp/add.out 2>&1 || { cat /tmp/add.out; fail "rowsafe add"; }
  until_ok 60 "restarts are allowed" sh -c "rowsafe show shop --json | grep -q '\"can_restart\": true'"
  rowsafe restart shop --yes >/dev/null || fail "rowsafe restart"
  until_ok 420 "rowsafe status shop: protected" rowsafe status shop
  # Rows written after the first backup: they reach the bucket as changes.
  PGPASSWORD=app-pw psql -qX -h localhost -U app -d shop -c "INSERT INTO orders SELECT g, 'late ' || g FROM generate_series(5001, 5100) g" ||
    fail "more rows"
  rowsafe mark shop before-move >/dev/null || fail "the Mark"
  until_ok 60 "the Mark reached the bucket" sh -c "rowsafe marks shop --json | grep -q '\"archived_at\"'"
  orders_sum >/w/sum
  echo "  ok (A): shop has $(cat /w/sum) and everything is in the bucket"
}

# server_b: a new server installed with the same bucket and passphrase.
server_b() {
  export DEBIAN_FRONTEND=noninteractive
  install_agent
  rowsafe ls | grep -q shop && fail "B already knows shop"

  # A wrong passphrase fails plainly; the empty cluster runs as before.
  write_env "not-the-passphrase-of-the-old-server"
  systemctl restart rowsafe-agent
  until_ok 30 "the agent is back" test -S /var/lib/rowsafe/control.sock
  sleep 6
  ! rowsafe restore shop --from-bucket --yes >/tmp/wrong.out 2>&1 || { cat /tmp/wrong.out; fail "restored with the wrong passphrase"; }
  cat /tmp/wrong.out
  grep -qi "passphrase" /tmp/wrong.out || fail "a wrong passphrase isn't said plainly"
  runuser -u postgres -- psql -qAtX -c "SELECT count(*) FROM pg_database WHERE datname = 'shop'" | grep -qx 0 ||
    fail "the empty cluster isn't as before after a failed restore"
  ! ls -d /var/lib/postgresql/*/main.before-fork-* >/dev/null 2>&1 || fail "a failed restore set the cluster's data aside"
  rowsafe ls | grep -q shop && fail "a failed restore added shop"
  echo "  ok (B): a wrong passphrase fails plainly, nothing changed"
  write_env "$CIPHER_PASS"
  systemctl restart rowsafe-agent
  until_ok 30 "the agent is back" test -S /var/lib/rowsafe/control.sock
  sleep 6

  # It asks for the name.
  ! rowsafe restore shop --from-bucket </dev/null >/tmp/noterm.out 2>&1 || fail "restored without a confirmation"
  grep -q -- "--yes" /tmp/noterm.out || { cat /tmp/noterm.out; fail "no word on --yes without a terminal"; }

  typed shop rowsafe restore shop --from-bucket >/tmp/restore.out 2>&1 || { cat /tmp/restore.out; fail "the restore"; }
  cat /tmp/restore.out
  [ "$(orders_sum)" = "$(cat /w/sum)" ] || fail "the rows on B: $(orders_sum), want $(cat /w/sum)"
  echo "  ok (B): shop is restored with every row ($(cat /w/sum))"
  until_ok 600 "rowsafe status shop on B: protected" rowsafe status shop
  rowsafe backups shop
  PGPASSWORD=app-pw psql -qX -h localhost -U app -d shop -c "INSERT INTO orders VALUES (9001, 'on B')" || fail "writing on B"
  rowsafe mark shop on-b >/dev/null || fail "a Mark on B"
  echo "  ok (B): protected here, writes and Marks work"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-no-account-restore: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-noaccount-restore.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-noaccount-restore-$$
  cleanup() {
    [ "${KEEP:-0}" = 1 ] && return
    docker rm -f "$name-a" "$name-b" "$name-minio" >/dev/null 2>&1 || true
    docker volume rm "$name-a" "$name-b" >/dev/null 2>&1 || true
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
    -v "$W/minio-certs:/certs:ro" minio/minio server /data --address :9000 --certs-dir /certs >/dev/null
  i=0
  until docker run --rm --network "$name" --entrypoint sh minio/minio -c \
    "mc alias set m https://minio:9000 rowsafe-test $secret --insecure >/dev/null && mc mb --insecure --ignore-existing m/rowsafe >/dev/null" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || {
      docker logs "$name-minio" >&2
      echo "test-no-account-restore: MinIO did not come up" >&2
      exit 1
    }
    sleep 1
  done

  # The same image as test-no-account.sh (Debian's PostgreSQL).
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
  start() {
    docker run -d --name "$name-$1" --hostname "server-$1" --network "$name" --privileged --cgroupns=host \
      -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --shm-size 256m \
      -v "$name-$1:/var/lib/postgresql" -v "$root:/src:ro" -v "$W:/w" "$tag" >/dev/null
    i=0
    until docker exec "$name-$1" systemctl is-system-running --wait >/dev/null 2>&1 ||
      [ "$(docker exec "$name-$1" systemctl is-system-running 2>/dev/null)" = degraded ]; do
      i=$((i + 1))
      [ "$i" -lt 60 ] || {
        echo "test-no-account-restore: systemd did not start in server $1" >&2
        exit 1
      }
      sleep 1
    done
  }
  run() {
    docker exec -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" -e ROLE="$1" "$name-$1" sh /src/scripts/test-no-account-restore.sh --server "$1"
  }

  echo "server A: shop, protected"
  start a
  run a
  echo "server A is lost"
  docker stop -t 5 "$name-a" >/dev/null
  echo "server B: same bucket and passphrase, an empty PostgreSQL"
  start b
  run b
  # A's backups are where they were; B's start in a new folder.
  docker run --rm --network "$name" --entrypoint sh minio/minio -c \
    "mc alias set m https://minio:9000 rowsafe-test $secret --insecure >/dev/null && mc ls --recursive --insecure m/rowsafe" >"$W/bucket.txt"
  grep -q '/shop/backup.info' "$W/bucket.txt" || grep -q 'shop/backup.info' "$W/bucket.txt" || {
    cat "$W/bucket.txt" >&2
    echo "test-no-account-restore: A's backups aren't in the bucket any more" >&2
    exit 1
  }
  grep -q 'shop-20[0-9]*-[0-9]*/backup.info' "$W/bucket.txt" || {
    cat "$W/bucket.txt" >&2
    echo "test-no-account-restore: B's backups aren't in a new folder" >&2
    exit 1
  }
  echo "  ok: A's backups stay in shop/, B's are in $(grep -o 'shop-20[0-9]*-[0-9]*' "$W/bucket.txt" | head -1)/"
  echo "test-no-account-restore: passed on $image"
}

ROLE=host
case ${1:-} in
  --server)
    ROLE=$2
    case $2 in
      a) server_a ;;
      b) server_b ;;
    esac
    ;;
  *) host "$@" ;;
esac
