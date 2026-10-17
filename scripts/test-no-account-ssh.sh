#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test a server on its own (the installer's --no-account) used from another
# computer over SSH, for real. The server: Debian with systemd, PostgreSQL,
# pgBackRest, a MinIO bucket, sshd, and the agent with its own control
# plane on /var/lib/rowsafe/control.sock (as in test-no-account.sh), with
# shop protected by sudo rowsafe add. The computer: another container with
# only ssh and the rowsafe CLI, which reaches the server through ssh alone:
#
#   rowsafe add shop ssh://deploy@pg (deploy may run only Rowsafe's bridge
#   with sudo; a user whose sudo asks for a password gets a plain answer),
#   status, mark, backups, marks, restore (a copy at the Mark), rewind
#   compare and rows (the deleted rows come back), alerts, channels, pulse
#   (run on the server by its rowsafe), rowsafe mcp shop (an MCP client
#   saves a Mark), the Guard hook (a Mark before DROP TABLE), and nothing
#   new listening on the network.
#
# Usage: sh scripts/test-no-account-ssh.sh [debian:trixie]   (needs Docker, ~5 min)

set -eu

fail() {
  echo "test-no-account-ssh: $*" >&2
  if [ "${ROLE:-}" = server ]; then
    echo "---- agent journal" >&2
    journalctl -u rowsafe-agent --no-pager -n 120 >&2 || true
  fi
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

# server sets up the database server: the agent without an account, shop
# protected, and sshd with keys for root, deploy and nosudo.
server() {
  ROLE=server
  export DEBIAN_FRONTEND=noninteractive
  W=/w
  major=$(ls /usr/lib/postgresql)
  unit=postgresql@$major-main.service

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
  PGPASSWORD=app-pw psql -qAtX -h localhost -U app -d shop \
    -c "CREATE TABLE orders (id int PRIMARY KEY, note text); INSERT INTO orders SELECT g, 'order ' || g FROM generate_series(1, 5) g" ||
    fail "the orders table"
  rowsafe add shop "postgres://app:app-pw@localhost:5432/shop" --yes >/tmp/add.out 2>&1 || { cat /tmp/add.out; fail "sudo rowsafe add"; }
  until_ok 60 "restarts are allowed" sh -c "rowsafe show shop --json 2>/dev/null | grep -q '\"can_restart\": true'"
  rowsafe restart shop --yes >/dev/null || fail "rowsafe restart"
  until_ok 180 "shop is active (archiving proven)" sh -c "rowsafe ls | grep shop | grep -q active"
  until_ok 420 "shop is protected (a full backup and a Proof)" rowsafe status shop

  # SSH: root and deploy with the test key; deploy may run only the bridge
  # as root (the line rowsafe suggests), nosudo's sudo asks for a password.
  useradd -m -s /bin/bash deploy
  useradd -m -s /bin/sh nosudo
  echo "nosudo ALL=(ALL:ALL) ALL" >/etc/sudoers.d/nosudo
  echo "deploy ALL=(root) NOPASSWD: /opt/rowsafe/rowsafe-agent control-bridge" >/etc/sudoers.d/rowsafe
  chmod 0440 /etc/sudoers.d/nosudo /etc/sudoers.d/rowsafe
  for h in /root /home/deploy /home/nosudo; do
    install -d -m 0700 "$h/.ssh"
    install -m 0600 "$W/client/id.pub" "$h/.ssh/authorized_keys"
    chown -R "$(stat -c %U "$h"):$(stat -c %G "$h")" "$h/.ssh"
  done
  ssh-keygen -A >/dev/null
  systemctl enable --now --quiet ssh
  until_ok 30 "sshd listens" sh -c "ss -ltnH | grep -q ':22 '"
  echo "  ok: the server is ready (shop protected, sshd up)"
}

# client is the other computer: only ssh and the rowsafe CLI.
client() {
  ROLE=client
  export HOME=/root
  install -m 0755 /w/rowsafe /usr/local/bin/rowsafe
  install -d -m 0700 ~/.ssh
  install -m 0600 /w/client/id ~/.ssh/id_ed25519
  cat >~/.ssh/config <<'EOF'
Host pg
  StrictHostKeyChecking accept-new
  IdentityFile ~/.ssh/id_ed25519
EOF
  as_root() { ssh -o BatchMode=yes root@pg "$@"; }
  orders() { as_root "runuser -u postgres -- psql -qAtX -d shop -c 'SELECT count(*) FROM orders'"; }
  [ "$(orders)" = 5 ] || fail "the server's orders"

  # sudo that asks for a password: a plain answer, nothing saved.
  ! rowsafe add x ssh://nosudo@pg >/tmp/nosudo.out 2>&1 || fail "saved through a sudo that asks for a password"
  grep -q "NOPASSWD: /opt/rowsafe/rowsafe-agent control-bridge" /tmp/nosudo.out || { cat /tmp/nosudo.out; fail "no plain answer for sudo's password"; }
  echo "  ok: sudo asking for a password gets the sudoers line to add"

  rowsafe add shop ssh://deploy@pg | tee /tmp/add.out || fail "rowsafe add shop ssh://deploy@pg"
  grep -q "Saved shop: shop on pg over SSH (as deploy). Rowsafe protects it there (active)" /tmp/add.out || fail "rowsafe add's answer"
  saved=$HOME/.config/rowsafe/databases.json
  ! grep -q "postgres://\|app-pw" "$saved" || { cat "$saved"; fail "a connection string was saved on the computer"; }
  rowsafe databases | grep -q "ssh://deploy@pg" || fail "rowsafe databases"

  rowsafe status shop || fail "rowsafe status shop (over SSH)"
  rowsafe status shop --json >/tmp/status.json || fail "rowsafe status --json"
  python3 -c 'import json,sys; d=json.load(open("/tmp/status.json")); sys.exit(0 if "shop" in json.dumps(d) else 1)' ||
    { cat /tmp/status.json; fail "status --json"; }
  echo "  ok: rowsafe status shop over SSH (and --json)"

  rowsafe mark shop before-drop --json | tee /tmp/mark.json
  grep -q '"status": *"archived"' /tmp/mark.json || fail "the Mark isn't archived"
  as_root "runuser -u postgres -- psql -qX -d shop -c 'DELETE FROM orders WHERE id > 2'" || fail "deleting rows"
  rowsafe marks shop | grep -q before-drop || fail "rowsafe marks"
  rowsafe backups shop | grep -qi full || fail "rowsafe backups"
  rowsafe proofs shop >/dev/null || fail "rowsafe proofs"

  rowsafe restore shop --to before-drop | tee /tmp/restore.out || fail "rowsafe restore over SSH"
  rowsafe restores shop | grep -q ready || fail "the copy isn't ready"
  rowsafe rewind compare shop public.orders | tee /tmp/compare.out || fail "rowsafe rewind compare"
  grep -q orders /tmp/compare.out || fail "the comparison doesn't list orders"
  [ "$(orders)" = 2 ] || fail "a restore changed production"
  ! rowsafe rewind rows shop public.orders </dev/null >/tmp/rows.out 2>&1 || fail "rows came back without a confirmation"
  rowsafe rewind rows shop public.orders --yes || fail "rowsafe rewind rows"
  [ "$(orders)" = 5 ] || fail "the rows didn't come back"
  rowsafe rewind drop shop --yes || fail "rowsafe rewind drop"
  until_ok 60 "the copy is gone" sh -c "! rowsafe restores shop | grep -q ready"
  echo "  ok: restore, compare and bring rows back, over SSH"

  rowsafe alerts shop >/dev/null || fail "rowsafe alerts shop"
  rowsafe channels list shop | grep -q "rowsafe channels add shop" || fail "rowsafe channels list shop"
  rowsafe alerts rules shop | grep -q backup_stale || fail "rowsafe alerts rules shop"

  # pulse runs on the server with its rowsafe (root saved shop there).
  rowsafe add rootshop ssh://root@pg --database shop >/dev/null || fail "rowsafe add rootshop"
  rowsafe pulse rootshop >/tmp/pulse.out 2>&1 || true
  grep -q "/100" /tmp/pulse.out || { cat /tmp/pulse.out; fail "rowsafe pulse over SSH"; }
  echo "  ok: rowsafe pulse runs on the server"

  # An AI agent: the MCP server on the server's agent saves a Mark.
  python3 - <<'PY' || fail "rowsafe mcp shop"
import json, signal, subprocess, sys
signal.alarm(150)
p = subprocess.Popen(["rowsafe", "mcp", "shop", "--allow-restore-points"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def send(m):
    p.stdin.write(json.dumps(m) + "\n"); p.stdin.flush()
def reply(i):
    for line in p.stdout:
        m = json.loads(line)
        if m.get("id") == i:
            return m
    sys.exit("no reply %d" % i)
send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}}})
reply(1)
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "create_restore_point", "arguments": {"database": "shop", "name": "mcp-before-migration"}}})
r = reply(2)["result"]
out = r.get("structuredContent") or {}
print("create_restore_point:", json.dumps(out))
if r.get("isError") or not out.get("confirmed"):
    sys.exit("not confirmed: %s" % json.dumps(r))
send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_restore_points", "arguments": {"database": "shop"}}})
names = [x["name"] for x in reply(3)["result"]["structuredContent"]["restore_points"]]
if "mcp-before-migration" not in names:
    sys.exit("list_restore_points: %s" % names)
p.stdin.close(); p.wait(timeout=30)
PY
  echo "  ok: rowsafe mcp shop: an MCP client saved a Mark on the server"

  # Guard: the project's database is the saved server; a Mark before DROP.
  mkdir -p /proj && cd /proj && rowsafe use shop >/dev/null
  printf '{"tool_name":"Bash","tool_input":{"command":"psql -c \\"DROP TABLE orders\\""},"cwd":"/proj"}' |
    rowsafe guard >/tmp/guard.out || { cat /tmp/guard.out; fail "rowsafe guard"; }
  grep -q 'restore point agent-.* created on shop' /tmp/guard.out || { cat /tmp/guard.out; fail "Guard didn't save a Mark"; }
  rowsafe marks | grep -q "agent-" || fail "Guard's Mark isn't on the server"
  echo "  ok: the Guard hook saved a Mark on the server before DROP TABLE"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-no-account-ssh: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-ssh.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-ssh-$$
  cleanup() {
    docker rm -f "$name-pg" "$name-minio" "$name-laptop" >/dev/null 2>&1 || true
    docker volume rm "$name-pgdata" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
    rm -rf "$W"
  }
  trap cleanup EXIT INT TERM

  echo "building rowsafe-agent and rowsafe (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe-agent" ./cmd/rowsafe-agent &&
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe" ./cmd/rowsafe)

  mkdir -p "$W/certs" "$W/minio-certs" "$W/client"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=rowsafe test CA" \
    -keyout "$W/certs/ca.key" -out "$W/certs/ca.crt" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=minio" -keyout "$W/minio-certs/private.key" -out "$W/minio.csr" 2>/dev/null
  printf 'subjectAltName=DNS:minio\n' >"$W/san.ext"
  openssl x509 -req -in "$W/minio.csr" -CA "$W/certs/ca.crt" -CAkey "$W/certs/ca.key" -CAcreateserial -days 2 \
    -extfile "$W/san.ext" -out "$W/minio-certs/public.crt" 2>/dev/null
  chmod 0644 "$W/minio-certs/private.key" "$W/certs/ca.crt"
  ssh-keygen -q -t ed25519 -N '' -C rowsafe-test -f "$W/client/id"
  chmod 0644 "$W/client/id" # copied with 0600 inside the container
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
      echo "test-no-account-ssh: MinIO did not come up" >&2
      exit 1
    }
    sleep 1
  done

  tag=rowsafe-test/ssh-server:$(echo "$image" | tr ':/' '--')
  echo "building $tag"
  docker build -q -t "$tag" - >/dev/null <<EOF
FROM $image
ENV container=docker
RUN apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus ca-certificates procps util-linux iproute2 \\
      postgresql pgbackrest openssh-server sudo >/dev/null && \\
    rm -f /lib/systemd/system/multi-user.target.wants/getty* /etc/ssh/ssh_host_* && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN ln -sf /dev/null /etc/systemd/system/systemd-binfmt.service && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.automount && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.mount
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
  laptop=rowsafe-test/ssh-laptop
  docker build -q -t "$laptop" - >/dev/null <<'EOF'
FROM python:3.13-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-client >/dev/null && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
EOF
  docker run -d --name "$name-pg" --network "$name" --network-alias pg --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --shm-size 256m \
    -v "$name-pgdata:/var/lib/postgresql" -v "$root:/src:ro" -v "$W:/w" \
    -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" "$tag" >/dev/null
  i=0
  until docker exec "$name-pg" systemctl is-system-running --wait >/dev/null 2>&1 ||
    [ "$(docker exec "$name-pg" systemctl is-system-running 2>/dev/null)" = degraded ]; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || {
      echo "test-no-account-ssh: systemd did not start in the container" >&2
      exit 1
    }
    sleep 1
  done
  docker exec -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" "$name-pg" sh /src/scripts/test-no-account-ssh.sh --server

  echo "the other computer: rowsafe over SSH"
  docker run --rm --name "$name-laptop" --network "$name" -v "$root:/src:ro" -v "$W:/w:ro" "$laptop" \
    sh /src/scripts/test-no-account-ssh.sh --client

  # On the network only sshd listens (PostgreSQL stays on localhost).
  after=$(docker exec "$name-pg" ss -ltnH)
  if echo "$after" | awk '{print $4}' | grep -v ':22$' | grep -qv '^127\.\|^\[::1\]'; then
    echo "$after" >&2
    echo "test-no-account-ssh: something but sshd listens on the network" >&2
    exit 1
  fi
  echo "  ok: nothing but sshd listens on the server's network"
  echo "test-no-account-ssh: passed on $image"
}

case ${1:-} in
  --server) server ;;
  --client) client ;;
  *) host "$@" ;;
esac
