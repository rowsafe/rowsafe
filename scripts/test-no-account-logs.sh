#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test logs on a server on its own (the installer's --no-account), for real:
# a Debian server with systemd as PID 1 and PostgreSQL, the agent as its
# systemd unit with its own control plane (internal/localcp). The agent
# reads PostgreSQL's log and keeps it on the server:
#
#   an error is found with rowsafe logs shop --errors (and --since, --grep),
#   a slow statement with --kind slow_query, the entries survive the agent
#   restarting, the files stay small, turning logs off stops keeping them,
#   and rowsafe logs forward --url sends errors to a webhook next to the
#   server, signed, in the hosted control plane's format (the host checks
#   what it received).
#
# Usage: sh scripts/test-no-account-logs.sh [debian:trixie]   (needs Docker, ~2 min)

set -eu

fail() {
  echo "test-no-account-logs: $*" >&2
  echo "---- agent journal" >&2
  journalctl -u rowsafe-agent --no-pager -n 120 >&2 || true
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

in_container() {
  export DEBIAN_FRONTEND=noninteractive
  W=/w
  major=$(ls /usr/lib/postgresql)
  unit=postgresql@$major-main.service

  install -d -m 0755 /opt/rowsafe /usr/local/lib/rowsafe /etc/rowsafe
  install -m 0755 "$W/rowsafe-agent" /opt/rowsafe/rowsafe-agent
  install -m 0755 "$W/rowsafe" /usr/local/bin/rowsafe
  install -m 0755 /src/scripts/rowsafe-agent-guard /usr/local/lib/rowsafe/rowsafe-agent-guard
  install -m 0644 /src/deploy/systemd/rowsafe-agent.service /etc/systemd/system/
  install -d -m 0700 -o postgres -g postgres /var/lib/rowsafe /var/lib/rowsafe/restart /etc/rowsafe/pgbackrest /var/log/rowsafe
  # Storage the agent needs to start; backups stay off in this test.
  cat >/etc/rowsafe/agent.env <<EOF
ROWSAFE_URL=unix:///var/lib/rowsafe/control.sock
ROWSAFE_AUTO_UPDATE=false
ROWSAFE_HEARTBEAT_INTERVAL=5s
ROWSAFE_POLL_INTERVAL=2s
ROWSAFE_REPO_S3_ENDPOINT=storage.invalid
ROWSAFE_REPO_S3_REGION=us-east-1
ROWSAFE_REPO_S3_BUCKET=unused
ROWSAFE_REPO_S3_KEY=unused
ROWSAFE_REPO_S3_KEY_SECRET=unused
ROWSAFE_REPO_CIPHER_PASS=unused-in-this-test-0123456789
EOF
  chown root:postgres /etc/rowsafe/agent.env
  chmod 0640 /etc/rowsafe/agent.env
  systemctl daemon-reload
  systemctl start "$unit"
  systemctl enable --now --quiet rowsafe-agent
  echo "PostgreSQL $major and the agent (no account) are running"
  until_ok 30 "the agent's control plane listens" test -S /var/lib/rowsafe/control.sock

  runuser -u postgres -- psql -qX -c "CREATE ROLE app LOGIN SUPERUSER PASSWORD 'app-pw'" -c "CREATE DATABASE shop OWNER app" ||
    fail "the app role and database"
  psql_app() { PGPASSWORD=app-pw psql -qAtX -h localhost -U app -d shop "$@"; }
  # Saved and planned (no --yes, no terminal: backups stay off); the agent
  # watches it from now on.
  rowsafe add shop "postgres://app:app-pw@localhost:5432/shop" </dev/null >/tmp/add.out 2>&1 || true
  grep -q "Saved shop" /tmp/add.out || { cat /tmp/add.out; fail "rowsafe add"; }
  until_ok 60 "the log is read" sh -c "rowsafe logs shop --json | grep -q '\"latest\"'; rowsafe logs shop >/dev/null"

  # An error, logged by PostgreSQL, found on the server.
  psql_app -c "SELECT * FROM missing_table_e2e" 2>/dev/null && fail "the query should fail"
  until_ok 60 "rowsafe logs shop --errors finds the error" sh -c "rowsafe logs shop --errors | grep -q missing_table_e2e"
  rowsafe logs shop --errors --since 1h | grep -q 'relation "missing_table_e2e" does not exist' || fail "--since 1h"
  rowsafe logs shop --grep MISSING_TABLE_E2E | grep -q ERROR || fail "--grep"
  rowsafe logs shop --errors --json | grep -q '"severity": "ERROR"' || fail "--json"
  ! rowsafe logs shop --errors --since 1s | grep -q missing_table_e2e || fail "--since 1s still shows an older error"
  rowsafe logs shop --groups --kind errors | grep -q missing_table_e2e || fail "--groups"
  echo "  ok: the error is found with --errors, --since, --grep and --groups"

  # A slow statement over time.
  runuser -u postgres -- psql -qX -c "ALTER SYSTEM SET log_min_duration_statement = 200" -c "SELECT pg_reload_conf()" >/dev/null
  psql_app -c "SELECT pg_sleep(0.4)" >/dev/null
  until_ok 60 "rowsafe logs shop --kind slow_query --since 24h shows it" sh -c "rowsafe logs shop --kind slow_query --since 24h | grep -q pg_sleep"

  # Forwarding errors to a webhook next to the server, from the server.
  rowsafe logs forward --url "$HOOK_URL" --kinds errors >/tmp/fwd.out 2>&1 || { cat /tmp/fwd.out; fail "rowsafe logs forward"; }
  grep -q "whsec_" /tmp/fwd.out || { cat /tmp/fwd.out; fail "no signing secret"; }
  rowsafe logs forward | grep -q webhook || fail "rowsafe logs forward (list)"
  psql_app -c "SELECT 1/0 AS forwarded_e2e" 2>/dev/null && fail "division by zero should fail"
  until_ok 60 "the error is delivered" sh -c "rowsafe logs forward list --json | grep -q '\"delivered\": [1-9]'"

  # The agent restarts: the entries are still there.
  systemctl restart rowsafe-agent
  until_ok 30 "the control plane is back" test -S /var/lib/rowsafe/control.sock
  rowsafe logs shop --errors | grep -q missing_table_e2e || fail "the entries are gone after a restart"
  echo "  ok: the entries survive the agent restarting"

  # Bounded: two files at most, small.
  ls /var/lib/rowsafe/local-logs
  [ "$(find /var/lib/rowsafe/local-logs -type f | wc -l)" -le 2 ] || fail "more than two log files"
  kb=$(du -sk /var/lib/rowsafe/local-logs | cut -f1)
  [ "$kb" -le 16500 ] || fail "the kept logs take ${kb} KB"
  stat -c '%a %U' /var/lib/rowsafe/local-logs/current.jsonl | grep -q '^600 postgres$' || fail "the log file's permissions"
  echo "  ok: the kept logs take ${kb} KB, readable by the agent only"

  # Off: no longer kept.
  rowsafe logs set shop --send off | grep -q "kept on this server off" || fail "rowsafe logs set --send off"
  sleep 6
  psql_app -c "SELECT * FROM while_off_e2e" 2>/dev/null || true
  sleep 12
  ! rowsafe logs shop --grep while_off_e2e | grep -q while_off_e2e || fail "kept while off"
  rowsafe logs shop --grep while_off_e2e | grep -q "aren't kept on this server" || fail "no word that logs are off"
  echo "  ok: off, nothing is kept"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-no-account-logs: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-noaccount-logs.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-noaccount-logs-$$
  cleanup() {
    docker rm -f "$name-pg" "$name-hook" >/dev/null 2>&1 || true
    docker volume rm "$name-pgdata" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
    rm -rf "$W"
  }
  trap cleanup EXIT INT TERM

  echo "building rowsafe-agent and rowsafe (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe-agent" ./cmd/rowsafe-agent &&
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe" ./cmd/rowsafe)

  docker network create "$name" >/dev/null
  # A webhook receiver: prints each request's signature and body.
  cat >"$W/hook.py" <<'PY'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        print("X-Rowsafe-Signature: %s %s" % (self.headers.get("X-Rowsafe-Signature"), body), flush=True)
        self.send_response(204)
        self.end_headers()
http.server.HTTPServer(("", 8080), H).serve_forever()
PY
  docker run -d --name "$name-hook" --network "$name" --network-alias hook -v "$W/hook.py:/hook.py:ro" \
    python:3.13-alpine python3 -u /hook.py >/dev/null

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
      echo "test-no-account-logs: systemd did not start in the container" >&2
      exit 1
    }
    sleep 1
  done
  docker exec -e HOOK_URL="http://hook:8080/rowsafe-logs" "$name-pg" sh /src/scripts/test-no-account-logs.sh --in-container
  docker logs "$name-hook" 2>/dev/null >"$W/hook.out"
  grep -q 'X-Rowsafe-Signature: t=.*,v1=.*"event":"logs"' "$W/hook.out" || {
    cat "$W/hook.out" >&2
    echo "test-no-account-logs: the webhook didn't get signed logs" >&2
    exit 1
  }
  grep -q '"database_name":"shop".*division by zero' "$W/hook.out" || {
    cat "$W/hook.out" >&2
    echo "test-no-account-logs: the webhook didn't get the error" >&2
    exit 1
  }
  ! grep -q 'missing_table_e2e\|pg_sleep' "$W/hook.out" || {
    cat "$W/hook.out" >&2
    echo "test-no-account-logs: the webhook got entries from before it was added, or not errors" >&2
    exit 1
  }
  echo "  ok: the webhook got the error, signed, and nothing else"
  echo "test-no-account-logs: passed on $image"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
