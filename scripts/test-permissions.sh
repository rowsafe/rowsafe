#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test one-click permission changes on a real server: Debian with systemd as
# PID 1, the rowsafe-permissions units taken from scripts/install.sh, root's
# copy of rowsafe-agent built from this repository, and a stand-in for root's
# installer copy that records how it was run. Requests signed with a real
# passkey key (internal/permissions/fixtures_test.go) are handed over the way
# the agent does, as the postgres user:
#
#   a signed change is verified and applied (the installer runs with the
#   exact --allow-X/--no-allow-X flags, as root, sandboxed: no network,
#   no new privileges); the same change again is refused (used before); a
#   passkey root didn't pair, a change for another server, a request that is
#   a symbolic link, an owners file others can write and a missing installer
#   are refused without running anything; `rowsafe-permissions owners` and
#   `remove-owner`; the agent's own copy (not root's) refuses to pair as
#   root, and pairing needs a terminal. Root never leaves files in the
#   agent's directory.
#
# Usage: sh scripts/test-permissions.sh [debian:trixie]   (needs Docker and network, ~2 min)

set -eu

fail() {
  echo "  FAIL $*" >&2
  journalctl -u rowsafe-permissions.service --no-pager -n 40 >&2 2>/dev/null || true
  exit 1
}
pass() { echo "  ok   $*"; }

# hand_over FIXTURE: the agent's way (as postgres, atomic rename).
hand_over() {
  rm -f /run/rowsafe-permissions/result
  runuser -u postgres -- sh -c "cp /w/fixtures/$1 /var/lib/rowsafe/permissions/.request.tmp && mv /var/lib/rowsafe/permissions/.request.tmp /var/lib/rowsafe/permissions/request"
  wait_answer
}

wait_answer() {
  i=0
  until [ -s /run/rowsafe-permissions/result ]; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || fail "no answer from the helper"
    sleep 0.3
  done
}

answer_has() { grep -qF "$1" /run/rowsafe-permissions/result || fail "answer lacks $1: $(cat /run/rowsafe-permissions/result)"; }

in_container() {
  useradd --system --home-dir /var/lib/postgresql --shell /bin/sh postgres
  install -d -m 0755 /usr/local/lib/rowsafe
  install -d -m 0750 -o root -g postgres /etc/rowsafe
  install -d -m 0700 -o postgres -g postgres /var/lib/rowsafe /var/lib/rowsafe/permissions
  install -m 0755 /w/rowsafe-agent /usr/local/lib/rowsafe/rowsafe-permissions
  # The units, exactly as the installer writes them.
  sed -n "/<<'ROWSAFE_PERMISSIONS_SERVICE_EOF' |/,/^ROWSAFE_PERMISSIONS_SERVICE_EOF\$/p" /src/scripts/install.sh | sed '1d;$d' |
    sed 's/@AGENT_USER@/postgres/' >/etc/systemd/system/rowsafe-permissions.service
  sed -n "/<<'ROWSAFE_PERMISSIONS_PATH_EOF'; then\$/,/^ROWSAFE_PERMISSIONS_PATH_EOF\$/p" /src/scripts/install.sh | sed '1d;$d' \
    >/etc/systemd/system/rowsafe-permissions.path
  grep -q '^ExecStart=/usr/local/lib/rowsafe/rowsafe-permissions apply$' /etc/systemd/system/rowsafe-permissions.service || fail "service unit not extracted"
  grep -q '^PathExists=' /etc/systemd/system/rowsafe-permissions.path || fail "path unit not extracted"
  # Root's installer copy, stood in: records its flags and what the sandbox allows.
  cat >/usr/local/lib/rowsafe/install.sh <<'SH'
#!/bin/sh
{
  echo "args=$*"
  echo "uid=$(id -u)"
  if timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then echo "network=yes"; else echo "network=no"; fi
  grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status && echo "nnp=yes"
} >>/var/lib/installer-calls
touch /etc/rowsafe/installer-wrote-here
echo "Rowsafe may install security updates when you click Install and confirm"
SH
  chmod 0755 /usr/local/lib/rowsafe/install.sh
  install -m 0644 /w/fixtures/owners /etc/rowsafe/owners
  install -m 0600 -o postgres -g postgres /w/fixtures/agent.json /var/lib/rowsafe/agent.json
  systemctl daemon-reload
  systemctl enable --now --quiet rowsafe-permissions.path
  command -v systemd-analyze >/dev/null && systemd-analyze security --offline=true --no-pager /etc/systemd/system/rowsafe-permissions.service 2>/dev/null |
    tail -n 1 | sed "s/^/  rowsafe-permissions: /" || true

  hand_over request-ok.json
  answer_has '"id":"task-1"'
  answer_has '"applied":true'
  answer_has 'Rowsafe may install security updates'
  grep -qx 'args=--permissions --no-prompt --allow-security-updates --no-allow-reboot' /var/lib/installer-calls || fail "installer flags: $(cat /var/lib/installer-calls)"
  grep -qx 'uid=0' /var/lib/installer-calls || fail "the installer didn't run as root"
  grep -qx 'nnp=yes' /var/lib/installer-calls || fail "the installer could gain privileges"
  ! grep -qx 'network=yes' /var/lib/installer-calls || fail "the installer reached the network"
  if ! timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then
    echo "  note: this container has no network, so the sandbox's network check proves little"
  fi
  [ -e /etc/rowsafe/installer-wrote-here ] || fail "the installer couldn't write /etc/rowsafe"
  [ ! -e /var/lib/rowsafe/permissions/request ] || fail "the request was left behind"
  [ "$(stat -c '%U %a' /run/rowsafe-permissions/result)" = "root 644" ] || fail "answer ownership/mode"
  [ "$(stat -c '%U %a' /var/lib/rowsafe-permissions)" = "root 700" ] || fail "state directory ownership/mode"
  journalctl -u rowsafe-permissions.service --no-pager | grep -q "verified a change signed by ana@example.com" || fail "decision not in the journal"
  pass "a signed change is verified and applied by root's installer (exact flags, sandboxed, journaled)"

  calls=$(wc -l </var/lib/installer-calls)
  hand_over request-replay.json
  answer_has '"id":"task-2"'
  answer_has 'applied before'
  hand_over request-other-key.json
  answer_has '"id":"task-3"'
  answer_has "isn't one root paired"
  hand_over request-other-host.json
  answer_has '"id":"task-4"'
  answer_has 'another server'
  [ "$(wc -l </var/lib/installer-calls)" = "$calls" ] || fail "the installer ran for a refused request"
  pass "replayed, unpaired passkey and other server: refused, nothing run"

  rm -f /run/rowsafe-permissions/result
  runuser -u postgres -- ln -s /etc/shadow /var/lib/rowsafe/permissions/request
  wait_answer
  answer_has "couldn't read the request"
  [ -s /etc/shadow ] && [ ! -L /var/lib/rowsafe/permissions/request ] || fail "symlinked request: wrong file removed or link left"
  rm -f /run/rowsafe-permissions/result
  runuser -u postgres -- mkfifo /var/lib/rowsafe/permissions/request
  wait_answer
  answer_has "couldn't read the request"
  pass "a symbolic link or FIFO as the request: refused, read and removed as the agent user only"

  chmod 0664 /etc/rowsafe/owners
  hand_over request-fresh-1.json
  answer_has "can't be trusted"
  chmod 0644 /etc/rowsafe/owners
  mv /usr/local/lib/rowsafe/install.sh /usr/local/lib/rowsafe/install.sh.off
  hand_over request-fresh-2.json
  answer_has "is missing"
  mv /usr/local/lib/rowsafe/install.sh.off /usr/local/lib/rowsafe/install.sh
  [ "$(wc -l </var/lib/installer-calls)" = "$calls" ] || fail "the installer ran for a refused request"
  pass "owners file others can write, missing installer: refused"

  fp=$(cat /w/fixtures/fingerprint)
  /usr/local/lib/rowsafe/rowsafe-permissions owners >/var/tmp/out 2>&1 || fail "owners: $(cat /var/tmp/out)"
  grep -q "$fp  ana@example.com" /var/tmp/out || fail "owners lists: $(cat /var/tmp/out)"
  /usr/local/lib/rowsafe/rowsafe-permissions remove-owner "$fp" >/var/tmp/out 2>&1 || fail "remove-owner: $(cat /var/tmp/out)"
  grep -q "can no longer change" /var/tmp/out || fail "remove-owner says: $(cat /var/tmp/out)"
  [ "$(stat -c '%U %G %a' /etc/rowsafe/owners)" = "root root 644" ] || fail "owners file ownership/mode after a change"
  hand_over request-fresh-3.json
  answer_has 'no passkey is paired'
  pass "owners and remove-owner (then every signed change is refused)"

  # Turning off needs no passkey: applied with none paired, but never the
  # firewall (its rule would go).
  hand_over request-remove.json
  answer_has '"id":"task-8"'
  answer_has '"applied":true'
  tail -n 4 /var/lib/installer-calls | grep -qx 'args=--permissions --no-prompt --no-allow-restart --no-allow-reboot' ||
    fail "removal flags: $(tail -n 4 /var/lib/installer-calls)"
  journalctl -u rowsafe-permissions.service --no-pager | grep -q "turn off \[reboot restart\], requested by ana@example.com" || fail "removal not in the journal"
  calls=$(wc -l </var/lib/installer-calls)
  hand_over request-remove-firewall.json
  answer_has 'needs a passkey'
  [ "$(wc -l </var/lib/installer-calls)" = "$calls" ] || fail "the installer ran to turn off the firewall without a passkey"
  [ "$(runuser -u postgres -- /usr/local/lib/rowsafe/rowsafe-permissions features)" = remove-without-passkey ] || fail "features as the agent user"
  pass "turning off without a passkey: applied with none paired, never the firewall; the agent can ask what the helper takes"

  install -d -m 0755 -o postgres -g postgres /opt/rowsafe
  install -m 0755 -o postgres -g postgres /w/rowsafe-agent /opt/rowsafe/rowsafe-agent
  if /opt/rowsafe/rowsafe-agent permissions pair >/var/tmp/out 2>&1 </dev/null; then fail "root paired with the agent user's binary"; fi
  grep -q "refusing to run as root from a binary" /var/tmp/out || fail "agent copy: $(cat /var/tmp/out)"
  if setsid /usr/local/lib/rowsafe/rowsafe-permissions pair >/var/tmp/out 2>&1 </dev/null; then fail "paired without a terminal"; fi
  grep -q "confirmed by a person at this server" /var/tmp/out || fail "no terminal: $(cat /var/tmp/out)"
  if runuser -u postgres -- /usr/local/lib/rowsafe/rowsafe-permissions apply >/var/tmp/out 2>&1; then fail "apply ran as the agent user"; fi
  pass "root never runs the agent user's binary; pairing needs a terminal; only root applies"

  [ -z "$(find /var/lib/rowsafe -user root)" ] || fail "root left files in the agent's directory: $(find /var/lib/rowsafe -user root)"
  pass "root left nothing in the agent's directory"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-permissions: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-permissions.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-permissions-$$
  cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$W"
  }
  trap cleanup EXIT INT TERM

  echo "building rowsafe-agent (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$W/rowsafe-agent" ./cmd/rowsafe-agent)
  tag=rowsafe-test/systemd:$(echo "$image" | tr ':/' '--')
  echo "building $tag"
  docker build -q -t "$tag" - >/dev/null <<DOCKERFILE
FROM $image
ENV container=docker
RUN apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus procps util-linux >/dev/null && \\
    rm -f /lib/systemd/system/multi-user.target.wants/getty* && apt-get clean && rm -rf /var/lib/apt/lists/*
# (binfmt masked: a privileged container shares the host's binfmt_misc, and
# systemd-binfmt unregisters every entry when it stops, emulation included.)
RUN ln -sf /dev/null /etc/systemd/system/systemd-binfmt.service && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.automount && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.mount
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
DOCKERFILE
  docker run -d --name "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
    -v "$root:/src:ro" -v "$W:/w" "$tag" >/dev/null
  i=0
  until docker exec "$name" systemctl is-system-running --wait >/dev/null 2>&1 ||
    [ "$(docker exec "$name" systemctl is-system-running 2>/dev/null)" = degraded ]; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || {
      echo "test-permissions: systemd did not start in the container" >&2
      exit 1
    }
    sleep 1
  done
  # Signed requests expire in minutes: made now.
  mkdir -p "$W/fixtures"
  (cd "$root" && ROWSAFE_PERMISSIONS_FIXTURES="$W/fixtures" go test -count=1 -run '^TestWriteFixtures$' ./internal/permissions >/dev/null)
  chmod -R a+rX "$W/fixtures"
  docker exec "$name" sh /src/scripts/test-permissions.sh --in-container
  echo "test-permissions: passed on $image"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
