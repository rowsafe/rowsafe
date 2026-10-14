#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test backups to an SFTP server for real: a Debian container with
# PostgreSQL, pgBackRest and an OpenSSH server (port 2222, user "u123",
# keys only) standing in for a Hetzner Storage Box.
#
#   1. the installer's SFTP setup (its own functions, sourced): refusals
#      (another engine, missing settings, user@host, an old pgBackRest),
#      the SSH key made as postgres (0600) and its public half shown with
#      how to add it, "add this key, then run the install command again"
#      while the server doesn't accept it (nothing written there), the host
#      key trusted on first use and said so, then pinned; a given
#      fingerprint or known_hosts line that matches, another of the
#      server's keys and a wrong key refused loudly; --check-storage;
#   2. the agent's own code (internal/agent/sftp_e2e_test.go, built with
#      -tags sftp_e2e) as postgres with those settings: adopt, check, a full
#      backup, Proof, a Rewind copy, storage use reported as provider sftp,
#      the storage test, and a changed host key stopping everything.
#
# Usage: sh scripts/test-sftp.sh [debian:trixie]   (needs Docker, ~2 min)

set -eu

pass() { echo "  ok   $*"; }
tfail() {
  echo "  FAIL $*" >&2
  echo "---- output" >&2
  cat "$W/out" >&2 2>/dev/null || true
  exit 1
}
has() { grep -qF -- "$1" "$W/out" || tfail "$2: output lacks: $1"; }
lacks() { ! grep -qF -- "$1" "$W/out" || tfail "$2: output has: $1"; }

# setup NAME: runs the installer's sftp_storage in a subshell (it exits on
# errors), its output in $W/out, what it exported in $W/exported.
setup() {
  rc=0
  (
    sftp_storage
    env | grep '^ROWSAFE_REPO_' | sort >"$W/exported"
  ) >"$W/out" 2>&1 </dev/null || rc=$?
  [ -z "${TEST_SHOW:-}" ] || sed 's/^/      | /' "$W/out"
}
expect_ok() { setup && [ "$rc" = 0 ] || tfail "$1 (exit $rc)"; pass "$1"; }
expect_fail() {
  rm -f "$W/exported"
  setup
  [ "$rc" != 0 ] || tfail "$1: succeeded"
  has "$2" "$1"
  [ ! -f "$W/exported" ] || tfail "$1: exported settings"
  pass "$1"
}
fp_of() { ssh-keygen -lf "$1" | awk '{ print $2 }'; }
# with VAR=VALUE CMD...: CMD with VAR set, in a subshell (a failure exits).
with() { (_kv=$1 && shift && export "${_kv?}" && "$@") || exit 1; }

in_container() {
  W=/w
  install -d -m 0755 "$W"

  # The SFTP server.
  useradd -m -s /bin/sh u123
  install -d -m 0700 -o u123 -g u123 /home/u123/.ssh
  install -m 0600 -o u123 -g u123 /dev/null /home/u123/.ssh/authorized_keys
  mkdir -p /run/sshd
  ssh-keygen -A >/dev/null
  # Many short connections from one place here: OpenSSH 9.8's penalties
  # for them would refuse later cases. (The installer itself connects only
  # a few times per run: a host key mismatch adds one scan.)
  penalties=''
  ! /usr/sbin/sshd -t -o PerSourcePenalties=no 2>/dev/null || penalties='-o PerSourcePenalties=no'
  # shellcheck disable=SC2086 # one option or none
  /usr/sbin/sshd -p 2222 -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no $penalties

  # PostgreSQL, archiving on from the start (adopt needs no restart).
  major=$(ls /usr/lib/postgresql)
  cat >>"/etc/postgresql/$major/main/postgresql.conf" <<CONF
wal_level = replica
archive_mode = on
archive_command = ''
CONF
  pg_ctlcluster "$major" main start

  # The installer's functions, without running it.
  sed '$d' /src/scripts/install.sh >"$W/install-lib.sh"
  # shellcheck disable=SC1091
  . "$W/install-lib.sh"
  # shellcheck disable=SC2034 # the installer's globals
  TMP=$(mktemp -d) HOST_ENGINE=postgresql
  install -d -m 0750 -o root -g postgres "$CONFIG_DIR"
  install -d -m 0700 -o postgres -g postgres "$CONFIG_DIR/pgbackrest"
  pgbackrest version
  echo "  -- the installer's SFTP setup"

  ROWSAFE_REPO_TYPE=sftp ROWSAFE_REPO_SFTP_HOST=127.0.0.1 ROWSAFE_REPO_SFTP_PORT=2222
  ROWSAFE_REPO_SFTP_USER=u123 ROWSAFE_REPO_SFTP_PATH=/home/u123/rowsafe/
  export ROWSAFE_REPO_TYPE ROWSAFE_REPO_SFTP_HOST ROWSAFE_REPO_SFTP_PORT ROWSAFE_REPO_SFTP_USER ROWSAFE_REPO_SFTP_PATH

  with HOST_ENGINE=mysql expect_fail "another engine refused" "work for PostgreSQL only for now"
  with ROWSAFE_REPO_SFTP_USER='' expect_fail "a missing user refused" "need: ROWSAFE_REPO_SFTP_USER"
  with ROWSAFE_REPO_SFTP_HOST=u123@127.0.0.1 expect_fail "user@host refused" "put the user name in ROWSAFE_REPO_SFTP_USER"
  with ROWSAFE_REPO_SFTP_PATH=/a/../b expect_fail "a path with .. refused" "must be a directory on the SFTP server"
  with STORAGE_PROVIDER=rowsafe expect_fail "Rowsafe Storage too refused" "choose one"
  printf '#!/bin/sh\necho "pgBackRest 2.44"\n' >"$W/old-pgbackrest" && chmod 755 "$W/old-pgbackrest"
  with ROWSAFE_PGBACKREST_BIN=$W/old-pgbackrest expect_fail "an old pgBackRest refused" "need pgBackRest 2.48 or later"
  [ ! -e "$CONFIG_DIR/pgbackrest/sftp_ed25519" ] || tfail "a refused setup made a key"

  expect_fail "the key not added yet" "add this key, then run the install command again"
  key=$CONFIG_DIR/pgbackrest/sftp_ed25519
  [ "$(stat -c '%U %a' "$key")" = "postgres 600" ] || tfail "key: $(stat -c '%U %a' "$key")"
  [ "$(stat -c '%U' "$key.pub")" = postgres ] || tfail "public key owner"
  has "$(cat "$key.pub")" "the public key shown"
  has "Append it to ~/.ssh/authorized_keys of u123 on 127.0.0.1" "how to add it"
  has "Trust on first use" "trust on first use said plainly"
  lacks "PRIVATE KEY" "the private key never shown"
  [ ! -e /home/u123/rowsafe ] || tfail "something was written on the SFTP server"
  pass "key made as postgres (0600), shown, nothing written yet"

  # The agent's user can't read root's files: as the SFTP server's admin.
  cat "$key.pub" >>/home/u123/.ssh/authorized_keys

  expect_ok "the key added: set up"
  has "backup storage works: wrote, read back and deleted a test file on the SFTP server" "test file"
  has "pinned the SFTP server's host key" "pinned"
  pinned=$(sed -n 's/^ROWSAFE_REPO_SFTP_HOST_KEY=//p' "$W/exported")
  ecdsa=$(fp_of /etc/ssh/ssh_host_ecdsa_key.pub)
  ed=$(fp_of /etc/ssh/ssh_host_ed25519_key.pub)
  case $pinned in "$ecdsa" | "$ed" | "$(fp_of /etc/ssh/ssh_host_rsa_key.pub)") ;; *) tfail "pinned $pinned is none of the server's keys" ;; esac
  has "$pinned" "the pinned fingerprint shown"
  grep -qx 'ROWSAFE_REPO_TYPE=sftp' "$W/exported" || tfail "type not exported"
  grep -qx 'ROWSAFE_REPO_SFTP_PATH=/home/u123/rowsafe' "$W/exported" || tfail "path not normalized"
  pass_=$(sed -n 's/^ROWSAFE_REPO_CIPHER_PASS=//p' "$W/exported")
  [ "${#pass_}" = 40 ] || tfail "no passphrase generated"
  lacks "$pass_" "the passphrase never printed"
  [ -d /home/u123/rowsafe ] && [ -z "$(ls -A /home/u123/rowsafe)" ] || tfail "test file left on the SFTP server"
  pass "host key $pinned pinned, passphrase generated and not shown"
  cp "$W/exported" "$W/settings"

  if [ "$pinned" = "$ecdsa" ]; then pinned_type=ecdsa-sha2-nistp256 other_fp=$ed other_type=ssh-ed25519; else pinned_type=ssh-ed25519 other_fp=$ecdsa other_type=ecdsa-sha2-nistp256; fi
  with ROWSAFE_REPO_SFTP_HOST_KEY=$pinned expect_ok "a given fingerprint that matches"
  has "the SFTP server's host key matches" "matches"
  lacks "Trust on first use" "no trust on first use with a given key"
  line=$(ssh-keyscan -p 2222 -t "$pinned_type" 127.0.0.1 2>/dev/null | grep -v "^#" | head -n 1)
  with "ROWSAFE_REPO_SFTP_HOST_KEY=$line" expect_ok "a given known_hosts line that matches"
  with ROWSAFE_REPO_SFTP_HOST_KEY=$other_fp expect_fail "another of the server's keys refused" "Yours is the server's $other_type key"
  with "ROWSAFE_REPO_SFTP_HOST_KEY=SHA256:$(head -c 32 /dev/urandom | base64 | tr -d '=')" expect_fail "a wrong host key refused" "Someone may be between this server and 127.0.0.1"
  has "nothing was sent to the SFTP server and nothing was changed" "nothing sent"
  with ROWSAFE_REPO_SFTP_HOST_KEY=MD5:aa:bb expect_fail "an MD5 fingerprint refused" "MD5 fingerprints are not enough"

  echo "  -- agent.env"
  # The installer's own path: maybe_guided_storage sets up the SFTP server,
  # write_env saves it, and nothing is missing but the enrollment.
  rc=0
  (
    maybe_guided_storage
    write_env
    echo "missing: $(missing_config)"
  ) >"$W/out" 2>&1 </dev/null || rc=$?
  [ "$rc" = 0 ] || tfail "the installer's storage step (exit $rc)"
  has "missing: ROWSAFE_ENROLL_TOKEN" "only the enrollment missing"
  for kv in "ROWSAFE_REPO_TYPE='sftp'" "ROWSAFE_REPO_SFTP_HOST='127.0.0.1'" "ROWSAFE_REPO_SFTP_PORT='2222'" \
    "ROWSAFE_REPO_SFTP_USER='u123'" "ROWSAFE_REPO_SFTP_PATH='/home/u123/rowsafe'" "ROWSAFE_REPO_SFTP_HOST_KEY='$pinned'"; do
    grep -qxF "$kv" "$ENV_FILE" || tfail "agent.env lacks $kv: $(grep SFTP "$ENV_FILE")"
  done
  ! grep -q '^ROWSAFE_REPO_SFTP_KEY_FILE=' "$ENV_FILE" || tfail "the default key file was written"
  [ "$(stat -c '%U %a' "$ENV_FILE")" = "postgres 600" ] || tfail "agent.env: $(stat -c '%U %a' "$ENV_FILE")"
  pass "agent.env has the SFTP server and its pinned host key"

  echo "  -- --check-storage"
  unset ROWSAFE_REPO_TYPE ROWSAFE_REPO_SFTP_HOST ROWSAFE_REPO_SFTP_PORT ROWSAFE_REPO_SFTP_USER ROWSAFE_REPO_SFTP_PATH
  rc=0
  (check_storage) >"$W/out" 2>&1 || rc=$?
  [ "$rc" = 0 ] || tfail "--check-storage (exit $rc)"
  has "backup storage works" "--check-storage"
  pass "--check-storage tests the SFTP server with the pinned key"
  sed -i "s/^ROWSAFE_REPO_SFTP_HOST_KEY=.*/ROWSAFE_REPO_SFTP_HOST_KEY='$other_fp'/" "$ENV_FILE"
  rc=0
  (check_storage) >"$W/out" 2>&1 || rc=$?
  [ "$rc" != 0 ] || tfail "--check-storage with another host key passed"
  has "presented a different host key than the pinned one" "--check-storage, changed key"
  pass "--check-storage refuses a host key that isn't the pinned one"

  echo "  -- the agent, for real"
  install -d -m 0700 -o postgres -g postgres "$W/agent"
  status=0
  # shellcheck disable=SC2046 # one setting per word (no spaces in them)
  runuser -u postgres -- env $(cat "$W/settings") SFTP_WORK="$W/agent" \
    /t/sftp-e2e.test -test.run '^TestRealSFTP$' -test.v -test.timeout 15m || status=$?
  if [ "$status" != 0 ]; then
    echo "---- PostgreSQL log" >&2
    tail -n 60 /var/log/postgresql/*.log >&2 2>/dev/null || true
    exit "$status"
  fi
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-sftp: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  T=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-sftp.XXXXXX")
  chmod 0755 "$T"
  name=rowsafe-sftp-$$
  cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$T"
  }
  trap cleanup EXIT INT TERM

  echo "building the test (linux/$arch)"
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go test -c -tags sftp_e2e -o "$T/sftp-e2e.test" ./internal/agent)
  chmod 0755 "$T/sftp-e2e.test"

  tag=rowsafe-test/sftp:$(echo "$image" | tr ':/' '--')
  echo "building $tag"
  docker build -q -t "$tag" - >/dev/null <<DOCKERFILE
FROM $image
RUN apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends ca-certificates procps util-linux postgresql pgbackrest \\
      openssh-server openssh-client >/dev/null && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*
DOCKERFILE
  docker run --rm --name "$name" --shm-size 256m -e TEST_SHOW="${TEST_SHOW:-}" \
    -v "$root:/src:ro" -v "$T:/t:ro" "$tag" sh /src/scripts/test-sftp.sh --in-container
  echo "test-sftp: passed on $image"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
