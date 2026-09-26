#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests scripts/install.sh in throwaway containers, one per supported system:
#
#   1. signature verification: a good release installs; tampered manifests,
#      wrong keys, bad checksums/sizes, version mismatches, http URLs and a
#      missing platform are all refused before anything is written;
#   2. a full install: unconfigured (enabled, not started), configured
#      (self-test, env file merge, no secrets printed), idempotent re-run,
#      upgrade, downgrade refusal, failing self-test keeps the old version,
#      uninstall, and --purge refusing while PostgreSQL still archives WAL;
#   3. on the first image, `systemd-analyze verify` and an offline security
#      review of both systemd units;
#   4. the guided storage setup, driven on a real pseudo-terminal (drive.py)
#      against a local S3 that checks SigV4 signatures (fakes3.py): R2 with a
#      generated passphrase that is shown once and must be confirmed, failed
#      storage tests explained (bucket, key, secret, region, clock, DNS),
#      re-runs that keep or change settings, a passphrase of one's own,
#      Ctrl-C at a hidden prompt, --check-storage and --no-prompt. Secrets
#      must never reach the terminal. Pasted bucket URLs (R2, B2, S3, Wasabi,
#      Spaces, any https endpoint) fill in the provider, endpoint and bucket.
#      The second copy (--add-storage): the first storage's bucket refused,
#      its own generated passphrase, kept on a re-run, tested by
#      --check-storage, without a terminal, and --remove-second-copy;
#   5. turning on backups after the install, with a stand-in agent whose
#      `setup` answers come from files: found PostgreSQL, name, plan, "Turn on
#      backups?", "Restart PostgreSQL now?" (yes, no), a taken name, another
#      archiver, an already registered database, --protect and --no-setup;
#   5b. Rowsafe Storage: the "where should backups go?" choice when the
#      control plane offers it (fakes3.py answers /v1/storage/offer), the
#      passphrase, --storage rowsafe without a terminal (passphrase generated
#      and never printed), the agent's storage test, moving to one's own
#      bucket and back, and --check-storage;
#   6. restarts on request (--allow-restart): the allow list, the root
#      helper's checks (unlisted port, garbage, symlinks, FIFOs, once a
#      minute; root never writes in the agent's directory), its stop and
#      start actions for Rewind (listed unit only, malformed actions
#      refused), the installer
#      not following symlinks planted in the agent's directories, and
#      --no-allow-restart / uninstall removing it;
#   7. updates on request (--allow-updates, --allow-security-updates,
#      --allow-reboot): the allow list and units, and the helper's update
#      mode with apt, dpkg and Debian's cluster tools stood in: exact
#      request shapes, what isn't allowed, a minor update (only that major's
#      packages, restarted), installing a major (the package's own cluster
#      dropped), an upgrade (allow list moved, record kept), its undo and
#      cleanup, a failed upgrade rolled back, security updates (PostgreSQL
#      held back) and a reboot.
#   8. PgBouncer on request (--allow-pooler): the allow list and units, the
#      helper in PgBouncer mode (install, configure from its template,
#      reload, off, refused values and foreign configurations) with apt-get
#      and systemctl stood in, and --no-allow-pooler.
#
# When Go is available the release key and the 0.2.0 release are made by the
# real `rowsafe-release keygen/manifest/sign`, so the installer is tested
# against exactly what `make release` publishes.
#
# Usage: scripts/test-install.sh [IMAGE...]
# Default images: debian:trixie debian:bookworm ubuntu:24.04 ubuntu:22.04

set -eu

# ------------------------------------------------------------ shared helpers

# fake_agent VERSION [fail] prints a stand-in agent: a shell script that
# answers `version`, `selftest` and `inspect` like the real binary.
fake_agent() {
  cat <<EOF
#!/bin/sh
# fake rowsafe-agent $1 for installer tests
case \${1:-} in
  version) echo $1 ;;
  selftest)
    if [ "${2:-}" = fail ]; then
      echo '{"version":"$1","platform":"linux/x","ok":false,"checks":[],"errors":["control plane: dial tcp 127.0.0.1:443: connect: connection refused","pgbackrest: exit status 1"]}'
      exit 1
    fi
    # The installer must run the self-test as postgres with agent.env loaded.
    # (as mysql on a MySQL server)
    if { [ "\$(id -un)" != postgres ] && [ "\$(id -un)" != mysql ]; } || [ -z "\${ROWSAFE_REPO_CIPHER_PASS:-}" ]; then
      echo '{"version":"$1","ok":false,"errors":["config: not run as postgres with agent.env"]}'
      exit 1
    fi
    echo '{"version":"$1","platform":"linux/x","ok":true,"checks":["config","repository settings","pgbackrest","control plane"]}' ;;
  inspect)
    printf '{\n  "server_version": "17.6 (Debian 17.6-1)",\n  "data_directory": "/var/lib/postgresql/17/main",\n  "archive_mode": "off"\n}\n' ;;
  run) i=0; while [ \$i -lt 1800 ]; do sleep 1; i=\$((i + 1)); done ;; # at most 30 minutes, even if nothing kills it
  storage)
    # Rowsafe Storage test: must run as postgres with agent.env loaded.
    f=/tmp/rowsafe-fake
    echo "storage \$*" >>"\$f/calls" 2>/dev/null || true
    if [ "\$(id -un)" != postgres ] || [ "\${ROWSAFE_STORAGE:-}" != rowsafe ]; then
      echo "storage test must run as postgres with ROWSAFE_STORAGE=rowsafe from agent.env" >&2
      exit 1
    fi
    if [ -s "\$f/storage.rc" ] && [ "\$(cat "\$f/storage.rc")" != 0 ]; then
      echo "error: no Rowsafe Storage credentials: control plane returned 503: storage unavailable" >&2
      exit 1
    fi
    echo "writing, reading and deleting a test file in Rowsafe Storage..."
    echo "Rowsafe Storage works: wrote, read back and deleted a test file" ;;
  setup)
    # Answers from /tmp/rowsafe-fake: CMD.out is printed, CMD.rc holds exit
    # codes (one per line, used in turn; the last one sticks).
    f=/tmp/rowsafe-fake
    shift
    echo "\$*" >>"\$f/calls"
    if [ "\$(id -un)" != postgres ] || [ -z "\${ROWSAFE_REPO_CIPHER_PASS:-}" ] || [ -n "\${ROWSAFE_TEST_LEAK:-}" ]; then
      echo "setup must run as postgres with only agent.env" >&2
      exit 1
    fi
    cmd=\$1
    shift
    while [ \$# -gt 0 ]; do
      [ "\$1" != --id-file ] || echo db_fake >"\$2"
      shift
    done
    [ ! -f "\$f/\$cmd.out" ] || cat "\$f/\$cmd.out"
    rc=0
    if [ -s "\$f/\$cmd.rc" ]; then
      rc=\$(head -n 1 "\$f/\$cmd.rc")
      [ "\$(wc -l <"\$f/\$cmd.rc")" -le 1 ] || sed -i 1d "\$f/\$cmd.rc"
    fi
    exit "\$rc" ;;
  *) exit 2 ;;
esac
EOF
}

# ------------------------------------------------------------ host side

host() {
  root=$(cd "$(dirname "$0")/.." && pwd)
  images=${*:-debian:trixie debian:bookworm ubuntu:24.04 ubuntu:22.04}
  docker info >/dev/null 2>&1 || {
    echo "test-install: Docker is not running" >&2
    exit 1
  }
  work=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-test-install.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  mkdir -p "$work/go"

  TEST_PUB='' TEST_PRIV=''
  if command -v go >/dev/null 2>&1 && (cd "$root" && CGO_ENABLED=0 go build -o "$work/rowsafe-release" ./cmd/rowsafe-release) 2>"$work/build.log"; then
    keys=$("$work/rowsafe-release" keygen)
    TEST_PUB=$(printf '%s\n' "$keys" | sed -n 's/^public: //p')
    TEST_PRIV=$(printf '%s\n' "$keys" | sed -n 's/^private: //p')
    d=$work/go/0.2.0
    mkdir -p "$d"
    for arch in amd64 arm64; do
      fake_agent 0.2.0 >"$d/rowsafe-agent-linux-$arch"
    done
    "$work/rowsafe-release" manifest --version 0.2.0 --base-url https://localhost:8443/agent --dist "$d" >"$d/manifest.json"
    ROWSAFE_RELEASE_PRIVATE_KEY=$TEST_PRIV "$work/rowsafe-release" sign "$d/manifest.json" 2>/dev/null
    "$work/rowsafe-release" verify --public-key "$TEST_PUB" "$d/manifest.json" "$d/manifest.json.sig" >/dev/null
    echo "test-install: release 0.2.0 made and signed by rowsafe-release"
  else
    echo "test-install: rowsafe-release unavailable; signing everything with openssl" >&2
  fi

  first=1
  for image in $images; do
    echo "=== $image"
    docker run --rm \
      -e TEST_PUB="$TEST_PUB" -e TEST_PRIV="$TEST_PRIV" -e TEST_UNITS="$first" -e TEST_SHOW="${TEST_SHOW:-}" \
      --cap-add NET_ADMIN \
      -v "$root/scripts:/src/scripts:ro" -v "$root/deploy:/src/deploy:ro" -v "$work/go:/go-release:ro" \
      "$image" sh /src/scripts/test-install.sh --in-container
    first=0
  done
  echo "test-install: all images passed"
}

# ------------------------------------------------------------ container side

pass() { echo "  ok   $*"; }
fail() {
  echo "  FAIL $*" >&2
  exit 1
}

# expect_ok NAME CMD... / expect_fail NAME PATTERN CMD...
expect_ok() {
  name=$1
  shift
  "$@" >"$W/out" 2>&1 || {
    cat "$W/out" >&2
    fail "$name"
  }
  pass "$name"
}

expect_fail() {
  name=$1 pattern=$2
  shift 2
  if "$@" >"$W/out" 2>&1; then
    cat "$W/out" >&2
    fail "$name: expected failure"
  fi
  grep -q "$pattern" "$W/out" || {
    cat "$W/out" >&2
    fail "$name: output lacks '$pattern'"
  }
  pass "$name"
}

# publish VERSION [DIR-VERSION] [fail]: agent binaries + manifest (unsigned).
publish() {
  v=$1 dir=${2:-$1}
  d=$W/srv/agent/$dir
  mkdir -p "$d"
  for a in amd64 arm64; do
    fake_agent "$v" "${3:-}" >"$d/rowsafe-agent-linux-$a"
  done
  write_manifest "$d" "$v" "https://localhost:8443/agent/$dir"
}

# write_manifest DIR VERSION URLBASE [ARCHS]: indented like Go's MarshalIndent.
write_manifest() {
  d=$1 v=$2 base=$3 archs=${4:-amd64 arm64}
  {
    printf '{\n  "version": "%s",\n  "released_at": "2026-09-24T00:00:00Z",\n  "artifacts": {' "$v"
    sep=''
    for a in $archs; do
      f=$d/rowsafe-agent-linux-$a
      printf '%s\n    "linux/%s": {\n      "url": "%s/rowsafe-agent-linux-%s",\n      "sha256": "%s",\n      "size": %s\n    }' \
        "$sep" "$a" "$base" "$a" "$(sha256sum "$f" | cut -d' ' -f1)" "$(wc -c <"$f" | tr -d ' ')"
      sep=','
    done
    printf '\n  }\n}\n'
  } >"$d/manifest.json"
}

sign() { # DIR [KEYFILE]
  openssl pkeyutl -sign -inkey "${2:-$W/release.key}" -rawin -in "$1/manifest.json" | base64 -w0 >"$1/manifest.json.sig"
  echo >>"$1/manifest.json.sig"
}

in_container() {
  W=/tmp/rt
  mkdir -p "$W/srv/agent"
  cd "$W"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends curl openssl ca-certificates procps python3 logrotate >/dev/null
  arch=$(dpkg --print-architecture)
  # shellcheck disable=SC1091
  echo "  $(. /etc/os-release && echo "$PRETTY_NAME"), $(openssl version | cut -d' ' -f1-2), $arch"

  # Release key: from rowsafe-release (Go) when given, else a fresh openssl one.
  if [ -n "${TEST_PRIV:-}" ]; then
    # Go private keys are seed||public; PKCS#8 for Ed25519 is a fixed 16-byte
    # header (302e020100300506032b657004220420) followed by the 32-byte seed.
    {
      echo '-----BEGIN PRIVATE KEY-----'
      { printf '\060\056\002\001\000\060\005\006\003\053\145\160\004\042\004\040'; printf '%s' "$TEST_PRIV" | base64 -d | head -c 32; } | base64 -w0
      echo
      echo '-----END PRIVATE KEY-----'
    } >release.key
    pub=$TEST_PUB
  else
    openssl genpkey -algorithm ed25519 -out release.key
    pub=$(openssl pkey -in release.key -pubout -outform DER | tail -c 32 | base64 -w0)
  fi
  [ "$(openssl pkey -in release.key -pubout -outform DER | tail -c 32 | base64 -w0)" = "$pub" ] || fail "key conversion"
  openssl genpkey -algorithm ed25519 -out other.key
  sed "s|@RELEASE_PUBLIC_KEY@|$pub|" /src/scripts/install.sh >install.sh
  # An executable wrapper (not a function) so `env VAR=... $INSTALLER` works.
  INSTALLER=$W/installer
  printf '#!/bin/sh\nexec env ROWSAFE_RELEASES_URL=https://localhost:8443/agent sh %s/install.sh "$@"\n' "$W" >"$INSTALLER"
  chmod 755 "$INSTALLER"
  cp /src/scripts/install.sh placeholder-install.sh

  # A local HTTPS release server with a throwaway CA.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=localhost -addext subjectAltName=DNS:localhost -keyout tls.key -out tls.crt 2>/dev/null
  export CURL_CA_BUNDLE=$W/tls.crt
  cat >server.py <<'EOF'
import functools, http.server, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("tls.crt", "tls.key")
class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass
handler = functools.partial(Quiet, directory="srv")
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), handler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
EOF
  python3 server.py &
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -s -o /dev/null https://localhost:8443/ && break
    sleep 0.5
  done

  # ---- releases
  if [ -d /go-release/0.2.0 ]; then
    cp -r /go-release/0.2.0 srv/agent/0.2.0 # signed by rowsafe-release
  else
    publish 0.2.0 && sign srv/agent/0.2.0
  fi
  mkdir -p srv/agent/stable && cp srv/agent/0.2.0/manifest.json srv/agent/0.2.0/manifest.json.sig srv/agent/stable/

  publish 0.3.0 && sign srv/agent/0.3.0 && sed -i 's/"size": \([0-9]*\)/"size": 1\1/' srv/agent/0.3.0/manifest.json
  publish 0.4.0 && sign srv/agent/0.4.0 && sed -i 's/fake/FAKE/' "srv/agent/0.4.0/rowsafe-agent-linux-$arch" # same size
  publish 0.5.0
  f=srv/agent/0.5.0/rowsafe-agent-linux-$arch
  sed -i "s/\"size\": $(wc -c <"$f" | tr -d ' ')/\"size\": 12/" srv/agent/0.5.0/manifest.json && sign srv/agent/0.5.0
  publish 0.2.0 0.6.0 && sign srv/agent/0.6.0 # manifest for 0.2.0 served as 0.6.0
  publish 0.7.0                                 # no signature at all
  publish 0.8.0 && echo 'bm90IGEgc2lnbmF0dXJl' >srv/agent/0.8.0/manifest.json.sig
  publish 0.9.0 && sign srv/agent/0.9.0 "$W/other.key"
  publish 0.10.0 && sed -i 's|https://localhost|http://localhost|' srv/agent/0.10.0/manifest.json && sign srv/agent/0.10.0
  other=amd64
  [ "$arch" = amd64 ] && other=arm64
  publish 0.11.0 && write_manifest srv/agent/0.11.0 0.11.0 https://localhost:8443/agent/0.11.0 "$other" && sign srv/agent/0.11.0
  publish 0.12.0 && sign srv/agent/0.12.0                   # a good upgrade
  publish 0.13.0 0.13.0 fail && sign srv/agent/0.13.0       # fails its self-test

  echo "  -- signature verification (download-only, as an unprivileged user)"
  useradd -m tester
  chmod 755 "$W" && chmod 644 install.sh placeholder-install.sh
  as_tester() { runuser -u tester -- env CURL_CA_BUNDLE="$CURL_CA_BUNDLE" ROWSAFE_RELEASES_URL=https://localhost:8443/agent "$@"; }
  expect_ok "good release by version" as_tester env ROWSAFE_VERSION=v0.2.0 sh install.sh --download-only /tmp/dl1
  cmp /tmp/dl1/rowsafe-agent "srv/agent/0.2.0/rowsafe-agent-linux-$arch" || fail "downloaded binary differs"
  expect_ok "good release by channel" as_tester sh install.sh --download-only /tmp/dl2
  expect_fail "placeholder key refused" "no release key built in" as_tester env ROWSAFE_VERSION=0.2.0 sh placeholder-install.sh --download-only /tmp/dl3
  expect_fail "tampered manifest" "signature is INVALID" as_tester env ROWSAFE_VERSION=0.3.0 sh install.sh --download-only /tmp/dl4
  expect_fail "tampered binary" "checksum mismatch" as_tester env ROWSAFE_VERSION=0.4.0 sh install.sh --download-only /tmp/dl5
  expect_fail "wrong size" "signed manifest says 12" as_tester env ROWSAFE_VERSION=0.5.0 sh install.sh --download-only /tmp/dl6
  expect_fail "replayed older manifest" "asked for 0.6.0 but the signed manifest is for 0.2.0" as_tester env ROWSAFE_VERSION=0.6.0 sh install.sh --download-only /tmp/dl7
  expect_fail "missing signature" "could not download" as_tester env ROWSAFE_VERSION=0.7.0 sh install.sh --download-only /tmp/dl8
  expect_fail "garbage signature" "signature is malformed" as_tester env ROWSAFE_VERSION=0.8.0 sh install.sh --download-only /tmp/dl9
  expect_fail "signed by another key" "signature is INVALID" as_tester env ROWSAFE_VERSION=0.9.0 sh install.sh --download-only /tmp/dl10
  expect_fail "http artifact URL" "invalid download URL" as_tester env ROWSAFE_VERSION=0.10.0 sh install.sh --download-only /tmp/dl11
  expect_fail "no build for this platform" "no build for linux/$arch" as_tester env ROWSAFE_VERSION=0.11.0 sh install.sh --download-only /tmp/dl12
  expect_fail "http releases URL" "must be an https URL" env ROWSAFE_RELEASES_URL=http://localhost:8443/agent sh install.sh --download-only /tmp/dl13
  for n in 3 4 5 6 7 8 9 10 11 12 13; do
    [ ! -e /tmp/dl$n ] || fail "a refused release left files in /tmp/dl$n"
  done
  pass "refused releases wrote nothing"

  echo "  -- install, reconfigure, upgrade, uninstall"
  expect_fail "requires root" "run the installer as root" as_tester sh install.sh
  useradd --system --home-dir /var/lib/postgresql --create-home --shell /bin/sh postgres
  mkdir -p /usr/lib/postgresql/17/bin /var/lib/postgresql/17/main
  printf '#!/bin/sh\n' >/usr/lib/postgresql/17/bin/postgres && chmod 755 /usr/lib/postgresql/17/bin/postgres

  # The enrollment token as an argument: refused combinations write
  # nothing and never echo a token.
  expect_fail "two different tokens refused" "two different enrollment tokens" \
    env ROWSAFE_ENROLL_TOKEN=rse_othertoken456 "$INSTALLER" rse_secrettoken123
  expect_fail "two token arguments refused" "more than one enrollment token" "$INSTALLER" rse_secrettoken123 rse_othertoken456
  expect_fail "token with --uninstall refused" "only goes with an install" "$INSTALLER" rse_secrettoken123 --uninstall
  expect_fail "stray argument refused" "unexpected argument" "$INSTALLER" notatoken789
  for s in rse_secrettoken123 rse_othertoken456 notatoken789; do
    ! grep -qF "$s" "$W/out" || fail "an argument was echoed"
  done
  [ ! -e /etc/rowsafe ] || fail "a refused argument wrote /etc/rowsafe"
  pass "token argument errors echo nothing and write nothing"

  # No ROWSAFE_URL: the agent defaults to https://api.rowsafe.sh. The token
  # is the argument, as in `curl -fsSL https://rowsafe.sh | sudo sh -s rse_...`.
  expect_ok "fresh install without repository settings" "$INSTALLER" rse_secrettoken123
  grep -q "^ROWSAFE_ENROLL_TOKEN='rse_secrettoken123'\$" /etc/rowsafe/agent.env || fail "token argument not written"
  [ -z "${TEST_SHOW:-}" ] || cat "$W/out"
  grep -q "Before the agent can start" "$W/out" || fail "no fill-in instructions"
  for k in ROWSAFE_REPO_S3_ENDPOINT ROWSAFE_REPO_S3_BUCKET ROWSAFE_REPO_S3_KEY ROWSAFE_REPO_S3_KEY_SECRET ROWSAFE_REPO_CIPHER_PASS; do
    grep -q "^    $k\$" "$W/out" || fail "instructions do not list $k"
  done
  ! grep -q "^    ROWSAFE_URL\$" "$W/out" || fail "ROWSAFE_URL listed as required; it has a default"
  ! grep -q rse_secrettoken123 "$W/out" || fail "the enrollment token was printed"
  [ "$(readlink /opt/rowsafe/rowsafe-agent)" = versions/0.2.0/rowsafe-agent ] || fail "symlink"
  [ "$(stat -c '%U %a' /etc/rowsafe/agent.env)" = "postgres 600" ] || fail "agent.env ownership/mode"
  [ "$(stat -c '%U %a' /opt/rowsafe)" = "postgres 755" ] || fail "/opt/rowsafe ownership/mode"
  [ "$(stat -c '%U %a' /usr/local/lib/rowsafe/rowsafe-agent-guard)" = "root 755" ] || fail "guard ownership/mode"
  [ "$(stat -c '%U %a' /usr/local/lib/rowsafe)" = "root 755" ] || fail "/usr/local/lib/rowsafe ownership/mode"
  [ -z "$(find /opt/rowsafe /var/lib/rowsafe -user root)" ] || fail "root owns files in the agent's directories"
  for d in /etc/rowsafe/pgbackrest /var/lib/rowsafe /var/log/rowsafe; do
    [ "$(stat -c '%U %a' "$d")" = "postgres 700" ] || fail "$d ownership/mode"
  done
  [ "$(stat -c '%U %G %a' /etc/rowsafe)" = "root postgres 750" ] || fail "/etc/rowsafe ownership/mode"
  cmp /usr/local/lib/rowsafe/rowsafe-agent-guard /src/scripts/rowsafe-agent-guard || fail "guard differs from scripts/rowsafe-agent-guard"
  cmp /etc/systemd/system/rowsafe-agent.service /src/deploy/systemd/rowsafe-agent.service || fail "unit differs from deploy/systemd/rowsafe-agent.service"
  cmp /etc/logrotate.d/rowsafe /src/deploy/logrotate/rowsafe || fail "logrotate config differs from deploy/logrotate/rowsafe"
  [ "$(stat -c '%U %a' /etc/logrotate.d/rowsafe)" = "root 644" ] || fail "logrotate config ownership/mode"
  grep -q "^#ROWSAFE_URL='https://api.rowsafe.sh'\$" /etc/rowsafe/agent.env || fail "default ROWSAFE_URL not left commented out"
  command -v pgbackrest >/dev/null || fail "pgbackrest not installed"
  echo x >/var/log/rowsafe/app-archive-push.log && chown postgres:postgres /var/log/rowsafe/app-archive-push.log
  logrotate --debug /etc/logrotate.d/rowsafe >"$W/lr" 2>&1 || { cat "$W/lr" >&2; fail "logrotate rejects the config"; }
  ! grep -qi "error" "$W/lr" || { cat "$W/lr" >&2; fail "logrotate reported an error"; }
  pass "layout, permissions, guard, unit and logrotate"

  secret_key=AKIAEXAMPLEKEY42 secret=s3cr3t/with+base64= cipher='cipher-pass-that-is-long-enough/+=='
  configured() {
    env ROWSAFE_REPO_S3_ENDPOINT=acct.eu.r2.cloudflarestorage.com ROWSAFE_REPO_S3_BUCKET=app-rowsafe \
      ROWSAFE_REPO_S3_KEY="$secret_key" ROWSAFE_REPO_S3_KEY_SECRET="$secret" ROWSAFE_REPO_CIPHER_PASS="$cipher" "$@"
  }
  # Both forms at once are fine when they agree.
  expect_ok "configured install self-tests as postgres" \
    configured env ROWSAFE_URL=https://api.example.test ROWSAFE_ENROLL_TOKEN=rse_secrettoken123 "$INSTALLER" rse_secrettoken123
  [ -z "${TEST_SHOW:-}" ] || cat "$W/out"
  grep -q "configuration, pgBackRest and control plane reachable" "$W/out" || fail "self-test not reported"
  grep -q "Next: turn on backups" "$W/out" || fail "no next step"
  grep -q "^ROWSAFE_URL='https://api.example.test'\$" /etc/rowsafe/agent.env || fail "ROWSAFE_URL not written"
  grep -q "17.6 (Debian 17.6-1), data directory /var/lib/postgresql/17/main, archive_mode=off" "$W/out" || fail "PostgreSQL summary"
  for s in "$secret_key" "$secret" "$cipher" rse_secrettoken123; do
    ! grep -qF "$s" "$W/out" || fail "a secret was printed"
  done
  [ "$(grep -c '^ROWSAFE_REPO_S3_BUCKET=' /etc/rowsafe/agent.env)" = 1 ] || fail "bucket line duplicated"
  ! grep -q '^#ROWSAFE_REPO_S3_BUCKET=' /etc/rowsafe/agent.env || fail "placeholder not replaced"
  grep -qF "ROWSAFE_REPO_S3_KEY_SECRET='$secret'" /etc/rowsafe/agent.env || fail "secret not written verbatim"
  grep -qF "ROWSAFE_REPO_CIPHER_PASS='$cipher'" /etc/rowsafe/agent.env || fail "cipher pass not written verbatim"
  pass "env file merged, secrets kept out of the output"

  # Exactly as piped from curl: sh -s rse_...
  expect_ok "re-run is idempotent (piped, token as argument)" \
    sh -c 'ROWSAFE_RELEASES_URL=https://localhost:8443/agent sh -s rse_secrettoken123 <"$1/install.sh"' piped "$W"
  grep -q "already on disk" "$W/out" || fail "binary downloaded again"
  grep -q "unchanged" "$W/out" || fail "env file changed on a plain re-run"
  expect_fail "bad cipher pass refused" "at least 20 characters" env ROWSAFE_REPO_CIPHER_PASS=short "$INSTALLER"
  expect_fail "endpoint with scheme refused" "without a scheme" env ROWSAFE_REPO_S3_ENDPOINT=https://x.r2.cloudflarestorage.com "$INSTALLER"
  expect_fail "quote in value refused" "single quotes" env ROWSAFE_REPO_S3_BUCKET="it's" "$INSTALLER"

  expect_ok "upgrade to 0.12.0" env ROWSAFE_VERSION=0.12.0 "$INSTALLER"
  [ "$(readlink /opt/rowsafe/rowsafe-agent)" = versions/0.12.0/rowsafe-agent ] || fail "not switched to 0.12.0"
  runuser -u postgres -- mkdir -p /var/lib/rowsafe/update/pending
  install -d -m 0755 -o root -g root /opt/rowsafe/bin && touch /opt/rowsafe/bin/rowsafe-agent-guard # an older install's guard
  expect_ok "channel older than installed keeps it" "$INSTALLER"
  grep -q "newer than stable" "$W/out" || fail "no keep message"
  [ "$(readlink /opt/rowsafe/rowsafe-agent)" = versions/0.12.0/rowsafe-agent ] || fail "downgraded by the channel"
  expect_fail "pinned downgrade refused" "refusing to downgrade" env ROWSAFE_VERSION=0.2.0 "$INSTALLER"
  expect_fail "failing self-test keeps the old version" "keeping rowsafe-agent 0.12.0" env ROWSAFE_VERSION=0.13.0 "$INSTALLER"
  [ -z "${TEST_SHOW:-}" ] || cat "$W/out"
  [ ! -e /opt/rowsafe/versions/0.13.0 ] || fail "the version that failed its self-test was left on disk"
  grep -q "control plane: dial tcp" "$W/out" || fail "self-test errors not shown"
  [ "$(readlink /opt/rowsafe/rowsafe-agent)" = versions/0.12.0/rowsafe-agent ] || fail "switched despite a failed self-test"
  expect_ok "allowed downgrade" env ROWSAFE_VERSION=0.2.0 ROWSAFE_ALLOW_DOWNGRADE=1 "$INSTALLER"
  [ "$(readlink /opt/rowsafe/rowsafe-agent)" = versions/0.2.0/rowsafe-agent ] || fail "downgrade not applied"
  [ ! -d /var/lib/rowsafe/update/pending ] || fail "manual switch left self-update state behind"
  [ ! -e /opt/rowsafe/bin ] || fail "the old guard directory /opt/rowsafe/bin was left behind"

  if [ "${TEST_UNITS:-0}" = 1 ]; then
    echo "  -- systemd units"
    apt-get install -y -qq --no-install-recommends systemd >/dev/null 2>&1
    expect_ok "systemd-analyze verify" systemd-analyze verify /etc/systemd/system/rowsafe-agent.service
    [ ! -s "$W/out" ] || {
      cat "$W/out" >&2
      fail "systemd-analyze verify printed warnings"
    }
    systemd-analyze security --offline=true --no-pager /etc/systemd/system/rowsafe-agent.service 2>/dev/null |
      tail -n 1 | sed "s/^/  rowsafe-agent: /"
  fi

  echo "x" >/var/lib/postgresql/17/main/postgresql.auto.conf
  echo "archive_command = '/usr/bin/pgbackrest --config=/etc/rowsafe/pgbackrest/app.conf --stanza=app archive-push %p'" \
    >>/var/lib/postgresql/17/main/postgresql.auto.conf
  expect_fail "purge refused while archiving" "still archives WAL" "$INSTALLER" --uninstall --purge
  [ -f /etc/rowsafe/agent.env ] && [ -x /opt/rowsafe/rowsafe-agent ] || fail "refused purge removed files"
  expect_ok "uninstall keeps config" "$INSTALLER" --uninstall
  [ ! -e /opt/rowsafe ] && [ -f /etc/rowsafe/agent.env ] && [ ! -e /etc/systemd/system/rowsafe-agent.service ] && [ -f /etc/logrotate.d/rowsafe ] &&
    [ ! -e /usr/local/lib/rowsafe ] || fail "uninstall result"
  grep -q "keeps running" "$W/out" || fail "no note that archiving keeps running"
  rm /var/lib/postgresql/17/main/postgresql.auto.conf
  expect_ok "purge" "$INSTALLER" --uninstall --purge
  [ ! -e /etc/rowsafe ] && [ ! -e /var/lib/rowsafe ] && [ ! -e /var/log/rowsafe ] && [ ! -e /etc/logrotate.d/rowsafe ] || fail "purge result"
  expect_fail "--purge needs --uninstall" "only goes with --uninstall" "$INSTALLER" --purge
  guided_storage_tests
}

# ------------------------------------------------------------ guided setup

# write_terminal_helpers writes drive.py (answers the installer on a real
# pseudo-terminal) and fakes3.py (a local S3 that checks SigV4 signatures).
write_terminal_helpers() {
  cat >"$W/drive.py" <<'EOF'
import fcntl, os, re, select, signal, sys, termios, time

# drive.py STEPS TRANSCRIPT CMD...: run CMD on a new terminal (so it has a
# /dev/tty) and answer like a person. STEPS has lines "PATTERN<TAB>ANSWER":
# wait for PATTERN (after the previous match), then type ANSWER and Enter.
# ANSWER {ctrl-c} presses Ctrl-C; {capture:RE} types group 1 of RE matched
# against everything shown so far. The transcript goes to TRANSCRIPT. Exits
# with CMD's status, 99 if a PATTERN never showed up, 98 if CMD left the
# terminal with echo off.
steps = []
with open(sys.argv[1]) as f:
    for line in f:
        line = line.rstrip("\n")
        if line:
            pat, _, ans = line.partition("\t")
            steps.append((pat, ans))

master, slave = os.openpty()
pid = os.fork()
if pid == 0:
    os.close(master)
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    for fd in (0, 1, 2):
        os.dup2(slave, fd)
    if slave > 2:
        os.close(slave)
    os.execvp(sys.argv[3], sys.argv[3:])

out = b""
status = None


def pump(timeout):
    """Read what the terminal shows; False once CMD has exited and all is read."""
    global out, status
    r, _, _ = select.select([master], [], [], timeout)
    if r:
        out += os.read(master, 65536)
        return True
    if status is None:
        p, st = os.waitpid(pid, os.WNOHANG)
        if p:
            status = st
    return status is None


failed = None
seen = 0
for pat, ans in steps:
    deadline = time.time() + 90
    while pat.encode() not in out[seen:]:
        if time.time() > deadline or not pump(0.2):
            break
    i = out.find(pat.encode(), seen)
    if i < 0:
        failed = f"never saw {pat!r}"
        break
    seen = i + len(pat)
    time.sleep(0.1)
    if ans == "{ctrl-c}":
        os.write(master, b"\x03")
        continue
    m = re.match(r"\{capture:(.*)\}$", ans)
    if m:
        found = re.search(m.group(1), out.decode("utf-8", "replace"))
        ans = found.group(1) if found else "?"
    os.write(master, ans.encode() + b"\r")

deadline = time.time() + 240
while failed is None and time.time() < deadline and pump(0.5):
    pass
if status is None:
    if failed is None:
        failed = "timed out"
    os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
while select.select([master], [], [], 0)[0]:
    data = os.read(master, 65536)
    if not data:
        break
    out += data
with open(sys.argv[2], "wb") as f:
    f.write(out)
if failed:
    sys.stderr.write(f"drive.py: {failed}\n")
    sys.exit(99)
if not termios.tcgetattr(slave)[3] & termios.ECHO:
    sys.stderr.write("drive.py: the terminal was left with echo off\n")
    sys.exit(98)
sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status))
EOF
  cat >"$W/fakes3.py" <<'EOF'
import datetime, hashlib, hmac, http.server, re, ssl, sys, urllib.parse

# A small S3 endpoint for installer tests: one bucket, one key pair, real
# SigV4 checking and AWS-style errors. Its region is the one in an
# s3.<region>.amazonaws.com host name, else "auto" (which, like R2, also
# takes us-east-1). A file named "skew" in the working directory moves its
# clock by that many seconds.
KEYS = {"AKIDTESTROWSAFE": "test/secret+key=="}
BUCKETS = {"rowsafe-test", "rowsafe-copy2"}
objects = {}


def sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


class S3(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, status, body=b"", ctype="application/xml", headers=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def error(self, status, code, msg="error"):
        self.reply(status, f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{msg}</Message></Error>".encode())

    def authorized(self, body):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("AWS4-HMAC-SHA256 "):
            return self.error(403, "AccessDenied")
        parts = dict(p.strip().split("=", 1) for p in auth[len("AWS4-HMAC-SHA256 "):].split(","))
        key, date, region, service, _ = parts["Credential"].split("/")
        if key not in KEYS:
            return self.error(403, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.")
        m = re.search(r"s3\.([a-z0-9-]+)\.amazonaws\.com$", self.headers.get("Host", "").split(":")[0])
        want = m.group(1) if m else "auto"
        if region != want and not (want == "auto" and region == "us-east-1"):
            return self.error(400, "AuthorizationHeaderMalformed", f"The authorization header is malformed; the region '{region}' is wrong; expecting '{want}'")
        amzdate = self.headers.get("x-amz-date", "")
        try:
            skew = int(open("skew").read())
        except OSError:
            skew = 0
        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=skew)
        sent = datetime.datetime.strptime(amzdate, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
        if abs((now - sent).total_seconds()) > 900:
            return self.error(403, "RequestTimeTooSkewed", "The difference between the request time and the current time is too large.")
        url = urllib.parse.urlsplit(self.path)
        query = sorted(urllib.parse.parse_qsl(url.query, keep_blank_values=True))
        cq = "&".join(urllib.parse.quote(k, safe="-_.~") + "=" + urllib.parse.quote(v, safe="-_.~") for k, v in query)
        signed = parts["SignedHeaders"].split(";")
        ch = "".join(f"{h}:{' '.join(self.headers.get(h, '').split())}\n" for h in signed)
        payload = self.headers.get("x-amz-content-sha256", hashlib.sha256(body).hexdigest())
        creq = "\n".join([self.command, url.path, cq, ch, ";".join(signed), payload])
        sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, f"{date}/{region}/{service}/aws4_request", hashlib.sha256(creq.encode()).hexdigest()])
        k = sign(sign(sign(sign(("AWS4" + KEYS[key]).encode(), date), region), service), "aws4_request")
        if hmac.new(k, sts.encode(), hashlib.sha256).hexdigest() != parts["Signature"]:
            return self.error(403, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided.")
        return True

    def handle_any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        if self.path == "/v1/storage/offer":  # the control plane's Rowsafe Storage offer
            self.close_connection = True  # curl -f hangs up after an error
            try:
                open("offer").close()
            except OSError:
                return self.reply(404, b'{"error":"not found"}', "application/json", [("Connection", "close")])
            return self.reply(200, b'{"available":true,"free_bytes":10000000000}', "application/json", [("Connection", "close")])
        if self.authorized(body) is not True:
            return
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        host = self.headers.get("Host", "").split(":")[0]
        if host.startswith("rowsafe-test."):  # virtual-hosted style
            bucket, key = "rowsafe-test", path.lstrip("/")
        else:
            bucket, _, key = path.lstrip("/").partition("/")
        if bucket not in BUCKETS:
            return self.error(404, "NoSuchBucket", "The specified bucket does not exist")
        store = objects.setdefault(bucket, {})
        if self.command == "PUT":
            store[key] = body
            return self.reply(200)
        if self.command in ("GET", "HEAD") and key:
            if key not in store:
                return self.error(404, "NoSuchKey", "The specified key does not exist.")
            return self.reply(200, store[key], "application/octet-stream",
                              [("Last-Modified", "Thu, 24 Sep 2026 00:00:00 GMT"), ("ETag", '"%s"' % hashlib.md5(store[key]).hexdigest())])
        if self.command == "DELETE":
            store.pop(key, None)
            return self.reply(204)
        if self.command == "POST":  # multi-object delete
            return self.reply(200, b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DeleteResult></DeleteResult>")
        # ListObjectsV2
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query, keep_blank_values=True))
        prefix, delim = q.get("prefix", ""), q.get("delimiter", "")
        contents, prefixes = [], set()
        for k in sorted(store):
            if not k.startswith(prefix):
                continue
            rest = k[len(prefix):]
            if delim and delim in rest:
                prefixes.add(prefix + rest.split(delim)[0] + delim)
            else:
                contents.append(f"<Contents><Key>{k}</Key><LastModified>2026-09-24T00:00:00.000Z</LastModified><Size>{len(store[k])}</Size></Contents>")
        cp = "".join(f"<CommonPrefixes><Prefix>{p}</Prefix></CommonPrefixes>" for p in sorted(prefixes))
        self.reply(200, f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>{bucket}</Name><Prefix>{prefix}</Prefix><IsTruncated>false</IsTruncated>{''.join(contents)}{cp}</ListBucketResult>".encode())

    do_GET = do_PUT = do_DELETE = do_HEAD = do_POST = handle_any


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
srv = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[3])), S3)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
EOF
}

# on_tty NAME STEPS CMD...: run CMD on a terminal, answering from the STEPS
# lines ("PATTERN<TAB>ANSWER"); the transcript (without CRs) is in $W/out.
on_tty() {
  name=$1 steps=$2
  shift 2
  printf '%b' "$steps" >"$W/steps"
  rc=0
  NO_COLOR=1 LANG=C.UTF-8 python3 "$W/drive.py" "$W/steps" "$W/tty.raw" "$@" || rc=$?
  tr -d '\r' <"$W/tty.raw" >"$W/out"
  [ -z "${TEST_SHOW:-}" ] || cat "$W/out"
}

tty_ok() {
  on_tty "$@"
  [ "$rc" = 0 ] || {
    cat "$W/out" >&2
    fail "$name (exit $rc)"
  }
  pass "$name"
}

tty_fail() { # NAME CODE STEPS CMD...
  n=$1 code=$2
  shift 2
  on_tty "$n" "$@"
  [ "$rc" = "$code" ] || {
    cat "$W/out" >&2
    fail "$n (exit $rc, wanted $code)"
  }
  pass "$n"
}

has() { grep -qF -- "$1" "$W/out" || {
  cat "$W/out" >&2
  fail "$name: output lacks '$1'"
}; }
lacks() { ! grep -qF -- "$1" "$W/out" || {
  cat "$W/out" >&2
  fail "$name: output shows '$1'"
}; }
env_is() { grep -qxF "$1='$2'" /etc/rowsafe/agent.env || {
  grep "^#*$1=" /etc/rowsafe/agent.env >&2
  fail "$name: agent.env lacks $1='$2'"
}; }

guided_storage_tests() {
  echo "  -- guided storage setup on a terminal"
  write_terminal_helpers
  acct=0123456789abcdef0123456789abcdef
  # api.rowsafe.sh too: the storage offer is asked locally, never online.
  names="s3.rowsafe.test $acct.eu.r2.cloudflarestorage.com s3.eu-central-1.amazonaws.com rowsafe-test.s3.eu-central-1.amazonaws.com api.rowsafe.sh api.rowsafe.test"
  echo "127.0.0.1 $names" >>/etc/hosts
  san=$(printf 'DNS:%s,' $names)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=s3.rowsafe.test -addext "subjectAltName=${san%,}" -keyout s3.key -out s3.crt 2>/dev/null
  # The named providers use the system CA store, as on a real host.
  cp s3.crt /usr/local/share/ca-certificates/rowsafe-test-s3.crt && update-ca-certificates >/dev/null 2>&1
  python3 fakes3.py s3.crt s3.key 443 &
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -s -o /dev/null "https://s3.rowsafe.test/" && break
    sleep 0.5
  done
  key=AKIDTESTROWSAFE secret='test/secret+key=='

  expect_fail "--storage needs a terminal" "needs a terminal" "$INSTALLER" --storage r2
  expect_fail "unknown provider refused" "unknown storage provider" "$INSTALLER" --storage dropbox
  [ ! -e /etc/rowsafe ] || fail "a refused option wrote /etc/rowsafe"

  # 1. First install, as from `curl ... | sudo sh -s rse_...` on a terminal:
  # R2 in the EU, a generated passphrase that must be confirmed.
  tty_ok "fresh install: R2 (EU), generated passphrase" \
    "Bucket URL\t\nChoose 1-6\t1\nCloudflare account ID\t$acct\nEU jurisdiction\ty\nBucket name\trowsafe-test\nAccess key ID\t$key\nSecret access key\t$secret\nChoose 1-2\t1\nto continue\tzzzz\nto continue\t{capture:[│|] {6}[A-Za-z0-9]{36}([A-Za-z0-9]{4}) }\n" \
    sh -c 'ROWSAFE_RELEASES_URL=https://localhost:8443/agent sh -s rse_secrettoken123 <"$1/install.sh"' piped "$W"
  has "Where should Rowsafe store your backups?"
  has "backup storage works: wrote, read back and deleted a test file"
  has "Save this in your password manager now."
  has "That doesn't match."
  has "passphrase confirmed"
  lacks "Broken pipe"
  has "Next: turn on backups"
  has "configuration, pgBackRest and control plane reachable"
  pass_=$(sed -n 's/^.*[│|]      \([A-Za-z0-9]\{40\}\)        [│|].*$/\1/p' "$W/out")
  [ "${#pass_}" = 40 ] || fail "generated passphrase not shown in the box"
  [ "$(grep -oF "$pass_" "$W/out" | wc -l)" = 1 ] || fail "the passphrase was shown more than once"
  lacks "$secret"
  lacks rse_secrettoken123
  ! grep -q "$(printf '\033')" "$W/out" || fail "colours despite NO_COLOR"
  env_is ROWSAFE_REPO_S3_ENDPOINT "$acct.eu.r2.cloudflarestorage.com"
  env_is ROWSAFE_REPO_S3_BUCKET rowsafe-test
  env_is ROWSAFE_REPO_S3_REGION auto
  env_is ROWSAFE_REPO_S3_URI_STYLE path
  env_is ROWSAFE_REPO_S3_KEY "$key"
  env_is ROWSAFE_REPO_S3_KEY_SECRET "$secret"
  env_is ROWSAFE_REPO_CIPHER_PASS "$pass_"
  [ "$(stat -c '%U %a' /etc/rowsafe/agent.env)" = "postgres 600" ] || fail "agent.env ownership/mode"
  pass "settings saved to agent.env, passphrase shown once, secrets never shown"

  # 2. A plain re-run on a terminal asks nothing.
  before=$(sha256sum /etc/rowsafe/agent.env)
  tty_ok "re-run on a terminal asks nothing" "" "$INSTALLER"
  has "change it with --setup-storage"
  lacks "Where should Rowsafe"
  [ "$(sha256sum /etc/rowsafe/agent.env)" = "$before" ] || fail "re-run changed agent.env"
  tty_ok "--setup-storage, keep the current settings" "Replace these storage settings?\tn\n" "$INSTALLER" --setup-storage
  has "kept the current storage settings"
  [ "$(sha256sum /etc/rowsafe/agent.env)" = "$before" ] || fail "declining changed agent.env"

  # 2b. Pasted bucket URLs fill in the provider, endpoint and bucket.
  tty_ok "--setup-storage: R2 bucket URL" \
    "Replace these storage settings?\ty\nBucket URL\thttps://$acct.eu.r2.cloudflarestorage.com/rowsafe-test\nAccess key ID\t$key\nSecret access key\t$secret\nKeep the current encryption passphrase?\t\n" \
    "$INSTALLER" --setup-storage
  has "Cloudflare R2, endpoint $acct.eu.r2.cloudflarestorage.com, bucket rowsafe-test"
  has "Object Read & Write"
  has "backup storage works"
  lacks "Bucket name"
  lacks "Choose 1-6"
  lacks "$secret"
  env_is ROWSAFE_REPO_S3_ENDPOINT "$acct.eu.r2.cloudflarestorage.com"
  env_is ROWSAFE_REPO_S3_BUCKET rowsafe-test
  env_is ROWSAFE_REPO_S3_REGION auto
  env_is ROWSAFE_REPO_S3_URI_STYLE path
  env_is ROWSAFE_REPO_CIPHER_PASS "$pass_"
  tty_ok "--setup-storage: S3 virtual-host bucket URL" \
    "Replace these storage settings?\ty\nBucket URL\thttps://rowsafe-test.s3.eu-central-1.amazonaws.com/\nAccess key ID\t$key\nSecret access key\t$secret\nKeep the current encryption passphrase?\t\n" \
    "$INSTALLER" --setup-storage
  has "Amazon S3, endpoint s3.eu-central-1.amazonaws.com, bucket rowsafe-test"
  has "backup storage works"
  lacks "AWS region"
  env_is ROWSAFE_REPO_S3_ENDPOINT s3.eu-central-1.amazonaws.com
  env_is ROWSAFE_REPO_S3_REGION eu-central-1
  env_is ROWSAFE_REPO_S3_URI_STYLE host
  tty_ok "--setup-storage: another https endpoint asks the region" \
    "Replace these storage settings?\ty\nBucket URL\thttp://s3.rowsafe.test/rowsafe-test\nBucket URL\thttps://s3.rowsafe.test/rowsafe-test\nRegion (\t\nAccess key ID\t$key\nSecret access key\t$secret\nKeep the current encryption passphrase?\t\n" \
    "$INSTALLER" --setup-storage
  has "Plain http:// is not supported"
  has "S3-compatible storage, endpoint s3.rowsafe.test, bucket rowsafe-test"
  has "backup storage works"
  env_is ROWSAFE_REPO_S3_ENDPOINT s3.rowsafe.test
  env_is ROWSAFE_REPO_S3_REGION us-east-1
  env_is ROWSAFE_REPO_S3_URI_STYLE path
  before=$(sha256sum /etc/rowsafe/agent.env)
  tty_fail "a dashboard link falls back to the provider menu" 130 \
    "Replace these storage settings?\ty\nBucket URL\thttps://dash.cloudflare.com/0123/r2/overview\nChoose 1-6\t{ctrl-c}\n" \
    "$INSTALLER" --setup-storage
  has "a link to your provider's dashboard"
  [ "$(sha256sum /etc/rowsafe/agent.env)" = "$before" ] || fail "an interrupted setup changed agent.env"
  pass "bucket URLs: R2, S3, other endpoints, http and dashboard links"

  # 3. Switch to self-hosted storage, getting it wrong three times first.
  # --storage preselects the provider; the passphrase is kept.
  echo "ROWSAFE_REPO_S3_PORT='9000'" >>/etc/rowsafe/agent.env # stale; must go
  tty_ok "--setup-storage: failures explained, then fixed" \
    "Replace these storage settings?\ty\nChoose 1-6\t\nEndpoint\thttps://s3.rowsafe.test/\nRegion (\t\npath-style\t\nBucket name\tno-such-bucket\nAccess key ID\t$key\nSecret access key\t$secret\ntest again?\ty\nChoose 1-6\t\nEndpoint\t\nRegion (\t\npath-style\t\nBucket name\trowsafe-test\nAccess key ID\tAKIDWRONG\nSecret access key\t\ntest again?\ty\nChoose 1-6\t\nEndpoint\t\nRegion (\t\npath-style\t\nBucket name\t\nAccess key ID\t$key\nSecret access key\twrong-secret-value\ntest again?\ty\nChoose 1-6\t\nEndpoint\t\nRegion (\t\npath-style\t\nBucket name\t\nAccess key ID\t\nSecret access key\t$secret\nKeep the current encryption passphrase?\t\n" \
    "$INSTALLER" --setup-storage --storage s3-compatible
  has "There is no bucket named 'no-such-bucket' there."
  has "The access key ID was not recognised."
  has "The secret doesn't match the access key ID."
  has "(storage said: NoSuchBucket: The specified bucket does not exist)"
  has "backup storage works"
  has "kept the current encryption passphrase"
  lacks "$secret"
  lacks wrong-secret-value
  lacks "$pass_"
  env_is ROWSAFE_REPO_S3_ENDPOINT s3.rowsafe.test
  env_is ROWSAFE_REPO_S3_REGION us-east-1
  env_is ROWSAFE_REPO_S3_URI_STYLE path
  env_is ROWSAFE_REPO_CIPHER_PASS "$pass_"
  ! grep -q '^ROWSAFE_REPO_S3_PORT=' /etc/rowsafe/agent.env || fail "stale ROWSAFE_REPO_S3_PORT kept"
  [ "$(grep -c "^#ROWSAFE_REPO_S3_PORT='443'$" /etc/rowsafe/agent.env)" = 1 ] || fail "ROWSAFE_REPO_S3_PORT not reset to the template once"
  pass "storage changed, stale settings reset, passphrase kept"

  # 4. Amazon S3 (host-style URLs) with a passphrase of one's own.
  tty_ok "--setup-storage: Amazon S3, own passphrase" \
    "Replace these storage settings?\ty\nBucket URL\t\nChoose 1-6\t3\nAWS region\teu-central-1\nBucket name\trowsafe-test\nAccess key ID\t$key\nSecret access key\t$secret\nKeep the current encryption passphrase?\tn\nChoose 1-2\t2\nYour passphrase\tshort\nYour passphrase\tmy-own-passphrase-long-enough\nType it again\tsomething-else-long-enough\nYour passphrase\tmy-own-passphrase-long-enough\nType it again\tmy-own-passphrase-long-enough\n" \
    "$INSTALLER" --setup-storage
  has "use at least 20"
  has "The two don't match."
  lacks my-own-passphrase-long-enough
  lacks "$secret"
  env_is ROWSAFE_REPO_S3_ENDPOINT s3.eu-central-1.amazonaws.com
  env_is ROWSAFE_REPO_S3_REGION eu-central-1
  env_is ROWSAFE_REPO_S3_URI_STYLE host
  env_is ROWSAFE_REPO_CIPHER_PASS my-own-passphrase-long-enough

  # 5. Ctrl-C at the hidden prompt: echo comes back (drive.py checks) and
  # nothing is saved.
  before=$(sha256sum /etc/rowsafe/agent.env)
  tty_fail "Ctrl-C at a hidden prompt restores the terminal" 130 \
    "Replace these storage settings?\ty\nBucket URL\thttps://s3.eu-central-003.backblazeb2.com/rowsafe-test\nAccess key ID\t$key\nSecret access key\t{ctrl-c}\n" \
    "$INSTALLER" --setup-storage
  [ "$(sha256sum /etc/rowsafe/agent.env)" = "$before" ] || fail "an interrupted setup changed agent.env"

  # 6. --check-storage, and what it says about common mistakes.
  expect_ok "--check-storage" "$INSTALLER" --check-storage
  grep -q "backup storage works" "$W/out" || fail "--check-storage: no success message"
  expect_fail "wrong region explained" "bucket is in a different region" \
    env ROWSAFE_REPO_S3_REGION=us-west-2 "$INSTALLER" --check-storage
  echo 3600 >"$W/skew"
  expect_fail "clock skew explained" "clock is wrong" "$INSTALLER" --check-storage
  rm "$W/skew"
  expect_fail "unknown host explained" "Can't find nonexistent.invalid" \
    env ROWSAFE_REPO_S3_ENDPOINT=nonexistent.invalid "$INSTALLER" --check-storage
  for s in "$secret" my-own-passphrase-long-enough; do
    ! grep -qF "$s" "$W/out" || fail "--check-storage printed a secret"
  done
  second_copy_tests

  # 7. --no-prompt on a terminal behaves exactly like no terminal.
  expect_ok "purge" "$INSTALLER" --uninstall --purge
  tty_ok "--no-prompt on a terminal asks nothing" "" "$INSTALLER" --no-prompt rse_secrettoken123
  has "Before the agent can start"
  has "without --no-prompt and it walks"
  lacks "Where should Rowsafe"
  expect_ok "purge" "$INSTALLER" --uninstall --purge
  bucket_url_tests
  rowsafe_storage_tests
  setup_flow_tests
  restart_tests
  create_cluster_tests
  firewall_tests
  [ "${TEST_UNITS:-0}" != 1 ] || mysql_host_tests
}

# ------------------------------------------------------------ second copy

second_copy_tests() {
  echo "  -- second copy (--add-storage)"
  first=$(grep -E '^ROWSAFE_REPO_' /etc/rowsafe/agent.env | sort)
  expect_fail "--add-storage without a terminal needs its settings" "needs these in the environment" "$INSTALLER" --add-storage
  # The first storage's bucket is refused; another bucket is tested; the
  # second copy gets its own generated passphrase.
  tty_ok "--add-storage: another bucket, own passphrase" \
    "Bucket URL\thttps://rowsafe-test.s3.eu-central-1.amazonaws.com/\nAccess key ID\t$key\nSecret access key\t$secret\nBucket URL\thttps://s3.rowsafe.test/rowsafe-copy2\nRegion (\t\nAccess key ID\t$key\nSecret access key\t$secret\nChoose 1-2\t1\nto continue\t{capture:[│|] {6}[A-Za-z0-9]{36}([A-Za-z0-9]{4}) }\n" \
    "$INSTALLER" --add-storage
  has "A second copy keeps your backups"
  has "That is the bucket your backups already go to."
  has "backup storage works"
  has "Your second copy encryption passphrase:"
  has "keep both in your password manager"
  has "Second copy saved."
  lacks "$secret"
  lacks "Turn on backups"
  pass2=$(sed -n 's/^.*[│|]      \([A-Za-z0-9]\{40\}\)        [│|].*$/\1/p' "$W/out")
  [ "${#pass2}" = 40 ] || fail "second copy passphrase not shown in the box"
  env_is ROWSAFE_REPO2_S3_ENDPOINT s3.rowsafe.test
  env_is ROWSAFE_REPO2_S3_BUCKET rowsafe-copy2
  env_is ROWSAFE_REPO2_S3_REGION us-east-1
  env_is ROWSAFE_REPO2_S3_URI_STYLE path
  env_is ROWSAFE_REPO2_S3_KEY "$key"
  env_is ROWSAFE_REPO2_S3_KEY_SECRET "$secret"
  env_is ROWSAFE_REPO2_CIPHER_PASS "$pass2"
  [ "$(grep -E '^ROWSAFE_REPO_' /etc/rowsafe/agent.env | sort)" = "$first" ] || fail "--add-storage changed the first storage's settings"
  ! grep -q "^ROWSAFE_REPO_CIPHER_PASS='$pass2'" /etc/rowsafe/agent.env || fail "the second copy reused the first passphrase"
  [ "$(grep -c '^# Second backup copy' /etc/rowsafe/agent.env)" = 1 ] || fail "second copy block not added once"
  pass "second copy saved beside the first storage, with its own passphrase"

  # A re-run keeps it; --check-storage tests both.
  before=$(sha256sum /etc/rowsafe/agent.env)
  tty_ok "--add-storage again, keep it" "Move the second copy to another bucket?\tn\n" "$INSTALLER" --add-storage
  has "kept the second copy's settings"
  [ "$(sha256sum /etc/rowsafe/agent.env)" = "$before" ] || fail "keeping the second copy changed agent.env"
  expect_ok "--check-storage tests both storages" "$INSTALLER" --check-storage
  grep -q "Testing the second copy's storage" "$W/out" || fail "--check-storage skipped the second copy"
  [ "$(grep -c "backup storage works" "$W/out")" = 2 ] || fail "--check-storage: not both storages tested"

  # Without a terminal: from the environment, tested before anything is saved.
  expect_fail "--add-storage --no-prompt: a failing bucket saves nothing" "second copy's storage test failed" \
    env ROWSAFE_REPO2_S3_BUCKET=no-such-bucket "$INSTALLER" --add-storage --no-prompt
  [ "$(sha256sum /etc/rowsafe/agent.env)" = "$before" ] || fail "a failing second copy changed agent.env"
  expect_fail "--add-storage --no-prompt: the first bucket refused" "another bucket than the first storage" \
    env ROWSAFE_REPO2_S3_ENDPOINT=s3.eu-central-1.amazonaws.com ROWSAFE_REPO2_S3_BUCKET=rowsafe-test "$INSTALLER" --add-storage --no-prompt

  # Off again: the settings become comments, the first storage stays.
  expect_ok "--remove-second-copy" "$INSTALLER" --remove-second-copy
  grep -q "The second copy is off" "$W/out" || fail "--remove-second-copy: no message"
  ! grep -q '^ROWSAFE_REPO2_' /etc/rowsafe/agent.env || fail "--remove-second-copy left settings active"
  [ "$(grep -E '^ROWSAFE_REPO_' /etc/rowsafe/agent.env | sort)" = "$first" ] || fail "--remove-second-copy changed the first storage"
  expect_fail "--add-storage only goes with an install" "only go with an install" "$INSTALLER" --add-storage --check-storage
  pass "second copy: kept, checked, automation, removed"
}

# ------------------------------------------------------------ Rowsafe Storage

rowsafe_storage_tests() {
  echo "  -- Rowsafe Storage"
  api=https://api.rowsafe.test
  touch "$W/offer"

  # 1. Fresh install on a terminal: Rowsafe Storage is the default answer;
  # the passphrase is generated, shown once and confirmed.
  tty_ok "fresh install: Rowsafe Storage" \
    "Choose 1-2\t\nChoose 1-2\t1\nto continue\t{capture:[│|] {6}[A-Za-z0-9]{36}([A-Za-z0-9]{4}) }\n" \
    sh -c 'ROWSAFE_URL=$2 ROWSAFE_RELEASES_URL=https://localhost:8443/agent sh -s rse_secrettoken123 <"$1/install.sh"' piped "$W" "$api"
  has "Where should backups go?"
  has "1) Rowsafe Storage     nothing to set up (10 GB free)"
  has "Rowsafe can't read them"
  has "backups go to Rowsafe Storage, encrypted with your passphrase"
  has "storage      Rowsafe Storage"
  lacks "Bucket URL"
  lacks "Access key ID"
  lacks rse_secrettoken123
  rpass=$(sed -n 's/^.*[│|]      \([A-Za-z0-9]\{40\}\)        [│|].*$/\1/p' "$W/out")
  [ "${#rpass}" = 40 ] || fail "$name: passphrase not shown"
  env_is ROWSAFE_STORAGE rowsafe
  env_is ROWSAFE_REPO_CIPHER_PASS "$rpass"
  ! grep -q '^ROWSAFE_REPO_S3_' /etc/rowsafe/agent.env || fail "$name: bucket settings written for Rowsafe Storage"

  # 2. Re-run: nothing asked. With the agent enrolled and running, the
  # installer runs its storage test.
  tty_ok "re-run on Rowsafe Storage asks nothing" "" "$INSTALLER" --no-setup
  has "backup storage: Rowsafe Storage (change it with --setup-storage)"
  lacks "Where should backups go?"
  echo '{"host_id":"host_1","agent_token":"rsa_x"}' >/var/lib/rowsafe/agent.json
  chown postgres:postgres /var/lib/rowsafe/agent.json
  runuser -u postgres -- /opt/rowsafe/rowsafe-agent run >/dev/null 2>&1 &
  agent_pid=$!
  sleep 1
  scenario
  expect_ok "agent running: Rowsafe Storage tested" "$INSTALLER" --no-setup
  grep -q "Rowsafe Storage works: wrote, read back and deleted a test file" "$W/out" || fail "$name: no storage test"
  called "storage test --wait 60s"
  scenario storage_rc=1
  expect_ok "a failing storage test warns, the install goes on" "$INSTALLER" --no-setup
  grep -q "Rowsafe Storage didn't work yet" "$W/out" || fail "$name: no warning"
  expect_fail "--check-storage on Rowsafe Storage fails" "Rowsafe Storage test failed" "$INSTALLER" --check-storage
  scenario
  expect_ok "--check-storage on Rowsafe Storage" "$INSTALLER" --check-storage
  grep -q "Rowsafe Storage works" "$W/out" || fail "$name: no success"
  kill "$agent_pid" 2>/dev/null || true
  wait "$agent_pid" 2>/dev/null || true
  rm -f /var/lib/rowsafe/agent.json

  # 3. Move to one's own bucket: the passphrase is kept, ROWSAFE_STORAGE
  # goes back to its commented-out default.
  tty_ok "--setup-storage: keep Rowsafe Storage" "Move them to your own bucket?\t\n" "$INSTALLER" --setup-storage --no-setup
  has "kept Rowsafe Storage"
  env_is ROWSAFE_STORAGE rowsafe
  tty_ok "--setup-storage: move to your own bucket" \
    "Move them to your own bucket?\ty\nBucket URL\thttps://s3.rowsafe.test/rowsafe-test\nRegion (\t\nAccess key ID\t$key\nSecret access key\t$secret\nKeep the current encryption passphrase?\t\n" \
    "$INSTALLER" --setup-storage --no-setup
  has "Rowsafe takes a new full backup in your bucket right away"
  has "backup storage works"
  lacks "Where should backups go?"
  env_is ROWSAFE_REPO_S3_ENDPOINT s3.rowsafe.test
  env_is ROWSAFE_REPO_CIPHER_PASS "$rpass"
  ! grep -q '^ROWSAFE_STORAGE=' /etc/rowsafe/agent.env || fail "$name: ROWSAFE_STORAGE kept"
  grep -q "^#ROWSAFE_STORAGE='own'$" /etc/rowsafe/agent.env || fail "$name: ROWSAFE_STORAGE not back to the template"

  # 4. And back, choosing Rowsafe Storage at the "where" question.
  tty_ok "--setup-storage: own bucket to Rowsafe Storage" \
    "Replace these storage settings?\ty\nChoose 1-2\t1\nKeep the current encryption passphrase?\t\n" \
    env ROWSAFE_URL=$api "$INSTALLER" --setup-storage --no-setup
  has "Where should backups go?"
  env_is ROWSAFE_STORAGE rowsafe
  env_is ROWSAFE_REPO_CIPHER_PASS "$rpass"
  ! grep -q '^ROWSAFE_REPO_S3_ENDPOINT=' /etc/rowsafe/agent.env || fail "$name: the old bucket was kept active"
  lacks "$secret"
  lacks "$rpass"

  # 5. Not offered (a self-hosted control plane): the question is skipped.
  rm -f "$W/offer"
  expect_ok "purge" "$INSTALLER" --uninstall --purge
  tty_fail "not offered: straight to the bucket" 130 "Bucket URL\t{ctrl-c}\n" \
    env ROWSAFE_URL=$api "$INSTALLER" rse_secrettoken123
  lacks "Where should backups go?"
  touch "$W/offer"

  # 6. Without a terminal: --storage rowsafe generates the passphrase, keeps
  # it only in agent.env and says how to see it.
  expect_ok "purge" "$INSTALLER" --uninstall --purge
  expect_ok "--storage rowsafe without a terminal" "$INSTALLER" --storage rowsafe rse_secrettoken123
  grep -q "a backup encryption passphrase was generated and saved as ROWSAFE_REPO_CIPHER_PASS" "$W/out" || fail "$name: no passphrase note"
  env_is ROWSAFE_STORAGE rowsafe
  gen=$(sed -n "s/^ROWSAFE_REPO_CIPHER_PASS='\([A-Za-z0-9]\{40\}\)'\$/\1/p" /etc/rowsafe/agent.env)
  [ "${#gen}" = 40 ] || fail "$name: no generated passphrase in agent.env"
  ! grep -qF "$gen" "$W/out" || fail "$name: the generated passphrase was printed"
  grep -q "storage      Rowsafe Storage" "$W/out" || fail "$name: summary"
  expect_ok "--storage rowsafe again keeps the passphrase" "$INSTALLER" --storage rowsafe
  env_is ROWSAFE_REPO_CIPHER_PASS "$gen"
  ! grep -q "was generated" "$W/out" || fail "$name: generated a second passphrase"
  expect_ok "purge" "$INSTALLER" --uninstall --purge
  expect_ok "--storage rowsafe with a passphrase from the environment" \
    env ROWSAFE_REPO_CIPHER_PASS=my-own-passphrase-long-enough "$INSTALLER" --storage rowsafe rse_secrettoken123
  env_is ROWSAFE_REPO_CIPHER_PASS my-own-passphrase-long-enough
  ! grep -q "was generated" "$W/out" || fail "$name: generated a passphrase despite the environment"
  ! grep -qF my-own-passphrase-long-enough "$W/out" || fail "$name: printed the passphrase"
  expect_ok "purge" "$INSTALLER" --uninstall --purge
  rm -f "$W/offer"
  pass "Rowsafe Storage: choice, passphrase, storage test, moving both ways, no terminal"
}

# ------------------------------------------------------------ bucket URLs

# bucket_url_tests runs the installer's own parse_bucket_url (with the
# helpers it uses) on the URL forms each provider shows.
bucket_url_tests() {
  echo "  -- bucket URLs"
  {
    grep -E '^(host_of|matches)\(\) \{.*\}$' /src/scripts/install.sh
    grep -E '^BUCKET_RE=' /src/scripts/install.sh
    sed -n '/^parse_bucket_url() {$/,/^}$/p' /src/scripts/install.sh
  } >"$W/parse.sh"
  # shellcheck disable=SC1091
  . "$W/parse.sh"
  a=0123456789abcdef0123456789abcdef
  while IFS='>' read -r url want; do
    [ -n "$url" ] || continue
    rc=0
    parse_bucket_url "$url" || rc=$?
    got="$rc|$S_PROVIDER|$S_ENDPOINT|$S_PORT|$S_BUCKET|$S_REGION|$S_URI"
    [ "$got" = "$want" ] || fail "parse_bucket_url $url: got $got, want $want"
  done <<EOF
https://$a.r2.cloudflarestorage.com/backups>0|r2|$a.r2.cloudflarestorage.com||backups|auto|path
https://$a.eu.r2.cloudflarestorage.com/rowsafe-test/>0|r2|$a.eu.r2.cloudflarestorage.com||rowsafe-test|auto|path
$a.fedramp.r2.cloudflarestorage.com/b12>0|r2|$a.fedramp.r2.cloudflarestorage.com||b12|auto|path
https://$a.r2.cloudflarestorage.com>0|r2|$a.r2.cloudflarestorage.com|||auto|path
https://s3.us-west-004.backblazeb2.com/my-bucket>0|b2|s3.us-west-004.backblazeb2.com||my-bucket|us-west-004|path
https://my-bucket.s3.eu-central-003.backblazeb2.com>0|b2|s3.eu-central-003.backblazeb2.com||my-bucket|eu-central-003|path
https://my-bucket.s3.eu-central-1.amazonaws.com/>0|s3|s3.eu-central-1.amazonaws.com||my-bucket|eu-central-1|host
https://s3.us-east-2.amazonaws.com/my.bucket>0|s3|s3.us-east-2.amazonaws.com||my.bucket|us-east-2|path
https://my-bucket.s3.amazonaws.com>0|s3|s3.us-east-1.amazonaws.com||my-bucket|us-east-1|host
https://MY-BUCKET.S3-us-gov-west-1.amazonaws.com/x/y>0|s3|s3.us-gov-west-1.amazonaws.com||my-bucket|us-gov-west-1|host
s3://my-bucket/rowsafe>0|s3|||my-bucket||host
https://s3.eu-central-2.wasabisys.com/wb1>0|wasabi|s3.eu-central-2.wasabisys.com||wb1|eu-central-2|path
https://wb1.s3.wasabisys.com>0|wasabi|s3.us-east-1.wasabisys.com||wb1|us-east-1|path
https://space-1.fra1.digitaloceanspaces.com>0|spaces|fra1.digitaloceanspaces.com||space-1|us-east-1|host
https://space-1.fra1.cdn.digitaloceanspaces.com/>0|spaces|fra1.digitaloceanspaces.com||space-1|us-east-1|host
https://nyc3.digitaloceanspaces.com/space-1>0|spaces|nyc3.digitaloceanspaces.com||space-1|us-east-1|host
https://minio.example.com:9000/backups>0|s3-compatible|minio.example.com|9000|backups||path
https://s3.example.com:443/backups>0|s3-compatible|s3.example.com||backups||path
https://s3.example.com>0|s3-compatible|s3.example.com||||path
https://dash.cloudflare.com/0123/r2/default/buckets/b>2||||||
https://secure.backblaze.com/b2_buckets.htm>2||||||
ftp://example.com/b>1||||||
not a url>1||||||
EOF
  pass "parse_bucket_url: R2, B2, S3, Wasabi, Spaces and other endpoints"
}

# ------------------------------------------------------------ database setup

F=/tmp/rowsafe-fake

# scenario KEY=VALUE...: what the stand-in agent's `setup` answers.
# discover: cluster lines (\t, \n); CMD_rc: exit codes (one per line);
# CMD_out: what CMD prints.
scenario() {
  rm -rf "$F"
  mkdir -p "$F"
  chmod 777 "$F"
  for kv in "$@"; do
    k=${kv%%=*} v=${kv#*=}
    case $k in
      *_rc) printf '%b\n' "$v" >"$F/${k%_rc}.rc" ;;
      *_out) printf '%b\n' "$v" >"$F/${k%_out}.out" ;;
    esac
  done
  chmod 666 "$F"/* 2>/dev/null || true
}

called() { grep -q -- "$1" "$F/calls" 2>/dev/null || {
  cat "$F/calls" >&2 2>/dev/null
  fail "$name: the agent was not asked: $1"
}; }
not_called() { ! grep -q -- "$1" "$F/calls" 2>/dev/null || {
  cat "$F/calls" >&2
  fail "$name: the agent was asked: $1"
}; }

setup_flow_tests() {
  echo "  -- turning on backups"
  secret_key=AKIAEXAMPLEKEY42 secret=s3cr3t/with+base64= cipher='cipher-pass-that-is-long-enough/+=='
  configured() {
    env ROWSAFE_REPO_S3_ENDPOINT=acct.eu.r2.cloudflarestorage.com ROWSAFE_REPO_S3_BUCKET=app-rowsafe \
      ROWSAFE_REPO_S3_KEY="$secret_key" ROWSAFE_REPO_S3_KEY_SECRET="$secret" ROWSAFE_REPO_CIPHER_PASS="$cipher" "$@"
  }
  # restarts go through pg_ctlcluster here (no systemd); record them.
  cat >/usr/local/bin/pg_ctlcluster <<'EOF'
#!/bin/sh
echo "$*" >>/tmp/rowsafe-fake/pg_ctlcluster
EOF
  chmod 755 /usr/local/bin/pg_ctlcluster
  # What root sees of the clusters (the PgBouncer allow list comes from it,
  # never from the agent's own discovery).
  printf '#!/bin/sh\ncat /tmp/rowsafe-fake-clusters 2>/dev/null || printf "17 main 5432 online postgres /var/lib/postgresql/17/main -\\n17 other 5433 online postgres /var/lib/postgresql/17/other -\\n"\n' >/usr/local/bin/pg_lsclusters
  chmod 755 /usr/local/bin/pg_lsclusters
  scenario
  expect_ok "configured install, agent not running" configured "$INSTALLER" rse_secrettoken123
  grep -q "Once the agent runs, run this installer again" "$W/out" || fail "no next step without a running agent"
  [ ! -e "$F/calls" ] || fail "setup ran without a running agent"

  # The agent is enrolled and running from here on.
  echo '{"host_id":"host_1","agent_token":"rsa_x"}' >/var/lib/rowsafe/agent.json
  chown postgres:postgres /var/lib/rowsafe/agent.json
  runuser -u postgres -- /opt/rowsafe/rowsafe-agent run >/dev/null 2>&1 &
  sleep 1
  shop='5432\t/var/run/postgresql\t17\tmain\t/var/lib/postgresql/17/main\t1288490189\tshop\tno\t-\tshop\t1.2 GiB\tpostgresql@17-main.service\t-'
  plan='PostgreSQL 17.6 on port 5432: 1.2 GiB, 1 database (shop).\n\nWhat Rowsafe will change:\n  - Prepare your bucket for this database\n\nRestart: PostgreSQL needs one quick restart (a few seconds) before backups start.'
  done_='Checking that changes reach your storage...\n✓ shop is protected. The first full backup is running.'
  status='db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake'

  scenario
  expect_ok "without a terminal: next steps, nothing asked" "$INSTALLER"
  grep -q "Run this installer again from a terminal" "$W/out" || fail "no next step without a terminal"
  [ ! -e "$F/calls" ] || fail "setup ran without a terminal or --protect"

  # 1. Found, named (a bad name first), plan, yes, restart needed, restart now.
  scenario "discover_out=$shop" "plan_out=$plan" "apply_out=Done: the backup settings are in place." apply_rc=10 \
    "wait_out=$done_" "status_out=$status"
  tty_ok "turn on backups, restart now" \
    "Allow Rowsafe to restart or stop PostgreSQL when you ask?\tn\nAllow Rowsafe to install and manage PgBouncer?\tn\nName it in Rowsafe [shop]\tTV Hub\nName it in Rowsafe\t\nTurn on backups for shop now? [Y/n]\t\nRestart PostgreSQL now? [y/N]\ty\n" \
    env ROWSAFE_TEST_LEAK=1 "$INSTALLER"
  has "Looking for PostgreSQL on this server"
  has "Found PostgreSQL 17 on port 5432 (1.2 GiB; databases: shop)"
  has "Use 2-40 lowercase letters"
  has "Preparing a plan"
  has "Nothing changes until you say yes."
  has "Turning on backups for shop"
  has "open connections are dropped and apps reconnect"
  has "PostgreSQL restarted"
  has "✓ shop is protected. The first full backup is running."
  has "Dashboard: https://app.rowsafe.test/databases/db_fake"
  has "Rowsafe can't restart or stop PostgreSQL"
  called "plan --name shop --port 5432 --socket-dir /var/run/postgresql --engine postgresql --id-file"
  called "apply --database db_fake"
  called "wait --database db_fake --timeout 5m"
  [ "$(cat "$F/pg_ctlcluster")" = "17 main restart" ] || fail "$name: pg_ctlcluster not run as 17 main restart"
  grep -q "is off" /etc/rowsafe/restart-allowed || fail "$name: the no to restarts from Rowsafe was not kept"
  [ ! -e /usr/local/lib/rowsafe/rowsafe-pg-restart ] || fail "$name: restart helper installed after a no"
  has "Rowsafe won't install or manage PgBouncer"
  grep -q "is off" /etc/rowsafe/pooler-allowed || fail "$name: the no to PgBouncer was not kept"
  [ ! -e /etc/systemd/system/rowsafe-pooler.path ] || fail "$name: PgBouncer helper installed after a no"

  # 2. Restart later: the command, and that Rowsafe finishes by itself.
  scenario "discover_out=$shop" "plan_out=$plan" apply_rc=10
  tty_ok "turn on backups, restart later" \
    "Name it in Rowsafe\t\nTurn on backups for shop now?\ty\nRestart PostgreSQL now?\t\n" "$INSTALLER"
  lacks "Allow Rowsafe to restart or stop PostgreSQL"
  lacks "Allow Rowsafe to install and manage PgBouncer"
  has "Restart PostgreSQL when it suits you:"
  has "sudo systemctl restart postgresql@17-main"
  has "Rowsafe notices the restart by itself and finishes setting up. Nothing else to do."
  lacks "Restart PostgreSQL in the Rowsafe dashboard"
  [ ! -e "$F/pg_ctlcluster" ] || fail "$name: PostgreSQL was restarted after a no"
  not_called "wait "

  # 3. No restart needed.
  scenario "discover_out=$shop" "wait_out=$done_" "status_out=$status"
  tty_ok "turn on backups, no restart needed" "Name it in Rowsafe\t\nTurn on backups for shop now?\t\n" "$INSTALLER"
  lacks "Restart PostgreSQL now?"
  has "shop is protected"
  called "wait --database db_fake"

  # 4. No at "Turn on backups?": nothing applied.
  scenario "discover_out=$shop" "plan_out=$plan"
  tty_ok "declining changes nothing" "Name it in Rowsafe\t\nTurn on backups for shop now?\tn\n" "$INSTALLER"
  has "OK, nothing was changed."
  not_called "apply"

  # 5. A taken name is asked again; another archiver needs a yes to replace it.
  scenario "discover_out=$shop" "plan_out=the name is taken" "plan_rc=7\n3" "wait_out=$done_"
  tty_ok "taken name, another archiver replaced" \
    "Name it in Rowsafe\t\nName it in Rowsafe\tshop-2\nReplace it with Rowsafe? [y/N]\ty\n" "$INSTALLER"
  called "plan --name shop-2"
  called "apply --database db_fake --force"

  # 6. Several clusters: skip one; a registered one waiting for a restart.
  scenario "discover_out=$shop\n5433\t/var/run/postgresql\t16\tbilling\t/var/lib/postgresql/16/billing\t8192\tbilling\tyes\tawaiting_restart\tbilling\t8.0 KiB\t-\tdb_2"
  tty_ok "several clusters, one waiting for a restart" \
    "Set up backups for it?\tn\nRestart PostgreSQL now?\tn\n" "$INSTALLER"
  has "backups for billing wait for a restart"
  has "sudo pg_ctlcluster 16 billing restart"
  not_called "plan"

  # 7. --no-setup asks nothing; --protect asks nothing and never restarts.
  scenario "discover_out=$shop"
  tty_ok "--no-setup on a terminal" "" "$INSTALLER" --no-setup
  lacks "Looking for PostgreSQL"
  [ ! -e "$F/calls" ] || fail "$name: setup ran"
  scenario "discover_out=$shop" "plan_out=$plan" apply_rc=10
  expect_ok "--protect: turned on, restart left to the user" "$INSTALLER" --protect shop
  grep -q "sudo systemctl restart postgresql@17-main" "$W/out" || fail "--protect: no restart command"
  grep -q "Rowsafe notices the restart by itself" "$W/out" || fail "--protect: no auto-finish note"
  called "plan --name shop --port 5432"
  called "apply --database db_fake"
  [ ! -e "$F/pg_ctlcluster" ] || fail "--protect restarted PostgreSQL"
  scenario "discover_out=$shop\n5433\t/var/run/postgresql\t16\tbilling\t/var/lib/postgresql/16/billing\t8192\tbilling\tno\t-\tbilling\t8.0 KiB\t-\t-"
  expect_fail "--protect with several clusters needs --protect-port" "pick one with --protect-port" "$INSTALLER" --protect app
  scenario "discover_out=$shop\n5433\t/var/run/postgresql\t16\tbilling\t/var/lib/postgresql/16/billing\t8192\tbilling\tno\t-\tbilling\t8.0 KiB\t-\t-" plan_rc=4 \
    "plan_out=Your Free plan includes 1 database. Upgrade at the dashboard."
  expect_fail "--protect over the plan limit" "Upgrade at the dashboard" "$INSTALLER" --protect billing --protect-port 5433
  called "plan --name billing --port 5433"
  expect_fail "--protect-port needs --protect" "only goes with --protect" "$INSTALLER" --protect-port 5433
  expect_fail "--protect checks the name" "lowercase letters" "$INSTALLER" --protect Bad_Name
  pass "turning on backups: prompts, restarts, --protect, --no-setup"
}

# ------------------------------------------------------------ restarts

restart_tests() {
  echo "  -- restarts on request (--allow-restart)"
  H=/usr/local/lib/rowsafe/rowsafe-pg-restart
  R=/var/lib/rowsafe/restart
  scenario "discover_out=$shop"
  expect_ok "--allow-restart" "$INSTALLER" --allow-restart
  grep -q "Rowsafe may restart or stop PostgreSQL when you ask" "$W/out" || fail "--allow-restart not confirmed"
  grep -qx "5432 postgresql@17-main.service" /etc/rowsafe/restart-allowed || fail "allow list lacks 5432"
  [ "$(stat -c '%U %a' /etc/rowsafe/restart-allowed)" = "root 644" ] || fail "allow list ownership/mode"
  [ "$(stat -c '%U %a' "$H")" = "root 755" ] || fail "helper ownership/mode"
  [ "$(stat -c '%U %a' "$R")" = "postgres 700" ] || fail "request directory ownership/mode"
  cmp "$H" /src/scripts/rowsafe-pg-restart || fail "helper differs from scripts/rowsafe-pg-restart"
  cmp /etc/systemd/system/rowsafe-pg-restart.service /src/deploy/systemd/rowsafe-pg-restart.service || fail "restart service differs"
  cmp /etc/systemd/system/rowsafe-pg-restart.path /src/deploy/systemd/rowsafe-pg-restart.path || fail "restart path unit differs"
  if [ "${TEST_UNITS:-0}" = 1 ]; then
    expect_ok "systemd-analyze verify (restart units)" \
      systemd-analyze verify /etc/systemd/system/rowsafe-pg-restart.service /etc/systemd/system/rowsafe-pg-restart.path
    [ ! -s "$W/out" ] || {
      cat "$W/out" >&2
      fail "systemd-analyze verify printed warnings for the restart units"
    }
    systemd-analyze security --offline=true --no-pager /etc/systemd/system/rowsafe-pg-restart.service 2>/dev/null |
      tail -n 1 | sed "s/^/  rowsafe-pg-restart: /"
  fi
  # A re-run without the flag keeps it (and asks nothing).
  scenario "discover_out=$shop"
  tty_ok "a re-run keeps restarts allowed (and asks about updates once)" \
    "Allow Rowsafe to create a new PostgreSQL cluster here\tn\nAllow Rowsafe to install PostgreSQL updates when you click Update?\tn\nAllow Rowsafe to install this server's security updates\tn\nName it in Rowsafe\t\nTurn on backups for shop now?\tn\n" "$INSTALLER"
  lacks "Allow Rowsafe to restart or stop PostgreSQL"
  lacks "Allow Rowsafe to reboot"
  [ -f /etc/rowsafe/updates-allowed ] && ! grep -q '^[a-z]' /etc/rowsafe/updates-allowed || fail "no to updates not kept"
  [ ! -e /etc/systemd/system/rowsafe-pg-update.path ] || fail "update units installed after a no"
  grep -qx "5432 postgresql@17-main.service" /etc/rowsafe/restart-allowed || fail "a re-run dropped the allow list"

  # The helper, run as its service would (root, its own result and state
  # directories), with systemctl stood in.
  cat >"$F/systemctl" <<'EOF'
#!/bin/sh
echo "$*" >>/tmp/rowsafe-fake/systemctl.calls
exit "$(cat /tmp/rowsafe-fake/systemctl.rc 2>/dev/null || echo 0)"
EOF
  chmod 755 "$F/systemctl"
  O=$W/helper-run # the service's RuntimeDirectory: root, 0755
  install -d -m 0755 -o root -g root "$O"
  helper() {
    timeout 30 env ROWSAFE_SYSTEMCTL="$F/systemctl" STATE_DIRECTORY="$W/helper-state" RUNTIME_DIRECTORY="$O" "$H" 2>>"$W/helper.log" ||
      fail "the helper failed or hung (exit $?)"
  }
  # Requests are written by the agent user, as the agent does.
  as_pg() { runuser -u postgres -- "$@"; }
  request() {
    rm -f "$O/result"
    printf '%s\n' "$1" | as_pg sh -c 'cat >"$1"' sh "$R/request"
    helper
    [ ! -e "$R/request" ] && [ ! -L "$R/request" ] || fail "helper left the request: $1"
    [ -f "$O/result" ] && [ ! -L "$O/result" ] || fail "no result for: $1"
  }
  result_has() { grep -qxF "$1" "$O/result" || {
    cat "$O/result" >&2
    fail "helper result lacks $1"
  }; }
  calls() { cat "$F/systemctl.calls" 2>/dev/null | wc -l | tr -d ' '; }
  # Root must never create or change anything in the agent's directory.
  root_free() { [ -z "$(find "$R" -user root)" ] || {
    ls -la "$R" >&2
    fail "root left files in $R ($1)"
  }; }

  helper # no request: nothing happens
  [ ! -e "$O/result" ] || fail "helper answered without a request"
  request "task_1 5432"
  result_has "id=task_1"
  result_has "ok=1"
  result_has "unit=postgresql@17-main.service"
  [ "$(cat "$F/systemctl.calls")" = "restart postgresql@17-main.service" ] || fail "helper ran: $(cat "$F/systemctl.calls")"
  [ "$(stat -c '%U %a' "$O/result")" = "root 644" ] || fail "result ownership/mode"
  root_free "after a restart"
  request "task_2 5432"
  result_has "ok=0"
  result_has "error=PostgreSQL (postgresql@17-main.service) was restarted less than a minute ago; try again in a minute"
  request "task_3 5499"
  result_has "id=task_3"
  result_has "ok=0"
  grep -q "^error=port 5499 is not in /etc/rowsafe/restart-allowed" "$O/result" || fail "unlisted port not explained"
  request 'x; systemctl poweroff 5432'
  result_has "ok=0"
  result_has "error=malformed request"

  # Rewind: stop and start the listed unit (no once-a-minute limit), in the
  # "ID ACTION PORT" form; anything else is refused before systemctl runs.
  : >"$F/systemctl.calls"
  request "rw_1 stop 5432"
  result_has "id=rw_1"
  result_has "action=stop"
  result_has "ok=1"
  result_has "unit=postgresql@17-main.service"
  request "rw_1 start 5432"
  result_has "action=start"
  result_has "ok=1"
  request "rw_2 stop 5432"
  result_has "ok=1"
  request "rw_2 start 5432"
  result_has "ok=1"
  [ "$(cat "$F/systemctl.calls")" = "$(printf 'stop postgresql@17-main.service\nstart postgresql@17-main.service\nstop postgresql@17-main.service\nstart postgresql@17-main.service')" ] ||
    fail "helper ran for stop/start: $(cat "$F/systemctl.calls")"
  request "rw_3 restart 5432"
  result_has "action=restart"
  result_has "error=PostgreSQL (postgresql@17-main.service) was restarted less than a minute ago; try again in a minute"
  request "rw_4 stop 5499"
  result_has "ok=0"
  grep -q "^error=port 5499 is not in /etc/rowsafe/restart-allowed" "$O/result" || fail "unlisted port not refused for stop"
  for bad in "rw_5 kill 5432" "rw_5 STOP 5432" "rw_5 stop" "rw_5 stop 5432 extra" "rw_5  stop 5432" "rw_5 stop 5432;reboot" \
    "rw_5 stop postgresql@17-main.service" "rw_5 disable 5432" "rw_5 stop 123456" "rw.5 stop 5432"; do
    request "$bad"
    result_has "ok=0"
    result_has "error=malformed request"
  done
  [ "$(calls)" = 4 ] || fail "helper ran systemctl for a refused stop/start: $(cat "$F/systemctl.calls")"
  : >"$F/systemctl.calls"
  echo "restart postgresql@17-main.service" >"$F/systemctl.calls"
  root_free "after stop and start"

  # A request symlinked to a file only root can read (holding a valid
  # request) is neither read nor followed; its target stays as it was.
  rm -rf "$W/helper-state"
  printf 'task_9 5432\n' >"$W/sentinel"
  chmod 600 "$W/sentinel"
  before=$(stat -c '%U %a %s %Y' "$W/sentinel")
  as_pg ln -s "$W/sentinel" "$R/request"
  rm -f "$O/result"
  helper
  [ ! -L "$R/request" ] || fail "helper left a symlinked request"
  result_has "error=malformed request"
  [ "$(stat -c '%U %a %s %Y' "$W/sentinel")" = "$before" ] && [ "$(cat "$W/sentinel")" = "task_9 5432" ] ||
    fail "a symlinked request changed its target"
  # A symlink planted where results used to go (the agent's directory) is
  # never written through: results go to root's own directory, where the
  # agent can't plant anything.
  echo keep >"$W/victim"
  as_pg ln -s "$W/victim" "$R/result"
  request "task_10 5499"
  [ "$(cat "$W/victim")" = keep ] || fail "helper wrote through a planted symlink"
  ! as_pg ln -s "$W/victim" "$O/.result.planted" 2>/dev/null || fail "the agent user can plant files in the helper's result directory"
  as_pg rm -f "$R/result"
  # A FIFO request can't make the helper wait.
  as_pg mkfifo "$R/request"
  rm -f "$O/result"
  start=$(date +%s)
  helper
  [ $(($(date +%s) - start)) -lt 10 ] || fail "a FIFO request held the helper"
  [ ! -e "$R/request" ] || fail "helper left the FIFO"
  result_has "error=malformed request"
  [ "$(calls)" = 1 ] || fail "helper ran systemctl for a refused request"
  root_free "after refused requests"

  echo 1 >"$F/systemctl.rc"
  request "task_4 5432"
  result_has "ok=0"
  grep -q "^error=systemctl restart postgresql@17-main.service failed" "$O/result" || fail "failed restart not reported"
  request "rw_6 stop 5432"
  result_has "ok=0"
  grep -q "^error=systemctl stop postgresql@17-main.service failed" "$O/result" || fail "failed stop not reported"
  rm -f "$F/systemctl.rc"
  chmod 666 /etc/rowsafe/restart-allowed
  rm -rf "$W/helper-state"
  request "task_5 5432"
  result_has "error=/etc/rowsafe/restart-allowed is writable by others than root"
  chmod 644 /etc/rowsafe/restart-allowed
  grep -q "rowsafe-pg-restart: restart postgresql@17-main.service: done" "$W/helper.log" || fail "helper did not log the restart"
  pass "restart helper: allow list, bad requests, symlinks, FIFO, once a minute, never writes in the agent's directory"

  # The installer never acts as root inside the agent's directories: a
  # symlink the agent user plants there doesn't make root change its target.
  install -d -m 0700 -o root -g root "$W/sentinel-dir"
  as_pg rm -rf /opt/rowsafe/versions/0.12.0 "$R"
  as_pg ln -s "$W/sentinel-dir" /opt/rowsafe/versions/0.12.0
  as_pg ln -s "$W/sentinel-dir" "$R"
  if env ROWSAFE_VERSION=0.12.0 "$INSTALLER" >"$W/out" 2>&1; then
    cat "$W/out" >&2
    fail "installed into a planted symlink"
  fi
  [ "$(stat -c '%U %a' "$W/sentinel-dir")" = "root 700" ] && [ -z "$(ls -A "$W/sentinel-dir")" ] ||
    fail "the installer changed a planted symlink's target"
  as_pg rm -f /opt/rowsafe/versions/0.12.0 "$R"
  as_pg mkdir -m 0700 "$R"
  pass "the installer doesn't follow symlinks planted in the agent's directories"

  pooler_tests
  update_tests

  expect_ok "--no-allow-restart" "$INSTALLER" --no-allow-restart
  [ ! -e /etc/systemd/system/rowsafe-pg-update.path ] && [ ! -e /etc/rowsafe/updates-allowed ] || fail "--no-allow-restart left updates allowed"
  [ ! -e "$H" ] && [ ! -e /etc/systemd/system/rowsafe-pg-restart.service ] && [ ! -e /etc/systemd/system/rowsafe-pg-restart.path ] ||
    fail "--no-allow-restart left the helper"
  ! grep -q '^[0-9]' /etc/rowsafe/restart-allowed || fail "--no-allow-restart kept the allow list"
  scenario "discover_out=$shop"
  expect_ok "--allow-restart again" "$INSTALLER" --allow-restart
  pkill -u postgres -f 'rowsafe-agent run' || true
  expect_ok "uninstall removes the restart helper" "$INSTALLER" --uninstall
  [ ! -e "$H" ] && [ ! -e /etc/systemd/system/rowsafe-pg-restart.path ] || fail "uninstall left the restart helper"
  expect_ok "purge" "$INSTALLER" --uninstall --purge
  [ ! -e /etc/rowsafe ] || fail "purge left /etc/rowsafe"
  pass "--no-allow-restart, uninstall and purge remove the restart helper"
}

# ------------------------------------------------------------ PgBouncer

# pooler_tests: --allow-pooler, and the helper in PgBouncer mode with apt-get
# and systemctl stood in (called from restart_tests, which set up $H, $F,
# $W, the systemctl stand-in, request, result_has and as_pg).
pooler_tests() {
  echo "  -- PgBouncer on request (--allow-pooler)"
  PR=/var/lib/rowsafe/pooler
  # The agent's discovery (agent-owned code) also claims 5499: ignored.
  scenario "discover_out=$shop\n5499\t/var/run/postgresql\t17\tevil\t/var/lib/postgresql/17/evil\t8192\tevil\tno\t-\tevil\t8.0 KiB\t-\t-"
  expect_ok "--allow-pooler" "$INSTALLER" --allow-pooler
  grep -q "Rowsafe may install and manage PgBouncer when you turn pooling on" "$W/out" || fail "--allow-pooler not confirmed"
  grep -qx "5432" /etc/rowsafe/pooler-allowed && grep -qx "5433" /etc/rowsafe/pooler-allowed || fail "pooler allow list lacks root's clusters"
  ! grep -q "5499" /etc/rowsafe/pooler-allowed || fail "a port only the agent's discovery reported was allowed"
  ! grep -qx public /etc/rowsafe/pooler-allowed || fail "public allowed without --allow-pooler-public"
  [ -e /etc/systemd/system/rowsafe-pooler-apt@.service ] && [ -d /etc/systemd/system/pgbouncer.service.d ] || fail "apt unit or drop-in directory missing"
  cmp "/etc/systemd/system/rowsafe-pooler-apt@.service" "/src/deploy/systemd/rowsafe-pooler-apt@.service" || fail "pooler apt unit differs"
  [ "$(stat -c '%U %a' /etc/rowsafe/pooler-allowed)" = "root 644" ] || fail "pooler allow list ownership/mode"
  [ "$(stat -c '%U %a' "$PR")" = "postgres 700" ] || fail "pooler request directory ownership/mode"
  cmp "$H" /src/scripts/rowsafe-pg-restart || fail "helper differs from scripts/rowsafe-pg-restart"
  cmp /etc/systemd/system/rowsafe-pooler.service /src/deploy/systemd/rowsafe-pooler.service || fail "pooler service differs"
  cmp /etc/systemd/system/rowsafe-pooler.path /src/deploy/systemd/rowsafe-pooler.path || fail "pooler path unit differs"
  if [ "${TEST_UNITS:-0}" = 1 ]; then
    expect_ok "systemd-analyze verify (pooler units)" \
      systemd-analyze verify /etc/systemd/system/rowsafe-pooler.service /etc/systemd/system/rowsafe-pooler.path
    [ ! -s "$W/out" ] || {
      cat "$W/out" >&2
      fail "systemd-analyze verify printed warnings for the pooler units"
    }
    systemd-analyze security --offline=true --no-pager /etc/systemd/system/rowsafe-pooler.service 2>/dev/null |
      tail -n 1 | sed "s/^/  rowsafe-pooler: /"
  fi
  scenario "discover_out=$shop"
  tty_ok "a re-run keeps PgBouncer allowed" "Name it in Rowsafe\t\nTurn on backups for shop now?\tn\n" "$INSTALLER"
  lacks "Allow Rowsafe to install and manage PgBouncer"
  grep -qx "5432" /etc/rowsafe/pooler-allowed || fail "a re-run dropped the pooler allow list"
  # A cluster found since is added only when someone says yes on a terminal.
  printf '17 main 5432 online postgres - -\n17 other 5433 online postgres - -\n17 new 5434 online postgres - -\n' >/tmp/rowsafe-fake-clusters
  scenario "discover_out=$shop"
  expect_ok "a re-run without a terminal" "$INSTALLER"
  ! grep -qx "5434" /etc/rowsafe/pooler-allowed || fail "a re-run added a cluster without asking"
  scenario "discover_out=$shop"
  tty_ok "a re-run asks about a new cluster" "Also allow PgBouncer for the PostgreSQL on port 5434?\ty\nName it in Rowsafe\t\nTurn on backups for shop now?\tn\n" "$INSTALLER"
  grep -qx "5434" /etc/rowsafe/pooler-allowed || fail "a yes didn't add the new cluster"
  rm -f /tmp/rowsafe-fake-clusters

  # The helper in PgBouncer mode, run as rowsafe-pooler.service would
  # (scenario reset the stand-ins). Starting rowsafe-pooler-apt@ACTION runs
  # the helper in its package mode, as that unit would.
  cat >"$F/systemctl" <<EOF
#!/bin/sh
echo "\$*" >>/tmp/rowsafe-fake/systemctl.calls
case "\$1 \$2" in
  "start rowsafe-pooler-apt@install.service") exec env ROWSAFE_HELPER_MODE=pooler-apt ROWSAFE_APT_ACTION=install "$H" ;;
  "start rowsafe-pooler-apt@purge.service") exec env ROWSAFE_HELPER_MODE=pooler-apt ROWSAFE_APT_ACTION=purge "$H" ;;
esac
exit "\$(cat /tmp/rowsafe-fake/systemctl.rc 2>/dev/null || echo 0)"
EOF
  chmod 755 "$F/systemctl"
  cat >"$F/apt-get" <<'APT_EOF'
#!/bin/sh
echo "$*" >>/tmp/rowsafe-fake/apt.calls
case "$*" in
  *install*pgbouncer*) printf '#!/bin/sh\necho "PgBouncer 1.24.1"\n' >/usr/local/bin/pgbouncer && chmod 755 /usr/local/bin/pgbouncer ;;
  *purge*pgbouncer*) rm -f /usr/local/bin/pgbouncer ;;
esac
APT_EOF
  chmod 755 "$F/apt-get"
  OP=$W/pooler-run
  install -d -m 0755 -o root -g root "$OP"
  PGB=$W/etc-pgbouncer
  rm -rf "$PGB" "$W/pooler-state" "$W/systemd"
  : >"$F/systemctl.calls"
  pooler_helper() {
    timeout 30 env ROWSAFE_HELPER_MODE=pooler ROWSAFE_RESTART_DIR="$PR" ROWSAFE_SYSTEMCTL="$F/systemctl" ROWSAFE_APT_GET="$F/apt-get" \
      ROWSAFE_PGBOUNCER_DIR="$PGB" ROWSAFE_SYSTEMD_DIR="$W/systemd" STATE_DIRECTORY="$W/pooler-state" RUNTIME_DIRECTORY="$OP" \
      "$H" 2>>"$W/helper.log" || fail "the PgBouncer helper failed or hung (exit $?)"
  }
  prequest() {
    rm -f "$OP/result"
    printf '%s\n' "$1" | as_pg sh -c 'cat >"$1"' sh "$PR/request"
    pooler_helper
    [ ! -e "$PR/request" ] && [ ! -L "$PR/request" ] || fail "helper left the request: $1"
    [ -f "$OP/result" ] || fail "no result for: $1"
  }
  presult() { grep -qxF "$1" "$OP/result" || {
    cat "$OP/result" >&2
    fail "PgBouncer helper result lacks $1"
  }; }
  pw=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  good="dbport=5432 listen=127.0.0.1,10.0.0.5 port=6432 mode=transaction pool_size=20 reserve_pool=5 max_db_conn=60 max_client_conn=1000 prepared=200 target_host=127.0.0.1 target_port=5432 restart=1 auth_dbname=postgres dbs=shop,app-2"

  pooler_helper # no request: nothing happens
  [ ! -e "$OP/result" ] || fail "PgBouncer helper answered without a request"
  rm -f /usr/local/bin/pgbouncer /tmp/rowsafe-fake/apt.calls
  prequest "pb_1 pooler-install"
  presult "ok=1"
  presult "installed=1"
  presult "version=1.24.1"
  grep -q "install -y -q --no-install-recommends pgbouncer" /tmp/rowsafe-fake/apt.calls || fail "apt-get install not run: $(cat /tmp/rowsafe-fake/apt.calls)"
  grep -qx "start rowsafe-pooler-apt@install.service" "$F/systemctl.calls" || fail "the package wasn't installed in its own unit"
  # At most one install or removal every 10 minutes.
  mv /usr/local/bin/pgbouncer "$W/pgbouncer.keep"
  rm -f /tmp/rowsafe-fake/apt.calls
  prequest "pb_c pooler-install"
  presult "ok=0"
  grep -q "^error=PgBouncer was installed or removed less than 10 minutes ago" "$OP/result" || fail "no cooldown between installs"
  [ ! -e /tmp/rowsafe-fake/apt.calls ] || fail "apt-get ran during the cooldown"
  mv "$W/pgbouncer.keep" /usr/local/bin/pgbouncer
  prequest "pb_1 pooler-configure $good password=$pw"
  presult "ok=1"
  presult "running=1"
  ini=$PGB/pgbouncer.ini
  [ "$(head -n 1 "$ini")" = ";; Managed by Rowsafe" ] || fail "config lacks the marker"
  for line in "* = host=127.0.0.1 port=5432 auth_user=rowsafe_pgbouncer" "shop = host=127.0.0.1 port=5432 auth_user=rowsafe_pgbouncer" \
    "app-2 = host=127.0.0.1 port=5432 auth_user=rowsafe_pgbouncer" "listen_addr = 127.0.0.1,10.0.0.5" "listen_port = 6432" \
    "auth_type = scram-sha-256" "auth_dbname = postgres" "pool_mode = transaction" "default_pool_size = 20" \
    "max_prepared_statements = 200" "admin_users = rowsafe_pgbouncer" 'auth_query = SELECT uname, phash FROM rowsafe_pgbouncer.user_lookup($1)'; do
    grep -qxF "$line" "$ini" || fail "config lacks: $line"
  done
  grep -qxF "\"rowsafe_pgbouncer\" \"$pw\"" "$PGB/userlist.txt" || fail "userlist lacks the password"
  [ "$(stat -c '%U %G %a' "$ini")" = "root postgres 640" ] && [ "$(stat -c '%U %G %a' "$PGB/userlist.txt")" = "root postgres 640" ] ||
    fail "config ownership/mode: $(stat -c '%U %G %a' "$ini" "$PGB/userlist.txt")"
  [ "$(stat -c '%U %a' "$PGB")" = "root 755" ] || fail "config directory ownership/mode"
  grep -q "LimitNOFILE=65536" "$W/systemd/pgbouncer.service.d/rowsafe.conf" || fail "no file limit drop-in"
  grep -qx "restart pgbouncer.service" "$F/systemctl.calls" || fail "PgBouncer not (re)started: $(cat "$F/systemctl.calls")"
  grep -q "enable --quiet pgbouncer.service" "$F/systemctl.calls" || fail "PgBouncer not enabled"
  [ -z "$(find "$PR" -user root)" ] || fail "root left files in $PR"
  # Without a password, the existing userlist stays; restart=0 doesn't restart.
  : >"$F/systemctl.calls"
  prequest "pb_2 pooler-configure $(printf '%s' "$good" | sed 's/restart=1/restart=0/; s/target_port=5432/target_port=5433/')"
  presult "ok=1"
  grep -qxF "* = host=127.0.0.1 port=5433 auth_user=rowsafe_pgbouncer" "$ini" || fail "retarget not written"
  grep -qF "$pw" "$PGB/userlist.txt" || fail "userlist lost its password"
  ! grep -q "^restart" "$F/systemctl.calls" || fail "restart=0 restarted PgBouncer"
  prequest "pb_3 pooler-reload"
  presult "ok=1"
  grep -qx "reload pgbouncer.service" "$F/systemctl.calls" || fail "reload not run"
  # PgBouncer only reaches allowed ports on 127.0.0.1.
  for bad in "target_host=10.9.9.9" "target_host=db.example.com" "target_port=5499"; do
    key=${bad%%=*}
    prequest "pb_t pooler-configure $(printf '%s' "$good" | sed "s/$key=[^ ]*//; s/  */ /g") $bad"
    presult "ok=0"
  done
  grep -q "^error=port 5499 is not in /etc/rowsafe/pooler-allowed: PgBouncer can't send connections there" "$OP/result" || fail "a foreign target port not refused"
  # Every address only with root's --allow-pooler-public.
  prequest "pb_p pooler-configure $(printf '%s' "$good" | sed 's/listen=[^ ]*/listen=*/')"
  presult "ok=0"
  grep -q "^error=listening on every address isn't allowed" "$OP/result" || fail "listen=* not refused"
  cp /etc/rowsafe/pooler-allowed "$W/allow.keep"
  echo public >>/etc/rowsafe/pooler-allowed
  prequest "pb_p pooler-configure $(printf '%s' "$good" | sed 's/listen=[^ ]*/listen=*/')"
  presult "ok=1"
  grep -qxF "listen_addr = *" "$ini" || fail "listen=* not written with the opt-in"
  cp "$W/allow.keep" /etc/rowsafe/pooler-allowed
  prequest "pb_2 pooler-configure $(printf '%s' "$good" | sed 's/restart=1/restart=0/; s/target_port=5432/target_port=5433/')"
  presult "ok=1"
  # Refusals: an unlisted port, bad values, anything that isn't a plain value.
  prequest "pb_4 pooler-configure $(printf '%s' "$good" | sed 's/dbport=5432/dbport=5499/')"
  presult "ok=0"
  grep -q "^error=port 5499 is not in /etc/rowsafe/pooler-allowed" "$OP/result" || fail "unlisted pooler port not refused"
  for bad in "mode=statement" "listen=localhost" "target_host=-evil" "pool_size=0" "port=80" "password=NOTHEX" \
    "auth_dbname=Bad-Name" "max_client_conn=5" "pool_size=007" "dbs=pgbouncer" "dbs=a.b"; do
    key=${bad%%=*}
    prequest "pb_5 pooler-configure $(printf '%s' "$good" | sed "s/$key=[^ ]*//; s/  */ /g") $bad"
    presult "ok=0"
  done
  # shellcheck disable=SC2016 # literal $(reboot) must reach the helper
  for bad in "pb_6 pooler-configure listen=1.2.3.4;reboot" 'pb_6 pooler-configure target_host=$(reboot)' "pb_6 pooler-evil" \
    "pb 6 pooler-install" "pb_6 restart 5432" "pb_6 pooler-configure mode=transaction ; x=1"; do
    prequest "$bad"
    presult "ok=0"
  done
  grep -qxF "* = host=127.0.0.1 port=5433 auth_user=rowsafe_pgbouncer" "$ini" || fail "a refused request changed the config"
  # Someone else's PgBouncer configuration is never replaced.
  cp "$ini" "$W/ini.rowsafe"
  printf '[databases]\nmine = host=10.9.9.9\n' >"$ini"
  prequest "pb_7 pooler-configure $good password=$pw"
  presult "ok=0"
  grep -q "has its own configuration" "$OP/result" || fail "a foreign config was not refused"
  grep -q "mine = host=10.9.9.9" "$ini" || fail "a foreign config was replaced"
  cp "$W/ini.rowsafe" "$ini"
  # A group-writable allow list is refused.
  chmod 664 /etc/rowsafe/pooler-allowed
  prequest "pb_8 pooler-reload"
  presult "error=/etc/rowsafe/pooler-allowed is writable by others than root"
  chmod 644 /etc/rowsafe/pooler-allowed
  # PgBouncer requests never reach the restart helper's mode.
  request "pb_9 pooler-reload"
  result_has "error=malformed request"
  # Off: stopped, drop-in removed, and the package Rowsafe installed purged
  # (10 minutes after it was installed).
  rm -f "$W/pooler-state/last-apt"
  : >"$F/systemctl.calls"
  prequest "pb_10 pooler-off remove_package=1"
  presult "ok=1"
  presult "removed=1"
  grep -qx "stop pgbouncer.service" "$F/systemctl.calls" && grep -q "disable --quiet pgbouncer.service" "$F/systemctl.calls" ||
    fail "PgBouncer not stopped and disabled"
  grep -q "purge -y -q pgbouncer" /tmp/rowsafe-fake/apt.calls || fail "package not purged"
  [ ! -e "$ini" ] && [ ! -e "$W/systemd/pgbouncer.service.d/rowsafe.conf" ] || fail "off left files"
  [ ! -e /usr/local/bin/pgbouncer ] || fail "pgbouncer still installed"
  # A package that was there before is kept, with its own files put back.
  printf '#!/bin/sh\necho "PgBouncer 1.18.0"\n' >/usr/local/bin/pgbouncer
  chmod 755 /usr/local/bin/pgbouncer
  install -d -o postgres -g postgres "$PGB"
  rm -f /tmp/rowsafe-fake/apt.calls
  prequest "pb_11 pooler-install"
  presult "installed=0"
  presult "version=1.18.0"
  [ ! -e /tmp/rowsafe-fake/apt.calls ] || fail "apt-get ran for an installed package"
  prequest "pb_11 pooler-configure $good password=$pw"
  presult "ok=1"
  prequest "pb_12 pooler-off remove_package=1"
  presult "removed=0"
  [ -x /usr/local/bin/pgbouncer ] || fail "a package Rowsafe didn't install was removed"
  rm -f /usr/local/bin/pgbouncer
  grep -q "pooler-configure: done (request pb_1)" "$W/helper.log" || fail "PgBouncer helper did not log"
  pass "PgBouncer helper: install, configure from its template, reload, off; allow list, bad values, foreign configs"

  expect_ok "--no-allow-pooler" "$INSTALLER" --no-allow-pooler
  [ ! -e /etc/systemd/system/rowsafe-pooler.service ] && [ ! -e /etc/systemd/system/rowsafe-pooler.path ] || fail "--no-allow-pooler left the units"
  [ -e "$H" ] || fail "--no-allow-pooler removed the helper restarts still use"
  grep -q "is off" /etc/rowsafe/pooler-allowed || fail "--no-allow-pooler kept the allow list"
  scenario "discover_out=$shop"
  expect_ok "--allow-pooler again" "$INSTALLER" --allow-pooler
  expect_ok "--no-allow-restart keeps the helper for PgBouncer" "$INSTALLER" --no-allow-restart
  [ -e "$H" ] && [ -e /etc/systemd/system/rowsafe-pooler.path ] || fail "--no-allow-restart removed the helper PgBouncer uses"
  expect_ok "--no-allow-pooler" "$INSTALLER" --no-allow-pooler
  [ ! -e "$H" ] || fail "the helper stayed with neither restarts nor PgBouncer allowed"
  scenario "discover_out=$shop"
  expect_ok "--allow-restart" "$INSTALLER" --allow-restart
  pass "--allow-pooler / --no-allow-pooler install and remove the PgBouncer helper"
}

# ------------------------------------------------------------ MySQL servers

# mysql_host_tests: a server with MySQL and no PostgreSQL. The agent runs as
# mysql (a unit drop-in), Percona XtraBackup comes from Percona's repository
# after its key's fingerprint is checked, Rowsafe's option file is included
# from /etc/mysql/conf.d, AppArmor's mysqld profile lets mysqld use Rowsafe's
# folders, and a purge keeps the server's binary log settings.
mysql_host_tests() {
  echo "  -- a MySQL server (no PostgreSQL)"
  pkill -u postgres -f 'rowsafe-agent run' 2>/dev/null || true
  userdel -r postgres 2>/dev/null || userdel postgres
  rm -rf /usr/lib/postgresql /var/lib/postgresql
  useradd --system --home-dir /nonexistent --no-create-home --shell /bin/false mysql
  printf '#!/bin/sh\necho "/usr/sbin/mysqld  Ver 8.4.3 for Linux on x86_64 (MySQL Community Server - GPL)"\n' >/usr/sbin/mysqld
  chmod 755 /usr/sbin/mysqld
  mkdir -p /etc/mysql/conf.d /etc/apparmor.d
  echo '#include <local/usr.sbin.mysqld>' >/etc/apparmor.d/usr.sbin.mysqld
  # Percona's key comes over the internet; the releases from the local server.
  cat /etc/ssl/certs/ca-certificates.crt "$W/tls.crt" >"$W/both.crt"
  export CURL_CA_BUNDLE=$W/both.crt
  expect_ok "MySQL server: configured install" configured env ROWSAFE_ENROLL_TOKEN=rse_secrettoken123 "$INSTALLER" --no-setup
  [ -z "${TEST_SHOW:-}" ] || cat "$W/out"
  grep -q "restore tests for the MySQL on this server" "$W/out" || fail "installer doesn't speak of MySQL"
  dpkg -s percona-xtrabackup-84 >/dev/null 2>&1 || fail "percona-xtrabackup-84 not installed"
  [ -s /usr/share/keyrings/rowsafe-percona.gpg ] || fail "Percona keyring missing"
  grep -q 'signed-by=/usr/share/keyrings/rowsafe-percona.gpg\] https://repo.percona.com/pxb-84-lts/apt' \
    /etc/apt/sources.list.d/rowsafe-percona-xtrabackup.list || fail "Percona source not pinned to its key"
  grep -qx 'User=mysql' /etc/systemd/system/rowsafe-agent.service.d/10-mysql.conf || fail "no drop-in running the agent as mysql"
  cmp /etc/systemd/system/rowsafe-agent.service /src/deploy/systemd/rowsafe-agent.service || fail "the unit itself changed"
  [ "$(stat -c '%U %a' /etc/rowsafe/agent.env)" = "mysql 600" ] || fail "agent.env ownership/mode on a MySQL server"
  [ "$(stat -c '%U %G %a' /etc/rowsafe)" = "root mysql 750" ] || fail "/etc/rowsafe ownership/mode on a MySQL server"
  [ "$(stat -c '%U %a' /etc/rowsafe/mysql/server.cnf)" = "mysql 640" ] || fail "Rowsafe's option file ownership/mode"
  [ "$(readlink /etc/mysql/conf.d/zz-rowsafe.cnf)" = /etc/rowsafe/mysql/server.cnf ] || fail "option file not included from conf.d"
  grep -q '^/var/lib/rowsafe/\*\* rwk,$' /etc/apparmor.d/local/usr.sbin.mysqld || fail "AppArmor override missing"
  command -v pgbackrest >/dev/null || fail "pgbackrest (storage test) not installed"
  pass "MySQL server: agent as mysql, XtraBackup from Percona (key checked), option file and AppArmor"
  expect_ok "MySQL server: re-run is idempotent" configured "$INSTALLER" --no-setup
  [ "$(grep -c "^# Rowsafe:" /etc/apparmor.d/local/usr.sbin.mysqld)" = 1 ] || fail "AppArmor override added twice"
  echo "log_bin = binlog" >>/etc/rowsafe/mysql/server.cnf
  expect_ok "MySQL server: purge" "$INSTALLER" --uninstall --purge
  [ -f /etc/mysql/conf.d/zz-rowsafe.cnf ] && [ ! -L /etc/mysql/conf.d/zz-rowsafe.cnf ] &&
    grep -q '^log_bin = binlog$' /etc/mysql/conf.d/zz-rowsafe.cnf || fail "purge dropped the server's binary log settings"
  [ ! -e /etc/systemd/system/rowsafe-agent.service.d/10-mysql.conf ] || fail "uninstall left the drop-in"
  pass "MySQL server: purge keeps the server's binary log settings as a plain file"
}

# ------------------------------------------------------------ updates

update_tests() {
  echo "  -- updates on request (--allow-updates, --allow-security-updates, --allow-reboot)"
  U=/etc/rowsafe/updates-allowed
  scenario "discover_out=$shop"
  expect_ok "--allow-updates" "$INSTALLER" --allow-updates
  grep -q "Rowsafe may install PostgreSQL updates and upgrade PostgreSQL" "$W/out" || fail "--allow-updates not confirmed"
  grep -q '^postgresql ' "$U" && ! grep -q '^security' "$U" && ! grep -q '^reboot' "$U" || fail "updates allow list: $(cat "$U")"
  [ "$(stat -c '%U %a' "$U")" = "root 644" ] || fail "updates allow list ownership/mode"
  cmp /etc/systemd/system/rowsafe-pg-update.service /src/deploy/systemd/rowsafe-pg-update.service || fail "update service differs"
  cmp /etc/systemd/system/rowsafe-pg-update.path /src/deploy/systemd/rowsafe-pg-update.path || fail "update path unit differs"
  if [ "${TEST_UNITS:-0}" = 1 ]; then
    expect_ok "systemd-analyze verify (update units)" \
      systemd-analyze verify /etc/systemd/system/rowsafe-pg-update.service /etc/systemd/system/rowsafe-pg-update.path
  fi
  scenario "discover_out=$shop"
  tty_ok "a re-run keeps the update answers" "Name it in Rowsafe\t\nTurn on backups for shop now?\tn\n" "$INSTALLER"
  lacks "install PostgreSQL updates when you click"
  scenario "discover_out=$shop"
  expect_ok "--allow-security-updates --allow-reboot" "$INSTALLER" --allow-security-updates --allow-reboot
  grep -q '^postgresql ' "$U" && grep -q '^security ' "$U" && grep -q '^reboot ' "$U" || fail "updates allow list: $(cat "$U")"

  # The helper in update mode, with apt, dpkg, the cluster tools and
  # systemctl stood in. The stand-ins keep their state in $S.
  S=$F/cluster
  B=$F/bin
  rm -rf "$S" "$B"
  mkdir -p "$S" "$B"
  chmod 777 "$S"
  cat >"$B/fake" <<'FAKE_EOF'
#!/bin/sh
S=/tmp/rowsafe-fake/cluster
cmd=${0##*/}
echo "$cmd $*" >>"$S/calls"
case $cmd in
  pg_lsclusters) cat "$S/clusters" 2>/dev/null ;;
  dpkg-query)
    case $* in
      *'${Version}'*)
        for a; do pkg=$a; done
        cat "$S/version-${pkg#postgresql-}" 2>/dev/null ;;
      *postgresql-17-\**) echo "ii  postgresql-17-cron" ;;
      *postgresql-18-\**) [ ! -e "$S/installed-18" ] || echo "ii  postgresql-18-cron" ;;
      *postgresql-18*) [ ! -e "$S/installed-18" ] || echo "ii  postgresql-18" ;;
    esac ;;
  apt-cache) printf '%s:\n  Installed: (none)\n  Candidate: 1.0-1\n' "$2" ;;
  apt-get)
    case " $* " in
      *' -s '*dist-upgrade*)
        echo "Inst libssl3t64 [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [arm64])"
        echo "Inst postgresql-17 [17.5-1] (17.6-1 Debian-Security:13/stable-security [arm64])"
        echo "Inst tzdata [2025a-1] (2025b-1 Debian:13/stable [all])" ;;
      ' -s remove '*) shift 2; for p in "$@"; do echo "Remv $p [1.0-1]"; done ;;
      *' remove '*) rm -f "$S/installed-18" ;;
      *' install '*--only-upgrade*postgresql-17*) echo 17.6-1 >"$S/version-17" ;;
      *' install '*postgresql-18*)
        touch "$S/installed-18"
        mkdir -p /usr/lib/postgresql/18/bin && touch /usr/lib/postgresql/18/bin/pg_upgrade && chmod 755 /usr/lib/postgresql/18/bin/pg_upgrade
        echo "18 main 5433 online postgres /var/lib/postgresql/18/main /var/log/postgresql/postgresql-18-main.log" >>"$S/clusters" ;;
    esac ;;
  pg_dropcluster)
    [ "$1" = --stop ] && shift
    grep -v "^$1 $2 " "$S/clusters" >"$S/c.tmp"
    cat "$S/c.tmp" >"$S/clusters" ;;
  pg_upgradecluster)
    [ ! -e "$S/upgrade.fail" ] || { echo "pg_upgrade failed: Your installation contains ..."; exit 1; }
    printf '17 main 5433 down postgres /var/lib/postgresql/17/main log\n18 main 5432 down postgres /var/lib/postgresql/18/main log\n' >"$S/clusters" ;;
  pg_conftool)
    [ "$(id -un)" = postgres ] || { echo "pg_conftool must run as the cluster owner" >&2; exit 1; }
    sed "s/^$1 $2 [0-9]* /$1 $2 $5 /" "$S/clusters" >"$S/c.tmp"
    cat "$S/c.tmp" >"$S/clusters" ;;
  du) printf '1048576\t%s\n' "$2" ;;
esac
exit 0
FAKE_EOF
  chmod 755 "$B/fake"
  for c in pg_lsclusters dpkg-query apt-cache apt-get pg_dropcluster pg_upgradecluster pg_conftool du; do ln -s fake "$B/$c"; done
  cat >"$F/systemctl" <<'FAKE_EOF'
#!/bin/sh
S=/tmp/rowsafe-fake/cluster
echo "$*" >>/tmp/rowsafe-fake/systemctl.calls
case $1 in
  show) echo 1000 ;;
  start | stop)
    case $2 in
      postgresql@*)
        m=${2#postgresql@}
        m=${m%%-*}
        from=down to=online
        [ "$1" = start ] || { from=online to=down; }
        [ "$1" = stop ] || [ ! -e "$S/start-$m.fail" ] || exit 1
        sed "s/^$m main \([0-9]*\) $from /$m main \1 $to /" "$S/clusters" >"$S/c.tmp"
        cat "$S/c.tmp" >"$S/clusters"
        ;;
    esac
    ;;
esac
exit 0
FAKE_EOF
  chmod 755 "$F/systemctl"
  for m in 17 18; do
    install -d -o postgres -g postgres /etc/postgresql/$m/main /var/lib/postgresql/$m/main
    echo "$m" | runuser -u postgres -- sh -c 'cat >"$1"' sh /var/lib/postgresql/$m/main/PG_VERSION
  done
  echo "17 main 5432 online postgres /var/lib/postgresql/17/main /var/log/postgresql/postgresql-17-main.log" >"$S/clusters"
  echo 17.5-1 >"$S/version-17"
  : >"$S/calls"
  : >"$S/c.tmp"
  chmod 666 "$S"/*
  rm -rf "$W/helper-state"
  uhelper() {
    timeout 30 env ROWSAFE_HELPER_MODE=update ROWSAFE_HELPER_PATH="$B:/usr/sbin:/usr/bin:/sbin:/bin" ROWSAFE_SYSTEMCTL="$F/systemctl" \
      STATE_DIRECTORY="$W/helper-state" RUNTIME_DIRECTORY="$O" "$H" 2>>"$W/helper.log" || fail "the update helper failed or hung (exit $?)"
  }
  urequest() {
    rm -f "$O/update-result"
    : >"$S/calls"
    : >"$F/systemctl.calls"
    printf '%s\n' "$1" | as_pg sh -c 'cat >"$1"' sh "$R/update-request"
    uhelper
    [ ! -e "$R/update-request" ] || fail "helper left the update request: $1"
    [ -f "$O/update-result" ] || fail "no update result for: $1"
  }
  u_has() { grep -qxF -- "$1" "$O/update-result" || {
    cat "$O/update-result" >&2
    fail "update result lacks $1"
  }; }
  u_called() { grep -qF -- "$1" "$S/calls" || {
    cat "$S/calls" >&2
    fail "the helper didn't run: $1"
  }; }

  uhelper # no request: nothing happens
  [ ! -e "$O/update-result" ] || fail "update helper answered without a request"
  for bad in "u1 pg-minor-update" "u1 pg-minor-update 5432 extra" "u1 apt-get install evil" "u1 pg-upgrade 5432 18 dump" \
    "u1 pg-install-major 5432 9" "u1 pg-install-major 5432 18;reboot" "u1 reboot now" "u1 pg-upgrade-undo 5432" "u.1 reboot" \
    "u1 security-updates 5432" "u1 pg-upgrade 5432 18 copy --force"; do
    urequest "$bad"
    u_has "ok=0"
    u_has "error=malformed request"
    [ ! -s "$S/calls" ] && [ ! -s "$F/systemctl.calls" ] || fail "the helper ran something for a malformed request: $bad"
  done
  # A restart request isn't read in update mode.
  printf 'r1 restart 5432\n' | as_pg sh -c 'cat >"$1"' sh "$R/request"
  rm -f "$O/update-result"
  uhelper
  [ -e "$R/request" ] && [ ! -e "$O/update-result" ] || fail "update mode read the restart request"
  as_pg rm -f "$R/request"

  # A minor update: only that major's packages, then a restart.
  urequest "u2 pg-minor-update 5432"
  u_has "ok=1"
  u_has "package=17.6-1"
  u_has "from_package=17.5-1"
  u_has "restarted=1"
  u_called "--only-upgrade postgresql-17 postgresql-client-17 libpq5 postgresql-17-cron"
  grep -qx "restart postgresql@17-main.service" "$F/systemctl.calls" || fail "minor update: no restart: $(cat "$F/systemctl.calls")"
  ! grep -q 'postgresql-18' "$S/calls" || fail "a minor update touched another major"
  urequest "u3 pg-minor-update 5499"
  u_has "ok=0"
  grep -q "^error=port 5499 is not in /etc/rowsafe/restart-allowed" "$O/update-result" || fail "unlisted port not refused"
  sed -i '/^postgresql /d' "$U"
  urequest "u4 pg-minor-update 5432"
  u_has "error=installing PostgreSQL updates from Rowsafe is not allowed on this server (run the installer again with --allow-updates)"
  [ ! -s "$S/calls" ] || fail "the helper ran something that isn't allowed"
  echo "postgresql" >>"$U"
  chmod 666 "$U"
  urequest "u5 pg-minor-update 5432"
  u_has "error=$U is writable by others than root"
  chmod 644 "$U"

  # A new major: its packages and the extension's; the package's own
  # cluster dropped.
  urequest "u6 pg-install-major 5432 18"
  u_has "ok=1"
  u_has "packages=postgresql-18 postgresql-client-18 postgresql-18-cron"
  u_has "dropped= 18/main"
  u_called "pg_dropcluster 18 main"
  grep -qx "stop postgresql@18-main.service" "$F/systemctl.calls" || fail "the package's cluster wasn't stopped by root first"
  urequest "u7 pg-install-major 5432 16"
  grep -q "^error=PostgreSQL 16 is not newer" "$O/update-result" || fail "older major not refused"

  # The upgrade: pg_upgradecluster, the allow list moved to the new unit,
  # the new version started, a record kept for undo.
  urequest "u8 pg-upgrade 5432 18 copy"
  u_has "ok=1"
  u_has "aside_port=5433"
  u_has "unit=postgresql@18-main.service"
  u_called "pg_upgradecluster -v 18 -m upgrade -j"
  u_called "--no-start 17 main"
  grep -qx "5432 postgresql@18-main.service" /etc/rowsafe/restart-allowed || fail "allow list not moved to 18"
  [ "$(stat -c '%U %a' /etc/rowsafe/restart-allowed)" = "root 644" ] || fail "allow list ownership/mode after the upgrade"
  grep -qx "start postgresql@18-main.service" "$F/systemctl.calls" || fail "18 not started"
  grep -qx "status=upgraded" "$W/helper-state/upgrade-5432" || fail "no upgrade record"
  urequest "u9 pg-upgrade 5432 19 link"
  grep -q "^ok=0" "$O/update-result" || fail "a second upgrade wasn't refused"
  urequest "u10 pg-upgrade-undo 5432 start"
  u_has "ok=1"
  u_has "unit=postgresql@17-main.service"
  u_called "pg_conftool 18 main set port 5433"
  u_called "pg_conftool 17 main set port 5432"
  [ "$(cat /etc/postgresql/18/main/start.conf)" = manual ] && [ "$(cat /etc/postgresql/17/main/start.conf)" = auto ] || fail "start.conf not switched"
  [ "$(stat -c %U /etc/postgresql/17/main/start.conf)" = postgres ] || fail "root wrote the cluster's start.conf"
  grep -qx "5432 postgresql@17-main.service" /etc/rowsafe/restart-allowed || fail "allow list not moved back to 17"
  grep -q '^17 main 5432 online' "$S/clusters" || fail "17 not running on 5432: $(cat "$S/clusters")"
  urequest "u11 pg-upgrade-undo 5432 start"
  u_has "error=that upgrade was already undone"
  grep -qx "old_data=/var/lib/postgresql/17/main" "$W/helper-state/upgrade-5432" &&
    grep -qx "new_data=/var/lib/postgresql/18/main" "$W/helper-state/upgrade-5432" || fail "data directories not recorded"
  # The agent user owns /etc/postgresql: it can repoint where PostgreSQL 18's
  # data lives, or make its configuration directory a link. Root must not
  # remove anything but the recorded data directory.
  cp "$S/clusters" "$S/clusters.good"
  install -d -o postgres -g postgres /var/lib/postgresql/decoy
  echo 18 >/var/lib/postgresql/decoy/PG_VERSION
  chown postgres /var/lib/postgresql/decoy/PG_VERSION
  for dir in /etc /var/lib/postgresql/decoy /home; do
    sed "s|^18 main 5433 down postgres [^ ]*|18 main 5433 down postgres $dir|" "$S/clusters.good" >"$S/clusters"
    urequest "u12a pg-upgrade-cleanup 5432"
    u_has "ok=0"
    grep -q "^error=Rowsafe didn't remove PostgreSQL 18/main: PostgreSQL 18/main's data directory is now $dir, not /var/lib/postgresql/18/main as recorded" "$O/update-result" ||
      fail "a repointed data directory ($dir) wasn't refused: $(cat "$O/update-result")"
    ! grep -q pg_dropcluster "$S/calls" || fail "pg_dropcluster ran for a repointed data directory ($dir)"
  done
  cp "$S/clusters.good" "$S/clusters"
  # The recorded path, but now a link to somewhere else.
  mv /var/lib/postgresql/18/main /var/lib/postgresql/18/main.real
  ln -s /var/lib/postgresql/decoy /var/lib/postgresql/18/main
  urequest "u12b pg-upgrade-cleanup 5432"
  grep -q "^error=.*the data directory /var/lib/postgresql/18/main is missing or its path goes through a symbolic link" "$O/update-result" ||
    fail "a linked data directory wasn't refused: $(cat "$O/update-result")"
  rm /var/lib/postgresql/18/main
  mv /var/lib/postgresql/18/main.real /var/lib/postgresql/18/main
  # A linked configuration directory, and a log link pointing at a system file.
  mv /etc/postgresql/18/main /etc/postgresql/18/main.real
  ln -s /etc/postgresql/18/main.real /etc/postgresql/18/main
  urequest "u12c pg-upgrade-cleanup 5432"
  grep -q "^error=.*the configuration directory /etc/postgresql/18/main is missing or its path goes through a symbolic link" "$O/update-result" ||
    fail "a linked configuration directory wasn't refused: $(cat "$O/update-result")"
  rm /etc/postgresql/18/main
  mv /etc/postgresql/18/main.real /etc/postgresql/18/main
  runuser -u postgres -- ln -s /etc/shadow /etc/postgresql/18/main/log
  urequest "u12d pg-upgrade-cleanup 5432"
  grep -q "^error=.*/etc/postgresql/18/main/log points outside /var/log/postgresql" "$O/update-result" ||
    fail "a log link to /etc/shadow wasn't refused: $(cat "$O/update-result")"
  rm /etc/postgresql/18/main/log
  [ -s /etc/shadow ] && [ -f /var/lib/postgresql/decoy/PG_VERSION ] || fail "something outside the cluster was removed"
  ! grep -q pg_dropcluster "$S/calls" || fail "pg_dropcluster ran despite a refusal"
  pass "cluster removal refuses repointed or linked data and configuration directories"
  urequest "u12 pg-upgrade-cleanup 5432"
  u_has "ok=1"
  u_has "dropped=18/main"
  u_called "pg_dropcluster 18 main"
  grep -q "^packages_removed=postgresql-18 postgresql-18-cron" "$O/update-result" || fail "18's packages not removed: $(cat "$O/update-result")"
  [ ! -e "$W/helper-state/upgrade-5432" ] || fail "upgrade record kept after cleanup"

  # A failed upgrade: pg_upgradecluster starts the old version again.
  urequest "u13 pg-install-major 5432 18"
  u_has "ok=1"
  touch "$S/upgrade.fail"
  urequest "u14 pg-upgrade 5432 18 copy"
  u_has "ok=0"
  u_has "rolled_back=1"
  grep -q "^error=pg_upgrade failed, and PostgreSQL 17 runs as before" "$O/update-result" || fail "failed upgrade not explained"
  grep -qx "5432 postgresql@17-main.service" /etc/rowsafe/restart-allowed || fail "a failed upgrade moved the allow list"
  rm -f "$S/upgrade.fail"
  # The new version doesn't start (Safe mode): the old one is put back.
  touch "$S/start-18.fail"
  urequest "u15 pg-upgrade 5432 18 copy"
  u_has "ok=0"
  u_has "rolled_back=1"
  grep -q "Rowsafe put PostgreSQL 17 back and started it" "$O/update-result" || fail "failed start not rolled back: $(cat "$O/update-result")"
  grep -qx "5432 postgresql@17-main.service" /etc/rowsafe/restart-allowed || fail "allow list not put back"
  grep -q '^17 main 5432 online' "$S/clusters" || fail "17 not back on 5432: $(cat "$S/clusters")"
  [ ! -e "$W/helper-state/upgrade-5432" ] || fail "record kept after a rollback"
  rm -f "$S/start-18.fail"

  # Security updates: from security origins only, PostgreSQL held back.
  urequest "u16 security-updates"
  u_has "ok=1"
  u_has "installed=1"
  u_has "packages=libssl3t64 "
  u_has "held_back=postgresql-17 "
  u_called "--only-upgrade libssl3t64"
  ! grep -q 'install.*tzdata' "$S/calls" || fail "a non-security update was installed"
  # Reboot: answered first, then asked of systemd.
  urequest "u17 reboot"
  u_has "ok=1"
  u_has "status=rebooting"
  grep -qx -- "--no-block reboot" "$F/systemctl.calls" || fail "no reboot asked: $(cat "$F/systemctl.calls")"
  sed -i '/^reboot /d' "$U"
  urequest "u18 reboot"
  u_has "error=rebooting the server from Rowsafe is not allowed here (run the installer again with --allow-reboot)"
  [ ! -s "$F/systemctl.calls" ] || fail "rebooted without permission"
  root_free "after update requests"
  pass "update helper: request shapes, allow lists, minor update, new major, upgrade, undo, cleanup, rollback, security updates, reboot"

  scenario "discover_out=$shop"
  expect_ok "--no-allow-updates --no-allow-security-updates --no-allow-reboot" "$INSTALLER" --no-allow-updates --no-allow-security-updates --no-allow-reboot
  [ ! -e /etc/systemd/system/rowsafe-pg-update.path ] && ! grep -q '^[a-z]' "$U" || fail "updates still allowed"
  [ -e "$H" ] || fail "turning updates off removed the restart helper"
  scenario "discover_out=$shop"
  expect_ok "--allow-updates again" "$INSTALLER" --allow-updates
  pass "--no-allow-updates and friends turn updates off and keep restarts"
}

# ------------------------------------------------------------ firewall

# firewall_tests: --allow-firewall, and the firewall helper with the real
# nft (the container has its own network namespace and CAP_NET_ADMIN).
firewall_tests() {
  echo "  -- the firewall on request (--allow-firewall)"
  apt-get install -y -qq --no-install-recommends nftables >/dev/null
  H=/usr/local/lib/rowsafe/rowsafe-firewall
  D=/var/lib/rowsafe/firewall
  # The ports come from root's own look (pg_lsclusters here), never from the
  # agent's discover output: port 22 in either is never allowed.
  cat >/usr/local/bin/pg_lsclusters <<'PGEOF'
#!/bin/sh
printf '17 main 5432 online postgres /var/lib/postgresql/17/main /var/log/postgresql/postgresql-17-main.log\n'
printf '17 odd 22 online postgres /var/lib/postgresql/17/odd /var/log/postgresql/postgresql-17-odd.log\n'
PGEOF
  chmod 755 /usr/local/bin/pg_lsclusters
  # The restart tests purged everything: install again, with a running agent.
  scenario
  expect_ok "install again for the firewall tests" configured "$INSTALLER" rse_secrettoken123
  echo '{"host_id":"host_1","agent_token":"rsa_x"}' >/var/lib/rowsafe/agent.json
  chown postgres:postgres /var/lib/rowsafe/agent.json
  runuser -u postgres -- /opt/rowsafe/rowsafe-agent run >/dev/null 2>&1 &
  sleep 1
  scenario "discover_out=$shop\n22\t/var/run/postgresql\t17\todd\t/var/lib/postgresql/17/odd\t8192\todd\tno\t-\todd\t8.0 KiB\tssh.service\t-"
  expect_ok "--allow-firewall" "$INSTALLER" --allow-firewall
  grep -q "Rowsafe may limit who can reach PostgreSQL's port (5432) when you ask" "$W/out" || {
    cat "$W/out" >&2
    fail "--allow-firewall not confirmed"
  }
  grep -qx "5432" /etc/rowsafe/firewall-allowed || fail "firewall allow list lacks 5432"
  ! grep -qx "22" /etc/rowsafe/firewall-allowed || fail "port 22 made it into the firewall allow list"
  ! grep -q "ssh.service" /etc/rowsafe/restart-allowed 2>/dev/null || fail "an agent-reported unit made it into the restart allow list"
  [ "$(stat -c '%U %a' /etc/rowsafe/firewall-allowed)" = "root 644" ] || fail "firewall allow list ownership/mode"
  [ "$(stat -c '%U %a' "$H")" = "root 755" ] || fail "firewall helper ownership/mode"
  [ "$(stat -c '%U %a' "$D")" = "postgres 700" ] || fail "firewall request directory ownership/mode"
  cmp "$H" /src/scripts/rowsafe-firewall || fail "helper differs from scripts/rowsafe-firewall"
  for u in rowsafe-firewall.service rowsafe-firewall.path rowsafe-firewall-restore.service; do
    cmp "/etc/systemd/system/$u" "/src/deploy/systemd/$u" || fail "$u differs"
  done
  ! grep -q "ReadWritePaths" /etc/systemd/system/rowsafe-firewall.service || fail "the firewall unit may write somewhere"
  if [ "${TEST_UNITS:-0}" = 1 ]; then
    expect_ok "systemd-analyze verify (firewall units)" systemd-analyze verify /etc/systemd/system/rowsafe-firewall.service \
      /etc/systemd/system/rowsafe-firewall.path /etc/systemd/system/rowsafe-firewall-restore.service
    [ ! -s "$W/out" ] || {
      cat "$W/out" >&2
      fail "systemd-analyze verify printed warnings for the firewall units"
    }
    systemd-analyze security --offline=true --no-pager /etc/systemd/system/rowsafe-firewall.service 2>/dev/null |
      tail -n 1 | sed "s/^/  rowsafe-firewall: /"
  fi
  # A re-run keeps the list as it is and asks nothing (restarts answered
  # already, so only the database questions come).
  scenario "discover_out=$shop"
  expect_ok "restarts and PgBouncer off for the firewall tests" "$INSTALLER" --no-allow-restart --no-allow-pooler
  scenario "discover_out=$shop"
  tty_ok "a re-run keeps the firewall allowed" "Name it in Rowsafe\t\nTurn on backups for shop now?\tn\n" "$INSTALLER"
  lacks "Allow Rowsafe to limit who can reach"
  grep -qx "5432" /etc/rowsafe/firewall-allowed || fail "a re-run dropped the firewall allow list"

  FO=$W/fw-run
  install -d -m 0755 -o root -g root "$FO"
  as_pg() { runuser -u postgres -- "$@"; }
  # ss and sshd stand in: PostgreSQL (postgres) listens on 5432 and 5433,
  # root on 5499, sshd on 22 and 2222.
  pg_uid=$(id -u postgres)
  {
    echo '#!/bin/sh'
    echo 'case "$*" in'
    echo "*p*) printf 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\\n' ;;"
    echo "*) printf 'LISTEN 0 244 0.0.0.0:5432 0.0.0.0:* uid:$pg_uid ino:1 sk:1\\nLISTEN 0 244 0.0.0.0:5433 0.0.0.0:* uid:$pg_uid ino:2 sk:2\\nLISTEN 0 128 0.0.0.0:5499 0.0.0.0:* uid:0 ino:3 sk:3\\n' ;;"
    echo 'esac'
  } >"$F/ss"
  printf '#!/bin/sh\nprintf "port 22\\nport 2222\\n"\n' >"$F/sshd"
  chmod 755 "$F/ss" "$F/sshd"
  fw() {
    timeout 90 env STATE_DIRECTORY="$W/fw-state" RUNTIME_DIRECTORY="$FO" ROWSAFE_FIREWALL_CONFIRM_WAIT="${WAIT:-3}" \
      ROWSAFE_SS="$F/ss" ROWSAFE_SSHD="$F/sshd" "$H" "$@" 2>>"$W/fw.log" ||
      fail "the firewall helper failed or hung (exit $?)"
  }
  # fw_request LINE ADDRESSES CONFIRM: as the agent does (CONFIRM=1 writes
  # the confirmation once the helper answers phase=pending). The agent
  # removes its own files afterwards: the helper never does.
  fw_request() {
    rm -f "$FO/result"
    [ -z "$2" ] || printf '%b' "$2" | as_pg sh -c 'cat >"$1"' sh "$D/addresses"
    confirmer=''
    if [ "${3:-0}" = 1 ]; then
      # At most 10 seconds (100 x 0.1s).
      (
        for _ in $(seq 1 100); do
          if grep -qx phase=pending "$FO/result" 2>/dev/null; then
            printf '%s\n' "${1%% *}" | as_pg sh -c 'cat >"$1.tmp" && mv "$1.tmp" "$1"' sh "$D/confirm"
            break
          fi
          sleep 0.1
        done
      ) &
      confirmer=$!
    fi
    printf '%s\n' "$1" | as_pg sh -c 'cat >"$1"' sh "$D/request"
    fw
    # Only the confirmer: a bare wait would also wait for the fake agent,
    # which runs until pkill.
    [ -z "$confirmer" ] || wait "$confirmer"
    [ -e "$D/request" ] || fail "helper removed the agent's request: $1"
    [ -f "$FO/result" ] || fail "no result for: $1"
    as_pg rm -f "$D/request" "$D/addresses" "$D/confirm"
  }
  fw_has() { grep -qxF "$1" "$FO/result" || {
    cat "$FO/result" >&2
    fail "firewall helper result lacks $1"
  }; }
  rules() { nft list table inet rowsafe 2>/dev/null; }

  fw # no request: nothing happens
  [ ! -e "$FO/result" ] || fail "firewall helper answered without a request"
  fw_request "fw_1 apply 5432" '10.0.0.0/16\n2001:db8::/32\n' 1
  fw_has "id=fw_1"
  fw_has "phase=done"
  fw_has "ok=1"
  rules | grep -q "tcp dport 5432 ip saddr 10.0.0.0/16 accept" || fail "no IPv4 allow rule: $(rules)"
  rules | grep -q "tcp dport 5432 ip6 saddr 2001:db8::/32 accept" || fail "no IPv6 allow rule: $(rules)"
  rules | grep -q "tcp dport 5432 drop" || fail "no drop rule: $(rules)"
  ! rules | grep -q "dport 22" || fail "the firewall helper touched SSH"
  grep -qx "addresses=10.0.0.0/16,2001:db8::/32" "$FO/port-5432" && grep -qx "loaded=1" "$FO/port-5432" || fail "port state not published"
  [ "$(stat -c '%U %a' "$FO/port-5432")" = "root 644" ] || fail "port state ownership/mode"
  [ -f "$W/fw-state/port-5432" ] && [ ! -e "$W/fw-state/pending-5432" ] || fail "a confirmed rule was not kept as port-5432"
  # A request is handled once.
  printf 'fw_1 apply 5432\n' | as_pg sh -c 'cat >"$1"' sh "$D/request"
  rm -f "$FO/result"
  fw
  [ ! -e "$FO/result" ] || fail "the same request was handled twice"
  as_pg rm -f "$D/request"

  # Without the agent's confirmation the previous rule comes back.
  WAIT=1 fw_request "fw_2 apply 5432" '192.168.7.0/24\n' 0
  fw_has "ok=0"
  grep -q "^error=the agent did not confirm" "$FO/result" || fail "unconfirmed change not explained"
  rules | grep -q "10.0.0.0/16" && ! rules | grep -q "192.168.7.0/24" || fail "unconfirmed change not rolled back: $(rules)"
  grep -qx "addresses=10.0.0.0/16,2001:db8::/32" "$FO/port-5432" || fail "rolled back state not published"
  [ ! -e "$W/fw-state/pending-5432" ] || fail "an unconfirmed rule was kept"

  n=0
  for bad in "0.0.0.0/0" "10.0.0.0/4" "::/0" "1.2.3.4;flush" "300.1.1.1" "example.com" '1.2.3.4 } accept; chain x {'; do
    n=$((n + 1))
    fw_request "fw_3_$n apply 5432" "$bad\n" 1
    fw_has "ok=0"
    grep -q "^error=not an address or range" "$FO/result" || fail "bad address $bad not refused"
  done
  fw_request "fw_4 apply 5499" '10.1.0.0/16\n' 1
  grep -q "^error=port 5499 is not in /etc/rowsafe/firewall-allowed" "$FO/result" || fail "unlisted port not refused"
  # Whatever the allow list says: never SSH, never below 1024, and only a
  # port PostgreSQL (the postgres user) listens on.
  printf '5432\n2222\n22\n5433\n5499\n' >/etc/rowsafe/firewall-allowed
  fw_request "fw_ssh apply 2222" '10.1.0.0/16\n' 1
  grep -q "^error=port 2222 is SSH's" "$FO/result" || fail "an sshd port was not refused"
  fw_request "fw_low apply 22" '10.1.0.0/16\n' 1
  grep -q "^error=port 22 can't be managed by Rowsafe" "$FO/result" || fail "a port below 1024 was not refused"
  fw_request "fw_nopg apply 5499" '10.1.0.0/16\n' 1
  grep -q "^error=no PostgreSQL of the postgres user listens on port 5499" "$FO/result" || fail "a port without PostgreSQL was not refused"
  printf '5432\n' >/etc/rowsafe/firewall-allowed
  for bad in "fw_5 flush 5432" "fw_5 apply" "fw_5 apply 5432 x" "fw.5 apply 5432" 'x; nft flush ruleset 5432' "fw_5 apply 05432" "fw_5 apply 99999999"; do
    fw_request "$bad" "" 0
    fw_has "error=malformed request"
  done
  rules | grep -q "10.0.0.0/16" || fail "refused requests changed the rules"
  # A symlinked request is neither read nor followed.
  printf 'fw_9 remove 5432\n' >"$W/fw-sentinel"
  chmod 600 "$W/fw-sentinel"
  as_pg ln -s "$W/fw-sentinel" "$D/request"
  rm -f "$FO/result"
  fw
  [ ! -e "$FO/result" ] || fail "a symlinked request was read"
  [ "$(cat "$W/fw-sentinel")" = "fw_9 remove 5432" ] || fail "a symlinked request changed its target"
  as_pg rm -f "$D/request"
  [ -z "$(find "$D" -user root)" ] || fail "root left files in $D"

  # Status: whether nftables still holds the rules.
  fw_request "fw_s1 status 5432" "" 0
  fw_has "ok=1"
  grep -qx "loaded=1" "$FO/port-5432" || fail "status: rules not reported loaded"
  nft delete table inet rowsafe
  fw_request "fw_s2 status 5432" "" 0
  grep -qx "loaded=0" "$FO/port-5432" || fail "status: a flushed table reported loaded"

  # At boot the kept rules come back; an unconfirmed one doesn't.
  printf '10.77.0.0/16\n' >"$W/fw-state/pending-5432"
  fw --restore
  rules | grep -q "10.0.0.0/16" || fail "--restore did not load the rules"
  ! rules | grep -q "10.77.0.0/16" || fail "--restore loaded an unconfirmed rule"
  [ ! -e "$W/fw-state/pending-5432" ] || fail "--restore kept an unconfirmed rule"
  fw_request "fw_6 remove 5432" "" 0
  fw_has "ok=1"
  ! rules | grep -q . || fail "remove left the table: $(rules)"
  [ ! -e "$FO/port-5432" ] || fail "remove left the port state"
  pass "firewall helper: nft rules, confirmation and rollback, pending rules, bad addresses and ports, SSH, allow list, symlinks, status, --restore, remove"

  fw_request "fw_7 apply 5432" '10.2.0.0/16\n' 1
  expect_ok "--no-allow-firewall" "$INSTALLER" --no-allow-firewall
  [ ! -e "$H" ] && [ ! -e /etc/systemd/system/rowsafe-firewall.path ] || fail "--no-allow-firewall left the helper"
  ! rules | grep -q . || fail "--no-allow-firewall left Rowsafe's rules"
  ! grep -q '^[0-9]' /etc/rowsafe/firewall-allowed || fail "--no-allow-firewall kept the allow list"
  scenario "discover_out=$shop"
  expect_ok "--allow-firewall again" "$INSTALLER" --allow-firewall
  pkill -u postgres -f 'rowsafe-agent run' || true
  expect_ok "uninstall removes the firewall helper" "$INSTALLER" --uninstall
  [ ! -e "$H" ] && [ ! -e /etc/systemd/system/rowsafe-firewall-restore.service ] || fail "uninstall left the firewall helper"
  expect_ok "purge" "$INSTALLER" --uninstall --purge
  rm -f /usr/local/bin/pg_lsclusters
  pass "--no-allow-firewall, uninstall and purge remove the firewall helper and its rules"
}

# ------------------------------------------------------------ forks: new clusters

create_cluster_tests() {
  echo "  -- creating clusters for forks (--allow-create-cluster)"
  H=/usr/local/lib/rowsafe/rowsafe-pg-restart
  C=/usr/local/lib/rowsafe/rowsafe-pg-create-cluster
  R=/var/lib/rowsafe/restart
  # pg_createcluster stood in: it writes the cluster's configuration like
  # postgresql-common does.
  cat >/usr/local/bin/pg_createcluster <<'EOF'
#!/bin/sh
echo "$*" >>/tmp/rowsafe-fake/pg_createcluster.calls
[ "$1" = --port ] || exit 2
port=$2 major=$5 name=$6
mkdir -p "/etc/postgresql/$major/$name"
printf "data_directory = '/var/lib/postgresql/%s/%s'\nport = %s\n" "$major" "$name" "$port" >"/etc/postgresql/$major/$name/postgresql.conf"
EOF
  chmod 755 /usr/local/bin/pg_createcluster
  scenario "discover_out=$shop"
  expect_ok "--allow-create-cluster" configured "$INSTALLER" rse_secrettoken123 --allow-create-cluster
  grep -q "Rowsafe may create a new PostgreSQL cluster (ports 5440-5499)" "$W/out" || fail "--allow-create-cluster not confirmed"
  grep -qx "ports 5440-5499" /etc/rowsafe/create-cluster-allowed || fail "allow file lacks the ports"
  [ "$(stat -c '%U %a' /etc/rowsafe/create-cluster-allowed)" = "root 644" ] || fail "create allow file ownership/mode"
  [ "$(stat -c '%U %a' /etc/rowsafe/created-clusters)" = "root 644" ] || fail "created-clusters ownership/mode"
  cmp "$C" /src/scripts/rowsafe-pg-create-cluster || fail "cluster creator differs from scripts/rowsafe-pg-create-cluster"
  cmp /etc/systemd/system/rowsafe-pg-create-cluster@.service /src/deploy/systemd/rowsafe-pg-create-cluster@.service || fail "create unit differs"
  cmp "$H" /src/scripts/rowsafe-pg-restart || fail "helper not installed for cluster creation"
  [ "$(stat -c '%U %a' "$R")" = "postgres 700" ] || fail "request directory ownership/mode"
  if [ "${TEST_UNITS:-0}" = 1 ]; then
    expect_ok "systemd-analyze verify (create unit)" systemd-analyze verify /etc/systemd/system/rowsafe-pg-create-cluster@.service
  fi

  # The helper, with systemctl standing in for systemd: starting the create
  # unit runs the creator as the unit would.
  O=$W/helper-run
  rm -rf "$O" "$W/helper-state"
  install -d -m 0755 -o root -g root "$O"
  install -d "$W/pgroot/17/bin"
  printf '#!/bin/sh\n' >"$W/pgroot/17/bin/postgres"
  chmod 755 "$W/pgroot/17/bin/postgres"
  cat >"$F/systemctl" <<EOF
#!/bin/sh
echo "\$*" >>/tmp/rowsafe-fake/systemctl.calls
case "\$1 \$2" in
  "start rowsafe-pg-create-cluster@"*)
    i=\${2#rowsafe-pg-create-cluster@}
    # The unit's output goes to its journal (stood in by a file).
    env ROWSAFE_PG_ROOT=$W/pgroot $C "\${i%.service}" 2>>/tmp/rowsafe-fake/journal
    exit \$? ;;
esac
exit 0
EOF
  chmod 755 "$F/systemctl"
  printf '#!/bin/sh\ncat /tmp/rowsafe-fake/journal 2>/dev/null\n' >"$F/journalctl"
  chmod 755 "$F/journalctl"
  helper() {
    timeout 30 env ROWSAFE_SYSTEMCTL="$F/systemctl" ROWSAFE_JOURNALCTL="$F/journalctl" STATE_DIRECTORY="$W/helper-state" \
      RUNTIME_DIRECTORY="$O" "$H" 2>>"$W/helper.log" || fail "the helper failed or hung (exit $?)"
  }
  as_pg() { runuser -u postgres -- "$@"; }
  request() {
    rm -f "$O/result" "$F/journal"
    printf '%s\n' "$1" | as_pg sh -c 'cat >"$1"' sh "$R/request"
    helper
    [ -f "$O/result" ] || fail "no result for: $1"
  }
  result_has() { grep -qxF "$1" "$O/result" || {
    cat "$O/result" >&2
    fail "helper result lacks $1"
  }; }
  grep -q '^# actions: restart stop start create-cluster$' "$H" || fail "the helper doesn't say it creates clusters"

  request "fork_1-create create-cluster 5440 17 shop_staging"
  result_has "action=create-cluster"
  result_has "ok=1"
  result_has "unit=postgresql@17-shop_staging.service"
  grep -q -- "--port 5440 --start-conf auto 17 shop_staging" "$F/pg_createcluster.calls" || fail "pg_createcluster not asked"
  grep -qx "5440 postgresql@17-shop_staging.service" /etc/rowsafe/created-clusters || fail "the new cluster isn't listed"
  # The helper may now stop and start it, like a cluster in restart-allowed.
  request "fork_1-stop stop 5440"
  result_has "ok=1"
  result_has "unit=postgresql@17-shop_staging.service"
  request "fork_1-start start 5440"
  result_has "ok=1"
  # Refused: outside the range, taken, not installed, bad requests.
  request "fork_2 create-cluster 5439 17 other"
  result_has "ok=0"
  result_has "error=port 5439 is not in the ports Rowsafe may create clusters on (5440-5499)"
  request "fork_3 create-cluster 5441 17 shop_staging"
  result_has "error=a PostgreSQL 17 cluster named shop_staging already exists"
  request "fork_4 create-cluster 5440 17 other"
  result_has "error=port 5440 is already used by a cluster Rowsafe manages"
  request "fork_5 create-cluster 5442 16 other"
  result_has "error=PostgreSQL 16 is not installed on this server"
  for bad in "fork_6 create-cluster 5443 17 Bad" "fork_6 create-cluster 5443 17 a-b" "fork_6 create-cluster 5443 17 x;reboot" \
    "fork_6 create-cluster 5443 17" "fork_6 create-cluster 543 17 x" "fork_6 create-cluster 5443 7 x" "fork_6 create-cluster 5443 17 ../x"; do
    request "$bad"
    result_has "ok=0"
    result_has "error=malformed request"
  done
  [ "$(grep -c . "$F/pg_createcluster.calls")" = 1 ] || fail "pg_createcluster ran for a refused request: $(cat "$F/pg_createcluster.calls")"
  # The creator checks on its own too (root could start the unit by hand).
  if env ROWSAFE_PG_ROOT="$W/pgroot" "$C" "17-6000-x" 2>"$W/creator.err"; then
    fail "the creator made a cluster outside the allowed ports"
  fi
  grep -q "port 6000 is not in the ports" "$W/creator.err" || fail "the creator didn't explain the refused port"
  # The creator writes nothing of Rowsafe's: only the helper lists clusters.
  grep -qx "ReadWritePaths=/etc/postgresql /var/lib/postgresql -/var/log/postgresql" /etc/systemd/system/rowsafe-pg-create-cluster@.service ||
    fail "the create unit may write outside PostgreSQL's directories"
  # A cluster whose configuration doesn't name the requested port isn't listed.
  cat >/usr/local/bin/pg_createcluster <<'EOF'
#!/bin/sh
mkdir -p "/etc/postgresql/$5/$6"
printf "port = 5999\n" >"/etc/postgresql/$5/$6/postgresql.conf"
EOF
  request "fork_9 create-cluster 5447 17 sneaky"
  result_has "ok=0"
  grep -q "^error=the new cluster's configuration .* doesn't name port 5447" "$O/result" || fail "a cluster on another port was accepted"
  ! grep -q "^5447 \|sneaky" /etc/rowsafe/created-clusters || fail "a cluster on another port was listed"
  rm -rf /etc/postgresql/17/sneaky
  chmod 666 /etc/rowsafe/create-cluster-allowed
  request "fork_7 create-cluster 5445 17 other"
  result_has "error=/etc/rowsafe/create-cluster-allowed is writable by others than root"
  chmod 644 /etc/rowsafe/create-cluster-allowed
  pass "creating clusters for forks: allow file, the creator's checks, bad requests, stop/start of created clusters"

  expect_ok "--no-allow-create-cluster" "$INSTALLER" --no-allow-create-cluster
  [ ! -e "$C" ] && [ ! -e /etc/systemd/system/rowsafe-pg-create-cluster@.service ] || fail "--no-allow-create-cluster left the creator"
  ! grep -q '^ports' /etc/rowsafe/create-cluster-allowed || fail "--no-allow-create-cluster kept the ports"
  grep -qx "5440 postgresql@17-shop_staging.service" /etc/rowsafe/created-clusters || fail "created clusters were forgotten"
  request "fork_8 create-cluster 5446 17 other"
  result_has "error=creating PostgreSQL clusters from Rowsafe is not allowed on this server"
  request "fork_8-stop stop 5440"
  result_has "ok=1"
  pkill -u postgres -f 'rowsafe-agent run' || true
  expect_ok "uninstall" "$INSTALLER" --uninstall --purge
  [ ! -e "$H" ] && [ ! -e "$C" ] || fail "uninstall left the helpers"
  rm -rf /usr/local/bin/pg_createcluster /etc/postgresql/17/shop_staging "$W/pgroot"
  pass "--no-allow-create-cluster keeps created clusters manageable; uninstall removes everything"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
