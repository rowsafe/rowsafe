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
#      review of both systemd units.
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
    if [ "\$(id -un)" != postgres ] || [ -z "\${ROWSAFE_REPO_CIPHER_PASS:-}" ]; then
      echo '{"version":"$1","ok":false,"errors":["config: not run as postgres with agent.env"]}'
      exit 1
    fi
    echo '{"version":"$1","platform":"linux/x","ok":true,"checks":["config","repository settings","pgbackrest","control plane"]}' ;;
  inspect)
    printf '{\n  "server_version": "17.6 (Debian 17.6-1)",\n  "data_directory": "/var/lib/postgresql/17/main",\n  "archive_mode": "off"\n}\n' ;;
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
  [ "$(stat -c '%U %a' /opt/rowsafe/bin/rowsafe-agent-guard)" = "root 755" ] || fail "guard ownership/mode"
  for d in /etc/rowsafe/pgbackrest /var/lib/rowsafe /var/log/rowsafe; do
    [ "$(stat -c '%U %a' "$d")" = "postgres 700" ] || fail "$d ownership/mode"
  done
  [ "$(stat -c '%U %G %a' /etc/rowsafe)" = "root postgres 750" ] || fail "/etc/rowsafe ownership/mode"
  cmp /opt/rowsafe/bin/rowsafe-agent-guard /src/scripts/rowsafe-agent-guard || fail "guard differs from scripts/rowsafe-agent-guard"
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
  grep -q "rowsafe adopt <name> --host" "$W/out" || fail "no next step"
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
  mkdir -p /var/lib/rowsafe/update/pending
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
  [ ! -e /opt/rowsafe ] && [ -f /etc/rowsafe/agent.env ] && [ ! -e /etc/systemd/system/rowsafe-agent.service ] && [ -f /etc/logrotate.d/rowsafe ] || fail "uninstall result"
  grep -q "keeps running" "$W/out" || fail "no note that archiving keeps running"
  rm /var/lib/postgresql/17/main/postgresql.auto.conf
  expect_ok "purge" "$INSTALLER" --uninstall --purge
  [ ! -e /etc/rowsafe ] && [ ! -e /var/lib/rowsafe ] && [ ! -e /var/log/rowsafe ] && [ ! -e /etc/logrotate.d/rowsafe ] || fail "purge result"
  expect_fail "--purge needs --uninstall" "only goes with --uninstall" "$INSTALLER" --purge
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
