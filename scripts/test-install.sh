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
#  10. permissions (sudo rowsafe-allow, --permissions): the installer copy
#      checked against the signed manifest (from the file, downloaded when
#      piped, a tampered one refused), root's copy of the agent, the
#      permissions-only mode (nothing else changes, needs refused or turned
#      off with what needs them, exit codes, the summary) and rowsafe-allow
#      (list, on, off, refusals, passkey commands only on root's agent copy).
#   9. files (--files, --allow-files): restic installed from a pinned,
#      SHA-256-verified release (a tampered one refused), read access
#      granted with ACLs, the "Back it up with ...?" question, the files
#      helper in its own unit: files-read and files-put only for the exact
#      folders and owners root listed (no default roots, no home, system or
#      .ssh paths, nothing the agent can write), size cap, cooldowns,
#      symlinks, .. paths, written as the folder's owner, never as root, and
#      --no-allow-files / uninstall removing it.
#
# When Go is available the release key and the 0.2.0 release are made by the
# real `rowsafe-release keygen/manifest/sign`, so the installer is tested
# against exactly what `make release` publishes.
#
#  11. Redis and Valkey: the setup flow with a stand-in agent (Rowsafe's ACL
#      user as the default user, kept by the server or added to its
#      configuration file by root, an administrator's login once, Redis
#      Cluster and old servers refused, --protect), restarts of their units
#      through the helper, and a Redis- or Valkey-only server with the
#      system's own package (Debian 12 and Ubuntu 24.04: Redis 7.0, Debian
#      13: Valkey 8.1, Ubuntu 22.04: Redis 6.0, refused before anything
#      changes).
#  12. servers Rowsafe creates (--cloud, a separate run): one non-interactive
#      run as cloud-init does it (--no-prompt --install-postgres 17
#      --listen-public --storage rowsafe --protect shop) installs real
#      PostgreSQL from apt.postgresql.org (signing key checked), makes it
#      reachable with TLS and SCRAM only, generates the passphrase, protects it
#      (the new PostgreSQL restarted once); a re-run changes nothing; a server
#      with PostgreSQL already is refused. Then the same with --install-mysql
#      8.4 (Debian 12, amd64), --install-mariadb 11.8 (Debian 13) and 11.4
#      (Debian 12), --install-valkey 8 (Debian 12 and 13) and
#      --install-clickhouse 26.8 (Debian 12; Debian 13 amd64) and 26.3
#      (Debian 13), --install-opensearch 3 (Debian 12 and 13; the real
#      agent's OpenSearch helpers when Go builds it, the package downloaded
#      once on this machine and verified by apt), each in a
#      container with systemd, with --firewall-ssh: the package from its own
#      source (key checked, pinned), secure defaults (root through the
#      socket; Valkey's default user off and its admin's password root's;
#      ClickHouse's default user locked, its admin's password root's, the
#      plain ports on 127.0.0.1 only, a renewed certificate loaded without a
#      restart),
#      TLS from the network with the certificate at the exact paths, the
#      ports closed by the firewall before the server listens publicly,
#      Rowsafe's own login made unattended, the new server restarted once; a
#      re-run (after what the agent does later: ACL SAVE, CONFIG REWRITE)
#      changes nothing; other servers refused. Needs the network.
#      And OpenSearch on a customer's own server (opensearch-own, Debian 12):
#      installed from its repository with its demo configuration and
#      running; the installer, without a terminal, adds Rowsafe's snapshot
#      folder and role to opensearch.yml (a copy kept), makes Rowsafe's user
#      with an administrator's login and doesn't restart it; after a restart
#      the real agent finds everything in place.
#      --install-meilisearch 1.54 (Debian 12 and 13, arm64 and amd64): the
#      Community Edition binary checked against the pinned SHA-256 (a
#      tampered one refused), its sandboxed unit, the master key root's only
#      and handed to the agent on stdin once, production mode, analytics off,
#      Meilisearch itself on 127.0.0.1:7701, Rowsafe's TLS front (the real
#      agent program) on 7700: HTTPS only, plain HTTP refused, TLS 1.1
#      refused, a renewed certificate served without a restart.
#      The regular run checks the --install-X refusals that need nothing.
#
# Usage: scripts/test-install.sh [IMAGE...]
#        scripts/test-install.sh --cloud [IMAGE...]   (section 12 only)
# Default images: debian:trixie debian:bookworm ubuntu:24.04 ubuntu:22.04
# TEST_ONLY=meilisearch only a Meilisearch running here, protected (the
# master key found in its configuration, Rowsafe's key made on stdin, the
# snapshots readable by the agent through an ACL; the real Meilisearch).
# TEST_ONLY=redis runs only the Redis and Valkey cases (11); TEST_ONLY=sqlite
# only the SQLite ones.
# (--cloud: debian:bookworm for PostgreSQL; TEST_ONLY=postgres,mysql,mariadb,valkey,clickhouse,opensearch,qdrant,meilisearch
# picks engines, CLOUD_RUNS the ENGINE:VERSION:IMAGE:PLATFORM runs, TEST_KEEP=1
# keeps a failed run's container)

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
    # (as mysql on a MySQL server, rowsafe on a ClickHouse one)
    if { [ "\$(id -un)" != postgres ] && [ "\$(id -un)" != mysql ] && [ "\$(id -un)" != rowsafe ]; } || [ -z "\${ROWSAFE_REPO_CIPHER_PASS:-}" ]; then
      echo '{"version":"$1","ok":false,"errors":["config: not run as postgres with agent.env"]}'
      exit 1
    fi
    echo '{"version":"$1","platform":"linux/x","ok":true,"checks":["config","repository settings","pgbackrest","control plane"]}' ;;
  inspect)
    printf '{\n  "server_version": "17.6 (Debian 17.6-1)",\n  "data_directory": "/var/lib/postgresql/17/main",\n  "archive_mode": "off"\n}\n' ;;
  run)
    # Started by its unit (systemd containers, --cloud): enrolled at once.
    if [ -n "\${ROWSAFE_ENROLL_TOKEN:-}" ] && [ ! -e /var/lib/rowsafe/agent.json ]; then
      echo '{"host_id":"host_1","agent_token":"rsa_x"}' >/var/lib/rowsafe/agent.json 2>/dev/null || true
    fi
    i=0; while [ \$i -lt 1800 ]; do sleep 1; i=\$((i + 1)); done ;; # at most 30 minutes, even if nothing kills it
  storage)
    # Rowsafe Storage test: must run as postgres (the agent's user:
    # /tmp/rowsafe-fake-user) with agent.env loaded.
    f=/tmp/rowsafe-fake
    echo "storage \$*" >>"\$f/calls" 2>/dev/null || true
    if [ "\$(id -un)" != "\$(cat /tmp/rowsafe-fake-user 2>/dev/null || echo postgres)" ] || [ "\${ROWSAFE_STORAGE:-}" != rowsafe ]; then
      echo "storage test must run as postgres with ROWSAFE_STORAGE=rowsafe from agent.env" >&2
      exit 1
    fi
    if [ -s "\$f/storage.rc" ] && [ "\$(cat "\$f/storage.rc")" != 0 ]; then
      echo "error: no Rowsafe Storage credentials: control plane returned 503: storage unavailable" >&2
      exit 1
    fi
    echo "writing, reading and deleting a test file in Rowsafe Storage..."
    echo "Rowsafe Storage works: wrote, read back and deleted a test file" ;;
  setup|mongodb|clickhouse|redis|opensearch|qdrant|meilisearch)
    # Answers from /tmp/rowsafe-fake: CMD.out is printed, CMD.rc holds exit
    # codes (one per line, used in turn; the last one sticks). MongoDB,
    # ClickHouse, Redis, OpenSearch, Qdrant and Meilisearch helpers are
    # mongodb-CMD, clickhouse-CMD, redis-CMD, opensearch-CMD, qdrant-CMD and
    # meilisearch-CMD; a password (a Qdrant key, a Meilisearch master key) on
    # stdin goes to CMD.stdin. (--cloud) Meilisearch's TLS front is the real
    # agent's.
    if [ "\$1" = meilisearch ] && [ "\${2:-}" = tls-front ]; then
      shift
      exec "/go-release/real/rowsafe-agent-linux-\$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')" meilisearch "\$@"
    fi
    f=/tmp/rowsafe-fake
    pre=''
    case \$1 in mongodb | clickhouse | redis | opensearch | qdrant | meilisearch) pre=\$1- ;; esac
    shift
    echo "\$pre\$*" >>"\$f/calls"
    case " \$* " in *" --admin-user "*) cat >"\$f/\$pre\$1.stdin" ;; esac
    case \$pre\$1 in qdrant-login | qdrant-save-login | meilisearch-login) cat >"\$f/\$pre\$1.stdin" ;; esac
    set -- "\$pre\$@"
    if [ "\$1" = mysql-account ] && [ -f /tmp/rowsafe-fake-user ]; then
      # (--cloud) root creates Rowsafe's account through the server's
      # socket, as the real agent does: root must get in without a password.
      [ "\$(id -u)" = 0 ] || { echo "setup mysql-account must run as root" >&2; exit 1; }
      cli=mysql
      ! command -v mariadb >/dev/null 2>&1 || cli=mariadb
      who=\$(cd / && "\$cli" --protocol=socket -u root -N -B -e 'SELECT CURRENT_USER()' </dev/null 2>&1)
      [ "\$who" = root@localhost ] || { echo "root can't sign in through the socket: \$who" >&2; exit 1; }
      echo "Rowsafe's account is ready (root signed in through the socket)"
      exit 0
    fi
    if [ "\$(id -un)" != "\$(cat /tmp/rowsafe-fake-user 2>/dev/null || echo postgres)" ] || [ -z "\${ROWSAFE_REPO_CIPHER_PASS:-}" ] || [ -n "\${ROWSAFE_TEST_LEAK:-}" ]; then
      echo "setup must run as postgres with only agent.env" >&2
      exit 1
    fi
    if [ "\$pre" = opensearch- ] && [ -x /usr/local/bin/rowsafe-agent-real ]; then
      # (--cloud, OpenSearch) the real agent's OpenSearch helpers, on the real
      # server: the administrator's password (CMD.stdin) goes to it on stdin.
      cmd=\${1#opensearch-}
      shift
      case " \$* " in *" --admin-user "*) exec /usr/local/bin/rowsafe-agent-real opensearch "\$cmd" "\$@" <"\$f/opensearch-\$cmd.stdin" ;; esac
      exec /usr/local/bin/rowsafe-agent-real opensearch "\$cmd" "\$@" </dev/null
    fi
    cmd=\$1
    shift
    while [ \$# -gt 0 ]; do
      [ "\$1" != --id-file ] || echo db_fake >"\$2"
      shift
    done
    if [ "\$cmd" = clickhouse-status ] && { [ -f /etc/clickhouse-server/users.d/rowsafe.xml ] ||
      [ "\$(curl -s -H 'X-ClickHouse-User: rowsafe' -H 'X-ClickHouse-Key: agent-password-for-the-test' --data-binary 'SELECT 1' http://127.0.0.1:8123/ 2>/dev/null)" = 1 ]; }; then
      # ClickHouse loads the users.d file root installed by itself (--cloud:
      # a real ClickHouse lets Rowsafe's user in; its folder isn't the agent's to read).
      sed 's/^login=missing\$/login=ok/' "\$f/\$cmd.out"
    elif [ -f "\$f/\$cmd.out" ]; then
      cat "\$f/\$cmd.out"
    fi
    rc=0
    if [ -s "\$f/\$cmd.rc" ]; then
      rc=\$(head -n 1 "\$f/\$cmd.rc")
      [ "\$(wc -l <"\$f/\$cmd.rc")" -le 1 ] || sed -i 1d "\$f/\$cmd.rc"
    fi
    exit "\$rc" ;;
  sqlite)
    # (sqlite) root's look for SQLite files programs have open: sqlite-find.out
    f=/tmp/rowsafe-fake
    shift
    echo "sqlite \$* (\$(id -un))" >>"\$f/calls"
    chmod 666 "\$f/calls" 2>/dev/null || true
    case \${1:-} in
      find) [ ! -f "\$f/sqlite-find.out" ] || cat "\$f/sqlite-find.out" ;;
      *) exit 2 ;;
    esac ;;
  files)
    # (files) answers from /tmp/rowsafe-fake: files-discover.out, files-access.out, files-list.out
    f=/tmp/rowsafe-fake
    shift
    echo "files \$* (\$(id -un))" >>"\$f/calls"
    case \${1:-} in
      discover) [ ! -f "\$f/files-discover.out" ] || cat "\$f/files-discover.out" ;;
      access) if [ -f "\$f/files-access.out" ]; then cat "\$f/files-access.out"; else echo yes; fi ;;
      list) [ ! -f "\$f/files-list.out" ] || cat "\$f/files-list.out" ;;
      add)
        [ "\$(id -un)" = "\$(cat /tmp/rowsafe-fake-user 2>/dev/null || echo postgres)" ] && [ -n "\${ROWSAFE_REPO_CIPHER_PASS:-}" ] || exit 1
        echo "fld_1 \$5" ;;
      *) exit 2 ;;
    esac ;;
  *) exit 2 ;;
esac
EOF
}

# ------------------------------------------------------------ host side

host() {
  root=$(cd "$(dirname "$0")/.." && pwd)
  mode=--in-container
  if [ "${1:-}" = --cloud ]; then
    shift
    mode=--in-container-cloud
    images=${*:-debian:bookworm}
  else
    images=${*:-debian:trixie debian:bookworm ubuntu:24.04 ubuntu:22.04}
  fi
  docker info >/dev/null 2>&1 || {
    echo "test-install: Docker is not running" >&2
    exit 1
  }
  work=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-test-install.XXXXXX")
  trap 'rm -rf "$work"; [ -z "${cloud_name:-}" ] || docker rm -f "$cloud_name" >/dev/null 2>&1' EXIT
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
    # The rendered installer, as `make release` puts it in the manifest.
    sed "s|@RELEASE_PUBLIC_KEY@|$TEST_PUB|" "$root/scripts/install.sh" >"$d/install.sh"
    "$work/rowsafe-release" manifest --version 0.2.0 --base-url https://localhost:18443/agent --dist "$d" >"$d/manifest.json"
    ROWSAFE_RELEASE_PRIVATE_KEY=$TEST_PRIV "$work/rowsafe-release" sign "$d/manifest.json" 2>/dev/null
    "$work/rowsafe-release" verify --public-key "$TEST_PUB" "$d/manifest.json" "$d/manifest.json.sig" >/dev/null
    echo "test-install: release 0.2.0 made and signed by rowsafe-release"
  else
    echo "test-install: rowsafe-release unavailable; signing everything with openssl" >&2
  fi

  # (files) The pinned restic releases, verified against the installer's
  # SHA-256, served to the containers by their local release server.
  rv=$(sed -n 's/^RESTIC_VERSION=//p' "$root/scripts/install.sh")
  mkdir -p "$work/go/restic/v$rv"
  for arch in amd64 arm64; do
    sum=$(sed -n "s/^RESTIC_SHA256_$(echo "$arch" | tr a-z A-Z)=//p" "$root/scripts/install.sh")
    f=$work/go/restic/v$rv/restic_${rv}_linux_$arch.bz2
    if curl -fsSL --retry 3 -o "$f" "https://github.com/restic/restic/releases/download/v$rv/restic_${rv}_linux_$arch.bz2" &&
      [ "$( (sha256sum "$f" 2>/dev/null || shasum -a 256 "$f") | cut -d' ' -f1)" = "$sum" ]; then
      :
    else
      rm -f "$f"
      echo "test-install: could not fetch restic $rv for $arch; its tests are skipped" >&2
    fi
  done

  # (meilisearch: --cloud, or TEST_ONLY=meilisearch) The pinned Meilisearch
  # release, verified against the installer's SHA-256 (kept in the user's
  # cache between runs) and served by the local release server, and the
  # real agent for Rowsafe's TLS front.
  meili=0
  if [ "$mode" = --in-container-cloud ]; then
    case " $(printf '%s' "${TEST_ONLY:-meilisearch}" | tr ',' ' ') " in *" meilisearch "*) meili=1 ;; esac
  elif [ "${TEST_ONLY:-}" = meilisearch ]; then
    meili=1
  fi
  if [ "$meili" = 1 ]; then
    mv=$(sed -n 's/^MEILI_VERSION=//p' "$root/scripts/install.sh")
    cache=${XDG_CACHE_HOME:-$HOME/.cache}/rowsafe-test-install/meilisearch/v$mv
    mkdir -p "$work/go/meilisearch/v$mv" "$work/go/real" "$cache"
    for arch in amd64 arm64; do
      asset=meilisearch-linux-$arch
      [ "$arch" = amd64 ] || asset=meilisearch-linux-aarch64
      sum=$(sed -n "s/^MEILI_SHA256_$(echo "$arch" | tr a-z A-Z)=//p" "$root/scripts/install.sh")
      sha() { (sha256sum "$1" 2>/dev/null || shasum -a 256 "$1") | cut -d' ' -f1; }
      if [ ! -f "$cache/$asset" ] || [ "$(sha "$cache/$asset")" != "$sum" ]; then
        if ! curl -fsSL --retry 3 -o "$cache/$asset" "https://github.com/meilisearch/meilisearch/releases/download/v$mv/$asset" ||
          [ "$(sha "$cache/$asset")" != "$sum" ]; then
          rm -f "$cache/$asset"
          echo "test-install: could not fetch Meilisearch $mv for $arch with the pinned SHA-256" >&2
          exit 1
        fi
      fi
      ln "$cache/$asset" "$work/go/meilisearch/v$mv/$asset" 2>/dev/null || cp "$cache/$asset" "$work/go/meilisearch/v$mv/$asset"
      (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOWORK=off go build -o "$work/go/real/rowsafe-agent-linux-$arch" ./cmd/rowsafe-agent) ||
        { echo "test-install: building the agent for linux/$arch failed (Meilisearch's TLS front)" >&2; exit 1; }
    done
  fi

  if [ "$mode" = --in-container-cloud ]; then
    opensearch_host_prep # opensearch
    cloud_host
    echo "test-install: all cloud runs passed"
    return 0
  fi
  first=1
  for image in $images; do
    echo "=== $image"
    docker run --rm \
      -e TEST_PUB="$TEST_PUB" -e TEST_PRIV="$TEST_PRIV" -e TEST_UNITS="$first" -e TEST_SHOW="${TEST_SHOW:-}" -e TEST_ONLY="${TEST_ONLY:-}" \
      --cap-add NET_ADMIN --cap-add SYS_PTRACE \
      -v "$root/scripts:/src/scripts:ro" -v "$root/deploy:/src/deploy:ro" -v "$work/go:/go-release:ro" \
      "$image" sh /src/scripts/test-install.sh "$mode"
    first=0
  done
  echo "test-install: all images passed"
}

# >>> opensearch
# opensearch_host_prep (--cloud, with OpenSearch runs): the real agent
# (its OpenSearch helpers run against the real server; built from this
# tree for the containers' processor) and OpenSearch's package, downloaded
# once into $os_cache (ROWSAFE_TEST_CACHE, default $TMPDIR/rowsafe-test-cache)
# and handed to the containers' apt, which checks it against the
# repository's signed index like any download. Without them the tests
# still run (the stand-in agent's answers; apt downloads the package).
os_cache=''
opensearch_host_prep() {
  case " $(printf '%s' "${TEST_ONLY:-opensearch}" | tr ',' ' ') " in *" opensearch "*) ;; *) return 0 ;; esac
  case $(docker info --format '{{.Architecture}}') in aarch64 | arm64) darch=arm64 ;; *) darch=amd64 ;; esac
  if command -v go >/dev/null 2>&1 && (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$darch GOWORK=off go build -o "$work/go/rowsafe-agent-real-linux-$darch" ./cmd/rowsafe-agent) 2>"$work/build-agent.log"; then
    echo "test-install: the real agent built for linux/$darch (its OpenSearch helpers)"
  else
    cat "$work/build-agent.log" >&2 2>/dev/null || true
    echo "test-install: could not build the real agent; OpenSearch runs use the stand-in agent's answers" >&2
  fi
  base=https://artifacts.opensearch.org/releases/bundle/opensearch/3.x/apt
  d=${ROWSAFE_TEST_CACHE:-${TMPDIR:-/tmp}/rowsafe-test-cache}/opensearch
  mkdir -p "$d"
  # shellcheck disable=SC2046 # version, file and checksum
  set -- $(curl -fsSL --retry 3 "$base/dists/stable/main/binary-$darch/Packages" |
    awk '/^Version:/ { v = $2 } /^Filename:/ { f = $2 } /^SHA256:/ { s = $2 } /^$/ { if (v != "") print v, f, s; v = f = s = "" }
      END { if (v != "") print v, f, s }' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)
  if [ $# != 3 ]; then
    echo "test-install: could not read OpenSearch's package index; apt downloads it in each container" >&2
    return 0
  fi
  f=$d/opensearch_$1_$darch.deb
  sum() { (sha256sum "$1" 2>/dev/null || shasum -a 256 "$1") | cut -d' ' -f1; }
  if [ ! -f "$f" ] || [ "$(sum "$f")" != "$3" ]; then
    echo "test-install: downloading OpenSearch $1 for $darch once (about 800 MB) into $d"
    rm -f "$d"/opensearch_*.deb
    curl -fsSL --retry 3 -o "$f.part" "$base/$2" && mv "$f.part" "$f" || rm -f "$f.part"
  fi
  if [ -f "$f" ] && [ "$(sum "$f")" = "$3" ]; then
    os_cache=$d
  else
    rm -f "$f"
    echo "test-install: OpenSearch's package didn't download; apt downloads it in each container" >&2
  fi
}
# <<< opensearch

# cloud_host (--cloud): PostgreSQL in a plain container per image, then
# MySQL, MariaDB and Valkey each in a container with systemd as PID 1 (their
# packages start the servers with systemd; Valkey's unit sandbox matters).
# TEST_ONLY picks some of postgres, mysql, mariadb, valkey, clickhouse,
# qdrant (default: all). Each run: ENGINE:VERSION:IMAGE:PLATFORM (MySQL's packages
# are amd64 only; the others run on the host's processor unless one is named).
CLOUD_RUNS=${CLOUD_RUNS:-"mysql:8.4:debian:bookworm:linux/amd64 mariadb:11.8:debian:trixie: mariadb:11.4:debian:bookworm: valkey:8:debian:bookworm: valkey:8:debian:trixie: clickhouse:26.8:debian:bookworm: clickhouse:26.3:debian:trixie: clickhouse:26.8:debian:bookworm:linux/amd64 opensearch:3:debian:bookworm: opensearch:3:debian:trixie: opensearch-own:3:debian:bookworm: qdrant:1.19:debian:bookworm: qdrant:1.19:debian:trixie: qdrant:1.19:debian:bookworm:linux/amd64 meilisearch:1.54:debian:trixie: meilisearch:1.54:debian:bookworm:linux/amd64"}
cloud_host() {
  only=$(printf '%s' "${TEST_ONLY:-postgres mysql mariadb valkey clickhouse opensearch qdrant meilisearch}" | tr ',' ' ')
  case " $only " in
    *" postgres "*)
      for image in $images; do
        echo "=== $image: --install-postgres"
        docker run --rm -e TEST_PUB="$TEST_PUB" -e TEST_PRIV="$TEST_PRIV" -e TEST_SHOW="${TEST_SHOW:-}" \
          -e TEST_PG_VERSION -e TEST_PG_EXTENSIONS -e TEST_PG_EXTENSIONS_LATER \
          --cap-add NET_ADMIN \
          -v "$root/scripts:/src/scripts:ro" -v "$root/deploy:/src/deploy:ro" -v "$work/go:/go-release:ro" \
          "$image" sh /src/scripts/test-install.sh --in-container-cloud
      done
      ;;
  esac
  for run in $CLOUD_RUNS; do
    engine=${run%%:*} rest=${run#*:}
    version=${rest%%:*} rest=${rest#*:}
    platform=${rest##*:} image=${rest%:*}
    case " $only " in *" ${engine%-own} "*) ;; *) continue ;; esac
    echo "=== $image${platform:+ ($platform)}: --install-$engine $version"
    tag=rowsafe-test/cloud:$(printf '%s' "$image${platform:+-$platform}" | tr ':/' '--')
    docker build -q --pull ${platform:+--platform "$platform"} -t "$tag" - >/dev/null <<EOF
FROM $image
ENV container=docker
RUN apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus ca-certificates procps iproute2 >/dev/null && \\
    rm -f /lib/systemd/system/multi-user.target.wants/getty* /usr/sbin/policy-rc.d && apt-get clean && rm -rf /var/lib/apt/lists/* && \\
    ln -sf /dev/null /etc/systemd/system/systemd-binfmt.service && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.automount && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.mount
# (binfmt masked: a privileged container shares the host's binfmt_misc, and
# systemd-binfmt unregisters every entry when it stops, emulation included.)
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
    cloud_name=rowsafe-test-cloud-$engine-$$
    docker rm -f "$cloud_name" >/dev/null 2>&1 || true
    # OpenSearch reads its service's control group files, and only under
    # /sys/fs/cgroup/system.slice (its own rules): its container gets a
    # control group tree of its own, as a virtual machine has, with the
    # size's memory.
    cgroups='--cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw'
    case $engine in opensearch*) cgroups='--cgroupns=private --memory=4g' ;; esac
    # shellcheck disable=SC2086 # $cgroups is several options
    docker run -d --name "$cloud_name" ${platform:+--platform "$platform"} --privileged $cgroups \
      --tmpfs /run --tmpfs /run/lock ${os_cache:+-v "$os_cache:/os-cache:ro"} \
      -v "$root/scripts:/src/scripts:ro" -v "$root/deploy:/src/deploy:ro" -v "$work/go:/go-release:ro" "$tag" >/dev/null
    i=0
    until docker exec "$cloud_name" systemctl is-system-running --wait >/dev/null 2>&1 ||
      [ "$(docker exec "$cloud_name" systemctl is-system-running 2>/dev/null)" = degraded ]; do
      i=$((i + 1))
      [ "$i" -lt 240 ] || {
        docker rm -f "$cloud_name" >/dev/null 2>&1
        echo "test-install: systemd did not start in the container" >&2
        exit 1
      }
      sleep 1
    done
    rc=0
    docker exec -e TEST_PUB="$TEST_PUB" -e TEST_PRIV="$TEST_PRIV" -e TEST_SHOW="${TEST_SHOW:-}" \
      "$cloud_name" sh /src/scripts/test-install.sh --in-container-cloud-engine "$engine" "$version" || rc=$?
    if [ "$rc" != 0 ] && [ -n "${TEST_KEEP:-}" ]; then
      echo "test-install: kept the container $cloud_name (TEST_KEEP)" >&2
      cloud_name=''
    fi
    [ -z "$cloud_name" ] || docker rm -f "$cloud_name" >/dev/null 2>&1 || true
    [ "$rc" = 0 ] || exit "$rc"
  done
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

# publish VERSION [DIR-VERSION] [fail]: agent binaries, the rendered
# installer + manifest (unsigned).
publish() {
  v=$1 dir=${2:-$1}
  d=$W/srv/agent/$dir
  mkdir -p "$d"
  for a in amd64 arm64; do
    fake_agent "$v" "${3:-}" >"$d/rowsafe-agent-linux-$a"
  done
  cp "$W/install.sh" "$d/install.sh"
  write_manifest "$d" "$v" "https://localhost:18443/agent/$dir"
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
    if [ -f "$d/install.sh" ]; then
      printf ',\n    "install.sh": {\n      "url": "%s/install.sh",\n      "sha256": "%s",\n      "size": %s\n    }' \
        "$base" "$(sha256sum "$d/install.sh" | cut -d' ' -f1)" "$(wc -c <"$d/install.sh" | tr -d ' ')"
    fi
    printf '\n  }\n}\n'
  } >"$d/manifest.json"
}

sign() { # DIR [KEYFILE]
  openssl pkeyutl -sign -inkey "${2:-$W/release.key}" -rawin -in "$1/manifest.json" | base64 -w0 >"$1/manifest.json.sig"
  echo >>"$1/manifest.json.sig"
}

# release_setup: the release key, the rendered installer ($INSTALLER), a
# local HTTPS release server and the signed 0.2.0 release on the stable
# channel.
release_setup() {
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
  printf '#!/bin/sh\nexec env ROWSAFE_RELEASES_URL=https://localhost:18443/agent ROWSAFE_RESTIC_URL=https://localhost:18443/restic ROWSAFE_MEILISEARCH_URL=https://localhost:18443/meilisearch sh %s/install.sh "$@"\n' "$W" >"$INSTALLER"
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
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 18443), handler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
EOF
  python3 server.py &
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -s -o /dev/null https://localhost:18443/ && break
    sleep 0.5
  done

  # ---- releases
  mkdir -p srv/restic
  [ ! -d /go-release/restic ] || cp -r /go-release/restic/. srv/restic/ # (files) the pinned restic
  [ ! -d /go-release/meilisearch ] || { mkdir -p srv/meilisearch && cp -r /go-release/meilisearch/. srv/meilisearch/; } # (meilisearch) the pinned release
  if [ -d /go-release/0.2.0 ]; then
    cp -r /go-release/0.2.0 srv/agent/0.2.0 # signed by rowsafe-release
  else
    publish 0.2.0 && sign srv/agent/0.2.0
  fi
  mkdir -p srv/agent/stable && cp srv/agent/0.2.0/manifest.json srv/agent/0.2.0/manifest.json.sig srv/agent/stable/
}

in_container() {
  release_setup

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
  publish 0.11.0 && write_manifest srv/agent/0.11.0 0.11.0 https://localhost:18443/agent/0.11.0 "$other" && sign srv/agent/0.11.0
  publish 0.12.0 && sign srv/agent/0.12.0                   # a good upgrade
  publish 0.13.0 0.13.0 fail && sign srv/agent/0.13.0       # fails its self-test

  if [ "${TEST_ONLY:-}" = redis ]; then
    redis_only_tests
    return 0
  fi
  if [ "${TEST_ONLY:-}" = sqlite ]; then
    sqlite_only_tests
    return 0
  fi
  if [ "${TEST_ONLY:-}" = meilisearch ]; then
    meilisearch_only_tests
    return 0
  fi

  echo "  -- signature verification (download-only, as an unprivileged user)"
  useradd -m tester
  chmod 755 "$W" && chmod 644 install.sh placeholder-install.sh
  as_tester() { runuser -u tester -- env CURL_CA_BUNDLE="$CURL_CA_BUNDLE" ROWSAFE_RELEASES_URL=https://localhost:18443/agent "$@"; }
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
  expect_fail "http releases URL" "must be an https URL" env ROWSAFE_RELEASES_URL=http://localhost:18443/agent sh install.sh --download-only /tmp/dl13
  for n in 3 4 5 6 7 8 9 10 11 12 13; do
    [ ! -e /tmp/dl$n ] || fail "a refused release left files in /tmp/dl$n"
  done
  pass "refused releases wrote nothing"

  echo "  -- install, reconfigure, upgrade, uninstall"
  expect_fail "requires root" "run the installer as root" as_tester sh install.sh
  install_db_option_tests
  useradd --system --home-dir /var/lib/postgresql --create-home --shell /bin/sh postgres
  mkdir -p /usr/lib/postgresql/17/bin /var/lib/postgresql/17/main
  printf '#!/bin/sh\n' >/usr/lib/postgresql/17/bin/postgres && chmod 755 /usr/lib/postgresql/17/bin/postgres
  expect_fail "--install-mariadb on a server with PostgreSQL refused" \
    "PostgreSQL 17 in /usr/lib/postgresql/17 is already installed on this server, so --install-mariadb won't install MariaDB next to it" \
    "$INSTALLER" rse_secrettoken123 --no-prompt --install-mariadb 11.8
  [ ! -e /etc/rowsafe ] && [ -z "$(ls /etc/apt/sources.list.d/rowsafe-* 2>/dev/null)" ] || fail "$name: something was written"

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
  # permit-host: one-click permission changes run root's own copy of the agent.
  [ "$(stat -c '%U %a' /usr/local/lib/rowsafe/rowsafe-permissions)" = "root 755" ] || fail "permissions helper ownership/mode"
  cmp /usr/local/lib/rowsafe/rowsafe-permissions /opt/rowsafe/versions/0.2.0/rowsafe-agent || fail "permissions helper is not the release's agent"
  grep -qx "Environment=ROWSAFE_AGENT_USER=postgres" /etc/systemd/system/rowsafe-permissions.service || fail "permissions unit's agent user"
  grep -qx "PathExists=/var/lib/rowsafe/permissions/request" /etc/systemd/system/rowsafe-permissions.path || fail "permissions path unit"
  [ "$(stat -c '%U %a' /var/lib/rowsafe/permissions)" = "postgres 700" ] || fail "permissions request directory"
  cmp /etc/systemd/system/rowsafe-agent.service /src/deploy/systemd/rowsafe-agent.service || fail "unit differs from deploy/systemd/rowsafe-agent.service"
  cmp /etc/logrotate.d/rowsafe /src/deploy/logrotate/rowsafe || fail "logrotate config differs from deploy/logrotate/rowsafe"
  [ "$(stat -c '%U %a' /etc/logrotate.d/rowsafe)" = "root 644" ] || fail "logrotate config ownership/mode"
  grep -q "^#ROWSAFE_URL='https://api.rowsafe.sh'\$" /etc/rowsafe/agent.env || fail "default ROWSAFE_URL not left commented out"
  command -v pgbackrest >/dev/null || fail "pgbackrest not installed"
  echo x >/var/log/rowsafe/app-archive-push.log && chown postgres:postgres /var/log/rowsafe/app-archive-push.log
  logrotate --debug /etc/logrotate.d/rowsafe >"$W/lr" 2>&1 || { cat "$W/lr" >&2; fail "logrotate rejects the config"; }
  ! grep -qi "error" "$W/lr" || { cat "$W/lr" >&2; fail "logrotate reported an error"; }
  pass "layout, permissions, guard, unit and logrotate"
  # (permissions) Root's copy of the installer for sudo rowsafe-allow,
  # checked against the signed manifest; rowsafe-allow itself.
  for f in /usr/local/lib/rowsafe/install.sh /usr/local/sbin/rowsafe-allow; do
    [ "$(stat -c '%U %G %a' "$f")" = "root root 755" ] || fail "$f ownership/mode: $(stat -c '%U %G %a' "$f")"
  done
  cmp /usr/local/lib/rowsafe/install.sh "$W/install.sh" || fail "the installer copy isn't the release's installer"
  cmp /usr/local/sbin/rowsafe-allow /src/scripts/rowsafe-allow || fail "rowsafe-allow differs from scripts/rowsafe-allow"
  pass "installer copy and rowsafe-allow in place"

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
    sh -c 'ROWSAFE_RELEASES_URL=https://localhost:18443/agent ROWSAFE_RESTIC_URL=https://localhost:18443/restic sh -s rse_secrettoken123 <"$1/install.sh"' piped "$W"
  grep -q "already on disk" "$W/out" || fail "binary downloaded again"
  grep -q "unchanged" "$W/out" || fail "env file changed on a plain re-run"
  # (permissions) Piped, the script can't copy itself: it downloads the
  # release's installer and checks it against the signed manifest.
  rm /usr/local/lib/rowsafe/install.sh
  expect_ok "piped: the installer copy is downloaded and checked" \
    sh -c 'ROWSAFE_RELEASES_URL=https://localhost:18443/agent ROWSAFE_RESTIC_URL=https://localhost:18443/restic sh -s rse_secrettoken123 <"$1/install.sh"' piped "$W"
  cmp /usr/local/lib/rowsafe/install.sh "$W/install.sh" || fail "the downloaded installer copy differs"
  grep -q "kept at /usr/local/lib/rowsafe/install.sh" "$W/out" || fail "no word about the installer copy"
  # A release whose installer doesn't match its signed manifest: no copy.
  cp srv/agent/0.2.0/install.sh "$W/install.sh.good"
  echo '# tampered' >>srv/agent/0.2.0/install.sh
  rm /usr/local/lib/rowsafe/install.sh
  expect_ok "piped: a tampered installer is not kept" \
    sh -c 'ROWSAFE_RELEASES_URL=https://localhost:18443/agent ROWSAFE_RESTIC_URL=https://localhost:18443/restic sh -s <"$1/install.sh"' piped "$W"
  grep -q "doesn't match the signed manifest; not keeping it" "$W/out" || fail "a tampered installer copy went unnoticed"
  [ ! -e /usr/local/lib/rowsafe/install.sh ] || fail "a tampered installer was kept"
  cp "$W/install.sh.good" srv/agent/0.2.0/install.sh
  expect_ok "from the file, the installer keeps itself" "$INSTALLER"
  cmp /usr/local/lib/rowsafe/install.sh "$W/install.sh" || fail "the installer didn't keep itself"
  expect_fail "bad cipher pass refused" "at least 20 characters" env ROWSAFE_REPO_CIPHER_PASS=short "$INSTALLER"
  expect_fail "endpoint with scheme refused" "without a scheme" env ROWSAFE_REPO_S3_ENDPOINT=https://x.r2.cloudflarestorage.com "$INSTALLER"
  expect_fail "quote in value refused" "single quotes" env ROWSAFE_REPO_S3_BUCKET="it's" "$INSTALLER"

  expect_ok "upgrade to 0.12.0" env ROWSAFE_VERSION=0.12.0 "$INSTALLER"
  [ "$(readlink /opt/rowsafe/rowsafe-agent)" = versions/0.12.0/rowsafe-agent ] || fail "not switched to 0.12.0"
  cmp /usr/local/lib/rowsafe/rowsafe-permissions /opt/rowsafe/versions/0.12.0/rowsafe-agent || fail "permissions helper not upgraded" # permit-host
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
    # permit-host
    expect_ok "systemd-analyze verify (permissions units)" \
      systemd-analyze verify /etc/systemd/system/rowsafe-permissions.service /etc/systemd/system/rowsafe-permissions.path
    [ ! -s "$W/out" ] || {
      cat "$W/out" >&2
      fail "systemd-analyze verify printed warnings for the permissions units"
    }
    systemd-analyze security --offline=true --no-pager /etc/systemd/system/rowsafe-permissions.service 2>/dev/null |
      tail -n 1 | sed "s/^/  rowsafe-permissions: /"
  fi

  echo "x" >/var/lib/postgresql/17/main/postgresql.auto.conf
  echo "archive_command = '/usr/bin/pgbackrest --config=/etc/rowsafe/pgbackrest/app.conf --stanza=app archive-push %p'" \
    >>/var/lib/postgresql/17/main/postgresql.auto.conf
  expect_fail "purge refused while archiving" "still archives WAL" "$INSTALLER" --uninstall --purge
  [ -f /etc/rowsafe/agent.env ] && [ -x /opt/rowsafe/rowsafe-agent ] || fail "refused purge removed files"
  expect_ok "uninstall keeps config" "$INSTALLER" --uninstall
  [ ! -e /opt/rowsafe ] && [ -f /etc/rowsafe/agent.env ] && [ ! -e /etc/systemd/system/rowsafe-agent.service ] && [ -f /etc/logrotate.d/rowsafe ] &&
    [ ! -e /usr/local/lib/rowsafe ] && [ ! -e /usr/local/sbin/rowsafe-allow ] || fail "uninstall result"
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

# Questions a test doesn't care about, answered whenever they show up
# (unless a step waits for them): the passkey offer at the end of a guided
# setup.
AUTO = [(p, a) for p, a in (("Pair a passkey now?", "n"),) if all(p not in s for s, _ in steps)]
auto_seen = 0

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
    global auto_seen
    r, _, _ = select.select([master], [], [], timeout)
    if r:
        out += os.read(master, 65536)
        for pat, ans in AUTO:
            i = out.find(pat.encode(), auto_seen)
            if i >= 0:
                auto_seen = i + len(pat)
                time.sleep(0.1)
                os.write(master, ans.encode() + b"\r")
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
    sh -c 'ROWSAFE_RELEASES_URL=https://localhost:18443/agent ROWSAFE_RESTIC_URL=https://localhost:18443/restic sh -s rse_secrettoken123 <"$1/install.sh"' piped "$W"
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
  files_tests
  create_cluster_tests
  firewall_tests
  [ "${TEST_UNITS:-0}" != 1 ] || mysql_host_tests
  [ "${TEST_UNITS:-0}" != 1 ] || clickhouse_host_tests
  redis_host_tests
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
    sh -c 'ROWSAFE_URL=$2 ROWSAFE_RELEASES_URL=https://localhost:18443/agent ROWSAFE_RESTIC_URL=https://localhost:18443/restic sh -s rse_secrettoken123 <"$1/install.sh"' piped "$W" "$api"
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
  # (permissions) Nothing asked, but what Rowsafe may do is shown.
  grep -q "What Rowsafe may do on" "$W/out" && grep -q "not allowed  restart" "$W/out" &&
    grep -q "Allow one:          sudo rowsafe-allow restart" "$W/out" || fail "no permissions summary without a terminal"
  ! grep -q "What may Rowsafe do on this server?" "$W/out" || fail "the questions' heading without a terminal"
  [ ! -e "$F/calls" ] || fail "setup ran without a terminal or --protect"

  # 1. Found, named (a bad name first), plan, yes, restart needed, restart now.
  scenario "discover_out=$shop" "plan_out=$plan" "apply_out=Done: the backup settings are in place." apply_rc=10 \
    "wait_out=$done_" "status_out=$status"
  tty_ok "turn on backups, restart now" \
    "Restart or stop PostgreSQL, when someone clicks Restart or Rewind?\tn\nInstall and manage PgBouncer (connection pooling)\tn\nName it in Rowsafe [shop]\tTV Hub\nName it in Rowsafe\t\nTurn on backups for shop now? [Y/n]\t\nRestart PostgreSQL now? [y/N]\ty\n" \
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
  has "What may Rowsafe do on this server?"
  has "Rowsafe only does these when someone clicks them in your dashboard and"
  has "not allowed  restart           restart or stop PostgreSQL"
  lacks "Rowsafe can't restart or stop PostgreSQL" # the summary says it, once
  called "plan --name shop --port 5432 --socket-dir /var/run/postgresql --id-file"
  called "apply --database db_fake"
  called "wait --database db_fake --timeout 5m"
  [ "$(cat "$F/pg_ctlcluster")" = "17 main restart" ] || fail "$name: pg_ctlcluster not run as 17 main restart"
  grep -q "is off" /etc/rowsafe/restart-allowed || fail "$name: the no to restarts from Rowsafe was not kept"
  [ ! -e /usr/local/lib/rowsafe/rowsafe-pg-restart ] || fail "$name: restart helper installed after a no"
  has "not allowed  pooler            install and manage PgBouncer"
  has "Allow one:          sudo rowsafe-allow restart"
  grep -q "is off" /etc/rowsafe/pooler-allowed || fail "$name: the no to PgBouncer was not kept"
  [ ! -e /etc/systemd/system/rowsafe-pooler.path ] || fail "$name: PgBouncer helper installed after a no"

  # 2. Restart later: the command, and that Rowsafe finishes by itself.
  scenario "discover_out=$shop" "plan_out=$plan" apply_rc=10
  tty_ok "turn on backups, restart later" \
    "Name it in Rowsafe\t\nTurn on backups for shop now?\ty\nRestart PostgreSQL now?\t\n" "$INSTALLER"
  lacks "Restart or stop PostgreSQL, when"
  lacks "Install and manage PgBouncer (connection"
  lacks "What may Rowsafe do on this server?" # nothing asked: no heading, just the summary
  has "What Rowsafe may do on"
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
  # Never asked (the earlier answers gone): without a terminal, what touches
  # only the database is allowed, the server's own updates and reboots aren't.
  rm -f /etc/rowsafe/restart-allowed /etc/rowsafe/updates-allowed /etc/rowsafe/pooler-allowed /etc/rowsafe/create-cluster-allowed
  expect_ok "--protect: turned on, restart left to the user" "$INSTALLER" --protect shop
  grep -qx "5432 postgresql@17-main.service" /etc/rowsafe/restart-allowed || fail "--protect: restarts not allowed by default"
  grep -q '^postgresql' /etc/rowsafe/updates-allowed && ! grep -q '^security\|^reboot' /etc/rowsafe/updates-allowed ||
    fail "--protect: updates by default: $(cat /etc/rowsafe/updates-allowed 2>&1)"
  grep -q "allowed      restart" "$W/out" && grep -q "not allowed  security-updates" "$W/out" || fail "--protect: the summary lacks the defaults"
  "$INSTALLER" --permissions --no-prompt --no-allow-restart --no-allow-pooler >/dev/null 2>&1 || fail "--protect: couldn't put the earlier answers back"
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
  mongodb_flow_tests
  clickhouse_flow_tests
  qdrant_flow_tests
  redis_flow_tests
  sqlite_flow_tests
}

# sqlite_flow_tests: SQLite files, named with --sqlite or found open (root's
# `rowsafe-agent sqlite find`): the agent gets read and write access with
# ACLs (owner, group and mode unchanged), the file goes to the agent's list,
# and the plan names the file (--engine sqlite --socket-dir PATH).
sqlite_flow_tests() {
  echo "  -- SQLite"
  id -u shopapp >/dev/null 2>&1 || useradd --system --user-group shopapp
  mkfile() { # PATH: a SQLite file owned by shopapp, 0644
    install -d -o shopapp -g shopapp -m 0755 "$(dirname "$1")"
    { printf 'SQLite format 3\000'; head -c 4080 /dev/zero; } >"$1"
    chown shopapp:shopapp "$1"
    chmod 0644 "$1"
  }
  db=/srv/shop/db/production.sqlite3
  mkfile "$db"
  rm -f /etc/rowsafe/sqlite-paths /etc/rowsafe/sqlite-clone-dirs
  line="0\t$db\t0\t-\t/srv/shop/db\t4096\tshop-production\tno\t-\tshop-production\t4.0 KiB\t-\t-\tsqlite"
  splan='SQLite database in /srv/shop/db (4.0 KiB, 2 tables, wal journal mode).\n\nWhat Rowsafe will change:\n  - Prepare your bucket for this database'

  # 1. --protect with --sqlite: access, the list, the plan by path.
  scenario "discover_out=$line" "plan_out=$splan" "wait_out=$done_" "status_out=$status"
  expect_ok "--protect --sqlite: access, list, plan by file" "$INSTALLER" --protect shop --sqlite "$db"
  called "plan --name shop --port 0 --socket-dir $db"
  called "--engine sqlite"
  called "apply --database db_fake"
  grep -qxF "$db" /etc/rowsafe/sqlite-paths || fail "$name: $db isn't in /etc/rowsafe/sqlite-paths"
  [ "$(stat -c '%a' /etc/rowsafe/sqlite-paths)" = 644 ] || fail "$name: /etc/rowsafe/sqlite-paths isn't 0644"
  getfacl -p "$db" 2>/dev/null | grep -qx 'user:postgres:rw-' || fail "$name: no ACL for the agent on $db"
  getfacl -p /srv/shop/db 2>/dev/null | grep -qx 'user:postgres:rwx' || fail "$name: no ACL for the agent on its folder"
  getfacl -p /srv/shop/db 2>/dev/null | grep -qx 'default:user:shopapp:rw-' || fail "$name: no default ACL for the app's user"
  [ "$(stat -c '%U %G' "$db")" = "shopapp shopapp" ] || fail "$name: the file's owner changed"
  getfacl -p "$db" 2>/dev/null | grep -qx 'group::r--' || fail "$name: the file's group gained access"
  grep -q "gave the agent (postgres) read and write access to $db" "$W/out" || fail "$name: the change isn't said"
  # Without a terminal, closing the SQLite files to others is allowed by default.
  grep -qx 'sqlite-paths' /etc/rowsafe/sqlite-modes-allowed || fail "$name: closing SQLite files isn't allowed by default"
  rm -f /etc/rowsafe/sqlite-modes-allowed # never asked again, for the question below

  # 2. A file found open, picked on a terminal; a folder for clones named
  # when asked (none allowed yet).
  db2=/srv/blog/blog.db
  mkfile "$db2"
  line2="0\t$db2\t0\t-\t/srv/blog\t4096\tblog\tno\t-\tblog\t4.0 KiB\t-\t-\tsqlite"
  scenario "sqlite-find_out=$db2\t4096\twal\t4242\truby\t-\t-\t999\t999\tblog" "discover_out=$line2" "plan_out=$splan"
  tty_ok "SQLite file found open: picked, access, plan" \
    "Protect $db2\ty\nAllow Rowsafe to make clones\ty\nFolder for the clones\t/srv/tty-clones\nclose the SQLite files to this server's other users\tn\nName it in Rowsafe\t\nTurn on backups for blog now?\tn\n" "$INSTALLER"
  called "sqlite find (root)"
  grep -qxF /srv/tty-clones /etc/rowsafe/sqlite-clone-dirs || fail "$name: the folder for clones isn't in the list"
  getfacl -p /srv/tty-clones 2>/dev/null | grep -qx 'user:postgres:rwx' || fail "$name: no ACL for the agent on the clones folder"
  called "--socket-dir $db2"
  grep -qxF "$db2" /etc/rowsafe/sqlite-paths || fail "$name: $db2 isn't in the list"
  getfacl -p "$db2" 2>/dev/null | grep -qx 'user:postgres:rw-' || fail "$name: no ACL for the agent on $db2"

  # 3. A side file is refused, and --protect takes exactly one --sqlite.
  expect_fail "--sqlite refuses a -wal file" "not its -wal" "$INSTALLER" --sqlite "$db-wal"
  expect_fail "--protect with two --sqlite files" "exactly one --sqlite" "$INSTALLER" --protect shop --sqlite "$db" --sqlite "$db2"
  pass "SQLite: --sqlite and found files get ACL access, the list, plans by file; side files refused"
  grep -qx '# Closing SQLite files to other users from Rowsafe (Security) is off.' /etc/rowsafe/sqlite-modes-allowed ||
    fail "the no to closing SQLite files isn't kept"

  # 4. --allow-sqlite-modes: root's helper may close the listed files (and
  #    only in their folders) to other users; --no-allow-sqlite-modes removes it.
  scenario "discover_out=$line" "plan_out=$splan"
  expect_ok "--allow-sqlite-modes: allow list, helper units" "$INSTALLER" --allow-sqlite-modes --no-setup
  has "Rowsafe may close the SQLite files to other users when you click Apply fix (Security)"
  grep -qx sqlite-paths /etc/rowsafe/sqlite-modes-allowed || fail "$name: $(cat /etc/rowsafe/sqlite-modes-allowed)"
  [ "$(stat -c '%U %a' /etc/rowsafe/sqlite-modes-allowed)" = "root 644" ] || fail "$name: allow list ownership/mode"
  u=/etc/systemd/system/rowsafe-sqlite-modes.service
  grep -qx 'ExecStart=/usr/local/lib/rowsafe/rowsafe-permissions sqlite-modes-apply' "$u" || fail "$name: no helper unit"
  grep -qx 'Environment=ROWSAFE_AGENT_USER=postgres' "$u" || fail "$name: the unit doesn't name the agent's user"
  grep -qx 'ReadWritePaths=-/srv/blog -/srv/shop/db' "$u" || fail "$name: ReadWritePaths isn't the listed files' folders: $(grep ReadWrite "$u")"
  grep -qx 'ProtectSystem=strict' "$u" || fail "$name: the unit may write everywhere"
  grep -qx 'PathExists=/var/lib/rowsafe/sqlite-modes/request' /etc/systemd/system/rowsafe-sqlite-modes.path || fail "$name: no path unit"
  [ "$(stat -c '%U %a' /var/lib/rowsafe/sqlite-modes)" = "postgres 700" ] || fail "$name: request directory ownership/mode"
  if [ "${TEST_UNITS:-0}" = 1 ]; then
    expect_ok "systemd-analyze verify (SQLite helper units)" systemd-analyze verify "$u" /etc/systemd/system/rowsafe-sqlite-modes.path
  fi
  scenario "discover_out=$line" "plan_out=$splan"
  expect_ok "--no-allow-sqlite-modes" "$INSTALLER" --no-allow-sqlite-modes --no-setup
  [ ! -e "$u" ] && [ ! -e /etc/systemd/system/rowsafe-sqlite-modes.path ] || fail "$name: helper units left"
  ! grep -qx sqlite-paths /etc/rowsafe/sqlite-modes-allowed || fail "$name: allow list kept"
  pass "SQLite: --allow-sqlite-modes sets up root's helper for the listed files' folders only; --no-allow-sqlite-modes removes it"
  rm -f /etc/rowsafe/sqlite-paths /etc/rowsafe/sqlite-modes-allowed

  # 4. Folders for clones (--sqlite-clone-dir): made when missing, write
  # access for the agent, a default ACL for the folder's owner, the list;
  # system folders and relative paths refused; asked only once.
  install -d -o shopapp -g shopapp -m 0750 /srv/shop/clones
  scenario
  expect_ok "--sqlite-clone-dir: folders allowed" "$INSTALLER" --no-setup --sqlite-clone-dir /srv/clones --sqlite-clone-dir /srv/shop/clones --sqlite-clone-dir /etc/rowsafe-clones
  for d in /srv/clones /srv/shop/clones; do
    grep -qxF "$d" /etc/rowsafe/sqlite-clone-dirs || fail "$name: $d isn't in /etc/rowsafe/sqlite-clone-dirs"
    getfacl -p "$d" 2>/dev/null | grep -qx 'user:postgres:rwx' || fail "$name: no ACL for the agent on $d"
    getfacl -p "$d" 2>/dev/null | grep -qx 'default:user:postgres:rw-' || fail "$name: no default ACL for the agent on $d"
    runuser -u postgres -- sh -c "touch '$d/probe' && rm '$d/probe'" || fail "$name: the agent can't write in $d"
  done
  getfacl -p /srv/shop/clones 2>/dev/null | grep -qx 'default:user:shopapp:rw-' || fail "$name: no default ACL for the folder's owner"
  [ "$(stat -c '%U %G' /srv/shop/clones)" = "shopapp shopapp" ] || fail "$name: the folder's owner changed"
  getfacl -p /srv/shop/clones 2>/dev/null | grep -qx 'other::---' || fail "$name: others gained access to the folder"
  getfacl -p /srv/shop/clones 2>/dev/null | grep -qx 'group::r-x' || fail "$name: the folder's group gained access"
  [ "$(stat -c '%a' /etc/rowsafe/sqlite-clone-dirs)" = 644 ] || fail "$name: the list isn't 0644"
  ! grep -q rowsafe-clones /etc/rowsafe/sqlite-clone-dirs || fail "$name: a system folder was allowed"
  [ ! -e /etc/rowsafe-clones ] || fail "$name: a folder was made under /etc"
  grep -q "may write SQLite clones into /srv/shop/clones" "$W/out" || fail "$name: the change isn't said"
  expect_ok "--sqlite-clone-dir: re-run keeps one line per folder" "$INSTALLER" --no-setup --sqlite-clone-dir /srv/clones
  [ "$(grep -cxF /srv/clones /etc/rowsafe/sqlite-clone-dirs)" = 1 ] || fail "$name: duplicate line"
  expect_fail "--sqlite-clone-dir refuses a relative path" "absolute path" "$INSTALLER" --sqlite-clone-dir srv/clones
  expect_fail "--sqlite-clone-dir refuses /" "absolute path" "$INSTALLER" --sqlite-clone-dir /
  pass "SQLite clones: --sqlite-clone-dir and the question allow folders with ACLs; system folders refused"
  rm -f /etc/rowsafe/sqlite-paths /etc/rowsafe/sqlite-clone-dirs
}

# sqlite_only_tests (TEST_ONLY=sqlite): what the SQLite cases need of the
# rest (an install with storage, the agent running as postgres), then only
# those cases.
sqlite_only_tests() {
  write_terminal_helpers
  useradd --system --home-dir /var/lib/postgresql --create-home --shell /bin/sh postgres
  mkdir -p /usr/lib/postgresql/17/bin /var/lib/postgresql/17/main
  printf '#!/bin/sh\n' >/usr/lib/postgresql/17/bin/postgres && chmod 755 /usr/lib/postgresql/17/bin/postgres
  configured() {
    env ROWSAFE_REPO_S3_ENDPOINT=acct.eu.r2.cloudflarestorage.com ROWSAFE_REPO_S3_BUCKET=app-rowsafe \
      ROWSAFE_REPO_S3_KEY=AKIAEXAMPLEKEY42 ROWSAFE_REPO_S3_KEY_SECRET=s3cr3t/with+base64= \
      ROWSAFE_REPO_CIPHER_PASS='cipher-pass-that-is-long-enough/+==' "$@"
  }
  scenario
  expect_ok "configured install" configured "$INSTALLER" rse_secrettoken123 --no-allow-restart --no-allow-pooler
  echo '{"host_id":"host_1","agent_token":"rsa_x"}' >/var/lib/rowsafe/agent.json
  chown postgres:postgres /var/lib/rowsafe/agent.json
  runuser -u postgres -- /opt/rowsafe/rowsafe-agent run >/dev/null 2>&1 &
  sleep 1
  done_='Checking that changes reach your storage...\n✓ shop is protected. The first full backup is running.'
  status='db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake'
  scenario
  expect_ok "agent running, restarts and pooling off" "$INSTALLER" --no-allow-restart --no-allow-pooler
  sqlite_flow_tests
  echo "test-install: SQLite cases passed"
}

# mongodb_flow_tests: a MongoDB server found by discover (engine column):
# its replica set and Rowsafe's own MongoDB user come before the plan.
mongodb_flow_tests() {
  echo "  -- MongoDB"
  mongo='27017\t-\t8\t-\t/var/lib/mongodb\t52428800\tshop\tno\t-\tshop\t50.0 MiB\tmongod.service\t-\tmongodb'
  rs='port=27017\nversion=8.0.4\nreplset=rs0\ninitiated=yes\nprimary=yes\nauth=on\nlogin=ok\nconfig=/etc/mongod.conf\ndbpath=/var/lib/mongodb\nkeyfile=-\nunit=mongod.service'
  standalone='port=27017\nversion=8.0.4\nreplset=-\ninitiated=no\nprimary=yes\nauth=off\nlogin=not-needed\nconfig=/etc/mongod.conf\ndbpath=/var/lib/mongodb\nkeyfile=-\nunit=mongod.service'
  noLogin='port=27017\nversion=8.0.4\nreplset=rs0\ninitiated=yes\nprimary=yes\nauth=on\nlogin=missing\nconfig=/etc/mongod.conf\ndbpath=/var/lib/mongodb\nkeyfile=-\nunit=mongod.service'
  mplan='MongoDB 8.0.4 on port 27017: 50.0 MiB, 1 database (shop).\n\nWhat Rowsafe will change:\n  - Prepare your bucket for this database\n\nNo downtime: MongoDB does not need a restart.'

  # 1. A replica set with Rowsafe's login: straight to the plan, with the engine.
  scenario "discover_out=$mongo" "mongodb-status_out=$rs" "plan_out=$mplan" "wait_out=$done_" "status_out=$status"
  tty_ok "MongoDB replica set: plan, turn on" "Name it in Rowsafe\t\nTurn on backups for shop now?\t\n" "$INSTALLER"
  has "Found MongoDB 8 on port 27017 (50.0 MiB; databases: shop)"
  has "No downtime: MongoDB does not need a restart."
  called "mongodb-status --port 27017"
  called "plan --name shop --port 27017 --id-file"
  called "--engine mongodb"
  not_called "socket-dir -"
  not_called "mongodb-login"
  called "apply --database db_fake"

  # 2. A standalone server: explained, and a no changes nothing.
  scenario "discover_out=$mongo" "mongodb-status_out=$standalone"
  tty_ok "MongoDB standalone: declined" "Name it in Rowsafe\t\nTurn on the replica set and restart MongoDB now? [y/N]\t\n" "$INSTALLER"
  has "runs as a standalone server"
  has "OK, nothing was changed."
  not_called "plan"
  not_called "mongodb-initiate"

  # 3. Access control on and no login yet: an administrator signs in once;
  #    the password goes to the agent on stdin and is never printed.
  scenario "discover_out=$mongo" "mongodb-status_out=$noLogin" "mongodb-login_rc=11\n0" \
    "mongodb-login_out=Created MongoDB user rowsafe for Rowsafe" "plan_out=$mplan"
  tty_ok "MongoDB login with an administrator" \
    "Name it in Rowsafe\t\nMongoDB administrator user [admin]\troot\nPassword for root\tAdm1n-S3cret\nTurn on backups for shop now?\tn\n" "$INSTALLER"
  called "mongodb-login --port 27017 --admin-user root"
  [ "$(cat "$F/mongodb-login.stdin")" = Adm1n-S3cret ] || fail "$name: the administrator's password didn't reach the agent on stdin"
  lacks "Adm1n-S3cret"
  ! grep -rq "Adm1n-S3cret" /etc/rowsafe /var/lib/rowsafe 2>/dev/null || fail "$name: the administrator's password was saved"
  called "plan --name shop --port 27017"

  # 4. --protect never restarts a standalone MongoDB without --mongodb-replica-set.
  scenario "discover_out=$mongo" "mongodb-status_out=$standalone"
  expect_fail "--protect with a standalone MongoDB" "isn't ready for backups" "$INSTALLER" --protect shop
  not_called "plan"
  scenario "discover_out=$mongo" "mongodb-status_out=$standalone"
  expect_fail "--no-mongodb-replica-set" "isn't ready for backups" "$INSTALLER" --protect shop --no-mongodb-replica-set
  grep -q "Skipped (--no-mongodb-replica-set)" "$W/out" || fail "--no-mongodb-replica-set: not explained"
  pass "MongoDB: engine in the plan, standalone explained, administrator login once, --protect never restarts"
}

# clickhouse_flow_tests: a ClickHouse server found by discover (engine
# column): Rowsafe's own ClickHouse user comes before the plan, as a users.d
# file root installs, or with an administrator's login once. Nothing restarts.
clickhouse_flow_tests() {
  echo "  -- ClickHouse"
  ch='8123\t-\t26.8\t-\t/var/lib/clickhouse\t52428800\tevents\tno\t-\tevents\t50.0 MiB\tclickhouse-server.service\t-\tclickhouse'
  chst() { printf 'port=8123\\nversion=26.8.15.10\\nlogin=%s\\nuser=clickhouse\\ndatadir=/var/lib/clickhouse\\nconfig=/etc/clickhouse-server/config.xml\\nusersd=-\\nunit=clickhouse-server.service\\nbinary=%s\\nreplicated=0\\ndocker=no' "$1" "${2:-/usr/bin/clickhouse}"; }
  chplan='ClickHouse 26.8.15.10 on port 8123: 50.0 MiB, 1 database (events).\n\nWhat Rowsafe will change:\n  - Prepare your bucket for this database\n\nNo downtime: ClickHouse does not need a restart.'
  usersxml='<clickhouse><users><rowsafe><password_sha256_hex>00ff</password_sha256_hex></rowsafe></users></clickhouse>'

  # 1. Rowsafe's login already works: straight to the plan, with the engine.
  scenario "discover_out=$ch" "clickhouse-status_out=$(chst ok)" "plan_out=$chplan" "wait_out=$done_" "status_out=$status"
  tty_ok "ClickHouse with Rowsafe's login: plan, turn on" "Name it in Rowsafe\t\nTurn on backups for events now?\t\n" "$INSTALLER"
  has "Found ClickHouse 26.8 on port 8123 (50.0 MiB; databases: events)"
  has "No downtime: ClickHouse does not need a restart."
  called "clickhouse-status --port 8123"
  called "plan --name events --port 8123 --id-file"
  called "--engine clickhouse"
  not_called "socket-dir -"
  not_called "clickhouse-login"
  called "apply --database db_fake"

  # 2. No login yet: root installs the agent's users.d file next to
  #    users.xml (root:clickhouse 0640); ClickHouse loads it, no admin asked.
  getent group clickhouse >/dev/null || groupadd --system clickhouse
  mkdir -p /etc/clickhouse-server
  echo '<clickhouse/>' >/etc/clickhouse-server/users.xml
  scenario "discover_out=$ch" "clickhouse-status_out=$(chst missing -)" "clickhouse-login_out=$usersxml" "plan_out=$chplan"
  tty_ok "ClickHouse login as a users.d file" "Name it in Rowsafe\t\nTurn on backups for events now?\tn\n" "$INSTALLER"
  called "clickhouse-login --port 8123 --users-xml"
  not_called "rowsafe-server" # SYSTEM RELOAD CONFIG only on servers Rowsafe created
  not_called "admin-user"
  f=/etc/clickhouse-server/users.d/rowsafe.xml
  [ "$(stat -c '%U %G %a' "$f" 2>/dev/null)" = "root clickhouse 640" ] || fail "$name: $f missing or not root:clickhouse 0640"
  [ "$(cat "$f")" = "$usersxml" ] || fail "$name: $f isn't what the agent printed"
  has "Rowsafe needs its own ClickHouse user, rowsafe"
  has "ClickHouse loaded it by itself, without a restart"
  has "Proof and Rewind copies need the clickhouse program"
  lacks "password_sha256_hex"
  called "plan --name events --port 8123"
  rm -rf /etc/clickhouse-server

  # 3. No users.d to use: the SQL way. "default" can't create users (13),
  #    an administrator signs in once; the password goes to the agent on
  #    stdin and is never printed or saved.
  scenario "discover_out=$ch" "clickhouse-status_out=$(chst missing)" "clickhouse-login_rc=13\n12\n0" \
    "clickhouse-login_out=Created ClickHouse user rowsafe for Rowsafe" "plan_out=$chplan"
  tty_ok "ClickHouse login with an administrator" \
    "Name it in Rowsafe\t\nClickHouse administrator user [default]\tadmin\nPassword for admin\twrong\nClickHouse administrator user [default]\tadmin\nPassword for admin\tCl1ck-S3cret\nTurn on backups for events now?\tn\n" "$INSTALLER"
  has "ClickHouse refused that login."
  called "clickhouse-login --port 8123 --admin-user admin"
  [ "$(cat "$F/clickhouse-login.stdin")" = Cl1ck-S3cret ] || fail "$name: the administrator's password didn't reach the agent on stdin"
  lacks "Cl1ck-S3cret"
  ! grep -rq "Cl1ck-S3cret" /etc/rowsafe /var/lib/rowsafe 2>/dev/null || fail "$name: the administrator's password was saved"
  called "plan --name events --port 8123"

  # 4. --protect: without a way to create the user it stops before the
  #    plan; ROWSAFE_CLICKHOUSE_ADMIN_* (no terminal) are used once.
  scenario "discover_out=$ch" "clickhouse-status_out=$(chst missing)" clickhouse-login_rc=13
  expect_fail "--protect: ClickHouse without a login" "ROWSAFE_CLICKHOUSE_ADMIN_USER" "$INSTALLER" --protect events
  grep -q "isn't ready for backups" "$W/out" || fail "$name: not explained"
  not_called "plan"
  scenario "discover_out=$ch" "clickhouse-status_out=$(chst missing)" "clickhouse-login_rc=13\n0" "plan_out=$chplan" "wait_out=$done_"
  expect_ok "--protect: ClickHouse administrator from the environment" \
    env ROWSAFE_CLICKHOUSE_ADMIN_USER=admin ROWSAFE_CLICKHOUSE_ADMIN_PASSWORD=Env-S3cret "$INSTALLER" --protect events
  called "clickhouse-login --port 8123 --admin-user admin"
  [ "$(cat "$F/clickhouse-login.stdin")" = Env-S3cret ] || fail "$name: the administrator's password didn't reach the agent on stdin"
  ! grep -q "Env-S3cret" "$W/out" || fail "$name: the administrator's password was printed"
  ! grep -q "ROWSAFE_CLICKHOUSE_ADMIN" /etc/rowsafe/agent.env || fail "$name: the administrator's login went to agent.env"
  called "apply --database db_fake"
  pass "ClickHouse: engine in the plan, users.d file as root, administrator login once, --protect"
}

qdrant_flow_tests() {
  echo "  -- Qdrant"
  qd='6333\t-\t1\t-\t/var/lib/qdrant/storage\t1048576\tvectors\tno\t-\tdocs\t1.0 MiB\tqdrant.service\t-\tqdrant'
  qdst() { printf 'port=6333\\nengine=qdrant\\nversion=1.19.2\\nlogin=%s\\ntls=no\\njwt=%s\\nbinary=%s\\ndocker=no\\ncluster=no\\nconfig=/etc/qdrant/config.yaml\\nunit=qdrant.service\\ncollections=1' "$1" "${2:-unknown}" "${3:-/usr/bin/qdrant}"; }
  qdplan='Qdrant 1.19.2 on port 6333: 1.0 MiB, 1 collection (docs).\n\nWhat Rowsafe will change:\n  - Prepare your bucket for this database\n\nNo downtime: Qdrant does not need a restart.'

  # 1. Rowsafe's key already works: straight to the plan, with the engine.
  scenario "discover_out=$qd" "qdrant-status_out=$(qdst ok yes)" "plan_out=$qdplan" "wait_out=$done_" "status_out=$status"
  tty_ok "Qdrant with Rowsafe's key: plan, turn on" "Name it in Rowsafe\t\nTurn on backups for vectors now?\t\n" "$INSTALLER"
  called "qdrant-status --port 6333"
  called "plan --name vectors --port 6333 --id-file"
  called "--engine qdrant"
  not_called "qdrant-login"
  not_called "qdrant-save-login"
  called "apply --database db_fake"

  # 2. No key yet, on a terminal: the person's api_key, typed once, goes to
  #    the agent on stdin, never printed or saved elsewhere.
  scenario "discover_out=$qd" "qdrant-status_out=$(qdst missing)" "plan_out=$qdplan"
  tty_ok "Qdrant key typed once" "Name it in Rowsafe\t\nQdrant api_key\tQd-Typed-Key-123\nTurn on backups for vectors now?\tn\n" "$INSTALLER"
  called "qdrant-save-login --port 6333"
  [ "$(cat "$F/qdrant-save-login.stdin")" = Qd-Typed-Key-123 ] || fail "$name: the key didn't reach the agent on stdin"
  lacks "Qd-Typed-Key-123"
  ! grep -rq "Qd-Typed-Key-123" /etc/rowsafe 2>/dev/null || fail "$name: the key was saved by root"
  called "plan --name vectors --port 6333"

  # 3. --protect: ROWSAFE_QDRANT_API_KEY (no terminal), else the api_key
  #    in Qdrant's configuration file, else it stops before the plan.
  scenario "discover_out=$qd" "qdrant-status_out=$(qdst missing)" "plan_out=$qdplan" "wait_out=$done_"
  expect_ok "--protect: Qdrant key from the environment" env ROWSAFE_QDRANT_API_KEY=Env-Qd-Key-456 "$INSTALLER" --protect vectors
  [ "$(cat "$F/qdrant-save-login.stdin")" = Env-Qd-Key-456 ] || fail "$name: the key didn't reach the agent on stdin"
  ! grep -q "Env-Qd-Key-456" "$W/out" || fail "$name: the key was printed"
  ! grep -q "ROWSAFE_QDRANT_API_KEY" /etc/rowsafe/agent.env || fail "$name: the key went to agent.env"
  called "apply --database db_fake"
  printf 'service:\n  host: 0.0.0.0\n  api_key: "Conf-Qd-Key-789" # the admin key\n' >"$W/qdrant.yaml"
  scenario "discover_out=$qd" "qdrant-status_out=$(qdst missing)" "plan_out=$qdplan" "wait_out=$done_"
  expect_ok "--protect: Qdrant key from its configuration file" env ROWSAFE_QDRANT_CONFIG="$W/qdrant.yaml" "$INSTALLER" --protect vectors
  [ "$(cat "$F/qdrant-save-login.stdin")" = Conf-Qd-Key-789 ] || fail "$name: the configuration file's key didn't reach the agent"
  grep -q "uses the api_key from Qdrant's configuration file" "$W/out" || fail "$name: not said where the key came from"
  ! grep -q "Conf-Qd-Key-789" "$W/out" || fail "$name: the key was printed"
  grep -q "service.alt_api_key" "$W/out" || fail "$name: not said how to give Rowsafe a key of its own"
  # Root set an alternative key in the configuration file: Rowsafe's own
  # (qdrant login), never the apps' api_key, and on a later run too.
  printf 'service:\n  api_key: "Conf-Qd-Key-789"\n  alt_api_key: Conf-Qd-Alt-321\n' >"$W/qdrant.yaml"
  scenario "discover_out=$qd" "qdrant-status_out=$(qdst missing)" "plan_out=$qdplan" "wait_out=$done_"
  expect_ok "--protect: Rowsafe's own key from Qdrant's configuration file" env ROWSAFE_QDRANT_CONFIG="$W/qdrant.yaml" "$INSTALLER" --protect vectors
  [ "$(cat "$F/qdrant-login.stdin")" = Conf-Qd-Alt-321 ] || fail "$name: the alternative key didn't reach the agent"
  not_called "qdrant-save-login"
  ! grep -q "Conf-Qd-Alt-321" "$W/out" || fail "$name: the key was printed"
  scenario "discover_out=$qd" "qdrant-status_out=$(qdst ok yes)" "plan_out=$qdplan" "wait_out=$done_"
  expect_ok "--protect: an alternative key added later replaces the api_key" env ROWSAFE_QDRANT_CONFIG="$W/qdrant.yaml" "$INSTALLER" --protect vectors
  [ "$(cat "$F/qdrant-login.stdin")" = Conf-Qd-Alt-321 ] || fail "$name: the alternative key didn't reach the agent"
  scenario "discover_out=$qd" "qdrant-status_out=$(qdst ok yes)" "qdrant-login_rc=12" "plan_out=$qdplan" "wait_out=$done_"
  expect_ok "--protect: an alternative key Qdrant hasn't loaded yet" env ROWSAFE_QDRANT_CONFIG="$W/qdrant.yaml" "$INSTALLER" --protect vectors
  grep -q "restart Qdrant when it suits you" "$W/out" || fail "$name: not said why the key was refused"
  not_called "qdrant-save-login"
  called "apply --database db_fake"
  scenario "discover_out=$qd" "qdrant-status_out=$(qdst missing)"
  expect_fail "--protect: Qdrant without a key" "ROWSAFE_QDRANT_API_KEY" "$INSTALLER" --protect vectors
  grep -q "isn't ready for backups" "$W/out" || fail "$name: not explained"
  not_called "plan"

  # 4. A Qdrant without keys: protected, with a warning.
  scenario "discover_out=$qd" "qdrant-status_out=$(qdst none)" "plan_out=$qdplan" "wait_out=$done_"
  expect_ok "--protect: Qdrant without keys" "$INSTALLER" --protect vectors
  grep -q "asks for no key" "$W/out" || fail "$name: no warning about a Qdrant without keys"
  not_called "qdrant-save-login"
  pass "Qdrant: engine in the plan, Rowsafe's key from root, the environment, its configuration or typed once, never printed"
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
  # Without a terminal, PostgreSQL's updates came with it, the server's own didn't.
  grep -q '^postgresql' /etc/rowsafe/updates-allowed && ! grep -q '^security\|^reboot' /etc/rowsafe/updates-allowed ||
    fail "--allow-restart: updates by default: $(cat /etc/rowsafe/updates-allowed 2>&1)"
  rm -f /etc/rowsafe/create-cluster-allowed /etc/rowsafe/updates-allowed # never asked, for the questions below
  # A re-run without the flag keeps it (and asks nothing).
  scenario "discover_out=$shop"
  tty_ok "a re-run keeps restarts allowed (and asks about updates once)" \
    "Create a new PostgreSQL cluster here\tn\nInstall PostgreSQL updates and upgrades\tn\nInstall this server's security updates\tn\nName it in Rowsafe\t\nTurn on backups for shop now?\tn\n" "$INSTALLER"
  lacks "Restart or stop PostgreSQL, when"
  lacks "Reboot this server, when"
  has "allowed      restart           restart or stop PostgreSQL"
  has "not allowed  security-updates  install this server's security updates"
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
  result_has "error=postgresql@17-main.service was restarted less than a minute ago; try again in a minute"
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
  result_has "error=postgresql@17-main.service was restarted less than a minute ago; try again in a minute"
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

  cp /etc/rowsafe/restart-allowed "$W/restart-allowed.saved"
  redis_restart_tests
  install -m 0644 -o root -g root "$W/restart-allowed.saved" /etc/rowsafe/restart-allowed
  scenario "discover_out=$shop"

  pooler_tests
  update_tests
  permissions_tests

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

# ------------------------------------------------------------ permissions

# permissions_tests: install.sh --permissions and sudo rowsafe-allow, on the
# server restart_tests set up (restarts allowed, the agent running).
permissions_tests() {
  echo "  -- permissions (--permissions, sudo rowsafe-allow)"
  P=/usr/local/lib/rowsafe/install.sh
  A=/usr/local/sbin/rowsafe-allow
  U=/etc/rowsafe/updates-allowed
  # perm NAME ARGS...: the installer copy's permissions mode, as root
  # automation runs it (no terminal, the releases unreachable: it must not
  # need them).
  perm() { ROWSAFE_RELEASES_URL=https://127.0.0.1:9/agent "$P" --permissions "$@"; }
  perm_rc() { # NAME CODE PATTERN ARGS...
    n=$1 code=$2 pattern=$3
    shift 3
    rc=0
    perm "$@" >"$W/out" 2>&1 || rc=$?
    [ "$rc" = "$code" ] && grep -qF -- "$pattern" "$W/out" || {
      cat "$W/out" >&2
      fail "$n (exit $rc, wanted $code with '$pattern')"
    }
    pass "$n"
  }
  # What --permissions must never touch.
  snapshot() {
    {
      readlink /opt/rowsafe/rowsafe-agent
      sha256sum /etc/rowsafe/agent.env /etc/systemd/system/rowsafe-agent.service /opt/rowsafe/rowsafe-agent "$P"
      find /opt/rowsafe /var/lib/rowsafe/agent.json -maxdepth 2 | sort
    } 2>/dev/null
  }
  allow_files() { sha256sum /etc/rowsafe/*-allowed 2>/dev/null; }
  last_lines_summary() {
    tail -n 12 "$W/out" | grep -q "What Rowsafe may do on" || {
      cat "$W/out" >&2
      fail "$n: the summary isn't at the end"
    }
  }

  scenario "discover_out=$shop"
  expect_ok "a known start: restarts on, updates off" "$INSTALLER" --allow-restart --no-allow-updates --no-allow-security-updates --no-allow-pooler --no-allow-create-cluster
  snapshot >"$W/snap.before"

  # Without a change: the summary, and nothing written.
  allow_files >"$W/allow.before"
  n="--permissions alone lists"
  perm_rc "$n" 0 "What Rowsafe may do on" 
  has "allowed      restart           restart or stop PostgreSQL (Restart, Rewind)"
  has "not allowed  updates           install PostgreSQL updates and upgrades"
  has "unavailable  firewall          nftables isn't installed"
  has "not allowed  create-cluster    create a PostgreSQL cluster for a fork"
  has "Allow one:          sudo rowsafe-allow create-cluster"
  has "Stop allowing one:  sudo rowsafe-allow --remove restart"
  allow_files | cmp -s - "$W/allow.before" || fail "--permissions without a change changed an allow list"

  # A need that stays off is refused; nothing changes.
  perm_rc "reboot without security updates refused" 2 \
    "reboot only works with security-updates allowed too. Allow them together: sudo rowsafe-allow security-updates reboot" --no-prompt --allow-reboot
  allow_files | cmp -s - "$W/allow.before" || fail "a refused change changed an allow list"
  perm_rc "on and off at once refused" 2 "security-updates needs restart, so it can't be allowed while restart is turned off" \
    --allow-security-updates --no-allow-restart
  perm_rc "not possible here refused" 2 "Rowsafe can't limit who can reach the database on this server: nftables isn't installed" --allow-firewall
  perm_rc "install options refused" 2 "--permissions only changes what Rowsafe may do" --protect shop
  [ ! -e /etc/systemd/system/rowsafe-pg-update.path ] || fail "a refused change installed the update units"
  allow_files | cmp -s - "$W/allow.before" || fail "a refused change changed an allow list"

  # On, with what they need.
  n="security updates and reboot on"
  perm_rc "$n" 0 "reboot: allowed" --no-prompt --allow-security-updates --allow-reboot
  has "security-updates: allowed"
  last_lines_summary
  grep -q '^security ' "$U" && grep -q '^reboot ' "$U" && ! grep -q '^postgresql' "$U" || fail "$n: $(cat "$U")"
  cmp /etc/systemd/system/rowsafe-pg-update.path /src/deploy/systemd/rowsafe-pg-update.path || fail "$n: no update path unit"
  [ "$(stat -c '%U %a' "$U")" = "root 644" ] || fail "$n: allow list ownership/mode"

  # Off: what needs it goes too.
  n="security updates off takes reboot along"
  perm_rc "$n" 0 "reboot: not allowed any more (it needs security-updates)" --no-allow-security-updates
  ! grep -q '^security' "$U" && ! grep -q '^reboot' "$U" || fail "$n: $(cat "$U")"
  [ ! -e /etc/systemd/system/rowsafe-pg-update.path ] || fail "$n: update units left"

  perm --allow-updates >"$W/out" 2>&1 || fail "updates on: $(cat "$W/out")"
  n="restart off takes updates along"
  perm_rc "$n" 0 "updates: not allowed any more (it needs restart)" --no-allow-restart
  has "restart: not allowed"
  ! grep -q '^[0-9]' /etc/rowsafe/restart-allowed || fail "$n: restart list kept"
  [ ! -e /usr/local/lib/rowsafe/rowsafe-pg-restart ] && [ ! -e /etc/systemd/system/rowsafe-pg-restart.path ] || fail "$n: restart helper left"
  [ ! -e "$U" ] && [ ! -e /etc/systemd/system/rowsafe-pg-update.path ] || fail "$n: updates left"
  perm_rc "updates need restart" 2 "Allow them together: sudo rowsafe-allow restart updates" --allow-updates

  # Root's own look at the clusters (pg_lsclusters), not the agent's.
  n="restart and updates on together"
  perm_rc "$n" 0 "updates: allowed" --allow-restart --allow-updates
  grep -qx "5432 postgresql@17-main.service" /etc/rowsafe/restart-allowed &&
    grep -qx "5433 postgresql@17-other.service" /etc/rowsafe/restart-allowed || fail "$n: $(cat /etc/rowsafe/restart-allowed)"
  cmp /usr/local/lib/rowsafe/rowsafe-pg-restart /src/scripts/rowsafe-pg-restart || fail "$n: no restart helper"
  grep -q '^postgresql ' "$U" || fail "$n: $(cat "$U")"

  # PgBouncer, and its public addresses.
  n="pooler with public addresses"
  perm_rc "$n" 0 "pooler-public: allowed" --allow-pooler --allow-pooler-public
  grep -qx 5432 /etc/rowsafe/pooler-allowed && grep -qx public /etc/rowsafe/pooler-allowed || fail "$n: $(cat /etc/rowsafe/pooler-allowed)"
  [ -e /etc/systemd/system/rowsafe-pooler.path ] || fail "$n: no pooler units"
  perm_rc "public addresses off, pooler stays" 0 "pooler-public: not allowed" --no-allow-pooler-public
  grep -qx 5432 /etc/rowsafe/pooler-allowed && ! grep -qx public /etc/rowsafe/pooler-allowed || fail "public kept: $(cat /etc/rowsafe/pooler-allowed)"
  perm_rc "public addresses need the pooler" 2 "pooler-public needs pooler" --allow-pooler-public --no-allow-pooler
  perm_rc "pooler off" 0 "pooler: not allowed" --no-allow-pooler
  [ ! -e /etc/systemd/system/rowsafe-pooler.path ] || fail "pooler units left"

  snapshot | cmp -s - "$W/snap.before" || {
    snapshot | diff "$W/snap.before" - >&2
    fail "--permissions changed the agent, its settings or its state"
  }
  pass "--permissions changes only the allow lists, helpers and units"

  # The installer run from elsewhere works the same, without the network.
  expect_ok "--permissions from another copy of the installer" env ROWSAFE_RELEASES_URL=https://127.0.0.1:9/agent sh "$W/install.sh" --permissions --allow-reboot --allow-security-updates
  grep -q '^reboot ' "$U" || fail "reboot not allowed: $(cat "$U")"

  # Not installed: refused, plainly.
  mv /etc/rowsafe/agent.env /etc/rowsafe/agent.env.away
  perm_rc "not installed" 2 "Rowsafe isn't installed on this server" --allow-restart
  mv /etc/rowsafe/agent.env.away /etc/rowsafe/agent.env

  # ---- rowsafe-allow
  expect_fail "rowsafe-allow needs root" "only root can see or change what Rowsafe may do" runuser -u tester -- "$A"
  expect_ok "rowsafe-allow --help without root" runuser -u tester -- "$A" --help
  grep -q "sudo rowsafe-allow --remove NAME" "$W/out" || fail "rowsafe-allow --help"
  ! grep -q -- "--add-owner" "$W/out" || fail "passkeys offered by an agent that can't pair them"
  expect_ok "rowsafe-allow lists" "$A"
  grep -q "allowed      reboot" "$W/out" && grep -q "What Rowsafe may do on" "$W/out" || fail "rowsafe-allow list: $(cat "$W/out")"
  ! grep -q "passkey" "$W/out" || fail "passkeys mentioned by an agent that can't pair them"
  expect_ok "rowsafe-allow --remove reboot" "$A" --remove reboot
  grep -q "reboot: not allowed" "$W/out" && ! grep -q '^reboot' "$U" || fail "rowsafe-allow --remove reboot: $(cat "$W/out")"
  expect_ok "rowsafe-allow reboot" "$A" reboot
  grep -q '^reboot ' "$U" || fail "rowsafe-allow reboot didn't allow it"
  expect_ok "rowsafe-allow pooler, --remove reboot in one go" "$A" pooler --remove reboot
  grep -qx 5432 /etc/rowsafe/pooler-allowed && ! grep -q '^reboot' "$U" || fail "rowsafe-allow pooler --remove reboot"
  expect_fail "rowsafe-allow refuses unknown names" "there is no permission called 'everything'" "$A" everything
  expect_fail "rowsafe-allow --remove needs a name" "needs a name, e.g. sudo rowsafe-allow --remove reboot" "$A" --remove
  expect_ok "rowsafe-allow --remove security-updates" "$A" --remove security-updates
  ! grep -q '^security' "$U" || fail "rowsafe-allow --remove security-updates kept them"
  expect_fail "rowsafe-allow: reboot needs security updates" "Allow them together: sudo rowsafe-allow security-updates reboot" "$A" reboot
  expect_fail "rowsafe-allow files needs a folder" "name the folder" "$A" files

  # Passkeys: only through root's copy of the agent (rowsafe-permissions),
  # when it can pair them.
  RP=/usr/local/lib/rowsafe/rowsafe-permissions
  expect_fail "passkeys need a newer agent" "too old for passkeys" "$A" --add-owner
  cp "$RP" "$W/root-agent.saved"
  cat >"$RP" <<'EOF'
#!/bin/sh
[ "$1" != --help ] || exit 0
echo "rowsafe-permissions $* as $(id -un)"
EOF
  expect_ok "rowsafe-allow --add-owner runs root's agent copy" "$A" --add-owner
  grep -q "rowsafe-permissions pair as root" "$W/out" || fail "--add-owner: $(cat "$W/out")"
  expect_ok "rowsafe-allow --owners" "$A" --owners
  grep -q "rowsafe-permissions owners as root" "$W/out" || fail "--owners: $(cat "$W/out")"
  expect_ok "rowsafe-allow --remove-owner" "$A" --remove-owner 3F2A-91C3-0B7E-55D4
  grep -q "rowsafe-permissions remove-owner 3F2A-91C3-0B7E-55D4 as root" "$W/out" || fail "--remove-owner: $(cat "$W/out")"
  expect_ok "rowsafe-allow --help offers passkeys" "$A" --help
  grep -q -- "--add-owner" "$W/out" || fail "no passkeys in --help"
  expect_fail "rowsafe-allow --remove-owner needs a fingerprint" "which passkey" "$A" --remove-owner
  cat >/etc/rowsafe/owners <<'EOF'
[
  {"credential_id": "Y3JlZC0x", "public_key": "pQECAyYgASFYIA", "alg": -7, "name": "ana@example.com",
   "fingerprint": "3F2A-91C3-0B7E-55D4", "rp_id": "app.rowsafe.sh", "origin": "https://app.rowsafe.sh",
   "added_at": "2026-10-01T10:00:00Z"},
  {"credential_id": "Y3JlZC0y", "public_key": "pQECAyYgASFYIB", "alg": -7, "name": "bo@example.com",
   "fingerprint": "0000-1111-2222-3333", "rp_id": "app.rowsafe.sh", "origin": "https://app.rowsafe.sh",
   "added_at": "2026-10-02T09:00:00Z"}
]
EOF
  chmod 644 /etc/rowsafe/owners
  expect_ok "rowsafe-allow lists the passkeys" "$A"
  grep -q "3F2A-91C3-0B7E-55D4  ana@example.com, added 2026-10-01" "$W/out" &&
    grep -q "0000-1111-2222-3333  bo@example.com, added 2026-10-02" "$W/out" || fail "passkeys not listed: $(cat "$W/out")"
  chmod 666 /etc/rowsafe/owners
  expect_ok "an owners file others can write isn't listed" "$A"
  ! grep -q "ana@example.com" "$W/out" || fail "listed passkeys from a file others can write"
  rm /etc/rowsafe/owners
  # Root never runs an agent binary that isn't root's.
  chown postgres "$RP"
  expect_fail "an agent copy root doesn't own is never run" "too old for passkeys" "$A" --owners
  cp "$W/root-agent.saved" "$RP"
  chown root:root "$RP"

  # Without a trusted installer copy, nothing runs.
  chown postgres "$P"
  expect_fail "an installer copy root doesn't own is never run" "Update it first" "$A" restart
  chown root:root "$P"
  pass "rowsafe-allow: list, on, off, refusals, passkey commands"
  expect_ok "back to the start" "$A" --remove pooler updates
}

# ------------------------------------------------------------ files

files_tests() {
  echo "  -- files (--files, --allow-files)"
  H=/usr/local/lib/rowsafe/rowsafe-pg-restart
  R=/var/lib/rowsafe/restart
  RB=/usr/local/lib/rowsafe/restic
  D=/etc/systemd/system/rowsafe-files-helper.service.d/folders.conf
  FU=/etc/systemd/system/rowsafe-files-helper.service
  FP=/etc/systemd/system/rowsafe-files-helper.path
  rv=$(sed -n 's/^RESTIC_VERSION=//p' /src/scripts/install.sh)
  secret_key=AKIAEXAMPLEKEY42 secret=s3cr3t/with+base64= cipher='cipher-pass-that-is-long-enough/+=='
  configured() {
    env ROWSAFE_REPO_S3_ENDPOINT=acct.eu.r2.cloudflarestorage.com ROWSAFE_REPO_S3_BUCKET=app-rowsafe \
      ROWSAFE_REPO_S3_KEY="$secret_key" ROWSAFE_REPO_S3_KEY_SECRET="$secret" ROWSAFE_REPO_CIPHER_PASS="$cipher" "$@"
  }
  shop_reg='5432\t/var/run/postgresql\t17\tmain\t/var/lib/postgresql/17/main\t1288490189\tshop\tyes\tactive\tshop\t1.2 GiB\tpostgresql@17-main.service\tdb_fake'
  command -v bzip2 >/dev/null || apt-get install -y -qq --no-install-recommends bzip2 >/dev/null

  # restic: a tampered download is refused and nothing is installed.
  mkdir -p "srv/restic-bad/v$rv"
  echo "not restic" | bzip2 >"srv/restic-bad/v$rv/restic_${rv}_linux_$arch.bz2"
  scenario
  expect_ok "a tampered restic is refused" configured env ROWSAFE_RELEASES_URL=https://localhost:18443/agent \
    ROWSAFE_RESTIC_URL=https://localhost:18443/restic-bad sh "$W/install.sh" rse_secrettoken123
  grep -q "does not match the SHA-256 of the official $rv release" "$W/out" || fail "tampered restic not reported"
  [ ! -e "$RB" ] || fail "a tampered restic was installed"
  if [ -f "srv/restic/v$rv/restic_${rv}_linux_$arch.bz2" ]; then
    expect_ok "restic installed from the pinned release" configured "$INSTALLER" rse_secrettoken123
    grep -q "restic $rv installed (official release, SHA-256 verified)" "$W/out" || fail "restic install not reported"
    [ "$(stat -c '%U %a' "$RB")" = "root 755" ] || fail "restic ownership/mode"
    "$RB" version | grep -q "^restic $rv " || fail "restic doesn't run"
    expect_ok "restic kept on a re-run" configured "$INSTALLER"
    grep -q "restic $rv (backs up the folders" "$W/out" || fail "restic reinstalled on a re-run"
  else
    echo "  skip restic from the release (not fetched on the host)"
    expect_ok "configured install" configured "$INSTALLER" rse_secrettoken123
  fi

  # The agent is enrolled and running; shop is registered.
  echo '{"host_id":"host_1","agent_token":"rsa_x"}' >/var/lib/rowsafe/agent.json
  chown postgres:postgres /var/lib/rowsafe/agent.json
  pkill -u postgres -f 'rowsafe-agent run' || true
  runuser -u postgres -- /opt/rowsafe/rowsafe-agent run >/dev/null 2>&1 &
  sleep 1
  getent passwd www-data >/dev/null || useradd --system www-data
  mkdir -p /srv/app/storage/cvs /srv/app/media /srv/other
  echo cv >/srv/app/storage/cvs/a.pdf
  chown -R www-data:www-data /srv/app /srv/other
  chmod 0750 /srv/app /srv/app/storage /srv/app/storage/cvs
  chmod 0700 /srv/other

  # --files PATH the agent can't read: root gives it read access (ACLs).
  scenario "discover_out=$shop_reg"
  printf 'no\n' >"$F/files-access.out"
  chmod 666 "$F"/*
  name="--files"
  expect_ok "--files grants read access and protects the folder" "$INSTALLER" --files /srv/app/storage --no-allow-restart
  [ -z "${TEST_SHOW:-}" ] || cat "$W/out"
  called "files add --database db_fake --path /srv/app/storage (postgres)"
  grep -q "gave the Rowsafe agent read access to /srv/app/storage" "$W/out" || fail "read access not reported"
  grep -q "/srv/app/storage is backed up with shop" "$W/out" || fail "protection not reported"
  grep -q "same passphrase restores them" "$W/out" || fail "no word on the files key"
  getfacl -p /srv/app/storage/cvs 2>/dev/null | grep -qx 'user:postgres:r-x' || fail "no ACL on the folder"
  getfacl -p /srv/app/storage/cvs 2>/dev/null | grep -qx 'default:user:postgres:r-x' || fail "no default ACL"
  getfacl -p /srv/app/storage/cvs/a.pdf 2>/dev/null | grep -qx 'user:postgres:r--' || fail "no ACL on a file"
  runuser -u postgres -- cat /srv/app/storage/cvs/a.pdf >/dev/null || fail "the agent user can't read the file"
  [ "$(stat -c '%U' /srv/app/storage/cvs/a.pdf)" = "www-data" ] || fail "ownership changed"
  # Without a terminal, putting restored files back (and PgBouncer) is
  # allowed by default.
  grep -q '^/srv/app/storage ' /etc/rowsafe/files-allowed || fail "--files: putting files back isn't allowed by default: $(cat /etc/rowsafe/files-allowed 2>&1)"
  grep -q '^[1-9]' /etc/rowsafe/pooler-allowed || fail "--files: PgBouncer isn't allowed by default"
  rm -f /etc/rowsafe/files-allowed /etc/rowsafe/pooler-allowed # never asked, for the questions below

  # Without a terminal and without --files, nothing about files is done.
  scenario "discover_out=$shop_reg"
  name="no terminal"
  expect_ok "no terminal, no --files: nothing about files" "$INSTALLER"
  not_called "files add"

  # On a terminal: the found folder is offered, then "put files back?",
  # which names exactly the folders it allows.
  scenario "discover_out=$shop_reg"
  printf '/srv/app/storage\n' >"$F/files-list.out"
  printf '/srv/app/storage\t2469606195\t1204\tno\t2.3 GiB\tLaravel storage (uploaded files)\n/srv/app/media\t10240\t3\tno\t10.0 KiB\tuploaded media\n' >"$F/files-discover.out"
  chmod 666 "$F"/*
  name="found folder"
  tty_ok "offer the found folder, allow putting files back" \
    "Install and manage PgBouncer (connection pooling)\tn\nso a restore brings back both? [Y/n]\t\nAllow Rowsafe to put restored files back into /srv/app/media, as the folder's owner?\ty\n" \
    "$INSTALLER"
  has "Rowsafe found /srv/app/media (10.0 KiB, 3 files: uploaded media)"
  lacks "Rowsafe found /srv/app/storage"
  called "files add --database db_fake --path /srv/app/media (postgres)"
  has "Rowsafe may put restored files back into /srv/app/media, as the folder's owner"
  WWW=$(id -u www-data)
  [ "$(grep -v '^#' /etc/rowsafe/files-allowed)" = "/srv/app/media $WWW" ] ||
    fail "files-allowed must list exactly the protected folder and its owner: $(cat /etc/rowsafe/files-allowed)"
  [ "$(stat -c '%U %a' /etc/rowsafe/files-allowed)" = "root 644" ] || fail "files-allowed ownership/mode"
  [ "$(grep -c '^ReadWritePaths=' "$D")" = 1 ] && grep -qx "ReadWritePaths=-/srv/app/media" "$D" && ! grep -q "ProtectHome" "$D" ||
    fail "files unit drop-in: $(cat "$D")"
  [ -x "$H" ] || fail "--allow-files didn't install the root helper"
  grep -q '^# actions: .*files-read files-put' "$H" || fail "helper lacks the files actions"
  # Files mode has its own unit and path unit; the restart helper's stay as
  # they are (nothing is added to them).
  grep -qx 'Environment=ROWSAFE_HELPER_MODE=files' "$FU" && grep -q 'CAP_FOWNER' "$FU" && grep -qx 'RestrictSUIDSGID=yes' "$FU" || fail "files unit"
  grep -qx 'PathExists=/var/lib/rowsafe/restart/files-request' "$FP" || fail "files path unit"
  [ ! -e /etc/systemd/system/rowsafe-pg-restart.service.d ] || fail "the restart unit got a drop-in"
  if [ "${TEST_UNITS:-0}" = 1 ] && command -v systemd-analyze >/dev/null; then
    expect_ok "systemd-analyze verify (files unit with its drop-in)" systemd-analyze verify "$FU" "$FP"
  fi

  # The helper's files mode, run as its service would.
  O=$W/files-helper-run
  ST=$W/files-helper-state
  install -d -m 0755 -o root -g root "$O"
  as_pg() { runuser -u postgres -- "$@"; }
  cat >"$W/fake-systemctl" <<'EOF'
#!/bin/sh
echo "$*" >>/tmp/rowsafe-files-systemctl.calls
EOF
  chmod 755 "$W/fake-systemctl"
  helper() { # MODE [ENV...]
    _mode=$1
    shift
    timeout 60 env ROWSAFE_HELPER_MODE="$_mode" ROWSAFE_SYSTEMCTL="$W/fake-systemctl" STATE_DIRECTORY="$ST" RUNTIME_DIRECTORY="$O" "$@" "$H" 2>>"$W/files-helper.log" ||
      fail "the helper failed or hung (exit $?)"
  }
  request() { # LINE: cooldowns cleared unless KEEP_COOLDOWN=1
    rm -f "$O/files-result"
    [ "${KEEP_COOLDOWN:-0}" = 1 ] || rm -f "$ST"/last-*
    printf '%s\n' "$1" | as_pg sh -c 'cat >"$1"' sh "$R/files-request"
    helper files
    [ ! -e "$R/files-request" ] || fail "helper left the files request"
    [ -f "$O/files-result" ] || fail "no result"
  }
  result_has() { grep -qxF "$1" "$O/files-result" || {
    cat "$O/files-result" >&2
    fail "helper result lacks $1"
  }; }
  refused() { # LINE TEXT
    request "$1"
    result_has "ok=0"
    grep -q "^error=.*$2" "$O/files-result" || fail "$1: expected '$2', got: $(cat "$O/files-result")"
  }
  allow() { # the allow list, as root writes it
    printf '%s\n' "$@" >/etc/rowsafe/files-allowed
    chmod 644 /etc/rowsafe/files-allowed
  }
  getent passwd appsvc >/dev/null || useradd --system --home-dir /srv/appsvc --create-home --shell /usr/sbin/nologin appsvc
  getent passwd alice >/dev/null || useradd --uid 1500 --home-dir /srv/alice --create-home --shell /bin/bash alice
  install -d -o alice -g alice /srv/alice/uploads
  ln -sfn /etc /srv/link
  mkdir -p /srv/rootowned
  allow "/srv/app/media $WWW" "/srv/other $WWW" "/srv/link $WWW" "/srv/nope $WWW" "/srv/rootowned 0" \
    "/srv/alice 1500" "/srv/alice/uploads 1500" "/srv 0" "/srv/appsvc $(id -u appsvc)" "/srv/app/storage $WWW 1"

  request "f_1 files-read /srv/other"
  result_has "ok=1"
  getfacl -p /srv/other 2>/dev/null | grep -qx 'user:postgres:r-x' || fail "files-read gave no access"
  [ "$(stat -c '%U' /srv/other)" = "www-data" ] || fail "files-read changed ownership"
  # files-read keeps a folder's ACL mask: another named entry isn't widened.
  install -d -o www-data -g www-data -m 0750 /srv/other/masked
  setfacl -m u:appsvc:rwx,m::r-x /srv/other/masked
  request "f_1m files-read /srv/other"
  result_has "ok=1"
  getfacl -p /srv/other/masked 2>/dev/null | grep -qx 'mask::r-x' || fail "files-read widened the ACL mask: $(getfacl -p /srv/other/masked)"
  # A service account whose home is exactly the folder is fine.
  request "f_1s files-read /srv/appsvc"
  result_has "ok=1"
  for bad in "/etc/ssh|a system or database folder" "/srv/../etc|not a plain path" "/srv/link|goes through a symbolic link" \
    "/srv/nope|doesn't exist" "/var/lib/rowsafe/files-staging|a system or database folder" \
    "/srv/app/media/sub|is not a folder root allowed" "/var/www|is not a folder root allowed" "/opt|is not a folder root allowed" \
    "/srv/app/storage|is not a folder root allowed" "/srv/alice|is the home folder of alice" \
    "/srv/alice/uploads|is inside the home folder of alice" "/srv|contains the home folder of"; do
    refused "f_2 files-read ${bad%%|*}" "${bad#*|}"
  done
  # The owner recorded at install must still own the folder.
  chown 1234 /srv/other
  refused "f_2u files-read /srv/other" "belongs to uid 1234 now, not uid $WWW"
  chown www-data /srv/other
  for bad in "f_3 files-read relative/path" "f_3 files-read /srv/a b" "f_3 files-put all r1 /srv/app/media" \
    "f_3 files-put missing ../x /srv/app/media" "f_3 files-put missing r1" "f_3 files-read /srv;reboot" "f_3 restart 5432"; do
    request "$bad"
    result_has "error=malformed request"
  done

  # files-put: staged by the agent user, written as the folder's owner with
  # the owner's own group (not the folder's).
  S=/var/lib/rowsafe/files-staging/r1
  stage() { # fresh staged tree
    as_pg rm -rf "$S"
    as_pg mkdir -p "$S/tree/sub"
    printf 'restored\n' | as_pg sh -c 'cat >"$1"' sh "$S/tree/sub/new.txt"
    printf 'from the snapshot\n' | as_pg sh -c 'cat >"$1"' sh "$S/tree/kept.txt"
    as_pg chmod 0700 "$S/tree"
  }
  stage
  echo "current" >/srv/app/media/kept.txt
  echo "added since" >/srv/app/media/extra.txt
  chown www-data:www-data /srv/app/media/kept.txt /srv/app/media/extra.txt
  chgrp staff /srv/app/media
  chmod 0751 /srv/app/media
  install -d -m 0700 "$ST"
  mkdir -p "$ST/put.stale"
  request "f_4 files-put missing r1 /srv/app/media"
  result_has "ok=1"
  [ ! -e "$ST/put.stale" ] || fail "a stale private copy was left"
  [ "$(cat /srv/app/media/sub/new.txt)" = restored ] || fail "files-put missing: new file not there"
  [ "$(stat -c '%U %G' /srv/app/media/sub/new.txt)" = "www-data www-data" ] || fail "files-put didn't write as the owner with the owner's group: $(stat -c '%U %G' /srv/app/media/sub/new.txt)"
  [ "$(cat /srv/app/media/kept.txt)" = current ] || fail "files-put missing overwrote a file"
  [ "$(stat -c '%a' /srv/app/media)" = 751 ] || fail "files-put changed the folder's mode"
  # At most one files-put every 2 minutes.
  KEEP_COOLDOWN=1 request "f_5c files-put replace r1 /srv/app/media"
  result_has "error=files-put ran less than 2 minutes ago; try again later"
  request "f_5 files-put replace r1 /srv/app/media"
  result_has "ok=1"
  [ "$(cat /srv/app/media/kept.txt)" = "from the snapshot" ] || fail "files-put replace"
  # And one files-read every 10 minutes.
  request "f_5r files-read /srv/other"
  KEEP_COOLDOWN=1 request "f_5s files-read /srv/other"
  result_has "error=files-read ran less than 10 minutes ago; try again later"

  # A compromised agent controls the staged tree: anything but plain files
  # and folders, or anything bound for .ssh, .gnupg or .config/systemd, is
  # refused before anything is written.
  cp /etc/passwd "$W/passwd.before"
  stage
  as_pg sh -c "printf '#!/bin/sh\n' >$S/tree/suid.sh && chmod 4755 $S/tree/suid.sh"
  refused "f_10 files-put missing r1 /srv/app/media" "set-user-ID"
  [ ! -e /srv/app/media/suid.sh ] || fail "a staged setuid file was written"
  stage
  as_pg sh -c "chmod 2755 $S/tree/sub && printf x >$S/tree/sub/g.txt"
  refused "f_11 files-put missing r1 /srv/app/media" "set-user-ID or set-group-ID"
  stage
  as_pg ln -s /etc/passwd "$S/tree/passwd"
  refused "f_12 files-put replace r1 /srv/app/media" "symbolic link"
  [ ! -e /srv/app/media/passwd ] && [ ! -L /srv/app/media/passwd ] || fail "a staged symlink was written"
  stage
  as_pg ln "$S/tree/kept.txt" "$S/tree/hard.txt"
  refused "f_13 files-put missing r1 /srv/app/media" "hard link"
  stage
  as_pg mkfifo "$S/tree/fifo"
  refused "f_14 files-put missing r1 /srv/app/media" "device, FIFO or socket"
  for p in .ssh/authorized_keys sub/.gnupg/pubring.kbx .config/systemd/user/evil.service; do
    stage
    as_pg sh -c 'mkdir -p "$(dirname "$1")" && echo x >"$1"' sh "$S/tree/$p"
    refused "f_16 files-put missing r1 /srv/app/media" "goes where Rowsafe never writes"
    [ ! -e "/srv/app/media/$p" ] || fail "files-put wrote $p"
  done
  cmp -s /etc/passwd "$W/passwd.before" || fail "a refused files-put touched /etc/passwd"
  # The size cap (20 GB by default; root can lower it in the files unit).
  stage
  rm -f "$ST"/last-* "$O/files-result"
  printf 'f_17b files-put missing r1 /srv/app/media\n' | as_pg sh -c 'cat >"$1"' sh "$R/files-request"
  helper files ROWSAFE_FILES_MAX_BYTES=10
  grep -q '^error=the staged files are .* more than the 10 bytes' "$O/files-result" || fail "size cap: $(cat "$O/files-result")"
  # A folder inside that Rowsafe's own user owns or can write: refused.
  install -d -o postgres /srv/app/media/pgdir
  refused "f_18 files-put missing r1 /srv/app/media" "Rowsafe's own user can change /srv/app/media/pgdir"
  rmdir /srv/app/media/pgdir
  install -d -o www-data -m 0777 /srv/app/media/open
  refused "f_18 files-read /srv/app/media" "Rowsafe's own user can change /srv/app/media/open"
  rmdir /srv/app/media/open

  # Never through a symbolic link in the folder, whether the staged path is
  # a folder or only a file's parent.
  install -d -o www-data -g www-data /srv/outside
  ln -sfn /srv/outside /srv/app/media/linkdir
  chown -h www-data:www-data /srv/app/media/linkdir
  stage
  as_pg sh -c "mkdir $S/tree/linkdir && printf evil >$S/tree/linkdir/evil.txt"
  refused "f_15 files-put replace r1 /srv/app/media" "linkdir is a symbolic link"
  [ ! -e /srv/outside/evil.txt ] || fail "files-put wrote through a symlinked folder"

  # mirror deletes only files whose folder is really inside the folder, and
  # a delete list naming .ssh is refused as a whole.
  echo "keep" >/srv/outside/x.txt
  chown www-data:www-data /srv/outside/x.txt
  stage
  printf 'extra.txt\n.ssh/authorized_keys\n' | as_pg sh -c 'cat >"$1"' sh "$S/delete"
  refused "f_6s files-put mirror r1 /srv/app/media" "goes where Rowsafe never writes"
  [ -e /srv/app/media/extra.txt ] || fail "a refused mirror removed a file"
  for p in ../../../etc/passwd /etc/passwd; do
    printf 'extra.txt\n%s\n' "$p" | as_pg sh -c 'cat >"$1"' sh "$S/delete"
    refused "f_6p files-put mirror r1 /srv/app/media" "a path to remove leaves the folder"
  done
  printf 'extra.txt\nsub\nlinkdir/x.txt\n./linkdir/x.txt\n' | as_pg sh -c 'cat >"$1"' sh "$S/delete"
  request "f_6 files-put mirror r1 /srv/app/media"
  result_has "ok=1"
  [ ! -e /srv/app/media/extra.txt ] || fail "files-put mirror left a file added since"
  [ -d /srv/app/media/sub ] || fail "files-put mirror removed a folder"
  [ "$(cat /srv/outside/x.txt)" = keep ] || fail "files-put mirror deleted through a symlinked folder"
  cmp -s /etc/passwd "$W/passwd.before" || fail "files-put mirror touched /etc/passwd"
  request "f_7 files-put missing nothing /srv/app/media"
  result_has "error=nothing is staged for restore nothing"
  refused "f_8 files-put missing r1 /srv/rootowned" "belongs to root: Rowsafe won't write there as root"
  [ -z "$(find "$R" /var/lib/rowsafe/files-staging -user root)" ] || fail "root left files in the agent's directories"
  [ -z "$(find "$ST" -maxdepth 1 -name 'put.*')" ] || fail "the helper left its private copy behind"
  chmod 666 /etc/rowsafe/files-allowed
  refused "f_9 files-read /srv/other" "/etc/rowsafe/files-allowed is writable by others than root"
  chmod 644 /etc/rowsafe/files-allowed

  # The restart helper never answers a files request: that is the files
  # unit's job alone (and its rights stay out of the restart unit).
  rm -f "$O/files-result"
  printf 'fr_1 files-read /srv/other\n' | as_pg sh -c 'cat >"$1"' sh "$R/files-request"
  helper restart
  [ -e "$R/files-request" ] && [ ! -e "$O/files-result" ] || fail "restart mode answered a files request"
  as_pg rm -f "$R/files-request"
  pass "files helper: exact folders and owners, no home/system/.ssh, size cap, cooldowns, own unit, never through symlinks, never root"

  # The installer: --no-allow-files removes the files units; --allow-files
  # with no folder named allows nothing; --files PATH --allow-files allows
  # exactly that folder; a re-run with --files adds one to an earlier yes.
  scenario "discover_out=$shop_reg"
  printf 'no\n' >"$F/files-access.out"
  chmod 666 "$F"/*
  expect_ok "--no-allow-files" "$INSTALLER" --no-allow-files
  [ ! -e "$D" ] && [ ! -e "$FU" ] && [ ! -e "$FP" ] && [ ! -e "$H" ] || fail "--no-allow-files left the files helper"
  ! grep -q '^/' /etc/rowsafe/files-allowed || fail "--no-allow-files kept the allow list"
  expect_ok "--allow-files without a folder" "$INSTALLER" --allow-files
  grep -q "No folder to put restored files back into yet" "$W/out" || fail "--allow-files alone should allow nothing"
  [ ! -e "$FU" ] || fail "--allow-files alone installed the files helper"
  expect_ok "--files PATH --allow-files" "$INSTALLER" --files /srv/app/media --allow-files --allow-restart
  [ "$(grep -v '^#' /etc/rowsafe/files-allowed)" = "/srv/app/media $WWW" ] || fail "allow list: $(cat /etc/rowsafe/files-allowed)"
  ! grep -q CAP_FOWNER /etc/systemd/system/rowsafe-pg-restart.service || fail "the restart unit got the files rights"
  expect_ok "a re-run adds a folder named with --files" "$INSTALLER" --files /srv/other
  [ "$(grep -v '^#' /etc/rowsafe/files-allowed | sort | paste -sd, -)" = "/srv/app/media $WWW,/srv/other $WWW" ] || fail "allow list after a re-run: $(cat /etc/rowsafe/files-allowed)"
  grep -qx "ReadWritePaths=-/srv/other" "$D" || fail "drop-in after a re-run"
  expect_ok "--no-allow-files keeps the helper for restarts" "$INSTALLER" --no-allow-files
  [ -x "$H" ] && [ ! -e "$D" ] && [ ! -e "$FU" ] || fail "--no-allow-files removed the helper restarts still need"
  expect_ok "--files PATH --allow-files again" "$INSTALLER" --files /srv/app/media --allow-files
  expect_fail "--files only with an install" "only go with an install" "$INSTALLER" --uninstall --files /srv/app/media
  pkill -u postgres -f 'rowsafe-agent run' || true
  expect_ok "uninstall removes files access and restic" "$INSTALLER" --uninstall
  [ ! -e "$RB" ] && [ ! -e "$D" ] && [ ! -e "$FU" ] && [ ! -e "$FP" ] && [ ! -e /etc/rowsafe/files-allowed ] && [ ! -e "$H" ] || fail "uninstall left files pieces"
  expect_ok "purge" "$INSTALLER" --uninstall --purge
  userdel -r alice 2>/dev/null || true
  userdel -r appsvc 2>/dev/null || true
  pass "files: restic, --files, the question, --allow-files, --no-allow-files, uninstall"
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
  lacks "Install and manage PgBouncer (connection"
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
  # At most one install every 10 minutes (removing right after is fine).
  mv /usr/local/bin/pgbouncer "$W/pgbouncer.keep"
  rm -f /tmp/rowsafe-fake/apt.calls
  prequest "pb_c pooler-install"
  presult "ok=0"
  grep -q "^error=PgBouncer was installed less than 10 minutes ago" "$OP/result" || fail "no cooldown between installs"
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
  # Off right after the install: stopped, drop-in removed, and the package
  # Rowsafe installed purged (the cooldown is per action).
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

# clickhouse_host_tests: a server with ClickHouse only (after the MySQL
# one: no postgres or mysql user). The agent runs as its own user, rowsafe
# (a unit drop-in, after clickhouse-server.service); nothing is installed
# for backups (ClickHouse's own BACKUP), and a missing clickhouse program is
# explained (Proof needs it).
clickhouse_host_tests() {
  echo "  -- a ClickHouse server (no PostgreSQL)"
  userdel mysql 2>/dev/null || true
  rm -f /usr/sbin/mysqld
  printf '#!/bin/sh\necho "ClickHouse server version 26.8.15.10 (official build)."\n' >/usr/bin/clickhouse-server
  chmod 755 /usr/bin/clickhouse-server
  expect_ok "ClickHouse server: configured install" configured env ROWSAFE_ENROLL_TOKEN=rse_secrettoken123 "$INSTALLER" --no-setup
  grep -q "backups, Marks and weekly restore tests for" "$W/out" || fail "$name: installer doesn't speak of ClickHouse"
  ! grep -q "restore to any second" "$W/out" || fail "$name: promises restores to any second for ClickHouse"
  grep -q "Proof (the weekly restore test) and Rewind copies need it" "$W/out" || fail "$name: missing clickhouse program not explained"
  id -u rowsafe >/dev/null 2>&1 || fail "$name: no rowsafe user"
  d=/etc/systemd/system/rowsafe-agent.service.d/10-clickhouse.conf
  grep -qx 'User=rowsafe' "$d" && grep -qx 'After=clickhouse-server.service' "$d" || fail "$name: no drop-in running the agent as rowsafe"
  cmp /etc/systemd/system/rowsafe-agent.service /src/deploy/systemd/rowsafe-agent.service || fail "$name: the unit itself changed"
  [ "$(stat -c '%U %a' /etc/rowsafe/agent.env)" = "rowsafe 600" ] || fail "$name: agent.env ownership/mode"
  ln -sf clickhouse-server /usr/bin/clickhouse
  expect_ok "ClickHouse server: re-run with the clickhouse program" configured "$INSTALLER" --no-setup
  grep -q "ClickHouse program at /usr/bin/clickhouse" "$W/out" || fail "$name: clickhouse program not found"
  expect_ok "ClickHouse server: uninstall" "$INSTALLER" --uninstall
  [ ! -e "$d" ] || fail "uninstall left the drop-in"
  pass "ClickHouse server: agent as rowsafe after clickhouse-server.service, clickhouse program checked"
}

# ------------------------------------------------------------ Redis and Valkey

# redis_flow_tests: a Redis or Valkey server found by discover (engine
# column): Rowsafe's own ACL user comes before the plan, as the default user
# or with an administrator's login once; the server keeps it, or root adds
# its line (the password's hash) to the configuration file. Redis Cluster
# and old servers are refused before the plan. Nothing restarts.
redis_flow_tests() {
  echo "  -- Redis and Valkey"
  rd='6379\t-\t7\t-\t/var/lib/redis\t1048576\tcache\tno\t-\tdb0\t1.0 MiB\tredis-server.service\t-\tredis'
  # rdst LOGIN [CONFIG] [CLUSTER] [VERSION] [ENGINE] [RIGHTS]
  rdst() {
    printf 'port=6379\\nengine=%s\\nversion=%s\\nlogin=%s\\nuser=-\\nunit=redis-server.service\\nbinary=/usr/bin/redis-server\\nconfig=%s\\naclfile=-\\ndatadir=/var/lib/redis\\ndbfilename=dump.rdb\\ndocker=no\\ncluster=%s\\nrole=master\\nneeds_auth=no\\nrights=%s' \
      "${5:-redis}" "${4:-7.0.15}" "$1" "${2:--}" "${3:-no}" "${6:--}"
  }
  rdplan='Redis 7.0.15 on port 6379: 1.0 MiB, 1 database (db0).\n\nWhat Rowsafe will change:\n  - Prepare your bucket for this database\n\nNo downtime: Redis does not need a restart.'
  hash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  acl="user rowsafe on #$hash ~* resetchannels -@all +@read -keys +ping +config|get +acl|whoami"

  # 1. Rowsafe's login already works: straight to the plan, with the engine.
  scenario "discover_out=$rd" "redis-status_out=$(rdst ok)" "plan_out=$rdplan" "wait_out=$done_" "status_out=$status"
  tty_ok "Redis with Rowsafe's login: plan, turn on" "Name it in Rowsafe\t\nTurn on backups for cache now?\t\n" "$INSTALLER"
  has "Found Redis 7 on port 6379 (1.0 MiB; databases: db0)"
  has "No downtime: Redis does not need a restart."
  called "redis-status --port 6379 --engine redis"
  called "plan --name cache --port 6379 --id-file"
  called "--engine redis"
  not_called "socket-dir -"
  not_called "redis-login"
  called "apply --database db_fake"

  # 2. No login yet, the default user has no password: Rowsafe's user is
  #    made as default and Redis keeps it itself; a snapshot file the agent
  #    can't read is only mentioned.
  install -d -m 0700 -o root -g root /var/lib/redis
  echo REDIS0011 >/var/lib/redis/dump.rdb
  chmod 600 /var/lib/redis/dump.rdb
  scenario "discover_out=$rd" "redis-status_out=$(rdst missing /etc/redis/redis.conf)" "redis-login_out=persisted=config\nacl_line=$acl" "plan_out=$rdplan"
  tty_ok "Redis login as the default user" "Name it in Rowsafe\t\nTurn on backups for cache now?\tn\n" "$INSTALLER"
  has "Rowsafe needs its own Redis user, rowsafe"
  has "Rowsafe's own Redis user, rowsafe, is ready (Redis keeps it in its configuration file)"
  has "Rowsafe can't read Redis's snapshot file (/var/lib/redis/dump.rdb)"
  called "redis-login --port 6379 --engine redis"
  not_called "admin-user"
  lacks "$hash"
  called "plan --name cache --port 6379"
  rm -rf /var/lib/redis

  # 2b. The log in Debian's folder (redis:adm, 2750, the file 640): the
  #     agent's user gets an access rule to read it (the folder's default
  #     for the files after a rotation too); owners and modes stay.
  ruser=''
  id -u redis >/dev/null 2>&1 || { useradd --system --no-create-home redis && ruser=1; }
  getent group adm >/dev/null || groupadd --system adm
  install -d -m 2750 -o redis -g adm /var/log/redis
  echo '1:M 04 Oct 2026 00:48:28.601 * Ready to accept connections tcp' >/var/log/redis/redis-server.log
  chown redis:adm /var/log/redis/redis-server.log && chmod 640 /var/log/redis/redis-server.log
  scenario "discover_out=$rd" "redis-status_out=$(rdst ok)\nlogfile=/var/log/redis/redis-server.log" "plan_out=$rdplan"
  tty_ok "Redis: its log made readable to the agent" "Name it in Rowsafe\t\nTurn on backups for cache now?\tn\n" "$INSTALLER"
  has "gave the Rowsafe agent read access to /var/log/redis (Redis's own log, for the Logs page; read-only, with an ACL; nothing else changed)"
  [ "$(stat -c '%U %G %a' /var/log/redis/redis-server.log)" = "redis adm 640" ] || fail "$name: the log's owner or mode changed"
  getfacl -p /var/log/redis 2>/dev/null | grep -qx 'default:user:postgres:r--' || fail "$name: no default ACL: $(getfacl -p /var/log/redis)"
  setpriv --reuid=postgres --regid=postgres --init-groups -- cat /var/log/redis/redis-server.log >/dev/null || fail "$name: the agent can't read the log"
  # A log straight in /var/log (root's folder) is only mentioned.
  mv /var/log/redis/redis-server.log /var/log/redis-test.log && setfacl -b /var/log/redis-test.log
  scenario "discover_out=$rd" "redis-status_out=$(rdst ok)\nlogfile=/var/log/redis-test.log" "plan_out=$rdplan"
  tty_ok "Redis: a log in a shared folder is left alone" "Name it in Rowsafe\t\nTurn on backups for cache now?\tn\n" "$INSTALLER"
  has "Rowsafe can't read Redis's log (/var/log/redis-test.log)"
  ! getfacl -p -s /var/log 2>/dev/null | grep -q postgres || fail "$name: an ACL on /var/log"
  rm -rf /var/log/redis /var/log/redis-test.log
  [ -z "$ruser" ] || userdel redis

  # 3. Redis couldn't keep it (it can't write its configuration file):
  #    root replaces the earlier "user rowsafe" line, keeping owner and mode.
  rgrp=''
  getent group redis >/dev/null || { groupadd --system redis && rgrp=1; }
  mkdir -p /etc/redis
  printf 'bind 127.0.0.1 -::1\nport 6379\nuser rowsafe on #%s ~* +@read\ndir /var/lib/redis\n' "$(echo "$hash" | tr 0-9 9876543210)" >/etc/redis/redis.conf
  chown root:redis /etc/redis/redis.conf
  chmod 640 /etc/redis/redis.conf
  scenario "discover_out=$rd" "redis-status_out=$(rdst missing /etc/redis/redis.conf)" \
    "redis-login_out=persisted=none\nwhy=the server can't write its configuration file /etc/redis/redis.conf (ERR Rewriting config file: Permission denied)\nacl_line=$acl" \
    "plan_out=$rdplan"
  tty_ok "Redis login kept in its configuration file by root" "Name it in Rowsafe\t\nTurn on backups for cache now?\tn\n" "$INSTALLER"
  has "added it to /etc/redis/redis.conf, so Redis keeps it when it restarts"
  lacks "forgets Rowsafe's user"
  lacks "$hash"
  f=/etc/redis/redis.conf
  [ "$(stat -c '%U %G %a' "$f")" = "root redis 640" ] || fail "$name: $f owner or mode changed"
  [ "$(grep -c '^user rowsafe ' "$f")" = 1 ] && grep -qxF "$acl" "$f" || fail "$name: $f lacks the new line once: $(cat "$f")"
  grep -qx 'port 6379' "$f" && grep -qx 'dir /var/lib/redis' "$f" || fail "$name: $f lost its settings"
  # A malformed line from the agent is never written.
  scenario "discover_out=$rd" "redis-status_out=$(rdst missing /etc/redis/redis.conf)" \
    "redis-login_out=persisted=none\nacl_line=user rowsafe on nopass ~* +@all" "plan_out=$rdplan"
  tty_ok "Redis: a malformed user line is refused" "Name it in Rowsafe\t\nTurn on backups for cache now?\tn\n" "$INSTALLER"
  grep -qxF "$acl" "$f" && ! grep -q nopass "$f" || fail "$name: $f changed: $(cat "$f")"
  has "Redis forgets Rowsafe's user when it restarts"
  rm -rf /etc/redis
  [ -z "$rgrp" ] || groupdel redis

  # 4. No configuration file at all: said plainly, with how to keep it.
  scenario "discover_out=$rd" "redis-status_out=$(rdst missing)" \
    "redis-login_out=persisted=none\nwhy=the server runs without an ACL file or a configuration file\nacl_line=$acl" "plan_out=$rdplan"
  tty_ok "Redis without a configuration file" "Name it in Rowsafe\t\nTurn on backups for cache now?\tn\n" "$INSTALLER"
  has "Redis forgets Rowsafe's user when it restarts (the server runs without an ACL file or a configuration file)"
  has "give Redis an ACL file"
  called "plan --name cache --port 6379"

  # 5. A password on the default user (11): an administrator signs in once;
  #    a refused login (12) asks again. The password goes to the agent on
  #    stdin and is never printed or saved.
  scenario "discover_out=$rd" "redis-status_out=$(rdst missing /etc/redis/redis.conf)" "redis-login_rc=11\n12\n0" \
    "redis-login_out=persisted=config\nacl_line=$acl" "plan_out=$rdplan"
  tty_ok "Redis login with an administrator" \
    "Name it in Rowsafe\t\nRedis administrator user [default]\t\nPassword for default\twrong\nRedis administrator user [default]\t\nPassword for default\tR3dis-S3cret\nTurn on backups for cache now?\tn\n" "$INSTALLER"
  has "Redis asks for a password."
  has "Redis refused that login."
  called "redis-login --port 6379 --engine redis --admin-user default"
  [ "$(cat "$F/redis-login.stdin")" = R3dis-S3cret ] || fail "$name: the administrator's password didn't reach the agent on stdin"
  lacks "R3dis-S3cret"
  ! grep -rq "R3dis-S3cret" /etc/rowsafe /var/lib/rowsafe 2>/dev/null || fail "$name: the administrator's password was saved"
  called "plan --name cache --port 6379"

  # 6. Redis Cluster and old servers: refused in one sentence, before the plan.
  scenario "discover_out=$rd" "redis-status_out=$(rdst ok - yes)"
  tty_ok "Redis Cluster refused" "Name it in Rowsafe\t\n" "$INSTALLER"
  has "runs in cluster mode (Redis Cluster), which Rowsafe doesn't protect yet"
  has "Backups for cache are not on yet."
  not_called "plan"
  scenario "discover_out=$rd" "redis-status_out=$(rdst missing - no 6.0.16)"
  tty_ok "Redis 6.0 refused" "Name it in Rowsafe\t\n" "$INSTALLER"
  has "Redis 6.0.16 is too old: Rowsafe needs Redis 7.0 or newer"
  has "packages.redis.io"
  not_called "redis-login"
  not_called "plan"

  # 7. Valkey: its own name and engine.
  vk='6380\t-\t8\t-\t/var/lib/valkey\t1048576\tqueue\tno\t-\tdb0\t1.0 MiB\tvalkey-server.service\t-\tvalkey'
  scenario "discover_out=$vk" "redis-status_out=$(rdst missing - no 8.1.1 valkey)" "redis-login_out=persisted=aclfile\nacl_line=$acl" \
    "plan_out=Valkey 8.1.1 on port 6380: 1.0 MiB, 1 database (db0)."
  tty_ok "Valkey: login kept in its ACL file" "Name it in Rowsafe\t\nTurn on backups for queue now?\tn\n" "$INSTALLER"
  has "Found Valkey 8 on port 6380 (1.0 MiB; databases: db0)"
  has "Rowsafe's own Valkey user, rowsafe, is ready (Valkey keeps it in its ACL file)"
  called "redis-login --port 6380 --engine valkey"
  called "--engine valkey"

  # 8. --protect: without a way to create the user it stops before the
  #    plan; ROWSAFE_REDIS_ADMIN_* (no terminal) are used once.
  scenario "discover_out=$rd" "redis-status_out=$(rdst missing)" redis-login_rc=11
  expect_fail "--protect: Redis without a login" "ROWSAFE_REDIS_ADMIN_USER" "$INSTALLER" --protect cache
  grep -q "isn't ready for backups" "$W/out" || fail "$name: not explained"
  not_called "plan"
  scenario "discover_out=$rd" "redis-status_out=$(rdst missing /etc/redis/redis.conf)" "redis-login_rc=11\n0" \
    "redis-login_out=persisted=config\nacl_line=$acl" "plan_out=$rdplan" "wait_out=$done_"
  expect_ok "--protect: Redis administrator from the environment" \
    env ROWSAFE_REDIS_ADMIN_USER=default ROWSAFE_REDIS_ADMIN_PASSWORD=Env-R3dis "$INSTALLER" --protect cache
  called "redis-login --port 6379 --engine redis --admin-user default"
  [ "$(cat "$F/redis-login.stdin")" = Env-R3dis ] || fail "$name: the administrator's password didn't reach the agent on stdin"
  ! grep -q "Env-R3dis" "$W/out" || fail "$name: the administrator's password was printed"
  ! grep -q "ROWSAFE_REDIS_ADMIN" /etc/rowsafe/agent.env || fail "$name: the administrator's login went to agent.env"
  called "apply --database db_fake"

  # 9. An already protected server whose login predates Databases & users
  #    (rights=old): the login is made again for the new rights; with them,
  #    nothing is asked.
  rdon='6379\t-\t7\t-\t/var/lib/redis\t1048576\tcache\tyes\tactive\tdb0\t1.0 MiB\tredis-server.service\tdb_fake\tredis'
  scenario "discover_out=$rdon" "redis-status_out=$(rdst ok /etc/redis/redis.conf no 7.0.15 redis old)" "redis-login_out=persisted=config\nacl_line=$acl"
  tty_ok "Redis: an old login gets the rights to manage users" "" "$INSTALLER"
  has "is protected as cache"
  has "needs a few more rights to manage Redis users"
  called "redis-login --port 6379 --engine redis"
  not_called "plan"
  scenario "discover_out=$rdon" "redis-status_out=$(rdst ok /etc/redis/redis.conf no 7.0.15 redis ok)"
  tty_ok "Redis: a login with the rights is left alone" "" "$INSTALLER"
  not_called "redis-login"
  pass "Redis and Valkey: engine in the plan, ACL user kept across restarts, administrator login once, Cluster and old servers refused, --protect, rights refreshed"
}

# redis_restart_tests: Redis and Valkey units (redis-server, redis,
# valkey-server, valkey and their @instance forms) go in the restart allow
# list from the agent's discovery, and the helper restarts, stops and starts
# them; another unit in the list is never touched.
redis_restart_tests() {
  echo "  -- restarts of Redis and Valkey"
  rH=/usr/local/lib/rowsafe/rowsafe-pg-restart
  rR=/var/lib/rowsafe/restart
  scenario "discover_out=$shop\n6379\t-\t7\t-\t/var/lib/redis\t1048576\tcache\tno\t-\tdb0\t1.0 MiB\tredis-server.service\t-\tredis\n6380\t-\t8\t-\t/var/lib/valkey\t1048576\tqueue\tno\t-\tdb0\t1.0 MiB\tvalkey-server@queue.service\t-\tvalkey\n6381\t-\t7\t-\t/var/lib/redis\t8\tother\tno\t-\tdb0\t8 B\tsshd.service\t-\tredis"
  expect_ok "--allow-restart with Redis and Valkey" "$INSTALLER" --allow-restart
  a=/etc/rowsafe/restart-allowed
  grep -qx "6379 redis-server.service" "$a" && grep -qx "6380 valkey-server@queue.service" "$a" || fail "$name: allow list: $(cat "$a")"
  ! grep -q "sshd" "$a" || fail "$name: a unit that isn't a database's was allowed"
  echo "6381 sshd.service" >>"$a"
  printf '#!/bin/sh\necho "$*" >>/tmp/rowsafe-fake/systemctl.calls\n' >"$F/systemctl"
  chmod 755 "$F/systemctl"
  : >"$F/systemctl.calls"
  rO=$W/redis-helper-run
  install -d -m 0755 -o root -g root "$rO"
  rd_request() {
    rm -f "$rO/result"
    printf '%s\n' "$1" | runuser -u postgres -- sh -c 'cat >"$1"' sh "$rR/request"
    timeout 30 env ROWSAFE_SYSTEMCTL="$F/systemctl" STATE_DIRECTORY="$W/redis-helper-state" RUNTIME_DIRECTORY="$rO" "$rH" 2>>"$W/helper.log" ||
      fail "the helper failed or hung (exit $?)"
    [ -f "$rO/result" ] || fail "no result for: $1"
  }
  rd_has() { grep -qxF "$1" "$rO/result" || {
    cat "$rO/result" >&2
    fail "helper result lacks $1"
  }; }
  rd_request "rd_1 restart 6379"
  rd_has "ok=1"
  rd_has "unit=redis-server.service"
  rd_request "rd_2 stop 6380"
  rd_has "ok=1"
  rd_has "unit=valkey-server@queue.service"
  rd_request "rd_2 start 6380"
  rd_has "ok=1"
  rd_request "rd_3 restart 6381"
  rd_has "ok=0"
  grep -q "^error=port 6381 is not in /etc/rowsafe/restart-allowed" "$rO/result" || fail "a unit that isn't a database's was restarted"
  [ "$(cat "$F/systemctl.calls")" = "$(printf 'restart redis-server.service\nstop valkey-server@queue.service\nstart valkey-server@queue.service')" ] ||
    fail "helper ran: $(cat "$F/systemctl.calls")"
  pass "Redis and Valkey units: allow list from discovery, restart, stop and start through the helper"
}

# redis_host_tests: a server with Redis or Valkey only, from the system's
# own package: the agent runs as its own user, rowsafe (a unit drop-in,
# after the server's unit, in the server's group to read its snapshot file);
# nothing is installed for backups; the server program is checked (Proof
# needs it). Ubuntu 22.04's Redis 6.0 is refused before anything changes.
redis_host_tests() {
  echo "  -- a Redis or Valkey server (no PostgreSQL)"
  pkill -f 'rowsafe-agent run' 2>/dev/null || true
  "$INSTALLER" --uninstall --purge >/dev/null 2>&1 || true
  ! id -u postgres >/dev/null 2>&1 || userdel postgres
  ! id -u mysql >/dev/null 2>&1 || userdel mysql
  rm -rf /usr/lib/postgresql /var/lib/postgresql /usr/sbin/mysqld /usr/bin/clickhouse-server /usr/bin/clickhouse
  # pgBackRest stays after an uninstall; a Redis server mustn't get it again.
  apt-get purge -y -qq pgbackrest >/dev/null 2>&1 || true
  # shellcheck disable=SC1091
  os=$(. /etc/os-release && echo "$ID $VERSION_ID")
  case $os in
    "debian 13") pkg=valkey-server eng=Valkey ;;
    *) pkg=redis-server eng=Redis ;;
  esac
  # The package's server isn't started in the container.
  printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d
  chmod 755 /usr/sbin/policy-rc.d
  apt-get install -y -qq --no-install-recommends "$pkg" >/dev/null 2>&1 || fail "could not install $pkg"
  rm -f /usr/sbin/policy-rc.d
  ver=$("$pkg" --version | sed -n 's/.* v=\([0-9.]*\).*/\1/p')
  echo "  $pkg $ver"
  if [ "$os" = "ubuntu 22.04" ]; then
    rm -rf /etc/rowsafe /opt/rowsafe
    ! id -u rowsafe >/dev/null 2>&1 || userdel rowsafe
    expect_fail "Redis $ver refused before anything changes" "Redis $ver is too old: Rowsafe needs Redis 7.0 or newer" \
      configured env ROWSAFE_ENROLL_TOKEN=rse_secrettoken123 "$INSTALLER" --no-setup
    grep -q "packages.redis.io" "$W/out" && grep -q "Nothing was changed on this server." "$W/out" || fail "$name: not explained"
    [ ! -e /etc/rowsafe ] && [ ! -e /opt/rowsafe ] && ! id -u rowsafe >/dev/null 2>&1 || fail "$name: something changed"
    pass "Redis 6.0 (Ubuntu 22.04's own): refused in one sentence, nothing changed"
    return 0
  fi
  pgb_before=$(command -v pgbackrest || true) # earlier PostgreSQL sections installed it in this container
  expect_ok "$eng server: configured install" configured env ROWSAFE_ENROLL_TOKEN=rse_secrettoken123 "$INSTALLER" --no-setup
  [ -z "${TEST_SHOW:-}" ] || cat "$W/out"
  grep -q "restore tests for the $eng on this server" "$W/out" || fail "$name: installer doesn't speak of $eng"
  grep -q "$eng program at /usr/bin/$pkg ($ver; Proof and Rewind copies use it)" "$W/out" || fail "$name: server program not found"
  grep -q "backups      $eng's own replication stream, encrypted by the agent" "$W/out" || fail "$name: summary"
  id -u rowsafe >/dev/null 2>&1 || fail "$name: no rowsafe user"
  d=/etc/systemd/system/rowsafe-agent.service.d/10-redis.conf
  grep -qx 'User=rowsafe' "$d" && grep -q '^After=.*redis-server.service' "$d" && grep -q '^After=.*valkey-server.service' "$d" ||
    fail "$name: no drop-in running the agent as rowsafe: $(cat "$d")"
  g=$(getent group redis valkey | head -n 1 | cut -d: -f1)
  [ -n "$g" ] && grep -qx "SupplementaryGroups=$g" "$d" || fail "$name: the agent isn't in the server's group ($g): $(cat "$d")"
  grep -q "this server runs $eng" "$d" || fail "$name: drop-in doesn't name $eng"
  cmp /etc/systemd/system/rowsafe-agent.service /src/deploy/systemd/rowsafe-agent.service || fail "$name: the unit itself changed"
  [ "$(stat -c '%U %a' /etc/rowsafe/agent.env)" = "rowsafe 600" ] || fail "$name: agent.env ownership/mode"
  [ -n "$pgb_before" ] || ! command -v pgbackrest >/dev/null || fail "$name: pgBackRest installed for $eng"
  ! grep -qi "installing pgbackrest" "$W/out" || fail "$name: the installer set up pgBackRest for $eng"
  expect_ok "$eng server: re-run is idempotent" configured "$INSTALLER" --no-setup
  expect_ok "$eng server: uninstall --purge" "$INSTALLER" --uninstall --purge
  [ ! -e "$d" ] || fail "$name: uninstall left the drop-in"
  grep -q "ACL DELUSER rowsafe" "$W/out" || fail "$name: how to remove Rowsafe's user isn't said"
  pass "$eng $ver server: agent as rowsafe in the $g group after its unit, server program checked, uninstall"
}

# meilisearch_only_tests (TEST_ONLY=meilisearch): a server that runs a
# Meilisearch of its own (the real program, the pinned release, started here
# as its own user from a configuration file, without systemd): the installer
# runs the agent as rowsafe, finds the instance's program, folders, address
# and master key from its process, hands the master key to the agent once on
# stdin (never printed, never kept), and lets the agent read the snapshot
# folder through an ACL (owners and modes unchanged).
meilisearch_only_tests() {
  echo "  -- a Meilisearch running here (adopt)"
  # (No iproute2 here: the installer installs it to see which process listens where.)
  apt-get purge -y -qq iproute2 >/dev/null 2>&1 || true
  ! command -v ss >/dev/null 2>&1 || fail "ss is still here"
  mver=$(sed -n 's/^MEILI_VERSION=//p' "$W/install.sh")
  asset=meilisearch-linux-$arch
  [ "$arch" = amd64 ] || asset=meilisearch-linux-aarch64
  [ -f "/go-release/meilisearch/v$mver/$asset" ] || fail "no Meilisearch release for the test (host side)"
  install -d -m 0755 /opt/meili
  install -m 0755 "/go-release/meilisearch/v$mver/$asset" /opt/meili/meilisearch
  useradd --system --home-dir /srv/meili --create-home --shell /usr/sbin/nologin meili
  chmod 0700 /srv/meili
  mk=adopt-test-master-key-0123456789abcdef
  printf 'db_path = "/srv/meili/data.ms"\nsnapshot_dir = "/srv/meili/snapshots"\nhttp_addr = "127.0.0.1:7700"\nmaster_key = "%s"\nenv = "production"\n' "$mk" >/etc/meilisearch.toml
  chown root:meili /etc/meilisearch.toml && chmod 0640 /etc/meilisearch.toml
  (cd /srv/meili && runuser -u meili -- /opt/meili/meilisearch --config-file-path /etc/meilisearch.toml >/srv/meili/log 2>&1 &)
  i=0
  until curl -fs http://127.0.0.1:7700/health >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || { cat /srv/meili/log >&2; fail "Meilisearch didn't start"; }
    sleep 1
  done
  [ ! -e /srv/meili/snapshots ] || fail "the snapshot folder exists before Rowsafe asks"
  configured() {
    env ROWSAFE_REPO_S3_ENDPOINT=acct.eu.r2.cloudflarestorage.com ROWSAFE_REPO_S3_BUCKET=app-rowsafe \
      ROWSAFE_REPO_S3_KEY=AKIAEXAMPLEKEY42 ROWSAFE_REPO_S3_KEY_SECRET=s3cr3t/with+base64= \
      ROWSAFE_REPO_CIPHER_PASS='cipher-pass-that-is-long-enough/+==' "$@"
  }
  echo rowsafe >/tmp/rowsafe-fake-user
  scenario
  expect_ok "Meilisearch server: configured install" configured env ROWSAFE_ENROLL_TOKEN=rse_secrettoken123 "$INSTALLER" --no-setup
  [ -z "${TEST_SHOW:-}" ] || cat "$W/out"
  grep -q "hourly snapshots, Marks and weekly restore tests" "$W/out" && grep -q "for the Meilisearch on this server" "$W/out" ||
    fail "$name: the installer doesn't speak of Meilisearch's snapshots"
  grep -q "backups      Meilisearch's own snapshots, encrypted by the agent" "$W/out" || fail "$name: summary"
  ! command -v pgbackrest >/dev/null 2>&1 || fail "$name: pgBackRest installed for Meilisearch"
  [ "$(stat -c '%U %a' /etc/rowsafe/agent.env)" = "rowsafe 600" ] || fail "$name: the agent doesn't run as rowsafe"
  d=/etc/systemd/system/rowsafe-agent.service.d/10-meilisearch.conf
  grep -qx 'User=rowsafe' "$d" && grep -qx 'After=meilisearch.service' "$d" || { cat "$d" >&2; fail "$name: the agent's drop-in"; }
  curl -fs http://127.0.0.1:7700/health >/dev/null 2>&1 || { tail -n 20 /srv/meili/log >&2; fail "$name: Meilisearch stopped during the install"; }
  pass "a Meilisearch server: the agent as rowsafe after meilisearch.service, no pgBackRest"

  # The agent "runs" (stand-in): protect it unattended.
  echo '{"host_id":"host_1","agent_token":"rsa_x"}' >/var/lib/rowsafe/agent.json
  chown rowsafe:rowsafe /var/lib/rowsafe/agent.json
  runuser -u rowsafe -- /opt/rowsafe/rowsafe-agent run >/dev/null 2>&1 &
  sleep 1
  line='7700\t-\t1\t-\t/srv/meili/data.ms\t65536\tsearch\tno\t-\t-\t64 KiB\t-\t-\tmeilisearch'
  scenario "discover_out=$line" "meilisearch-status_out=answers=yes\ntls=no\nversion=$mver\nlogin=missing" \
    "meilisearch-login_out=version=$mver\ntls=no\nkey_uid=0f0e\nno_auth=no" \
    "plan_out=Backups for search: Meilisearch's own snapshots, every hour." \
    "wait_out=✓ search is protected. The first full backup is running." "status_out=db_fake\tsearch\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake"
  curl -fs http://127.0.0.1:7700/health >/dev/null 2>&1 || { tail -n 20 /srv/meili/log >&2; fail "Meilisearch stopped before --protect"; }
  if ! "$INSTALLER" --protect search >"$W/out" 2>&1; then
    cat "$W/out" >&2
    echo "--- debug: ss, processes, fake calls" >&2
    ss -ltnp >&2 2>&1 || true
    ps -eo pid,user,comm,args | grep -i meili >&2 || true
    cat "$F/calls" >&2 2>/dev/null || true
    fail "protected unattended (--protect search)"
  fi
  pass "protected unattended (--protect search)"
  [ -z "${TEST_SHOW:-}" ] || cat "$W/out"
  called "meilisearch-login --port 7700 --binary /opt/meili/meilisearch --db-path /srv/meili/data.ms --snapshot-dir /srv/meili/snapshots --listen 127.0.0.1 --analytics yes"
  [ "$(cat "$F/meilisearch-login.stdin")" = "$mk" ] || fail "$name: the agent didn't get the master key (from the configuration file) on stdin"
  ! grep -qF "$mk" "$W/out" || fail "$name: the master key was printed"
  ! grep -rqsF "$mk" /etc/rowsafe /var/lib/rowsafe /etc/systemd/system || fail "$name: the master key is in Rowsafe's files"
  grep -q "Meilisearch sends anonymous usage data to its makers" "$W/out" || fail "$name: analytics on isn't said"
  called "plan --name search --port 7700"
  called "--engine meilisearch"
  [ "$(stat -c '%U %a' /srv/meili/snapshots)" = "meili 755" ] || [ "$(stat -c '%U' /srv/meili/snapshots)" = meili ] || fail "$name: the snapshot folder isn't Meilisearch's"
  setpriv --reuid=rowsafe --regid=rowsafe --clear-groups test -r /srv/meili/snapshots -a -x /srv/meili/snapshots || fail "$name: the agent can't read the snapshot folder"
  [ "$(stat -c '%U %G' /srv/meili)" = "meili meili" ] && getfacl -p /srv/meili 2>/dev/null | grep -qx 'group::---' &&
    getfacl -p /srv/meili 2>/dev/null | grep -qx 'other::---' || fail "$name: Meilisearch's folder's owner or access changed"
  # (Passing through /srv/meili, the agent also sees what Meilisearch leaves
  # readable to everyone there; its API key reads the documents anyway.)
  # A snapshot Meilisearch writes there is readable by the agent.
  curl -fs -X POST -H "Authorization: Bearer $mk" http://127.0.0.1:7700/snapshots >/dev/null
  i=0
  until [ -s /srv/meili/snapshots/data.ms.snapshot ] || [ "$i" -ge 30 ]; do sleep 1; i=$((i + 1)); done
  setpriv --reuid=rowsafe --regid=rowsafe --clear-groups test -r /srv/meili/snapshots/data.ms.snapshot || fail "$name: the agent can't read the snapshot"
  pass "Meilisearch adopted: the master key from its configuration, given to the agent once on stdin, never printed or kept; snapshots readable through an ACL"

  # No master key found and no terminal: refused with what to set.
  pkill -f '/opt/meili/meilisearch' || true
  sleep 1
  sed -i '/^master_key/d' /etc/meilisearch.toml
  printf 'master_key = "%s"\n' "$mk" >/srv/meili/other.toml
  (cd /srv/meili && runuser -u meili -- env MEILI_MASTER_KEY="$mk" /opt/meili/meilisearch --config-file-path /etc/meilisearch.toml >/srv/meili/log 2>&1 &)
  i=0
  until curl -fs http://127.0.0.1:7700/health >/dev/null 2>&1; do i=$((i + 1)); [ "$i" -lt 60 ] || fail "Meilisearch didn't start again"; sleep 1; done
  scenario "discover_out=$line" "meilisearch-status_out=answers=yes\ntls=no\nversion=$mver\nlogin=missing" \
    "meilisearch-login_out=version=$mver\ntls=no\nkey_uid=0f0f\nno_auth=no" "plan_rc=5" "plan_out=search is already protected."
  expect_ok "the master key from the process's environment" "$INSTALLER" --protect search
  [ "$(cat "$F/meilisearch-login.stdin")" = "$mk" ] || fail "$name: the master key from the environment didn't reach the agent"
  ! grep -qF "$mk" "$W/out" || fail "$name: the master key was printed"
  pass "the master key found in Meilisearch's environment too"
  pkill -f '/opt/meili/meilisearch' || true
  echo "test-install: Meilisearch cases passed"
}

# redis_only_tests (TEST_ONLY=redis): what the Redis and Valkey cases need
# of the rest (an install with storage, the agent running as postgres),
# then only those cases.
redis_only_tests() {
  write_terminal_helpers
  useradd --system --home-dir /var/lib/postgresql --create-home --shell /bin/sh postgres
  mkdir -p /usr/lib/postgresql/17/bin /var/lib/postgresql/17/main
  printf '#!/bin/sh\n' >/usr/lib/postgresql/17/bin/postgres && chmod 755 /usr/lib/postgresql/17/bin/postgres
  configured() {
    env ROWSAFE_REPO_S3_ENDPOINT=acct.eu.r2.cloudflarestorage.com ROWSAFE_REPO_S3_BUCKET=app-rowsafe \
      ROWSAFE_REPO_S3_KEY=AKIAEXAMPLEKEY42 ROWSAFE_REPO_S3_KEY_SECRET=s3cr3t/with+base64= \
      ROWSAFE_REPO_CIPHER_PASS='cipher-pass-that-is-long-enough/+==' "$@"
  }
  scenario
  expect_ok "configured install" configured "$INSTALLER" rse_secrettoken123 --no-allow-restart --no-allow-pooler
  echo '{"host_id":"host_1","agent_token":"rsa_x"}' >/var/lib/rowsafe/agent.json
  chown postgres:postgres /var/lib/rowsafe/agent.json
  runuser -u postgres -- /opt/rowsafe/rowsafe-agent run >/dev/null 2>&1 &
  sleep 1
  shop='5432\t/var/run/postgresql\t17\tmain\t/var/lib/postgresql/17/main\t1288490189\tshop\tno\t-\tshop\t1.2 GiB\tpostgresql@17-main.service\t-'
  done_='Checking that changes reach your storage...\n✓ shop is protected. The first full backup is running.'
  status='db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake'
  scenario
  expect_ok "agent running, restarts and pooling off" "$INSTALLER" --no-allow-restart --no-allow-pooler
  redis_flow_tests
  redis_restart_tests
  redis_host_tests
  echo "test-install: Redis and Valkey cases passed"
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
      *' -s '*' install '*postgresql-17-postgis-3*)
        echo "Inst postgresql-17 [17.5-1] (17.6-1 apt.postgresql.org [arm64])"
        echo "Inst postgresql-17-postgis-3 (3.6.4-1 apt.postgresql.org [arm64])" ;;
      *' -s '*' install '*) for p in "$@"; do :; done; echo "Inst $p (1.0-1 apt.postgresql.org [all])" ;;
      *' remove '*) rm -f "$S/installed-18" ;;
      *' install '*--only-upgrade*postgresql-17*) echo 17.6-1 >"$S/version-17" ;;
      *' install '*postgresql-17-pgvector*)
        mkdir -p /usr/share/postgresql/17/extension && touch /usr/share/postgresql/17/extension/vector.control
        echo 0.8.1-1 >"$S/version-17-pgvector" ;;
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
  u_has "error=installing PostgreSQL updates from Rowsafe is not allowed on this server (allow it on the server with: sudo rowsafe-allow updates)"
  [ ! -s "$S/calls" ] || fail "the helper ran something that isn't allowed"
  echo "postgresql" >>"$U"
  chmod 666 "$U"
  urequest "u5 pg-minor-update 5432"
  u_has "error=$U is writable by others than root"
  chmod 644 "$U"

  # An extension's package: only the names Rowsafe installs, only that
  # name's package for the cluster's major, only when apt changes no
  # installed package.
  for bad in "u5a pg-install-extension 5432 pg_cron" "u5a pg-install-extension 5432 vector extra" "u5a pg-install-extension 5432" \
    "u5a pg-install-extension 5432 timescaledb-2-postgresql-17" "u5a pg-install-extension 5432 vector;reboot" "u5a pg-install-extension x vector"; do
    urequest "$bad"
    u_has "ok=0"
    u_has "error=malformed request"
    [ ! -s "$S/calls" ] || fail "the helper ran something for a malformed request: $bad"
  done
  urequest "u5b pg-install-extension 5432 vector"
  u_has "ok=1"
  u_has "package=postgresql-17-pgvector"
  u_has "version=0.8.1-1"
  u_called "install -y --no-install-recommends postgresql-17-pgvector"
  ! grep -q "restart" "$F/systemctl.calls" || fail "installing an extension restarted something: $(cat "$F/systemctl.calls")"
  urequest "u5c pg-install-extension 5432 postgis"
  u_has "ok=0"
  grep -q "^error=installing postgresql-17-postgis-3 would also update postgresql-17 (it needs a newer PostgreSQL 17): install PostgreSQL's update first" "$O/update-result" ||
    fail "an extension that would update PostgreSQL wasn't refused: $(cat "$O/update-result")"
  ! grep -q " install -y" "$S/calls" || fail "the helper installed something that would update PostgreSQL: $(cat "$S/calls")"
  rm -f /usr/share/postgresql/17/extension/vector.control
  urequest "u5d pg-install-extension 5499 vector"
  grep -q "^error=port 5499 is not in /etc/rowsafe/restart-allowed" "$O/update-result" || fail "an extension for an unlisted port not refused"

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
  u_has "error=rebooting the server from Rowsafe is not allowed here (allow it on the server with: sudo rowsafe-allow reboot)"
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
  lacks "Limit who can reach PostgreSQL"
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
  grep -q "^error=no database server (PostgreSQL, MySQL, MariaDB, MongoDB, ClickHouse, Redis or Valkey) listens on port 5499" "$FO/result" || fail "a port without PostgreSQL was not refused"
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

  # Servers Rowsafe creates (--firewall-ssh, the line "ssh" in root's list):
  # the "server" action sets PostgreSQL's and SSH's allow lists at once.
  ssh_addrs() { printf '%b' "$1" | as_pg sh -c 'cat >"$1"' sh "$D/ssh-addresses"; }
  ssh_addrs '198.51.100.7\n'
  fw_request "fw_srv0 server 5432" '10.3.0.0/16\n' 1
  grep -q "^error=SSH's allow list isn't Rowsafe's" "$FO/result" || fail "the server action was not refused without --firewall-ssh"
  ! rules | grep -q . || fail "a refused server action changed the rules"
  printf '5432\nssh\n' >/etc/rowsafe/firewall-allowed
  ssh_addrs '198.51.100.7\n'
  fw_request "fw_srv1 server 5432" '10.3.0.0/16\n2001:db8::/32\n' 1
  fw_has "ok=1"
  rules | grep -q "ct state established,related accept" || fail "replies to connections already made aren't let through: $(rules)"
  rules | grep -q "tcp dport { 22, 2222 } ip saddr 198.51.100.7 accept" && rules | grep -q "tcp dport { 22, 2222 } drop" ||
    fail "no SSH rules: $(rules)"
  rules | grep -q "tcp dport 5432 ip6 saddr 2001:db8::/32 accept" && rules | grep -q "tcp dport 5432 drop" || fail "no PostgreSQL rules: $(rules)"
  grep -qx "addresses=198.51.100.7" "$FO/ssh" && grep -qx "ports=22,2222" "$FO/ssh" && grep -qx "loaded=1" "$FO/ssh" || fail "SSH's rule not published"
  [ -f "$W/fw-state/ssh-allowed" ] && [ ! -e "$W/fw-state/ssh-pending" ] || fail "a confirmed SSH rule was not kept"
  # Everyone for PostgreSQL (passwords still needed), no one for SSH.
  ssh_addrs ''
  fw_request "fw_srv2 server 5432" '0.0.0.0/0\n::/0\n' 1
  fw_has "ok=1"
  rules | grep -q "tcp dport 5432 meta nfproto ipv6 accept" && ! rules | grep -q "198.51.100.7" && rules | grep -q "tcp dport { 22, 2222 } drop" ||
    fail "open PostgreSQL, closed SSH: $(rules)"
  # Unconfirmed: both lists come back as they were.
  ssh_addrs '192.0.2.1\n'
  WAIT=1 fw_request "fw_srv3 server 5432" '10.9.0.0/16\n' 0
  fw_has "ok=0"
  ! rules | grep -q "192.0.2.1" && ! rules | grep -q "10.9.0.0/16" && rules | grep -q "meta nfproto ipv6 accept" || fail "unconfirmed server action not rolled back: $(rules)"
  [ ! -s "$W/fw-state/ssh-allowed" ] && [ ! -e "$W/fw-state/ssh-pending" ] || fail "an unconfirmed SSH rule was kept"
  ssh_addrs '0.0.0.0/1\n'
  fw_request "fw_srv4 server 5432" '' 1
  grep -q "^error=not an address or range: 0.0.0.0/1" "$FO/result" || fail "a too wide SSH range was not refused"
  # Several ports in one request (ClickHouse's 9440 and 8443): set,
  # confirmed and put back together.
  printf '5432\n5433\nssh\n' >/etc/rowsafe/firewall-allowed
  ssh_addrs ''
  fw_request "fw_srv6 server 5432,5433" '10.4.0.0/16\n' 1
  fw_has "ok=1"
  rules | grep -q "tcp dport 5432 ip saddr 10.4.0.0/16 accept" && rules | grep -q "tcp dport 5433 ip saddr 10.4.0.0/16 accept" ||
    fail "two ports in one request: $(rules)"
  [ -f "$W/fw-state/port-5432" ] && [ -f "$W/fw-state/port-5433" ] && [ ! -e "$W/fw-state/pending-5433" ] || fail "two ports not kept"
  WAIT=1 fw_request "fw_srv7 server 5432,5433" '10.5.0.0/16\n' 0
  fw_has "ok=0"
  ! rules | grep -q "10.5.0.0/16" && rules | grep -q "tcp dport 5433 ip saddr 10.4.0.0/16 accept" || fail "two unconfirmed ports not both put back: $(rules)"
  fw_request "fw_srv8 server 5432,5499" '10.6.0.0/16\n' 1
  grep -q "^error=port 5499 is not in" "$FO/result" && ! rules | grep -q "10.6.0.0/16" || fail "a request with an unlisted port changed something: $(rules)"
  fw_request "fw_srv9 apply 5432,5433" '10.6.0.0/16\n' 1
  grep -q "^error=malformed request" "$FO/result" || fail "several ports accepted for apply"
  fw_request "fw_srv10 remove 5433" "" 0
  printf '5432\nssh\n' >/etc/rowsafe/firewall-allowed
  as_pg rm -f "$D/ssh-addresses"
  fw --restore
  rules | grep -q "tcp dport { 22, 2222 } drop" || fail "--restore dropped SSH's rule"
  # Root takes SSH back: its rule goes at the next load, PostgreSQL's stays.
  printf '5432\n' >/etc/rowsafe/firewall-allowed
  fw --restore
  ! rules | grep -q "dport { 22" && ! rules | grep -q "ct state" && rules | grep -q "tcp dport 5432 drop" || fail "SSH's rule stayed without the ssh line: $(rules)"
  [ ! -e "$FO/ssh" ] || fail "SSH's rule still published"
  rm -f "$W/fw-state/ssh-allowed" "$W/fw-state/ssh-ports"
  fw_request "fw_srv5 remove 5432" "" 0
  ! rules | grep -q . || fail "remove left the table: $(rules)"
  pass "firewall helper, servers Rowsafe creates: SSH and PostgreSQL at once, several ports together, everyone and no one, rollback, --restore, root taking SSH back"

  # The installer's --firewall-ssh: PostgreSQL's port closed before anything
  # else, the ssh line kept until --no-firewall-ssh.
  expect_fail "--firewall-ssh with --no-allow-firewall" "can't go with --no-allow-firewall" "$INSTALLER" --firewall-ssh --no-allow-firewall
  expect_fail "--firewall-ssh only with an install" "only go with an install" "$INSTALLER" --firewall-ssh --uninstall
  scenario "discover_out=$shop"
  expect_ok "--firewall-ssh" "$INSTALLER" --firewall-ssh
  grep -q "PostgreSQL's port (5432) is closed to everyone but this server until Rowsafe applies who may connect" "$W/out" &&
    grep -q "and SSH, as set in the dashboard" "$W/out" || {
    cat "$W/out" >&2
    fail "--firewall-ssh not confirmed"
  }
  grep -qx ssh /etc/rowsafe/firewall-allowed && grep -qx 5432 /etc/rowsafe/firewall-allowed || fail "--firewall-ssh allow list"
  rules | grep -q "tcp dport 5432 drop" && ! rules | grep -q "dport 22" || fail "--firewall-ssh didn't close PostgreSQL's port: $(rules)"
  scenario "discover_out=$shop"
  expect_ok "a re-run keeps --firewall-ssh" "$INSTALLER" --allow-firewall
  grep -qx ssh /etc/rowsafe/firewall-allowed || fail "a re-run dropped the ssh line"
  scenario "discover_out=$shop"
  expect_ok "--no-firewall-ssh" "$INSTALLER" --no-firewall-ssh
  ! grep -qx ssh /etc/rowsafe/firewall-allowed && grep -qx 5432 /etc/rowsafe/firewall-allowed || fail "--no-firewall-ssh allow list"
  grep -q "Rowsafe no longer limits who can reach SSH" "$W/out" || fail "--no-firewall-ssh not confirmed"
  nft delete table inet rowsafe 2>/dev/null || true
  rm -rf /var/lib/rowsafe-firewall
  pass "--firewall-ssh closes PostgreSQL's port first and keeps SSH's allow list Rowsafe's until --no-firewall-ssh"

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
  grep -q '^# actions: restart stop start create-cluster\( \|$\)' "$H" || fail "the helper doesn't say it creates clusters"

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

# ------------------------------------------------------------ servers Rowsafe creates

# install_db_option_tests: --install-mysql, --install-mariadb and
# --install-valkey refused before anything changes (no network): two
# --install options, versions Rowsafe doesn't install, MySQL on arm64
# (uname stood in), MariaDB 11.4 on Debian 13, Valkey on Ubuntu, and a
# server without systemd.
install_db_option_tests() {
  # shellcheck disable=SC1091
  os=$(. /etc/os-release && echo "$ID $VERSION_ID")
  expect_fail "--install-mysql with --install-postgres refused" "give only one" "$INSTALLER" --install-mysql 8.4 --install-postgres 17
  expect_fail "--install-valkey with --install-mariadb refused" "give only one" "$INSTALLER" --install-valkey 8 --install-mariadb 11.8
  expect_fail "--install-mysql twice refused" "give only one" "$INSTALLER" --install-mysql 8.4 --install-mysql 8.4
  expect_fail "--install-mysql 8.0 refused" "Rowsafe installs MySQL 8.4, not '8.0'" "$INSTALLER" --install-mysql 8.0
  expect_fail "--install-mariadb 10.11 refused" "Rowsafe installs MariaDB 11.4 or 11.8, not '10.11'" "$INSTALLER" --install-mariadb 10.11
  expect_fail "--install-valkey 7.2 refused" "Rowsafe installs Valkey 8, not '7.2'" "$INSTALLER" --install-valkey 7.2
  expect_fail "--install-valkey needs a version" "needs a version" "$INSTALLER" --install-valkey
  expect_fail "--install-mariadb only with an install" "only go with an install" "$INSTALLER" --install-mariadb 11.8 --uninstall
  expect_fail "--install-clickhouse 25.8 refused" "Rowsafe installs ClickHouse 26.3 or 26.8, not '25.8'" "$INSTALLER" --install-clickhouse 25.8
  expect_fail "--install-clickhouse with --install-valkey refused" "give only one" "$INSTALLER" --install-clickhouse 26.8 --install-valkey 8
  expect_fail "--install-opensearch 2 refused" "Rowsafe installs OpenSearch 3, not '2'" "$INSTALLER" --install-opensearch 2
  expect_fail "--install-opensearch with --install-clickhouse refused" "give only one" "$INSTALLER" --install-opensearch 3 --install-clickhouse 26.8
  expect_fail "--install-qdrant 1.18 refused" "Rowsafe installs Qdrant 1.19, not '1.18'" "$INSTALLER" --install-qdrant 1.18
  expect_fail "--install-qdrant with --install-clickhouse refused" "give only one" "$INSTALLER" --install-qdrant 1.19 --install-clickhouse 26.8
  expect_fail "--pg-extensions without --install-postgres refused" "only goes with --install-postgres" "$INSTALLER" --pg-extensions vector
  expect_fail "--pg-extensions with --install-mysql refused" "only goes with --install-postgres" "$INSTALLER" --install-mysql 8.4 --pg-extensions vector
  expect_fail "--pg-extensions: an unknown name refused" "Rowsafe installs vector (pgvector), postgis (PostGIS) and timescaledb (TimescaleDB), not 'pg_cron'" \
    "$INSTALLER" --install-postgres 17 --pg-extensions vector,pg_cron
  expect_fail "--pg-extensions: a package name refused" "not 'timescaledb-2-postgresql-17'" "$INSTALLER" --install-postgres 17 --pg-extensions timescaledb-2-postgresql-17
  expect_fail "--pg-extensions on PostgreSQL 14 refused" "for PostgreSQL 15 to 18, not 14" "$INSTALLER" --install-postgres 14 --pg-extensions timescaledb
  expect_fail "--pg-extensions needs names" "needs extensions" "$INSTALLER" --install-postgres 17 --pg-extensions ,
  printf 'MemTotal:        2014280 kB\n' >"$W/meminfo-2g"
  expect_fail "--install-clickhouse on 2 GB refused" "ClickHouse needs a server with at least 4 GB of memory, and this one has 1967 MB" \
    env ROWSAFE_MEMINFO="$W/meminfo-2g" "$INSTALLER" rse_secrettoken123 --no-prompt --install-clickhouse 26.8
  expect_fail "--install-opensearch on 2 GB refused" "OpenSearch needs a server with at least 4 GB of memory, and this one has 1967 MB" \
    env ROWSAFE_MEMINFO="$W/meminfo-2g" "$INSTALLER" rse_secrettoken123 --no-prompt --install-opensearch 3
  printf 'MemTotal:        1004280 kB\n' >"$W/meminfo-1g"
  expect_fail "--install-qdrant on 1 GB refused" "Qdrant needs a server with at least 2 GB of memory, and this one has 980 MB" \
    env ROWSAFE_MEMINFO="$W/meminfo-1g" "$INSTALLER" rse_secrettoken123 --no-prompt --install-qdrant 1.19
  mkdir -p "$W/arm64"
  printf '#!/bin/sh\ncase "${1:-}" in -m) echo aarch64 ;; *) exec /bin/uname "$@" ;; esac\n' >"$W/arm64/uname"
  chmod 755 "$W/arm64/uname"
  expect_fail "--install-mysql on arm64 refused" "MySQL's own packages are built for Intel and AMD processors only; this server is arm64" \
    env PATH="$W/arm64:$PATH" "$INSTALLER" rse_secrettoken123 --no-prompt --install-mysql 8.4
  case $os in
    ubuntu*)
      expect_fail "--install-valkey on Ubuntu refused" "Valkey 8 isn't packaged for Ubuntu yet" "$INSTALLER" rse_secrettoken123 --no-prompt --install-valkey 8
      ;;
    "debian 13")
      expect_fail "--install-mariadb 11.4 on Debian 13 refused" "MariaDB 11.4 isn't published for Debian 13; install MariaDB 11.8 instead" \
        "$INSTALLER" rse_secrettoken123 --no-prompt --install-mariadb 11.4
      ;;
  esac
  [ -d /run/systemd/system ] ||
    expect_fail "--install-mariadb without systemd refused" "needs systemd" "$INSTALLER" rse_secrettoken123 --no-prompt --install-mariadb 11.8
  [ ! -e /etc/rowsafe ] && [ ! -e /opt/rowsafe ] && [ -z "$(ls /etc/apt/sources.list.d/rowsafe-* 2>/dev/null)" ] ||
    fail "a refused --install option changed something"
  [ ! -e /usr/bin/qdrant ] || fail "a refused --install-qdrant installed Qdrant"
  pass "--install-mysql, --install-mariadb, --install-valkey, --install-clickhouse, --install-opensearch, --install-qdrant and --pg-extensions: refusals change nothing"
}

# cloud_container (--cloud): --install-postgres and --listen-public for
# real, in one non-interactive run like cloud-init's.
cloud_container() {
  release_setup
  echo "  -- servers Rowsafe creates (--install-postgres, --listen-public)"
  # The release server's CA and the public ones: the installer downloads the
  # PostgreSQL project's signing key from www.postgresql.org.
  cat /etc/ssl/certs/ca-certificates.crt "$W/tls.crt" >"$W/ca-bundle.crt"
  export CURL_CA_BUNDLE=$W/ca-bundle.crt
  pgv=${TEST_PG_VERSION:-17}

  expect_fail "--install-postgres needs a version" "needs a PostgreSQL version" "$INSTALLER" --install-postgres
  expect_fail "--install-postgres 12 refused" "from 13 to 18" "$INSTALLER" --install-postgres 12
  expect_fail "--install-postgres only with an install" "only go with an install" "$INSTALLER" --install-postgres "$pgv" --uninstall
  expect_fail "--listen-public only with an install" "only go with an install" "$INSTALLER" --listen-public --check-storage
  [ ! -e /etc/rowsafe ] || fail "a refused option wrote /etc/rowsafe"

  # PostgreSQL already here (binaries, a package): refused, nothing changed.
  mkdir -p /usr/lib/postgresql/15/bin
  printf '#!/bin/sh\n' >/usr/lib/postgresql/15/bin/postgres && chmod 755 /usr/lib/postgresql/15/bin/postgres
  expect_fail "PostgreSQL already installed: refused" "PostgreSQL is already installed on this server (PostgreSQL 15" \
    "$INSTALLER" rse_secrettoken123 --no-prompt --install-postgres "$pgv"
  [ ! -e /etc/apt/sources.list.d/pgdg.list ] || fail "the repository was added despite the refusal"
  rm -rf /usr/lib/postgresql

  # By --protect time on a real server the agent has enrolled and runs. A
  # stand-in agent: the postgres user and its state exist before the run
  # (PostgreSQL's packages take the existing user), so the stand-in can run.
  useradd --system --user-group --home-dir /var/lib/postgresql --create-home --shell /bin/bash postgres
  install -d -m 0700 -o postgres -g postgres /var/lib/rowsafe
  echo '{"host_id":"host_1","agent_token":"rsa_x"}' >/var/lib/rowsafe/agent.json
  chown postgres:postgres /var/lib/rowsafe/agent.json
  mkdir -p "$W/fa"
  fake_agent 0.2.0 >"$W/fa/rowsafe-agent"
  chmod 755 "$W" "$W/fa" "$W/fa/rowsafe-agent"
  runuser -u postgres -- "$W/fa/rowsafe-agent" run >/dev/null 2>&1 &
  agent_pid=$!
  sleep 1
  shop="5432\t/var/run/postgresql\t$pgv\tmain\t/var/lib/postgresql/$pgv/main\t8192\tpostgres\tno\t-\tpostgres\t7.5 MiB\tpostgresql@$pgv-main.service\t-"
  status='db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake'
  scenario "discover_out=$shop" "plan_out=Restart: PostgreSQL needs one quick restart." apply_rc=10 \
    "wait_out=✓ shop is protected. The first full backup is running." "status_out=$status"

  # TEST_PG_EXTENSIONS (default all three; "" for none) at install,
  # TEST_PG_EXTENSIONS_LATER through the root helper afterwards.
  pgx=${TEST_PG_EXTENSIONS-vector,postgis,timescaledb}
  cloud_init() {
    sh -c 'w=$1; shift; ROWSAFE_RELEASES_URL=https://localhost:18443/agent ROWSAFE_RESTIC_URL=https://localhost:18443/restic sh -s -- "$@" <"$w/install.sh"' \
      cloud-init "$W" rse_secrettoken123 --no-prompt --install-postgres "$pgv" ${pgx:+--pg-extensions "$pgx"} --listen-public --storage rowsafe --protect shop
  }
  expect_ok "one run, as cloud-init: PostgreSQL, network, Rowsafe Storage, protected" cloud_init
  [ -z "${TEST_SHOW:-}" ] || cat "$W/out"
  grep -q "the PostgreSQL project's repository (apt.postgresql.org, key B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8)" "$W/out" || fail "$name: no word about the repository"
  grep -qx "deb \[signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc\] https://apt.postgresql.org/pub/repos/apt $(. /etc/os-release && echo "$VERSION_CODENAME")-pgdg main" \
    /etc/apt/sources.list.d/pgdg.list || fail "$name: pgdg.list"
  dpkg-query -W -f '${Version}\n' "postgresql-$pgv" | grep -q pgdg || fail "$name: postgresql-$pgv isn't the PostgreSQL project's package"
  [ "$(cat /etc/rowsafe/installed-postgresql)" = "$pgv" ] || fail "$name: no record of the installed major"
  pg_lsclusters -h | awk -v m="$pgv" '$1 == m && $2 == "main" && $4 ~ /^online/ { f = 1 } END { exit !f }' || fail "$name: the cluster isn't running"
  q() { runuser -u postgres -- psql -X -A -t -q -d postgres -c "$1"; }
  [ "$(q 'SHOW listen_addresses')" = '*' ] || fail "$name: listen_addresses"
  [ "$(q 'SHOW ssl')" = on ] || fail "$name: ssl"
  [ "$(q 'SHOW password_encryption')" = scram-sha-256 ] || fail "$name: password_encryption"
  [ "$(q 'SHOW server_encoding')" = UTF8 ] || fail "$name: server_encoding is $(q 'SHOW server_encoding')"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-postgresql/server.key)" = "root postgres 640" ] || fail "$name: TLS key ownership/mode"
  hba=$(q 'SHOW hba_file')
  [ "$(grep -c '^hostssl all  *all  *0.0.0.0/0  *scram-sha-256$' "$hba")" = 1 ] &&
    [ "$(grep -c '^hostssl all  *all  *::/0  *scram-sha-256$' "$hba")" = 1 ] || fail "$name: pg_hba.conf rules"
  [ "$(stat -c '%U' "$hba")" = postgres ] || fail "$name: pg_hba.conf changed owner"
  grep -q "PostgreSQL restarted" "$W/out" || fail "$name: the new PostgreSQL wasn't restarted for backups"
  called "plan --name shop --port 5432"
  called "apply --database db_fake"
  called "wait --database db_fake --timeout 3m"
  grep -q "a backup encryption passphrase was generated" "$W/out" || fail "$name: no passphrase note"
  gen=$(sed -n "s/^ROWSAFE_REPO_CIPHER_PASS='\([A-Za-z0-9]\{40\}\)'\$/\1/p" /etc/rowsafe/agent.env)
  [ "${#gen}" = 40 ] || fail "$name: no generated passphrase"
  ! grep -qF "$gen" "$W/out" || fail "$name: the passphrase was printed"
  ! grep -q rse_secrettoken123 "$W/out" || fail "$name: the token was printed"
  pass "PostgreSQL $pgv from apt.postgresql.org, listening with TLS and SCRAM, protected, passphrase kept on the server"
  [ -z "$pgx" ] || cloud_pg_extension_checks

  # From the network: TLS and a password, nothing else.
  ip=$(hostname -i | awk '{ print $1 }')
  q "CREATE ROLE app LOGIN PASSWORD 'app-password-for-the-test'" >/dev/null
  conn="host=$ip port=5432 dbname=postgres user=app"
  [ "$(PGPASSWORD=app-password-for-the-test psql -X -A -t "$conn sslmode=require" -c 'SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()' 2>&1)" = t ] ||
    fail "TLS login from the network"
  if PGPASSWORD=app-password-for-the-test psql -X "$conn sslmode=disable" -c 'SELECT 1' >"$W/out" 2>&1; then fail "a login without TLS was accepted"; fi
  grep -q "no encryption" "$W/out" || { cat "$W/out" >&2; fail "a login without TLS wasn't refused by pg_hba.conf"; }
  if PGPASSWORD=wrong psql -X "$conn sslmode=require" -c 'SELECT 1' >"$W/out" 2>&1; then fail "a wrong password was accepted"; fi
  grep -q "password authentication failed" "$W/out" || { cat "$W/out" >&2; fail "a wrong password wasn't refused"; }
  [ "$(q "SELECT rolpassword LIKE 'SCRAM-SHA-256\$%' FROM pg_authid WHERE rolname = 'app'")" = t ] || fail "the password isn't stored as SCRAM"
  pass "from the network: TLS and SCRAM logins only"

  # Again: nothing changes, nothing restarts.
  started=$(q 'SELECT pg_postmaster_start_time()')
  scenario "discover_out=5432\t/var/run/postgresql\t$pgv\tmain\t/var/lib/postgresql/$pgv/main\t8192\tshop\tyes\tactive\tpostgres\t7.5 MiB\tpostgresql@$pgv-main.service\tdb_fake" \
    plan_rc=5 "plan_out=shop is already protected." "status_out=$status"
  expect_ok "re-run changes nothing" cloud_init
  grep -q "PostgreSQL $pgv is installed (by an earlier run of this installer)" "$W/out" || fail "$name: not recognized as its own"
  grep -q "nothing to change" "$W/out" || fail "$name: --listen-public changed something"
  [ -z "$pgx" ] || grep -q "extensions $(printf '%s' "$pgx" | sed 's/,/, /g'): nothing to change" "$W/out" || fail "$name: --pg-extensions changed something"
  [ "$(q 'SELECT pg_postmaster_start_time()')" = "$started" ] || fail "$name: PostgreSQL was restarted"
  [ "$(grep -c '^hostssl' "$hba")" = 2 ] || fail "$name: pg_hba.conf rules added twice"
  [ "$(sed -n "s/^ROWSAFE_REPO_CIPHER_PASS='\(.*\)'\$/\1/p" /etc/rowsafe/agent.env)" = "$gen" ] || fail "$name: the passphrase changed"
  not_called "apply"
  pass "re-run: nothing changed, nothing restarted"

  # Another major, or the same one not installed by Rowsafe: refused.
  expect_fail "another major refused" "already installed on this server (PostgreSQL $pgv" "$INSTALLER" --no-prompt --install-postgres 16 --no-setup
  mv /etc/rowsafe/installed-postgresql "$W/installed-postgresql"
  expect_fail "PostgreSQL not installed by Rowsafe refused" "already installed on this server" "$INSTALLER" --no-prompt --install-postgres "$pgv" --no-setup
  mv "$W/installed-postgresql" /etc/rowsafe/installed-postgresql
  pass "refused on a server with PostgreSQL that --install-postgres didn't install"

  [ -z "${TEST_PG_EXTENSIONS_LATER:-}" ] || cloud_pg_extensions_later

  kill "$agent_pid" 2>/dev/null || true
  wait "$agent_pid" 2>/dev/null || true
}

# cloud_pg_extension_checks: what --pg-extensions $pgx did, used for real.
cloud_pg_extension_checks() {
  for e in $(printf '%s' "$pgx" | tr ',' ' '); do
    case $e in
      vector) p=postgresql-$pgv-pgvector ;;
      postgis) p=postgresql-$pgv-postgis-3 ;;
      timescaledb) p=postgresql-$pgv-timescaledb ;;
    esac
    [ "$(dpkg-query -W -f '${db:Status-Status}' "$p" 2>/dev/null)" = installed ] || fail "$name: $p isn't installed"
    for d in postgres template1; do
      [ "$(runuser -u postgres -- psql -X -A -t -q -d "$d" -c "SELECT count(*) FROM pg_extension WHERE extname = '$e'")" = 1 ] ||
        fail "$name: $e isn't on in $d"
    done
  done
  q "CREATE DATABASE later_app" >/dev/null
  [ "$(runuser -u postgres -- psql -X -A -t -q -d later_app -c "SELECT count(*) FROM pg_extension WHERE extname IN ($(printf "'%s'" "$pgx" | sed "s/,/','/g"))")" = \
    "$(printf '%s' "$pgx" | tr ',' '\n' | grep -c .)" ] || fail "$name: a new database doesn't have the extensions"
  case ",$pgx," in
    *,vector,*)
      q "CREATE TABLE items (id int PRIMARY KEY, embedding vector(3)); INSERT INTO items VALUES (1, '[1,2,3]'), (2, '[3,2,1]');
         CREATE INDEX ON items USING hnsw (embedding vector_l2_ops)" >/dev/null || fail "$name: pgvector"
      [ "$(q "SELECT id FROM items ORDER BY embedding <-> '[3,2,2]' LIMIT 1")" = 2 ] || fail "$name: pgvector's nearest neighbour"
      ;;
  esac
  case ",$pgx," in
    *,postgis,*)
      [ "$(q "SELECT ST_Distance('SRID=4326;POINT(13.40 52.52)'::geography, 'SRID=4326;POINT(2.35 48.86)'::geography) / 1000 BETWEEN 870 AND 890")" = t ] ||
        fail "$name: PostGIS's distance Berlin-Paris: $(q "SELECT ST_Distance('SRID=4326;POINT(13.40 52.52)'::geography, 'SRID=4326;POINT(2.35 48.86)'::geography)")"
      ;;
  esac
  case ",$pgx," in
    *,timescaledb,*)
      q 'SHOW shared_preload_libraries' | tr ',' '\n' | tr -d ' ' | grep -qx timescaledb || fail "$name: TimescaleDB isn't loaded at start"
      [ "$(q 'SHOW timescaledb.telemetry_level')" = off ] || fail "$name: TimescaleDB's telemetry is $(q 'SHOW timescaledb.telemetry_level')"
      [ "$(q 'SHOW timescaledb.license')" = apache ] || fail "$name: TimescaleDB's license is $(q 'SHOW timescaledb.license')"
      dpkg-query -W -f '${Version}' "postgresql-$pgv-timescaledb" | grep -q pgdg || fail "$name: TimescaleDB isn't the PostgreSQL project's package"
      ! grep -rqs -e packagecloud -e timescale /etc/apt/sources.list /etc/apt/sources.list.d || fail "$name: another package source was added"
      q "CREATE TABLE metrics (time timestamptz NOT NULL, device int, value double precision);
         SELECT create_hypertable('metrics', by_range('time', INTERVAL '1 day'));
         INSERT INTO metrics SELECT t, 1, 1.5 FROM generate_series(now() - interval '3 days', now(), interval '1 hour') t" >/dev/null || fail "$name: a hypertable"
      [ "$(q "SELECT count(*) > 1 FROM timescaledb_information.chunks WHERE hypertable_name = 'metrics'")" = t ] || fail "$name: no chunks"
      [ "$(q "SELECT count(DISTINCT time_bucket('1 day', time)) >= 3 FROM metrics")" = t ] || fail "$name: time_bucket"
      ;;
  esac
  q "DROP DATABASE later_app" >/dev/null
  pass "--pg-extensions $pgx: packages, loaded, on in postgres, template1 and a new database, used for real"
}

# cloud_pg_extensions_later: TEST_PG_EXTENSIONS_LATER through the root
# helper's update mode (pg-install-extension), for real, then turned on as
# the agent does (TimescaleDB: shared_preload_libraries and a restart).
cloud_pg_extensions_later() {
  hd=$W/helper
  install -d -m 0755 "$hd" "$hd/out" "$hd/state"
  install -d -m 0700 -o postgres -g postgres "$hd/req"
  printf 'postgresql\n' >"$hd/updates-allowed"
  printf '5432 postgresql@%s-main.service\n' "$pgv" >"$hd/restart-allowed"
  chmod 644 "$hd/updates-allowed" "$hd/restart-allowed"
  for e in $TEST_PG_EXTENSIONS_LATER; do
    printf 'later%s pg-install-extension 5432 %s\n' "$e" "$e" | runuser -u postgres -- sh -c 'cat >"$1"' sh "$hd/req/update-request"
    rm -f "$hd/out/update-result"
    timeout 1200 env ROWSAFE_HELPER_MODE=update ROWSAFE_RESTART_DIR="$hd/req" ROWSAFE_UPDATES_ALLOW="$hd/updates-allowed" \
      ROWSAFE_RESTART_ALLOW="$hd/restart-allowed" RUNTIME_DIRECTORY="$hd/out" STATE_DIRECTORY="$hd/state" \
      sh /src/scripts/rowsafe-pg-restart 2>>"$W/helper.log" || fail "the helper failed for $e"
    grep -qx ok=1 "$hd/out/update-result" || {
      cat "$hd/out/update-result" "$hd/state/update.log" >&2
      fail "the helper didn't install $e"
    }
    if [ "$e" = timescaledb ]; then
      ! grep -rqs -e packagecloud -e timescale /etc/apt/sources.list /etc/apt/sources.list.d || fail "the helper added a package source"
      q "ALTER SYSTEM SET shared_preload_libraries = 'timescaledb'" >/dev/null
      pg_ctlcluster "$pgv" main restart || fail "PostgreSQL doesn't restart with TimescaleDB"
      q "ALTER SYSTEM SET timescaledb.telemetry_level = 'off'" >/dev/null
      q "SELECT pg_reload_conf()" >/dev/null
    fi
    q "CREATE EXTENSION IF NOT EXISTS $e" >/dev/null || fail "turning on $e after the helper installed it"
    [ "$e" != timescaledb ] || [ "$(q 'SHOW timescaledb.license')" = apache ] || fail "TimescaleDB's license is $(q 'SHOW timescaledb.license')"
  done
  pass "the root helper installed $TEST_PG_EXTENSIONS_LATER for real (pg-install-extension), turned on afterwards"
}

# cloud_engine_container ENGINE VERSION (--cloud, in a container with
# systemd): --install-mysql, --install-mariadb or --install-valkey for real,
# in one non-interactive run like cloud-init's, with --listen-public,
# --firewall-ssh and --protect; then a re-run that changes nothing and the
# refusals.
cloud_engine_container() {
  engine=$1 ver=$2
  release_setup
  apt-get install -y -qq --no-install-recommends nftables >/dev/null
  cat /etc/ssl/certs/ca-certificates.crt "$W/tls.crt" >"$W/ca-bundle.crt"
  export CURL_CA_BUNDLE=$W/ca-bundle.crt
  F=/tmp/rowsafe-fake
  # shellcheck disable=SC1091
  os=$(. /etc/os-release && echo "$ID $VERSION_ID")
  case $engine in
    mysql) label=MySQL unit=mysql port=3306 user=mysql ;;
    mariadb) label=MariaDB unit=mariadb port=3306 user=mysql ;;
    valkey) label=Valkey unit=valkey-server port=6380 user=rowsafe ;;
    clickhouse) label=ClickHouse unit=clickhouse-server port=8123 user=rowsafe ;;
    opensearch) label=OpenSearch unit=opensearch port=9200 user=rowsafe ;;
    qdrant) label=Qdrant unit=qdrant port=6333 user=rowsafe ;;
    meilisearch) label=Meilisearch unit=meilisearch port=7700 user=rowsafe ;;
  esac
  echo "  -- servers Rowsafe creates: --install-$engine $ver ($os, $arch)"
  [ "$engine" != opensearch ] || opensearch_test_prep # opensearch

  # Refused before anything changes: another database server already here.
  if [ "$engine" = valkey ]; then
    printf '#!/bin/sh\necho "/usr/sbin/mysqld  Ver 8.4.3 for Linux on x86_64 (MySQL Community Server - GPL)"\n' >/usr/sbin/mysqld
    chmod 755 /usr/sbin/mysqld
    expect_fail "MySQL already here: --install-valkey refused" "MySQL 8.4.3 in /usr/sbin/mysqld is already installed on this server, so --install-valkey won't install Valkey next to it" \
      "$INSTALLER" rse_secrettoken123 --no-prompt --install-valkey "$ver"
    rm -f /usr/sbin/mysqld
  else
    printf '#!/bin/sh\necho "Valkey server v=8.1.1 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64 build=0"\n' >/usr/local/bin/valkey-server
    chmod 755 /usr/local/bin/valkey-server
    expect_fail "Valkey already here: --install-$engine refused" "Valkey 8.1.1 is already installed on this server, so --install-$engine won't install $label next to it" \
      "$INSTALLER" rse_secrettoken123 --no-prompt --install-"$engine" "$ver"
    rm -f /usr/local/bin/valkey-server
  fi
  [ ! -e /etc/rowsafe ] && [ -z "$(ls /etc/apt/sources.list.d/rowsafe-* 2>/dev/null)" ] || fail "$name: something was written"
  [ "$engine" != qdrant ] || [ ! -e /usr/bin/qdrant ] || fail "$name: Qdrant was installed anyway"

  if [ "$engine" = meilisearch ]; then
    # A binary that isn't the one Rowsafe pinned is refused, before anything changes.
    mkdir -p "$W/srv/bad/v1.54.3"
    for a in meilisearch-linux-amd64 meilisearch-linux-aarch64; do echo 'not meilisearch' >"$W/srv/bad/v1.54.3/$a"; done
    expect_fail "a Meilisearch binary that doesn't match the pinned SHA-256 refused" "doesn't match the SHA-256 Rowsafe pinned for it" \
      env ROWSAFE_RELEASES_URL=https://localhost:18443/agent ROWSAFE_MEILISEARCH_URL=https://localhost:18443/bad \
      sh "$W/install.sh" rse_secrettoken123 --no-prompt --install-meilisearch "$ver" --no-setup
    [ ! -e /usr/local/bin/meilisearch ] && [ -z "$(ls /usr/local/lib/meilisearch/*/meilisearch 2>/dev/null)" ] || fail "$name: the binary was installed"
    rm -rf /etc/rowsafe /var/tmp/rowsafe-meilisearch.*
  fi

  # The stand-in agent runs as the engine's agent user (mysql or rowsafe);
  # its unit enrolls it at once (agent.json).
  echo "$user" >/tmp/rowsafe-fake-user
  case $engine in
    meilisearch)
      line="7700\t-\t1\t-\t/var/lib/meilisearch/data/data.ms\t8192\tmeilisearch\tno\t-\t-\t8 KiB\tmeilisearch.service\t-\tmeilisearch"
      scenario "discover_out=$line" "meilisearch-status_out=answers=yes\ntls=no\nversion=1.54.3\nlogin=missing" \
        "meilisearch-login_out=version=1.54.3\ntls=no\nkey_uid=0f0e\nno_auth=no" \
        "plan_out=Backups for shop: Meilisearch's own snapshots, every hour." \
        "wait_out=✓ shop is protected. The first full backup is running." "status_out=db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake"
      ;;
    clickhouse)
      line="8123\t-\t$ver\t-\t/var/lib/clickhouse\t8192\tclickhouse\tno\t-\t-\t8 KiB\tclickhouse-server.service\t-\tclickhouse"
      scenario "discover_out=$line" "clickhouse-status_out=$(ch_status missing)" "clickhouse-login_out=$(ch_users_xml)" \
        "plan_out=Backups for shop: ClickHouse's own BACKUP, and each new part as it appears." \
        "wait_out=✓ shop is protected. The first full backup is running." "status_out=db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake"
      ;;
    opensearch)
      line="9200\t-\t3\t-\t/var/lib/opensearch\t8192\topensearch\tno\t-\t-\t8 KiB\topensearch.service\t-\topensearch"
      scenario "discover_out=$line" "opensearch-status_out=$(os_status missing)" "opensearch-login_rc=11\n0" \
        "opensearch-login_out=Rowsafe's OpenSearch user \"rowsafe\" is ready; its password is saved for the agent only." \
        "plan_out=Backups for shop: OpenSearch's own snapshots." \
        "wait_out=✓ shop is protected. The first full backup is running." "status_out=db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake"
      # Refused before anything changes: a server too small for OpenSearch.
      printf 'MemTotal:        2014280 kB\n' >"$W/meminfo-2g"
      expect_fail "--install-opensearch on 2 GB refused" "OpenSearch needs a server with at least 4 GB of memory, and this one has 1967 MB" \
        env ROWSAFE_MEMINFO="$W/meminfo-2g" "$INSTALLER" rse_secrettoken123 --no-prompt --install-opensearch "$ver"
      [ ! -e /etc/rowsafe ] && [ -z "$(ls /etc/apt/sources.list.d/rowsafe-* 2>/dev/null)" ] || fail "$name: something was written"
      # The rest as on a 4 GB server (the container sees the host's memory).
      printf 'MemTotal:        4000000 kB\n' >"$W/meminfo-4g"
      export ROWSAFE_MEMINFO="$W/meminfo-4g"
      ;;
    qdrant)
      line="6333\t-\t1\t-\t/var/lib/qdrant/storage\t8192\tqdrant\tno\t-\t-\t8 KiB\tqdrant.service\t-\tqdrant"
      scenario "discover_out=$line" "qdrant-status_out=$(qd_status missing)" "qdrant-login_out=jwt=true" \
        "plan_out=Backups for shop: Qdrant's own snapshots, encrypted on this server." \
        "wait_out=✓ shop is protected. The first full backup is running." "status_out=db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake"
      ;;
    valkey)
      line="6380\t-\t8\t-\t/var/lib/valkey\t8192\tvalkey\tno\t-\t-\t8 KiB\tvalkey-server.service\t-\tvalkey"
      scenario "discover_out=$line" "redis-status_out=login=missing\nversion=8.0.0\nconfig=/etc/valkey/valkey.conf\naclfile=/etc/valkey/users.acl\ncluster=no\nbinary=/usr/bin/valkey-server" \
        "redis-login_rc=11\n0" "redis-login_out=persisted=aclfile" \
        "plan_out=Backups for shop: Valkey's own replication stream." \
        "wait_out=✓ shop is protected. The first full backup is running." "status_out=db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake"
      ;;
    *)
      line="3306\t/run/mysqld/mysqld.sock\t$ver\t-\t/var/lib/mysql\t8192\t$engine\tno\t-\t-\t1.2 MiB\t$unit.service\t-\t$engine"
      scenario "discover_out=$line" "plan_out=Restart: $label needs one quick restart (binary log settings)." apply_rc=10 \
        "wait_out=✓ shop is protected. The first full backup is running." "status_out=db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake"
      ;;
  esac

  cloud_init() {
    sh -c 'w=$1; shift; ROWSAFE_RELEASES_URL=https://localhost:18443/agent ROWSAFE_RESTIC_URL=https://localhost:18443/restic ROWSAFE_MEILISEARCH_URL=https://localhost:18443/meilisearch sh -s -- "$@" <"$w/install.sh"' \
      cloud-init "$W" rse_secrettoken123 --no-prompt --install-"$engine" "$ver" --listen-public --storage rowsafe --protect shop \
      --allow-restart --firewall-ssh
  }
  expect_ok "one run, as cloud-init: $label $ver, network, firewall, Rowsafe Storage, protected" cloud_init
  [ -z "${TEST_SHOW:-}" ] || cat "$W/out"
  cp "$W/out" "$W/first.out"
  [ "$(cat "/etc/rowsafe/installed-$engine")" = "$ver" ] || fail "$name: no record of the installed version"
  systemctl is-active --quiet "$unit" && systemctl is-enabled --quiet "$unit" || fail "$name: $unit isn't running and enabled"
  grep -q "the $label on this server" "$W/out" || fail "$name: the installer doesn't speak of $label"
  [ "$(stat -c '%U %a' /etc/rowsafe/agent.env)" = "$user 600" ] || fail "$name: the agent doesn't run as $user"
  # (Only the permissions summary may say what is for PostgreSQL only.)
  ! grep -i postgresql "$W/out" | grep -qv '^ *unavailable ' || { grep -i postgresql "$W/out" >&2; fail "$name: the output speaks of PostgreSQL"; }
  gen=$(sed -n "s/^ROWSAFE_REPO_CIPHER_PASS='\([A-Za-z0-9]\{40\}\)'\$/\1/p" /etc/rowsafe/agent.env)
  [ "${#gen}" = 40 ] || fail "$name: no generated passphrase"
  ! grep -qF "$gen" "$W/out" || fail "$name: the passphrase was printed"
  ! grep -q rse_secrettoken123 "$W/out" || fail "$name: the token was printed"
  called "plan --name shop --port $port"
  called "wait --database db_fake --timeout 3m"
  # The firewall closed the ports before the server listened publicly.
  closed=$(grep -n "closed to everyone but this server" "$W/out" | head -n 1 | cut -d: -f1)
  public=$(grep -n "$label listens on the network" "$W/out" | head -n 1 | cut -d: -f1)
  [ -n "$closed" ] && [ -n "$public" ] && [ "$closed" -lt "$public" ] || fail "$name: the ports weren't closed before $label listened on the network"
  ip=$(hostname -i | awk '{ print $1 }')
  nft list table inet rowsafe >"$W/nft" || fail "$name: no firewall table"

  case $engine in
    mysql | mariadb) cloud_mysql_checks ;;
    valkey) cloud_valkey_checks ;;
    clickhouse) cloud_clickhouse_checks ;;
    opensearch) cloud_opensearch_checks ;;
    qdrant) cloud_qdrant_checks && cloud_qdrant_update ;;
    meilisearch) cloud_meilisearch_checks && cloud_meilisearch_update ;;
  esac
  pass "$label $ver: installed from its own source with its key checked, secure defaults, TLS from the network, protected"

  # Again: nothing changes, nothing restarts.
  pid=$(systemctl show -p MainPID --value "$unit")
  case $engine in
    meilisearch)
      cp /etc/systemd/system/meilisearch.service "$W/meili.unit"
      cp /etc/systemd/system/rowsafe-meilisearch-tls.service "$W/front.unit"
      fpid=$(systemctl show -p MainPID --value rowsafe-meilisearch-tls)
      scenario "discover_out=7700\t-\t1\t-\t/var/lib/meilisearch/data/data.ms\t8192\tshop\tyes\tactive\t-\t8 KiB\tmeilisearch.service\tdb_fake\tmeilisearch" \
        "meilisearch-status_out=answers=yes\ntls=no\nversion=1.54.3\nlogin=ok" plan_rc=5 "plan_out=shop is already protected." \
        "status_out=db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake"
      ;;
    clickhouse)
      for f in /etc/clickhouse-server/config.d/zz-rowsafe.xml /etc/clickhouse-server/config.d/zz-rowsafe-network.xml \
        /etc/clickhouse-server/users.d/zz-rowsafe-admin.xml /etc/clickhouse-server/users.d/rowsafe.xml /etc/apt/preferences.d/rowsafe-clickhouse; do
        cp "$f" "$W/$(basename "$f").before"
      done
      scenario "discover_out=8123\t-\t$ver\t-\t/var/lib/clickhouse\t8192\tshop\tyes\tactive\t-\t8 KiB\tclickhouse-server.service\tdb_fake\tclickhouse" \
        "clickhouse-status_out=$(ch_status ok)" plan_rc=5 "plan_out=shop is already protected." \
        "status_out=db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake"
      ;;
    opensearch)
      for f in $(os_files); do cp "$f" "$W/$(basename "$f").before"; done
      scenario "discover_out=9200\t-\t3\t-\t/var/lib/opensearch\t8192\tshop\tyes\tactive\t-\t8 KiB\topensearch.service\tdb_fake\topensearch" \
        "opensearch-status_out=$(os_status ok)" plan_rc=5 "plan_out=shop is already protected." \
      ;;
    qdrant)
      for f in /etc/qdrant/config.yaml /etc/qdrant/qdrant.env /etc/systemd/system/qdrant.service /etc/rowsafe/qdrant/api-key \
        /etc/rowsafe/qdrant/alt-api-key /etc/rowsafe/qdrant/read-only-api-key /etc/ssl/rowsafe-qdrant/rowsafe-server.crt; do
        cp "$f" "$W/$(basename "$f").before"
      done
      scenario "discover_out=6333\t-\t1\t-\t/var/lib/qdrant/storage\t8192\tshop\tyes\tactive\t-\t8 KiB\tqdrant.service\tdb_fake\tqdrant" \
        "qdrant-status_out=$(qd_status ok)" plan_rc=5 "plan_out=shop is already protected." \
        "status_out=db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake"
      ;;
    valkey)
      # What the agent does later: its own user kept with ACL SAVE, the
      # certificate reloaded with CONFIG SET and CONFIG REWRITE (quotes).
      printf 'AUTH admin %s\nACL SETUSER rowsafe on >agent-password-for-the-test ~* &* +@all\nACL SAVE\nCONFIG SET tls-cert-file /etc/ssl/rowsafe-valkey/rowsafe-server.crt\nCONFIG REWRITE\n' \
        "$(cat /etc/rowsafe/valkey/admin-password)" | valkey-cli -s /run/valkey/valkey-server.sock >"$W/cli" 2>&1
      [ "$(grep -c '^OK$' "$W/cli")" = 5 ] || { cat "$W/cli" >&2; fail "the agent's ACL SAVE and CONFIG REWRITE"; }
      grep -q '^tls-cert-file "/etc/ssl/rowsafe-valkey/rowsafe-server.crt"$' /etc/valkey/valkey.conf || fail "CONFIG REWRITE didn't quote (the test expects it to)"
      cp /etc/valkey/users.acl "$W/users.acl"
      cp /etc/valkey/valkey.conf "$W/valkey.conf"
      scenario "discover_out=6380\t-\t8\t-\t/var/lib/valkey\t8192\tshop\tyes\tactive\t-\t8 KiB\tvalkey-server.service\tdb_fake\tvalkey" \
        "redis-status_out=login=ok\nversion=8.0.0\nrights=ok\nbinary=/usr/bin/valkey-server" plan_rc=5 "plan_out=shop is already protected." \
        "status_out=db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake"
      ;;
    *)
      cp "$(cloud_net_conf)" "$W/net.cnf"
      scenario "discover_out=3306\t/run/mysqld/mysqld.sock\t$ver\t-\t/var/lib/mysql\t8192\tshop\tyes\tactive\t-\t1.2 MiB\t$unit.service\tdb_fake\t$engine" \
        plan_rc=5 "plan_out=shop is already protected." "status_out=db_fake\tshop\tactive\trunning\thttps://app.rowsafe.test/databases/db_fake"
      ;;
  esac
  cp /var/lib/rowsafe-firewall/port-"$port" "$W/fw-port" 2>/dev/null || true
  expect_ok "re-run changes nothing" cloud_init
  grep -q "$label $ver is installed (by an earlier run of this installer)" "$W/out" || fail "$name: not recognized as its own"
  grep -q "$label listens on the network.*nothing to change" "$W/out" || fail "$name: --listen-public changed something"
  grep -q "the $label on this server" "$W/out" || fail "$name: the re-run took this server for another engine"
  [ "$(systemctl show -p MainPID --value "$unit")" = "$pid" ] || fail "$name: $label was restarted"
  [ "$(stat -c '%U' /etc/rowsafe/agent.env)" = "$user" ] || fail "$name: the agent's user changed"
  not_called "apply"
  case $engine in
    clickhouse)
      for f in /etc/clickhouse-server/config.d/zz-rowsafe.xml /etc/clickhouse-server/config.d/zz-rowsafe-network.xml \
        /etc/clickhouse-server/users.d/zz-rowsafe-admin.xml /etc/clickhouse-server/users.d/rowsafe.xml /etc/apt/preferences.d/rowsafe-clickhouse; do
        cmp -s "$f" "$W/$(basename "$f").before" || fail "$name: $f changed"
      done
      not_called "clickhouse-login"
      ;;
    opensearch)
      for f in $(os_files); do
        cmp -s "$f" "$W/$(basename "$f").before" || fail "$name: $f changed"
      done
      not_called "opensearch-login"
      ;;
    qdrant)
      for f in /etc/qdrant/config.yaml /etc/qdrant/qdrant.env /etc/systemd/system/qdrant.service /etc/rowsafe/qdrant/api-key \
        /etc/rowsafe/qdrant/alt-api-key /etc/rowsafe/qdrant/read-only-api-key /etc/ssl/rowsafe-qdrant/rowsafe-server.crt; do
        cmp -s "$f" "$W/$(basename "$f").before" || fail "$name: $f changed"
      done
      not_called "qdrant-login"
      ;;
    valkey)
      cmp -s /etc/valkey/users.acl "$W/users.acl" || fail "$name: the ACL file changed"
      cmp -s /etc/valkey/valkey.conf "$W/valkey.conf" || { diff "$W/valkey.conf" /etc/valkey/valkey.conf >&2; fail "$name: valkey.conf changed"; }
      ;;
    meilisearch)
      cmp -s /etc/systemd/system/meilisearch.service "$W/meili.unit" || fail "$name: Meilisearch's unit changed"
      cmp -s /etc/systemd/system/rowsafe-meilisearch-tls.service "$W/front.unit" || fail "$name: the TLS front's unit changed"
      [ "$(systemctl show -p MainPID --value rowsafe-meilisearch-tls)" = "$fpid" ] || fail "$name: the TLS front was restarted"
      not_called "meilisearch-login"
      ;;
    *) cmp -s "$(cloud_net_conf)" "$W/net.cnf" || fail "$name: the network settings changed" ;;
  esac
  pass "re-run: nothing changed, nothing restarted, still $label's agent"

  # Another engine, another version, or the same one not installed by Rowsafe: refused.
  other=valkey other_ver=8 other_label=Valkey
  [ "$engine" != qdrant ] || [ "$os" != "debian 13" ] || other=clickhouse other_ver=26.8 other_label=ClickHouse
  [ "$engine" != valkey ] || other=mariadb other_ver=11.8 other_label=MariaDB
  if [ "$engine" = clickhouse ]; then
    alt=26.3
    [ "$ver" != 26.3 ] || alt=26.8
    expect_fail "another ClickHouse version refused" "ClickHouse $ver is already installed on this server (by an earlier run of this installer)" \
      "$INSTALLER" --no-prompt --install-clickhouse "$alt" --no-setup
  fi
  expect_fail "--install-$other on this $label server refused" "is already installed on this server, so --install-$other won't install $other_label next to it" \
    "$INSTALLER" --no-prompt --install-"$other" "$other_ver" --no-setup
  if [ "$engine" = mariadb ]; then
    alt=11.4
    [ "$ver" != 11.4 ] || alt=11.8
    if [ "$os" != "debian 13" ]; then
      expect_fail "another MariaDB version refused" "MariaDB $ver is already installed on this server (by an earlier run of this installer)" \
        "$INSTALLER" --no-prompt --install-mariadb "$alt" --no-setup
    fi
  fi
  mv "/etc/rowsafe/installed-$engine" "$W/installed"
  expect_fail "$label not installed by Rowsafe refused" "already installed on this server" "$INSTALLER" --no-prompt --install-"$engine" "$ver" --no-setup
  mv "$W/installed" "/etc/rowsafe/installed-$engine"
  pass "refused on a server with a database server --install-$engine didn't install"
}

# cloud_net_conf: where --install-mysql/-mariadb keeps the network settings.
cloud_net_conf() {
  if [ "$engine" = mariadb ]; then echo /etc/mysql/mariadb.conf.d/zz-rowsafe-network.cnf; else echo /etc/mysql/conf.d/zz-rowsafe-network.cnf; fi
}

# cloud_mysql_checks: MySQL or MariaDB after the cloud-init run.
cloud_mysql_checks() {
  cli=mysql
  [ "$engine" != mariadb ] || cli=mariadb
  q() { "$cli" --protocol=socket -u root -N -B -e "$1"; }
  if [ "$engine" = mysql ]; then
    grep -q "Oracle's MySQL repository (repo.mysql.com, mysql-8.4-lts, key BCA43417C3B485DD128EC6D4B7B3B788A8D3785C)" "$W/out" || fail "$name: no word about the repository"
    # shellcheck disable=SC1091
    grep -qx "deb \[signed-by=/usr/share/keyrings/rowsafe-mysql.gpg\] https://repo.mysql.com/apt/$(. /etc/os-release && echo "$ID $VERSION_CODENAME") mysql-8.4-lts" \
      /etc/apt/sources.list.d/rowsafe-mysql.list || fail "$name: rowsafe-mysql.list"
    grep -qx 'Pin: origin repo.mysql.com' /etc/apt/preferences.d/rowsafe-mysql || fail "$name: no pin"
    pkg=mysql-community-server
    dpkg-query -W -f '${Version}\n' "$pkg" | grep -q '^8\.4\.' || fail "$name: $pkg isn't 8.4"
    apt-cache policy "$pkg" | grep -A1 '^ \*\*\*' | grep -q 'repo.mysql.com' || fail "$name: $pkg isn't Oracle's"
    [ "$(q "SELECT plugin FROM mysql.user WHERE User = 'root' AND Host = 'localhost'")" = auth_socket ] || fail "$name: root isn't auth_socket"
    [ "$(q "SELECT COUNT(*) FROM mysql.user WHERE User = '' OR (User = 'root' AND Host <> 'localhost')")" = 0 ] || fail "$name: anonymous or remote root"
    dpkg -s percona-xtrabackup-84 >/dev/null 2>&1 || fail "$name: Percona XtraBackup 8.4 not installed"
    ! ss -ltnH | awk '{ print $4 }' | grep -q ':33060$' || fail "$name: MySQL's X Protocol listens"
  else
    grep -q "MariaDB's repository (dlm.mariadb.com, $ver, key 177F4010FE56CA3336300305F1656F24C74CD1D8)" "$W/out" || fail "$name: no word about the repository"
    # shellcheck disable=SC1091
    grep -qx "deb \[signed-by=/usr/share/keyrings/rowsafe-mariadb.gpg\] https://dlm.mariadb.com/repo/mariadb-server/$ver/repo/$(. /etc/os-release && echo "$ID $VERSION_CODENAME") main" \
      /etc/apt/sources.list.d/rowsafe-mariadb.list || fail "$name: rowsafe-mariadb.list"
    grep -qx 'Pin: release o=MariaDB' /etc/apt/preferences.d/rowsafe-mariadb || fail "$name: no pin"
    for pkg in mariadb-server mariadb-client mariadb-backup mariadb-common; do
      dpkg-query -W -f '${Version}\n' "$pkg" | grep -q "^1:$ver\.[0-9]*+maria" || fail "$name: $pkg isn't MariaDB's own $ver ($(dpkg-query -W -f '${Version}' "$pkg"))"
    done
    [ "$(q "SELECT JSON_VALUE(Priv, '\$.plugin') FROM mysql.global_priv WHERE User = 'root' AND Host = 'localhost'")" = unix_socket ] || fail "$name: root isn't unix_socket"
    [ "$(q "SELECT COUNT(*) FROM mysql.global_priv WHERE User = '' OR (User = 'root' AND Host <> 'localhost')")" = 0 ] || fail "$name: anonymous or remote root"
  fi
  [ -z "$(q "SHOW DATABASES LIKE 'test'")" ] || fail "$name: a test database"
  called "mysql-account"
  grep -q "$label restarted" "$W/out" || fail "$name: the new $label wasn't restarted for backups"
  called "apply --database db_fake"
  [ "$(stat -c '%U %G %a' /etc/mysql/rowsafe-tls)" = "mysql mysql 750" ] || fail "$name: certificate folder owner/mode"
  [ "$(stat -c '%U %G %a' /etc/mysql/rowsafe-tls/rowsafe-server.crt)" = "mysql mysql 644" ] || fail "$name: certificate owner/mode"
  [ "$(stat -c '%U %G %a' /etc/mysql/rowsafe-tls/rowsafe-server.key)" = "mysql mysql 600" ] || fail "$name: key owner/mode"
  [ ! -e /var/lib/mysql/rowsafe-server.key ] || fail "$name: the key is in the data directory (backups would carry it)"
  grep -qx 'ReadWritePaths=-/etc/mysql/rowsafe-tls' /etc/systemd/system/rowsafe-agent.service.d/10-mysql.conf || fail "$name: the agent can't replace the certificate"
  conf=$(cloud_net_conf)
  [ "$(stat -c '%U %G %a' "$conf")" = "root root 644" ] || fail "$name: $conf owner/mode"
  grep -qx 'bind-address = \*' "$conf" && grep -qx 'require_secure_transport = ON' "$conf" &&
    grep -qx 'ssl_cert = /etc/mysql/rowsafe-tls/rowsafe-server.crt' "$conf" && grep -qx 'ssl_key = /etc/mysql/rowsafe-tls/rowsafe-server.key' "$conf" &&
    grep -qx 'tls_version = TLSv1.2,TLSv1.3' "$conf" || { cat "$conf" >&2; fail "$name: $conf"; }
  [ "$(q 'SELECT @@bind_address')" = '*' ] || fail "$name: bind_address is $(q 'SELECT @@bind_address')"
  ss -ltnH | awk '{ print $4 }' | grep -Eqx '(\*|0\.0\.0\.0):3306' || fail "$name: not listening on every IPv4 address"
  grep -q 'tcp dport 3306 drop' "$W/nft" && [ -e /var/lib/rowsafe-firewall/port-3306 ] || { cat "$W/nft" >&2; fail "$name: port 3306 isn't closed by the firewall"; }
  grep -qx 3306 /etc/rowsafe/firewall-allowed || fail "$name: 3306 isn't in the firewall's allow list"
  grep -q "$label's port (3306) is closed to everyone but this server" "$W/out" || fail "$name: no word about the firewall"
  # From the network: TLS only.
  q "CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY 'app-password-for-the-test'"
  if [ "$engine" = mysql ]; then tls=--ssl-mode=REQUIRED notls=--ssl-mode=DISABLED; else tls='--ssl --ssl-verify-server-cert=0' notls=--skip-ssl; fi
  # shellcheck disable=SC2086 # options
  c=$(MYSQL_PWD=app-password-for-the-test "$cli" -h "$ip" -u app $tls -N -B -e "SHOW STATUS LIKE 'Ssl_cipher'" 2>&1 | cut -f2)
  [ -n "$c" ] && ! printf '%s' "$c" | grep -q ERROR || fail "TLS login from the network: $c"
  # shellcheck disable=SC2086 # options
  if MYSQL_PWD=app-password-for-the-test "$cli" -h "$ip" -u app $notls -e 'SELECT 1' >"$W/out" 2>&1; then fail "a login without TLS was accepted"; fi
  grep -q "insecure transport are prohibited" "$W/out" || { cat "$W/out" >&2; fail "a login without TLS wasn't refused"; }
  echo | openssl s_client -starttls mysql -connect "$ip:3306" 2>/dev/null | openssl x509 -noout -fingerprint -sha256 >"$W/fp" &&
    [ "$(cat "$W/fp")" = "$(openssl x509 -in /etc/mysql/rowsafe-tls/rowsafe-server.crt -noout -fingerprint -sha256)" ] || fail "the server doesn't present its certificate"
  q "DROP USER 'app'@'%'"
  # The agent replaces the certificate later and reloads it (same files).
  if [ "$engine" = mysql ]; then q 'ALTER INSTANCE RELOAD TLS'; else q 'FLUSH SSL'; fi
  # pgBackRest (the storage test) brings a postgres user; still a MySQL server.
  pass "$label from the network: TLS only, its certificate at the exact paths"
}

# cloud_valkey_checks: Valkey after the cloud-init run.
cloud_valkey_checks() {
  if [ "$os" = "debian 12" ]; then
    grep -qx 'deb \[signed-by=/usr/share/keyrings/debian-archive-keyring.gpg\] https://deb.debian.org/debian bookworm-backports main' \
      /etc/apt/sources.list.d/rowsafe-bookworm-backports.list || fail "$name: no bookworm-backports source"
    dpkg-query -W -f '${Version}\n' valkey-server | grep -q '^8\..*bpo12' || fail "$name: valkey-server isn't bookworm-backports' 8"
  else
    [ ! -e /etc/apt/sources.list.d/rowsafe-bookworm-backports.list ] || fail "$name: backports added on $os"
    dpkg-query -W -f '${Version}\n' valkey-server | grep -q '^8\.' || fail "$name: valkey-server isn't 8"
  fi
  ! command -v pgbackrest >/dev/null 2>&1 || fail "$name: pgBackRest installed for Valkey"
  [ "$(stat -c '%U %G %a' /etc/rowsafe/valkey)" = "root root 700" ] || fail "$name: /etc/rowsafe/valkey owner/mode"
  [ "$(stat -c '%U %G %a' /etc/rowsafe/valkey/admin-password)" = "root root 600" ] || fail "$name: admin-password owner/mode"
  pw=$(cat /etc/rowsafe/valkey/admin-password)
  printf '%s\n' "$pw" | grep -Eqx '[0-9a-f]{64}' || fail "$name: the admin password isn't 64 hex digits"
  ! grep -qF "$pw" "$W/out" || fail "$name: the admin password was printed"
  [ "$(stat -c '%U %G %a' /etc/valkey/users.acl)" = "valkey valkey 640" ] || fail "$name: users.acl owner/mode"
  grep -q '^user default off' /etc/valkey/users.acl || fail "$name: the default user isn't off"
  grep -q "^user admin on .*#$(printf '%s' "$pw" | sha256sum | cut -d' ' -f1) " /etc/valkey/users.acl || fail "$name: no admin in users.acl"
  for l in 'aclfile /etc/valkey/users.acl' 'appendonly yes' 'appendfsync everysec' 'bind \* -::\*' 'port 0' 'tls-port 6380' \
    'unixsocket /run/valkey/valkey-server.sock' 'unixsocketperm 700' \
    'tls-cert-file /etc/ssl/rowsafe-valkey/rowsafe-server.crt' 'tls-key-file /etc/ssl/rowsafe-valkey/rowsafe-server.key' \
    'tls-auth-clients no' 'tls-protocols "TLSv1.2 TLSv1.3"'; do
    [ "$(grep -c "^$l\$" /etc/valkey/valkey.conf)" = 1 ] || fail "$name: valkey.conf lacks '$l' (once)"
  done
  [ "$(stat -c '%U %G %a' /etc/valkey/valkey.conf)" = "valkey valkey 640" ] || fail "$name: valkey.conf owner/mode"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-valkey)" = "rowsafe valkey 2750" ] || fail "$name: certificate folder owner/mode"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-valkey/rowsafe-server.key)" = "rowsafe valkey 640" ] || fail "$name: key owner/mode"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-valkey/rowsafe-server.crt)" = "rowsafe valkey 644" ] || fail "$name: certificate owner/mode"
  grep -qx 'ReadWritePaths=-/etc/ssl/rowsafe-valkey' /etc/systemd/system/rowsafe-agent.service.d/10-redis.conf || fail "$name: the agent can't replace the certificate"
  # Rowsafe's own user, created with the administrator's login (on stdin).
  called "redis-login --port 6380 --engine valkey --admin-user admin"
  [ "$(cat "$F/redis-login.stdin")" = "$pw" ] || fail "$name: the agent didn't get the administrator's password on stdin"
  called "apply --database db_fake"
  # No plain port at all; the socket is root's and valkey's; TLS on 6380 from the network.
  ! ss -ltnH | awk '{ print $4 }' | grep -q ':6379$' || fail "Valkey still listens in plain text on 6379"
  [ "$(stat -c '%U %a' /run/valkey/valkey-server.sock)" = "valkey 700" ] || fail "$name: socket owner/mode"
  [ "$(echo PING | valkey-cli -s /run/valkey/valkey-server.sock 2>&1 | head -n 1)" = "NOAUTH Authentication required." ] || fail "the socket answers without a password"
  [ "$(printf 'AUTH default x\n' | valkey-cli -s /run/valkey/valkey-server.sock 2>&1 | head -n 1 | cut -c1-9)" != OK ] || fail "the default user signs in"
  [ "$(printf 'AUTH admin %s\nPING\n' "$pw" | valkey-cli -h "$ip" -p 6380 --tls --insecure 2>&1 | sed -n 2p)" = PONG ] || fail "TLS login on 6380"
  if echo PING | valkey-cli -h "$ip" -p 6380 >"$W/cli" 2>&1 && grep -q PONG "$W/cli"; then fail "plain text on the TLS port"; fi
  echo | openssl s_client -connect "$ip:6380" 2>/dev/null | openssl x509 -noout -fingerprint -sha256 >"$W/fp" &&
    [ "$(cat "$W/fp")" = "$(openssl x509 -in /etc/ssl/rowsafe-valkey/rowsafe-server.crt -noout -fingerprint -sha256)" ] || fail "Valkey doesn't present its certificate"
  p=6380
  grep -q "tcp dport $p drop" "$W/nft" && [ -e "/var/lib/rowsafe-firewall/port-$p" ] || { cat "$W/nft" >&2; fail "$name: port $p isn't closed by the firewall"; }
  grep -qx "$p" /etc/rowsafe/firewall-allowed || fail "$name: $p isn't in the firewall's allow list"
  grep -Eq "Valkey's ports? \((6379, )?6380\) (is|are) closed to everyone but this server" "$W/out" || fail "$name: no word about the firewall"
  pass "Valkey from the network: TLS on 6380 only (no plain port), passwords only, the certificate at the exact paths, closed by the firewall"
}

# cloud_meilisearch_checks: Meilisearch after the cloud-init run.
cloud_meilisearch_checks() {
  mver=$(sed -n 's/^MEILI_VERSION=//p' "$W/install.sh")
  bin=/usr/local/lib/meilisearch/$mver/meilisearch
  [ "$(stat -c '%U %G %a' "$bin")" = "root root 755" ] && [ "$(readlink /usr/local/bin/meilisearch)" = "$bin" ] || fail "$name: the program's owner, mode or link"
  sum=$(sed -n "s/^MEILI_SHA256_$(echo "$arch" | tr a-z A-Z)=//p" "$W/install.sh")
  [ "$(sha256sum "$bin" | cut -d' ' -f1)" = "$sum" ] || fail "$name: the program isn't the pinned Community Edition build"
  [ "$(/usr/local/bin/meilisearch --version)" = "meilisearch $mver" ] || fail "$name: version"
  grep -q "Meilisearch $mver (Community Edition), SHA-256 checked" "$W/out" || fail "$name: no word about the check"
  ! command -v pgbackrest >/dev/null 2>&1 || fail "$name: pgBackRest installed for Meilisearch"
  # The master key: root's only, never printed, handed to the agent once on stdin.
  [ "$(stat -c '%U %G %a' /etc/meilisearch/master-key.env)" = "root root 600" ] || fail "$name: master key file owner/mode"
  mk=$(sed -n 's/^MEILI_MASTER_KEY=//p' /etc/meilisearch/master-key.env)
  printf '%s\n' "$mk" | grep -Eqx '[0-9a-f]{64}' || fail "$name: the master key isn't 64 hex digits"
  ! grep -qF "$mk" "$W/out" || fail "$name: the master key was printed"
  ! grep -rqsF "$mk" /etc/rowsafe /var/lib/rowsafe /etc/systemd/system || fail "$name: the master key is in Rowsafe's files or a unit"
  called "meilisearch-login --port 7700 --local-port 7701 --binary /usr/local/bin/meilisearch --db-path /var/lib/meilisearch/data/data.ms --snapshot-dir /var/lib/meilisearch/snapshots --unit meilisearch.service --listen \* --rowsafe"
  [ "$(cat "$F/meilisearch-login.stdin")" = "$mk" ] || fail "$name: the agent didn't get the master key on stdin"
  called "apply --database db_fake"
  # The unit: its user, production, no analytics, this server only, sandboxed.
  u=/etc/systemd/system/meilisearch.service
  [ "$(systemctl show -p User --value meilisearch)" = meilisearch ] || fail "$name: not run as meilisearch"
  for want in '--env production' '--no-analytics' '--http-addr 127.0.0.1:7701' '--db-path /var/lib/meilisearch/data/data.ms' \
    '--snapshot-dir /var/lib/meilisearch/snapshots' '--max-indexing-memory '; do
    grep -q -- "^ExecStart=.*$want" "$u" || fail "$name: the unit lacks $want"
  done
  for want in EnvironmentFile=/etc/meilisearch/master-key.env NoNewPrivileges=yes ProtectSystem=strict ReadWritePaths=/var/lib/meilisearch \
    PrivateTmp=yes CapabilityBoundingSet= SystemCallFilter=@system-service; do
    grep -qx "$want" "$u" || fail "$name: the unit lacks $want"
  done
  [ "$(stat -c '%U %G %a' /var/lib/meilisearch/data)" = "meilisearch meilisearch 700" ] || fail "$name: the data folder's owner/mode"
  [ "$(stat -c '%U %G %a' /var/lib/meilisearch/snapshots)" = "meilisearch meilisearch 750" ] || fail "$name: the snapshot folder's owner/mode"
  d=/etc/systemd/system/rowsafe-agent.service.d/10-meilisearch.conf
  grep -qx 'User=rowsafe' "$d" && grep -qx 'SupplementaryGroups=meilisearch' "$d" && grep -qx 'ReadWritePaths=-/etc/ssl/rowsafe-meilisearch' "$d" ||
    { cat "$d" >&2; fail "$name: the agent's drop-in"; }
  # A key is needed; the master key works; plain HTTP only on 127.0.0.1.
  [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7701/indexes)" = 401 ] || fail "Meilisearch answers without a key"
  [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $mk" http://127.0.0.1:7701/indexes)" = 200 ] || fail "the master key doesn't work"
  ss -ltnH | awk '{ print $4 }' | grep -qx '127.0.0.1:7701' || fail "Meilisearch isn't on 127.0.0.1:7701"
  ! ss -ltnH | awk '{ print $4 }' | grep -Eq '^(0\.0\.0\.0|\*|\[::\]):7701$' || fail "Meilisearch's plain port listens beyond this server"
  if curl -s -m 5 "http://$ip:7701/health" >/dev/null 2>&1; then fail "plain HTTP reaches Meilisearch from the network"; fi
  # The snapshots are the agent's to read, the data isn't.
  curl -s -X POST -H "Authorization: Bearer $mk" http://127.0.0.1:7701/snapshots >/dev/null
  i=0
  until [ -s /var/lib/meilisearch/snapshots/data.ms.snapshot ] || [ "$i" -ge 30 ]; do
    sleep 1
    i=$((i + 1))
  done
  mgid=$(getent group meilisearch | cut -d: -f3)
  setpriv --reuid=rowsafe --regid=rowsafe --groups="$mgid" test -r /var/lib/meilisearch/snapshots/data.ms.snapshot ||
    fail "the agent can't read Meilisearch's snapshot"
  if setpriv --reuid=rowsafe --regid=rowsafe --groups="$mgid" ls /var/lib/meilisearch/data >/dev/null 2>&1; then
    fail "the agent can read Meilisearch's data folder"
  fi
  # Rowsafe's TLS front: HTTPS on 7700 with the certificate at the exact paths.
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-meilisearch)" = "rowsafe rowsafe-meilisearch-tls 2750" ] || fail "$name: certificate folder owner/mode"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-meilisearch/rowsafe-server.key)" = "rowsafe rowsafe-meilisearch-tls 640" ] || fail "$name: key owner/mode"
  [ "$(stat -c '%U %G %a' /usr/local/lib/rowsafe/rowsafe-meilisearch-tls)" = "root root 755" ] || fail "$name: the front's program isn't root's"
  f=/etc/systemd/system/rowsafe-meilisearch-tls.service
  grep -qx User=rowsafe-meilisearch-tls "$f" && grep -qx MemoryDenyWriteExecute=yes "$f" && grep -qx CapabilityBoundingSet= "$f" || fail "$name: the front's unit"
  systemctl is-active --quiet rowsafe-meilisearch-tls && systemctl is-enabled --quiet rowsafe-meilisearch-tls || fail "$name: the front isn't running and enabled"
  fu=$(ps -o uid= -p "$(systemctl show -p MainPID --value rowsafe-meilisearch-tls)" | tr -d ' ')
  [ "$fu" = "$(id -u rowsafe-meilisearch-tls)" ] || fail "$name: the front runs as uid '$fu'"
  ! id -nG rowsafe-meilisearch-tls | tr ' ' '\n' | grep -qx meilisearch || fail "$name: the front's user is in Meilisearch's group"
  [ "$(curl -sk -o /dev/null -w '%{http_code}' "https://$ip:7700/indexes")" = 401 ] || fail "HTTPS on 7700 without a key isn't refused"
  [ "$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $mk" "https://$ip:7700/indexes")" = 200 ] || fail "HTTPS on 7700 with the key"
  curl -sk -X POST -H "Authorization: Bearer $mk" -H 'Content-Type: application/json' "https://$ip:7700/indexes/movies/documents" \
    --data '[{"id":1,"title":"Carol"},{"id":2,"title":"Heat"}]' >/dev/null
  i=0
  until curl -sk -H "Authorization: Bearer $mk" -H 'Content-Type: application/json' "https://$ip:7700/indexes/movies/search" --data '{"q":"heat"}' 2>/dev/null |
    grep -q '"Heat"'; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || fail "a search over HTTPS through the front"
    sleep 1
  done
  [ "$(curl -s -o "$W/plain" -w '%{http_code}' "http://$ip:7700/indexes")" = 400 ] && grep -q 'HTTPS only' "$W/plain" || fail "plain HTTP on 7700 isn't refused"
  if echo | openssl s_client -connect "$ip:7700" -tls1_1 >/dev/null 2>&1; then fail "TLS 1.1 accepted on 7700"; fi
  fp() { echo | openssl s_client -connect "$ip:7700" 2>/dev/null | openssl x509 -noout -fingerprint -sha256; }
  [ "$(fp)" = "$(openssl x509 -in /etc/ssl/rowsafe-meilisearch/rowsafe-server.crt -noout -fingerprint -sha256)" ] || fail "the front doesn't present the certificate"
  # A renewed certificate (as the agent writes it: certificate, then key) is
  # served without restarting anything.
  mpid=$(systemctl show -p MainPID --value meilisearch) fpid=$(systemctl show -p MainPID --value rowsafe-meilisearch-tls)
  # shellcheck disable=SC2016 # $1 expands in the inner shell
  (cd / && runuser -u rowsafe -- sh -c 'umask 027; cd "$1" &&
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj /CN=renewed.example \
      -keyout .new.key -out .new.crt >/dev/null 2>&1 && chmod 0644 .new.crt && chmod 0640 .new.key &&
    mv -f .new.crt rowsafe-server.crt && mv -f .new.key rowsafe-server.key' \
    renew /etc/ssl/rowsafe-meilisearch) || fail "renewing the certificate as the agent"
  i=0
  until [ "$(fp)" = "$(openssl x509 -in /etc/ssl/rowsafe-meilisearch/rowsafe-server.crt -noout -fingerprint -sha256)" ]; do
    i=$((i + 1))
    [ "$i" -lt 20 ] || fail "the renewed certificate isn't served"
    sleep 1
  done
  [ "$(systemctl show -p MainPID --value meilisearch)" = "$mpid" ] && [ "$(systemctl show -p MainPID --value rowsafe-meilisearch-tls)" = "$fpid" ] ||
    fail "renewing the certificate restarted something"
  # The firewall: 7700 closed before the front listened, nothing for 7701.
  grep -q 'tcp dport 7700 drop' "$W/nft" && [ -e /var/lib/rowsafe-firewall/port-7700 ] || { cat "$W/nft" >&2; fail "$name: port 7700 isn't closed by the firewall"; }
  grep -qx 7700 /etc/rowsafe/firewall-allowed && ! grep -qx 7701 /etc/rowsafe/firewall-allowed || fail "$name: the firewall's allow list"
  grep -q "Meilisearch's port (7700) is closed to everyone but this server" "$W/out" || fail "$name: no word about the firewall"
  grep -qx '7700 meilisearch.service' /etc/rowsafe/restart-allowed || fail "$name: restarts of meilisearch.service aren't allowed on 7700"
  pass "Meilisearch from the network: HTTPS only on 7700 (TLS 1.2+), plain HTTP refused, a renewed certificate served without a restart"
}

# ch_status LOGIN: what `rowsafe-agent clickhouse status` says of the new
# server (the stand-in agent says login=ok once root installed users.d/rowsafe.xml).
ch_status() {
  printf 'port=8123\nversion=%s\nlogin=%s\nuser=clickhouse\ndatadir=/var/lib/clickhouse/\nconfig=/etc/clickhouse-server/config.xml\nusersd=/etc/clickhouse-server/users.d\nunit=clickhouse-server.service\nbinary=/usr/bin/clickhouse\nreplicated=0\ndocker=no' \
    "$ver" "$1"
}

# ch_users_xml: Rowsafe's own user as the agent's `clickhouse login
# --users-xml` makes it (internal/engine/clickhouse/setup.go), with a
# password the test knows.
ch_users_xml() {
  printf '<clickhouse>\n  <users>\n    <rowsafe>\n      <password_sha256_hex>%s</password_sha256_hex>\n      <networks>\n        <ip>127.0.0.1</ip>\n        <ip>::1</ip>\n      </networks>\n      <profile>default</profile>\n      <quota>default</quota>\n      <grants>\n        <query>GRANT SELECT, INSERT, BACKUP, KILL QUERY, ALTER UPDATE, ALTER DELETE, S3, CREATE DATABASE, CREATE TABLE, DROP DATABASE, DROP TABLE, ALTER TABLE ON *.*</query>\n        <query>GRANT ACCESS MANAGEMENT ON *.*</query>\n        <query>GRANT SELECT ON system.*</query>\n        <query>GRANT SYSTEM RELOAD CONFIG ON *.*</query>\n      </grants>\n    </rowsafe>\n  </users>\n</clickhouse>' \
    "$(printf '%s' agent-password-for-the-test | sha256sum | cut -d' ' -f1)"
}

# cloud_clickhouse_checks: ClickHouse after the cloud-init run.
cloud_clickhouse_checks() {
  grep -q "ClickHouse's repository (packages.clickhouse.com, lts, $ver.\*, key 3A9EA1193A97B548BE1457D48919F6BD2B48D754)" "$W/out" || fail "$name: no word about the repository"
  grep -qx 'deb \[signed-by=/usr/share/keyrings/rowsafe-clickhouse.gpg\] https://packages.clickhouse.com/deb lts main' /etc/apt/sources.list.d/rowsafe-clickhouse.list ||
    fail "$name: rowsafe-clickhouse.list"
  grep -qx "Pin: version $ver.\*" /etc/apt/preferences.d/rowsafe-clickhouse && grep -qx 'Pin: origin packages.clickhouse.com' /etc/apt/preferences.d/rowsafe-clickhouse ||
    fail "$name: no pin"
  for pkg in clickhouse-server clickhouse-client clickhouse-common-static; do
    dpkg-query -W -f '${Version}\n' "$pkg" | grep -q "^$ver\." || fail "$name: $pkg isn't $ver ($(dpkg-query -W -f '${Version}' "$pkg"))"
  done
  apt-cache policy clickhouse-server | awk '$1 == "Candidate:" { print $2 }' | grep -q "^$ver\." || fail "$name: apt would leave the $ver series"
  ! command -v pgbackrest >/dev/null 2>&1 || fail "$name: pgBackRest installed for ClickHouse"
  [ "$(stat -c '%U %G %a' /etc/rowsafe/clickhouse)" = "root root 700" ] || fail "$name: /etc/rowsafe/clickhouse owner/mode"
  [ "$(stat -c '%U %G %a' /etc/rowsafe/clickhouse/admin-password)" = "root root 600" ] || fail "$name: admin-password owner/mode"
  pw=$(cat /etc/rowsafe/clickhouse/admin-password)
  printf '%s\n' "$pw" | grep -Eqx '[0-9a-f]{64}' || fail "$name: the admin password isn't 64 hex digits"
  ! grep -qF "$pw" "$W/out" || fail "$name: the admin password was printed"
  adm=/etc/clickhouse-server/users.d/zz-rowsafe-admin.xml
  grep -q "<password_sha256_hex>$(printf '%s' "$pw" | sha256sum | cut -d' ' -f1)</password_sha256_hex>" "$adm" || fail "$name: no admin in $adm"
  ! grep -qF "$pw" "$adm" || fail "$name: the admin password itself is in $adm"
  [ "$(stat -c '%G %a' "$adm")" = "clickhouse 640" ] || fail "$name: $adm group/mode"
  chq() { # chq USER PASSWORD QUERY: on this server's plain HTTP port
    printf 'header = "X-ClickHouse-User: %s"\nheader = "X-ClickHouse-Key: %s"\n' "$1" "$2" | curl -sS -K - --data-binary "$3" http://127.0.0.1:8123/
  }
  [ "$(chq admin "$pw" 'SELECT currentUser()')" = admin ] || fail "$name: the administrator can't sign in on this server"
  chq default '' 'SELECT 1' | grep -q 'Authentication failed' || fail "$name: the default user signs in"
  curl -sS --data-binary 'SELECT 1' http://127.0.0.1:8123/ | grep -q 'Authentication failed' || fail "$name: anyone signs in as default"
  [ "$(chq admin "$pw" "SELECT count() FROM system.users WHERE name = 'default' AND toString(auth_type) LIKE '%no_password%'")" = 0 ] || fail "$name: default has no password"
  # Settings for a small server; no MySQL, PostgreSQL or interserver ports.
  [ "$(chq admin "$pw" "SELECT value FROM system.server_settings WHERE name = 'max_server_memory_usage_to_ram_ratio'")" = 0.75 ] || fail "$name: memory ratio"
  [ "$(chq admin "$pw" "SELECT value FROM system.server_settings WHERE name = 'cache_size_to_ram_max_ratio'")" = 0.1 ] || fail "$name: cache ratio"
  grep -q '<level>information</level>' /etc/clickhouse-server/config.d/zz-rowsafe.xml || fail "$name: log level"
  ! ss -ltnH | awk '{ print $4 }' | grep -Eq ':(9004|9005|9009)$' || { ss -ltn >&2; fail "$name: MySQL, PostgreSQL or interserver ports listen"; }
  # The data folder: the clickhouse group (the agent) reads it, again at every start.
  [ "$(stat -c '%U %G %a' /var/lib/clickhouse)" = "clickhouse clickhouse 750" ] || fail "$name: /var/lib/clickhouse owner/mode"
  grep -qx 'ExecStartPre=-/bin/chmod 0750 /var/lib/clickhouse' /etc/systemd/system/clickhouse-server.service.d/rowsafe.conf || fail "$name: no start drop-in"
  runuser -u rowsafe -g rowsafe -G clickhouse -- ls /var/lib/clickhouse/store >/dev/null || fail "$name: the agent (group clickhouse, as its unit gives it) can't read the data folder"
  # Rowsafe's own user, installed by root as a users.d file (no administrator asked).
  called "clickhouse-login --port 8123 --users-xml --rowsafe-server"
  [ "$(stat -c '%U %G %a' /etc/clickhouse-server/users.d/rowsafe.xml)" = "root clickhouse 640" ] || fail "$name: users.d/rowsafe.xml owner/mode"
  [ "$(chq rowsafe agent-password-for-the-test 'SELECT currentUser()')" = rowsafe ] || fail "$name: Rowsafe's user can't sign in"
  called "apply --database db_fake"
  grep -qx 'SupplementaryGroups=clickhouse' /etc/systemd/system/rowsafe-agent.service.d/10-clickhouse.conf &&
    grep -qx 'ReadWritePaths=-/etc/ssl/rowsafe-clickhouse' /etc/systemd/system/rowsafe-agent.service.d/10-clickhouse.conf || fail "$name: the agent's drop-in"
  # TLS: the certificate at the exact paths; plain ports on 127.0.0.1 only.
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-clickhouse)" = "rowsafe clickhouse 2750" ] || fail "$name: certificate folder owner/mode"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-clickhouse/rowsafe-server.key)" = "rowsafe clickhouse 640" ] || fail "$name: key owner/mode"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-clickhouse/rowsafe-server.crt)" = "rowsafe clickhouse 644" ] || fail "$name: certificate owner/mode"
  ss -ltnH | awk '{ print $4 }' >"$W/listen"
  grep -qx '127.0.0.1:8123' "$W/listen" && grep -qx '127.0.0.1:9000' "$W/listen" || { cat "$W/listen" >&2; fail "$name: the plain ports aren't on 127.0.0.1"; }
  ! grep -Eq '^(\*|0\.0\.0\.0|\[::\]):(8123|9000)$' "$W/listen" || { cat "$W/listen" >&2; fail "$name: a plain port listens on every address"; }
  for p in 9440 8443; do
    grep -Eqx "(\*|0\.0\.0\.0|\[::\]):$p" "$W/listen" || { cat "$W/listen" >&2; fail "$name: $p doesn't listen on every address"; }
    grep -q "tcp dport $p drop" "$W/nft" && [ -e "/var/lib/rowsafe-firewall/port-$p" ] || { cat "$W/nft" >&2; fail "$name: port $p isn't closed by the firewall"; }
    grep -qx "$p" /etc/rowsafe/firewall-allowed || fail "$name: $p isn't in the firewall's allow list"
    echo | openssl s_client -connect "$ip:$p" 2>/dev/null | openssl x509 -noout -fingerprint -sha256 >"$W/fp" &&
      [ "$(cat "$W/fp")" = "$(openssl x509 -in /etc/ssl/rowsafe-clickhouse/rowsafe-server.crt -noout -fingerprint -sha256)" ] || fail "ClickHouse doesn't present its certificate on $p"
    if echo | openssl s_client -tls1_1 -connect "$ip:$p" >"$W/tls11" 2>&1 && grep -q 'Cipher is [A-Z]' "$W/tls11"; then fail "TLS 1.1 accepted on $p"; fi
  done
  grep -q "ClickHouse's ports (8443, 9440) are closed to everyone but this server" "$W/out" || fail "$name: no word about the firewall"
  ! grep -Eqx '8123|9000' /etc/rowsafe/firewall-allowed || fail "$name: the plain ports (this server's only) are in the firewall's allow list"
  # From the network: an app's user over TLS (native protocol and HTTPS); nothing plain.
  chq admin "$pw" "CREATE USER app IDENTIFIED WITH sha256_password BY 'app-password-for-the-test'" >/dev/null
  chq admin "$pw" 'GRANT SELECT ON system.one TO app' >/dev/null
  [ "$(clickhouse-client --host "$ip" --port 9440 --secure --accept-invalid-certificate --user app --password app-password-for-the-test -q 'SELECT 41 + 1' 2>&1)" = 42 ] ||
    fail "TLS login on 9440"
  [ "$(curl -sS -k -u app:app-password-for-the-test --data-binary 'SELECT 42' "https://$ip:8443/")" = 42 ] || fail "HTTPS login on 8443"
  if clickhouse-client --host "$ip" --port 9000 --user app --password app-password-for-the-test -q 'SELECT 1' >"$W/plain" 2>&1; then fail "plain native protocol from the network"; fi
  if curl -sS -u app:app-password-for-the-test --data-binary 'SELECT 1' "http://$ip:8123/" >"$W/plain" 2>&1; then fail "plain HTTP from the network"; fi
  if curl -sS -k --data-binary 'SELECT 1' "https://$ip:8443/" 2>&1 | grep -qx 1; then fail "HTTPS without a password"; fi
  # Access control: the system tables need a grant; no clusters (the
  # packages' test ones point elsewhere); apps' users (made like Databases &
  # users does, as Rowsafe's user) get rowsafe_app's limits and can't raise them.
  [ "$(chq admin "$pw" 'SELECT count() FROM system.clusters')" = 0 ] || fail "$name: clusters are configured"
  chq rowsafe agent-password-for-the-test "CREATE USER app2 IDENTIFIED WITH sha256_password BY 'app2-password-for-the-test' HOST ANY SETTINGS PROFILE 'rowsafe_app'" >/dev/null
  chq rowsafe agent-password-for-the-test 'CREATE DATABASE appdb2' >/dev/null
  chq rowsafe agent-password-for-the-test 'GRANT SELECT, INSERT, CREATE TABLE ON appdb2.* TO app2' >/dev/null
  [ "$(chq app2 app2-password-for-the-test 'SELECT count() FROM system.tables WHERE database = currentDatabase()')" = 0 ] || fail "$name: an app's user can't list its own tables"
  chq app2 app2-password-for-the-test 'SELECT count() FROM system.query_log' | grep -q 'ACCESS_DENIED' || fail "$name: an app's user reads system.query_log"
  chq app2 app2-password-for-the-test 'SELECT 1 SETTINGS max_memory_usage = 999999999999' | grep -q 'SETTING_CONSTRAINT_VIOLATION' || fail "$name: an app's user raised its memory limit"
  [ "$(chq app2 app2-password-for-the-test "SELECT getSetting('max_threads') <= $(nproc)")" = 1 ] || fail "$name: rowsafe_app's threads"
  chq admin "$pw" 'DROP USER app2' >/dev/null
  chq admin "$pw" 'DROP DATABASE appdb2' >/dev/null
  # The administrator signs in from this server's own addresses only (HOST
  # LOCAL; this container's address is one of them, so it is read, not tried).
  [ "$(chq admin "$pw" "SELECT empty(host_ip) AND host_names = ['localhost'] AND empty(host_names_regexp) FROM system.users WHERE name = 'admin'")" = 1 ] ||
    fail "$name: the administrator may sign in from elsewhere"
  chq admin "$pw" 'DROP USER app' >/dev/null
  # What the agent does with a renewed certificate: the same files, written
  # by the agent's user, loaded with SYSTEM RELOAD CONFIG; nothing restarts.
  pid=$(systemctl show -p MainPID --value clickhouse-server)
  # shellcheck disable=SC2016 # expands in the inner shell
  runuser -u rowsafe -- sh -c 'cd /etc/ssl/rowsafe-clickhouse && umask 027 &&
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj /CN=renewed.test \
      -keyout k.new -out c.new >/dev/null 2>&1 && chmod 0640 k.new && chmod 0644 c.new && mv -f k.new rowsafe-server.key && mv -f c.new rowsafe-server.crt' ||
    fail "the agent's user can't replace the certificate"
  [ -z "$(chq rowsafe agent-password-for-the-test 'SYSTEM RELOAD CONFIG')" ] || fail "Rowsafe's user can't SYSTEM RELOAD CONFIG"
  want=$(openssl x509 -in /etc/ssl/rowsafe-clickhouse/rowsafe-server.crt -noout -fingerprint -sha256)
  for p in 9440 8443; do
    [ "$(echo | openssl s_client -connect "127.0.0.1:$p" 2>/dev/null | openssl x509 -noout -fingerprint -sha256)" = "$want" ] || fail "the renewed certificate isn't served on $p"
  done
  [ "$(systemctl show -p MainPID --value clickhouse-server)" = "$pid" ] || fail "ClickHouse restarted for the certificate"
  pass "ClickHouse from the network: TLS only on 9440 and 8443, plain ports on this server only, a renewed certificate loaded without a restart"
}

# >>> opensearch
# opensearch_test_prep: OpenSearch's package from the host's cache (apt
# still checks it against the repository's signed index; the image's
# docker-clean would delete it after the first dpkg run), and the real
# agent for its OpenSearch helpers (the stand-in agent hands them over).
opensearch_test_prep() {
  rm -f /etc/apt/apt.conf.d/docker-clean
  for d in /os-cache/opensearch_*_"$arch".deb; do
    [ ! -f "$d" ] || cp "$d" /var/cache/apt/archives/
  done
  if [ -f "/go-release/rowsafe-agent-real-linux-$arch" ]; then
    install -m 0755 "/go-release/rowsafe-agent-real-linux-$arch" /usr/local/bin/rowsafe-agent-real
    echo "  (the real agent answers the OpenSearch helpers)"
  else
    echo "  (no real agent: the stand-in agent answers the OpenSearch helpers)"
  fi
}

# os_status LOGIN: what `rowsafe-agent opensearch status` says (the
# stand-in's answer, when the real agent isn't there).
os_status() {
  printf 'port=9200\nversion=3.9.0\nlogin=%s\nsecurity=on\ntls=on\nrepo=ok\nrepodir=/var/lib/rowsafe-opensearch/snapshots\nrestapi=ok\nhotreload=on\nnodes=1\nconfig=/etc/opensearch/opensearch.yml\nhome=/usr/share/opensearch\nunit=opensearch.service\nuser=opensearch' "$1"
}

# os_files: --install-opensearch's files, which a re-run must leave as they are.
os_files() {
  echo /etc/opensearch/opensearch.yml /etc/opensearch/jvm.options.d/rowsafe-heap.options \
    /etc/opensearch/opensearch-security/internal_users.yml /etc/opensearch/opensearch-security/roles_mapping.yml \
    /etc/systemd/system/opensearch.service.d/rowsafe.conf /etc/apt/preferences.d/rowsafe-opensearch \
    /etc/ssl/rowsafe-opensearch-transport/node.crt /etc/ssl/rowsafe-opensearch/rowsafe-server.crt
}

# real_os_status: the real agent's `opensearch status` (as the agent runs it).
real_os_status() {
  # shellcheck disable=SC2016 # expands in the inner shell
  runuser -u rowsafe -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/var/lib/rowsafe \
    sh -c 'set -a; . /etc/rowsafe/agent.env; set +a; exec /usr/local/bin/rowsafe-agent-real opensearch status --port 9200' </dev/null
}

# osq USER PASSWORD PATH [CURL-OPTION...]: a request to this server's REST
# port as USER (the password on curl's stdin); prints the HTTP status, the
# body in $W/os.body.
osq() {
  u=$1 p=$2 path=$3
  shift 3
  printf 'user = "%s:%s"\n' "$u" "$p" | curl -sk -K - -o "$W/os.body" -w '%{http_code}' "$@" "https://127.0.0.1:9200$path"
}

# os_wait: OpenSearch answers on 9200 (up to 5 minutes).
os_wait() {
  i=0
  until [ "$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:9200/)" = 401 ]; do
    i=$((i + 2))
    [ "$i" -lt 300 ] || { journalctl -u opensearch -n 30 --no-pager >&2; fail "OpenSearch doesn't answer on 9200"; }
    sleep 2
  done
}

# cloud_opensearch_checks: OpenSearch after the cloud-init run.
cloud_opensearch_checks() {
  grep -q "OpenSearch's repository (artifacts.opensearch.org, 3.x, key A8B2D9E04CD51FEF6AA2DB53BA81D99981191457)" "$W/out" || fail "$name: no word about the repository"
  grep -qx 'deb \[signed-by=/usr/share/keyrings/rowsafe-opensearch.gpg\] https://artifacts.opensearch.org/releases/bundle/opensearch/3.x/apt stable main' \
    /etc/apt/sources.list.d/rowsafe-opensearch.list || fail "$name: rowsafe-opensearch.list"
  grep -qx 'Pin: version 3.\*' /etc/apt/preferences.d/rowsafe-opensearch && grep -qx 'Pin: origin artifacts.opensearch.org' /etc/apt/preferences.d/rowsafe-opensearch ||
    fail "$name: no pin"
  dpkg-query -W -f '${Version}\n' opensearch | grep -q '^3\.' || fail "$name: opensearch isn't 3.x"
  apt-cache policy opensearch | awk '$1 == "Candidate:" { print $2 }' | grep -q '^3\.' || fail "$name: apt would leave OpenSearch 3"
  ! command -v pgbackrest >/dev/null 2>&1 || fail "$name: pgBackRest installed for OpenSearch"
  # No demo configuration: no demo certificates, users or passwords.
  [ -z "$(ls /etc/opensearch/*.pem 2>/dev/null)" ] || fail "$name: the demo certificates are there"
  ! grep -q 'kibanaserver\|demo' /etc/opensearch/opensearch-security/internal_users.yml || fail "$name: demo users in internal_users.yml"
  [ "$(stat -c '%U %G %a' /etc/rowsafe/opensearch)" = "root root 700" ] || fail "$name: /etc/rowsafe/opensearch owner/mode"
  [ "$(stat -c '%U %G %a' /etc/rowsafe/opensearch/admin-password)" = "root root 600" ] || fail "$name: admin-password owner/mode"
  pw=$(cat /etc/rowsafe/opensearch/admin-password)
  printf '%s\n' "$pw" | grep -Eqx '[0-9a-f]{64}' || fail "$name: the admin password isn't 64 hex digits"
  ! grep -qF "$pw" "$W/out" || fail "$name: the admin password was printed"
  ! grep -rqF "$pw" /etc/opensearch || fail "$name: the admin password itself is in /etc/opensearch"
  # Only signed-in users: nobody without a password, nor with the demo's admin:admin; the administrator in.
  [ "$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:9200/)" = 401 ] || fail "$name: anyone gets in"
  [ "$(osq admin admin /)" = 401 ] || fail "$name: admin:admin gets in"
  [ "$(osq admin "$pw" /_plugins/_security/authinfo)" = 200 ] || fail "$name: the administrator can't sign in"
  [ "$(osq admin "$pw" /_plugins/_security/api/internalusers)" = 200 ] || fail "$name: can't list the users"
  for u in kibanaserver kibanaro logstash readall snapshotrestore anomalyadmin; do
    ! grep -q "\"$u\"" "$W/os.body" || fail "$name: the demo user $u exists"
  done
  # A new index has no replicas (there is no second server to hold them).
  [ "$(osq admin "$pw" /rowsafe-test-index -X PUT)" = 200 ] || { cat "$W/os.body" >&2; fail "$name: can't create an index"; }
  [ "$(osq admin "$pw" '/_cat/indices/rowsafe-test-index?h=rep')" = 200 ] && [ "$(tr -d ' \n' <"$W/os.body")" = 0 ] ||
    { cat "$W/os.body" >&2; fail "$name: a new index gets replicas on a one-server cluster"; }
  [ "$(osq admin "$pw" /rowsafe-test-index -X DELETE)" = 200 ] || fail "$name: can't delete the test index"
  # Rowsafe's own user, made with the administrator's login (on stdin).
  called "opensearch-login --port 9200 --admin-user admin"
  [ "$(cat "$F/opensearch-login.stdin")" = "$pw" ] || fail "$name: the agent didn't get the administrator's password on stdin"
  called "apply --database db_fake"
  if [ -x /usr/local/bin/rowsafe-agent-real ]; then
    real_os_status >"$W/osst" 2>&1 || { cat "$W/osst" >&2; fail "$name: the agent's status"; }
    for kv in login=ok security=on tls=on repo=ok restapi=ok hotreload=on unit=opensearch.service; do
      grep -qx "$kv" "$W/osst" || { cat "$W/osst" >&2; fail "$name: the agent's status lacks $kv"; }
    done
    [ "$(osq admin "$pw" /_plugins/_security/api/internalusers/rowsafe)" = 200 ] || fail "$name: Rowsafe's user isn't in OpenSearch"
    pass "the real agent: Rowsafe's user signs in, snapshots allowed in its folder, it may manage users"
  fi
  # Settings: heap, unit, memory map, Performance Analyzer, folders and their owners.
  grep -qx -- '-Xms1953m' /etc/opensearch/jvm.options.d/rowsafe-heap.options && grep -qx -- '-Xmx1953m' /etc/opensearch/jvm.options.d/rowsafe-heap.options ||
    fail "$name: the heap isn't half of 4 GB"
  ps -o args= -u opensearch | grep -q -- '-Xmx1953m' || fail "$name: OpenSearch doesn't run with its heap"
  grep -qx 'TimeoutStartSec=300' /etc/systemd/system/opensearch.service.d/rowsafe.conf && grep -qx 'UMask=0027' /etc/systemd/system/opensearch.service.d/rowsafe.conf ||
    fail "$name: OpenSearch's unit drop-in"
  [ "$(cat /proc/sys/vm/max_map_count)" -ge 262144 ] || fail "$name: vm.max_map_count is $(cat /proc/sys/vm/max_map_count)"
  # The signing key's weekly refresh, and what Rowsafe's role can't reach.
  systemctl is-enabled --quiet rowsafe-opensearch-key.timer || fail "$name: the signing key's refresh isn't on"
  [ "$(cat /var/lib/rowsafe-opensearch/key-status)" = ok ] || fail "$name: the signing key's status: $(cat /var/lib/rowsafe-opensearch/key-status 2>&1)"
  [ "$(grep -c '^plugins\.security\.restapi\.endpoints_disabled\.rowsafe_agent\.' /etc/opensearch/opensearch.yml)" = 7 ] ||
    fail "$name: Rowsafe's role isn't kept off the security endpoints it doesn't need"
  if [ -n "$(systemctl list-unit-files --no-legend opensearch-performance-analyzer.service 2>/dev/null)" ]; then
    [ "$(systemctl is-enabled opensearch-performance-analyzer.service 2>/dev/null)" = masked ] || fail "$name: Performance Analyzer isn't masked"
    ! systemctl is-active --quiet opensearch-performance-analyzer.service || fail "$name: Performance Analyzer runs"
  fi
  [ "$(stat -c '%U %G %a' /var/lib/rowsafe-opensearch)" = "root opensearch 750" ] || fail "$name: /var/lib/rowsafe-opensearch owner/mode"
  [ "$(stat -c '%U %G %a' /var/lib/rowsafe-opensearch/snapshots)" = "opensearch opensearch 2750" ] || fail "$name: snapshot folder owner/mode"
  grep -qx 'path.repo: \["/var/lib/rowsafe-opensearch/snapshots"\]' /etc/opensearch/opensearch.yml || fail "$name: path.repo"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-opensearch-transport/node.key)" = "opensearch opensearch 400" ] || fail "$name: node key owner/mode"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-opensearch-transport)" = "root root 755" ] || fail "$name: node certificate folder owner/mode"
  ! runuser -u rowsafe -- cat /etc/ssl/rowsafe-opensearch-transport/node.key >/dev/null 2>&1 || fail "$name: the agent reads the node key"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-opensearch)" = "rowsafe opensearch 2750" ] || fail "$name: certificate folder owner/mode"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-opensearch/rowsafe-server.key)" = "rowsafe opensearch 640" ] || fail "$name: key owner/mode"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-opensearch/rowsafe-server.crt)" = "rowsafe opensearch 644" ] || fail "$name: certificate owner/mode"
  d=/etc/systemd/system/rowsafe-agent.service.d/10-opensearch.conf
  grep -qx 'User=rowsafe' "$d" && grep -qx 'After=opensearch.service' "$d" && grep -qx 'SupplementaryGroups=opensearch' "$d" &&
    grep -qx 'ReadWritePaths=-/etc/ssl/rowsafe-opensearch' "$d" || fail "$name: the agent's drop-in"
  id -nG rowsafe | tr ' ' '\n' | grep -qx opensearch || fail "$name: rowsafe isn't in the opensearch group"
  runuser -u rowsafe -- cat /etc/opensearch/opensearch.yml >/dev/null || fail "$name: the agent can't read opensearch.yml"
  grep -qx '9200 opensearch.service' /etc/rowsafe/restart-allowed || fail "$name: OpenSearch isn't in restart-allowed"
  # The network: HTTPS on 9200 on every address, 9300 on 127.0.0.1 only, closed by the firewall.
  ss -ltnH | awk '{ print $4 }' >"$W/listen"
  grep -Eqx '(\*|0\.0\.0\.0|\[::\]|\[::ffff:0\.0\.0\.0\]):9200' "$W/listen" || { cat "$W/listen" >&2; fail "$name: 9200 doesn't listen on every address"; }
  grep -q ':9300$' "$W/listen" || { cat "$W/listen" >&2; fail "$name: 9300 doesn't listen"; }
  ! grep ':9300$' "$W/listen" | grep -Eqv '^(127\.0\.0\.1|\[::ffff:127\.0\.0\.1\]|\[::1\]):9300$' || { cat "$W/listen" >&2; fail "$name: 9300 listens beyond this server"; }
  grep -q "tcp dport 9200 drop" "$W/nft" && [ -e /var/lib/rowsafe-firewall/port-9200 ] || { cat "$W/nft" >&2; fail "$name: port 9200 isn't closed by the firewall"; }
  [ "$(grep -Ex '[0-9]+' /etc/rowsafe/firewall-allowed)" = 9200 ] || fail "$name: the firewall's allow list isn't 9200 alone"
  grep -q "OpenSearch's port (9200) is closed to everyone but this server" "$W/out" || fail "$name: no word about the firewall"
  echo | openssl s_client -connect "$ip:9200" 2>/dev/null | openssl x509 -noout -fingerprint -sha256 >"$W/fp" &&
    [ "$(cat "$W/fp")" = "$(openssl x509 -in /etc/ssl/rowsafe-opensearch/rowsafe-server.crt -noout -fingerprint -sha256)" ] || fail "OpenSearch doesn't present its certificate"
  if echo | openssl s_client -tls1_1 -connect "$ip:9200" >"$W/tls11" 2>&1 && grep -q 'Cipher is [A-Z]' "$W/tls11"; then fail "TLS 1.1 accepted on 9200"; fi
  [ "$(curl -sk -o /dev/null -w '%{http_code}' "https://$ip:9200/")" = 401 ] || fail "$name: anyone gets in from the network"
  [ "$(printf 'user = "admin:%s"\n' "$pw" | curl -sk -K - -o /dev/null -w '%{http_code}' "https://$ip:9200/")" = 200 ] || fail "$name: the administrator can't sign in from the network"
  if curl -s -o /dev/null --max-time 10 "http://$ip:9200/" 2>/dev/null; then fail "$name: plain HTTP answers on 9200"; fi
  # What the agent does with a renewed certificate: the same files, written
  # by the agent's user; OpenSearch loads them by itself, nothing restarts.
  pid=$(systemctl show -p MainPID --value opensearch)
  # shellcheck disable=SC2016 # expands in the inner shell
  runuser -u rowsafe -- sh -c 'cd /etc/ssl/rowsafe-opensearch && umask 027 &&
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj /CN=renewed.test \
      -keyout k.new -out c.new >/dev/null 2>&1 && chmod 0640 k.new && chmod 0644 c.new && mv -f k.new rowsafe-server.key && mv -f c.new rowsafe-server.crt' ||
    fail "the agent's user can't replace the certificate"
  want=$(openssl x509 -in /etc/ssl/rowsafe-opensearch/rowsafe-server.crt -noout -fingerprint -sha256)
  i=0
  until [ "$(echo | openssl s_client -connect 127.0.0.1:9200 2>/dev/null | openssl x509 -noout -fingerprint -sha256)" = "$want" ]; do
    i=$((i + 2))
    [ "$i" -lt 120 ] || fail "the renewed certificate isn't served on 9200 within 2 minutes"
    sleep 2
  done
  [ "$(systemctl show -p MainPID --value opensearch)" = "$pid" ] || fail "OpenSearch restarted for the certificate"
  pass "OpenSearch from the network: HTTPS on 9200 only (9300 on this server), passwords only, no demo users, a renewed certificate loaded without a restart"
}

# cloud_opensearch_own (--cloud, opensearch-own): OpenSearch on a
# customer's own server, installed from its repository with its demo
# configuration and running; the installer without a terminal (--protect,
# the administrator's login from the environment).
cloud_opensearch_own() {
  ver=$1 engine=opensearch
  release_setup
  apt-get install -y -qq --no-install-recommends nftables >/dev/null
  cat /etc/ssl/certs/ca-certificates.crt "$W/tls.crt" >"$W/ca-bundle.crt"
  export CURL_CA_BUNDLE=$W/ca-bundle.crt
  F=/tmp/rowsafe-fake
  # shellcheck disable=SC1091
  os=$(. /etc/os-release && echo "$ID $VERSION_ID")
  echo "  -- OpenSearch $ver on a server of one's own ($os, $arch): protected without a restart"
  opensearch_test_prep
  ospw='Kx7-Tide-Lantern-93!q'
  curl -fsSL https://artifacts.opensearch.org/publickeys/opensearch-release.pgp -o /usr/share/keyrings/opensearch-test.asc
  echo 'deb [signed-by=/usr/share/keyrings/opensearch-test.asc] https://artifacts.opensearch.org/releases/bundle/opensearch/3.x/apt stable main' \
    >/etc/apt/sources.list.d/opensearch-3.x.list
  apt-get update -qq >/dev/null
  OPENSEARCH_INITIAL_ADMIN_PASSWORD=$ospw apt-get install -y -qq opensearch >"$W/apt.log" 2>&1 || { tail -n 20 "$W/apt.log" >&2; fail "installing OpenSearch with its demo configuration"; }
  systemctl enable --now opensearch >/dev/null 2>&1 || systemctl start opensearch || { journalctl -u opensearch -n 30 --no-pager >&2; fail "OpenSearch doesn't start"; }
  os_wait
  [ "$(osq admin "$ospw" /)" = 200 ] || fail "the demo configuration's administrator can't sign in"
  yml=/etc/opensearch/opensearch.yml
  cp -p "$yml" "$W/opensearch.yml.orig"
  grep -q '^plugins.security.restapi.roles_enabled:' "$yml" || fail "the demo configuration has no roles_enabled (the test expects one)"
  ! grep -q '^path.repo' "$yml" || fail "the demo configuration has path.repo (the test expects none)"
  pid=$(systemctl show -p MainPID --value opensearch)
  echo rowsafe >/tmp/rowsafe-fake-user
  line="9200\t-\t3\t-\t/var/lib/opensearch\t8192\t-\tno\t-\t-\t8 KiB\topensearch.service\t-\topensearch"
  scenario "discover_out=$line" "opensearch-status_out=$(os_status missing | sed 's/^restapi=ok$/restapi=unknown/')" "opensearch-login_rc=11\n0" \
    "opensearch-login_out=Rowsafe's OpenSearch user \"rowsafe\" is ready; its password is saved for the agent only." \
    "plan_out=Backups for search wait for OpenSearch's restart (path.repo)." \
    "wait_out=✓ search is protected." "status_out=db_fake\tsearch\tawaiting_restart\twaiting\thttps://app.rowsafe.test/databases/db_fake"
  expect_ok "protected without a terminal, the administrator's login from the environment" \
    env ROWSAFE_OPENSEARCH_ADMIN_USER=admin ROWSAFE_OPENSEARCH_ADMIN_PASSWORD="$ospw" \
    "$INSTALLER" rse_secrettoken123 --no-prompt --storage rowsafe --allow-restart --protect search
  [ -z "${TEST_SHOW:-}" ] || cat "$W/out"
  grep -q "the OpenSearch on this server" "$W/out" || fail "$name: the installer doesn't speak of OpenSearch"
  ! grep -q "restore to any second" "$W/out" || fail "$name: promises restores to any second for OpenSearch"
  ! grep -qF "$ospw" "$W/out" || fail "$name: the administrator's password was printed"
  [ "$(stat -c '%U %a' /etc/rowsafe/agent.env)" = "rowsafe 600" ] || fail "$name: the agent doesn't run as rowsafe"
  d=/etc/systemd/system/rowsafe-agent.service.d/10-opensearch.conf
  grep -qx 'User=rowsafe' "$d" && grep -qx 'SupplementaryGroups=opensearch' "$d" || fail "$name: the agent's drop-in"
  ! grep -q ReadWritePaths "$d" || fail "$name: the agent may write a certificate folder Rowsafe didn't make"
  ! grep -i postgresql "$W/out" | grep -qv '^ *unavailable ' || { grep -i postgresql "$W/out" >&2; fail "$name: the output speaks of PostgreSQL"; }
  # opensearch.yml: Rowsafe's folder and role added, the previous file kept (root's only).
  grep -qx 'path.repo: \["/var/lib/rowsafe-opensearch/snapshots"\]' "$yml" || { cat "$yml" >&2; fail "$name: path.repo"; }
  # (one line, or a block list as OpenSearch's demo configuration writes it)
  r=$(awk '/^plugins\.security\.restapi\.roles_enabled:/ { sub(/^[^:]*: */, ""); print; b = 1; next }
    b && /^[[:space:]]*-/ { print; next } { b = 0 }' "$yml" | tr '\n' ' ')
  for role in all_access security_rest_api_access rowsafe_agent; do
    printf '%s\n' "$r" | grep -q "$role" || fail "$name: roles_enabled lacks $role ($r)"
  done
  [ "$(grep -c '^plugins.security.restapi.roles_enabled:' "$yml")" = 1 ] || fail "$name: roles_enabled twice"
  [ "$(grep -c '^plugins\.security\.restapi\.endpoints_disabled\.rowsafe_agent\.' "$yml")" = 7 ] || fail "$name: endpoints_disabled for Rowsafe's role"
  # The demo configuration: said plainly; its super administrator's key kept from the agent's group.
  grep -q "parts of its demo configuration" "$W/out" || fail "$name: no word about the demo configuration"
  [ ! -f /etc/opensearch/kirk-key.pem ] || [ "$(stat -c %a /etc/opensearch/kirk-key.pem)" = 600 ] || fail "$name: kirk-key.pem is readable by OpenSearch's group"
  [ "$(stat -c '%U %G %a' "$yml.rowsafe-backup")" = "root root 600" ] || fail "$name: the copy of opensearch.yml owner/mode"
  cmp -s "$yml.rowsafe-backup" "$W/opensearch.yml.orig" || fail "$name: the copy isn't the previous opensearch.yml"
  [ "$(stat -c '%U %G %a' "$yml")" = "$(stat -c '%U %G %a' "$W/opensearch.yml.orig")" ] || fail "$name: opensearch.yml's owner or mode changed"
  [ "$(stat -c '%U %G %a' /var/lib/rowsafe-opensearch/snapshots)" = "opensearch opensearch 2750" ] || fail "$name: snapshot folder owner/mode"
  [ ! -e /etc/systemd/system/opensearch.service.d/rowsafe.conf ] || fail "$name: OpenSearch's unit was changed"
  # No restart without someone's yes: said what to do instead.
  [ "$(systemctl show -p MainPID --value opensearch)" = "$pid" ] || fail "$name: OpenSearch was restarted"
  grep -q "backups start after its next restart" "$W/out" || fail "$name: no word about the restart"
  grep -q "sudo systemctl restart opensearch" "$W/out" || fail "$name: no restart command"
  grep -q "or with Restart in the Rowsafe dashboard" "$W/out" || fail "$name: no word about Restart in the dashboard"
  grep -qx '9200 opensearch.service' /etc/rowsafe/restart-allowed || fail "$name: OpenSearch isn't in restart-allowed"
  called "opensearch-login --port 9200 --admin-user admin"
  [ "$(cat "$F/opensearch-login.stdin")" = "$ospw" ] || fail "$name: the administrator's password didn't reach the agent on stdin"
  called "plan --name search --port 9200"
  pass "opensearch.yml changed (a copy kept), Rowsafe's user made, OpenSearch not restarted"
  if [ -x /usr/local/bin/rowsafe-agent-real ]; then
    real_os_status >"$W/osst" 2>&1 || { cat "$W/osst" >&2; fail "the agent's status before the restart"; }
    grep -qx login=ok "$W/osst" && grep -qx repo=missing "$W/osst" || { cat "$W/osst" >&2; fail "the agent's status before the restart"; }
  fi

  # A re-run before the restart: nothing changes (no second copy, no restart).
  cp "$yml" "$W/opensearch.yml.after"
  expect_ok "re-run before the restart changes nothing" env ROWSAFE_OPENSEARCH_ADMIN_USER=admin ROWSAFE_OPENSEARCH_ADMIN_PASSWORD="$ospw" \
    "$INSTALLER" --no-prompt --protect search
  cmp -s "$yml" "$W/opensearch.yml.after" || fail "$name: opensearch.yml changed"
  cmp -s "$yml.rowsafe-backup" "$W/opensearch.yml.orig" || fail "$name: the copy was replaced"
  [ "$(systemctl show -p MainPID --value opensearch)" = "$pid" ] || fail "$name: OpenSearch was restarted"

  # The person restarts OpenSearch: everything Rowsafe needs is in place.
  systemctl restart opensearch
  os_wait
  if [ -x /usr/local/bin/rowsafe-agent-real ]; then
    real_os_status >"$W/osst" 2>&1 || { cat "$W/osst" >&2; fail "the agent's status after the restart"; }
    for kv in login=ok security=on repo=ok restapi=ok unit=opensearch.service; do
      grep -qx "$kv" "$W/osst" || { cat "$W/osst" >&2; fail "after the restart the agent's status lacks $kv"; }
    done
    pass "after one restart, the real agent: Rowsafe's user signs in, snapshots allowed in its folder, it may manage users"
  fi

  # A form the installer doesn't edit: left alone, with what to do.
  cp "$W/opensearch.yml.orig" "$yml"
  printf 'path:\n  repo: ["/mnt/backups"]\n' >>"$yml"
  cp "$yml" "$W/opensearch.yml.list"
  rm -f "$yml.rowsafe-backup"
  expect_fail "a path.repo set in a nested block is left alone" "Do it yourself" env ROWSAFE_OPENSEARCH_ADMIN_USER=admin ROWSAFE_OPENSEARCH_ADMIN_PASSWORD="$ospw" \
    "$INSTALLER" --no-prompt --protect search
  cmp -s "$yml" "$W/opensearch.yml.list" || fail "$name: opensearch.yml changed"
  [ ! -e "$yml.rowsafe-backup" ] || fail "$name: a copy was made of a file left alone"
  cp "$W/opensearch.yml.after" "$yml"

  expect_ok "uninstall leaves OpenSearch alone" "$INSTALLER" --uninstall
  [ ! -e /etc/systemd/system/rowsafe-agent.service.d/10-opensearch.conf ] || fail "$name: the agent's drop-in is left"
  ! id -nG rowsafe | tr ' ' '\n' | grep -qx opensearch || fail "$name: rowsafe is still in the opensearch group"
  systemctl is-active --quiet opensearch && cmp -s "$yml" "$W/opensearch.yml.after" || fail "$name: OpenSearch was changed"
  pass "OpenSearch's own server: a form not edited is left alone; uninstall leaves OpenSearch as it is"
}
# <<< opensearch

# qd_status LOGIN: what `rowsafe-agent qdrant status` says of the new server.
qd_status() {
  printf 'port=6333\nengine=qdrant\nversion=1.19.2\nlogin=%s\ntls=yes\njwt=yes\nbinary=/usr/bin/qdrant\ndocker=no\ncluster=no\nconfig=/etc/qdrant/config.yaml\nunit=qdrant.service\ncollections=0' "$1"
}

# qd_jwt KEYFILE CLAIMS: a token Qdrant takes, signed with the key in
# KEYFILE (HS256), as the agent signs its own.
qd_jwt() {
  b64() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
  _h=$(printf '{"alg":"HS256","typ":"JWT"}' | b64)
  _p=$(printf '%s' "$2" | b64)
  _s=$(printf '%s' "$_h.$_p" | openssl dgst -sha256 -mac HMAC -macopt "key:$(cat "$1")" -binary | b64)
  printf '%s.%s.%s' "$_h" "$_p" "$_s"
}

# qdc KEY METHOD PATH [BODY]: the HTTP status of a request to Qdrant from
# the network (TLS, the certificate not checked), the key on stdin.
qdc() {
  printf 'header = "api-key: %s"\n' "$1" |
    curl -sk -K - -o "$W/qd.body" -w '%{http_code}' -X "$2" -H 'Content-Type: application/json' ${4:+--data "$4"} "https://$ip:6333$3" || true
}

# cloud_qdrant_update: the root helper's Qdrant update (db-minor-update on
# qdrant.service), for real: nothing to do at the pinned release; from an
# "older" program (a stand-in saying 1.19.1), the pinned release downloaded
# from GitHub, checked and installed, and Qdrant restarted.
cloud_qdrant_update() {
  hd=$W/qhelper
  install -d -m 0755 "$hd" "$hd/out" "$hd/state"
  install -d -m 0700 -o rowsafe -g rowsafe "$hd/req"
  printf 'database\n' >"$hd/updates-allowed"
  printf '6333 qdrant.service\n' >"$hd/restart-allowed"
  chmod 644 "$hd/updates-allowed" "$hd/restart-allowed"
  qd_helper() {
    printf '%s db-minor-update 6333\n' "$1" | runuser -u rowsafe -- sh -c 'cat >"$1"' sh "$hd/req/update-request"
    rm -f "$hd/out/update-result"
    timeout 1200 env ROWSAFE_HELPER_MODE=update ROWSAFE_AGENT_USER=rowsafe ROWSAFE_RESTART_DIR="$hd/req" ROWSAFE_UPDATES_ALLOW="$hd/updates-allowed" \
      ROWSAFE_RESTART_ALLOW="$hd/restart-allowed" RUNTIME_DIRECTORY="$hd/out" STATE_DIRECTORY="$hd/state" \
      sh /src/scripts/rowsafe-pg-restart 2>>"$W/qhelper.log" || fail "$name: the helper failed ($1)"
  }
  pid=$(systemctl show -p MainPID --value qdrant)
  qd_helper qdu1
  grep -qx ok=1 "$hd/out/update-result" && grep -qx package=1.19.2 "$hd/out/update-result" && grep -qx restarted=0 "$hd/out/update-result" ||
    { cat "$hd/out/update-result" "$W/qhelper.log" >&2; fail "$name: the pinned release isn't 'already the newest'"; }
  [ "$(systemctl show -p MainPID --value qdrant)" = "$pid" ] || fail "$name: nothing to update, yet Qdrant restarted"
  # An older program on disk: a stand-in that says 1.19.1 and runs the real one.
  mv /usr/bin/qdrant /usr/local/lib/qdrant-real
  printf '#!/bin/sh\ncase "${1:-}" in --version) echo "qdrant 1.19.1" ;; *) exec /usr/local/lib/qdrant-real "$@" ;; esac\n' >/usr/bin/qdrant
  chmod 0755 /usr/bin/qdrant
  qd_helper qdu2
  grep -qx ok=1 "$hd/out/update-result" && grep -qx from_package=1.19.1 "$hd/out/update-result" && grep -qx package=1.19.2 "$hd/out/update-result" &&
    grep -qx restarted=1 "$hd/out/update-result" || { cat "$hd/out/update-result" "$W/qhelper.log" >&2; fail "$name: the helper didn't update Qdrant"; }
  [ "$(/usr/bin/qdrant --version)" = "qdrant 1.19.2" ] && [ ! -L /usr/bin/qdrant ] && head -c 4 /usr/bin/qdrant | grep -q ELF ||
    fail "$name: /usr/bin/qdrant isn't Qdrant 1.19.2's program after the update"
  [ "$(systemctl show -p MainPID --value qdrant)" != "$pid" ] || fail "$name: Qdrant wasn't restarted on the new program"
  rm -f /usr/local/lib/qdrant-real
  i=0
  until [ "$(qdc '' GET /collections)" = 401 ]; do
    i=$((i + 1))
    [ $i -lt 60 ] || fail "$name: Qdrant doesn't answer after the update"
    sleep 1
  done
  grep -q 'Qdrant on port 6333: 1.19.1 -> 1.19.2 (restarted: 1)' "$W/qhelper.log" || fail "$name: the helper's log"
  pass "the root helper updates Qdrant to the pinned release (SHA-256 checked), restarts it, and does nothing at the pinned one"
}

# cloud_meilisearch_update: the root helper's update (db-minor-update):
# nothing at the pinned release; from an older one (a stand-in that says
# 1.54.2 and runs the real program), the pinned release is installed from
# its download (SHA-256 checked) into its own folder, the program switched
# and Meilisearch restarted once with its dumpless upgrade (a drop-in in
# /run, gone afterwards).
cloud_meilisearch_update() {
  hd=$W/mhelper
  install -d -m 0755 "$hd" "$hd/out" "$hd/state"
  install -d -m 0700 -o rowsafe -g rowsafe "$hd/req"
  printf 'database\n' >"$hd/updates-allowed"
  printf '7700 meilisearch.service\n' >"$hd/restart-allowed"
  chmod 644 "$hd/updates-allowed" "$hd/restart-allowed"
  ms_helper() {
    printf '%s db-minor-update 7700\n' "$1" | runuser -u rowsafe -- sh -c 'cat >"$1"' sh "$hd/req/update-request"
    rm -f "$hd/out/update-result"
    timeout 1200 env ROWSAFE_HELPER_MODE=update ROWSAFE_AGENT_USER=rowsafe ROWSAFE_RESTART_DIR="$hd/req" ROWSAFE_UPDATES_ALLOW="$hd/updates-allowed" \
      ROWSAFE_RESTART_ALLOW="$hd/restart-allowed" RUNTIME_DIRECTORY="$hd/out" STATE_DIRECTORY="$hd/state" \
      ROWSAFE_MEILISEARCH_RELEASES_URL=https://localhost:18443/meilisearch \
      sh /src/scripts/rowsafe-pg-restart 2>>"$W/mhelper.log" || fail "$name: the helper failed ($1)"
  }
  mver=$(sed -n 's/^MEILI_VERSION=//p' "$W/install.sh")
  real=/usr/local/lib/meilisearch/$mver/meilisearch
  pid=$(systemctl show -p MainPID --value meilisearch)
  ms_helper msu1
  grep -qx ok=1 "$hd/out/update-result" && grep -qx "package=$mver" "$hd/out/update-result" && grep -qx restarted=0 "$hd/out/update-result" ||
    { cat "$hd/out/update-result" "$W/mhelper.log" >&2; fail "$name: the pinned release isn't 'already the newest'"; }
  [ "$(systemctl show -p MainPID --value meilisearch)" = "$pid" ] || fail "$name: nothing to update, yet Meilisearch restarted"
  # An older program: a stand-in that says 1.54.2 and runs the real one,
  # which the update downloads again into its folder.
  install -d -m 0755 /usr/local/lib/meilisearch/1.54.2
  mv "$real" /usr/local/lib/meilisearch/1.54.2/real
  printf '#!/bin/sh\ncase "${1:-}" in --version) echo "meilisearch 1.54.2" ;; *) exec /usr/local/lib/meilisearch/1.54.2/real "$@" ;; esac\n' \
    >/usr/local/lib/meilisearch/1.54.2/meilisearch
  chmod 0755 /usr/local/lib/meilisearch/1.54.2/meilisearch
  ln -sfn /usr/local/lib/meilisearch/1.54.2/meilisearch /usr/local/bin/meilisearch
  ms_helper msu2
  grep -qx ok=1 "$hd/out/update-result" && grep -qx from_package=1.54.2 "$hd/out/update-result" && grep -qx "package=$mver" "$hd/out/update-result" &&
    grep -qx restarted=1 "$hd/out/update-result" || { cat "$hd/out/update-result" "$W/mhelper.log" >&2; fail "$name: the helper didn't update Meilisearch"; }
  [ "$(readlink /usr/local/bin/meilisearch)" = "$real" ] && [ "$(/usr/local/bin/meilisearch --version)" = "meilisearch $mver" ] &&
    [ "$(stat -c '%U %a' "$real")" = "root 755" ] || fail "$name: the program isn't Meilisearch $mver's after the update"
  [ "$(systemctl show -p MainPID --value meilisearch)" != "$pid" ] || fail "$name: Meilisearch wasn't restarted on the new program"
  [ ! -e /run/systemd/system/meilisearch.service.d/50-rowsafe-upgrade.conf ] || fail "$name: the upgrade drop-in stayed"
  ! systemctl show -p Environment --value meilisearch | grep -q MEILI_UPGRADE_DB || fail "$name: the next start would upgrade again"
  rm -rf /usr/local/lib/meilisearch/1.54.2
  i=0
  until curl -fsS --max-time 3 http://127.0.0.1:7701/health 2>/dev/null | grep -q available; do
    i=$((i + 1))
    [ $i -lt 60 ] || fail "$name: Meilisearch doesn't answer after the update"
    sleep 1
  done
  grep -q "Meilisearch on port 7700: 1.54.2 -> $mver (dumpless upgrade, restarted)" "$W/mhelper.log" || fail "$name: the helper's log"
  pass "the root helper updates Meilisearch to the pinned release (SHA-256 checked, dumpless upgrade, one restart), and does nothing at the pinned one"

  # The TLS front follows agent updates: root's refresh copies the agent's
  # program only when it matches the release's signed manifest.
  systemctl is-enabled --quiet rowsafe-meilisearch-tls-refresh.path || fail "$name: the front's refresh path unit isn't enabled"
  front=/usr/local/lib/rowsafe/rowsafe-meilisearch-tls
  agent=$(readlink -f /opt/rowsafe/rowsafe-agent)
  cp "$agent" "$W/agent.orig"
  printf 'stale' >>"$front"
  /usr/local/lib/rowsafe/rowsafe-meilisearch-tls-refresh >"$W/refresh.out" 2>&1 || fail "$name: the refresh failed: $(cat "$W/refresh.out")"
  cmp -s "$agent" "$front" && grep -q "now runs rowsafe-agent" "$W/refresh.out" || fail "$name: the front wasn't refreshed: $(cat "$W/refresh.out")"
  [ "$(stat -c '%U %a' "$front")" = "root 755" ] || fail "$name: the front's program owner or mode"
  printf 'tampered' >>"$agent"
  printf 'stale' >>"$front"
  cp "$front" "$W/front.before"
  /usr/local/lib/rowsafe/rowsafe-meilisearch-tls-refresh >"$W/refresh.out" 2>&1
  cmp -s "$front" "$W/front.before" && grep -q "doesn't match its signed manifest" "$W/refresh.out" ||
    fail "$name: a program that doesn't match the signed manifest reached the front: $(cat "$W/refresh.out")"
  cat "$W/agent.orig" >"$agent"
  /usr/local/lib/rowsafe/rowsafe-meilisearch-tls-refresh >/dev/null 2>&1
  i=0
  until systemctl is-active --quiet rowsafe-meilisearch-tls && echo | openssl s_client -connect 127.0.0.1:7700 2>/dev/null | grep -q "BEGIN CERTIFICATE"; do
    i=$((i + 1))
    [ $i -lt 30 ] || fail "$name: the TLS front doesn't serve after its refresh"
    sleep 1
  done
  pass "the TLS front follows agent updates: copied only when it matches the signed manifest, then restarted"
}

# cloud_qdrant_checks: Qdrant after the cloud-init run.
cloud_qdrant_checks() {
  grep -Eq "Qdrant 1[.]19[.][0-9]+ downloaded and checked [(]SHA-256 [0-9a-f]{64}[)]" "$W/out" || fail "$name: no word about the checked download"
  [ "$(/usr/bin/qdrant --version | head -n 1)" = "qdrant 1.19.2" ] || fail "$name: /usr/bin/qdrant isn't 1.19.2"
  if [ "$(dpkg --print-architecture)" = amd64 ]; then
    [ "$(dpkg-query -W -f '${Version}' qdrant)" = 1.19.2-1 ] || fail "$name: the qdrant package isn't 1.19.2-1"
  fi
  ! command -v pgbackrest >/dev/null 2>&1 || fail "$name: pgBackRest installed for Qdrant"
  [ "$(stat -c '%U %G %a' /etc/rowsafe/qdrant)" = "root root 700" ] || fail "$name: /etc/rowsafe/qdrant owner/mode"
  for k in api-key read-only-api-key alt-api-key; do
    [ "$(stat -c '%U %G %a' "/etc/rowsafe/qdrant/$k")" = "root root 600" ] || fail "$name: $k owner/mode"
    grep -Eqx '[0-9a-f]{64}' "/etc/rowsafe/qdrant/$k" || fail "$name: $k isn't 64 hex digits"
    ! grep -qF "$(cat "/etc/rowsafe/qdrant/$k")" "$W/out" || fail "$name: $k was printed"
    ! grep -qF "$(cat "/etc/rowsafe/qdrant/$k")" /etc/qdrant/config.yaml || fail "$name: $k is in config.yaml"
  done
  [ "$(stat -c '%U %G %a' /etc/qdrant/qdrant.env)" = "root root 600" ] || fail "$name: qdrant.env owner/mode"
  grep -qx "QDRANT__SERVICE__ALT_API_KEY=$(cat /etc/rowsafe/qdrant/alt-api-key)" /etc/qdrant/qdrant.env || fail "$name: qdrant.env lacks Rowsafe's key"
  [ "$(cat /etc/rowsafe/qdrant-keys)" = "api_key read_only_api_key alt_api_key" ] || fail "$name: the names of the keys set"
  [ "$(stat -c '%U %G %a' /etc/qdrant/config.yaml)" = "root root 644" ] || fail "$name: config.yaml owner/mode (keyless, readable)"
  for l in 'telemetry_disabled: true' '  enable_tls: true' '  jwt_rbac: true' '  enable_cors: false' '  enable_snapshot_url_recovery: false' \
    '  enabled: false' '  cert_ttl: 60' '  cert: /etc/ssl/rowsafe-qdrant/rowsafe-server.crt'; do
    grep -qx "$l" /etc/qdrant/config.yaml || fail "$name: config.yaml lacks '$l'"
  done
  # Its own user, sandboxed.
  [ "$(systemctl show -p User --value qdrant)" = qdrant ] && [ "$(systemctl show -p NoNewPrivileges --value qdrant)" = yes ] &&
    [ "$(systemctl show -p ProtectSystem --value qdrant)" = strict ] && [ "$(systemctl show -p PrivateTmp --value qdrant)" = yes ] ||
    fail "$name: Qdrant's unit isn't sandboxed"
  [ "$(ps -o user= -p "$(systemctl show -p MainPID --value qdrant)")" = qdrant ] || fail "$name: Qdrant doesn't run as qdrant"
  [ "$(stat -c '%U %G %a' /var/lib/qdrant/storage)" = "qdrant qdrant 750" ] || fail "$name: storage owner/mode"
  # The agent reads the settings, never the keys nor Qdrant's files: it isn't
  # in Qdrant's group.
  runuser -u rowsafe -g rowsafe -- cat /etc/qdrant/config.yaml >/dev/null || fail "$name: the agent can't read Qdrant's settings"
  if runuser -u rowsafe -g rowsafe -- cat /etc/qdrant/qdrant.env >/dev/null 2>&1; then fail "$name: the agent reads Qdrant's keys"; fi
  if runuser -u rowsafe -g rowsafe -- ls /var/lib/qdrant/storage >/dev/null 2>&1; then fail "$name: the agent reads Qdrant's files"; fi
  ! grep -q 'SupplementaryGroups' /etc/systemd/system/rowsafe-agent.service.d/10-qdrant.conf &&
    grep -qx 'ReadWritePaths=-/etc/ssl/rowsafe-qdrant' /etc/systemd/system/rowsafe-agent.service.d/10-qdrant.conf || fail "$name: the agent's drop-in"
  [ "$(systemctl is-enabled qdrant 2>/dev/null)" = enabled ] || fail "$name: qdrant.service is $(systemctl is-enabled qdrant 2>&1) after the install (masked while the package went in)"
  # Rowsafe's own key (alt_api_key), given to the agent on stdin by root.
  called "qdrant-login --port 6333"
  [ "$(cat "$F/qdrant-login.stdin")" = "$(cat /etc/rowsafe/qdrant/alt-api-key)" ] || fail "$name: the agent didn't get Rowsafe's key on stdin"
  called "apply --database db_fake"
  grep -qx '6333 qdrant.service' /etc/rowsafe/restart-allowed || fail "$name: restarts (--allow-restart) don't name qdrant.service"
  # TLS: the certificate at the exact paths, on both ports, from the network.
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-qdrant)" = "rowsafe qdrant 2750" ] || fail "$name: certificate folder owner/mode"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-qdrant/rowsafe-server.key)" = "rowsafe qdrant 640" ] || fail "$name: key owner/mode"
  [ "$(stat -c '%U %G %a' /etc/ssl/rowsafe-qdrant/rowsafe-server.crt)" = "rowsafe qdrant 644" ] || fail "$name: certificate owner/mode"
  ss -ltnHp | awk '{ print $4 }' >"$W/listen"
  for p in 6333 6334; do
    grep -Eqx "(\*|0\.0\.0\.0|\[::\]):$p" "$W/listen" || { cat "$W/listen" >&2; fail "$name: $p doesn't listen on every address"; }
    grep -q "tcp dport $p drop" "$W/nft" && [ -e "/var/lib/rowsafe-firewall/port-$p" ] || { cat "$W/nft" >&2; fail "$name: port $p isn't closed by the firewall"; }
    grep -qx "$p" /etc/rowsafe/firewall-allowed || fail "$name: $p isn't in the firewall's allow list"
    echo | openssl s_client -connect "$ip:$p" 2>/dev/null | openssl x509 -noout -fingerprint -sha256 >"$W/fp" &&
      [ "$(cat "$W/fp")" = "$(openssl x509 -in /etc/ssl/rowsafe-qdrant/rowsafe-server.crt -noout -fingerprint -sha256)" ] || fail "Qdrant doesn't present its certificate on $p"
  done
  ! grep -q ':6335$' "$W/listen" || fail "$name: the cluster port 6335 listens"
  grep -q "Qdrant's ports (6333, 6334) are closed to everyone but this server" "$W/out" || fail "$name: no word about the firewall"
  # Keys: nothing without one; the read-only key reads but can't write; a
  # token signed with Rowsafe's key works; plain HTTP is answered nowhere.
  [ "$(qdc '' GET /collections)" = 401 ] || fail "Qdrant answers the network without a key"
  [ "$(qdc "$(cat /etc/rowsafe/qdrant/api-key)" PUT /collections/app '{"vectors":{"size":4,"distance":"Cosine"}}')" = 200 ] || fail "the admin key can't create a collection"
  [ "$(qdc "$(cat /etc/rowsafe/qdrant/read-only-api-key)" GET /collections/app)" = 200 ] || fail "the read-only key can't read"
  [ "$(qdc "$(cat /etc/rowsafe/qdrant/read-only-api-key)" DELETE /collections/app)" = 403 ] || fail "the read-only key can delete"
  tok=$(qd_jwt /etc/rowsafe/qdrant/alt-api-key "{\"access\":\"m\",\"exp\":$(($(date +%s) + 300))}")
  [ "$(qdc "$tok" POST '/snapshots?wait=true')" = 200 ] || fail "a token signed with Rowsafe's key can't take a snapshot"
  snap=$(sed -n 's/.*"name":"\([^"]*\)".*/\1/p' "$W/qd.body")
  [ -n "$snap" ] && [ "$(qdc "$tok" DELETE "/snapshots/$snap")" = 200 ] || fail "deleting the snapshot"
  [ "$(qdc "$(qd_jwt /etc/rowsafe/qdrant/alt-api-key '{"access":"r"}')" DELETE /collections/app)" = 403 ] || fail "a read-only token can delete"
  [ "$(qdc "$(qd_jwt /etc/rowsafe/qdrant/read-only-api-key '{"access":"m"}')" GET /collections)" = 401 ] ||
    [ "$(qdc "$(qd_jwt /etc/rowsafe/qdrant/read-only-api-key '{"access":"m"}')" GET /collections)" = 403 ] || fail "a token signed with the read-only key works"
  [ "$(qdc "$(cat /etc/rowsafe/qdrant/api-key)" DELETE /collections/app)" = 200 ] || fail "removing the test collection"
  if curl -s --max-time 5 "http://$ip:6333/" 2>/dev/null | grep -q qdrant; then fail "plain HTTP from the network"; fi
  # What the agent does with a renewed certificate: the same files, written
  # by the agent's user; Qdrant serves it on REST within a minute
  # (tls.cert_ttl), without a restart.
  pid=$(systemctl show -p MainPID --value qdrant)
  # shellcheck disable=SC2016 # expands in the inner shell
  runuser -u rowsafe -- sh -c 'cd /etc/ssl/rowsafe-qdrant && umask 027 &&
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 -subj /CN=renewed.test \
      -keyout k.new -out c.new >/dev/null 2>&1 && chmod 0640 k.new && chmod 0644 c.new && mv -f k.new rowsafe-server.key && mv -f c.new rowsafe-server.crt' ||
    fail "the agent's user can't replace the certificate"
  want=$(openssl x509 -in /etc/ssl/rowsafe-qdrant/rowsafe-server.crt -noout -fingerprint -sha256)
  i=0
  until [ "$(echo | openssl s_client -connect 127.0.0.1:6333 2>/dev/null | openssl x509 -noout -fingerprint -sha256)" = "$want" ]; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || fail "the renewed certificate isn't served on 6333 within 100 seconds"
    sleep 1
  done
  [ "$(systemctl show -p MainPID --value qdrant)" = "$pid" ] || fail "Qdrant restarted for the certificate"
  pass "Qdrant from the network: TLS only on 6333 and 6334, keys only (Rowsafe's signs tokens), no cluster port, a renewed certificate loaded without a restart"
}

case ${1:-} in
  --in-container) in_container ;;
  --in-container-cloud) cloud_container ;;
  --in-container-cloud-engine)
    if [ "$2" = opensearch-own ]; then cloud_opensearch_own "$3"; else cloud_engine_container "$2" "$3"; fi ;;
  *) host "$@" ;;
esac
