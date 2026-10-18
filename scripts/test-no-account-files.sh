#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Test files on a server on its own (the installer's --no-account), for
# real: a Debian server with systemd as PID 1, PostgreSQL, pgBackRest,
# restic and a MinIO bucket; the agent runs its own control plane
# (internal/localcp) and the rowsafe CLI on the server talks to it.
#
#   - A Docker volume with no database (docker:VOLUME; the volume is a real
#     one mounted where Docker keeps it, behind Docker's 0710 folder, and the
#     docker CLI is a stub that names its folder): rowsafe gives the agent
#     read access (an ACL) and backs it up as the server's own.
#   - An app's uploads (www-data's, closed to others) with the database shop.
#   - Files deleted, changed and added; each restored into another folder
#     and compared with the originals; the live folders untouched.
#   - In place: refused without the typed name; with it, a Mark first; the
#     agent can't write into www-data's folder, so the files wait next to it.
#   - A folder the agent may write: missing files back in place, a
#     whole-folder restore and its undo.
#   - rowsafe status, files Proof, snapshots, alert rules, an agent restart.
#
# Usage: sh scripts/test-no-account-files.sh [debian:trixie]   (needs Docker, ~6 min)

set -eu
# The MinIO test image (built once from source: scripts/minio).
MINIO_SH=$(cd "$(dirname "$0")" && pwd)/minio/image.sh

fail() {
  echo "test-no-account-files: $*" >&2
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

# same DIR1 DIR2: the same files with the same contents.
same() {
  diff -r "$1" "$2" >/tmp/diff.out 2>&1 || {
    cat /tmp/diff.out >&2
    return 1
  }
}

# rfc3339 now, a second after the newest snapshot (times are to the second).
point() {
  sleep 2
  date -u +%Y-%m-%dT%H:%M:%SZ
  sleep 2
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
  echo "PostgreSQL $major, restic $(restic version | cut -d' ' -f2) and the agent (no account) are running"
  until_ok 30 "the agent's control plane listens" test -S /var/lib/rowsafe/control.sock
  until_ok 30 "the server is enrolled" sh -c "rowsafe status 2>&1 | grep -q '1 host'"

  # The folders. A Docker volume: Docker's own folders are closed (0710,
  # 0701), its data root's; the stub CLI answers docker volume inspect.
  vol=/var/lib/docker/volumes/appdata/_data
  chmod 0710 /var/lib/docker
  chmod 0701 /var/lib/docker/volumes
  mkdir -p "$vol/db" "$vol/config"
  head -c 300000 /dev/urandom >"$vol/db/data.bin"
  echo "setting=1" >"$vol/config/app.conf"
  echo "keep me" >"$vol/config/notes.txt"
  chown -R root:root "$vol"
  chmod 0700 "$vol"
  cat >/usr/local/bin/docker <<'EOF'
#!/bin/sh
# Test stub: the Docker CLI's answer for the volume mounted where Docker keeps it.
[ "$1 $2" = "volume inspect" ] || exit 1
for v; do :; done
[ "$v" = appdata ] || { echo "Error response from daemon: get $v: no such volume" >&2; exit 1; }
echo /var/lib/docker/volumes/appdata/_data
EOF
  chmod 0755 /usr/local/bin/docker
  # An app's uploads: www-data's, closed to other users.
  up=/var/www/uploads
  mkdir -p "$up/cvs" "$up/photos"
  echo "CV of Ada" >"$up/cvs/ada.pdf"
  echo "CV of Bob" >"$up/cvs/bob.pdf"
  head -c 500000 /dev/urandom >"$up/photos/team.jpg"
  chown -R www-data:www-data /var/www
  chmod -R o-rwx "$up"
  ! runuser -u postgres -- ls "$up" >/dev/null 2>&1 || fail "the agent could read the uploads before it was allowed"

  # No database yet: the volume is the server's own. Read access first
  # (asked; --yes answers), then protected.
  ! rowsafe files add docker:nope --yes >/tmp/nope.out 2>&1 || fail "an unknown volume was added"
  grep -q "no such volume" /tmp/nope.out || { cat /tmp/nope.out; fail "no plain answer for an unknown volume"; }
  rowsafe files add docker:appdata --yes | tee /tmp/addvol.out || fail "rowsafe files add docker:appdata"
  grep -q ": protecting $vol" /tmp/addvol.out || fail "the volume wasn't protected as the server's own"
  getfacl -p "$vol" 2>/dev/null | grep -q "^user:postgres:r-x" || fail "no read ACL on the volume"
  runuser -u postgres -- ls "$vol/config" >/dev/null || fail "the agent can't read the volume"
  rowsafe files --server | grep -q "$vol" || fail "rowsafe files --server doesn't list the volume"
  rowsafe files backup --server | tee /tmp/bkvol.out || fail "rowsafe files backup --server"
  echo "  ok: a Docker volume with no database, readable through an ACL, backed up"

  # The database, protected (rowsafe add, the restart through the root
  # helper, the check, the first backup).
  runuser -u postgres -- psql -qX -c "CREATE ROLE app LOGIN SUPERUSER PASSWORD 'app-pw'" -c "CREATE DATABASE shop OWNER app" ||
    fail "the app role and database"
  rowsafe add shop "postgres://app:app-pw@localhost:5432/shop" --yes >/tmp/add.out || { cat /tmp/add.out; fail "rowsafe add"; }
  until_ok 60 "restarts are allowed" sh -c "rowsafe show shop --json 2>/dev/null | grep -q '\"can_restart\": true'"
  rowsafe restart shop --yes >/dev/null || fail "rowsafe restart"
  until_ok 180 "shop is active" sh -c "rowsafe ls | grep shop | grep -q active"

  # The uploads go with shop.
  rowsafe files add shop "$up" --yes | tee /tmp/addup.out || fail "rowsafe files add shop"
  grep -q "shop: protecting $up" /tmp/addup.out || fail "the uploads weren't protected with shop"
  rowsafe files backup shop || fail "rowsafe files backup shop"
  rowsafe files shop | tee /tmp/files.out
  grep "$up" /tmp/files.out | grep -q " ok " || fail "the uploads aren't ok after a backup"
  rowsafe files snapshots shop | tee /tmp/snaps.out
  grep -Eq "^[0-9-]+ [0-9:]+ +[0-9a-f]{8} " /tmp/snaps.out || fail "rowsafe files snapshots lists no snapshot"
  echo "  ok: the uploads backed up with shop, snapshots listed"

  # Then things go wrong: deleted, changed, added.
  snap=$(rowsafe files snapshots --server --json | grep -o '"id": *"[0-9a-f]*"' | head -1 | sed 's/.*"\([0-9a-f]*\)"$/\1/')
  [ -n "$snap" ] || fail "no snapshot ID for the volume"
  mkdir -p /root/orig
  cp -a "$up" /root/orig/uploads
  cp -a "$vol" /root/orig/appdata
  T=$(point)
  rm "$up/cvs/ada.pdf" "$vol/config/notes.txt"
  echo "overwritten by a bug" >"$up/cvs/bob.pdf"
  echo "setting=2" >"$vol/config/app.conf"
  echo "added later" >"$up/cvs/new.pdf"
  chown www-data:www-data "$up/cvs/new.pdf"

  # Into another folder: everything as it was; the live folders untouched.
  rowsafe files restore shop --at "$T" --into /srv/restored/uploads | tee /tmp/into.out || fail "restore into another folder"
  grep -q "wasn't changed" /tmp/into.out || fail "the summary doesn't say the folder wasn't changed"
  same /root/orig/uploads /srv/restored/uploads || fail "the restored uploads differ from the originals"
  [ "$(stat -c %U:%a /srv/restored/uploads)" = "postgres:700" ] || fail "the restored folder is open to others"
  rowsafe files restore --server --snapshot "$snap" --into /srv/restored/appdata | tee /tmp/intovol.out || fail "restore the volume into another folder"
  same /root/orig/appdata /srv/restored/appdata || fail "the restored volume differs from the original"
  [ "$(cat "$up/cvs/bob.pdf")" = "overwritten by a bug" ] && [ ! -e "$up/cvs/ada.pdf" ] && [ ! -e "$vol/config/notes.txt" ] ||
    fail "restoring into another folder changed a live one"
  ! rowsafe files restore shop --at "$T" --into /srv/restored/uploads >/tmp/full.out 2>&1 || fail "restored into a folder that isn't empty"
  echo "  ok: the uploads and the volume restored into other folders match the originals; live folders untouched"

  # In place: only with the typed name; a Mark first. The agent may only
  # read www-data's folder, so the missing file waits next to it.
  ! rowsafe files restore shop --at "$T" </dev/null >/tmp/noconfirm.out 2>&1 || fail "restored in place without a confirmation"
  rowsafe files restore shop --at "$T" --yes | tee /tmp/inplace.out || fail "restore in place"
  rowsafe marks shop | grep -q "before-files-restore-" || fail "no Mark before restoring in place"
  held=$(grep -o '/var/lib/rowsafe/files-restored/[^ ,]*' /tmp/inplace.out | head -1 | sed 's/\.$//')
  [ -n "$held" ] && cmp -s "$held/cvs/ada.pdf" /root/orig/uploads/cvs/ada.pdf || fail "the missing file isn't waiting next to the folder"
  [ "$(cat "$up/cvs/bob.pdf")" = "overwritten by a bug" ] || fail "a changed file was overwritten without --overwrite"
  echo "  ok: in place needs the name, saves a Mark first; files it can't write wait in $held"

  # A folder the agent may write: in place for real, a whole-folder
  # restore and its undo.
  ex=/srv/exports
  install -d -o postgres -g postgres "$ex"
  runuser -u postgres -- sh -c "echo 'id,total' >$ex/a.csv && echo 'id,name' >$ex/b.csv"
  rowsafe files add --server "$ex" || fail "rowsafe files add --server $ex"
  rowsafe files backup --server >/dev/null || fail "backup of $ex"
  T2=$(point)
  rm "$ex/a.csv"
  runuser -u postgres -- sh -c "echo later >$ex/added.csv"
  rowsafe files restore --server --folder "$ex" --at "$T2" --yes | tee /tmp/ex.out || fail "restore $ex in place"
  [ "$(cat "$ex/a.csv")" = "id,total" ] || fail "a.csv isn't back in place"
  [ -e "$ex/added.csv" ] || fail "a missing-files restore removed a file"
  rowsafe files restore --server --folder "$ex" --at "$T2" --whole-folder --yes >/dev/null || fail "whole-folder restore"
  [ ! -e "$ex/added.csv" ] || fail "the whole-folder restore kept a file added since"
  until_ok 90 "the kept folder is reported" sh -c "rowsafe files --server | grep -q 'rowsafe files undo --server'"
  rowsafe files undo --server --yes || fail "rowsafe files undo --server"
  [ "$(cat "$ex/added.csv")" = later ] || fail "undo didn't put added.csv back"
  echo "  ok: in place, whole folder and undo on a folder the agent may write"

  # Status, Proof, schedules, alert rules, an agent restart.
  rowsafe files set --server --every 30m --keep-days 60 | grep -q "every 30 minutes, kept 60 days" || fail "rowsafe files set"
  rowsafe files proof shop | tee /tmp/proof.out || fail "files Proof"
  until_ok 120 "rowsafe status lists the folders" sh -c "rowsafe status >/tmp/status.out 2>&1; grep -q 'Files:' /tmp/status.out && grep -q '$up (shop): ok' /tmp/status.out && grep -q '$vol (the server itself): ok' /tmp/status.out"
  cat /tmp/status.out
  rowsafe alerts rules | grep -q files_backup_stale || fail "no files alert rules"
  ! rowsafe alerts 2>/dev/null | grep -q "files_" || fail "a files alert fires on a healthy server"
  systemctl restart rowsafe-agent
  until_ok 30 "the control plane is back" test -S /var/lib/rowsafe/control.sock
  rowsafe files shop | grep -q "$up" || fail "the uploads were forgotten after an agent restart"
  rowsafe files --server | grep -q "every 30 minutes" || fail "the server's settings were forgotten after an agent restart"
  echo "  ok: status, Proof, settings, alert rules; all kept across an agent restart"
}

host() {
  image=${1:-debian:trixie}
  root=$(cd "$(dirname "$0")/.." && pwd)
  docker info >/dev/null 2>&1 || {
    echo "test-no-account-files: Docker is not available" >&2
    exit 1
  }
  arch=$(docker version --format '{{.Server.Arch}}')
  W=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-files.XXXXXX")
  chmod 0755 "$W"
  name=rowsafe-files-$$
  cleanup() {
    docker rm -f "$name-pg" "$name-minio" >/dev/null 2>&1 || true
    docker volume rm "$name-pgdata" "$name-appdata" >/dev/null 2>&1 || true
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
      echo "test-no-account-files: MinIO did not come up" >&2
      exit 1
    }
    sleep 1
  done

  tag=rowsafe-test/files:$(echo "$image" | tr ':/' '--')
  echo "building $tag"
  docker build -q -t "$tag" - >/dev/null <<EOF
FROM $image
ENV container=docker
RUN apt-get update -qq && \\
    apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus ca-certificates procps util-linux \\
      postgresql pgbackrest restic acl >/dev/null && \\
    rm -f /lib/systemd/system/multi-user.target.wants/getty* && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN ln -sf /dev/null /etc/systemd/system/systemd-binfmt.service && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.automount && \\
    ln -sf /dev/null /etc/systemd/system/proc-sys-fs-binfmt_misc.mount
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
EOF
  # The app's Docker volume, mounted where Docker keeps volumes.
  docker run -d --name "$name-pg" --network "$name" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --shm-size 256m \
    -v "$name-pgdata:/var/lib/postgresql" -v "$name-appdata:/var/lib/docker/volumes/appdata/_data" \
    -v "$root:/src:ro" -v "$W:/w" \
    -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" "$tag" >/dev/null
  i=0
  until docker exec "$name-pg" systemctl is-system-running --wait >/dev/null 2>&1 ||
    [ "$(docker exec "$name-pg" systemctl is-system-running 2>/dev/null)" = degraded ]; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || {
      echo "test-no-account-files: systemd did not start in the container" >&2
      exit 1
    }
    sleep 1
  done
  docker exec -e S3_SECRET="$secret" -e CIPHER_PASS="$cipher" "$name-pg" sh /src/scripts/test-no-account-files.sh --in-container
  echo "test-no-account-files: passed on $image"
}

case ${1:-} in
  --in-container) in_container ;;
  *) host "$@" ;;
esac
