#!/usr/bin/env bash
# SQLite engine integration test on Linux, as in production: the engine's Go
# test (compiled here, copied in) runs as the agent's user "rowsafe" with
# the ACLs the installer gives, and the "app" is Python's sqlite3 module (C
# SQLite with POSIX locks) running as its own user "app" in another process,
# hammering a WAL database while the agent copies it: the app's checkpoints
# race the agent's, its WAL resets, a wal_checkpoint(TRUNCATE) of its own
# breaks the stream on purpose; then restores to several moments, a Mark
# and the newest point, Proof, Rewind copy/compare/rows/in place/undo,
# clones into a folder allowed for them, discovery of the files running
# programs have open, and the security check's fix through root's helper
# (the app's files, the agent's ACL).
#
#   scripts/test-sqlite.sh
#   TEST_RUN=TestFindOpen scripts/test-sqlite.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=${SQLITE_TEST_IMAGE:-debian:trixie-slim}
TEST_RUN=${TEST_RUN:-TestSQLite|TestFindOpen}
LIMIT=${TEST_TIMEOUT:-1500}

to() {
	if command -v timeout >/dev/null 2>&1; then
		timeout "$@"
	else
		perl -e '$s = shift; $pid = fork; if (!$pid) { exec @ARGV or exit 127 } $SIG{ALRM} = sub { kill "TERM", $pid; sleep 5; kill "KILL", $pid; exit 124 }; alarm $s; waitpid($pid, 0); exit($? >> 8)' "$@"
	fi
}

case $(docker info --format '{{.Architecture}}') in
aarch64 | arm64) arch=arm64 ;;
*) arch=amd64 ;;
esac
work=$(mktemp -d)
name=rowsafe-test-sqlite-$$
cleanup() {
	docker rm -f "$name" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

echo "==> compiling the test for linux/$arch"
(cd "$HERE" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=$arch go test -c -o "$work/sqlite.test" ./internal/engine/sqlite)
cp -R "$HERE/internal/engine/sqlite/testdata" "$work/testdata"

echo "==> running it in $IMAGE (agent as rowsafe, app as app)"
docker run -d --name "$name" -v "$work:/work:ro" "$IMAGE" sleep infinity >/dev/null
docker exec "$name" sh -euc '
	apt-get update -qq >/dev/null
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 acl sudo >/dev/null
	useradd -m app
	useradd -m rowsafe
	echo "rowsafe ALL=(app) NOPASSWD: ALL" >/etc/sudoers.d/rowsafe-test
	# TestSQLiteSecurity: root'"'"'s helper for SQLite files is this test binary,
	# run as root (it stands in for rowsafe-sqlite-modes.service).
	echo "rowsafe ALL=(root) NOPASSWD: /opt/pkg/sqlite.test" >>/etc/sudoers.d/rowsafe-test
	chmod 0440 /etc/sudoers.d/rowsafe-test
	# The app'"'"'s folder, as the installer leaves it: the agent may write in it,
	# and SQLite side files created there work for both users.
	install -d -o app -g app -m 0755 /srv/app/db
	setfacl -m u:rowsafe:rwx /srv/app/db
	setfacl -d -m u::rw-,g::r--,o::r--,u:rowsafe:rw-,u:app:rw- /srv/app/db
	# A folder for clones, as --sqlite-clone-dir leaves it (the app owns it).
	install -d -o app -g app -m 0750 /srv/app/clones
	setfacl -m u:rowsafe:rwx /srv/app/clones
	setfacl -d -m u::rw-,g::rw-,o::---,u:rowsafe:rw-,u:app:rw- /srv/app/clones
	install -d -o rowsafe -g rowsafe -m 0755 /opt/pkg
	cp -R /work/sqlite.test /work/testdata /opt/pkg/
	chown -R rowsafe:rowsafe /opt/pkg && chmod -R a+rX /opt/pkg
'
to "$LIMIT" docker exec -u rowsafe -w /opt/pkg \
	-e USER=rowsafe -e HOME=/home/rowsafe \
	-e ROWSAFE_TEST_SQLITE_INTEROP=1 -e ROWSAFE_TEST_SQLITE_DIR=/srv/app/db -e ROWSAFE_TEST_SQLITE_CLONE_DIR=/srv/app/clones -e ROWSAFE_TEST_SQLITE_APP_USER=app \
	"$name" ./sqlite.test -test.count=1 -test.v -test.run "$TEST_RUN" -test.timeout "${LIMIT}s"
echo "==> SQLite integration test passed"
