#!/usr/bin/env bash
# Redis and Valkey engine integration test: runs the engine's Go integration
# test (compiled here, copied in) inside the official redis and
# valkey/valkey images: the server and its program as shipped, the server
# as its own user with a configuration file it can rewrite, the test as a
# non-root user like the agent, and the bucket inside the test process.
# Then the first image runs again as a Docker sidecar (the server in its own
# container, the test in another with ROWSAFE_REDIS_HOST and the data volume
# mounted read only).
#
#   scripts/test-redis.sh
#   REDIS_IMAGES="valkey/valkey:8.1" DOCKER_MODE=no scripts/test-redis.sh
#   TEST_RUN=TestRedisSnapshotMode REDIS_IMAGES="redis:7.4" scripts/test-redis.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
IMAGES=${REDIS_IMAGES:-redis:7.0 redis:7.4 redis:8.2 redis:8.10 valkey/valkey:7.2 valkey/valkey:8.1 valkey/valkey:9.0}
LIMIT=${TEST_TIMEOUT:-1500}
TEST_RUN=${TEST_RUN:-TestRedis}
PASS=rowsafe-test-admin-password

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
containers=""
cleanup() {
	for c in $containers; do docker rm -f "$c" >/dev/null 2>&1 || true; done
	docker network rm "rowsafe-test-redis-$$" >/dev/null 2>&1 || true
	docker volume rm "rowsafe-test-redis-$$-data" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

(cd "$HERE" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOWORK=off go test -c -tags redis_integration -o "$work/redis.test" ./internal/engine/redis/)

image() { # image SOURCE -> tag
	local src=$1 engine=redis user=redis bin=redis-server
	case $src in valkey*) engine=valkey user=valkey bin=valkey-server ;; esac
	cat >"$work/Dockerfile" <<DOCKERFILE
FROM $src
RUN useradd -m -s /bin/bash rowsafe 2>/dev/null || adduser -D rowsafe; \
    mkdir -p /etc/rowsafe-test && printf 'port 6379\nbind 0.0.0.0\nprotected-mode no\nrequirepass $PASS\ndir /data\nsave ""\nappendonly no\n' >/etc/rowsafe-test/server.conf && \
    chown -R $user /etc/rowsafe-test /data
COPY redis.test /usr/local/bin/
ENV ROWSAFE_TEST_REDIS_ENGINE=$engine ROWSAFE_TEST_SERVER_BIN=$bin ROWSAFE_TEST_SERVER_USER=$user
DOCKERFILE
	local tag="rowsafe-test/redis:$(echo "$src" | tr '/:' '--')"
	to 900 docker build -q -t "$tag" "$work" >/dev/null
	echo "$tag"
}

run_test() { # run_test CONTAINER USER ENV...
	local c=$1 u=$2
	shift 2
	to "$LIMIT" docker exec "$@" -e ROWSAFE_TEST_REDIS_PORT=6379 -e ROWSAFE_TEST_REDIS_ADMIN_PASSWORD=$PASS -u "$u" -w /tmp "$c" \
		/usr/local/bin/redis.test -test.v -test.count=1 -test.timeout=$((LIMIT - 60))s -test.run "$TEST_RUN"
}

rc=0
first=""
for src in $IMAGES; do
	tag=$(image "$src")
	first=${first:-$tag}
	c="rowsafe-test-redis-$$-$(echo "$src" | tr '/:.' '---')"
	containers="$containers $c"
	echo "==> $src (native: the server and the test in one container)"
	docker run -d --name "$c" "$tag" sleep infinity >/dev/null
	docker exec "$c" sh -c 'su -s /bin/sh "$ROWSAFE_TEST_SERVER_USER" -c "$ROWSAFE_TEST_SERVER_BIN /etc/rowsafe-test/server.conf --daemonize yes"'
	sleep 1
	if ! run_test "$c" rowsafe; then
		echo "FAIL: $src" >&2
		docker exec "$c" sh -c 'tail -n 30 /data/*.log 2>/dev/null || true'
		rc=1
	fi
	docker rm -f "$c" >/dev/null
done

if [ "${DOCKER_MODE:-yes}" = yes ] && [ -n "$first" ]; then
	echo "==> ${IMAGES%% *} as a Docker sidecar"
	net="rowsafe-test-redis-$$"
	vol="rowsafe-test-redis-$$-data"
	docker network create "$net" >/dev/null
	docker volume create "$vol" >/dev/null
	s="rowsafe-test-redis-$$-server"
	a="rowsafe-test-redis-$$-agent"
	containers="$containers $s $a"
	docker run -d --name "$s" --network "$net" -v "$vol:/data" "$first" sh -c 'chown "$ROWSAFE_TEST_SERVER_USER" /data; exec su -s /bin/sh "$ROWSAFE_TEST_SERVER_USER" -c "$ROWSAFE_TEST_SERVER_BIN /etc/rowsafe-test/server.conf"' >/dev/null
	docker run -d --name "$a" --network "$net" -v "$vol:/srv-data:ro" "$first" sleep infinity >/dev/null
	sleep 2
	# As the agent image runs: the image's own user (uid 999), which owns the
	# server's files in the shared volume (the images' umask is 0077).
	if ! run_test "$a" 999 -e ROWSAFE_REDIS_HOST="$s" -e ROWSAFE_REDIS_DATA_DIR=/srv-data; then
		echo "FAIL: Docker sidecar" >&2
		rc=1
	fi
fi
exit $rc
