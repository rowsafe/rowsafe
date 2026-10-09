#!/usr/bin/env bash
# Qdrant engine integration test: runs the engine's Go integration test
# (compiled here, copied in) inside Qdrant's official image: the server as
# shipped, with TLS on REST and gRPC, an admin key, a read-only key,
# Rowsafe's own key (alt_api_key) and JWT access control on; the test as a
# non-root user like the agent, with the image's qdrant program for Proof
# and copies, and the bucket inside the test process. Then it runs again as
# a Docker sidecar (the server in its own container, the test in another
# with ROWSAFE_QDRANT_URL).
#
#   scripts/test-qdrant.sh
#   QDRANT_IMAGES="qdrant/qdrant:v1.19.2" DOCKER_MODE=no scripts/test-qdrant.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
IMAGES=${QDRANT_IMAGES:-qdrant/qdrant:v1.19.2}
LIMIT=${TEST_TIMEOUT:-1200}
TEST_RUN=${TEST_RUN:-TestQdrant}
ADMIN=rowsafe-test-admin-key-$$-0123456789abcdef
ALT=rowsafe-test-alt-key-$$-0123456789abcdef0
RO=rowsafe-test-ro-key-$$-0123456789abcdef01

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
	docker network rm "rowsafe-test-qdrant-$$" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

(cd "$HERE" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOWORK=off go test -c -tags qdrant_integration -o "$work/qdrant.test" ./internal/engine/qdrant/)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/key.pem" -out "$work/cert.pem" -days 2 \
	-subj /CN=localhost -addext "subjectAltName=DNS:localhost,DNS:server,IP:127.0.0.1" 2>/dev/null
cat >"$work/config.yaml" <<YAML
log_level: WARN
telemetry_disabled: true
storage:
  storage_path: /qdrant/storage
  snapshots_path: /qdrant/snapshots
service:
  host: 0.0.0.0
  http_port: 6333
  grpc_port: 6334
  enable_tls: true
  enable_cors: false
  jwt_rbac: true
  enable_snapshot_url_recovery: false
  api_key: $ADMIN
  alt_api_key: $ALT
  read_only_api_key: $RO
cluster:
  enabled: false
tls:
  cert: /etc/rowsafe-test/cert.pem
  key: /etc/rowsafe-test/key.pem
  cert_ttl: 60
YAML

image() { # image SOURCE -> tag
	cat >"$work/Dockerfile" <<DOCKERFILE
FROM $1
RUN useradd -m -s /bin/bash rowsafe && mkdir -p /etc/rowsafe-test
COPY config.yaml cert.pem key.pem /etc/rowsafe-test/
COPY qdrant.test /usr/local/bin/
RUN chmod 0644 /etc/rowsafe-test/* && chmod 0755 /usr/local/bin/qdrant.test
DOCKERFILE
	local tag
	tag="rowsafe-test/qdrant:$(echo "$1" | tr '/:' '--')"
	to 900 docker build -q -t "$tag" "$work" >/dev/null
	echo "$tag"
}

run_test() { # run_test CONTAINER ENV...
	local c=$1
	shift
	to "$LIMIT" docker exec "$@" -e ROWSAFE_TEST_QDRANT_PORT=6333 -e ROWSAFE_TEST_QDRANT_ADMIN_KEY=$ADMIN -e ROWSAFE_TEST_QDRANT_ALT_KEY=$ALT \
		-e ROWSAFE_QDRANT_BIN=/qdrant/qdrant -e ROWSAFE_QDRANT_CONFIG=/etc/rowsafe-test/config.yaml -u rowsafe -w /tmp "$c" \
		/usr/local/bin/qdrant.test -test.v -test.count=1 -test.timeout=$((LIMIT - 60))s -test.run "$TEST_RUN"
}

wait_ready() { # wait_ready CONTAINER
	for _ in $(seq 60); do
		if docker exec "$1" bash -c 'exec 3<>/dev/tcp/127.0.0.1/6333' 2>/dev/null; then return 0; fi
		sleep 1
	done
	docker logs "$1" | tail -n 20
	return 1
}

rc=0
first=""
for src in $IMAGES; do
	tag=$(image "$src")
	first=${first:-$tag}
	c="rowsafe-test-qdrant-$$-$(echo "$src" | tr '/:.' '---')"
	containers="$containers $c"
	echo "==> $src (native: the server and the test in one container)"
	docker run -d --name "$c" --entrypoint /qdrant/qdrant -w /qdrant "$tag" --config-path /etc/rowsafe-test/config.yaml >/dev/null
	wait_ready "$c"
	if ! run_test "$c"; then
		echo "FAIL: $src" >&2
		docker logs "$c" 2>&1 | tail -n 30
		rc=1
	fi
	docker rm -f "$c" >/dev/null
done

if [ "${DOCKER_MODE:-yes}" = yes ] && [ -n "$first" ]; then
	echo "==> ${IMAGES%% *} as a Docker sidecar"
	net="rowsafe-test-qdrant-$$"
	docker network create "$net" >/dev/null
	s="rowsafe-test-qdrant-$$-server"
	a="rowsafe-test-qdrant-$$-agent"
	containers="$containers $s $a"
	docker run -d --name "$s" --network "$net" --network-alias server --entrypoint /qdrant/qdrant -w /qdrant "$first" --config-path /etc/rowsafe-test/config.yaml >/dev/null
	docker run -d --name "$a" --network "$net" --entrypoint sleep "$first" infinity >/dev/null
	wait_ready "$s"
	if ! run_test "$a" -e ROWSAFE_QDRANT_URL=https://server:6333; then
		echo "FAIL: Docker sidecar" >&2
		rc=1
	fi
fi
exit $rc
