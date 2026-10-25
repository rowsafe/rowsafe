#!/usr/bin/env bash
# Meilisearch engine integration test: runs the engine's Go integration test
# (compiled here, copied in) inside Meilisearch's official image, as a
# non-root user like the agent, with the image's meilisearch program for
# "production", Proof, copies and rewinds, and the bucket inside the test
# process.
#
# Then, as a Docker sidecar: Meilisearch in its own container, the test in
# the agent's image (deploy/docker/agent-meilisearch.Dockerfile, built
# here) on the same network, reading the snapshots from a shared volume, as
# compose.meilisearch.example.yml sets it up.
#
#   scripts/test-meilisearch.sh
#   MEILISEARCH_IMAGES="getmeili/meilisearch:v1.54.3" scripts/test-meilisearch.sh
#   SIDECAR=0 scripts/test-meilisearch.sh    # without the sidecar run
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
IMAGES=${MEILISEARCH_IMAGES:-getmeili/meilisearch:v1.54.3}
LIMIT=${TEST_TIMEOUT:-1200}
TEST_RUN=${TEST_RUN:-TestIntegration}

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
net="rowsafe-test-meilisearch-$$"
vol="rowsafe-test-meilisearch-snapshots-$$"
# shellcheck disable=SC2329 # the EXIT trap runs it
cleanup() {
	for c in $containers; do docker rm -f "$c" >/dev/null 2>&1 || true; done
	docker network rm "$net" >/dev/null 2>&1 || true
	docker volume rm "$vol" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

(cd "$HERE" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOWORK=off go test -c -tags meilisearch_integration -o "$work/meilisearch.test" ./internal/engine/meilisearch/)

rc=0
for src in $IMAGES; do
	c="rowsafe-test-meilisearch-$$-$(echo "$src" | tr '/:.' '---')"
	containers="$containers $c"
	echo "==> $src"
	docker run -d --name "$c" --entrypoint sleep "$src" infinity >/dev/null
	docker cp "$work/meilisearch.test" "$c:/usr/local/bin/meilisearch.test"
	docker exec "$c" sh -c 'adduser -D rowsafe 2>/dev/null || useradd -m rowsafe; chmod 0755 /usr/local/bin/meilisearch.test'
	if ! to "$LIMIT" docker exec -e ROWSAFE_TEST_MEILISEARCH_BIN="$(docker exec "$c" sh -c 'command -v meilisearch')" -u rowsafe -w /tmp "$c" \
		/usr/local/bin/meilisearch.test -test.v -test.count=1 -test.timeout=$((LIMIT - 60))s -test.run "$TEST_RUN"; then
		echo "FAIL: $src" >&2
		rc=1
	fi
	docker rm -f "$c" >/dev/null
done

# The sidecar: the agent image of the release Rowsafe pins, next to it.
if [ "${SIDECAR:-1}" = 1 ]; then
	agent=rowsafe-test/agent:meilisearch1
	if ! docker image inspect "$agent" >/dev/null 2>&1; then
		echo "==> building the agent image for Meilisearch"
		to 1800 docker build -q -f "$HERE/deploy/docker/agent-meilisearch.Dockerfile" -t "$agent" "$HERE" >/dev/null
	fi
	docker network create "$net" >/dev/null
	master=$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')
	src=getmeili/meilisearch:v$(sed -n 's/^ARG DB_VERSION=//p' "$HERE/deploy/docker/agent-meilisearch.Dockerfile")
	cs="rowsafe-test-meilisearch-$$-db"
	containers="$containers $cs"
	echo "==> $src (sidecar)"
	docker run -d --name "$cs" --network "$net" --network-alias meilisearch -e MEILI_MASTER_KEY="$master" -e MEILI_NO_ANALYTICS=true \
		-e MEILI_SNAPSHOT_DIR=/meili_snapshots -v "$vol:/meili_snapshots" "$src" >/dev/null
	if ! to "$LIMIT" docker run --rm --network "$net" -v "$vol:/meili_snapshots:ro" -v "$work/meilisearch.test:/usr/local/bin/meilisearch.test:ro" \
		-e ROWSAFE_TEST_MEILISEARCH_URL=http://meilisearch:7700 -e ROWSAFE_TEST_MEILISEARCH_MASTER="$master" -w /tmp \
		--entrypoint /usr/local/bin/meilisearch.test "$agent" -test.v -test.count=1 -test.timeout=$((LIMIT - 60))s -test.run TestSidecarIntegration; then
		echo "FAIL: $src (sidecar)" >&2
		docker logs --tail 30 "$cs" >&2 || true
		rc=1
	fi
fi
exit $rc
