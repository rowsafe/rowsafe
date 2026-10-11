#!/usr/bin/env bash
# Meilisearch engine integration test: runs the engine's Go integration test
# (compiled here, copied in) inside Meilisearch's official image, as a
# non-root user like the agent, with the image's meilisearch program for
# "production", Proof, copies and rewinds, and the bucket inside the test
# process.
#
#   scripts/test-meilisearch.sh
#   MEILISEARCH_IMAGES="getmeili/meilisearch:v1.54.3" scripts/test-meilisearch.sh
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
cleanup() {
	for c in $containers; do docker rm -f "$c" >/dev/null 2>&1 || true; done
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
exit $rc
