#!/usr/bin/env bash
# ClickHouse backup gateway integration test: starts the official
# clickhouse/clickhouse-server image and runs the gateway's Go integration
# test on this machine against it. ClickHouse reaches the gateway through
# host.docker.internal (Docker Desktop, and Linux with host-gateway): BACKUP
# of a database (MergeTree, ReplacingMergeTree, Log, materialized view), an
# incremental BACKUP on top, RESTORE ... AS another database through a
# read-only gateway, same row counts and checksums, and only ciphertext in
# the bucket.
#
#   scripts/test-clickhouse-gateway.sh                   # ClickHouse 25.8 and 24.8
#   CLICKHOUSE_VERSIONS="25.8" scripts/test-clickhouse-gateway.sh
#   ROWSAFE_TEST_CLICKHOUSE_ROWS=300000 scripts/test-clickhouse-gateway.sh   # quicker
#   ROWSAFE_TEST_BUCKET_DELAY=45s scripts/test-clickhouse-gateway.sh         # a slow bucket
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
VERSIONS=${CLICKHOUSE_VERSIONS:-25.8 24.8}

# timeout(1) is not on macOS by default.
to() {
	if command -v timeout >/dev/null; then
		timeout "$@"
	else
		perl -e 'alarm shift; exec @ARGV or die "exec: $!"' "$@"
	fi
}

rc=0
for v in $VERSIONS; do
	name=rowsafe-test-clickhouse-gw-$$-${v//./}
	echo "==> ClickHouse $v"
	to 600 docker pull -q "clickhouse/clickhouse-server:$v" >/dev/null
	to 120 docker run -d --rm --name "$name" -p 127.0.0.1::8123 -e CLICKHOUSE_PASSWORD=rowsafe-test \
		--add-host host.docker.internal:host-gateway "clickhouse/clickhouse-server:$v" >/dev/null
	trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
	port=$(docker port "$name" 8123/tcp | head -n1 | sed 's/.*://')
	deadline=$((SECONDS + 90))
	until curl -sf "http://127.0.0.1:$port/ping" >/dev/null; do
		if [ $SECONDS -gt $deadline ]; then
			echo "ClickHouse $v did not start"
			docker logs "$name" 2>&1 | tail -n 30
			exit 1
		fi
		sleep 1
	done
	if ! (cd "$HERE" && ROWSAFE_TEST_CLICKHOUSE_URL="http://127.0.0.1:$port/" ROWSAFE_TEST_CLICKHOUSE_PASSWORD=rowsafe-test \
		ROWSAFE_TEST_CLICKHOUSE_GATEWAY_HOST=host.docker.internal \
		to 1800 go test -timeout 29m -count=1 -tags clickhouse_integration -run TestClickHouse -v ./internal/objstore/s3gw/ 2>&1 | grep -v 'level=DEBUG' | tail -n 40; exit "${PIPESTATUS[0]}"); then
		rc=1
		echo "FAIL: ClickHouse $v"
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
done
exit $rc
