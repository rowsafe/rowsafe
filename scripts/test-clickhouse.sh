#!/usr/bin/env bash
# ClickHouse engine integration test: runs the engine's Go integration test
# (compiled here, copied in) inside the official clickhouse/clickhouse-server
# images: the server and the clickhouse program as shipped, with an embedded
# Keeper (replicated tables), the test as a non-root user like the agent,
# and the bucket inside the test process. The first version makes Rowsafe's
# login as a users.d file, the others with SQL.
#
#   scripts/test-clickhouse.sh                      # ClickHouse 25.8 and 24.8
#   CLICKHOUSE_VERSIONS="25.8" scripts/test-clickhouse.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
VERSIONS=${CLICKHOUSE_VERSIONS:-25.8 24.8}
LIMIT=${TEST_TIMEOUT:-1800}

# timeout(1), or a perl stand-in where there is none (macOS).
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

(cd "$HERE" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go test -c -tags clickhouse_integration -o "$work/clickhouse.test" ./internal/engine/clickhouse/)
(cd "$HERE" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$work/rowsafe-agent" ./cmd/rowsafe-agent)
cat >"$work/keeper.xml" <<'XML'
<clickhouse>
  <keeper_server>
    <tcp_port>9181</tcp_port>
    <server_id>1</server_id>
    <log_storage_path>/var/lib/clickhouse/coordination/log</log_storage_path>
    <snapshot_storage_path>/var/lib/clickhouse/coordination/snapshots</snapshot_storage_path>
    <raft_configuration><server><id>1</id><hostname>localhost</hostname><port>9234</port></server></raft_configuration>
  </keeper_server>
  <zookeeper><node><host>localhost</host><port>9181</port></node></zookeeper>
  <macros><shard>01</shard><replica>r1</replica></macros>
</clickhouse>
XML

rc=0
mode=xml
for v in $VERSIONS; do
	img=rowsafe-test/clickhouse:$v
	cat >"$work/Dockerfile" <<DOCKERFILE
FROM clickhouse/clickhouse-server:$v
RUN useradd -m -s /bin/bash rowsafe
COPY keeper.xml /etc/clickhouse-server/config.d/keeper.xml
COPY clickhouse.test rowsafe-agent /usr/local/bin/
DOCKERFILE
	to 900 docker build -q -t "$img" "$work" >/dev/null
	name=rowsafe-test-clickhouse-$$-${v//./}
	containers="$containers $name"
	echo "==> ClickHouse $v, login made with $mode"
	if ! to "$LIMIT" docker run --rm --name "$name" -e CLICKHOUSE_SKIP_USER_SETUP=1 -e MODE=$mode --entrypoint bash "$img" -euc '
		/entrypoint.sh >/tmp/server.log 2>&1 &
		for _ in $(seq 1 120); do clickhouse-client -q "SELECT 1" >/dev/null 2>&1 && break; sleep 1; done
		echo "server $(clickhouse-client -q "SELECT version()")"
		# The installer contract: rowsafe-agent clickhouse status/login.
		agent() { su rowsafe -c "env ROWSAFE_STATE_DIR=/tmp/agent-state rowsafe-agent clickhouse $*"; }
		agent status --port 8123 | grep -qx login=missing
		if agent status --port 8124 >/dev/null 2>&1; then echo "status on a dead port succeeded"; exit 1; fi
		if [ "$MODE" = xml ]; then
			agent login --port 8123 --users-xml >/etc/clickhouse-server/users.d/rowsafe.xml
			chown root:clickhouse /etc/clickhouse-server/users.d/rowsafe.xml
			chmod 0640 /etc/clickhouse-server/users.d/rowsafe.xml
		else
			agent login --port 8123
		fi
		for _ in $(seq 1 30); do agent status --port 8123 | grep -qx login=ok && break; sleep 1; done
		agent status --port 8123
		agent status --port 8123 | grep -qx login=ok
		rm -f /etc/clickhouse-server/users.d/rowsafe.xml
		clickhouse-client -q "DROP USER IF EXISTS rowsafe" 2>/dev/null || true
		for _ in $(seq 1 30); do [ "$(clickhouse-client -q "SELECT count() FROM system.users WHERE name = '"'"'rowsafe'"'"'")" = 0 ] && break; sleep 1; done
		extra=""
		if [ "$MODE" = xml ]; then
			chown rowsafe:clickhouse /etc/clickhouse-server/users.d
			chmod 2770 /etc/clickhouse-server/users.d
			extra="ROWSAFE_TEST_CLICKHOUSE_USERSD=/etc/clickhouse-server/users.d"
		fi
		cd /tmp
		su rowsafe -c "env ROWSAFE_TEST_CLICKHOUSE_PORT=8123 ROWSAFE_TEST_CLICKHOUSE_REPLICATED=1 $extra \
			/usr/local/bin/clickhouse.test -test.v -test.count=1 -test.run TestClickHouse -test.timeout 25m" 2>&1 | tail -n 150
		exit ${PIPESTATUS[0]}
	'; then
		rc=1
		echo "FAIL: ClickHouse $v"
	fi
	mode=sql
done
exit $rc
