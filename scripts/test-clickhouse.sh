#!/usr/bin/env bash
# ClickHouse engine integration test: runs the engine's Go integration test
# (compiled here, copied in) inside the official clickhouse/clickhouse-server
# images: the server and the clickhouse program as shipped, with an embedded
# Keeper (replicated tables), the test as a non-root user like the agent,
# and the bucket inside the test process. The first version makes Rowsafe's
# login as a users.d file, the others with SQL; then the first version runs
# again as a Docker sidecar (ClickHouse in its own container with a
# password, the agent in another, ROWSAFE_CLICKHOUSE_URL and the gateway on
# the containers' network).
#
#   scripts/test-clickhouse.sh                      # ClickHouse 26.8, 26.3, 25.8 and 24.8, then 26.8 in Docker
#   CLICKHOUSE_VERSIONS="25.8" DOCKER_MODE=no scripts/test-clickhouse.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
VERSIONS=${CLICKHOUSE_VERSIONS:-26.8 26.3 25.8 24.8}
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
	docker network rm "rowsafe-test-clickhouse-$$" >/dev/null 2>&1 || true
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
  <backups><allowed_path>/var/lib/rowsafe-dl/</allowed_path></backups>
</clickhouse>
XML

image() {
	cat >"$work/Dockerfile" <<DOCKERFILE
FROM clickhouse/clickhouse-server:$1
RUN useradd -m -s /bin/bash rowsafe && install -d -o rowsafe -g clickhouse -m 2750 /var/lib/rowsafe-dl
COPY keeper.xml /etc/clickhouse-server/config.d/keeper.xml
COPY clickhouse.test rowsafe-agent /usr/local/bin/
DOCKERFILE
	to 900 docker build -q -t "rowsafe-test/clickhouse:$1" "$work" >/dev/null
}

rc=0
if [ "${CLICKHOUSE_CLONE:-}" = 1 ]; then
	# Clones: a second, empty server in the same container (its own ports,
	# data and Keeper ports).
	v=${VERSIONS%% *}
	img=rowsafe-test/clickhouse:$v
	image "$v"
	name=rowsafe-test-clickhouse-clone-$$
	containers="$containers $name"
	echo "==> ClickHouse $v, clone into a second server"
	to "$LIMIT" docker run --rm --name "$name" -e CLICKHOUSE_SKIP_USER_SETUP=1 --entrypoint bash "$img" -euc '
		/entrypoint.sh >/tmp/server.log 2>&1 &
		install -d -o clickhouse -g clickhouse /tmp/ch2
		su clickhouse -s /bin/sh -c "clickhouse-server --config-file=/etc/clickhouse-server/config.xml -- \
			--http_port=8125 --tcp_port=9005 --mysql_port=9006 --postgresql_port=9007 --interserver_http_port=9019 \
			--path=/tmp/ch2/ --tmp_path=/tmp/ch2/tmp/ --user_files_path=/tmp/ch2/user_files/ --format_schema_path=/tmp/ch2/format_schemas/ \
			--access_control_path=/tmp/ch2/access/ --logger.log=/tmp/ch2/server.log --logger.errorlog=/tmp/ch2/error.log \
			--keeper_server.tcp_port=9182 --keeper_server.raft_configuration.server.port=9235 \
			--keeper_server.log_storage_path=/tmp/ch2/coordination/log --keeper_server.snapshot_storage_path=/tmp/ch2/coordination/snapshots \
			--zookeeper.node.port=9182 >/tmp/ch2.out 2>&1 &"
		for p in 8123 8125; do
			for _ in $(seq 1 120); do wget -qO- "http://127.0.0.1:$p/ping" >/dev/null 2>&1 && break; sleep 1; done
		done
		cd /tmp
		su rowsafe -c "env ROWSAFE_TEST_CLICKHOUSE_PORT=8123 ROWSAFE_TEST_CLICKHOUSE_CLONE_PORT=8125 \
			/usr/local/bin/clickhouse.test -test.v -test.count=1 -test.run TestClickHouseClone -test.timeout 20m" 2>&1 | tail -n 80
		exit ${PIPESTATUS[0]}
	' || rc=1
	exit $rc
fi
mode=xml
for v in $VERSIONS; do
	img=rowsafe-test/clickhouse:$v
	image "$v"
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
		su rowsafe -c "env ROWSAFE_TEST_CLICKHOUSE_PORT=8123 ROWSAFE_TEST_CLICKHOUSE_REPLICATED=1 ROWSAFE_TEST_CLICKHOUSE_DOWNLOAD_DIR=/var/lib/rowsafe-dl/dl $extra \
			/usr/local/bin/clickhouse.test -test.v -test.count=1 -test.run TestClickHouse -test.timeout 25m" 2>&1 | tail -n 150
		exit ${PIPESTATUS[0]}
	'; then
		rc=1
		echo "FAIL: ClickHouse $v"
	fi
	mode=sql
done

# A Docker sidecar: ClickHouse (stock entrypoint, a password) and the agent
# in separate containers on one network.
if [ "${DOCKER_MODE:-yes}" = yes ]; then
	v=${VERSIONS%% *}
	img=rowsafe-test/clickhouse:$v
	image "$v"
	net=rowsafe-test-clickhouse-$$
	server=$net-server
	agent=$net-agent
	containers="$containers $server $agent"
	docker network create "$net" >/dev/null
	echo "==> ClickHouse $v in Docker, the agent in a sidecar"
	to 120 docker run -d --rm --name "$server" --network "$net" --network-alias clickhouse \
		-e CLICKHOUSE_PASSWORD=adminpw -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 "$img" >/dev/null
	if ! to "$LIMIT" docker run --rm --name "$agent" --network "$net" --network-alias agent --entrypoint bash "$img" -euc '
		for _ in $(seq 1 120); do wget -qO- http://clickhouse:8123/ping >/dev/null 2>&1 && break; sleep 1; done
		export ROWSAFE_CLICKHOUSE_URL=http://clickhouse:8123 ROWSAFE_CLICKHOUSE_GATEWAY_LISTEN=0.0.0.0:9010 ROWSAFE_CLICKHOUSE_GATEWAY_URL=http://agent:9010
		pass="ROWSAFE_CLICKHOUSE_URL=$ROWSAFE_CLICKHOUSE_URL ROWSAFE_CLICKHOUSE_GATEWAY_LISTEN=$ROWSAFE_CLICKHOUSE_GATEWAY_LISTEN ROWSAFE_CLICKHOUSE_GATEWAY_URL=$ROWSAFE_CLICKHOUSE_GATEWAY_URL"
		agent() { su rowsafe -c "env ROWSAFE_STATE_DIR=/tmp/agent-state $pass rowsafe-agent clickhouse $*"; }
		agent status --port 8123 | grep -qx docker=yes
		rc=0; agent login --port 8123 </dev/null || rc=$?
		[ "$rc" = 11 ] || { echo "login without an admin: exit $rc, want 11"; exit 1; }
		rc=0; echo wrong | agent login --port 8123 --admin-user default || rc=$?
		[ "$rc" = 12 ] || { echo "login with a wrong password: exit $rc, want 12"; exit 1; }
		echo adminpw | agent login --port 8123 --admin-user default
		agent status --port 8123
		agent status --port 8123 | grep -qx login=ok
		cd /tmp
		su rowsafe -c "env $pass ROWSAFE_TEST_CLICKHOUSE_PORT=8123 ROWSAFE_TEST_CLICKHOUSE_REPLICATED=0 \
			ROWSAFE_TEST_CLICKHOUSE_ADMIN=default ROWSAFE_TEST_CLICKHOUSE_ADMIN_PASSWORD=adminpw \
			/usr/local/bin/clickhouse.test -test.v -test.count=1 -test.run TestClickHouse -test.timeout 25m" 2>&1 | tail -n 150
		exit ${PIPESTATUS[0]}
	'; then
		rc=1
		echo "FAIL: ClickHouse $v in Docker"
	fi
	docker rm -f "$server" >/dev/null 2>&1 || true
	docker network rm "$net" >/dev/null 2>&1 || true
fi
exit $rc
