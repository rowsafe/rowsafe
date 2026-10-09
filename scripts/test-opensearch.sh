#!/usr/bin/env bash
# OpenSearch engine integration test: runs the engine's Go integration test
# (compiled here, copied in) inside the official opensearchproject/opensearch
# image, set up like the installer's --install-opensearch: the security
# plugin on with an administrator only (no demo users), TLS on the REST
# port with certificates made here, the node-to-node port on loopback,
# Rowsafe's snapshot folder in path.repo, certificates reloaded by
# themselves. The test runs as OpenSearch's own user (the agent reads the
# snapshot folder through OpenSearch's group on a real server) and keeps
# the bucket inside its process.
#
#   scripts/test-opensearch.sh
#   OPENSEARCH_IMAGES="opensearchproject/opensearch:2.19.4" scripts/test-opensearch.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
IMAGES=${OPENSEARCH_IMAGES:-opensearchproject/opensearch:3.9.0}
LIMIT=${TEST_TIMEOUT:-1800}
TEST_RUN=${TEST_RUN:-TestOpenSearch}
PASS=Rowsafe-Test-Admin-Password-42

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
# shellcheck disable=SC2329 # the EXIT trap runs it
cleanup() {
	for c in $containers; do docker rm -f "$c" >/dev/null 2>&1 || true; done
	rm -rf "$work"
}
trap cleanup EXIT

(cd "$HERE" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOWORK=off go test -c -tags opensearch_integration -o "$work/opensearch.test" ./internal/engine/opensearch/)

# Certificates: a CA and the node's certificate (node to node), and the
# REST port's own self-signed one (the agent replaces it).
mkdir -p "$work/tls"
(
	cd "$work/tls"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 -subj "/CN=rowsafe-opensearch-ca" \
		-keyout ca.key -out transport-ca.crt 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=rowsafe-opensearch-node" -keyout transport.key -out node.csr 2>/dev/null
	printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' >ext.cnf
	openssl x509 -req -in node.csr -CA transport-ca.crt -CAkey ca.key -CAcreateserial -days 3650 -extfile ext.cnf -out transport.crt 2>/dev/null
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 -subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout rowsafe-server.key -out rowsafe-server.crt 2>/dev/null
	rm -f ca.key node.csr ext.cnf transport-ca.srl
)

cat >"$work/opensearch.yml" <<'YML'
cluster.name: rowsafe
node.name: rowsafe-1
discovery.type: single-node
path.repo: ["/var/lib/rowsafe-opensearch/snapshots"]
network.host: 127.0.0.1
http.host: 0.0.0.0
transport.host: 127.0.0.1
cluster.default_number_of_replicas: 0
plugins.security.ssl.transport.pemcert_filepath: /etc/ssl/rowsafe-opensearch/transport.crt
plugins.security.ssl.transport.pemkey_filepath: /etc/ssl/rowsafe-opensearch/transport.key
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/ssl/rowsafe-opensearch/transport-ca.crt
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /etc/ssl/rowsafe-opensearch/rowsafe-server.crt
plugins.security.ssl.http.pemkey_filepath: /etc/ssl/rowsafe-opensearch/rowsafe-server.key
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/ssl/rowsafe-opensearch/transport-ca.crt
plugins.security.ssl.http.clientauth_mode: NONE
plugins.security.ssl.http.enabled_protocols: ["TLSv1.3", "TLSv1.2"]
plugins.security.ssl.certificates_hot_reload.enabled: true
plugins.security.ssl.http.enforce_cert_reload_dn_verification: false
plugins.security.allow_default_init_securityindex: true
plugins.security.nodes_dn: ["CN=rowsafe-opensearch-node"]
plugins.security.restapi.roles_enabled: ["all_access", "rowsafe_agent"]
plugins.security.restapi.endpoints_disabled.rowsafe_agent.ACTIONGROUPS: ["GET", "PUT", "POST", "DELETE", "PATCH"]
plugins.security.restapi.endpoints_disabled.rowsafe_agent.TENANTS: ["GET", "PUT", "POST", "DELETE", "PATCH"]
plugins.security.restapi.endpoints_disabled.rowsafe_agent.AUDIT: ["GET", "PUT", "POST", "DELETE", "PATCH"]
plugins.security.restapi.endpoints_disabled.rowsafe_agent.ALLOWLIST: ["GET", "PUT", "POST", "DELETE", "PATCH"]
plugins.security.restapi.endpoints_disabled.rowsafe_agent.NODESDN: ["GET", "PUT", "POST", "DELETE", "PATCH"]
plugins.security.restapi.endpoints_disabled.rowsafe_agent.SSL: ["GET", "PUT", "POST", "DELETE", "PATCH"]
plugins.security.restapi.endpoints_disabled.rowsafe_agent.CACHE: ["GET", "PUT", "POST", "DELETE", "PATCH"]
plugins.security.system_indices.enabled: true
YML

rc=0
for src in $IMAGES; do
	cat >"$work/Dockerfile" <<DOCKERFILE
FROM $src
USER root
COPY opensearch.yml /usr/share/opensearch/config/opensearch.yml
COPY tls/ /etc/ssl/rowsafe-opensearch/
RUN mkdir -p /var/lib/rowsafe-opensearch/snapshots && chown -R 1000:1000 /var/lib/rowsafe-opensearch /etc/ssl/rowsafe-opensearch && \
    chmod 2750 /var/lib/rowsafe-opensearch/snapshots && \
    H=\$(PW='$PASS' OPENSEARCH_JAVA_HOME=/usr/share/opensearch/jdk /usr/share/opensearch/plugins/opensearch-security/tools/hash.sh -env PW 2>/dev/null | tail -n 1) && \
    printf '_meta:\n  type: "internalusers"\n  config_version: 2\nadmin:\n  hash: "%s"\n  reserved: true\n' "\$H" >/usr/share/opensearch/config/opensearch-security/internal_users.yml && \
    printf '_meta:\n  type: "rolesmapping"\n  config_version: 2\nall_access:\n  reserved: true\n  users: ["admin"]\n' >/usr/share/opensearch/config/opensearch-security/roles_mapping.yml && \
    chown -R 1000:1000 /usr/share/opensearch/config
COPY opensearch.test /usr/local/bin/
USER 1000
ENV DISABLE_INSTALL_DEMO_CONFIG=true OPENSEARCH_JAVA_OPTS="-Xms1g -Xmx1g"
DOCKERFILE
	tag="rowsafe-test/opensearch:$(echo "$src" | tr '/:' '--')"
	to 900 docker build -q -t "$tag" "$work" >/dev/null
	c="rowsafe-test-opensearch-$$-$(echo "$src" | tr '/:.' '---')"
	containers="$containers $c"
	docker run -d --name "$c" -m 4g "$tag" >/dev/null
	echo "== $src: waiting for OpenSearch"
	for _ in $(seq 1 90); do
		code=$(docker exec "$c" curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:9200/ 2>/dev/null || true)
		[ "$code" = 401 ] && break
		sleep 2
	done
	[ "$code" = 401 ] || { docker logs --tail 40 "$c"; echo "OpenSearch didn't start"; rc=1; continue; }
	if ! to "$LIMIT" docker exec -e ROWSAFE_TEST_OPENSEARCH_ADMIN_PASSWORD=$PASS -e ROWSAFE_OPENSEARCH_CONF=/usr/share/opensearch/config \
		-e ROWSAFE_TEST_TLS_DIR=/etc/ssl/rowsafe-opensearch -w /tmp "$c" \
		/usr/local/bin/opensearch.test -test.v -test.count=1 -test.timeout=$((LIMIT - 60))s -test.run "$TEST_RUN"; then
		echo "== $src: FAILED"
		docker logs --tail 30 "$c" 2>&1 | grep -v '^WARNING' || true
		rc=1
	else
		echo "== $src: passed"
	fi
	docker rm -f "$c" >/dev/null
done
exit $rc
