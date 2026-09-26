#!/usr/bin/env bash
# MongoDB engine integration test: runs the engine's Go integration test
# inside the official mongo images (mongod and the Database Tools as
# shipped), on a replica set of one, with and without access control.
#
#   scripts/test-mongodb.sh            # MongoDB 7.0 and 8.0
#   MONGO_VERSIONS="6.0 7.0 8.0" scripts/test-mongodb.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
VERSIONS=${MONGO_VERSIONS:-7.0 8.0}
GO_IMAGE=${GO_IMAGE:-golang:1.26}
MODCACHE=$(go env GOMODCACHE)
rc=0
for v in $VERSIONS; do
	img=rowsafe-test/mongodb-go:$v
	docker build -q -t "$img" - >/dev/null <<DOCKERFILE
FROM $GO_IMAGE AS go
FROM mongo:$v
COPY --from=go /usr/local/go /usr/local/go
ENV PATH=/usr/local/go/bin:\$PATH GOFLAGS=-mod=mod GOTOOLCHAIN=local
DOCKERFILE
	for auth in off on; do
		echo "==> MongoDB $v, access control $auth"
		if ! docker run --rm -v "$HERE":/src:ro -v "$MODCACHE":/go/pkg/mod -v rowsafe-test-gocache:/root/.cache/go-build \
			-e GOMODCACHE=/go/pkg/mod -e AUTH=$auth -w /src "$img" bash -euc '
			mkdir -p /data/rs /tmp/work
			args="--dbpath /data/rs --replSet rs0 --port 27017 --bind_ip 127.0.0.1 --fork --logpath /tmp/mongod.log"
			if [ "$AUTH" = on ]; then
				openssl rand -base64 48 > /tmp/keyfile; chmod 400 /tmp/keyfile
				mongod $args --keyFile /tmp/keyfile >/dev/null
				mongosh --quiet --eval "rs.initiate()" >/dev/null
				until mongosh --quiet --eval "db.hello().isWritablePrimary" | grep -q true; do sleep 1; done
				mongosh --quiet admin --eval "db.createUser({user: \"admin\", pwd: \"adminpw\", roles: [\"root\"]})" >/dev/null
				export ROWSAFE_TEST_MONGODB_ADMIN=admin ROWSAFE_TEST_MONGODB_ADMIN_PASSWORD=adminpw
			else
				mongod $args >/dev/null
				mongosh --quiet --eval "rs.initiate()" >/dev/null
				until mongosh --quiet --eval "db.hello().isWritablePrimary" | grep -q true; do sleep 1; done
			fi
			cp -r /src /tmp/work/src && cd /tmp/work/src
			ROWSAFE_TEST_MONGODB_PORT=27017 go test -count=1 -tags mongodb_integration -run TestMongoDB -v ./internal/engine/mongodb/ 2>&1 | tail -n 80
			exit ${PIPESTATUS[0]}
		'; then
			rc=1
			echo "FAIL: MongoDB $v, access control $auth"
		fi
	done
done
exit $rc
