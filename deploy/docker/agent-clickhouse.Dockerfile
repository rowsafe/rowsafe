# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Rowsafe agent as a Docker sidecar for the official clickhouse/clickhouse-server
# images, which stay unmodified. Built on the same image as the database, so
# the clickhouse program that Proof and Rewind copies run (a temporary
# server, 127.0.0.1 only) is ClickHouse's own, of the same version. It runs
# as the image's clickhouse user. Published as
# ghcr.io/rowsafe/agent:<version>-clickhouse<CH_VERSION>.
#
#   docker build -f deploy/docker/agent-clickhouse.Dockerfile --build-arg CH_VERSION=26.8 -t rowsafe-agent:clickhouse26.8 .
#
# The agent reaches ClickHouse's HTTP interface over the compose network
# (ROWSAFE_CLICKHOUSE_URL=http://clickhouse:8123), and ClickHouse writes its
# backups to the agent's gateway (ROWSAFE_CLICKHOUSE_GATEWAY_URL), which
# encrypts every object before it goes to your bucket. See
# deploy/docker/compose.clickhouse.example.yml.

# The newest LTS release (ClickHouse's LTS releases are YY.3 and YY.8).
ARG CH_VERSION=26.8

FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY protocol ./protocol
COPY release ./release
COPY collect ./collect
COPY client ./client
COPY mcp ./mcp
COPY masking ./masking
COPY pglog ./pglog
COPY preview ./preview
COPY tune ./tune
COPY pgprobe ./pgprobe
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/rowsafe/rowsafe/internal/agent.Version=${VERSION}" \
      -o /out/rowsafe-agent ./cmd/rowsafe-agent

FROM clickhouse/clickhouse-server:${CH_VERSION}
ARG CH_VERSION
# /var/lib/rowsafe: identity, ClickHouse login, Proofs and Rewind copies
# (a volume). The image's clickhouse user runs the agent.
RUN install -d -o clickhouse -g clickhouse -m 0700 /var/lib/rowsafe /var/log/rowsafe \
 && clickhouse server --version >/dev/null
COPY --from=build /out/rowsafe-agent /usr/local/bin/rowsafe-agent

LABEL org.opencontainers.image.title="Rowsafe agent (ClickHouse ${CH_VERSION} sidecar)" \
      org.opencontainers.image.source="https://github.com/rowsafe/rowsafe" \
      org.opencontainers.image.licenses="Apache-2.0"

# Native mode: ClickHouse needs no spool (it has no change log to copy).
# The gateway listens on the compose network so the ClickHouse container can
# send its BACKUP to it; set ROWSAFE_CLICKHOUSE_URL and
# ROWSAFE_CLICKHOUSE_GATEWAY_URL in the compose file.
ENV ROWSAFE_MODE=native \
    ROWSAFE_STATE_DIR=/var/lib/rowsafe \
    ROWSAFE_CONFIG_DIR=/var/lib/rowsafe/config \
    ROWSAFE_DRILL_DIR=/var/lib/rowsafe/drills \
    ROWSAFE_REWIND_DIR=/var/lib/rowsafe/rewind \
    ROWSAFE_LOG_DIR=/var/log/rowsafe \
    ROWSAFE_AUTO_UPDATE=false \
    ROWSAFE_CLICKHOUSE_GATEWAY_LISTEN=0.0.0.0:9010

USER clickhouse
WORKDIR /var/lib/rowsafe
VOLUME ["/var/lib/rowsafe"]
ENTRYPOINT ["/usr/local/bin/rowsafe-agent"]
CMD ["run"]
