# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Rowsafe agent as a Docker sidecar for the official mariadb images
# (10.6, 10.11, 11.4), which stay unmodified. The image is built FROM the
# same mariadb image, which already carries mariadb-backup, mbstream and
# mariadb-binlog of the server's exact version, so restore tests and Rewind
# copies run the very same server. It runs as the image's mysql user
# (999:999). Published as ghcr.io/rowsafe/agent:<version>-mariadb<version>.
#
#   docker build -f deploy/docker/agent-mariadb.Dockerfile --build-arg MARIADB_VERSION=11.4 -t rowsafe-agent:mariadb11.4 .
#
# See deploy/docker/compose.mariadb.yml.

ARG MARIADB_VERSION=11.4

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
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/rowsafe/rowsafe/internal/agent.Version=${VERSION}" \
      -o /out/rowsafe-agent ./cmd/rowsafe-agent

FROM mariadb:${MARIADB_VERSION}
ARG MARIADB_VERSION
RUN set -eux; \
    command -v mariadb-backup || command -v mariabackup; command -v mbstream; \
    install -d -o mysql -g mysql -m 0700 /var/lib/rowsafe /var/log/rowsafe /rowsafe-spool

COPY --from=build /out/rowsafe-agent /usr/local/bin/rowsafe-agent

LABEL org.opencontainers.image.title="Rowsafe agent (MariaDB ${MARIADB_VERSION} sidecar)" \
      org.opencontainers.image.source="https://github.com/rowsafe/rowsafe" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV ROWSAFE_MODE=docker-sidecar \
    ROWSAFE_STATE_DIR=/var/lib/rowsafe \
    ROWSAFE_CONFIG_DIR=/var/lib/rowsafe/pgbackrest \
    ROWSAFE_DRILL_DIR=/var/lib/rowsafe/drills \
    ROWSAFE_LOG_DIR=/var/log/rowsafe \
    ROWSAFE_SPOOL_DIR=/rowsafe-spool \
    ROWSAFE_AUTO_UPDATE=false

USER mysql
WORKDIR /var/lib/rowsafe
VOLUME ["/var/lib/rowsafe"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD ["/usr/local/bin/rowsafe-agent", "health"]
ENTRYPOINT ["/usr/local/bin/rowsafe-agent"]
CMD ["run"]
