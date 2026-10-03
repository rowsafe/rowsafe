# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Rowsafe agent as a Docker sidecar for the official redis and valkey/valkey
# images, which stay unmodified. Built on the same image as the database, so
# the server program that Proof and Rewind copies run (a temporary server,
# on a private Unix socket only) is the database's own, of the same version.
# It runs as the image's own user (redis or valkey). Published as
# ghcr.io/rowsafe/agent:redis<VERSION> and :valkey<VERSION> (floating: the
# newest release) and ...:<version>-redis<VERSION> (exact: pins a release).
#
#   docker build -f deploy/docker/agent-redis.Dockerfile --build-arg ENGINE=redis --build-arg DB_VERSION=8.2 -t rowsafe-agent:redis8.2 .
#   docker build -f deploy/docker/agent-redis.Dockerfile --build-arg ENGINE=valkey --build-arg DB_VERSION=8.1 -t rowsafe-agent:valkey8.1 .
#
# The agent reaches the server over the compose network
# (ROWSAFE_REDIS_HOST=redis) as Rowsafe's own ACL user, follows its changes
# as a hidden replica and takes snapshots over the replication handshake:
# it needs no access to the server's files. See
# deploy/docker/compose.redis.example.yml.

# redis or valkey; the base image is redis:<DB_VERSION> or valkey/valkey:<DB_VERSION>.
ARG ENGINE=redis
ARG DB_VERSION=8.2

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

FROM redis:${DB_VERSION} AS base-redis
FROM valkey/valkey:${DB_VERSION} AS base-valkey

FROM base-${ENGINE}
ARG ENGINE
ARG DB_VERSION
# The image's variant, its floating tag: redis8.2, valkey8.1 (set by the
# release workflow). rowsafe-docker-control picks the same variant of a new
# release when it updates the agent's container.
ARG IMAGE_VARIANT=${ENGINE}${DB_VERSION}
ARG VERSION=dev
# /var/lib/rowsafe: identity, Rowsafe's login, Proofs and Rewind copies (a
# volume), owned by the image's own user (redis or valkey, uid 999).
RUN install -d -o "$ENGINE" -g "$ENGINE" -m 0700 /var/lib/rowsafe /var/log/rowsafe /rowsafe-spool \
 && "$ENGINE-server" --version >/dev/null
COPY --from=build /out/rowsafe-agent /usr/local/bin/rowsafe-agent

LABEL org.opencontainers.image.title="Rowsafe agent (${ENGINE} ${DB_VERSION} sidecar)" \
      org.opencontainers.image.source="https://github.com/rowsafe/rowsafe" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      sh.rowsafe.agent.variant="${IMAGE_VARIANT}"

# docker-sidecar mode: Restart in the dashboard goes through the optional
# container control service (rowsafe-docker-control), like MySQL's.
ENV ROWSAFE_MODE=docker-sidecar \
    ROWSAFE_SPOOL_DIR=/rowsafe-spool \
    ROWSAFE_STATE_DIR=/var/lib/rowsafe \
    ROWSAFE_CONFIG_DIR=/var/lib/rowsafe/config \
    ROWSAFE_DRILL_DIR=/var/lib/rowsafe/drills \
    ROWSAFE_REWIND_DIR=/var/lib/rowsafe/rewind \
    ROWSAFE_LOG_DIR=/var/log/rowsafe \
    ROWSAFE_AUTO_UPDATE=false \
    ROWSAFE_IMAGE_VARIANT=${IMAGE_VARIANT}

USER 999:999
WORKDIR /var/lib/rowsafe
VOLUME ["/var/lib/rowsafe"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD ["/usr/local/bin/rowsafe-agent", "health"]
ENTRYPOINT ["/usr/local/bin/rowsafe-agent"]
CMD ["run"]
