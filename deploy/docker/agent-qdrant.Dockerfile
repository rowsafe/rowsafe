# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Rowsafe agent as a Docker sidecar for the official qdrant/qdrant image,
# which stays unmodified. Built on the same image as the database, so the
# qdrant program that Proof and Rewind copies run (a temporary Qdrant, on
# 127.0.0.1 inside this container only, behind a key only the agent knows)
# is the database's own, of the same version. It runs as its own user
# (rowsafe, uid 10001). Published as ghcr.io/rowsafe/agent:qdrant<X.Y>
# (floating: the newest release) and ...:<version>-qdrant<X.Y> (exact: pins
# a release).
#
#   docker build -f deploy/docker/agent-qdrant.Dockerfile -t rowsafe-agent:qdrant1.19 .
#
# The agent reaches Qdrant over the compose network
# (ROWSAFE_QDRANT_URL=http://qdrant:6333, or https:// with TLS on) with
# Rowsafe's own key (Qdrant's alt_api_key) and takes Qdrant's own snapshots
# through its API: it needs no access to Qdrant's files. See
# deploy/docker/compose.qdrant.example.yml.

# The exact Qdrant release (its image tag without the "v"), and that tag's
# image by digest (the multi-platform index): a tag moved upstream can't
# change what the agent image is built on. scripts/check-qdrant-pins.sh
# checks it against the registry; a test checks it goes with DB_VERSION.
ARG DB_VERSION=1.19.2
ARG DB_IMAGE_DIGEST=sha256:b7b0444c4c351c970b98e90a6f89c2ee4287c65b44e52b4cb503fa5b2aa927ad

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

FROM qdrant/qdrant:v${DB_VERSION}@${DB_IMAGE_DIGEST}
ARG DB_VERSION
# The image's variant, its floating tag: qdrant1.19 (set by the release
# workflow). rowsafe-docker-control picks the same variant of a new release
# when it updates the agent's container.
ARG IMAGE_VARIANT=qdrant
ARG VERSION=dev
# /var/lib/rowsafe: identity, Rowsafe's key, Proofs and Rewind copies (a
# volume), owned by the agent's own user.
RUN groupadd --system --gid 10001 rowsafe \
 && useradd --system --uid 10001 --gid rowsafe --home-dir /var/lib/rowsafe --shell /usr/sbin/nologin rowsafe \
 && install -d -o rowsafe -g rowsafe -m 0700 /var/lib/rowsafe /var/log/rowsafe /rowsafe-spool \
 && /qdrant/qdrant --version >/dev/null
COPY --from=build /out/rowsafe-agent /usr/local/bin/rowsafe-agent

LABEL org.opencontainers.image.title="Rowsafe agent (Qdrant ${DB_VERSION} sidecar)" \
      org.opencontainers.image.source="https://github.com/rowsafe/rowsafe" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      sh.rowsafe.agent.variant="${IMAGE_VARIANT}"

# docker-sidecar mode: Restart in the dashboard goes through the optional
# container control service (rowsafe-docker-control).
ENV ROWSAFE_MODE=docker-sidecar \
    ROWSAFE_SPOOL_DIR=/rowsafe-spool \
    ROWSAFE_STATE_DIR=/var/lib/rowsafe \
    ROWSAFE_CONFIG_DIR=/var/lib/rowsafe/config \
    ROWSAFE_DRILL_DIR=/var/lib/rowsafe/drills \
    ROWSAFE_REWIND_DIR=/var/lib/rowsafe/rewind \
    ROWSAFE_LOG_DIR=/var/log/rowsafe \
    ROWSAFE_AUTO_UPDATE=false \
    ROWSAFE_QDRANT_BIN=/qdrant/qdrant \
    ROWSAFE_IMAGE_VARIANT=${IMAGE_VARIANT}

USER 10001:10001
WORKDIR /var/lib/rowsafe
VOLUME ["/var/lib/rowsafe"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD ["/usr/local/bin/rowsafe-agent", "health"]
ENTRYPOINT ["/usr/local/bin/rowsafe-agent"]
CMD ["run"]
