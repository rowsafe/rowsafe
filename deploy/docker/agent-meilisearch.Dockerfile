# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Rowsafe agent as a Docker sidecar for the official getmeili/meilisearch
# image (Community Edition), which stays unmodified. Built on the same
# image, so the meilisearch program that Proof and Rewind copies run (a
# temporary Meilisearch on 127.0.0.1 inside this container only, with a
# master key only the agent knows) is Meilisearch's own: the newest release
# Rowsafe pins, which opens snapshots of Meilisearch 1.12 and newer (older
# ones through its dumpless upgrade, on the copy only). It runs as its own
# user (rowsafe, uid 10001). Published as ghcr.io/rowsafe/agent:meilisearch1
# (floating: the newest release) and ...:<version>-meilisearch1 (exact).
#
#   docker build -f deploy/docker/agent-meilisearch.Dockerfile -t rowsafe-agent:meilisearch1 .
#
# The agent reaches Meilisearch over the compose network
# (ROWSAFE_MEILISEARCH_URL=http://meilisearch:7700) with Rowsafe's own API
# key (made once with the master key, which it never keeps) and reads the
# snapshots Meilisearch writes from the volume both containers mount. See
# deploy/docker/compose.meilisearch.example.yml.

# The exact Meilisearch release (protocol.MeilisearchVersion, its image tag
# without the "v"), and that tag's image by digest (the multi-platform
# index). A test checks it goes with the release Rowsafe pins.
ARG DB_VERSION=1.54.3
ARG DB_IMAGE_DIGEST=sha256:e68913ab7d6f5b159529e472cfd362ce3c741fafd3c127961b2142abbe41b3c9

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
COPY pulse ./pulse
COPY pgprobe ./pgprobe
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/rowsafe/rowsafe/internal/agent.Version=${VERSION}" \
      -o /out/rowsafe-agent ./cmd/rowsafe-agent

FROM getmeili/meilisearch:v${DB_VERSION}@${DB_IMAGE_DIGEST}
ARG DB_VERSION
# The image's variant, its floating tag (set by the release workflow).
ARG IMAGE_VARIANT=meilisearch1
ARG VERSION=dev
# /var/lib/rowsafe: identity, Rowsafe's key, Proofs and Rewind copies (a
# volume), owned by the agent's own user. The program stays root's (the
# agent runs only a program root owns).
RUN addgroup -S -g 10001 rowsafe \
 && adduser -S -D -H -u 10001 -G rowsafe -h /var/lib/rowsafe -s /sbin/nologin rowsafe \
 && install -d -o rowsafe -g rowsafe -m 0700 /var/lib/rowsafe /var/log/rowsafe /rowsafe-spool \
 && /bin/meilisearch --version | grep -q "^meilisearch ${DB_VERSION}$"
COPY --from=build /out/rowsafe-agent /usr/local/bin/rowsafe-agent

LABEL org.opencontainers.image.title="Rowsafe agent (Meilisearch ${DB_VERSION} sidecar)" \
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
    ROWSAFE_MEILISEARCH_BIN=/bin/meilisearch \
    ROWSAFE_MEILISEARCH_SNAPSHOT_DIR=/meili_snapshots \
    ROWSAFE_IMAGE_VARIANT=${IMAGE_VARIANT}

USER 10001:10001
WORKDIR /var/lib/rowsafe
VOLUME ["/var/lib/rowsafe"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD ["/usr/local/bin/rowsafe-agent", "health"]
# The image's own entrypoint is tini, which runs Meilisearch: the agent
# replaces it (it starts and stops its temporary instances itself).
ENTRYPOINT ["/usr/local/bin/rowsafe-agent"]
CMD ["run"]
