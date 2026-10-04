# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Rowsafe agent for SQLite databases in Docker: a small image with the agent
# (pure Go, SQLite included) and restic (backups of the app's folders). It
# shares the app's volume and runs as the app's user (compose `user:`), so
# SQLite's locks and its -wal and -shm files work for both. Published as
# ghcr.io/rowsafe/agent:sqlite (floating: the newest release) and
# ...:<version>-sqlite (exact: pins a release).
#
#   docker build -f deploy/docker/agent-sqlite.Dockerfile -t rowsafe-agent:sqlite .
#
# See deploy/docker/compose.sqlite.example.yml.
ARG DEBIAN_SUITE=trixie
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

FROM debian:${DEBIAN_SUITE}-slim
ARG VERSION=dev
# rowsafe-docker-control picks the same variant of a new release.
ARG IMAGE_VARIANT=sqlite
ARG RESTIC_VERSION=0.19.1
ARG RESTIC_SHA256_AMD64=f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c
ARG RESTIC_SHA256_ARM64=a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl bzip2; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) restic_sum="${RESTIC_SHA256_AMD64}"; restic_arch=amd64 ;; \
      arm64) restic_sum="${RESTIC_SHA256_ARM64}"; restic_arch=arm64 ;; \
      *) echo "no pinned restic for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/restic.bz2 "https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_linux_${restic_arch}.bz2"; \
    echo "${restic_sum}  /tmp/restic.bz2" | sha256sum -c -; \
    bunzip2 -c /tmp/restic.bz2 >/usr/local/bin/restic; rm -f /tmp/restic.bz2; chmod 0755 /usr/local/bin/restic; \
    apt-get purge -y --auto-remove curl bzip2; \
    rm -rf /var/lib/apt/lists/*; \
    # The agent runs as the app's user, whatever its uid: its state folder
    # (a volume) is writable by any user; the agent's own files in it are 0600.
    install -d -m 1777 /var/lib/rowsafe /var/log/rowsafe
COPY --from=build /out/rowsafe-agent /usr/local/bin/rowsafe-agent

LABEL org.opencontainers.image.title="Rowsafe agent (SQLite)" \
      org.opencontainers.image.source="https://github.com/rowsafe/rowsafe" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      sh.rowsafe.agent.variant="${IMAGE_VARIANT}"

# Native mode: SQLite needs no spool outside the agent (it copies the WAL
# itself). Set ROWSAFE_SQLITE_PATHS to the database files, as the agent sees
# them in the app's volume.
ENV ROWSAFE_MODE=native \
    ROWSAFE_STATE_DIR=/var/lib/rowsafe \
    ROWSAFE_CONFIG_DIR=/var/lib/rowsafe/config \
    ROWSAFE_DRILL_DIR=/var/lib/rowsafe/drills \
    ROWSAFE_REWIND_DIR=/var/lib/rowsafe/rewind \
    ROWSAFE_LOG_DIR=/var/log/rowsafe \
    ROWSAFE_AUTO_UPDATE=false \
    ROWSAFE_RESTIC_BIN=/usr/local/bin/restic \
    ROWSAFE_IMAGE_VARIANT=${IMAGE_VARIANT}

WORKDIR /var/lib/rowsafe
VOLUME ["/var/lib/rowsafe"]
ENTRYPOINT ["/usr/local/bin/rowsafe-agent"]
CMD ["run"]
