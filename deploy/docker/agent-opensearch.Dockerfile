# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Rowsafe agent as a Docker sidecar for the official
# opensearchproject/opensearch image, which stays unmodified. Built on the
# same image as the database, so the OpenSearch program that Proof and
# Rewind copies run (a temporary OpenSearch on 127.0.0.1 inside this
# container only, with a small heap and a login only the agent knows) is
# OpenSearch's own, of the newest release of the major version. It runs as
# its own user (rowsafe, uid 10001), in OpenSearch's group (gid 1000) to
# read the snapshots OpenSearch writes into the shared snapshot volume.
# Published as ghcr.io/rowsafe/agent:opensearch<major> (floating: the
# newest release) and ...:<version>-opensearch<major> (exact: pins a release).
#
#   docker build -f deploy/docker/agent-opensearch.Dockerfile -t rowsafe-agent:opensearch3 .
#
# The agent reaches OpenSearch over the compose network
# (ROWSAFE_OPENSEARCH_URL=http://opensearch:9200 with the security plugin
# off, or https:// with ROWSAFE_OPENSEARCH_CA_FILE) and reads the snapshot
# repository from the volume both containers mount at
# /var/lib/rowsafe-opensearch/snapshots. See
# deploy/docker/compose.opensearch.example.yml.

# The exact OpenSearch release (its image tag), and that tag's image by
# digest (the multi-platform index): a tag moved upstream can't change what
# the agent image is built on. The release workflow sets both per major
# version (opensearch2, opensearch3).
ARG DB_VERSION=3.9.0
ARG DB_IMAGE_DIGEST=sha256:adfa61f85025d06b4aeb562e7e74fde7e31c437039c93c3862c17e9acebd6c7c

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

FROM opensearchproject/opensearch:${DB_VERSION}@${DB_IMAGE_DIGEST}
ARG DB_VERSION
# The image's variant, its floating tag: opensearch3 (set by the release
# workflow). rowsafe-docker-control picks the same variant of a new release
# when it updates the agent's container.
ARG IMAGE_VARIANT=opensearch3
ARG VERSION=dev
USER root
# /var/lib/rowsafe: identity, logins, Proofs and Rewind copies (a volume),
# owned by the agent's own user. OpenSearch's folder opens to everyone for
# reading (the image keeps it to its own user): the agent runs its program
# for temporary servers, never as OpenSearch's user. The demo
# configuration's tools aren't run here: temporary servers get their own
# certificates and login.
RUN groupadd --system --gid 10001 rowsafe \
 && useradd --system --uid 10001 --gid rowsafe --groups opensearch --home-dir /var/lib/rowsafe --shell /sbin/nologin rowsafe \
 && install -d -o rowsafe -g rowsafe -m 0700 /var/lib/rowsafe /var/log/rowsafe /rowsafe-spool \
 && chmod 0755 /usr/share/opensearch \
 && test -x /usr/share/opensearch/bin/opensearch \
 && ls /usr/share/opensearch/lib/opensearch-${DB_VERSION}.jar >/dev/null
COPY --from=build /out/rowsafe-agent /usr/local/bin/rowsafe-agent

LABEL org.opencontainers.image.title="Rowsafe agent (OpenSearch ${DB_VERSION} sidecar)" \
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
    ROWSAFE_OPENSEARCH_HOME=/usr/share/opensearch \
    ROWSAFE_IMAGE_VARIANT=${IMAGE_VARIANT}

# The uid alone, so the user's groups apply too (opensearch: the snapshots).
USER 10001
WORKDIR /var/lib/rowsafe
VOLUME ["/var/lib/rowsafe"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD ["/usr/local/bin/rowsafe-agent", "health"]
ENTRYPOINT ["/usr/local/bin/rowsafe-agent"]
CMD ["run"]
