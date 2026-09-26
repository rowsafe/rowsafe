# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Rowsafe agent as a Docker sidecar for the official mongo:N images, which
# stay unmodified. Built on the same official mongo image as the database,
# so mongodump, mongorestore and mongod (for Proof and Rewind copies) are
# exactly MongoDB's own, of the same version. Published as
# ghcr.io/rowsafe/agent:<version>-mongo<major>.
#
#   docker build -f deploy/docker/agent-mongodb.Dockerfile --build-arg MONGO_VERSION=8.0 -t rowsafe-agent:mongo8 .
#
# The agent reaches MongoDB over the compose network
# (ROWSAFE_MONGODB_HOST=mongo). See
# deploy/docker/compose.mongodb.example.yml and docs/docker.md.

ARG MONGO_VERSION=8.0

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

FROM mongo:${MONGO_VERSION}
ARG MONGO_VERSION
# /var/lib/rowsafe: identity, MongoDB login, oplog position, Proofs and
# Rewind copies (a volume). The image's mongodb user (999) runs the agent.
RUN install -d -o mongodb -g mongodb -m 0700 /var/lib/rowsafe /var/log/rowsafe \
 && mongodump --version >/dev/null && mongorestore --version >/dev/null && mongod --version >/dev/null
COPY --from=build /out/rowsafe-agent /usr/local/bin/rowsafe-agent

LABEL org.opencontainers.image.title="Rowsafe agent (MongoDB ${MONGO_VERSION} sidecar)" \
      org.opencontainers.image.source="https://github.com/rowsafe/rowsafe" \
      org.opencontainers.image.licenses="Apache-2.0"

# Native mode: MongoDB needs no spool (the agent reads the oplog itself).
ENV ROWSAFE_MODE=native \
    ROWSAFE_STATE_DIR=/var/lib/rowsafe \
    ROWSAFE_CONFIG_DIR=/var/lib/rowsafe/config \
    ROWSAFE_DRILL_DIR=/var/lib/rowsafe/drills \
    ROWSAFE_REWIND_DIR=/var/lib/rowsafe/rewind \
    ROWSAFE_LOG_DIR=/var/log/rowsafe \
    ROWSAFE_AUTO_UPDATE=false

USER mongodb
WORKDIR /var/lib/rowsafe
VOLUME ["/var/lib/rowsafe"]
ENTRYPOINT ["/usr/local/bin/rowsafe-agent"]
CMD ["run"]
