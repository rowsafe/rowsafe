# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# rowsafe-docker-control: the opt-in service that lets the Rowsafe agent
# stop, start and restart exactly one container (your PostgreSQL service)
# without the agent ever seeing the Docker socket. A single static binary on
# an empty image: no shell, no package manager, nothing else to run.
# Published as ghcr.io/rowsafe/docker-control:<version>.
#
#   docker build -f deploy/docker/docker-control.Dockerfile -t rowsafe-docker-control .
#
# It runs as root only to open the Docker socket (owned by root); run it
# with every capability dropped, a read-only root filesystem and
# no-new-privileges, as deploy/docker/compose.example.yml does. See
# internal/dockerctl for the policy and https://rowsafe.sh/docs/guides/docker
# for the threat model.

FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd/rowsafe-docker-control ./cmd/rowsafe-docker-control
COPY internal/dockerctl ./internal/dockerctl
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid= -X main.version=${VERSION}" \
      -o /out/rowsafe-docker-control ./cmd/rowsafe-docker-control

FROM scratch
COPY --from=build /out/rowsafe-docker-control /rowsafe-docker-control
LABEL org.opencontainers.image.title="Rowsafe docker-control (restart one PostgreSQL container on the agent's request)" \
      org.opencontainers.image.source="https://github.com/rowsafe/rowsafe" \
      org.opencontainers.image.licenses="Apache-2.0"
USER 0:0
VOLUME ["/run/rowsafe-control"]
ENTRYPOINT ["/rowsafe-docker-control"]
CMD ["run"]
