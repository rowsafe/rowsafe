# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Rowsafe agent as a Docker sidecar for the official postgres:NN images,
# which stay unmodified. One image per PostgreSQL major version and image
# flavour: it carries pgBackRest and that major's server binaries (for
# restore drills) from apt.postgresql.org, and runs as the postgres image's
# postgres uid/gid. Published as ghcr.io/rowsafe/agent:<version>-pg<major>
# and ...-pg<major>-alpine.
#
#   docker build -f deploy/docker/agent.Dockerfile --build-arg PG_MAJOR=17 -t rowsafe-agent:pg17 .
#   # for postgres:NN-alpine (postgres is uid/gid 70 there):
#   docker build -f deploy/docker/agent.Dockerfile --build-arg PG_MAJOR=17 \
#       --build-arg PG_UID=70 --build-arg PG_GID=70 -t rowsafe-agent:pg17-alpine .
#
# See docs/docker.md and deploy/docker/compose.example.yml.

ARG DEBIAN_SUITE=trixie

# The agent is a static Go binary, cross-compiled on the build machine.
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
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/rowsafe/rowsafe/internal/agent.Version=${VERSION}" \
      -o /out/rowsafe-agent ./cmd/rowsafe-agent

FROM debian:${DEBIAN_SUITE}-slim
ARG DEBIAN_SUITE
ARG PG_MAJOR=17
# Must match the postgres user of the PostgreSQL image: 999 in the Debian
# images, 70 in the Alpine ones. The agent checks this at startup.
ARG PG_UID=999
ARG PG_GID=999
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8

# The postgres user first, so the packages below reuse it; no default
# cluster; then PostgreSQL server binaries and pgBackRest from PGDG, and the
# en_US.UTF-8 locale the official images initialise databases with (a drill
# cannot connect to a database whose locale the OS lacks).
RUN set -eux; \
    groupadd --system --gid "${PG_GID}" postgres; \
    useradd --system --uid "${PG_UID}" --gid postgres --home-dir /var/lib/rowsafe --shell /usr/sbin/nologin postgres; \
    mkdir -p /etc/postgresql-common/createcluster.d; \
    echo 'create_main_cluster = false' > /etc/postgresql-common/createcluster.d/rowsafe.conf; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl locales procps util-linux; \
    install -d /usr/share/postgresql-common/pgdg; \
    curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc; \
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt ${DEBIAN_SUITE}-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends "postgresql-${PG_MAJOR}" pgbackrest; \
    localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8; \
    apt-get purge -y --auto-remove curl; \
    # JIT is never used here (drills only count tables). Up to PostgreSQL 17 \
    # the server package pulls in LLVM, most of the image: remove it, which \
    # breaks the package dependency on purpose (install further packages in \
    # a derived image with `apt-get -f install` first). 18+ packages JIT \
    # separately. \
    rm -rf "/usr/lib/postgresql/${PG_MAJOR}/lib/bitcode" "/usr/lib/postgresql/${PG_MAJOR}/lib/llvmjit"*; \
    jit="$(dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' 'libllvm*' 'libz3-*' 2>/dev/null | awk '$1 == "ii" {print $2}')"; \
    if [ -n "$jit" ]; then dpkg --purge --force-depends $jit; fi; \
    rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/*; \
    test "$(id -u postgres):$(id -g postgres)" = "${PG_UID}:${PG_GID}"; \
    pgbackrest version; "/usr/lib/postgresql/${PG_MAJOR}/bin/postgres" --version

# /var/lib/rowsafe: identity, generated pgBackRest configs, drills (a volume).
# /rowsafe-spool: WAL handed over by archive_command (a volume shared with
# PostgreSQL; a new, empty volume takes this directory's owner, so
# PostgreSQL can write to it). /var/run/postgresql: PostgreSQL's socket (a
# shared volume).
RUN install -d -o postgres -g postgres -m 0700 /var/lib/rowsafe /var/log/rowsafe /rowsafe-spool \
 && install -d -o postgres -g postgres -m 2775 /var/run/postgresql \
 && install -d -o postgres -g postgres -m 0700 /tmp/pgbackrest

COPY --from=build /out/rowsafe-agent /usr/local/bin/rowsafe-agent

LABEL org.opencontainers.image.title="Rowsafe agent (PostgreSQL ${PG_MAJOR} sidecar)" \
      org.opencontainers.image.source="https://github.com/rowsafe/rowsafe" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV ROWSAFE_MODE=docker-sidecar \
    ROWSAFE_STATE_DIR=/var/lib/rowsafe \
    ROWSAFE_CONFIG_DIR=/var/lib/rowsafe/pgbackrest \
    ROWSAFE_DRILL_DIR=/var/lib/rowsafe/drills \
    ROWSAFE_LOG_DIR=/var/log/rowsafe \
    ROWSAFE_SPOOL_DIR=/rowsafe-spool \
    ROWSAFE_PG_BIN_DIR=/usr/lib/postgresql/%d/bin \
    ROWSAFE_PGBACKREST_BIN=/usr/bin/pgbackrest \
    ROWSAFE_AUTO_UPDATE=false \
    PG_MAJOR=${PG_MAJOR}

USER ${PG_UID}:${PG_GID}
WORKDIR /var/lib/rowsafe
VOLUME ["/var/lib/rowsafe"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD ["/usr/local/bin/rowsafe-agent", "health"]
ENTRYPOINT ["/usr/local/bin/rowsafe-agent"]
CMD ["run"]
