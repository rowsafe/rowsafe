# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
#
# Rowsafe agent as a Docker sidecar for the official mysql:8.4 and mysql:8.0
# images, which stay unmodified. The image is built FROM the same mysql
# image (so restore tests and Rewind copies run the very same server
# version) and adds Percona XtraBackup and the MySQL client tools
# (mysqlbinlog) from their vendors' repositories, whose signing keys are
# checked against pinned fingerprints. It runs as the mysql image's mysql
# user (999:999). Published as ghcr.io/rowsafe/agent:<version>-mysql<8.4|8.0>.
#
#   docker build -f deploy/docker/agent-mysql.Dockerfile --build-arg MYSQL_VERSION=8.4 -t rowsafe-agent:mysql8.4 .
#
# See deploy/docker/compose.mysql.yml.

ARG MYSQL_VERSION=8.4

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

FROM mysql:${MYSQL_VERSION}
ARG MYSQL_VERSION
# Percona's packaging key (https://www.percona.com/downloads/RPM-GPG-KEY-percona).
ARG PERCONA_KEY_FPR=4D1BB29D63D98E422B2113B19334A25F8507EFA5
RUN set -eux; \
    case "${MYSQL_VERSION}" in 8.0*) pxb=80; repo=pxb-80 ;; *) pxb=84; repo=pxb-84-lts ;; esac; \
    curl -fsSL -o /tmp/percona.key https://repo.percona.com/yum/PERCONA-PACKAGING-KEY; \
    fpr="$(gpg --show-keys --with-colons /tmp/percona.key | awk -F: '$1 == "fpr" { print $10; exit }')"; \
    test "$fpr" = "${PERCONA_KEY_FPR}"; \
    install -m 0644 /tmp/percona.key /etc/pki/rpm-gpg/RPM-GPG-KEY-percona; \
    printf '[percona-%s]\nname=Percona XtraBackup\nbaseurl=https://repo.percona.com/%s/yum/release/9/RPMS/$basearch\nenabled=1\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-percona\n' \
      "$repo" "$repo" > /etc/yum.repos.d/percona-xtrabackup.repo; \
    microdnf install -y "percona-xtrabackup-${pxb}" cpio; \
    # mysqlbinlog is in MySQL's client package, which conflicts with the
    # image's minimal server package: take only mysqlbinlog from the client
    # package of the image's exact version, checked with MySQL's key (which
    # the image carries).
    ver="$(rpm -q --qf '%{VERSION}-%{RELEASE}' mysql-community-server-minimal)"; arch="$(uname -m)"; \
    mm="$(echo "${MYSQL_VERSION}" | cut -d. -f1,2)"; case "$mm" in 8.0) mrepo=mysql80-community ;; *) mrepo="mysql-${mm}-community" ;; esac; \
    curl -fsSL -o /tmp/client.rpm "https://repo.mysql.com/yum/${mrepo}/el/9/${arch}/mysql-community-client-${ver}.${arch}.rpm"; \
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-mysql*; rpm -K /tmp/client.rpm | grep -q 'digests signatures OK'; \
    (cd / && rpm2cpio /tmp/client.rpm | cpio -idm ./usr/bin/mysqlbinlog); rm -f /tmp/client.rpm; \
    microdnf remove -y cpio; \
    microdnf clean all; rm -rf /var/cache/yum /tmp/percona.key; \
    xtrabackup --version; mysqlbinlog --version; \
    install -d -o mysql -g mysql -m 0700 /var/lib/rowsafe /var/log/rowsafe /rowsafe-spool

COPY --from=build /out/rowsafe-agent /usr/local/bin/rowsafe-agent

LABEL org.opencontainers.image.title="Rowsafe agent (MySQL ${MYSQL_VERSION} sidecar)" \
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
