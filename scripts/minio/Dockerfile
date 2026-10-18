# MinIO and its mc client for Rowsafe's Docker tests (an S3 bucket behind
# TLS). MinIO stopped publishing images and binaries, so this builds them
# from their source (AGPL-3.0, github.com/minio/minio and minio/mc) at a
# pinned release. Test use only: never shipped with Rowsafe.
ARG GO_VERSION=1.25
FROM golang:${GO_VERSION}-alpine AS build
ARG MINIO_VERSION=RELEASE.2025-10-15T17-29-55Z
ARG MC_VERSION=RELEASE.2025-08-13T08-35-41Z
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN apk add --no-cache git && \
    go install github.com/minio/minio@${MINIO_VERSION} && \
    go install github.com/minio/mc@${MC_VERSION}

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /go/bin/minio /go/bin/mc /usr/bin/
EXPOSE 9000
ENTRYPOINT ["minio"]
