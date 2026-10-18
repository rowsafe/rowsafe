#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Prints the MinIO image Rowsafe's Docker tests use, building it once from
# MinIO's source (Dockerfile here): MinIO no longer publishes images.
# ROWSAFE_TEST_MINIO_IMAGE overrides it.
set -eu
if [ -n "${ROWSAFE_TEST_MINIO_IMAGE:-}" ]; then
  echo "$ROWSAFE_TEST_MINIO_IMAGE"
  exit 0
fi
tag=rowsafe-test/minio:2025-10-15
if ! docker image inspect "$tag" >/dev/null 2>&1; then
  echo "building $tag from MinIO's source (once, a few minutes)" >&2
  docker build -q -t "$tag" "$(cd "$(dirname "$0")" && pwd)" >/dev/null
fi
echo "$tag"
