#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Records the README demo (docs/demo/rowsafe-demo.gif, .mp4, .webm) with real
# output: a PostgreSQL 17 in Docker with planted problems, a terminal that
# installs the rowsafe CLI from https://rowsafe.sh/cli, saves the database with
# rowsafe add and runs pulse, fix and pulse again. Needs Docker. Takes about 12 minutes: pulse reports a session
# idle in a transaction only after 10 minutes.
#
#   docs/demo/record.sh
set -eu
cd "$(dirname "$0")"

compose() { docker compose "$@"; }

compose down -v --remove-orphans >/dev/null 2>&1 || true
trap 'compose down -v --remove-orphans >/dev/null 2>&1 || true' EXIT

compose build -q vhs
compose up -d --wait db
compose exec -T db psql -q -U postgres -d shop -v ON_ERROR_STOP=1 <plant.sql >/dev/null

# An application that started a transaction, changed a row and never
# committed. It starts after the bulk delete, so cleanup can still remove
# those rows.
compose exec -d db sh -c \
  '(echo "BEGIN; UPDATE customers SET name = name WHERE id = 1;"; sleep infinity) | psql -q -U postgres -d shop'

echo "Waiting 10 minutes for the idle transaction to count..."
sleep "${ROWSAFE_DEMO_WAIT:-610}"

compose run --rm vhs demo.tape

# Shrink the GIF (vhs writes every frame in full).
compose run --rm --entrypoint gifsicle vhs -O3 --lossy=40 --colors 64 \
  -o rowsafe-demo.gif rowsafe-demo.gif
ls -l rowsafe-demo.gif rowsafe-demo.mp4 rowsafe-demo.webm
