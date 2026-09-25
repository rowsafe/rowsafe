#!/usr/bin/env bash
# A rowsafe CLI with `rowsafe preview` for test-action.sh: preview prints
# what feat/copies' `rowsafe preview --json` prints (Go's JSON: the markdown
# has \n and < escapes; a nested result), everything else goes to the
# real CLI in $FAKE_REAL_CLI. The preview's arguments go to $FAKE_ARGS.
# FAKE_PREVIEW picks the outcome: safe, careful, dangerous, failed, or
# error (the preview couldn't run).
set -eu
if [ "${1:-} ${2:-}" = "help preview" ]; then
  echo "rowsafe preview [NAME] FILE [--db DB] [--json | --format text|json|markdown] [--fail-on careful|dangerous]"
  echo "                                             run a migration (FILE, or - for stdin) on a fresh copy of the database"
  exit 0
fi
if [ "${1:-}" != preview ]; then
  exec "$FAKE_REAL_CLI" "$@"
fi
printf '%s\n' "$*" >"$FAKE_ARGS"
echo "Previewing on a fresh copy of $2 (production is never touched)..." >&2
v=${FAKE_PREVIEW:-safe}
if [ "$v" = error ]; then
  cat <<'JSON'
{
  "verdict": "",
  "summary": "",
  "error": "The preview couldn't run: app has no backup yet: previews start from the latest backup"
}
JSON
  exit 1
fi
echo "  running the migration on the copy" >&2
case $v in
  failed) sum='The migration fails on the copy: ERROR: column \"note\" of relation \"orders\" already exists (line 2).' ;;
  dangerous) sum='ALTER TABLE orders rewrites 3.1 GB and blocks writes for about 2 min on production.' ;;
  careful) sum='CREATE INDEX on orders blocks writes for about 20 s on production. Use CREATE INDEX CONCURRENTLY.' ;;
  *) sum='Adds a column without a default: quick, no rewrite.' ;;
esac
md="### Rowsafe migration preview: $v\\n\\n$sum\\n\\n\\u003cdetails\\u003e\\u003csummary\\u003eStatements\\u003c/summary\\u003e\\n\\n| # | Statement |\\n|---|---|\\n| 1 | ALTER TABLE orders |\\n\\n\\u003c/details\\u003e\\n"
cat <<JSON
{
  "verdict": "$v",
  "summary": "$sum",
  "error": "",
  "id": "prv_1",
  "database": "$2",
  "label": "x",
  "status": "succeeded",
  "markdown": "$md",
  "result": {
    "verdict": "nested-$v",
    "summary": "nested"
  }
}
JSON
