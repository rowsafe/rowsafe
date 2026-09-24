#!/usr/bin/env bash
# Runs the Rowsafe GitHub Action's scripts the way action.yml does, against
# the mock API (test/mockapi), in every situation the action handles, and
# checks the outputs, the job summary and the exit status.
#
#   integrations/github-action/test/test-action.sh
#
# ROWSAFE_TEST_CLI=/path/to/rowsafe tests that CLI instead of one built from
# this checkout (e.g. an older release, to test the fallbacks).
# ROWSAFE_TEST_RELEASE=0.3.0 also installs that release from GitHub the way
# the action does (network), verifying its checksum and provenance.
# ROWSAFE_TEST_KEEP=1 keeps each case's log, outputs and summary.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
action=$(cd "$here/.." && pwd)
repo=$(cd "$action/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/rowsafe-action-test.XXXXXX")
mock_pid=""
cleanup() {
  if [ -n "$mock_pid" ]; then
    kill "$mock_pid" 2>/dev/null
    wait "$mock_pid" 2>/dev/null
  fi
  if [ -n "${ROWSAFE_TEST_KEEP:-}" ]; then echo "kept $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT

echo "building the CLI and the mock API"
(cd "$repo" && go build -o "$work/bin/rowsafe" ./cmd/rowsafe && go build -o "$work/bin/mockapi" ./integrations/github-action/test/mockapi)
cli=${ROWSAFE_TEST_CLI:-$work/bin/rowsafe}

port=$((20000 + RANDOM % 20000))
"$work/bin/mockapi" -addr "127.0.0.1:$port" -databases app,unprotected-db,broken-db,stuck-db >"$work/mock.log" 2>&1 &
mock_pid=$!
for _ in $(seq 50); do
  curl -fsS "http://127.0.0.1:$port/_mock/marks" >/dev/null 2>&1 && break
  sleep 0.1
done

# A git checkout for the preview tests: one migration already deployed, one new.
proj=$work/project
mkdir -p "$proj/migrations/001_init" "$proj/migrations/002_add_column"
git -C "$proj" init -q
git -C "$proj" config user.email test@example.com
git -C "$proj" config user.name test
echo 'CREATE TABLE orders (id bigint primary key);' >"$proj/migrations/001_init/migration.sql"
git -C "$proj" add -A && git -C "$proj" commit -qm init
before=$(git -C "$proj" rev-parse HEAD)
echo 'ALTER TABLE orders ADD COLUMN note text;' >"$proj/migrations/002_add_column/migration.sql"
git -C "$proj" add -A && git -C "$proj" commit -qm 'add column'
sha=$(git -C "$proj" rev-parse HEAD)

pass=0
failures=0
case_dir=""

# run NAME [VAR=VALUE...]: one run of the action (install with cli-path, then
# the main script) with the INPUT_* variables given. Sets $status.
run() {
  local name=$1
  shift
  case_dir=$work/cases/$name
  mkdir -p "$case_dir/runner"
  : >"$case_dir/output"
  : >"$case_dir/summary"
  : >"$case_dir/path"
  status=0
  (
    cd "$proj"
    export GITHUB_OUTPUT=$case_dir/output GITHUB_STEP_SUMMARY=$case_dir/summary GITHUB_PATH=$case_dir/path
    export RUNNER_TEMP=$case_dir/runner RUNNER_OS=${RUNNER_OS:-$(uname -s)} GITHUB_SHA=$sha
    export GITHUB_EVENT_NAME=push ROWSAFE_BEFORE_SHA=$before GITHUB_RUN_ID=4242 GITHUB_REPOSITORY=acme/shop
    export INPUT_API_KEY=rsk_test INPUT_API_URL=http://127.0.0.1:$port ROWSAFE_APP_URL=https://app.example.test
    export INPUT_CLI_PATH=$cli
    for kv in "$@"; do export "${kv?}"; done
    "$action/scripts/install-cli.sh" resolve
    INPUT_RESOLVED_VERSION=$(sed -n 's/^version=//p' "$GITHUB_OUTPUT") \
      INPUT_RESOLVED_PLATFORM=$(sed -n 's/^platform=//p' "$GITHUB_OUTPUT") \
      INPUT_RESOLVED_DIR=$(sed -n 's/^dir=//p' "$GITHUB_OUTPUT") \
      "$action/scripts/install-cli.sh" install
    PATH="$(cat "$GITHUB_PATH"):$PATH" "$action/scripts/run.sh"
  ) >"$case_dir/log" 2>&1 || status=$?
}

out() { sed -n "s/^$1=//p" "$case_dir/output" | tail -n 1; }
fail() {
  echo "FAIL [$(basename "$case_dir")]: $*"
  echo "--- log"; sed 's/^/    /' "$case_dir/log"
  echo "--- summary"; sed 's/^/    /' "$case_dir/summary"
  failures=$((failures + 1))
}
expect_status() { [ "$status" = "$1" ] || fail "exit status $status, want $1"; }
expect_out() { [ "$(out "$1")" = "$2" ] || fail "output $1 = '$(out "$1")', want '$2'"; }
expect_summary() { grep -qF -- "$1" "$case_dir/summary" || fail "summary lacks: $1"; }
expect_log() { grep -qF -- "$1" "$case_dir/log" || fail "log lacks: $1"; }
expect_no_log() { if grep -v '^::add-mask::' "$case_dir/log" | grep -qF -- "$1"; then fail "log has: $1"; fi; }
reported=0
ok() { # the checks since the previous ok() passed
  if [ "$failures" -eq "$reported" ]; then pass=$((pass + 1)); echo "ok   $1"; else echo "FAIL $1"; fi
  reported=$failures
}
marks() { curl -fsS "http://127.0.0.1:$port/_mock/marks"; }

short=${sha:0:7}
json=true
"$cli" help mark | grep -q -- --json || json=false

# 1. The usual deploy: protected, default label, wait until confirmed.
run happy INPUT_DATABASE=app
expect_status 0
expect_out mark "before-deploy-$short"
expect_out database app
expect_out protected true
expect_out restore-from-backup 20260924-020000F
expect_out mark-status archived
expect_out dashboard-url https://app.example.test/databases/app/restore-points
expect_summary "### Rowsafe: Mark \`before-deploy-$short\` saved on app"
expect_summary "| Restores from backup | \`20260924-020000F\` |"
expect_summary "[Rewind to this Mark](https://app.example.test/databases/app/restore-points)"
expect_summary "rowsafe rewind copy app --mark before-deploy-$short"
expect_log "::notice title=Rowsafe::Saved Mark before-deploy-$short on app"
expect_log "::add-mask::rsk_test"
ok "protected database: Mark saved and confirmed, outputs and summary"

# 2. The same commit again (a re-run): the default label gets -2.
run rerun INPUT_DATABASE=app
expect_status 0
expect_out mark "before-deploy-$short-2"
expect_log "A Mark for this commit already exists; using before-deploy-$short-2."
ok "re-run of the same commit: before-deploy-$short-2"

# 3. A custom label is cleaned up into a valid Mark name.
run label INPUT_DATABASE=app "INPUT_LABEL=Release v1.2 / API"
expect_status 0
expect_out mark release-v1-2-api
expect_log 'Mark name: "Release v1.2 / API" becomes "release-v1-2-api"'
ok "custom label cleaned up"

# 4. A custom label that exists is an error, not a silent rename.
run duplicate INPUT_DATABASE=app INPUT_LABEL=release-v1-2-api
expect_status 1
expect_log "a Mark named release-v1-2-api already exists on app"
expect_summary "### Rowsafe: Mark not saved"
ok "existing custom label fails clearly"

# 5. Not protected + require-protected: stop before the Mark.
run unprotected-required INPUT_DATABASE=unprotected-db INPUT_REQUIRE_PROTECTED=true
expect_status 1
expect_out protected false
expect_summary "### Rowsafe: unprotected-db is not protected"
expect_summary "- WAL archiving is failing"
expect_summary "[Open unprotected-db in the dashboard](https://app.example.test/databases/unprotected-db)"
if marks | grep -q '^unprotected-db/'; then fail "a Mark was saved on an unprotected database with require-protected"; fi
ok "not protected + require-protected: stopped, no Mark"

# 6. Not protected, default: warn and still save the Mark.
run unprotected-warn INPUT_DATABASE=unprotected-db
expect_status 0
expect_out protected false
expect_log "::warning title=Rowsafe::unprotected-db is not protected right now"
expect_summary "| Protected | **no**: WAL archiving is failing"
ok "not protected: warning, Mark saved"

# 7. The Mark can't be confirmed (archiving broken): fail with the reason.
run broken INPUT_DATABASE=broken-db
expect_status 1
expect_summary "### Rowsafe: Mark not confirmed"
expect_summary "usually because WAL archiving"
expect_log "not yet confirmed in the repository"
expect_summary "[Open broken-db in the dashboard](https://app.example.test/databases/broken-db)"
ok "Mark not confirmed: fails in plain words, with the agent's reason"

# 7b. The agent never picks the Mark up: give up after the timeout.
run stuck INPUT_DATABASE=stuck-db ROWSAFE_ACTION_TIMEOUT_SECONDS=3
expect_status 1
expect_summary "### Rowsafe: Mark not confirmed"
expect_summary "is the Rowsafe agent on the database server running?"
ok "Mark never picked up: gives up after wait-timeout-minutes"

# 8. wait: false only requests it.
run no-wait INPUT_DATABASE=app INPUT_LABEL=queued-only INPUT_WAIT=false
expect_status 0
expect_out mark queued-only
expect_summary "### Rowsafe: Mark \`queued-only\` requested on app"
if [ "$json" = true ]; then expect_out mark-status pending; fi
ok "wait: false"

# 9. No database input and several databases: ask which; .rowsafe.json answers.
run which-db INPUT_LABEL=x1
expect_status 1
expect_summary "### Rowsafe: which database?"
expect_log "Set the database input"
echo '{"database": "app"}' >"$proj/.rowsafe.json"
run rowsafe-json INPUT_LABEL=from-project-file
rm "$proj/.rowsafe.json"
expect_status 0
expect_out database app
ok "database from .rowsafe.json, and a clear question without it"

# 10. preview-sql: only the new migration; skipped when the CLI can't preview.
run preview INPUT_DATABASE=app INPUT_LABEL=with-preview "INPUT_PREVIEW_SQL=migrations/**/migration.sql"
expect_status 0
if "$cli" help preview | grep -q '^rowsafe preview'; then
  expect_log "Previewing 1 migration file(s)"
else
  expect_log "Migration preview: 1 of 2 matching files are new or changed since ${before:0:7}."
  expect_log "::notice title=Rowsafe::Migration preview skipped"
  expect_summary "**Migration preview:** skipped"
fi
expect_out mark with-preview
run preview-none INPUT_DATABASE=app INPUT_LABEL=no-new-migrations "INPUT_PREVIEW_SQL=migrations/001_init/*.sql"
expect_status 0
expect_log "no new migration files match"
run preview-dispatch INPUT_DATABASE=app INPUT_LABEL=dispatched "INPUT_PREVIEW_SQL=migrations/**/migration.sql" GITHUB_EVENT_NAME=workflow_dispatch
expect_status 0
expect_log "::warning title=Rowsafe::Migration preview skipped: can't tell which migration files are new"
expect_out mark dispatched
ok "preview-sql: new files only (skipped when unknown), graceful without rowsafe preview"

# 10b. With a CLI that has `rowsafe preview` (a wrapper standing in for it;
# FAKE_PREVIEW_VERDICT picks the verdict it reports).
cat >"$work/bin/rowsafe-with-preview" <<EOF
#!/usr/bin/env bash
if [ "\$1 \$2" = "help preview" ]; then
  echo "rowsafe preview [NAME] FILE [--json]   run migration SQL on a copy and report what it would do"
  exit 0
fi
if [ "\$1" = preview ]; then
  echo "Restoring a copy of \$2..." >&2
  grep -q 'ALTER TABLE' "\$3" || exit 1
  printf '{\n  "database": "%s",\n  "verdict": "%s",\n  "summary": "ALTER TABLE orders rewrites 3.1 GB and blocks writes for about 2 min."\n}\n' "\$2" "\${FAKE_PREVIEW_VERDICT:-safe}"
  exit 0
fi
exec "$cli" "\$@"
EOF
chmod +x "$work/bin/rowsafe-with-preview"
run preview-careful INPUT_DATABASE=app INPUT_LABEL=preview-careful "INPUT_PREVIEW_SQL=migrations/**/migration.sql" \
  "INPUT_CLI_PATH=$work/bin/rowsafe-with-preview" INPUT_PREVIEW_FAIL_ON=dangerous FAKE_PREVIEW_VERDICT=careful
expect_status 0
expect_out preview-verdict careful
expect_out mark preview-careful
expect_log "Previewing 1 migration file(s) on a copy of app"
expect_summary "**Migration preview: careful.** ALTER TABLE orders rewrites 3.1 GB"
run preview-dangerous INPUT_DATABASE=app INPUT_LABEL=preview-dangerous "INPUT_PREVIEW_SQL=migrations/**/migration.sql" \
  "INPUT_CLI_PATH=$work/bin/rowsafe-with-preview" INPUT_PREVIEW_FAIL_ON=dangerous FAKE_PREVIEW_VERDICT=dangerous
expect_status 1
expect_summary "### Rowsafe: migration looks dangerous"
if marks | grep -q '/preview-dangerous '; then fail "a Mark was saved after a dangerous preview with preview-fail-on"; fi
ok "rowsafe preview: verdict in the summary; preview-fail-on stops before the Mark"

# 11. Credentials.
run no-key INPUT_API_KEY=
expect_status 1
expect_summary "### Rowsafe: no API key"
run bad-key INPUT_API_KEY=not-a-key INPUT_DATABASE=app
expect_status 1
expect_summary "### Rowsafe: API key rejected"
expect_no_log "not-a-key"
ok "missing and rejected API keys"

run unknown-db INPUT_DATABASE=nope
expect_status 1
expect_summary "### Rowsafe: database not found"
ok "unknown database name"

# 12. Invalid inputs.
run bad-wait INPUT_DATABASE=app INPUT_WAIT=maybe
expect_status 1
expect_summary "wait must be true or false"
ok "invalid input"

# 13. Installing a real release the way the action does (network).
if [ -n "${ROWSAFE_TEST_RELEASE:-}" ]; then
  run release INPUT_CLI_PATH= "INPUT_VERSION=$ROWSAFE_TEST_RELEASE" INPUT_DATABASE=app INPUT_LABEL=installed-release \
    "RUNNER_TOOL_CACHE=$work/toolcache" "GH_TOKEN=${GH_TOKEN:-$(gh auth token 2>/dev/null || true)}"
  expect_status 0
  expect_log "checksum: OK"
  expect_log "provenance: built by rowsafe/rowsafe/.github/workflows/release.yml@refs/tags/v$ROWSAFE_TEST_RELEASE"
  expect_out mark installed-release
  expect_out restore-from-backup 20260924-020000F
  ok "installs release $ROWSAFE_TEST_RELEASE (checksum + provenance) and marks with it"
  # A tampered cached copy is replaced, never run.
  printf 'x' >>"$(find "$work/toolcache" -name rowsafe -type f)"
  run release-tampered INPUT_CLI_PATH= "INPUT_VERSION=$ROWSAFE_TEST_RELEASE" INPUT_DATABASE=app INPUT_LABEL=installed-again \
    "RUNNER_TOOL_CACHE=$work/toolcache" "GH_TOKEN=${GH_TOKEN:-$(gh auth token 2>/dev/null || true)}"
  expect_status 0
  expect_log "doesn't match the release checksum; downloading it again"
  ok "a cached CLI that doesn't match the checksum is downloaded again"
fi

echo
echo "$pass passed, $failures failed (CLI $("$cli" version), mark --json: $json)"
[ "$failures" -eq 0 ]
