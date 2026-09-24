#!/usr/bin/env bash
# The Rowsafe GitHub Action: before a deploy, check that the database can be
# restored, optionally preview the migration on a copy, and save a Mark (a
# named restore point) the deploy can be rewound to.
#
# Inputs come from action.yml as INPUT_* environment variables; the rowsafe
# CLI is on PATH (install-cli.sh). Writes step outputs and a job summary.
set -euo pipefail

say() { printf '%s\n' "$*"; }
output() { printf '%s=%s\n' "$1" "$2" >>"${GITHUB_OUTPUT:-/dev/null}"; }
summary() { printf '%s\n' "$@" >>"${GITHUB_STEP_SUMMARY:-/dev/null}"; }
notice() { printf '::notice title=Rowsafe::%s\n' "$*"; }
warning() { printf '::warning title=Rowsafe::%s\n' "$*"; }

# stop fails the step: an error annotation, and the same message (plus any
# markdown lines given) at the top of the job summary.
stop() { # TITLE MESSAGE [SUMMARY-LINE...]
  local title=$1 msg=$2
  shift 2
  printf '::error title=Rowsafe: %s::%s\n' "$title" "$msg"
  summary "### Rowsafe: $title" "" "$msg" ""
  [ $# -gt 0 ] && summary "$@" ""
  exit 1
}

# bool NAME VALUE sets BOOL to true or false, or stops on anything else.
bool() {
  case $(printf '%s' "$2" | tr '[:upper:]' '[:lower:]') in
    true | yes | 1 | on) BOOL=true ;;
    false | no | 0 | off | '') BOOL=false ;;
    *) stop "invalid input" "$1 must be true or false (got \"$2\")." ;;
  esac
}

# field KEY FILE prints a top-level string field of the indented JSON the
# CLI prints (one field per line).
field() {
  sed -n "s/^  \"$1\": \"\\(.*\\)\",\\{0,1\\}\$/\\1/p" "$2" | head -n 1 | sed 's/\\"/"/g; s/\\\\/\\/g'
}

# run_limited SECONDS CMD... runs CMD with a time limit; after it,
# $TMP/timed-out exists. Output goes wherever the caller redirects it.
# (The watchdog doesn't hold the caller's stdout or stderr open.)
run_limited() {
  local secs=$1 pid watchdog rc=0
  shift
  rm -f "$TMP/timed-out"
  "$@" &
  pid=$!
  (
    sleep "$secs"
    touch "$TMP/timed-out"
    kill -TERM "$pid" 2>/dev/null
  ) >/dev/null 2>&1 &
  watchdog=$!
  wait "$pid" || rc=$?
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  return "$rc"
}

# capture NAME CMD... runs CMD with its stdout in $TMP/NAME.out and its
# stderr both in the log (live) and in $TMP/NAME.err.
capture() {
  local name=$1
  shift
  { "$@" 2>&1 1>&3 3>&- | tee "$TMP/$name.err" >&2; } 3>"$TMP/$name.out"
}

# ---------------------------------------------------------------- inputs

TMP=$(mktemp -d "${RUNNER_TEMP:-/tmp}/rowsafe-action.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

if [ -z "${INPUT_API_KEY:-}" ]; then
  fork=""
  if [ "${GITHUB_EVENT_NAME:-}" = pull_request ]; then
    fork=" Pull requests from forks don't get secrets, so run this action on pushes to your deploy branch instead."
  fi
  stop "no API key" "The api-key input is empty. Create a key in the Rowsafe dashboard (Settings > API keys) or with \`rowsafe api-keys create deploy-ci\`, save it as a repository secret named ROWSAFE_API_KEY, and pass it: \`api-key: \${{ secrets.ROWSAFE_API_KEY }}\`.$fork"
fi
printf '::add-mask::%s\n' "$INPUT_API_KEY"
export ROWSAFE_API_KEY=$INPUT_API_KEY
if [ -n "${INPUT_API_URL:-}" ]; then
  export ROWSAFE_URL=${INPUT_API_URL%/}
fi
API_URL=${ROWSAFE_URL:-https://api.rowsafe.sh}

bool wait "${INPUT_WAIT:-true}"
WAIT=$BOOL
bool require-protected "${INPUT_REQUIRE_PROTECTED:-false}"
REQUIRE_PROTECTED=$BOOL
bool preview-changed-only "${INPUT_PREVIEW_CHANGED_ONLY:-true}"
CHANGED_ONLY=$BOOL
TIMEOUT_MIN=${INPUT_WAIT_TIMEOUT_MINUTES:-10}
printf '%s\n' "$TIMEOUT_MIN" | grep -Eq '^[1-9][0-9]{0,3}$' ||
  stop "invalid input" "wait-timeout-minutes must be a whole number of minutes, such as 10 (got \"$TIMEOUT_MIN\")."
TIMEOUT_SECS=${ROWSAFE_ACTION_TIMEOUT_SECONDS:-$((TIMEOUT_MIN * 60))} # the override is for tests
PREVIEW_FAIL_ON=${INPUT_PREVIEW_FAIL_ON:-never}
case $PREVIEW_FAIL_ON in never | dangerous | careful) ;; *)
  stop "invalid input" "preview-fail-on must be never, dangerous or careful (got \"$PREVIEW_FAIL_ON\")." ;;
esac

if [ -n "${INPUT_WORKING_DIRECTORY:-}" ] && [ "$INPUT_WORKING_DIRECTORY" != . ]; then
  cd "$INPUT_WORKING_DIRECTORY" || stop "invalid input" "working-directory $INPUT_WORKING_DIRECTORY doesn't exist in this checkout."
fi

SHA=${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}
SHORT_SHA=${SHA:0:7}

# The dashboard lives next to the API (api.rowsafe.sh -> app.rowsafe.sh);
# ROWSAFE_APP_URL says where it is otherwise.
APP_URL=${ROWSAFE_APP_URL:-}
if [ -z "$APP_URL" ]; then
  case $API_URL in
    https://api.*) APP_URL="https://app.${API_URL#https://api.}" ;;
  esac
fi
APP_URL=${APP_URL%/}

# ---------------------------------------------------------------- label

# A Mark name is 1-63 lowercase letters, digits, - and _, starting with a
# letter or digit. Anything else in the label is turned into dashes.
sanitize() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9_-]+/-/g; s/^[^a-z0-9]+//' | cut -c1-63 | sed -E 's/-+$//'
}
AUTO_LABEL=false
if [ -n "${INPUT_LABEL:-}" ]; then
  LABEL=$(sanitize "$INPUT_LABEL")
  [ -n "$LABEL" ] || stop "invalid label" "The label \"$INPUT_LABEL\" has no letters or digits. Use something like before-deploy-v42."
  [ "$LABEL" = "$INPUT_LABEL" ] || say "Mark name: \"$INPUT_LABEL\" becomes \"$LABEL\" (lowercase letters, digits, - and _ only)."
else
  LABEL="before-deploy-$SHORT_SHA"
  AUTO_LABEL=true
fi

# ---------------------------------------------------------------- database

CLI_VERSION=$(rowsafe version 2>/dev/null || echo unknown)
supports() { # COMMAND FLAG: does this CLI's help for COMMAND mention FLAG?
  rowsafe help "$1" 2>/dev/null | grep -q -- "$2"
}

# The CLI finds the database the same way everywhere: the database input,
# else ROWSAFE_DATABASE, else .rowsafe.json in this directory or a parent,
# else the organization's only database. `rowsafe show` answers with it.
if [ -n "${INPUT_DATABASE:-}" ]; then
  DB_ARG=("$INPUT_DATABASE")
else
  DB_ARG=()
fi
if ! rowsafe show ${DB_ARG[@]+"${DB_ARG[@]}"} >"$TMP/show.out" 2>"$TMP/show.err"; then
  err=$(sed 's/^error: //' "$TMP/show.err")
  case $err in
    *"invalid API key"* | *"invalid credentials"* | *"HTTP 401"*)
      stop "API key rejected" "Rowsafe didn't accept the API key ($err). Check the ROWSAFE_API_KEY secret: it must be a current key of your organization (Settings > API keys)." ;;
    *"not found"*)
      stop "database not found" "Rowsafe has no database named \"${INPUT_DATABASE:-}\" in this API key's organization. Use the name shown in the dashboard." ;;
    *"which database"*)
      stop "which database?" "${err%%$'\n'*} Set the database input, e.g. \`database: app\`, or commit a .rowsafe.json (\`rowsafe init app\`)." ;;
    *)
      stop "can't reach Rowsafe" "Couldn't look up the database at $API_URL: $err" ;;
  esac
fi
DB=$(sed -n 's/^Name: *\([^ ]*\).*/\1/p' "$TMP/show.out" | head -n 1)
[ -n "$DB" ] || DB=${INPUT_DATABASE:-}
output database "$DB"
DASHBOARD_URL=""
if [ -n "$APP_URL" ]; then
  DASHBOARD_URL="$APP_URL/databases/$DB/restore-points"
fi
output dashboard-url "$DASHBOARD_URL"
say "Database: $DB  (rowsafe CLI $CLI_VERSION, $API_URL)"

# ---------------------------------------------------------------- is it protected?

say ""
say "Checking that $DB can be restored right now..."
rc=0
rowsafe status "$DB" >"$TMP/status.out" 2>"$TMP/status.err" || rc=$?
sed 's/^./  &/' "$TMP/status.out"
PROTECTED=unknown
case $rc in
  0) PROTECTED=true ;;
  3) PROTECTED=false ;;
  *)
    sed 's/^/  /' "$TMP/status.err"
    stop "can't check $DB" "Couldn't check whether $DB can be restored: $(sed 's/^error: //' "$TMP/status.err" | head -n 3)" ;;
esac
output protected "$PROTECTED"
REASONS=$(sed -n 's/^  - /- /p' "$TMP/status.out")
if [ "$PROTECTED" = false ]; then
  if [ "$REQUIRE_PROTECTED" = true ]; then
    open=""
    [ -n "$APP_URL" ] && open="[Open $DB in the dashboard]($APP_URL/databases/$DB) to fix it."
    stop "$DB is not protected" \
      "Deploy stopped: $DB can't be restored right now, so a Mark wouldn't let you rewind this deploy. Fix the reasons below (or set require-protected: false to deploy anyway)." \
      "$REASONS" "" "$open"
  fi
  warning "$DB is not protected right now, so rewinding this deploy might not work. $(printf '%s' "$REASONS" | tr '\n' ' ')Set require-protected: true to stop deploys when this happens."
fi

# ---------------------------------------------------------------- migration preview

PREVIEW_MD=()
PREVIEW_VERDICT=""
if [ -n "${INPUT_PREVIEW_SQL:-}" ]; then
  say ""
  # Match the patterns (one per line or space-separated, ** allowed).
  shopt -s nullglob
  shopt -s globstar 2>/dev/null || true # bash 4+
  files=()
  # shellcheck disable=SC2086 # word splitting and globbing are the point
  for f in $INPUT_PREVIEW_SQL; do
    [ -f "$f" ] && files+=("$f")
  done
  shopt -u nullglob
  shopt -u globstar 2>/dev/null || true
  # Only the files this push or pull request adds or changes: migrations
  # that already ran would fail on a copy of production.
  base=""
  case ${GITHUB_EVENT_NAME:-} in
    pull_request | pull_request_target) base=${ROWSAFE_BASE_SHA:-} ;;
    push) base=${ROWSAFE_BEFORE_SHA:-} ;;
  esac
  skip=""
  if [ "$CHANGED_ONLY" = true ] && [ ${#files[@]} -gt 0 ]; then
    if [ -z "$base" ] || [ "$base" = 0000000000000000000000000000000000000000 ]; then
      skip="can't tell which migration files are new (this run isn't a push or a pull request with a base). Set preview-changed-only: false to preview every file matching preview-sql."
    else
      git cat-file -e "$base^{commit}" 2>/dev/null || git fetch -q --no-tags --depth=1 origin "$base" 2>/dev/null || true
      if git diff --name-only --diff-filter=AM --relative "$base" HEAD -- >"$TMP/changed" 2>/dev/null; then
        kept=()
        for f in "${files[@]}"; do
          grep -Fxq -- "${f#./}" "$TMP/changed" && kept+=("$f")
        done
        say "Migration preview: ${#kept[@]} of ${#files[@]} matching files are new or changed since ${base:0:7}."
        files=(${kept[@]+"${kept[@]}"})
      else
        skip="couldn't compare with ${base:0:7} to find the new migration files. Use actions/checkout with fetch-depth: 0."
      fi
    fi
  fi

  if [ -n "$skip" ]; then
    warning "Migration preview skipped: $skip"
    PREVIEW_MD=("**Migration preview:** skipped, $skip")
  elif [ ${#files[@]} -eq 0 ]; then
    say "Migration preview: no new migration files match \"$INPUT_PREVIEW_SQL\"; nothing to preview."
    PREVIEW_MD=("**Migration preview:** no new migration files matched \`$INPUT_PREVIEW_SQL\`.")
  elif ! rowsafe help preview 2>/dev/null | grep -q '^rowsafe preview'; then
    notice "Migration preview skipped: rowsafe CLI $CLI_VERSION can't preview migrations yet. Use a newer version (version: latest) to preview them on a copy before deploying."
    PREVIEW_MD=("**Migration preview:** skipped, the rowsafe CLI $CLI_VERSION can't preview migrations yet.")
  else
    # Preview them together, in order, on one copy: later migrations
    # usually depend on earlier ones.
    for f in "${files[@]}"; do
      printf -- '-- %s\n' "$f"
      cat "$f"
      printf '\n'
    done >"$TMP/preview.sql"
    say "Previewing ${#files[@]} migration file(s) on a copy of $DB (production isn't touched):"
    printf '  %s\n' "${files[@]}"
    json=false
    args=(preview "$DB" "$TMP/preview.sql")
    if supports preview --json; then
      json=true
      args+=(--json)
    fi
    rc=0
    capture preview run_limited "$TIMEOUT_SECS" rowsafe "${args[@]}" || rc=$?
    if [ -e "$TMP/timed-out" ]; then
      warning "The migration preview didn't finish within $TIMEOUT_MIN minutes, so there is no verdict."
      PREVIEW_MD=("**Migration preview:** didn't finish within $TIMEOUT_MIN minutes.")
    else
      [ "$json" = true ] || sed 's/^/  /' "$TMP/preview.out"
      if [ "$json" = true ]; then
        PREVIEW_VERDICT=$(field verdict "$TMP/preview.out" | tr '[:upper:]' '[:lower:]')
        headline=$(field summary "$TMP/preview.out")
        perr=$(field error "$TMP/preview.out")
        [ -n "$perr" ] && [ -z "$PREVIEW_VERDICT" ] && PREVIEW_VERDICT=dangerous && headline="The migration failed on the copy: $perr"
      else
        PREVIEW_VERDICT=$(grep -Eoiw 'safe|careful|dangerous' "$TMP/preview.out" | head -n 1 | tr '[:upper:]' '[:lower:]' || true)
        headline=$(head -n 1 "$TMP/preview.out")
      fi
      if [ "$rc" -ne 0 ] && [ -z "$PREVIEW_VERDICT" ]; then
        warning "The migration preview couldn't finish: $(sed 's/^error: //' "$TMP/preview.err" | tail -n 1)"
        PREVIEW_MD=("**Migration preview:** couldn't finish: $(sed 's/^error: //' "$TMP/preview.err" | tail -n 1)")
      else
        say "Migration preview: ${PREVIEW_VERDICT:-done}${headline:+. $headline}"
        PREVIEW_MD=("**Migration preview: ${PREVIEW_VERDICT:-done}.** ${headline}" ""
          "<details><summary>Preview details (${#files[@]} file(s))</summary>" "" '```' "$(head -c 60000 "$TMP/preview.out")" '```' "" "</details>")
      fi
    fi
    output preview-verdict "$PREVIEW_VERDICT"
    if { [ "$PREVIEW_FAIL_ON" = dangerous ] && [ "$PREVIEW_VERDICT" = dangerous ]; } ||
      { [ "$PREVIEW_FAIL_ON" = careful ] && { [ "$PREVIEW_VERDICT" = dangerous ] || [ "$PREVIEW_VERDICT" = careful ]; }; }; then
      stop "migration looks $PREVIEW_VERDICT" \
        "Deploy stopped: the migration preview on a copy of $DB says \"$PREVIEW_VERDICT\" (preview-fail-on: $PREVIEW_FAIL_ON). Nothing was changed in production and no Mark was saved." \
        "${PREVIEW_MD[@]}"
    fi
  fi
fi

# ---------------------------------------------------------------- the Mark

say ""
if [ "$WAIT" = true ]; then
  say "Mark $LABEL on $DB:"
else
  say "Mark $LABEL on $DB (only requested: wait is false):"
fi
JSON=false
supports mark --json && JSON=true
mark() { # LABEL
  local args=(mark "$DB" "$1")
  [ "$WAIT" = true ] || args+=(--no-wait)
  [ "$JSON" = true ] && args+=(--json)
  capture mark run_limited "$TIMEOUT_SECS" rowsafe "${args[@]}"
}
rc=0
mark "$LABEL" || rc=$?
# The default label is per commit; a re-run (or a second deploy of the same
# commit) gets -2, -3, ...
n=2
while [ "$rc" -ne 0 ] && [ "$AUTO_LABEL" = true ] && [ $n -le 20 ] && grep -q 'already exists' "$TMP/mark.err"; do
  LABEL="before-deploy-$SHORT_SHA-$n"
  say "A Mark for this commit already exists; using $LABEL."
  rc=0
  mark "$LABEL" || rc=$?
  n=$((n + 1))
done
output mark "$LABEL"

STATUS="" RESTORE_FROM="" ERROR=""
if [ "$JSON" = true ]; then
  STATUS=$(field status "$TMP/mark.out")
  RESTORE_FROM=$(field restore_from_backup "$TMP/mark.out")
  ERROR=$(field error "$TMP/mark.out")
else
  # An older CLI: read the Mark back from the list.
  sed 's/^/  /' "$TMP/mark.out"
  if rowsafe marks "$DB" >"$TMP/marks.out" 2>/dev/null; then
    read -r STATUS RESTORE_FROM < <(awk -v l="$LABEL" '$1 == l { rfb = ($3 == "-") ? $4 : $5; if (rfb == "-") rfb = ""; print $2, rfb; exit }' "$TMP/marks.out") || true
  fi
fi
[ "$RESTORE_FROM" = "-" ] && RESTORE_FROM=""
output restore-from-backup "$RESTORE_FROM"
output mark-status "${STATUS:-unknown}"

rewind_line=""
if [ -n "$DASHBOARD_URL" ]; then
  rewind_line="**[Rewind to this Mark]($DASHBOARD_URL)** in the Rowsafe dashboard if this deploy goes wrong."
fi
diy=("<details><summary>From the command line</summary>" "" '```sh'
  "# a copy of $DB as it was at the Mark, next to production (production isn't touched)"
  "rowsafe rewind copy $DB --mark $LABEL"
  "# rows the deploy deleted or changed, by table"
  "rowsafe rewind compare $DB"
  '```' "" "</details>")

if [ -e "$TMP/timed-out" ]; then
  stop "Mark not confirmed" \
    "Rowsafe didn't confirm Mark $LABEL on $DB within $TIMEOUT_MIN minutes (is the Rowsafe agent on the database server running?). The deploy wasn't protected by a Mark, so this step failed. It may still be saved: check Marks in the dashboard." \
    "${rewind_line:+[Open Marks for $DB]($DASHBOARD_URL)}"
fi
if [ "$rc" -ne 0 ]; then
  msg=$ERROR
  if [ -z "$msg" ]; then # the CLI's error line (older CLIs print the task's on stdout)
    msg=$({ sed -n 's/^Error: //p' "$TMP/mark.out"; sed -n 's/^error: //p' "$TMP/mark.err"; } | tail -n 3)
  fi
  [ -n "$msg" ] || msg="the rowsafe CLI exited with status $rc."
  open=""
  [ -n "$APP_URL" ] && open="[Open $DB in the dashboard]($APP_URL/databases/$DB) to see why and fix it."
  if [ "$STATUS" = unconfirmed ]; then
    say "  the server said: $msg"
    stop "Mark not confirmed" \
      "The Mark $LABEL was written on $DB, but your storage didn't confirm it in time, usually because WAL archiving (copying changes to your bucket) is failing. The deploy isn't covered, so this step failed." \
      "$open" "" "<details><summary>What the server said</summary>" "" '```' "$msg" '```' "" "</details>"
  fi
  case $msg in
    *"already exists"*) msg="a Mark named $LABEL already exists on $DB. Choose another label, or leave label empty for an automatic one." ;;
    *"read-only"*) msg="the API key is read-only. Saving a Mark needs a read-write key (Settings > API keys)." ;;
  esac
  stop "Mark not saved" "Rowsafe couldn't save Mark $LABEL on $DB: $msg" "$open"
fi

# ---------------------------------------------------------------- report

when=$(date -u '+%Y-%m-%d %H:%M:%S UTC')
if [ "$WAIT" = true ]; then
  state="confirmed in your storage at $when"
  say "Mark $LABEL is in your storage.${RESTORE_FROM:+ A rewind to it starts from backup $RESTORE_FROM.}"
  notice "Saved Mark $LABEL on $DB. If this deploy goes wrong, rewind to it${DASHBOARD_URL:+: $DASHBOARD_URL}"
else
  state="requested at $when; not waiting for confirmation (wait: false)"
  say "Mark $LABEL requested (${STATUS:-pending})."
  notice "Requested Mark $LABEL on $DB${DASHBOARD_URL:+: $DASHBOARD_URL}"
fi

case $PROTECTED in
  true) protected_md="yes: backups, WAL archiving and the latest restore test are all OK" ;;
  *) protected_md="**no**: $(printf '%s' "$REASONS" | sed 's/^- //' | paste -sd ';' - | sed 's/;/; /g')" ;;
esac
run_url=""
if [ -n "${GITHUB_RUN_ID:-}" ]; then
  run_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/$GITHUB_RUN_ID"
fi

if [ "$WAIT" = true ]; then
  summary "### Rowsafe: Mark \`$LABEL\` saved on $DB" ""
else
  summary "### Rowsafe: Mark \`$LABEL\` requested on $DB" ""
fi
summary "If this deploy goes wrong, you can rewind **$DB** to the moment just before it." ""
summary "| | |" "|---|---|"
summary "| Mark | \`$LABEL\`, $state |"
summary "| Database | $DB |"
summary "| Protected | $protected_md |"
[ -n "$RESTORE_FROM" ] && summary "| Restores from backup | \`$RESTORE_FROM\` |"
summary "| Commit | \`$SHORT_SHA\`${run_url:+ ([run $GITHUB_RUN_ID]($run_url))} |"
summary ""
if [ ${#PREVIEW_MD[@]} -gt 0 ]; then
  summary "${PREVIEW_MD[@]}" ""
fi
[ -n "$rewind_line" ] && summary "$rewind_line" ""
summary "${diy[@]}"
