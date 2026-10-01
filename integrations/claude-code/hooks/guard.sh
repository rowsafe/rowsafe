#!/bin/sh
# Rowsafe Guard: a PreToolUse hook on Bash.
#
# `rowsafe guard` reads the hook event on stdin. When the command looks like a
# destructive database operation (a migration, DROP, TRUNCATE, ...), it creates
# a restore point on the project's database first and prints a note for Claude.
# It blocks the command (exit 2, reason on stderr) only when the project
# requires protection and the restore point can't be confirmed.
#
# This wrapper never lets the hook approve a command: a reply that carries a
# permission decision is dropped, so Claude Code's own permission checks
# always apply.

# Without the rowsafe CLI there is nothing to do.
command -v rowsafe >/dev/null 2>&1 || exit 0

out=$(rowsafe guard)
code=$?

case $out in
*permissionDecision* | *'"decision"'*) out= ;;
esac
if [ -n "$out" ]; then
	printf '%s\n' "$out"
fi
exit "$code"
