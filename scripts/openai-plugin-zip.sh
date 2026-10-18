#!/usr/bin/env bash
# Builds the ZIP for the OpenAI plugin directory (ChatGPT and Codex) from
# integrations/codex: the MCP server only. The directory rejects packages
# with lifecycle hooks, and flags skills that run code outside the package
# (the rowsafe CLI); ChatGPT can't run the CLI and its connection is read and
# Marks only, so the hook and the skills stay in the plugin people install
# from this repository.
#
#   scripts/openai-plugin-zip.sh            -> dist/rowsafe-openai-plugin-<version>.zip
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/integrations/codex"
version="$(jq -r .version "$src/.codex-plugin/plugin.json")"
out="$root/dist/rowsafe-openai-plugin-$version.zip"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pkg="$work/rowsafe"
mkdir -p "$pkg/.codex-plugin"

cp -R "$src/assets" "$pkg/"
# The directory matches the server by key and URL only (the draft it created
# has no Codex-only settings such as tool_timeout_sec).
jq --indent 2 '{mcpServers: (.mcpServers | map_values({url}))}' "$src/.mcp.json" >"$pkg/.mcp.json"
jq --indent 2 'del(.hooks, .skills)' "$src/.codex-plugin/plugin.json" >"$pkg/.codex-plugin/plugin.json"

# The directory takes exactly one remote MCP server with no headers.
jq -e '(.mcpServers | length) == 1 and ([.mcpServers[] | select(.headers)] | length) == 0' \
	"$pkg/.mcp.json" >/dev/null || { echo "openai-plugin-zip: .mcp.json must declare one server, no headers" >&2; exit 1; }
# Five positive and three negative review cases.
jq -e '.extensions["com.openai"].review.test_cases | (.positive | length) == 5 and (.negative | length) == 3' \
	"$pkg/.codex-plugin/plugin.json" >/dev/null || { echo "openai-plugin-zip: need 5 positive and 3 negative test cases" >&2; exit 1; }

mkdir -p "$root/dist"
rm -f "$out"
(cd "$pkg" && zip -qrX "$out" . -x '.DS_Store')
echo "$out"
