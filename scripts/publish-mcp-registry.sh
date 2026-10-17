#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# publish-mcp-registry.sh: publishes server.json to the official MCP Registry
# (registry.modelcontextprotocol.io, name sh.rowsafe/rowsafe) at a release's
# version. release.yml runs it for every tag; run it by hand to catch up.
#
# The sh.rowsafe namespace is proven with DNS: rowsafe.sh has a TXT record
# "v=MCPv1; k=ed25519; p=<public key>", and MCP_REGISTRY_PRIVATE_KEY is the
# matching Ed25519 private key (hex). Without the key it uses an existing
# `mcp-publisher login`.
#
#   scripts/publish-mcp-registry.sh 0.10.20     (mcp-publisher on PATH)
set -eu

version=${1:?usage: publish-mcp-registry.sh VERSION}
version=${version#v}
root=$(cd "$(dirname "$0")/.." && pwd)
registry=https://registry.modelcontextprotocol.io
name=$(jq -r .name "$root/server.json")

# A version is published once; the registry refuses it a second time.
if curl -fsS "$registry/v0/servers?search=$name&version=$version" |
	jq -e --arg n "$name" --arg v "$version" '.servers[] | select(.server.name == $n and .server.version == $v)' >/dev/null; then
	echo "$name $version is already in the MCP Registry"
	exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
jq --arg v "$version" '.version = $v' "$root/server.json" >"$tmp/server.json"

if [ -n "${MCP_REGISTRY_PRIVATE_KEY:-}" ]; then
	mcp-publisher login dns --domain rowsafe.sh --private-key "$MCP_REGISTRY_PRIVATE_KEY"
fi
mcp-publisher publish "$tmp/server.json"

curl -fsS "$registry/v0/servers?search=$name&version=latest" |
	jq -e --arg n "$name" --arg v "$version" '.servers[] | select(.server.name == $n and .server.version == $v)' >/dev/null ||
	{ echo "the MCP Registry does not show $name $version as the latest version" >&2; exit 1; }
echo "published $name $version to the MCP Registry"
