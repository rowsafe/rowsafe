#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# check-qdrant-pins.sh: checks the Qdrant release Rowsafe pins against its
# sources. The installer's QDRANT_* SHA-256 pins against the digests GitHub
# records for the release's files (Qdrant publishes no checksum files or
# signatures; GitHub computes these itself when a file is uploaded), and the
# agent image's DB_IMAGE_DIGEST against the registry's digest of the tag.
# Run it when changing the pins (TestPinsAgree checks the copies agree).
#
#   scripts/check-qdrant-pins.sh           (GITHUB_TOKEN raises GitHub's rate limit)
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
pin() { sed -n "s/^$1=\\(.*\\)$/\\1/p" "$2" | head -n 1; }
version=$(pin QDRANT_VERSION "$root/scripts/install.sh")
deb=$(pin QDRANT_DEB_AMD64 "$root/scripts/install.sh" | sed "s/\${QDRANT_VERSION}/$version/")
deb_sum=$(pin QDRANT_DEB_AMD64_SHA256 "$root/scripts/install.sh")
tgz=$(pin QDRANT_TGZ_ARM64 "$root/scripts/install.sh")
tgz_sum=$(pin QDRANT_TGZ_ARM64_SHA256 "$root/scripts/install.sh")
digest=$(sed -n 's/^ARG DB_IMAGE_DIGEST=\(sha256:[0-9a-f]*\)$/\1/p' "$root/deploy/docker/agent-qdrant.Dockerfile")
[ -n "$version" ] && [ -n "$deb_sum" ] && [ -n "$tgz_sum" ] && [ -n "$digest" ] || { echo "check-qdrant-pins: pins not found" >&2; exit 2; }

rc=0
auth=''
[ -z "${GITHUB_TOKEN:-}" ] || auth="Authorization: Bearer $GITHUB_TOKEN"
rel=$(curl -fsSL ${auth:+-H "$auth"} -H 'Accept: application/vnd.github+json' \
	"https://api.github.com/repos/qdrant/qdrant/releases/tags/v$version") || { echo "check-qdrant-pins: can't read release v$version from GitHub" >&2; exit 2; }
# The release's assets, one per line: name and GitHub's digest.
assets=$(printf '%s' "$rel" | tr -d '\n' | sed 's/}, *{/}\n{/g' |
	sed -n 's/.*"name": *"\([^"]*\)".*"digest": *"sha256:\([0-9a-f]\{64\}\)".*/\1 \2/p')
for f in "$deb $deb_sum" "$tgz $tgz_sum"; do
	set -- $f
	got=$(printf '%s\n' "$assets" | awk -v n="$1" '$1 == n { print $2 }')
	if [ -z "$got" ]; then
		echo "FAIL $1: GitHub records no digest for it in release v$version" >&2
		rc=1
	elif [ "$got" != "$2" ]; then
		echo "FAIL $1: pinned $2, GitHub says $got" >&2
		rc=1
	else
		echo "ok   $1 (Qdrant $version): $2"
	fi
done

token=$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:qdrant/qdrant:pull" |
	sed -n 's/.*"token": *"\([^"]*\)".*/\1/p')
reg=$(curl -fsSI -H "Authorization: Bearer $token" \
	-H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json' \
	"https://registry-1.docker.io/v2/qdrant/qdrant/manifests/v$version" | tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: *//p')
if [ "$reg" = "$digest" ]; then
	echo "ok   qdrant/qdrant:v$version: $digest"
else
	echo "FAIL qdrant/qdrant:v$version: pinned $digest, the registry says ${reg:-nothing}" >&2
	rc=1
fi
exit $rc
