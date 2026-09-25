#!/usr/bin/env bash
# Exports the GitHub Action as the content of its own repository
# (rowsafe/action), which GitHub Marketplace needs: action.yml at the root.
#
#   integrations/github-action/export.sh DEST [VERSION]
#
# DEST is a checkout of rowsafe/action (or an empty directory). Everything
# in it except .git is replaced: action.yml, README.md, LICENSE, scripts/
# and examples/. With VERSION (e.g. 1.0.0) it also prints the
# commands that commit, tag vVERSION and move the major tag (v1). Nothing is
# pushed: publishing stays a manual step.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
dest=${1:?usage: export.sh DEST [VERSION]}
version=${2:-}
if [ -n "$version" ]; then
  version=${version#v}
  printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "VERSION must look like 1.0.0" >&2; exit 1; }
fi

mkdir -p "$dest"
dest=$(cd "$dest" && pwd)
case $dest in "$repo" | "$repo"/*) echo "DEST must be outside this repository" >&2; exit 1 ;; esac

# Clear the old content, keeping the repository itself. Refuse a directory
# that isn't empty and isn't a previous export.
if [ -n "$(find "$dest" -mindepth 1 -maxdepth 1 ! -name .git ! -name .DS_Store | head -n 1)" ] && [ ! -f "$dest/action.yml" ]; then
  echo "$dest isn't empty and has no action.yml: refusing to replace its content" >&2
  exit 1
fi
find "$dest" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +

cp "$here/action.yml" "$here/README.md" "$dest/"
cp "$repo/LICENSE" "$dest/LICENSE"
mkdir -p "$dest/scripts" "$dest/examples"
cp "$here"/scripts/*.sh "$dest/scripts/"
chmod 0755 "$dest"/scripts/*.sh
cp "$here"/examples/*.yml "$dest/examples/"

# No workflow files: Marketplace refuses repositories that have any. The
# action is tested in rowsafe/rowsafe (.github/workflows/action.yml).
commit=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo main)

echo "Exported the action to $dest"
if [ -n "$version" ]; then
  major=${version%%.*}
  cat <<EOF

To publish v$version (check the diff first; nothing has been pushed):

  cd $dest
  git add -A && git commit -m "v$version (from rowsafe/rowsafe $commit)"
  git tag -a v$version -m "v$version"
  git tag -fa v$major -m "v$major -> v$version"
  git push origin main v$version && git push -f origin v$major

Then draft a GitHub release for v$version and tick "Publish this Action to the GitHub Marketplace".
EOF
fi
