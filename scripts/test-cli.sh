#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests scripts/cli.sh (the CLI installer at https://rowsafe.sh/cli) on this
# computer, macOS or Linux, without Docker or root:
#
#   sh scripts/test-cli.sh          against a fake release served locally
#   sh scripts/test-cli.sh --real   also installs the real latest release
#
# Each case runs with its own HOME and PATH in a temporary folder.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CLI_SH=$ROOT/scripts/cli.sh
WORK=$(mktemp -d 2>/dev/null || mktemp -d -t rowsafe-test-cli)
SERVER_PID=''
cleanup() {
  [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}
pass() { printf 'ok   %s\n' "$*"; }

case $(uname -s) in Darwin) OS=darwin ;; *) OS=linux ;; esac
case $(uname -m) in x86_64 | amd64) ARCH=amd64 ;; *) ARCH=arm64 ;; esac
if [ "$OS" = darwin ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then ARCH=arm64; fi

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{ print $1 }'; else shasum -a 256 "$1" | awk '{ print $1 }'; fi
}

# A fake release v9.9.9 whose "CLI" is a shell script printing its version.
REL=$WORK/release/v9.9.9
mkdir -p "$REL"
printf '#!/bin/sh\necho 9.9.9\n' >"$REL/rowsafe-$OS-$ARCH"
printf '%s  rowsafe-%s-%s\n' "$(sha256_of "$REL/rowsafe-$OS-$ARCH")" "$OS" "$ARCH" >"$REL/SHA256SUMS"
# The same release with a tampered binary.
BAD=$WORK/release/v9.9.8
mkdir -p "$BAD"
cp "$REL/SHA256SUMS" "$BAD/SHA256SUMS"
printf '#!/bin/sh\necho evil\n' >"$BAD/rowsafe-$OS-$ARCH"

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
(cd "$WORK/release" && exec python3 -m http.server "$PORT" --bind 127.0.0.1) >/dev/null 2>&1 &
SERVER_PID=$!
i=0
until curl -fsS -o /dev/null "http://127.0.0.1:$PORT/v9.9.9/SHA256SUMS" 2>/dev/null; do
  i=$((i + 1))
  [ $i -lt 50 ] || fail "the fake release server didn't start"
  sleep 0.1
done

# run_case NAME SHELL [VAR=VALUE...]: runs cli.sh with a fresh HOME, a PATH
# without ~/.local/bin, and the fake release; output in $WORK/NAME.out.
run_case() {
  name=$1 shell=$2
  shift 2
  home=$WORK/home-$name
  mkdir -p "$home"
  env -i HOME="$home" SHELL="$shell" PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    ROWSAFE_DOWNLOAD_BASE="http://127.0.0.1:$PORT" ROWSAFE_CURL_PROTO='=http' \
    ROWSAFE_VERSION=9.9.9 "$@" sh "$CLI_SH" >"$WORK/$name.out" 2>&1
}

# 1. zsh, nothing on PATH: installs to ~/.local/bin and adds it to .zshrc once.
if [ -w /usr/local/bin ]; then
  run_case zsh /bin/zsh ROWSAFE_INSTALL_DIR="$WORK/home-zsh/.local/bin" || { cat "$WORK/zsh.out"; fail "zsh install"; }
else
  run_case zsh /bin/zsh || { cat "$WORK/zsh.out"; fail "zsh install"; }
fi
[ "$("$WORK/home-zsh/.local/bin/rowsafe")" = 9.9.9 ] || fail "zsh: CLI not installed in ~/.local/bin"
grep -qF "export PATH=\"$WORK/home-zsh/.local/bin:\$PATH\"" "$WORK/home-zsh/.zshrc" || fail "zsh: PATH not added to .zshrc"
grep -q 'rowsafe login' "$WORK/zsh.out" || fail "zsh: no next step printed"
pass "installs to ~/.local/bin and adds it to the PATH in .zshrc"

# 2. Running it again changes nothing in the profile.
if [ -w /usr/local/bin ]; then
  run_case zsh /bin/zsh ROWSAFE_INSTALL_DIR="$WORK/home-zsh/.local/bin" || fail "zsh re-run"
else
  run_case zsh /bin/zsh || fail "zsh re-run"
fi
[ "$(grep -c '# rowsafe CLI' "$WORK/home-zsh/.zshrc")" = 1 ] || fail "re-run: PATH added twice"
pass "running it again updates in place, PATH added once"

# 3. bash: .bash_profile on macOS, .bashrc on Linux.
run_case bash /bin/bash ROWSAFE_INSTALL_DIR="$WORK/home-bash/.local/bin" || { cat "$WORK/bash.out"; fail "bash install"; }
if [ "$OS" = darwin ]; then prof=.bash_profile; else prof=.bashrc; fi
grep -q 'rowsafe CLI' "$WORK/home-bash/$prof" || fail "bash: PATH not added to $prof"
pass "bash: PATH added to $prof"

# 4. ROWSAFE_NO_MODIFY_PATH leaves profiles alone and says what to add.
run_case nomod /bin/zsh ROWSAFE_INSTALL_DIR="$WORK/home-nomod/bin" ROWSAFE_NO_MODIFY_PATH=1 || fail "no-modify install"
[ ! -e "$WORK/home-nomod/.zshrc" ] || fail "no-modify: .zshrc was written"
grep -q "Add $WORK/home-nomod/bin to your PATH" "$WORK/nomod.out" || fail "no-modify: no PATH hint"
pass "ROWSAFE_NO_MODIFY_PATH=1 changes no profile"

# 5. A binary that doesn't match SHA256SUMS is refused and nothing is installed.
if run_case bad /bin/zsh ROWSAFE_VERSION=9.9.8 ROWSAFE_INSTALL_DIR="$WORK/home-bad/bin"; then fail "tampered binary installed"; fi
grep -q "doesn't match the release's SHA256SUMS" "$WORK/bad.out" || { cat "$WORK/bad.out"; fail "tampered: wrong message"; }
[ ! -e "$WORK/home-bad/bin/rowsafe" ] || fail "tampered: something was installed"
pass "a binary that doesn't match SHA256SUMS is refused"

# 6. A version that doesn't exist fails clearly.
if run_case missing /bin/zsh ROWSAFE_VERSION=1.2.3 ROWSAFE_INSTALL_DIR="$WORK/home-missing/bin"; then fail "missing version installed"; fi
grep -q "couldn't download rowsafe-$OS-$ARCH 1.2.3" "$WORK/missing.out" || { cat "$WORK/missing.out"; fail "missing: wrong message"; }
pass "a missing version fails with a plain message"

# 7. A malformed version is refused before downloading.
if run_case junk /bin/zsh 'ROWSAFE_VERSION=1.2;rm' ROWSAFE_INSTALL_DIR="$WORK/home-junk/bin"; then fail "junk version accepted"; fi
grep -q 'should look like' "$WORK/junk.out" || fail "junk: wrong message"
pass "a malformed ROWSAFE_VERSION is refused"

# 8. The real latest release from GitHub (network).
if [ "${1:-}" = --real ]; then
  home=$WORK/home-real
  mkdir -p "$home"
  env -i HOME="$home" SHELL=/bin/zsh PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    ROWSAFE_INSTALL_DIR="$home/.local/bin" sh "$CLI_SH" >"$WORK/real.out" 2>&1 || { cat "$WORK/real.out"; fail "real install"; }
  v=$("$home/.local/bin/rowsafe" version) || fail "real: the CLI doesn't run"
  HOME=$home "$home/.local/bin/rowsafe" help >/dev/null || fail "real: rowsafe help"
  pass "installs the real latest release ($v, $OS/$ARCH) and it runs"
fi

printf 'all CLI installer tests passed\n'
