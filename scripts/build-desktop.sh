#!/usr/bin/env bash
# Builds BENCchat for the desktop targets that can be produced from Linux:
# native Linux, plus a Windows cross-compile.
#
# macOS is deliberately absent. Wails needs Cocoa through CGO to build a .app
# and refuses to cross-compile ("Crosscompiling to Mac not currently
# supported"), so a macOS build requires a real macOS machine — that is what
# .github/workflows/build.yml uses a macos runner for.
#
# By default the binaries have NO server address in them: config.DefaultAuthHost
# stays empty and you type the address on the sign-on screen. That is the right
# build to hand to anyone else. To make a personal build that already knows
# where to connect, pass the host in the environment:
#
#     AUTH_HOST=chat.example.com ./scripts/build-desktop.sh
#
# It is passed via -ldflags and never written to a file, so it cannot end up in
# git by accident. Do not use it for anything you publish — a binary can be
# `strings`-grepped, so a baked-in host is public the moment the binary is.
set -euo pipefail
cd "$(dirname "$0")/.."

# Node and wails install per-user rather than system-wide on this machine.
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"

command -v wails >/dev/null || {
  echo "wails not found on PATH." >&2
  echo "Install it with: go install github.com/wailsapp/wails/v2/cmd/wails@v2.10.1" >&2
  exit 1
}

# Stamp the build so a running client can report exactly what it was built from.
# A stale client that predates a wire change fails against the server in a way
# that is invisible without this -- see the sign-on screen's build line.
VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT}"
if [[ -n "${AUTH_HOST:-}" ]]; then
  LDFLAGS="${LDFLAGS} -X github.com/benco-holdings/benchat/internal/config.DefaultAuthHost=${AUTH_HOST}"
  echo "==> building with a baked-in host — keep these binaries to yourself"
else
  echo "==> building with no server address (enter it on the sign-on screen)"
fi
echo "==> build stamp: ${VERSION} (${COMMIT})"

build() {
  local platform="$1" label="$2"
  shift 2
  echo
  echo "==> $label"
  if [[ -n "$LDFLAGS" ]]; then
    wails build -platform "$platform" -ldflags "$LDFLAGS" "$@"
  else
    wails build -platform "$platform" "$@"
  fi
}

# webkit2_41 is required wherever webkit2gtk 4.1 is the only version present
# (Artix here, Ubuntu 24.04 in CI). Without it the build hunts for the 4.0
# pkg-config file and fails. It is a Linux-only tag — passing it to the Windows
# target would be noise.
#
# Order matters. Wails generates the TypeScript bindings by compiling a helper
# and RUNNING it, which a cross-compile turns into a Windows .exe that Linux
# cannot exec ("fork/exec /tmp/wailsbindings: exec format error"). The native
# Linux build therefore goes first and regenerates frontend/wailsjs/, and the
# Windows build reuses what it produced. CI doesn't need this dance — it builds
# Windows natively on a Windows runner.
build linux/amd64   "Linux (amd64)"   -tags webkit2_41
build windows/amd64 "Windows (amd64)" -skipbindings

echo
echo "Built:"
ls -la build/bin/
