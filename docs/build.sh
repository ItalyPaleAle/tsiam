#!/usr/bin/env bash

# Go version to use for building
GO_VERSION="1.26.2"

set -e

# Detect the OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux)  GOOS="linux"  ;;
  Darwin) GOOS="darwin" ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac
case "$ARCH" in
  x86_64)           GOARCH="amd64"  ;;
  aarch64|arm64)    GOARCH="arm64"  ;;
  *)                echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Check if go is installed
if ! command -v go &>/dev/null; then
  echo "Go not found; bootstrapping Go ${GO_VERSION}..."
  CACHE_DIR=".cache/go-toolchain"
  TARBALL="go${GO_VERSION}.${GOOS}-${GOARCH}.tar.gz"
  mkdir -p "${CACHE_DIR}"
  curl -fsSL "https://dl.google.com/go/${TARBALL}" -o "${CACHE_DIR}/${TARBALL}"
  tar -C "${CACHE_DIR}" -xzf "${CACHE_DIR}/${TARBALL}"
  export PATH="${CACHE_DIR}/go/bin:$PATH"
fi

export GOCACHE=".cache/go"
export NODE_ENV=production
echo -e "\033[0;32mBuilding with Hugo...\033[0m"

go run github.com/italypaleale/hugo-assets/cmd/vercel-docs-build
