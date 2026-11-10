#!/bin/sh
# Builds the project in one step: build/html-simple-pgp.html (the single file) and
# build/pages/ (the PWA). Nothing to install — only Node 24 or newer.
#
#   ./build.sh          build
#   ./build.sh --check  unit tests, build, browser tests (needs a local Chrome)
set -eu

cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js $(cat .nvmrc) or newer is needed: https://nodejs.org" >&2
  exit 1
fi
major=$(node -p 'process.versions.node.split(".")[0]')
if [ "$major" -lt "$(cat .nvmrc)" ]; then
  echo "Node.js $(cat .nvmrc) or newer is needed, this is $(node --version)" >&2
  exit 1
fi

case "${1:-}" in
  "") node --run build ;;
  --check) node --run check ;;
  *)
    echo "usage: ./build.sh [--check]" >&2
    exit 2
    ;;
esac

if [ -z "${1:-}" ]; then
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 build/html-simple-pgp.html
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum build/html-simple-pgp.html
  fi
fi
