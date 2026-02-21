#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <version>"
  echo "Example: $0 v1.0.0"
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

version="$1"

# Accept either 1.0.0 or v1.0.0 and normalize to v-prefixed tag.
if [[ "$version" != v* ]]; then
  version="v${version}"
fi

if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid version: $version" >&2
  echo "Expected semantic version format like v1.0.0" >&2
  exit 1
fi

echo "Running release commands for ${version}..."

git add .
git commit -m "release ${version}"
git tag -a "${version}" -m "${version}"
git push origin main
git push origin "${version}"

echo "Release commands completed for ${version}."
