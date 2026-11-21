#!/usr/bin/env bash
set -euo pipefail

# Keep the source and checksum tied to one upstream release
version='0.13.1'
checksum='0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d'
url="https://github.com/containers/bubblewrap/releases/download/v${version}/bubblewrap-${version}.tar.xz"
scratch_dir=$(mktemp -d)
trap 'rm -rf -- "$scratch_dir"' EXIT
archive="$scratch_dir/bubblewrap.tar.xz"

# Check the entire download before unpacking or running any of its contents
curl --fail --silent --show-error --location --retry 3 \
  --proto '=https' --proto-redir '=https' --output "$archive" "$url"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check
tar -xJf "$archive" -C "$scratch_dir"

# Build without downloading extra Meson dependencies
meson setup "$scratch_dir/build" "$scratch_dir/bubblewrap-$version" \
  --wrap-mode=nodownload -Dtests=false -Dman=disabled \
  -Dbash_completion=disabled -Dzsh_completion=disabled
meson compile -C "$scratch_dir/build"

# Reject an unexpected binary before replacing the system executable
if ! version_output=$("$scratch_dir/build/bwrap" --version); then
  printf '%s\n' 'failed to check bubblewrap version' >&2
  exit 1
fi
if [[ $version_output != "bubblewrap $version" ]]; then
  printf 'unexpected bubblewrap version; expected %s\n' "$version" >&2
  exit 1
fi
sudo install -m 0755 -- "$scratch_dir/build/bwrap" /usr/bin/bwrap
