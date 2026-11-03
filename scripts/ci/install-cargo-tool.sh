#!/usr/bin/env bash
set -euo pipefail

# Each archive and checksum identifies one reviewed upstream release
if [[ $# -ne 1 ]]; then
  printf 'usage: %s {nextest|deny|audit}\n' "$0" >&2
  exit 2
fi

case "$1" in
  nextest)
    url='https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.138/cargo-nextest-0.9.138-x86_64-unknown-linux-gnu.tar.gz'
    checksum='3793bf0c27607b196f502c39b2108f571de89fcda7586ae6beefa11ee177b216'
    member='cargo-nextest'
    binary='cargo-nextest'
    ;;
  deny)
    url='https://github.com/EmbarkStudios/cargo-deny/releases/download/0.19.0/cargo-deny-0.19.0-x86_64-unknown-linux-musl.tar.gz'
    checksum='0e8c2aa59128612c90d9e09c02204e912f29a5b8d9a64671b94608cbe09e064f'
    member='cargo-deny-0.19.0-x86_64-unknown-linux-musl/cargo-deny'
    binary='cargo-deny'
    ;;
  audit)
    url='https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.22.0/cargo-audit-x86_64-unknown-linux-gnu-v0.22.0.tgz'
    checksum='210d47f963a3570bd47645c983893bdbcb562a0cbc440d8b0aafc250bfefe118'
    member='cargo-audit-x86_64-unknown-linux-gnu-v0.22.0/cargo-audit'
    binary='cargo-audit'
    ;;
  *)
    printf 'unknown CI tool: %s\n' "$1" >&2
    exit 2
    ;;
esac

# Verify the complete download before extracting only the expected binary
scratch_dir=$(mktemp -d)
trap 'rm -rf -- "$scratch_dir"' EXIT
archive="$scratch_dir/tool.tar.gz"
curl --fail --silent --show-error --location --retry 3 \
  --proto '=https' --proto-redir '=https' --output "$archive" "$url"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check
tar -xOzf "$archive" "$member" > "$scratch_dir/$binary"

# Publish the verified executable only after extraction succeeds
mkdir -p "$HOME/.cargo/bin"
install -m 755 "$scratch_dir/$binary" "$HOME/.cargo/bin/$binary"
