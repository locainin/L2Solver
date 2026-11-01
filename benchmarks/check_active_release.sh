#!/usr/bin/env bash
# Exercise packaged executables only inside the existing owned namespace fixtures
set -euo pipefail

if [[ $# -ne 1 ]]; then
    printf 'usage: %s RELEASE_ARCHIVE\n' "$0" >&2
    exit 2
fi

archive=$(realpath -- "$1")
qualified=$(mktemp -d "${TMPDIR:-/tmp}/l2solver-release-check.XXXXXX")
trap 'rm -rf -- "$qualified"' EXIT

# Extract only the two fixed executable names and preserve their restricted modes
tar --extract --gzip --file "$archive" --directory "$qualified" \
    --no-same-owner -- l2solver l2solver-active-helper
test -x "$qualified/l2solver"
test -x "$qualified/l2solver-active-helper"
export L2_TEST_MAIN_BINARY="$qualified/l2solver"
export L2_TEST_ACTIVE_HELPER="$qualified/l2solver-active-helper"

# Each fixture proves namespace ownership before creating or changing interfaces
# Missing kernel capabilities fail this qualification with the fixture's reason
python3 crates/l2-active-cli/tests/vlan/namespace.py \
    "$L2_TEST_MAIN_BINARY" "$L2_TEST_ACTIVE_HELPER"
cargo test --locked --package l2-active-cli --test cli -- --ignored --exact \
    dhcp::dhcp_cli_observes_owned_veth_offer_and_confirms_helper_cleanup \
    ndp::ndp_cli_observes_owned_veth_advertisement_and_confirms_cleanup \
    ndp::global_ndp_cli_requires_a_direct_route_and_observes_the_reply \
    listen::receive_only_cli_commands_observe_owned_veth_frames_and_release_memberships \
    dot1x::dot1x_cli_observes_owned_veth_request_and_confirms_cleanup
