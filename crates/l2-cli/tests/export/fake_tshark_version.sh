#!/bin/sh
set -eu

# Return the fixture version without entering the export behavior
if [ "${1:-}" = "-n" ] && [ "${2:-}" = "-v" ]; then
    IFS= read -r version < "${0%/*}/version.txt"
    printf '%s\n' "$version"
    exit 0
fi

# Record calls that reach the shared export fixture
printf '%s\n' export >> "${0%/*}/invocations.txt"
exec "${0%/*}/tshark-export" "$@"
