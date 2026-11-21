#!/bin/sh
set -eu

# Return the fixture version without entering the export behavior
if [ "$#" -eq 2 ] && [ "$1" = "-n" ] && [ "$2" = "-v" ]; then
    printf '%s\n' '__VERSION__'
    exit 0
fi

# Fail during discovery when the test requires rejection before export
export_mode='__EXPORT_MODE__'
if [ "$export_mode" = 'fails' ]; then
    printf '%s\n' 'unexpected fixture export' >&2
    exit 77
fi

__EXPORT_SCRIPT__
