#!/bin/sh
set -eu

# Every phase requires the offline profile to hide installed capture helpers
if [ "${WIRESHARK_EXTCAP_DIR:-}" = "" ] || [ ! -d "$WIRESHARK_EXTCAP_DIR" ]; then
    printf '%s\n' 'private extcap directory missing' >&2
    exit 65
fi

# Each phase reads a fixed fixture next to the copied executable
for argument in "$@"; do
    case "$argument" in
        -v)
            printf '%s\n' 'TShark receipt fixture'
            exit 0
            ;;
        plugins)
            exit 0
            ;;
        currentprefs)
            cat "${0%/*}/preferences.txt"
            exit 0
            ;;
        fields)
            printf '%s\n' 'packet count diagnostic' >&2
            cat "${0%/*}/frames.txt"
            exit 0
            ;;
        json)
            cat "${0%/*}/packets.json"
            exit 0
            ;;
    esac
done

exit 64
