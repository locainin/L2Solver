#!/bin/sh
set -eu

# Every phase requires the offline profile to hide installed capture helpers
if [ "${WIRESHARK_EXTCAP_DIR:-}" = "" ] || [ ! -d "$WIRESHARK_EXTCAP_DIR" ]; then
    printf '%s\n' 'private extcap directory missing' >&2
    exit 65
fi

# Older TShark releases reject glossary requests unless -G is first
for argument in "$@"; do
    if [ "$argument" = '-G' ] && [ "$1" != '-G' ]; then
        printf '%s\n' 'tshark: -G only valid as first option' >&2
        exit 64
    fi
done

if [ "$1" = '-G' ]; then
    # Require the same offline profile and name-resolution controls as other phases
    if [ "$#" -ne 5 ] || [ "$3" != '-n' ] || [ "$4" != '-C' ]; then
        printf '%s\n' 'glossary profile arguments missing' >&2
        exit 64
    fi
    profile_preferences="${WIRESHARK_CONFIG_DIR}/profiles/$5/preferences"
    if [ ! -f "$profile_preferences" ]; then
        printf '%s\n' 'glossary profile missing' >&2
        exit 65
    fi
    if [ -f "${0%/*}/$2.fail" ]; then
        printf 'fixture %s failed\n' "$2" >&2
        exit 42
    fi
    case "$2" in
        plugins)
            printf 'fixture.so\t1.0\tdissector\tfixture.so\n'
            exit 0
            ;;
        currentprefs)
            cat "$profile_preferences"
            exit 0
            ;;
    esac
    exit 64
fi

# Each phase reads a fixed fixture next to the copied executable
for argument in "$@"; do
    case "$argument" in
        -v)
            printf '%s\n' 'TShark receipt fixture'
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
