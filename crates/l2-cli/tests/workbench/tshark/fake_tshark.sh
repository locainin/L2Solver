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
    if [ "$2" = '__FAILED_GLOSSARY__' ]; then
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

# Keep phase output inside the selected executable for the isolated filesystem
for argument in "$@"; do
    case "$argument" in
        -v)
            printf '%s\n' 'TShark 4.4.19'
            exit 0
            ;;
        fields)
            printf '%s\n' 'packet count diagnostic' >&2
            printf '%b' '__FRAMES_OCTAL__'
            exit 0
            ;;
        json)
            printf '%b' '__PACKETS_OCTAL__'
            exit 0
            ;;
    esac
done

exit 64
