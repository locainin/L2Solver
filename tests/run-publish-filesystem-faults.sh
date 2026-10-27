#!/usr/bin/env bash
set -euo pipefail

test_binary=${1:?pass the compiled publish integration-test executable}
results_root=${2:?pass an existing directory for temporary mountpoints}

run_in_namespace() {
    local binary=$1
    local root=$2
    local area full_mount readonly_mount
    area=$(mktemp -d "$root/l2-publish-faults.XXXXXXXX")
    full_mount="$area/full"
    readonly_mount="$area/read-only"

    # Propagation changes and mounts stay inside this unprivileged namespace
    mount --make-rprivate /
    mkdir -- "$full_mount" "$readonly_mount"
    cleanup() {
        while mountpoint -q -- "$readonly_mount"; do
            umount -- "$readonly_mount"
        done
        if mountpoint -q -- "$full_mount"; then
            umount -- "$full_mount"
        fi
        rmdir -- "$readonly_mount" "$full_mount" "$area"
    }
    trap cleanup EXIT

    mount -t tmpfs -o size=1m,mode=0700 tmpfs "$full_mount"
    L2_TEST_ENOSPC_ROOT="$full_mount" "$binary" \
        --exact faults::real_full_filesystem_preserves_the_existing_directory --nocapture

    mount -t tmpfs -o size=1m,mode=0700,uid=0,gid=0 tmpfs "$readonly_mount"
    mkdir -- "$readonly_mount/bundle"
    printf '%s' 'previous output' > "$readonly_mount/bundle/payload"
    mount --bind "$readonly_mount" "$readonly_mount"
    mount -o remount,bind,ro "$readonly_mount"
    L2_TEST_EROFS_ROOT="$readonly_mount" "$binary" \
        --exact faults::real_read_only_filesystem_preserves_the_existing_directory --nocapture
    cleanup
    trap - EXIT
}

export -f run_in_namespace
unshare --user --map-root-user --mount -- \
    bash -c 'set -euo pipefail; run_in_namespace "$@"' run_in_namespace "$test_binary" "$results_root"
