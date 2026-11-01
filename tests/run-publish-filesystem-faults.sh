#!/usr/bin/env bash
set -euo pipefail

test_binary=${1:?pass the compiled publish integration-test executable}
results_root=${2:?pass an existing directory for temporary mountpoints}
checkpoint_test_binary=${3:-}
generation_test_binary=${4:-}
case_buffer_test_binary=${5:-}

run_in_namespace() {
    local binary=$1
    local root=$2
    local checkpoint_binary=$3
    local generation_binary=$4
    local case_buffer_binary=$5
    local case_buffer_test='export::processing::case_buffer::tests::qualification::faults::real_full_tmpfs_spill_preserves_previous_output_and_cleans_private_files'
    require_test() {
        local binary_path=$1
        local test_name=$2
        if ! "$binary_path" --list --exact "$test_name" | grep -Fx -- "$test_name: test" > /dev/null; then
            printf 'required test not found: %s\n' "$test_name" >&2
            return 1
        fi
    }
    require_test "$binary" faults::real_full_filesystem_preserves_the_existing_directory
    require_test "$binary" faults::real_read_only_filesystem_preserves_the_existing_directory
    if [[ -n "$checkpoint_binary" ]]; then
        require_test "$checkpoint_binary" \
            recovery_job::cache::tests::real_full_filesystem_preserves_prior_checkpoint_and_respects_strict_mode
    fi
    if [[ -n "$generation_binary" ]]; then
        require_test "$generation_binary" \
            cache::execution::real_full_filesystem_preserves_the_committed_execution_generation
    fi
    if [[ -n "$case_buffer_binary" ]]; then
        require_test "$case_buffer_binary" "$case_buffer_test"
    fi
    l2_fault_area=$(mktemp -d "$root/l2-publish-faults.XXXXXXXX")
    l2_fault_full_mount="$l2_fault_area/full"
    l2_fault_readonly_mount="$l2_fault_area/read-only"
    cleanup() {
        while mountpoint -q -- "$l2_fault_readonly_mount"; do
            umount -- "$l2_fault_readonly_mount"
        done
        if mountpoint -q -- "$l2_fault_full_mount"; then
            umount -- "$l2_fault_full_mount"
        fi
        if [[ -d "$l2_fault_readonly_mount" ]]; then
            rmdir -- "$l2_fault_readonly_mount"
        fi
        if [[ -d "$l2_fault_full_mount" ]]; then
            rmdir -- "$l2_fault_full_mount"
        fi
        rmdir -- "$l2_fault_area"
    }
    trap cleanup EXIT

    # Propagation changes and mounts stay inside this unprivileged namespace
    mount --make-rprivate /
    mkdir -- "$l2_fault_full_mount" "$l2_fault_readonly_mount"
    mount -t tmpfs -o size=1m,mode=0700 tmpfs "$l2_fault_full_mount"
    L2_TEST_ENOSPC_ROOT="$l2_fault_full_mount" "$binary" \
        --exact faults::real_full_filesystem_preserves_the_existing_directory --nocapture
    if [[ -n "$checkpoint_binary" ]]; then
        L2_TEST_ENOSPC_ROOT="$l2_fault_full_mount" "$checkpoint_binary" \
            --exact recovery_job::cache::tests::real_full_filesystem_preserves_prior_checkpoint_and_respects_strict_mode --nocapture
    fi
    if [[ -n "$generation_binary" ]]; then
        L2_TEST_ENOSPC_ROOT="$l2_fault_full_mount" "$generation_binary" \
            --exact cache::execution::real_full_filesystem_preserves_the_committed_execution_generation --nocapture
    fi
    if [[ -n "$case_buffer_binary" ]]; then
        L2_TEST_ENOSPC_ROOT="$l2_fault_full_mount" "$case_buffer_binary" \
            --exact "$case_buffer_test" --ignored --nocapture
    fi

    mount -t tmpfs -o size=1m,mode=0700,uid=0,gid=0 tmpfs "$l2_fault_readonly_mount"
    mkdir -- "$l2_fault_readonly_mount/bundle"
    printf '%s' 'previous output' > "$l2_fault_readonly_mount/bundle/payload"
    mount --bind "$l2_fault_readonly_mount" "$l2_fault_readonly_mount"
    mount -o remount,bind,ro "$l2_fault_readonly_mount"
    L2_TEST_EROFS_ROOT="$l2_fault_readonly_mount" "$binary" \
        --exact faults::real_read_only_filesystem_preserves_the_existing_directory --nocapture
    cleanup
    trap - EXIT
}

export -f run_in_namespace
unshare --user --map-root-user --mount -- \
    bash -c 'set -euo pipefail; run_in_namespace "$@"' run_in_namespace \
    "$test_binary" "$results_root" "$checkpoint_test_binary" "$generation_test_binary" \
    "$case_buffer_test_binary"
