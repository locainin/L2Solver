#!/usr/bin/env bash
# Build and observe an isolated VLAN bridge without changing host interfaces
set -euo pipefail

if [[ $# != 2 ]]; then
    printf '%s\n' 'Usage: namespace.sh BINARY OUTPUT_DIRECTORY' >&2
    exit 1
fi

binary=$(realpath -- "$1")
output=$(realpath -- "$2")
script=$(realpath -- "${BASH_SOURCE[0]}")

# User, network and mount namespaces hold every privileged lab operation
if [[ ${L2SOLVER_LAB_INNER:-} != 1 ]]; then
    exec unshare --user --map-root-user --net --mount --pid --mount-proc --kill-child=KILL --fork \
        env L2SOLVER_LAB_INNER=1 bash "$script" "$binary" "$output"
fi

# The inner marker alone cannot bypass process isolation
if [[ $$ != 1 ]]; then
    printf '%s\n' 'Lab setup requires the private PID namespace' >&2
    exit 1
fi

mount --make-rprivate /
mount -t tmpfs none /run
mkdir -p /run/netns

cleanup() {
    # Only names created inside the isolated namespace are removed
    if [[ -n ${capture_pid:-} ]]; then
        kill "$capture_pid" 2>/dev/null || true
        wait "$capture_pid" 2>/dev/null || true
    fi
    ip netns delete l2-a 2>/dev/null || true
    ip netns delete l2-b 2>/dev/null || true
}
trap cleanup EXIT

wait_bounded_capture() {
    local capture_status=0
    if wait "$capture_pid"; then
        capture_status=0
    else
        capture_status=$?
    fi
    capture_pid=
    if [[ $capture_status != 0 && $capture_status != 3 ]]; then
        printf 'Bounded capture exited unexpectedly with status %s\n' \
            "$capture_status" >&2
        return 1
    fi
}

ip netns add l2-a
ip netns add l2-b
ip link add br0 type bridge vlan_filtering 1
ip link set br0 up

for side in a b; do
    ip link add "bridge-$side" type veth peer name "port-$side"
    ip link set "port-$side" netns "l2-$side"
    ip link set "bridge-$side" master br0
    ip link set "bridge-$side" up
    bridge vlan del dev "bridge-$side" vid 1
    bridge vlan add dev "bridge-$side" vid 10 pvid untagged
    ip -n "l2-$side" link set lo up
    ip -n "l2-$side" link set "port-$side" up
done
ip -n l2-a addr add 192.0.2.1/24 dev port-a
ip -n l2-b addr add 192.0.2.2/24 dev port-b

# A raw wireless assessment must reject an Ethernet capture link
if ip netns exec l2-a "$binary" wifi assess --interface port-a --packets 1 \
    > "$output/namespace-wifi.txt" 2> "$output/namespace-wifi-status.txt"; then
    printf '%s\n' 'Wireless assessment accepted an Ethernet capture link' >&2
    exit 1
fi
rg -q 'wireless assessment requires IEEE 802.11 or radiotap' \
    "$output/namespace-wifi-status.txt"

wait_ready() {
    local status_file=$1
    local pattern=$2
    local description=$3
    for _ in {1..100}; do
        if rg -q "$pattern" "$status_file"; then
            return 0
        fi
        if ! kill -0 "$capture_pid" 2>/dev/null; then
            cat -- "$status_file" >&2
            wait "$capture_pid"
            return 1
        fi
        sleep 0.02
    done
    printf '%s did not become ready\n' "$description" >&2
    return 1
}

# Readiness is observed from the actual capture command before kernel traffic starts
timeout --kill-after=1s 10s ip netns exec l2-a "$binary" listen port-a 2 \
    > "$output/namespace-capture.txt" 2> "$output/namespace-capture-status.txt" &
capture_pid=$!
wait_ready "$output/namespace-capture-status.txt" '^Listening on ' 'Capture'
ip netns exec l2-b ping -c 3 -W 1 192.0.2.1 > "$output/namespace-ping.txt"
wait_bounded_capture
rg -q 'frames=2 malformed=0 invalid=0 unsupported=0 truncated=0' "$output/namespace-capture.txt"

# Exercise the canonical assessment command through the real receive-only backend
timeout --kill-after=1s 10s ip netns exec l2-a "$binary" assess \
    --interface port-a --packets 2 --format json \
    > "$output/namespace-survey.json" 2> "$output/namespace-survey-status.txt" &
capture_pid=$!
wait_ready "$output/namespace-survey-status.txt" '^Surveying ' 'Survey'
ip netns exec l2-b ping -c 3 -W 1 192.0.2.1 > "$output/namespace-survey-ping.txt"
wait_bounded_capture

# Save the same kernel traffic with its Linux source identity and collection status
timeout --kill-after=1s 10s ip netns exec l2-a "$binary" record port-a 2 \
    "$output/namespace-record.pcapng" \
    > "$output/namespace-record.txt" 2> "$output/namespace-record-status.txt" &
capture_pid=$!
wait_ready "$output/namespace-record-status.txt" '^Recording ' 'Recorder'
ip netns exec l2-b ping -c 3 -W 1 192.0.2.1 > "$output/namespace-record-ping.txt"
record_status=0
if wait "$capture_pid"; then
    record_status=0
else
    record_status=$?
fi
capture_pid=
if [[ $record_status != 3 || ! -s "$output/namespace-record.pcapng" ]]; then
    printf 'Recorder did not save the bounded incomplete capture (status %s)\n' \
        "$record_status" >&2
    exit 1
fi
inspect_status=0
if "$binary" inspect "$output/namespace-record.pcapng" \
    > "$output/namespace-record-inspection.txt"; then
    inspect_status=0
else
    inspect_status=$?
fi
[[ $inspect_status == 3 ]]
rg -q 'frames=2 malformed=0 invalid=0 unsupported=0 truncated=0' \
    "$output/namespace-record-inspection.txt"
rg -q 'source_collection .*incomplete_sections=1' \
    "$output/namespace-record-inspection.txt"
json_status=0
if "$binary" json "$output/namespace-record.pcapng" \
    > "$output/namespace-record-replay.jsonl"; then
    json_status=0
else
    json_status=$?
fi
[[ $json_status == 3 ]]
rg -q '"record_type":"source_collection".*"incomplete_sections":1' \
    "$output/namespace-record-replay.jsonl"

# Verify the same link identity is visible through an explicit down/up transition
ip -n l2-a link set port-a down
ip -n l2-a link set port-a up
ip -n l2-a -details link show port-a > "$output/namespace-link.txt"
# Linux bridge BPDUs supply an independent kernel-generated protocol fixture
# Only namespace root maps to the unprivileged caller, so keep that capture identity
timeout --kill-after=1s 10s ip netns exec l2-a tcpdump -Z root -U -i port-a -s 65535 -c 1 \
    -w "$output/linux-stp.pcap" ether dst 01:80:c2:00:00:00 \
    > "$output/namespace-stp-status.txt" 2>&1 &
capture_pid=$!
wait_ready "$output/namespace-stp-status.txt" 'listening on ' 'STP observer'
ip link set br0 type bridge stp_state 1
wait "$capture_pid"
capture_pid=
"$binary" observe "$output/linux-stp.pcap" > "$output/namespace-stp-observation.txt"
printf '%s\n' 'Namespace VLAN and STP capture regression passed'
