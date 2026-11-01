"""Exercise HSRP kernel filters in the common owned-veth filter harness."""

import subprocess
import sys
from pathlib import Path

import namespace as harness

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parents[2] / "l2-active/tests/first_hop/hsrp/fixtures"
owned = harness.owned


def change(frame, offset, data):
    return harness.mutate(frame, offset, data)


def frame_cases():
    valid = (FIXTURES / "advertisement.bin").read_bytes()
    other = (FIXTURES / "other-group.bin").read_bytes()
    options = (FIXTURES / "max-ip-options.bin").read_bytes()
    bad_ttl = (FIXTURES / "bad-ttl.bin").read_bytes()
    version_two = (FIXTURES / "hsrp-v2.bin").read_bytes()
    malformed_state = change(valid, 44, bytes([3]))
    malformed_ip_checksum = change(valid, 24, bytes([0]))
    malformed_udp_checksum = change(valid, 40, bytes([0]))
    short_fixed = change(change(valid, 16, bytes.fromhex("0023")), 38, bytes.fromhex("000f"))
    group_beyond_ip = change(valid, 16, bytes.fromhex("0022"))
    group_beyond_udp = change(valid, 38, bytes.fromhex("000e"))
    version_beyond_ip = change(valid, 16, bytes.fromhex("001c"))
    version_beyond_udp = change(valid, 38, bytes.fromhex("0008"))
    first_fragment = change(valid, 20, bytes.fromhex("2000"))
    later_fragment = change(valid, 20, bytes.fromhex("0001"))
    common_bad = [
        change(valid, 5, bytes([3])),
        change(valid, 12, bytes.fromhex("86dd")),
        change(valid, 14, bytes([0x65])),
        change(valid, 14, bytes([0x44])),
        change(valid, 23, bytes([6])),
        change(valid, 33, bytes([3])),
        change(valid, 34, bytes.fromhex("07c2")),
        change(valid, 36, bytes.fromhex("07c2")),
        change(valid, 42, bytes([2])),
        version_two,
        version_beyond_ip,
        version_beyond_udp,
        later_fragment,
        valid[:42],
        valid[:12] + bytes.fromhex("81000007") + valid[12:],
    ]
    # Capture one byte of the group, even if the rest of the packet was lost
    captured_group = valid[:49]
    selected_accept = [valid, options, bad_ttl, malformed_state, malformed_ip_checksum, malformed_udp_checksum, short_fixed, captured_group]
    selected_reject = common_bad + [other, group_beyond_ip, group_beyond_udp, first_fragment, valid[:48]]
    group_255_accept = [other]
    group_255_reject = common_bad + [valid, options, bad_ttl]
    wildcard_accept = selected_accept + [other, group_beyond_ip, group_beyond_udp, first_fragment, valid[:48]]
    wildcard_reject = common_bad
    # Direction is independently checked by the common kernel filter prefix
    return [
        (selected_accept, selected_reject, valid),
        (group_255_accept, group_255_reject, other),
        (wildcard_accept, wildcard_reject, valid),
    ]


# Reuse the same namespace, witness, VLAN metadata, and teardown checks
harness.frames = frame_cases

if __name__ == "__main__":
    try:
        if len(sys.argv) >= 6 and sys.argv[1] == "--child":
            owned.child(
                [int(value) for value in sys.argv[2:5]],
                int(sys.argv[5]),
                sys.argv[6:],
                harness.exercise,
                "filters_checked=true",
            )
        elif len(sys.argv) > 2 and sys.argv[1] == "--":
            owned.parent(__file__, sys.argv[2:])
        else:
            raise RuntimeError("usage: hsrp_namespace.py -- COMMAND ARG ...")
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"isolated filter fixture error: {error}", file=sys.stderr)
        sys.exit(1)
