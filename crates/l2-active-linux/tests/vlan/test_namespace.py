"""Verify how the VLAN witness labels captured packet representations."""

import importlib.util
import socket
import struct
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location("l2_vlan_namespace", Path(__file__).with_name("namespace.py"))
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("VLAN fixture is unavailable")
vlan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vlan)


class Capture:
    def __init__(self, packet, status, tci=37, tpid=0x8100, flags=0):
        data = struct.pack("=IIIHHHH", status, len(packet), len(packet), 0, 0, tci, tpid)
        self.result = (packet, [(vlan.SOL_PACKET, vlan.PACKET_AUXDATA, data)], flags, None)

    def recvmsg(self, _size, _control_size):
        return self.result


class PacketRepresentationTests(unittest.TestCase):
    def test_auxiliary_vlan_tag_is_reconstructed_and_identified(self):
        untagged = bytes.fromhex("0200000000010200000000020806") + bytes(46)
        capture = Capture(untagged, vlan.TP_STATUS_VLAN_VALID | vlan.TP_STATUS_VLAN_TPID_VALID,
                          tpid=0x88A8)
        frame, representation = vlan.packet_with_auxiliary_tag(capture)
        self.assertEqual(frame, vlan.tagged(untagged, "802.1ad", 37))
        self.assertEqual(representation, "auxiliary")

    def test_unmodified_tagged_frame_is_identified_separately(self):
        untagged = bytes.fromhex("0200000000010200000000020806") + bytes(46)
        tagged = vlan.tagged(untagged, "802.1Q", 37)
        frame, representation = vlan.packet_with_auxiliary_tag(Capture(tagged, 0))
        self.assertEqual(frame, tagged)
        self.assertEqual(representation, "unmodified")

    def test_auxiliary_tag_without_tpid_uses_8021q_and_preserves_vid_zero(self):
        untagged = bytes.fromhex("0200000000010200000000020806") + bytes(46)
        frame, representation = vlan.packet_with_auxiliary_tag(
            Capture(untagged, vlan.TP_STATUS_VLAN_VALID, tci=0, tpid=0)
        )
        self.assertEqual(frame, vlan.tagged(untagged, "802.1Q", 0))
        self.assertEqual(representation, "auxiliary")

    def test_truncated_auxiliary_data_is_rejected(self):
        capture = Capture(bytes(60), 0, flags=socket.MSG_CTRUNC)
        with self.assertRaises(RuntimeError):
            vlan.packet_with_auxiliary_tag(capture)

    def test_missing_auxiliary_record_is_rejected(self):
        capture = Capture(bytes(60), 0)
        capture.result = (bytes(60), [], 0, None)
        with self.assertRaises(RuntimeError):
            vlan.packet_with_auxiliary_tag(capture)


if __name__ == "__main__":
    unittest.main()
