"""Generate independent DTP and VTP Ethernet fixtures with Scapy 2.8.0."""

from pathlib import Path

from scapy.all import Dot3, LLC, SNAP, raw
from scapy.contrib.dtp import DTP, DTPDomain, DTPNeighbor, DTPStatus, DTPType
from scapy.contrib.vtp import VTP, VTPVlanInfo

HERE = Path(__file__).resolve().parent
SOURCE = "02:00:00:00:00:02"
DESTINATION = "01:00:0c:cc:cc:cc"
PADDING = b"PADDING-SECRET"


def frame(protocol, payload):
    packet = (
        Dot3(src=SOURCE, dst=DESTINATION)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
        / SNAP(OUI=0x00000C, code=protocol)
        / payload
    )
    # Deliberately keep private padding outside the 802.3 length field
    return raw(packet) + PADDING


fixtures = {
    "dtp.bin": frame(
        0x2004,
        DTP(
            ver=1,
            tlvlist=[
                DTPDomain(domain=b"PRIVATE-DOMAIN\x00"),
                DTPStatus(status=b"\x83"),
                DTPType(dtptype=b"\xa5"),
                DTPNeighbor(neighbor=SOURCE),
            ],
        ),
    ),
    "vtp-summary.bin": frame(
        0x2003,
        VTP(
            ver=2,
            code=1,
            followers=1,
            domname=b"PRIVATE-DOMAIN",
            rev=0x1020304,
            uid="192.0.2.7",
            timestamp=b"240101120000",
            md5=b"DIGEST-SECRET!!!",
        ),
    ),
    "vtp-subset.bin": frame(
        0x2003,
        VTP(
            ver=1,
            code=2,
            seq=1,
            domname=b"PRIVATE-DOMAIN",
            rev=0x1020304,
            vlaninfo=[
                VTPVlanInfo(
                    status=1,
                    type=1,
                    vlanid=37,
                    mtu=1500,
                    dot10index=0x000186c5,
                    vlanname=b"SECRET-VLAN",
                ),
                VTPVlanInfo(
                    status=0,
                    type=1,
                    vlanid=84,
                    mtu=1400,
                    dot10index=0x000186f4,
                    vlanname=b"VOICE",
                ),
            ],
        ),
    ),
    "vtp-request.bin": frame(
        0x2003,
        VTP(ver=2, code=3, domname=b"PRIVATE-DOMAIN", startvalue=37),
    ),
}
for name, content in fixtures.items():
    (HERE / name).write_bytes(content)
