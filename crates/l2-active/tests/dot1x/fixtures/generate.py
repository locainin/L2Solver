"""Produce independent offline EAPOL frames with Scapy 2.8.0."""

from pathlib import Path

from scapy.all import EAP, EAPOL, Ether, Raw

HERE = Path(__file__).resolve().parent
CLIENT = "02:00:00:00:00:01"
AUTHENTICATOR = "02:00:00:00:00:02"
PAE = "01:80:c2:00:00:03"


def padded(frame):
    """Keep link-layer padding outside the EAPOL length."""
    encoded = bytes(frame)
    return encoded + bytes(max(0, 60 - len(encoded)))


start = Ether(dst=PAE, src=CLIENT, type=0x888E) / EAPOL(version=2, type=1, len=0)
request = (
    Ether(dst=CLIENT, src=AUTHENTICATOR, type=0x888E)
    / EAPOL(version=2, type=0)
    / EAP(code=1, id=41, type=1)
)
group = (
    Ether(dst=PAE, src=AUTHENTICATOR, type=0x888E)
    / EAPOL(version=1, type=0)
    / EAP(code=1, id=0, type=2)
    / Raw(b"notice")
)

for filename, frame in [
    ("start.bin", start),
    ("request.bin", request),
    ("group.bin", group),
]:
    (HERE / filename).write_bytes(padded(frame))
