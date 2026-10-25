"""Generate harmless payloads and capture their actual socket transfers."""

import base64
import gzip
import hashlib
import json
import selectors
import socket
import subprocess
import time
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import dataclass


@dataclass(frozen=True)
class Specimen:
    name: str
    wire: bytes
    plan: dict
    expected: bytes | None
    transport: str = "udp"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def specimens():
    # A clear message supplies structural expectations, while its full hash stays withheld
    plain = json.dumps({"schema": "network-lab-v1", "sequence": 42,
                        "measurements": list(range(256)), "message": "owned loopback evidence"},
                       separators=(",", ":")).encode()
    def plan(families, depth=1):
        checks = [{"kind": "prefix", "bytes": list(b'{"schema":')}, {"kind": "json"}]
        return {"families": deepcopy(families), "constraints": checks,
                "max_depth": depth, "max_candidates": 1024}

    def single(kind):
        return plan([{"kind": kind}])

    def layered_plan():
        return plan([{"kind": kind} for kind in ["reverse", "base64", "gzip"]], 3)

    compressed = gzip.compress(plain, mtime=0)
    layered = base64.b64encode(compressed)[::-1]
    key = bytes([23, 169, 92])
    xor = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(plain))
    known = {"kind": "known_plaintext_xor", "offset": 5,
             "bytes": list(plain[5:53]), "key_lengths": [2, 3, 4, 5, 6]}
    wrong_holdout = bytearray(xor)
    wrong_holdout[12] ^= 1
    damaged = bytearray(compressed)
    damaged[-8] ^= 1  # Corrupt the CRC, retaining a plausible gzip header
    alternate = json.dumps({"schema": "network-lab-v1", "sequence": 999,
                            "message": "valid structure is not independent validation"},
                           separators=(",", ":")).encode()
    return [
        Specimen("plain", plain, single("reverse"), plain),
        Specimen("xor-single", bytes(byte ^ 0xA7 for byte in plain), single("single_byte_xor"), plain),
        Specimen("xor-repeat", xor, plan([known]), plain),
        Specimen("byte-add", bytes((byte + 73) % 256 for byte in plain), single("byte_add"), plain),
        Specimen("rotate-bits", bytes(((byte << 3) | (byte >> 5)) & 255 for byte in plain),
                 single("rotate_bits"), plain),
        Specimen("layered", layered, layered_plan(), plain),
        Specimen("tcp-layered", layered, layered_plan(), plain, "tcp"),
        Specimen("random-control", hashlib.shake_256(b"harmless lab control").digest(len(plain)),
                 single("single_byte_xor"), None),
        Specimen("valid-json-control", alternate, single("reverse"), None),
        Specimen("damaged-gzip", base64.b64encode(damaged)[::-1], layered_plan(), None),
        Specimen("truncated-layer", base64.b64encode(compressed[:-6])[::-1], layered_plan(), None),
        Specimen("xor-holdout-control", bytes(wrong_holdout), plan([known]), None),
    ]


def wait_ready(process, deadline):
    """Wait for the output file announcement before probing actual packet capture."""
    output = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stderr, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            for key, _ in selector.select(timeout=0.1):
                chunk = key.fileobj.read1(4096)
                output.extend(chunk)
                if b"File:" in output:
                    return bytes(output)
            if process.poll() is not None:
                break
    raise RuntimeError("dumpcap did not become ready: " + output.decode(errors="replace"))


def probe_capture(process, server, deadline):
    """A banner precedes activation, so require a reported captured probe packet."""
    output = bytearray()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, selectors.DefaultSelector() as selector:
        client.bind(("127.0.0.1", 0))
        client.settimeout(1)
        selector.register(process.stderr, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            client.sendto(b"L2Solver capture readiness", server.getsockname())
            server.recvfrom(65535)
            for key, _ in selector.select(timeout=0.05):
                output.extend(key.fileobj.read1(4096))
                if b"Packets:" in output:
                    return bytes(output)
            if process.poll() is not None:
                break
    raise RuntimeError("dumpcap never reported a captured readiness probe")


def capture(directory, samples):
    """Keep all traffic on dynamically bound IPv4 loopback sockets with finite deadlines."""
    with ExitStack() as stack:
        servers = []
        for sample in samples:
            kind = socket.SOCK_STREAM if sample.transport == "tcp" else socket.SOCK_DGRAM
            server = stack.enter_context(socket.socket(socket.AF_INET, kind))
            server.settimeout(3)
            server.bind(("127.0.0.1", 0))
            if sample.transport == "tcp":
                server.listen(1)
            servers.append(server)
        probe = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        probe.bind(("127.0.0.1", 0))
        probe.settimeout(1)
        readiness_port = probe.getsockname()[1]
        ports = [server.getsockname()[1] for server in [*servers, probe]]
        expression = "host 127.0.0.1 and (" + " or ".join(f"port {port}" for port in ports) + ")"
        command = ["dumpcap", "-i", "lo", "-p", "-f", expression, "-s", "65535",
                   "-a", "duration:12", "-a", "filesize:1024", "-w", str(directory / "capture.pcapng")]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        initial = b""
        tail = b""
        received = []
        try:
            initial = wait_ready(process, time.monotonic() + 5)
            initial += probe_capture(process, probe, time.monotonic() + 5)
            for sample, server in zip(samples, servers):
                address = server.getsockname()
                kind = socket.SOCK_STREAM if sample.transport == "tcp" else socket.SOCK_DGRAM
                with socket.socket(socket.AF_INET, kind) as client:
                    client.settimeout(3)
                    client.bind(("127.0.0.1", 0))
                    if sample.transport == "udp":
                        sent = client.sendto(sample.wire, address)
                        observed, peer = server.recvfrom(65535)
                    else:
                        client.connect(address)
                        connection, peer = server.accept()
                        with connection:
                            connection.settimeout(3)
                            # Small writes exercise reconstruction across real TCP segments
                            for start in range(0, len(sample.wire), 37):
                                client.sendall(sample.wire[start:start + 37])
                                time.sleep(0.005)
                            client.shutdown(socket.SHUT_WR)
                            chunks = []
                            while chunk := connection.recv(65535):
                                chunks.append(chunk)
                            observed = b"".join(chunks)
                            sent = len(sample.wire)
                    if sent != len(sample.wire) or observed != sample.wire:
                        raise ValueError("socket transfer did not preserve the supplied bytes")
                    (directory / (sample.name + ".received.bin")).write_bytes(observed)
                    received.append({"name": sample.name, "transport": sample.transport,
                                     "source": list(peer), "destination": list(address),
                                     "received_bytes": len(observed), "received_sha256": digest(observed)})
            # Dumpcap's normal finite stop flushes records and capture-loss counters
            _, tail = process.communicate(timeout=15)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    _, tail = process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    _, tail = process.communicate(timeout=3)
            (directory / "dumpcap.log").write_bytes(initial + tail)
            process.stderr.close()
        if process.returncode != 0:
            raise RuntimeError("dumpcap failed; inspect dumpcap.log")
    return {"command": command, "readiness_port": readiness_port, "receivers": received}
