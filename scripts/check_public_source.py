"""Reject local data and executable blobs from the tracked public source tree."""
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


PRIVATE_ROOTS = {
    "docs", "notes", "reports", "review", "investigations", "pcap_samples", "target",
}
CAPTURE_NAME = re.compile(r"\.(?:pcap|pcapng|cap)(?:\..*)?$", re.IGNORECASE)
DATA_HEADERS = (
    b"\x7fELF", b"MZ", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a",
)


def excluded(name):
    path = PurePosixPath(name)
    return (
        path.parts[0] in PRIVATE_ROOTS
        or path.parts[:2] in (("tests", "pcaps"), ("fuzz", "target"),
                              ("fuzz", "corpus"), ("fuzz", "artifacts"),
                              ("benchmarks", "cache"), ("benchmarks", "results"))
        or path.suffix.lower() in (".md", ".rst", ".log", ".pyc")
        or path.name == ".env" or path.name.startswith(".env.")
        or CAPTURE_NAME.search(path.name) is not None
    )


def main():
    root = Path(subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], text=True,
    ).strip())
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0")
    failed = False
    for encoded in paths:
        if not encoded:
            continue
        name = encoded.decode("utf-8", errors="surrogateescape")
        path = root / name
        # Inspect the actual file so a renamed capture or executable is also rejected
        bad = excluded(name) or path.is_symlink()
        if not bad:
            with path.open("rb") as stream:
                bad = stream.read(4).startswith(DATA_HEADERS)
        if bad:
            print(f"excluded public source: {name!r}", file=sys.stderr)
            failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
