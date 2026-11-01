"""Deliver VRRP candidates only inside a proved disposable veth namespace."""

import importlib.util
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
HARNESS = HERE.parents[2] / "support/receive_only_veth.py"
SPEC = importlib.util.spec_from_file_location("l2_receive_only_veth", HARNESS)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("receive-only veth harness is unavailable")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)

if __name__ == "__main__":
    try:
        fixture.main(
            __file__,
            HERE,
            "VRRP",
            ("v2-auth.bin", "pseudo.bin", "bad-ttl.bin", "other-vrid.bin", "valid.bin"),
            "advertisements_delivered=true no_client_send=true",
        )
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"isolated fixture error: {error}", file=sys.stderr)
        sys.exit(1)
