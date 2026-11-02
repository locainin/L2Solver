"""Run the live correlation test in a proved private loopback namespace."""

import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
NAMESPACE_FIXTURE = HERE.parents[2] / "l2-active-linux/tests/fixtures/namespace.py"
SPEC = importlib.util.spec_from_file_location("l2_endpoint_namespace", NAMESPACE_FIXTURE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("namespace verifier is unavailable")
ns = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ns)

NAMES = ("user", "mnt", "net")
PARENT_FDS = "L2_TEST_ENDPOINT_PARENT_FDS"
PARENT_UID = "L2_TEST_ENDPOINT_PARENT_UID"
CHILD_MODE = "L2_TEST_ENDPOINT_NAMESPACE_CHILD"
TEST_NAME = "strace_correlate_io_captured_packets"


def prove_scope(fds, parent_uid):
    if len(fds) != len(NAMES) or len(set(fds)) != len(NAMES):
        raise RuntimeError("parent namespace descriptors are incomplete")
    # The shared verifier closes its inputs, so retain the pinned originals
    parent_fds = {name: os.dup(fd) for name, fd in zip(NAMES, fds, strict=True)}
    net_fd = ns.prove_scope(parent_fds, parent_uid)
    try:
        ns.require_loopback_only()
    finally:
        os.close(net_fd)


def child(fds, parent_uid, test_binary):
    prove_scope(fds, parent_uid)
    # The only interface belongs to the newly created network namespace
    ns.command("ip", "link", "set", "dev", "lo", "up")
    environment = os.environ.copy()
    environment[CHILD_MODE] = "1"
    environment[PARENT_FDS] = ",".join(str(fd) for fd in fds)
    environment[PARENT_UID] = str(parent_uid)
    result = subprocess.run(
        [test_binary, "--exact", TEST_NAME, "--nocapture"],
        pass_fds=fds,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode or "test result: ok. 1 passed; 0 failed;" not in result.stdout:
        raise RuntimeError(f"correlation child failed: {result.stdout} {result.stderr}")
    print("capture_test_passed=true")


def wait_for_owned_process(process, timeout):
    try:
        return process.communicate(timeout=timeout)
    except BaseException:
        # A timeout or interruption must also stop the capture and tracer
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=5)
        raise


def parent(test_binary):
    fds = [ns.open_namespace(name) for name in NAMES]
    try:
        command = [
            "unshare", "--user", "--map-root-user", "--net", "--mount", "--pid",
            "--mount-proc", "--fork", "--kill-child=KILL", sys.executable, __file__, "--child",
            *(str(fd) for fd in fds), str(os.getuid()), test_binary,
        ]
        # One process group keeps timeout cleanup scoped to this disposable fixture
        process = subprocess.Popen(
            command, pass_fds=fds, start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        stdout, stderr = wait_for_owned_process(process, 45)
        if process.returncode:
            raise RuntimeError(f"isolated correlation failed: {stdout} {stderr}")
        print(stdout.strip())
    finally:
        for fd in fds:
            os.close(fd)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--run":
        parent(sys.argv[2])
    elif len(sys.argv) == 7 and sys.argv[1] == "--child":
        child([int(value) for value in sys.argv[2:5]], int(sys.argv[5]), sys.argv[6])
    elif len(sys.argv) == 2 and sys.argv[1] == "--verify":
        fds = [int(value) for value in os.environ[PARENT_FDS].split(",")]
        prove_scope(fds, int(os.environ[PARENT_UID]))
    else:
        raise RuntimeError("invalid namespace fixture arguments")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"private namespace fixture: {error}", file=sys.stderr)
        sys.exit(1)
