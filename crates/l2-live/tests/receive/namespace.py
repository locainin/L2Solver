"""Run the deadline test with a proved private loopback and bounded cleanup."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
NAMESPACE_FIXTURE = HERE.parents[2] / "l2-active-linux/tests/fixtures/namespace.py"
SPEC = importlib.util.spec_from_file_location("l2_live_namespace", NAMESPACE_FIXTURE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("namespace verifier is unavailable")
ns = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ns)

NAMES = ("user", "mnt", "net", "pid")
PARENT_FDS = "L2_TEST_LIVE_PARENT_FDS"
PARENT_UID = "L2_TEST_LIVE_PARENT_UID"
CHILD_MODE = "L2_TEST_LIVE_NAMESPACE_CHILD"
TEST_NAME = "expired_deadline_stops_after_loopback_traffic"


def prove_scope(fds, parent_uid):
    if len(fds) != len(NAMES) or len(set(fds)) != len(NAMES):
        raise RuntimeError("parent namespace descriptors are incomplete")
    # The shared verifier closes its inputs, so keep the inherited descriptors
    parent_fds = {name: os.dup(fd) for name, fd in zip(NAMES, fds, strict=True)}
    net_fd = ns.prove_scope(parent_fds, parent_uid)
    try:
        ns.require_loopback_only()
    finally:
        os.close(net_fd)


def child(fds, parent_uid, test_binary, mode):
    prove_scope(fds, parent_uid)
    # Bring up only the loopback proven to belong to the private namespace
    ns.command("ip", "link", "set", "dev", "lo", "up")
    probe_fds = []
    try:
        # Each guard probe changes only the proof presented to the test child
        if mode == "same":
            probe_fds = [ns.open_namespace(name) for name in NAMES]
            child_fds = probe_fds
            parent_uid = os.getuid()
        elif mode == "pid":
            probe_fds = [ns.open_namespace("pid")]
            child_fds = [*fds[:3], *probe_fds]
        elif mode == "missing":
            child_fds = []
        else:
            child_fds = fds
        environment = os.environ.copy()
        environment[CHILD_MODE] = "1"
        if mode == "missing":
            environment.pop(PARENT_FDS, None)
            environment.pop(PARENT_UID, None)
        else:
            environment[PARENT_FDS] = ",".join(str(fd) for fd in child_fds)
            environment[PARENT_UID] = str(parent_uid)
        result = subprocess.run(
            [test_binary, "--exact", TEST_NAME, "--nocapture"],
            pass_fds=child_fds,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        for fd in probe_fds:
            os.close(fd)
    if mode != "run":
        expected = {
            "missing": "missing parent descriptors",
            "same": "user namespace did not change",
            "pid": "pid namespace did not change",
        }[mode]
        if not result.returncode or "unproved private namespace" not in result.stderr or expected not in result.stderr:
            raise RuntimeError(f"invalid namespace proof was not rejected: {result.stdout} {result.stderr}")
        print("namespace_rejected=true")
        return
    if result.returncode or "test result: ok. 1 passed; 0 failed;" not in result.stdout:
        raise RuntimeError(f"deadline child failed: {result.stdout} {result.stderr}")
    print("deadline_test_passed=true")


def parent(test_binary, mode):
    fds = [ns.open_namespace(name) for name in NAMES]
    try:
        command = [
            "unshare", "--user", "--map-root-user", "--net", "--mount", "--pid",
            "--mount-proc", "--fork", "--kill-child=KILL", sys.executable, __file__, "--child",
            *(str(fd) for fd in fds), str(os.getuid()), test_binary, mode,
        ]
        # One process group lets the timeout stop every fixture descendant
        process = subprocess.Popen(
            command, pass_fds=fds, start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        stdout, stderr = ns.wait_for_owned_process(process, 20)
        if process.returncode:
            raise RuntimeError(f"isolated deadline failed: {stdout} {stderr}")
        print(stdout.strip())
    finally:
        for fd in fds:
            os.close(fd)


def main():
    modes = {"--run": "run", "--probe-missing": "missing", "--probe-same": "same", "--probe-pid": "pid"}
    if len(sys.argv) == 3 and sys.argv[1] in modes:
        parent(sys.argv[2], modes[sys.argv[1]])
    elif len(sys.argv) == 9 and sys.argv[1] == "--child" and sys.argv[8] in modes.values():
        child([int(value) for value in sys.argv[2:6]], int(sys.argv[6]), sys.argv[7], sys.argv[8])
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
