"""Check that the VLAN pin fixture requires its child test to run."""

import importlib.util
import sys
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location("l2_vlan_kernel", Path(__file__).with_name("kernel.py"))
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("VLAN kernel fixture is unavailable")
kernel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kernel)


class PinChildTests(unittest.TestCase):
    def test_rejects_a_successful_process_that_runs_no_child_test(self):
        command = [sys.executable, "-c", "print('test result: ok. 0 passed; 0 failed;')"]
        with self.assertRaisesRegex(RuntimeError, "VLAN pin check failed"):
            kernel.run_pin_child(command, (1, 2), {kernel.ns.SOURCE: 3}, "normal", "l2vlan0")

    def test_accepts_one_successful_child_test(self):
        command = [sys.executable, "-c", "print('test result: ok. 1 passed; 0 failed;')"]
        kernel.run_pin_child(command, (1, 2), {kernel.ns.SOURCE: 3}, "normal", "l2vlan0")

    def test_rejects_a_failed_child_process(self):
        command = [sys.executable, "-c", "import sys; sys.exit(1)"]
        with self.assertRaisesRegex(RuntimeError, "VLAN pin check failed"):
            kernel.run_pin_child(command, (1, 2), {kernel.ns.SOURCE: 3}, "normal", "l2vlan0")


if __name__ == "__main__":
    unittest.main()
