"""Inspect a Linux package and record the release work still requiring evidence."""

import argparse
import os
import platform
import subprocess
import sys
import tarfile
from pathlib import Path

from benchmarks.package_release import ARCHIVE_NAME, _command_output, _release_metadata
from benchmarks.qualification.cli import check_packaged_startup, run_packaged_cli
from benchmarks.qualification.elf import inspect_elf
from benchmarks.qualification.package import check_checksum, unpack_package
from benchmarks.qualification.receipt import build_receipt, runner_identity_status
from benchmarks.runner.catalogue import hash_file
from benchmarks.runner.execution import write_json_new

ROOT = Path(__file__).resolve().parents[2]


def _identity():
    metadata = _release_metadata()
    # Hosted image values identify the actual runner rather than its moving label
    return {
        **metadata,
        "rustc_verbose": _command_output(["rustc", "-vV"]),
        "lock_sha256": hash_file(
            ROOT / "Cargo.lock", expected_bytes=(ROOT / "Cargo.lock").stat().st_size
        ),
        "fuzz_lock_sha256": hash_file(
            ROOT / "fuzz/Cargo.lock",
            expected_bytes=(ROOT / "fuzz/Cargo.lock").stat().st_size,
        ),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "runner": {
            "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion"),
            "runner_os": os.environ.get("RUNNER_OS"),
            "runner_arch": os.environ.get("RUNNER_ARCH"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "github_sha": os.environ.get("GITHUB_SHA"),
        },
        "hosted": os.environ.get("GITHUB_ACTIONS") == "true",
    }


def execute(package_directory, output_directory):
    if Path.cwd().resolve() != ROOT:
        raise ValueError("run qualification from the clean repository root")
    package_directory = Path(package_directory).resolve()
    output_directory = Path(output_directory).resolve()
    # A new directory keeps receipts from different attempts separate
    output_directory.mkdir(parents=True, exist_ok=False)
    try:
        identity = _identity()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        checks = {
            "source_identity": {"status": "blocked", "reason": str(error)},
            "package": {"status": "blocked", "reason": "source identity unavailable"},
            "elf": {"status": "blocked", "reason": "package validation did not pass"},
            "packaged_startup": {"status": "blocked", "reason": "package validation did not pass"},
            "packaged_cli": {
                "status": "blocked",
                "reason": "package validation did not pass",
            },
        }
        receipt = build_receipt({}, checks)
        write_json_new(output_directory / "qualification.json", receipt)
        return receipt
    archive = package_directory / ARCHIVE_NAME
    checksum = package_directory / f"{ARCHIVE_NAME}.sha256"
    checks = {
        "source_identity": {"status": "passed"},
        "runner_identity": runner_identity_status(
            identity["runner"], identity["source_commit"], hosted=identity["hosted"]
        ),
    }
    package = None
    try:
        package = unpack_package(
            archive,
            checksum,
            output_directory / "unpacked",
            source_commit=identity["source_commit"],
            source_tree=identity["source_tree"],
            lock_sha256=identity["lock_sha256"],
            rustc_version=identity["rustc_version"],
            cargo_version=identity["cargo_version"],
        )
        checks["package"] = {
            "status": "passed",
            "archive_sha256": package["archive_sha256"],
            "binary_sha256": package["provenance"]["binary"]["sha256"],
            "active_binary_sha256": package["provenance"]["active_binary"]["sha256"],
            "active_helper_sha256": package["provenance"]["active_helper"]["sha256"],
        }
    except FileNotFoundError as error:
        checks["package"] = {"status": "blocked", "reason": str(error)}
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        EOFError,
        tarfile.TarError,
    ) as error:
        checks["package"] = {"status": "failed", "reason": str(error)}

    if package is None:
        # Later checks cannot safely inspect a package that did not validate
        for name in ("elf", "packaged_startup", "packaged_cli"):
            checks[name] = {
                "status": "blocked",
                "reason": "package validation did not pass",
            }
    else:
        inspected = {}
        for key in ("binary", "active_binary", "active_helper"):
            try:
                executable = package[key]
                directory = output_directory / f"elf-{executable.name}"
                directory.mkdir()
                inspected[executable.name] = {
                    "status": "passed", **inspect_elf(executable, directory)
                }
            except FileNotFoundError as error:
                inspected[package[key].name] = {"status": "blocked", "reason": str(error)}
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                inspected[package[key].name] = {"status": "failed", "reason": str(error)}
        statuses = {result["status"] for result in inspected.values()}
        checks["elf"] = {
            "status": "failed" if "failed" in statuses else "blocked" if "blocked" in statuses else "passed",
            "executables": inspected,
        }
        try:
            checks["packaged_startup"] = check_packaged_startup(
                package["binary"], package["active_binary"], package["active_helper"],
                output_directory / "startup",
            )
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            checks["packaged_startup"] = {"status": "failed", "reason": str(error)}
        try:
            checks["packaged_cli"] = run_packaged_cli(
                package["binary"], output_directory / "cli"
            )
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            subprocess.SubprocessError,
        ) as error:
            checks["packaged_cli"] = {"status": "failed", "reason": str(error)}

        # Every result must still refer to the same source and packaged bytes
        try:
            check_checksum(checksum, archive.name, package["archive_sha256"])
            unchanged = (
                hash_file(archive, expected_bytes=package["archive_bytes"])
                == package["archive_sha256"]
                and hash_file(
                    package["binary"],
                    expected_bytes=package["provenance"]["binary"]["bytes"],
                )
                == package["provenance"]["binary"]["sha256"]
                and hash_file(
                    package["active_binary"],
                    expected_bytes=package["provenance"]["active_binary"]["bytes"],
                )
                == package["provenance"]["active_binary"]["sha256"]
                and hash_file(
                    package["active_helper"],
                    expected_bytes=package["provenance"]["active_helper"]["bytes"],
                )
                == package["provenance"]["active_helper"]["sha256"]
                and _identity() == identity
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            unchanged = False
        if not unchanged:
            checks["package"] = {
                "status": "failed",
                "reason": "source or package changed during qualification",
            }

    receipt = build_receipt(identity, checks)
    write_json_new(output_directory / "qualification.json", receipt)
    return receipt


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-directory", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument(
        "--candidate-only",
        action="store_true",
        help="return success for passing candidate checks while external release gates remain blocked",
    )
    options = parser.parse_args(arguments)
    try:
        receipt = execute(options.package_directory, options.output_directory)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"release qualification: {error}", file=sys.stderr)
        return 2
    print(f"Saved candidate receipt: {options.output_directory / 'qualification.json'}")
    if any(row["status"] == "failed" for row in receipt["candidate_checks"].values()):
        return 1
    if options.candidate_only and receipt["candidate_checks_passed"]:
        return 0
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
