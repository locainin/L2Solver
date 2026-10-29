"""Inspect Linux runtime requirements without executing the inspected binary."""

import re
import subprocess
from pathlib import Path


def parse_elf_inspection(header, program, dynamic, versions):
    if not re.search(r"(?m)^\s*Class:\s*ELF64\s*$", header) or not re.search(
        r"(?m)^\s*Machine:\s*Advanced Micro Devices X86-64\s*$", header
    ):
        raise ValueError("candidate must be an ELF64 x86-64 executable")
    if "Dynamic section" not in dynamic and "no dynamic section" not in dynamic:
        raise ValueError("readelf did not describe the dynamic section")
    interpreter = re.findall(r"Requesting program interpreter:\s*([^\]]+)\]", program)
    if len(interpreter) > 1:
        raise ValueError("ELF reports multiple program interpreters")
    # DT_NEEDED lists direct dependencies without loading the executable
    needed = re.findall(r"\(NEEDED\).*?Shared library:\s*\[([^\]]+)\]", dynamic)
    if dynamic.count("(NEEDED)") != len(needed):
        raise ValueError("ELF dependency output could not be parsed")

    # Read only version requirements, never version definitions from the binary
    needs = versions.split("Version needs section", 1)
    requirements = (
        re.findall(r"\bName:\s*(GLIBC_\d+(?:\.\d+)+)\b", needs[1])
        if len(needs) == 2
        else []
    )
    highest = max(
        requirements,
        key=lambda value: tuple(
            int(part) for part in value.removeprefix("GLIBC_").split(".")
        ),
        default=None,
    )
    return {
        "needed": needed,
        "interpreter": interpreter[0].strip() if interpreter else None,
        "glibc_requirement": highest,
        "glibc_versions": sorted(
            set(requirements),
            key=lambda value: tuple(
                int(part) for part in value.removeprefix("GLIBC_").split(".")
            ),
        ),
    }


def inspect_elf(binary, directory):
    """Save raw readelf reports alongside the parsed requirements."""
    reports = {}
    for name, flag in (
        ("header", "-hW"),
        ("program", "-lW"),
        ("dynamic", "-dW"),
        ("versions", "-VW"),
    ):
        result = subprocess.run(
            ["readelf", flag, str(binary)],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        (Path(directory) / f"elf-{name}.txt").write_text(
            result.stdout, encoding="utf-8"
        )
        reports[name] = result.stdout
    return parse_elf_inspection(**reports)
