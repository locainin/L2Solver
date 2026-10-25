"""Run a finite owned-loopback network experiment in a fresh directory."""

import argparse
from pathlib import Path

from benchmarks.runner.execution import write_json_new

from .analysis import analyze
from .traffic import capture, specimens


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    arguments = parser.parse_args()
    binary = arguments.binary.resolve(strict=True)
    arguments.directory.mkdir(parents=True, exist_ok=False)
    samples = specimens()
    transport = capture(arguments.directory, samples)
    write_json_new(arguments.directory / "transport.json", transport)
    result = analyze(binary, arguments.directory, samples, transport)
    for sample in result["results"]:
        print(sample["name"] + ": " + sample["result"])


if __name__ == "__main__":
    main()
