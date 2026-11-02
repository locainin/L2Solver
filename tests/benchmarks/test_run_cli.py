"""Command-line paths and defaults are explicit and predictable."""

import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

from benchmarks.run import main, parse_arguments


class RunArgumentTests(unittest.TestCase):
    def test_defaults_select_canonical_benchmark_configuration(self):
        arguments = parse_arguments([
            "--binary", "target/release/l2solver", "--catalogue", "input/catalogue.json",
        ])

        self.assertEqual(arguments.catalogue.as_posix(), "input/catalogue.json")
        self.assertEqual(arguments.results_directory.as_posix(), "benchmarks/results")
        self.assertEqual(arguments.mode, "case")

    def test_missing_catalogue_is_reported_as_a_required_argument(self):
        error_output = StringIO()
        with redirect_stderr(error_output), self.assertRaises(SystemExit) as error:
            parse_arguments(["--binary", "analyzer"])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("--catalogue", error_output.getvalue())

    def test_stream_mode_accepts_explicit_paths(self):
        arguments = parse_arguments([
            "--binary", "target/release/l2solver",
            "--catalogue", "input/catalogue.json",
            "--results-directory", "out/summary",
            "--mode", "stream",
        ])

        self.assertEqual(arguments.catalogue.as_posix(), "input/catalogue.json")
        self.assertEqual(arguments.results_directory.as_posix(), "out/summary")
        self.assertEqual(arguments.mode, "stream")

    def test_index_mode_is_available(self):
        arguments = parse_arguments([
            "--binary", "analyzer", "--catalogue", "catalogue.json", "--mode", "index",
        ])

        self.assertEqual(arguments.mode, "index")

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(SystemExit):
            parse_arguments([
                "--binary", "analyzer", "--catalogue", "catalogue.json", "--mode", "automatic",
            ])

    def test_invalid_catalogue_reports_cli_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_catalogue = Path(directory) / "missing.json"
            error_output = StringIO()

            with redirect_stderr(error_output):
                status = main(["--binary", "analyzer", "--catalogue", str(missing_catalogue)])

        self.assertEqual(status, 2)
        self.assertIn("benchmark:", error_output.getvalue())
        self.assertNotIn("Traceback", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()


def test_filtered_run_records_input_budgets(tmp_path):
    import json

    from support import case_for, program, write_sample

    catalogue, sample, metadata, capture = write_sample(tmp_path, "selected")
    _, excluded, _, _ = write_sample(tmp_path, "excluded")
    (excluded / "capture.pcap").unlink()
    catalogue.write_text(json.dumps({
        "schema_version": 1, "description": "Generated sources",
        "sources": [str((path / "source.json").relative_to(tmp_path)) for path in (sample, excluded)],
    }))
    binary = program(tmp_path, "import pathlib,sys\npathlib.Path(sys.argv[-1]).write_text("
                     + repr(json.dumps(case_for(metadata, capture))) + ")\n")
    results = tmp_path / "results"

    code = main([
        "--binary", str(binary), "--catalogue", str(catalogue),
        "--sample", "selected", "--run-id", "selected", "--results-directory", str(results),
        "--max-capture-bytes", str(len(capture)), "--max-input-bytes", str(len(capture)),
        "--max-metadata-bytes", "4096",
    ])

    assert code == 0
    summary = json.loads((results / "selected.json").read_text())
    assert summary["samples"] == 1
    assert summary["input_limits"] == {
        "max_metadata_bytes": 4096, "max_capture_bytes": len(capture), "max_input_bytes": len(capture),
    }
    assert not (excluded / "runs").exists()
