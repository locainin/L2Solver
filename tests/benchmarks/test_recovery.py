"""Recovery benchmarks retain bounded, independently hashed output receipts."""

import json
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
from support import program, write_sample

import benchmarks.recovery as recovery_module
from benchmarks.recovery import (
    ProgressWatcher,
    build_extract_command,
    parse_arguments,
    parse_cache_stats,
    read_progress_log,
    run_recovery_benchmark,
    validate_export_output,
)
from tests.benchmarks.recovery_support import write_export


def write_recovery_analyzer(root):
    body = textwrap.dedent(
        """
        import json, os, signal, sys, time
        from pathlib import Path

        arguments = sys.argv[1:]
        cache_root = Path(os.environ['XDG_CACHE_HOME']) / 'l2solver'
        state_root = Path(os.environ['XDG_STATE_HOME']) / 'l2solver'
        cache_root.mkdir(parents=True, exist_ok=True)
        state_root.mkdir(parents=True, exist_ok=True)
        if arguments[:2] == ['cache', 'stats']:
            stage = cache_root / 'stage'
            entries = int(stage.is_file())
            checkpoints = int((state_root / 'checkpoint').is_file())
            print(f'Cache entries: {entries}')
            print(f'Cached stage bytes: {stage.stat().st_size if entries else 0}')
            print(f'Job checkpoints: {checkpoints}')
            raise SystemExit(0)

        output = Path(arguments[arguments.index('--output') + 1])
        profile = arguments[arguments.index('--profile') + 1]
        if output.exists():
            event = {
                'created_at_unix_ms': time.time_ns() // 1_000_000,
                'current_phase': None,
                'phases': [{'phase': 'ingestion', 'state': 'pending', 'completed': 0}],
                'counters': {'cache_hits': 1, 'cache_misses': 0},
            }
            print(json.dumps(event), file=sys.stderr, flush=True)
            raise SystemExit(0)

        interrupted_output = output.name == 'resume-output'
        checkpoint = state_root / 'checkpoint'
        stage = cache_root / 'stage'
        index_cache_hit = stage.is_file()
        event = {
            'label': 'recovery',
            'created_at_unix_ms': 123 if interrupted_output else time.time_ns() // 1_000_000,
            'elapsed_ms': 1,
            'current_phase': 'transform_discovery',
            'phases': [
                {
                    'phase': 'ingestion',
                    'state': 'skipped' if index_cache_hit else 'completed',
                    'completed': 0 if index_cache_hit else 1,
                    'total': 1,
                },
                {
                    'phase': 'transform_discovery',
                    'state': 'in_progress',
                    'completed': 1,
                    'total': 5,
                }
            ],
            'counters': {
                'cache_hits': int(index_cache_hit),
                'cache_misses': int(not index_cache_hit),
            },
            'cancel_requested': False,
        }
        print(json.dumps(event), file=sys.stderr, flush=True)

        if interrupted_output and not checkpoint.exists():
            # The index finishes before the search phase and remains usable on resume
            stage.write_text(profile, encoding='utf-8')

            def stop(_signal, _frame):
                checkpoint.parent.mkdir(parents=True, exist_ok=True)
                checkpoint.write_text('saved work', encoding='utf-8')
                raise SystemExit(130)
            signal.signal(signal.SIGINT, stop)
            for _ in range(50):
                time.sleep(0.01)

        stage.write_text(profile, encoding='utf-8')
        output.mkdir()
        artifact = b'verified'
        evidence = b'{"source":"capture"}\\n'
        output.joinpath('artifact.bin').write_bytes(artifact)
        output.joinpath('evidence.jsonl').write_bytes(evidence)
        output.joinpath('summary.txt').write_text('complete\\n', encoding='utf-8')
        manifest = {
            'schema_version': 1,
            'export_status': 'complete',
            'evidence': {'file': 'evidence.jsonl', 'coverage': {'retained_bytes': len(evidence)}},
            'artifacts': [{'file': 'artifact.bin', 'byte_length': len(artifact), 'provenance': []}],
        }
        output.joinpath('manifest.json').write_text(json.dumps(manifest) + '\\n', encoding='utf-8')
        raise SystemExit(0)
        """
    )
    return program(root, body)


def test_extract_command_contains_only_supported_recovery_arguments(tmp_path):
    command = build_extract_command(
        tmp_path / "l2solver",
        tmp_path / "capture.pcap",
        tmp_path / "export",
        profile="deep",
        jobs=2,
        strict_cache=True,
    )

    assert command == [
        str(tmp_path / "l2solver"),
        "extract",
        str(tmp_path / "capture.pcap"),
        "--output",
        str(tmp_path / "export"),
        "--profile",
        "deep",
        "--progress",
        "json",
        "--memory-limit",
        "512MiB",
        "--jobs",
        "2",
        "--strict-cache",
    ]


def test_cache_stats_require_all_counts_and_parse_exact_bytes():
    assert parse_cache_stats(
        "Cache entries: 12\nCached stage bytes: 4096\nJob checkpoints: 3\n"
    ) == {"entries": 12, "entry_bytes": 4096, "checkpoints": 3}

    with pytest.raises(ValueError, match="checkpoint"):
        parse_cache_stats("Cache entries: 1\nCached stage bytes: 2\n")


def test_cache_stats_accept_cli_human_readable_byte_annotation():
    assert parse_cache_stats(
        "Cache entries: 537\n"
        "Cached stage bytes: 1689701637 (1.57 GiB)\n"
        "Job checkpoints: 1\n"
    ) == {"entries": 537, "entry_bytes": 1689701637, "checkpoints": 1}


def test_export_receipt_hashes_manifest_artifacts_and_counts_bytes(tmp_path):
    output = tmp_path / "output"
    write_export(output)

    receipt = validate_export_output(output, exit_code=0)

    assert receipt["output_bytes"] == sum(
        path.stat().st_size for path in output.iterdir()
    )
    assert receipt["evidence_sidecar_bytes"] == len(b'{"source":"capture"}\n')
    assert receipt["recovered_artifact_bytes"] == len(b"verified")
    assert receipt["evidence_bytes"] == len(b"verified") + len(
        b'{"source":"capture"}\n'
    )
    assert receipt["artifacts"] == [
        {
            "file": "artifact.bin",
            "byte_length": len(b"verified"),
            "sha256": "1c34f88707b55e6104c4eb20e71ffa3d33e414b71ef689a15fad0640d0ac58cb",
            "origins": [],
        }
    ]


def test_export_receipt_preserves_exact_coverage_and_omissions(tmp_path):
    output = tmp_path / "output"
    write_export(output)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["full_source_coverage"] = {"omitted_frames": 4}
    manifest["discovery_coverage"] = {
        "recovery": {"omitted_record_input_frames": 0, "record_learning_frames_not_sampled": 1}
    }
    manifest["evidence"]["coverage"].update(
        {"selected_cases": 3, "retained_cases": 3, "omitted_cases": 0}
    )
    manifest["omitted_artifact_references"] = [{"reason": "limit", "count": 1}]
    manifest["incomplete_components"] = [{"component": "search", "reason": "bounded"}]
    manifest_path.write_text(json.dumps(manifest))

    receipt = validate_export_output(output, exit_code=0)

    assert receipt["coverage"] == {
        "full_source": manifest["full_source_coverage"],
        "discovery": manifest["discovery_coverage"],
        "evidence": manifest["evidence"]["coverage"],
        "omitted_artifact_references": manifest["omitted_artifact_references"],
        "incomplete_components": manifest["incomplete_components"],
    }


def test_legacy_export_missing_coverage_is_unknown_not_zero(tmp_path):
    output = tmp_path / "output"
    write_export(output)
    receipt = validate_export_output(output, exit_code=0)

    assert receipt["coverage"]["full_source"] is None
    assert receipt["coverage"]["discovery"] is None
    assert receipt["coverage"]["omitted_artifact_references"] is None


def test_progress_receipt_keeps_charged_peak_and_worker_admission(tmp_path):
    log = tmp_path / "stderr.log"
    first = {
        "created_at_unix_ms": 123, "phases": [], "counters": {},
        "memory_admission": {
            "limit_bytes": 512, "peak_bytes": 120,
            "working_sets": {"peak_active_cases": 2, "admitted_cases": 7},
        },
    }
    second = {
        **first,
        "memory_admission": {
            "limit_bytes": 512, "peak_bytes": 180,
            "working_sets": {"peak_active_cases": 3, "admitted_cases": 9},
        },
    }
    log.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")

    assert read_progress_log(log)["memory_admission"] == {
        "samples": 2,
        "limit_bytes": 512,
        "peak_charged_bytes": 180,
        "peak_active_cases": 3,
        "admitted_cases": 9,
    }


def test_progress_without_admission_snapshot_does_not_claim_zero_usage(tmp_path):
    log = tmp_path / "stderr.log"
    log.write_text(json.dumps({"phases": [], "counters": {}}) + "\n")
    assert read_progress_log(log)["memory_admission"] is None


def test_progress_retains_reported_worker_pool_without_inferring_it(tmp_path):
    log = tmp_path / "stderr.log"
    event = {
        "phases": [{"phase": "expansion", "message": "Analyzing capture with up to 2 recovery worker(s)"}],
        "counters": {},
    }
    log.write_text(json.dumps(event) + "\n")
    assert read_progress_log(log)["recovery_worker_pool_size"] == 2

    event["phases"][0]["message"] = "unrelated progress"
    log.write_text(json.dumps(event) + "\n")
    assert read_progress_log(log)["recovery_worker_pool_size"] is None


def test_progress_rejects_conflicting_reported_worker_pools(tmp_path):
    log = tmp_path / "stderr.log"
    events = [
        {"phases": [{"phase": "expansion", "message": f"Analyzing capture with up to {count} recovery worker(s)"}], "counters": {}}
        for count in (2, 4)
    ]
    log.write_text("".join(json.dumps(event) + "\n" for event in events))
    with pytest.raises(ValueError, match="worker pool"):
        read_progress_log(log)


@pytest.mark.parametrize("bad_peak", [-1, True, "12", None])
def test_progress_rejects_malformed_admission_measurements(tmp_path, bad_peak):
    log = tmp_path / "stderr.log"
    event = {
        "phases": [], "counters": {},
        "memory_admission": {
            "limit_bytes": 512, "peak_bytes": bad_peak,
            "working_sets": {"peak_active_cases": 1, "admitted_cases": 2},
        },
    }
    log.write_text(json.dumps(event) + "\n")
    with pytest.raises(ValueError, match="memory admission"):
        read_progress_log(log)


def test_export_validator_rejects_mismatched_manifest_artifact_size(tmp_path):
    output = tmp_path / "output"
    write_export(output)
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"][0]["byte_length"] += 1
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError, match="byte length"):
        validate_export_output(output, exit_code=0)


def test_progress_watcher_triggers_only_for_active_search_work(tmp_path):
    log = tmp_path / "stderr.log"
    watcher = ProgressWatcher("transform_discovery", minimum_completed=1)
    event = {
        "current_phase": "reconstruction",
        "phases": [],
        "counters": {"cache_hits": 0},
    }
    log.write_text(json.dumps(event) + "\n")

    assert not watcher.should_interrupt({"stderr": log})
    event["current_phase"] = "transform_discovery"
    event["phases"] = [
        {
            "phase": "transform_discovery",
            "state": "in_progress",
            "completed": 1,
        }
    ]
    with log.open("a") as stream:
        stream.write(json.dumps(event) + "\n")

    assert watcher.should_interrupt({"stderr": log})
    assert watcher.trigger_event["current_phase"] == "transform_discovery"


def test_progress_watcher_waits_for_completed_search_work(tmp_path):
    log = tmp_path / "stderr.log"
    watcher = ProgressWatcher("transform_discovery", minimum_completed=1)
    event = {
        "current_phase": "transform_discovery",
        "phases": [
            {
                "phase": "transform_discovery",
                "state": "in_progress",
                "completed": 0,
            }
        ],
        "counters": {"cache_hits": 0},
    }
    log.write_text(json.dumps(event) + "\n")

    assert not watcher.should_interrupt({"stderr": log})
    assert watcher.trigger_event is None


def test_progress_watcher_triggers_after_candidate_work_in_active_search(tmp_path):
    log = tmp_path / "stderr.log"
    watcher = ProgressWatcher(
        "transform_discovery",
        minimum_completed=1,
        minimum_candidates_examined=500,
    )
    event = {
        "current_phase": "reconstruction",
        "phases": [
            {
                "phase": "transform_discovery",
                "state": "in_progress",
                "completed": 0,
            }
        ],
        "counters": {"candidates_examined": 500},
    }
    log.write_text(json.dumps(event) + "\n")

    assert not watcher.should_interrupt({"stderr": log})
    event["current_phase"] = "transform_discovery"
    event["counters"]["candidates_examined"] = 499
    with log.open("a") as stream:
        stream.write(json.dumps(event) + "\n")
    assert not watcher.should_interrupt({"stderr": log})

    event["counters"]["candidates_examined"] = 500
    with log.open("a") as stream:
        stream.write(json.dumps(event) + "\n")
    assert watcher.should_interrupt({"stderr": log})
    assert watcher.trigger_event["counters"]["candidates_examined"] == 500


def test_progress_log_reads_cumulative_cache_hit_counter(tmp_path):
    log = tmp_path / "stderr.log"
    first = {
        "created_at_unix_ms": 123,
        "elapsed_ms": 10,
        "current_phase": None,
        "phases": [{"phase": "ingestion", "state": "in_progress", "completed": 3}],
        "counters": {"cache_hits": 2},
    }
    second = {
        "created_at_unix_ms": 123,
        "elapsed_ms": 20,
        "current_phase": "transform_discovery",
        "phases": [{"phase": "ingestion", "state": "skipped", "completed": 0}],
        "counters": {"cache_hits": 5},
    }
    log.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")

    receipt = read_progress_log(log)

    assert receipt["events"] == 2
    assert receipt["cache_hits"] == 5
    assert receipt["job_created_at_unix_ms"] == 123
    assert receipt["phases_seen"] == ["transform_discovery"]
    assert receipt["index_cache_hit"] is True


def test_progress_log_does_not_mistake_other_cache_hits_for_index_reuse(tmp_path):
    log = tmp_path / "stderr.log"
    event = {
        "elapsed_ms": 20,
        "current_phase": "transform_discovery",
        "phases": [{"phase": "ingestion", "state": "completed", "completed": 1}],
        "counters": {"cache_hits": 1},
    }
    log.write_text(json.dumps(event) + "\n")

    receipt = read_progress_log(log)

    assert receipt["cache_hits"] == 1
    assert receipt["index_cache_hit"] is False


def test_progress_log_rejects_events_from_multiple_jobs(tmp_path):
    log = tmp_path / "stderr.log"
    first = {"created_at_unix_ms": 123, "phases": [], "counters": {}}
    second = {"created_at_unix_ms": 456, "phases": [], "counters": {}}
    log.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")

    with pytest.raises(ValueError, match="multiple job identities"):
        read_progress_log(log)


def test_progress_log_uses_restored_identity_after_pending_start_event(tmp_path):
    log = tmp_path / "stderr.log"
    pending_start = {
        "created_at_unix_ms": 123,
        "elapsed_ms": 0,
        "current_phase": None,
        "phases": [{"phase": "preparation", "state": "pending", "completed": 0}],
        "counters": {"candidates_examined": 0},
    }
    resumed = {
        "created_at_unix_ms": 456,
        "elapsed_ms": 10,
        "current_phase": "transform_discovery",
        "phases": [
            {
                "phase": "transform_discovery",
                "state": "in_progress",
                "completed": 0,
            }
        ],
        "counters": {"candidates_examined": 100},
    }
    log.write_text(json.dumps(pending_start) + "\n" + json.dumps(resumed) + "\n")

    receipt = read_progress_log(log)

    assert receipt["job_created_at_unix_ms"] == 456
    assert receipt["pending_initial_job_created_at_unix_ms"] == 123


def test_progress_log_accepts_multiple_idle_placeholders_with_elapsed_time(tmp_path):
    log = tmp_path / "stderr.log"
    pending = {
        "created_at_unix_ms": 123,
        "elapsed_ms": 2,
        "current_phase": None,
        "phases": [{"phase": "preparation", "state": "pending", "completed": 0}],
        "counters": {"candidates_examined": 0},
    }
    later_pending = {**pending, "elapsed_ms": 17}
    resumed = {
        "created_at_unix_ms": 456,
        "elapsed_ms": 30,
        "current_phase": "transform_discovery",
        "phases": [
            {"phase": "transform_discovery", "state": "in_progress", "completed": 1}
        ],
        "counters": {"candidates_examined": 8},
    }
    log.write_text(
        "".join(json.dumps(event) + "\n" for event in (pending, later_pending, resumed))
    )

    receipt = read_progress_log(log)

    assert receipt["events"] == 3
    assert receipt["job_created_at_unix_ms"] == 456
    assert receipt["pending_initial_job_created_at_unix_ms"] == 123


def test_progress_log_rejects_placeholder_that_started_work_before_restore(tmp_path):
    log = tmp_path / "stderr.log"
    pending = {
        "created_at_unix_ms": 123,
        "elapsed_ms": 0,
        "current_phase": None,
        "phases": [{"phase": "preparation", "state": "pending", "completed": 0}],
        "counters": {"candidates_examined": 0},
    }
    started = {**pending, "elapsed_ms": 3, "counters": {"candidates_examined": 1}}
    resumed = {**pending, "created_at_unix_ms": 456}
    log.write_text(
        "".join(json.dumps(event) + "\n" for event in (pending, started, resumed))
    )

    with pytest.raises(ValueError, match="multiple job identities"):
        read_progress_log(log)


@pytest.mark.parametrize("elapsed", [-1, True, "2", None])
def test_progress_log_rejects_invalid_placeholder_elapsed_time(tmp_path, elapsed):
    log = tmp_path / "stderr.log"
    pending = {
        "created_at_unix_ms": 123,
        "elapsed_ms": elapsed,
        "current_phase": None,
        "phases": [{"phase": "preparation", "state": "pending", "completed": 0}],
        "counters": {"candidates_examined": 0},
    }
    resumed = {**pending, "created_at_unix_ms": 456, "elapsed_ms": 20}
    log.write_text(json.dumps(pending) + "\n" + json.dumps(resumed) + "\n")

    with pytest.raises(ValueError, match="multiple job identities"):
        read_progress_log(log)


def test_recovery_benchmark_runs_cold_warm_deep_and_verified_resume(
    tmp_path, monkeypatch
):
    catalogue, _sample_dir, _metadata, _capture = write_sample(tmp_path)
    from benchmarks.runner.catalogue import load_catalogue

    sample = load_catalogue(catalogue)[0]
    binary = write_recovery_analyzer(tmp_path)
    monkeypatch.chdir(tmp_path)
    result_directory = "results/recovery-one"

    report = run_recovery_benchmark(
        sample,
        binary,
        result_directory,
        run_id="recovery-one",
        catalogue_path=catalogue,
        timeout=10,
    )

    assert report["status"] == "complete"
    assert report["workload"]["catalogue_sha256"]
    cold = report["runs"]["cold"]
    warm = report["runs"]["warm"]
    warm_recompute = report["runs"]["warm_recompute"]
    deep = report["runs"]["deep"]
    interrupted = report["runs"]["interrupted"]
    resumed = report["runs"]["resume"]
    assert cold["output_path"] == warm["output_path"]
    assert cold["output"]["files"] == warm["output"]["files"]
    assert cold["cache_before"]["cache"]["file_count"] == 0
    assert cold["progress"]["index_cache_hit"] is False
    assert warm["progress"]["cache_hits"] == 1
    assert warm["progress"]["index_cache_hit"] is False
    assert warm_recompute["output_path"] != warm["output_path"]
    assert warm_recompute["progress"]["index_cache_hit"] is True
    assert deep["output_path"] != warm_recompute["output_path"]
    assert deep["progress"]["index_cache_hit"] is True
    assert interrupted["status"] == "interrupted"
    assert interrupted["interrupt_event"]["current_phase"] == "transform_discovery"
    assert interrupted["cache_after"]["stats"]["checkpoints"] > 0
    assert (
        interrupted["progress"]["job_created_at_unix_ms"]
        == resumed["progress"]["job_created_at_unix_ms"]
    )
    assert resumed["status"] in {"complete", "partial"}
    assert resumed["progress"]["index_cache_hit"] is True
    assert (tmp_path / result_directory / "recovery.json").is_file()


def test_recovery_benchmark_can_stop_after_same_output_warm_run(tmp_path):
    catalogue, _sample_dir, _metadata, _capture = write_sample(tmp_path)
    from benchmarks.runner.catalogue import load_catalogue

    sample = load_catalogue(catalogue)[0]
    binary = write_recovery_analyzer(tmp_path)
    report = run_recovery_benchmark(
        sample,
        binary,
        tmp_path / "results" / "cold-warm",
        run_id="cold-warm",
        catalogue_path=catalogue,
        scenario_set="cold-warm",
        timeout=10,
    )

    assert report["status"] == "complete"
    assert report["conditions"]["scenario_set"] == "cold-warm"
    assert list(report["runs"]) == ["cold", "warm"]
    assert report["runs"]["warm"]["same_output_identity_as_cold"] is True


def test_recovery_benchmark_scenario_set_defaults_to_full_and_rejects_unknown():
    defaults = parse_arguments([
        "--sample", "sample", "--binary", "l2solver", "--catalogue", "catalogue.json",
    ])
    assert defaults.scenario_set == "full"
    assert defaults.catalogue == Path("catalogue.json")

    with pytest.raises(SystemExit):
        parse_arguments(
            [
                "--sample",
                "sample",
                "--binary",
                "l2solver",
                "--catalogue",
                "catalogue.json",
                "--scenario-set",
                "warm",
            ]
        )


def test_recovery_benchmark_requires_an_explicit_catalogue(capsys):
    with pytest.raises(SystemExit) as error:
        parse_arguments(["--sample", "sample", "--binary", "l2solver"])
    assert error.value.code == 2
    assert "--catalogue" in capsys.readouterr().err


def test_recovery_benchmark_reports_when_search_phase_never_occurs(tmp_path):
    catalogue, _sample_dir, _metadata, _capture = write_sample(tmp_path)
    from benchmarks.runner.catalogue import load_catalogue

    sample = load_catalogue(catalogue)[0]
    binary = write_recovery_analyzer(tmp_path)

    report = run_recovery_benchmark(
        sample,
        binary,
        tmp_path / "results" / "no-interrupt",
        run_id="no-interrupt",
        interrupt_phase="expansion",
        timeout=10,
    )

    assert report["status"] == "interrupt_not_observed"
    assert report["runs"]["interrupted"]["status"] == "not_triggered"
    assert report["runs"]["interrupted"]["metrics"]["interrupt_sent"] is False
    assert "resume" not in report["runs"]


def test_phase_receipt_survives_cache_stats_failure(tmp_path, monkeypatch):
    process_directory = tmp_path / "process"
    process_directory.mkdir()
    stdout = process_directory / "stdout.log"
    stderr = process_directory / "stderr.log"
    stdout.write_text("")
    stderr.write_text("")
    metrics = {"peak_sampled_rss_bytes": 4096, "user_cpu_seconds": 0.25}

    monkeypatch.setattr(
        recovery_module,
        "cache_snapshot",
        lambda *_args: {"stats": {"entries": 0, "entry_bytes": 0, "checkpoints": 0}},
    )
    monkeypatch.setattr(recovery_module, "xdg_environment", lambda *_args: {})
    monkeypatch.setattr(
        recovery_module,
        "build_extract_command",
        lambda *_args, **_kwargs: ["l2solver", "extract"],
    )
    monkeypatch.setattr(
        recovery_module,
        "_process_result",
        lambda command, directory, *_args, **_kwargs: {
            "command": command,
            "exit_code": 3,
            "status": "partial",
            "error": None,
            "elapsed_seconds": 1.5,
            "metrics": metrics,
            "stdout_log": str(stdout),
            "stderr_log": str(stderr),
        },
    )
    monkeypatch.setattr(
        recovery_module,
        "validate_export_output",
        lambda *_args, **_kwargs: {"output_bytes": 7},
    )

    def fail_cache_stats(*_args):
        raise ValueError("cache statistics did not parse")

    monkeypatch.setattr(recovery_module, "_cache_stats", fail_cache_stats)

    with pytest.raises(ValueError, match="cache statistics did not parse"):
        recovery_module._phase_record(
            "cold",
            Path("l2solver"),
            SimpleNamespace(capture=tmp_path / "capture.pcap"),
            tmp_path / "output",
            process_directory,
            tmp_path / "cache",
            tmp_path / "state",
            profile="normal",
            jobs=1,
            strict_cache=False,
            timeout=5,
            max_log_bytes=1024,
            max_output_bytes=1024,
            max_manifest_bytes=1024,
        )

    receipt = json.loads((process_directory / "raw-run.json").read_text())
    assert receipt["record"]["status"] == "partial"
    assert receipt["record"]["elapsed_seconds"] == 1.5
    assert receipt["record"]["metrics"] == metrics
    assert receipt["record"]["output"] == {"output_bytes": 7}
    assert receipt["postprocessing"]["cache_stats"] == "pending"


def test_phase_receipt_survives_progress_log_failure(tmp_path, monkeypatch):
    process_directory = tmp_path / "process"
    process_directory.mkdir()
    stdout = process_directory / "stdout.log"
    stderr = process_directory / "stderr.log"
    stdout.write_text("")
    stderr.write_text("")
    metrics = {"peak_sampled_rss_bytes": 8192, "user_cpu_seconds": 0.5}

    monkeypatch.setattr(
        recovery_module,
        "cache_snapshot",
        lambda *_args: {"stats": {"entries": 0, "entry_bytes": 0, "checkpoints": 0}},
    )
    monkeypatch.setattr(recovery_module, "xdg_environment", lambda *_args: {})
    monkeypatch.setattr(
        recovery_module,
        "build_extract_command",
        lambda *_args, **_kwargs: ["l2solver", "extract"],
    )
    monkeypatch.setattr(
        recovery_module,
        "_process_result",
        lambda command, directory, *_args, **_kwargs: {
            "command": command,
            "exit_code": 3,
            "status": "partial",
            "error": None,
            "elapsed_seconds": 2.5,
            "metrics": metrics,
            "stdout_log": str(stdout),
            "stderr_log": str(stderr),
        },
    )

    def fail_progress_log(*_args):
        raise ValueError("progress log contains multiple job identities")

    monkeypatch.setattr(recovery_module, "read_progress_log", fail_progress_log)

    with pytest.raises(ValueError, match="multiple job identities"):
        recovery_module._phase_record(
            "resume",
            Path("l2solver"),
            SimpleNamespace(capture=tmp_path / "capture.pcap"),
            tmp_path / "output",
            process_directory,
            tmp_path / "cache",
            tmp_path / "state",
            profile="deep",
            jobs=1,
            strict_cache=False,
            timeout=5,
            max_log_bytes=1024,
            max_output_bytes=1024,
            max_manifest_bytes=1024,
        )

    receipt = json.loads((process_directory / "raw-run.json").read_text())
    assert receipt["process"]["metrics"] == metrics
    assert receipt["record"]["status"] == "partial"
    assert receipt["postprocessing"]["progress_log"] == "failed"
