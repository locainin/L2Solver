"""Keep the candidate checks separate from unfinished release qualification."""

# These trials need separate approved evidence before a release claim
EXTERNAL_SCENARIOS = (
    (
        "cgroup-challenge",
        "Real 512 MiB normal/deep worker matrix and exact challenge oracle",
    ),
    (
        "cgroup-cache-publication-refinement",
        "Capped cache restoration, publication, refinement and insufficient budget",
    ),
    (
        "interruption-and-crash-recovery",
        "Search-phase signals, crash boundaries and resumed evidence equivalence",
    ),
    (
        "filesystem-failures",
        "Real ENOSPC and read-only filesystems preserve published output",
    ),
    ("concurrent-writers", "Independent writers preserve a single unmixed publication"),
    (
        "corrupt-cache-and-algorithm-invalidation",
        "Corrupt checkpoints are rejected and algorithm changes invalidate affected searches",
    ),
    (
        "archive-bomb-and-invalid-dimensions",
        "Expansion and allocation remain bounded on adversarial input",
    ),
    ("older-evidence-compatibility", "Supported older evidence is read or migrated"),
    (
        "evidence-amplification",
        "Challenge provenance, all Case records and physical-size comparison",
    ),
    (
        "heldout-protocols",
        "Frozen family-disjoint held-out and negative-control evaluation",
    ),
    (
        "large-streaming-refinement",
        "Large, encoded, compressed, corrupt and output-budget fixtures",
    ),
    ("fuzzing", "Approved parser and recovery-state fuzz execution"),
    ("mutation-testing", "Approved mutation execution and surviving-mutant review"),
    ("hosted-final-source", "A completed clean hosted run on the final source"),
)

REQUIRED_CANDIDATE_CHECKS = frozenset(
    ("source_identity", "runner_identity", "package", "elf", "packaged_startup", "packaged_cli")
)


def runner_identity_status(runner, commit, *, hosted):
    """Require the actual image and event commit when a hosted run is claimed."""
    if not hosted:
        return {"status": "passed", "scope": "local; no hosted runner claim"}
    fields = (
        "image_os",
        "image_version",
        "runner_os",
        "runner_arch",
        "run_id",
        "run_attempt",
        "github_sha",
    )
    if any(not runner.get(field) for field in fields):
        return {
            "status": "blocked",
            "reason": "hosted runner image or run identity is missing",
        }
    if (
        runner["image_os"] != "ubuntu24"
        or runner["runner_os"] != "Linux"
        or runner["runner_arch"] != "X64"
        or runner["github_sha"] != commit
    ):
        return {
            "status": "failed",
            "reason": "hosted runner or checked-out source identity differs",
        }
    return {"status": "passed", "scope": "hosted runner identity observed"}


def build_receipt(identity, checks):
    """Report only measured checks; external work cannot be supplied as a success flag."""
    return {
        "schema_version": 1,
        "identity": identity,
        "candidate_checks": checks,
        "candidate_checks_passed": REQUIRED_CANDIDATE_CHECKS.issubset(checks)
        and all(row.get("status") == "passed" for row in checks.values()),
        "release_qualified": False,
        "external_scenarios": [
            {"id": name, "status": "blocked", "reason": reason}
            for name, reason in EXTERNAL_SCENARIOS
        ],
    }
