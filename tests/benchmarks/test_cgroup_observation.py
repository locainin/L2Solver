"""Cgroup receipts preserve measurements without changing cgroup settings."""

import pytest

from benchmarks import cgroup_enforcement


def write_cgroup(group, *, maximum="max", high="max", current=0, stat="anon 0\nfile 0\nkernel 0\n"):
    group.mkdir(parents=True, exist_ok=True)
    (group / "memory.max").write_text(f"{maximum}\n")
    (group / "memory.high").write_text(f"{high}\n")
    (group / "memory.current").write_text(f"{current}\n")
    (group / "memory.stat").write_text(stat)


def test_hierarchy_records_inherited_limits_and_unlimited_values(tmp_path):
    root = tmp_path / "cgroup"
    parent = root / "parent"
    leaf = parent / "workload"
    write_cgroup(parent, maximum="400", high="300")
    write_cgroup(leaf, maximum="512", high="max")

    receipt = cgroup_enforcement.hierarchy_limits(leaf, root)

    assert receipt["limits_complete"] is True
    assert receipt["effective_visible_max_bytes"] == 400
    assert receipt["effective_visible_high_bytes"] == 300
    assert receipt["limits"] == [
        {"path": "/parent/workload", "max": 512, "high": "max"},
        {"path": "/parent", "max": 400, "high": 300},
        {"path": "/", "max": None, "high": None},
    ]


def test_unavailable_ancestor_is_not_treated_as_unlimited(tmp_path):
    root = tmp_path / "cgroup"
    parent = root / "parent"
    leaf = parent / "workload"
    write_cgroup(leaf, maximum="512")

    receipt = cgroup_enforcement.hierarchy_limits(leaf, root)

    assert receipt["limits_complete"] is False
    assert receipt["effective_visible_max_bytes"] == 512
    assert receipt["limits"][1] == {"path": "/parent", "max": None, "high": None}


def test_cpu_hierarchy_records_the_strictest_visible_quota(tmp_path):
    root = tmp_path / "cgroup"
    parent = root / "parent"
    leaf = parent / "workload"
    leaf.mkdir(parents=True)
    (parent / "cpu.max").write_text("150000 100000\n")
    (leaf / "cpu.max").write_text("30000 100000\n")

    receipt = cgroup_enforcement.cpu_hierarchy_limits(leaf, root)

    assert receipt["limits_complete"] is True
    assert receipt["effective_visible_quota"] == {"quota_us": 30000, "period_us": 100000}
    assert receipt["limits"] == [
        {"path": "/parent/workload", "quota_us": 30000, "period_us": 100000},
        {"path": "/parent", "quota_us": 150000, "period_us": 100000},
        {"path": "/", "quota_us": None, "period_us": None},
    ]


def test_missing_cpu_limit_is_unknown_even_when_parent_has_a_quota(tmp_path):
    root = tmp_path / "cgroup"
    parent = root / "parent"
    leaf = parent / "workload"
    leaf.mkdir(parents=True)
    (parent / "cpu.max").write_text("200000 100000\n")

    receipt = cgroup_enforcement.cpu_hierarchy_limits(leaf, root)

    assert receipt["limits_complete"] is False
    assert receipt["effective_visible_quota"] == {"quota_us": 200000, "period_us": 100000}
    assert receipt["limits"][0]["quota_us"] is None


@pytest.mark.parametrize("value", ["bad 100000", "100000 0", "0 100000", "1", "1 -1"])
def test_invalid_cpu_limit_is_rejected(tmp_path, value):
    root = tmp_path / "cgroup"
    leaf = root / "workload"
    leaf.mkdir(parents=True)
    (leaf / "cpu.max").write_text(value)
    with pytest.raises(ValueError):
        cgroup_enforcement.cpu_hierarchy_limits(leaf, root)


def test_hierarchy_rejects_a_leaf_outside_its_root(tmp_path):
    (tmp_path / "root").mkdir()
    (tmp_path / "outside").mkdir()
    with pytest.raises(ValueError):
        cgroup_enforcement.hierarchy_limits(tmp_path / "outside", tmp_path / "root")


def test_cgroup_samples_keep_stat_at_the_largest_observed_current(tmp_path, monkeypatch):
    group = tmp_path / "workload"
    write_cgroup(group, current=120, stat="anon 70\nfile 40\nkernel 10\n")
    clock = [1.0]
    monkeypatch.setattr(cgroup_enforcement.time, "monotonic", lambda: clock[0])
    observer = cgroup_enforcement.CgroupSamples(group)
    observer.sample()
    (group / "memory.current").write_text("80\n")
    (group / "memory.stat").write_text("anon 30\nfile 40\nkernel 10\n")
    observer.sample()
    clock[0] += 0.05
    observer.sample()

    assert observer.result() == {
        "samples": 2,
        "peak_current_bytes": 120,
        "memory_stat_at_peak": {"anon": 70, "file": 40, "kernel": 10},
    }


def test_event_deltas_preserve_all_counts_and_reject_missing_or_reset_fields():
    before = {"high": 1, "max": 2, "oom": 3, "oom_kill": 4, "oom_group_kill": 5}
    after = {"high": 3, "max": 7, "oom": 3, "oom_kill": 4, "oom_group_kill": 6}
    assert cgroup_enforcement.event_deltas(before, after) == {
        "high": 2, "max": 5, "oom": 0, "oom_kill": 0, "oom_group_kill": 1
    }
    with pytest.raises(ValueError, match="events"):
        cgroup_enforcement.event_deltas(before, {**after, "max": 0})
    with pytest.raises(ValueError, match="events"):
        cgroup_enforcement.event_deltas(before, {key: value for key, value in after.items() if key != "high"})


@pytest.mark.parametrize("content", ["anon 1\nanon 2\n", "anon -1\n", "anon nope\n"])
def test_memory_stat_rejects_invalid_counts(tmp_path, content):
    path = tmp_path / "memory.stat"
    path.write_text(content)
    with pytest.raises(ValueError):
        cgroup_enforcement.read_counts(path)
