use super::Reader;
use std::{error::Error, fs, path::Path};

type TestResult = Result<(), Box<dyn Error>>;

fn group(directory: &Path, current: u64, maximum: &str, high: &str) -> TestResult {
    fs::create_dir_all(directory)?;
    for (name, value) in [
        ("memory.current", current.to_string()),
        ("memory.peak", (current + 20).to_string()),
        ("memory.max", maximum.to_owned()),
        ("memory.high", high.to_owned()),
        (
            "memory.stat",
            "anon 40\nfile 50\nkernel 10\nshmem 3\nfile_dirty 4\nfile_writeback 5\ninactive_file 30\nfuture_field 19\n".to_owned(),
        ),
        (
            "memory.events",
            "low 0\nhigh 2\nmax 3\noom 4\noom_kill 5\nfuture_event 9\n".to_owned(),
        ),
    ] {
        fs::write(directory.join(name), value)?;
    }
    Ok(())
}

fn proc_files(directory: &Path, mount: &Path, group: &str) -> TestResult {
    fs::create_dir_all(directory)?;
    fs::write(
        directory.join("cgroup"),
        format!("5:cpu:/legacy\n0::{group}\n"),
    )?;
    let escaped = mount.to_string_lossy().replace(' ', "\\040");
    fs::write(
        directory.join("mountinfo"),
        format!("36 27 0:34 / {escaped} rw,nosuid - cgroup2 cgroup rw\n"),
    )?;
    fs::write(
        directory.join("status"),
        "Name:\tl2solver\nVmRSS:\t12 kB\nVmHWM:\t17 kB\n",
    )?;
    Ok(())
}

#[test]
fn sample_distinguishes_process_cgroup_and_inherited_memory_limits() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mount = temporary.path().join("cgroup mount");
    let proc = temporary.path().join("proc");
    group(&mount, 900, "max", "max")?;
    group(&mount.join("parent"), 500, "700", "650")?;
    group(&mount.join("parent/job"), 100, "1000", "max")?;
    proc_files(&proc, &mount, "/parent/job")?;

    let sample = Reader::open(&proc)?.sample()?;
    assert_eq!(sample.process_rss_bytes, 12 * 1024);
    assert_eq!(sample.process_peak_rss_bytes, 17 * 1024);
    let cgroup = sample.cgroup.ok_or("missing cgroup observation")?;
    assert_eq!(cgroup.current_bytes, 100);
    assert_eq!(cgroup.peak_bytes, Some(120));
    assert_eq!(cgroup.anonymous_bytes, Some(40));
    assert_eq!(cgroup.file_bytes, Some(50));
    assert_eq!(cgroup.kernel_bytes, Some(10));
    assert_eq!(cgroup.effective_max_bytes, Some(700));
    assert_eq!(cgroup.effective_high_bytes, Some(650));
    assert_eq!(cgroup.max_headroom_bytes, Some(200));
    assert_eq!(cgroup.high_headroom_bytes, Some(150));
    assert_eq!(cgroup.events.high, 2);
    assert_eq!(cgroup.events.max, 3);
    assert_eq!(cgroup.events.oom, 4);
    assert_eq!(cgroup.events.oom_kill, 5);
    Ok(())
}

#[test]
fn missing_unified_hierarchy_still_reports_process_memory() -> TestResult {
    let temporary = tempfile::tempdir()?;
    fs::write(temporary.path().join("cgroup"), "5:cpu:/legacy\n")?;
    fs::write(temporary.path().join("mountinfo"), "")?;
    fs::write(
        temporary.path().join("status"),
        "VmRSS: 0 kB\nVmHWM: 0 kB\n",
    )?;
    let sample = Reader::open(temporary.path())?.sample()?;
    assert_eq!(sample.process_rss_bytes, 0);
    assert!(sample.cgroup.is_none());
    Ok(())
}

#[test]
fn parent_limits_are_rechecked_when_the_operator_changes_them() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mount = temporary.path().join("cgroups");
    let proc = temporary.path().join("proc");
    group(&mount, 100, "max", "max")?;
    group(&mount.join("job"), 100, "1000", "max")?;
    proc_files(&proc, &mount, "/job")?;
    let reader = Reader::open(&proc)?;
    assert_eq!(
        reader
            .sample()?
            .cgroup
            .ok_or("missing cgroup")?
            .effective_max_bytes,
        Some(1000)
    );
    fs::write(mount.join("memory.max"), "80")?;
    let sample = reader.sample()?.cgroup.ok_or("missing cgroup")?;
    assert_eq!(sample.effective_max_bytes, Some(80));
    assert_eq!(sample.max_headroom_bytes, Some(0));
    Ok(())
}

#[test]
fn malformed_or_oversized_kernel_records_are_rejected() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mount = temporary.path().join("cgroups");
    let proc = temporary.path().join("proc");
    group(&mount, 100, "max", "max")?;
    group(&mount.join("job"), 100, "1000", "max")?;
    proc_files(&proc, &mount, "/job")?;
    let reader = Reader::open(&proc)?;
    fs::remove_file(mount.join("job/memory.max"))?;
    assert!(reader.sample().is_err());
    fs::write(mount.join("job/memory.max"), "not-a-limit")?;
    assert!(reader.sample().is_err());
    fs::write(mount.join("job/memory.max"), "1000")?;
    fs::write(
        proc.join("status"),
        "VmRSS: 18446744073709551615 kB\nVmHWM: 17 kB\n",
    )?;
    assert!(reader.sample().is_err());
    fs::write(proc.join("status"), vec![b'0'; 128 * 1024])?;
    assert!(reader.sample().is_err());
    Ok(())
}

#[test]
fn hierarchy_parent_components_cannot_escape_the_cgroup_mount() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mount = temporary.path().join("cgroups");
    let proc = temporary.path().join("proc");
    proc_files(&proc, &mount, "/../outside")?;
    assert!(Reader::open(&proc).is_err());
    Ok(())
}

#[test]
fn a_mount_root_is_removed_before_resolving_the_visible_hierarchy() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mount = temporary.path().join("cgroups");
    let proc = temporary.path().join("proc");
    group(&mount, 100, "700", "max")?;
    group(&mount.join("job"), 90, "max", "max")?;
    proc_files(&proc, &mount, "/container/job")?;
    fs::write(
        proc.join("mountinfo"),
        format!(
            "36 27 0:34 /container {} rw - cgroup2 cgroup rw\n",
            mount.display()
        ),
    )?;
    assert_eq!(
        Reader::open(&proc)?
            .sample()?
            .cgroup
            .ok_or("missing cgroup")?
            .effective_max_bytes,
        Some(700)
    );
    Ok(())
}
