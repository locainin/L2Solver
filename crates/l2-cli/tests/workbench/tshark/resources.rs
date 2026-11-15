use super::*;

pub fn test_plan() -> Result<ResourcePlan, Box<dyn std::error::Error>> {
    resolve(
        None,
        InputSize {
            capture_bytes: Some(0),
            keylog_bytes: 0,
        },
        None,
        operator_configuration(None, std::env::var_os)?,
        Duration::from_secs(10),
        None,
        0,
    )
    .map(|(plan, _)| plan)
}

#[test]
fn memory_headroom() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        available_memory("MemTotal: 900 kB\nMemAvailable: 24 kB\n")?,
        24 * 1024
    );
    assert!(available_memory("MemTotal: 900 kB\n").is_err());
    assert!(available_memory("MemAvailable: 24 MB\n").is_err());
    assert!(available_memory("MemAvailable: 18446744073709551615 kB\n").is_err());
    assert!(available_memory("MemAvailable: 1 kB\nMemAvailable: 2 kB\n").is_err());
    Ok(())
}

#[test]
fn finite_requests() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(request("MEMORY", Some("2".into()), 7, 1024)?, 2048);
    assert_eq!(request("MEMORY", None, 7, 1024)?, 7);
    for invalid in ["", "-1", "1.5", "18446744073709551615", "unlimited"] {
        assert!(request("MEMORY", Some(invalid.into()), 7, 1024).is_err());
    }
    Ok(())
}

#[test]
fn memory_job_ceiling() -> Result<(), Box<dyn std::error::Error>> {
    const MIB: u64 = 1024 * 1024;
    assert_eq!(
        memory_request(None, 8 * MIB, Some(2 * MIB), 4096)?.get(),
        2 * MIB
    );
    assert_eq!(
        memory_request(Some(MIB), 8 * MIB, Some(2 * MIB), 4096)?.get(),
        MIB
    );
    assert!(memory_request(Some(3 * MIB), 8 * MIB, Some(2 * MIB), 4096).is_err());
    assert!(memory_request(None, 8 * MIB, Some(0), 4096).is_err());
    Ok(())
}

#[test]
fn operator_settings() -> Result<(), Box<dyn std::error::Error>> {
    let settings = [
        ("L2SOLVER_TSHARK_MEMORY_MIB", "1024"),
        ("L2SOLVER_TSHARK_SWAP_MIB", "0"),
        ("L2SOLVER_TSHARK_TASKS", "42"),
        ("L2SOLVER_TSHARK_TEMPORARY_MIB", "2048"),
        ("L2SOLVER_TSHARK_TMP_MIB", "8"),
        ("L2SOLVER_TSHARK_SHM_MIB", "4"),
        ("L2SOLVER_TSHARK_OBJECT_MIB", "512"),
        ("L2SOLVER_TSHARK_OBJECT_FILES", "16384"),
    ];
    let config = operator_configuration(Some(ObjectExportBudget::DEFAULT), |name| {
        settings
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| (*value).into())
    })?;
    assert_eq!(config.memory_bytes, Some(1024 * 1024 * 1024));
    assert_eq!(config.swap_bytes, Some(0));
    assert_eq!(config.tasks, Some(42));
    assert_eq!(config.temporary_bytes, Some(2048 * 1024 * 1024));
    assert_eq!(config.tmp_bytes, Some(8 * 1024 * 1024));
    assert_eq!(config.shm_bytes, Some(4 * 1024 * 1024));
    let objects = config.objects.ok_or("object request missing")?;
    assert_eq!(objects.budget, ObjectExportBudget::DEFAULT);
    assert_eq!(objects.mode, ObjectLimitMode::Explicit);
    let standalone = operator_configuration(None, |name| {
        assert!(
            !name.contains("OBJECT_"),
            "standalone probe read object settings"
        );
        None
    })?;
    assert_eq!(standalone.objects, None);
    Ok(())
}

#[test]
fn host_task_headroom() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(task_headroom("1000\n", "0.10 0.10 0.10 5/240 17\n")?, 760);
    assert_eq!(task_headroom("100\n", "0.10 0.10 0.10 5/240 17\n")?, 0);
    assert!(task_headroom("1000\n", "0.10 0.10 0.10 5/nope 17\n").is_err());
    assert!(task_headroom("1000\n", "0.10 0.10 0.10 6/5 17\n").is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn inherited_swap_and_task_headroom() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let leaf = root.path().join("leaf");
    let parent = root.path().join("parent");
    std::fs::create_dir(&leaf)?;
    std::fs::create_dir(&parent)?;
    std::fs::write(leaf.join("memory.swap.max"), b"100")?;
    std::fs::write(leaf.join("memory.swap.current"), b"30")?;
    std::fs::write(parent.join("memory.swap.max"), b"60")?;
    std::fs::write(parent.join("memory.swap.current"), b"20")?;
    let hierarchy = [leaf.clone(), parent.clone(), root.path().to_owned()];
    assert_eq!(cgroup_headroom(&hierarchy, "memory.swap")?, Some(40));
    std::fs::write(parent.join("memory.swap.max"), b"max")?;
    assert_eq!(cgroup_headroom(&hierarchy, "memory.swap")?, Some(70));
    std::fs::write(leaf.join("pids.max"), b"50")?;
    std::fs::write(leaf.join("pids.current"), b"48")?;
    std::fs::write(parent.join("pids.max"), b"80")?;
    std::fs::write(parent.join("pids.current"), b"79")?;
    assert_eq!(cgroup_headroom(&hierarchy, "pids")?, Some(1));
    std::fs::write(parent.join("pids.current"), b"81")?;
    assert_eq!(cgroup_headroom(&hierarchy, "pids")?, Some(0));
    std::fs::write(leaf.join("memory.swap.current"), b"bad")?;
    assert!(cgroup_headroom(&hierarchy, "memory.swap").is_err());
    assert_eq!(
        swap_free("MemAvailable: 10 kB\nSwapFree: 24 kB\n")?,
        24 * 1024
    );
    assert!(swap_free("MemAvailable: 10 kB\n").is_err());
    assert!(check_swap_request(41, 60, Some(40)).is_err());
    assert!(check_swap_request(41, 40, None).is_err());
    check_swap_request(40, 60, Some(40))?;
    Ok(())
}

#[test]
fn object_limits() -> Result<(), Box<dyn std::error::Error>> {
    let default = ObjectExportBudget::DEFAULT;
    let automatic = object_request(default, None, None)?;
    assert_eq!(automatic.budget, default);
    assert_eq!(automatic.mode, ObjectLimitMode::Automatic);

    let larger = object_request(default, Some("2048".into()), Some("20000".into()))?;
    assert_eq!(larger.budget.temporary_bytes, 2048 * 1024 * 1024);
    assert_eq!(larger.budget.temporary_files, 20_000);
    assert_eq!(larger.mode, ObjectLimitMode::Explicit);

    let bytes = object_request(default, Some("512".into()), None)?;
    assert_eq!(bytes.budget, default);
    assert_eq!(bytes.mode, ObjectLimitMode::Explicit);
    let files = object_request(default, None, Some("20000".into()))?;
    assert_eq!(files.budget.temporary_bytes, default.temporary_bytes);
    assert_eq!(files.budget.temporary_files, 20_000);
    assert_eq!(files.mode, ObjectLimitMode::Explicit);
    let default_files = object_request(default, None, Some("16384".into()))?;
    assert_eq!(default_files.budget, default);
    assert_eq!(default_files.mode, ObjectLimitMode::Explicit);

    let custom = ObjectExportBudget {
        temporary_bytes: 42,
        temporary_files: 5,
    };
    let request = object_request(custom, None, None)?;
    assert_eq!(request.budget, custom);
    assert_eq!(request.mode, ObjectLimitMode::Explicit);
    Ok(())
}

#[test]
fn invalid_object_limits() {
    for value in [
        "",
        "0",
        "-1",
        "+1",
        " 1",
        "1.5",
        "unlimited",
        "18446744073709551615",
    ] {
        assert!(
            object_request(ObjectExportBudget::DEFAULT, Some(value.into()), None).is_err(),
            "bytes: {value}"
        );
        assert!(
            object_request(ObjectExportBudget::DEFAULT, None, Some(value.into())).is_err(),
            "files: {value}"
        );
    }
    assert!(
        object_request(
            ObjectExportBudget::DEFAULT,
            Some("17592186044416".into()),
            None
        )
        .is_err()
    );
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        assert!(
            object_request(
                ObjectExportBudget::DEFAULT,
                Some(OsString::from_vec(vec![0xff])),
                None
            )
            .is_err()
        );
    }
}

#[test]
fn large_object_admission() -> Result<(), Box<dyn std::error::Error>> {
    const GIB: u64 = 1024 * 1024 * 1024;
    let config = operator_configuration(Some(ObjectExportBudget::DEFAULT), |name| match name {
        "L2SOLVER_TSHARK_OBJECT_MIB" => Some("2048".into()),
        "L2SOLVER_TSHARK_OBJECT_FILES" => Some("20000".into()),
        _ => None,
    })?;
    let capacity = HostCapacity {
        memory_bytes: 16 * GIB,
        workspace_bytes: 32 * GIB,
        tasks: 10_000,
        allocation_granule: NonZeroU64::new(4096).ok_or("zero page")?,
    };
    let input = InputSize {
        capture_bytes: Some(1),
        keylog_bytes: 0,
    };
    let (selected, mode) = limits(capacity, None, config, Duration::from_secs(10), None)?;
    let plan = ResourcePlan::new(capacity, input, selected, None, mode)?;
    assert_eq!(plan.limits().object_bytes.get(), 2 * GIB);
    assert_eq!(plan.limits().object_files.get(), 20_000);

    let constrained = HostCapacity {
        memory_bytes: GIB,
        ..capacity
    };
    let (selected, mode) = limits(constrained, None, config, Duration::from_secs(10), None)?;
    assert!(ResourcePlan::new(constrained, input, selected, None, mode).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn planned_parent_is_workspace_parent() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let parent = root.path().join("parent");
    let moved = root.path().join("moved");
    std::fs::create_dir(&parent)?;
    let (_, held) = resolve(
        Some(&parent),
        InputSize {
            capture_bytes: Some(0),
            keylog_bytes: 0,
        },
        None,
        operator_configuration(None, std::env::var_os)?,
        Duration::from_secs(10),
        None,
        0,
    )?;
    std::fs::rename(&parent, &moved)?;
    std::fs::create_dir(&parent)?;
    let workspace = super::super::secure_files::Workspace::in_parent(held)?;
    assert_eq!(std::fs::read_dir(&moved)?.count(), 1);
    assert_eq!(std::fs::read_dir(&parent)?.count(), 0);
    workspace.close()?;
    Ok(())
}
