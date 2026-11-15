use l2_workbench::job::{
    HostCapacity, InputSize, ObjectLimitMode, ResourceLimits, ResourcePlan, ResourcePlanError,
    workspace_capacity,
};
use std::{num::NonZeroU64, time::Duration};

fn nz(value: u64) -> NonZeroU64 {
    assert_ne!(value, 0);
    NonZeroU64::new(value).unwrap_or(NonZeroU64::MIN)
}

const fn host() -> HostCapacity {
    HostCapacity {
        memory_bytes: 8_000,
        workspace_bytes: 10_000,
        tasks: 32,
        allocation_granule: NonZeroU64::MIN,
    }
}

fn limits() -> ResourceLimits {
    ResourceLimits {
        capture_bytes: nz(5_000),
        temporary_bytes: nz(4_500),
        object_bytes: nz(1_000),
        object_files: nz(10),
        child_memory_bytes: nz(4_000),
        child_swap_bytes: 0,
        child_tasks: nz(16),
        timeout: Duration::from_secs(120),
        tmpfs_bytes: nz(500),
        shm_bytes: nz(500),
    }
}

const fn input() -> InputSize {
    InputSize {
        capture_bytes: Some(2_000),
        keylog_bytes: 500,
    }
}

#[test]
fn workspace_reserve() {
    assert_eq!(workspace_capacity(0), 0);
    assert_eq!(workspace_capacity(1), 0);
    assert_eq!(workspace_capacity(7), 6);
    assert_eq!(workspace_capacity(8), 7);
    assert_eq!(workspace_capacity(9), 7);
    assert_eq!(workspace_capacity(80), 70);
    assert_eq!(workspace_capacity(u64::MAX), 16_140_901_064_495_857_663);
}

#[test]
fn runtime_representation() {
    for timeout in [
        Duration::from_nanos(1),
        Duration::from_secs(u64::MAX / 1_000_000 + 1),
    ] {
        let mut requested = limits();
        requested.timeout = timeout;
        assert_eq!(
            ResourcePlan::new(host(), input(), requested, None, ObjectLimitMode::Explicit),
            Err(ResourcePlanError::InvalidLimit("timeout"))
        );
    }
}

#[test]
fn exact_budgets() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        host().automatic_child_memory().map(NonZeroU64::get),
        Some(4_000)
    );
    assert_eq!(
        host().automatic_child_tasks().map(NonZeroU64::get),
        Some(16)
    );
    let plan = ResourcePlan::new(host(), input(), limits(), None, ObjectLimitMode::Explicit)?;
    assert_eq!(*plan.limits(), limits());
    Ok(())
}

#[test]
fn automatic_object_clamps() -> Result<(), Box<dyn std::error::Error>> {
    let mut requested = limits();
    requested.object_bytes = nz(1_200);
    requested.tmpfs_bytes = nz(250);
    requested.shm_bytes = nz(250);
    let plan = ResourcePlan::new(host(), input(), requested, None, ObjectLimitMode::Automatic)?;
    assert_eq!(plan.limits().object_bytes, nz(1_000));
    assert_eq!(
        ResourcePlan::new(host(), input(), requested, None, ObjectLimitMode::Explicit),
        Err(ResourcePlanError::LimitExceeded {
            resource: "object bytes",
            requested: 1_200,
            maximum: 1_000,
        })
    );

    // Give storage more room so the memory side is the active object bound
    requested.temporary_bytes = nz(5_000);
    requested.tmpfs_bytes = nz(500);
    requested.shm_bytes = nz(500);
    let plan = ResourcePlan::new(host(), input(), requested, None, ObjectLimitMode::Automatic)?;
    assert_eq!(plan.limits().object_bytes, nz(1_000));
    assert!(
        ResourcePlan::new(host(), input(), requested, None, ObjectLimitMode::Explicit).is_err()
    );
    Ok(())
}

#[test]
fn admin_ceilings() -> Result<(), Box<dyn std::error::Error>> {
    let mut requested = limits();
    requested.object_bytes = nz(900);
    let mut ceiling = limits();
    ceiling.object_bytes = nz(800);
    let plan = ResourcePlan::new(
        host(),
        input(),
        requested,
        Some(ceiling),
        ObjectLimitMode::Automatic,
    )?;
    assert_eq!(plan.limits().object_bytes, nz(800));
    assert!(
        ResourcePlan::new(
            host(),
            input(),
            requested,
            Some(ceiling),
            ObjectLimitMode::Explicit
        )
        .is_err()
    );
    ceiling.object_bytes = nz(900);
    assert!(
        ResourcePlan::new(
            host(),
            input(),
            requested,
            Some(ceiling),
            ObjectLimitMode::Explicit
        )
        .is_ok()
    );

    ceiling.child_tasks = nz(15);
    assert!(
        ResourcePlan::new(
            host(),
            input(),
            requested,
            Some(ceiling),
            ObjectLimitMode::Automatic
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn raised_memory_ceiling() {
    let mut requested = limits();
    requested.child_memory_bytes = nz(6_000);
    let ceiling = requested;
    assert!(
        ResourcePlan::new(
            host(),
            input(),
            requested,
            Some(ceiling),
            ObjectLimitMode::Explicit
        )
        .is_ok()
    );
    let mut ceiling = ceiling;
    ceiling.child_memory_bytes = nz(5_999);
    assert!(
        ResourcePlan::new(
            host(),
            input(),
            requested,
            Some(ceiling),
            ObjectLimitMode::Explicit
        )
        .is_err()
    );
}

#[test]
fn no_object_headroom() {
    let mut requested = limits();
    requested.temporary_bytes = nz(2_500);
    assert!(
        ResourcePlan::new(host(), input(), requested, None, ObjectLimitMode::Automatic).is_err()
    );
    requested = limits();
    requested.tmpfs_bytes = nz(1_000);
    requested.shm_bytes = nz(1_000);
    assert!(
        ResourcePlan::new(host(), input(), requested, None, ObjectLimitMode::Automatic).is_err()
    );
}

#[test]
fn staged_object_storage() -> Result<(), Box<dyn std::error::Error>> {
    let mut requested = limits();
    // One object copy fits, but the private and staged copies coexist
    requested.temporary_bytes = nz(4_000);
    assert_eq!(
        ResourcePlan::new(host(), input(), requested, None, ObjectLimitMode::Explicit),
        Err(ResourcePlanError::LimitExceeded {
            resource: "object bytes",
            requested: 1_000,
            maximum: 750,
        })
    );
    let plan = ResourcePlan::new(host(), input(), requested, None, ObjectLimitMode::Automatic)?;
    assert_eq!(plan.limits().object_bytes, nz(750));
    Ok(())
}

#[test]
fn admin_fields() {
    let mut ceilings = Vec::new();
    let mut ceiling = limits();
    ceiling.capture_bytes = nz(4_999);
    ceilings.push(ceiling);
    ceiling = limits();
    ceiling.temporary_bytes = nz(4_499);
    ceilings.push(ceiling);
    ceiling = limits();
    ceiling.object_files = nz(9);
    ceilings.push(ceiling);
    ceiling = limits();
    ceiling.child_memory_bytes = nz(3_999);
    ceilings.push(ceiling);
    ceiling = limits();
    ceiling.child_tasks = nz(15);
    ceilings.push(ceiling);
    ceiling = limits();
    ceiling.timeout = Duration::from_secs(119);
    ceilings.push(ceiling);
    ceiling = limits();
    ceiling.tmpfs_bytes = nz(499);
    ceilings.push(ceiling);
    ceiling = limits();
    ceiling.shm_bytes = nz(499);
    ceilings.push(ceiling);
    for ceiling in ceilings {
        assert!(
            ResourcePlan::new(
                host(),
                input(),
                limits(),
                Some(ceiling),
                ObjectLimitMode::Explicit
            )
            .is_err()
        );
    }

    let mut requested = limits();
    requested.child_swap_bytes = 1;
    assert!(
        ResourcePlan::new(
            host(),
            input(),
            requested,
            Some(limits()),
            ObjectLimitMode::Explicit
        )
        .is_err()
    );
}

#[test]
fn rejects_host_exhaustion() {
    let mut constrained = host();
    constrained.workspace_bytes = 3_999;
    assert!(
        ResourcePlan::new(
            constrained,
            input(),
            limits(),
            None,
            ObjectLimitMode::Explicit
        )
        .is_err()
    );
    constrained = host();
    constrained.memory_bytes = 4_571;
    assert!(
        ResourcePlan::new(
            constrained,
            input(),
            limits(),
            None,
            ObjectLimitMode::Explicit
        )
        .is_err()
    );
    constrained = host();
    constrained.tasks = 15;
    assert!(
        ResourcePlan::new(
            constrained,
            input(),
            limits(),
            None,
            ObjectLimitMode::Explicit
        )
        .is_err()
    );
    assert_eq!(
        HostCapacity {
            memory_bytes: 1,
            workspace_bytes: 1,
            tasks: 1,
            allocation_granule: NonZeroU64::MIN,
        }
        .automatic_child_tasks(),
        None
    );
}

#[test]
fn rejects_snapshot_overflow() {
    let mut too_large = input();
    too_large.capture_bytes = Some(5_001);
    assert!(
        ResourcePlan::new(
            host(),
            too_large,
            limits(),
            None,
            ObjectLimitMode::Automatic
        )
        .is_err()
    );
    too_large.capture_bytes = Some(2_001);
    assert!(
        ResourcePlan::new(host(), too_large, limits(), None, ObjectLimitMode::Explicit).is_err()
    );
    too_large.capture_bytes = Some(1);
    too_large.keylog_bytes = u64::MAX;
    assert!(
        ResourcePlan::new(
            host(),
            too_large,
            limits(),
            None,
            ObjectLimitMode::Automatic
        )
        .is_err()
    );

    // An unknown stream must be admitted against its complete logical cap
    let unknown = InputSize {
        capture_bytes: None,
        keylog_bytes: 0,
    };
    assert!(
        ResourcePlan::new(host(), unknown, limits(), None, ObjectLimitMode::Automatic).is_err()
    );
    let mut requested = limits();
    requested.capture_bytes = nz(1_000);
    assert!(ResourcePlan::new(host(), unknown, requested, None, ObjectLimitMode::Explicit).is_ok());
}

#[test]
fn rejects_unbounded_limits() {
    let updates: [fn(&mut ResourceLimits); 9] = [
        |limit| limit.capture_bytes = nz(u64::MAX),
        |limit| limit.temporary_bytes = nz(u64::MAX),
        |limit| limit.object_bytes = nz(u64::MAX),
        |limit| limit.object_files = nz(u64::MAX),
        |limit| limit.child_memory_bytes = nz(u64::MAX),
        |limit| limit.child_swap_bytes = u64::MAX,
        |limit| limit.child_tasks = nz(u64::MAX),
        |limit| limit.tmpfs_bytes = nz(u64::MAX),
        |limit| limit.shm_bytes = nz(u64::MAX),
    ];
    for update in updates {
        let mut invalid = limits();
        update(&mut invalid);
        assert!(matches!(
            ResourcePlan::new(host(), input(), invalid, None, ObjectLimitMode::Automatic),
            Err(ResourcePlanError::InvalidLimit(_))
        ));
    }
    let mut invalid = limits();
    invalid.timeout = Duration::ZERO;
    assert!(ResourcePlan::new(host(), input(), invalid, None, ObjectLimitMode::Automatic).is_err());
    invalid.timeout = Duration::MAX;
    assert!(ResourcePlan::new(host(), input(), invalid, None, ObjectLimitMode::Automatic).is_err());

    invalid = limits();
    invalid.capture_bytes = nz(l2_pcap::ABSOLUTE_MAX_INPUT_BYTES + 1);
    assert_eq!(
        ResourcePlan::new(host(), input(), invalid, None, ObjectLimitMode::Automatic),
        Err(ResourcePlanError::LimitExceeded {
            resource: "capture bytes",
            requested: u128::from(l2_pcap::ABSOLUTE_MAX_INPUT_BYTES) + 1,
            maximum: u128::from(l2_pcap::ABSOLUTE_MAX_INPUT_BYTES),
        })
    );
}

#[test]
fn limits_json() -> Result<(), Box<dyn std::error::Error>> {
    let value = serde_json::to_value(limits())?;
    let decoded: ResourceLimits = serde_json::from_value(value.clone())?;
    assert_eq!(decoded, limits());
    let mut value = value;
    value
        .as_object_mut()
        .ok_or("limits must be an object")?
        .insert(String::from("unexpected"), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<ResourceLimits>(value).is_err());
    Ok(())
}

#[test]
fn tmpfs_pages() -> Result<(), Box<dyn std::error::Error>> {
    let mut capacity = host();
    capacity.allocation_granule = nz(16);
    let mut requested = limits();
    requested.child_memory_bytes = nz(128);
    requested.tmpfs_bytes = nz(1);
    requested.shm_bytes = nz(1);
    requested.object_bytes = nz(17);

    let plan = ResourcePlan::new(
        capacity,
        input(),
        requested,
        None,
        ObjectLimitMode::Explicit,
    )?;
    assert_eq!(plan.limits().object_bytes, nz(17));
    requested.object_bytes = nz(33);
    let automatic = ResourcePlan::new(
        capacity,
        input(),
        requested,
        None,
        ObjectLimitMode::Automatic,
    )?;
    assert_eq!(automatic.limits().object_bytes, nz(32));
    assert_eq!(
        ResourcePlan::new(
            capacity,
            input(),
            requested,
            None,
            ObjectLimitMode::Explicit
        ),
        Err(ResourcePlanError::LimitExceeded {
            resource: "object bytes",
            requested: 33,
            maximum: 32,
        })
    );
    Ok(())
}

#[test]
fn tmpfs_rounding_overflow() {
    let mut capacity = host();
    capacity.memory_bytes = u64::MAX;
    capacity.allocation_granule = nz(16);
    let mut requested = limits();
    requested.child_memory_bytes = nz(128);
    requested.tmpfs_bytes = nz(u64::MAX - 1);
    assert!(
        ResourcePlan::new(
            capacity,
            input(),
            requested,
            None,
            ObjectLimitMode::Automatic
        )
        .is_err()
    );
}

#[test]
fn logical_object_cap() -> Result<(), Box<dyn std::error::Error>> {
    let mut capacity = host();
    capacity.allocation_granule = nz(16);
    let mut requested = limits();
    requested.child_memory_bytes = nz(128);
    requested.temporary_bytes = nz(2_534);
    requested.tmpfs_bytes = nz(1);
    requested.shm_bytes = nz(1);
    requested.object_bytes = nz(100);
    let plan = ResourcePlan::new(
        capacity,
        input(),
        requested,
        None,
        ObjectLimitMode::Automatic,
    )?;
    assert_eq!(plan.limits().object_bytes, nz(17));
    Ok(())
}
