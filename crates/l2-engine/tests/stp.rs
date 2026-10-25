use l2_capture::InterfaceId;
use l2_codecs::{BridgeId, decode_stp};
use l2_engine::{MonoTime, StpObserver, StpUpdate};
use std::{error::Error, time::Duration};

const fn interface(section: u32, index: u32) -> InterfaceId {
    InterfaceId { section, index }
}

fn configuration_bpdu(root: BridgeId, bridge: BridgeId) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, 0];
    bytes.push(0);
    bytes.extend_from_slice(&root.wire_priority_and_extension().to_be_bytes());
    bytes.extend_from_slice(&root.mac);
    bytes.extend_from_slice(&4_u32.to_be_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&bridge.wire_priority_and_extension().to_be_bytes());
    bytes.extend_from_slice(&bridge.mac);
    bytes.extend_from_slice(&0x8001_u16.to_be_bytes());
    bytes.extend_from_slice(&0x0100_u16.to_be_bytes());
    bytes.extend_from_slice(&0x1400_u16.to_be_bytes());
    bytes.extend_from_slice(&0x0200_u16.to_be_bytes());
    bytes.extend_from_slice(&0x0f00_u16.to_be_bytes());
    bytes
}

#[test]
fn reports_root_changes_monotonic_age() -> Result<(), Box<dyn Error>> {
    let observed_on = interface(0, 3);
    let first_root = BridgeId::from_wire(0x8001, [0, 1, 2, 3, 4, 5]);
    let second_root = BridgeId::from_wire(0x8001, [0, 1, 2, 3, 4, 6]);
    let bridge = BridgeId::from_wire(0x9002, [0x80, 0, 0, 0, 0, 1]);
    let first_bytes = configuration_bpdu(first_root, bridge);
    let second_bytes = configuration_bpdu(second_root, bridge);
    let first_frame = decode_stp(&first_bytes)?;
    let second_frame = decode_stp(&second_bytes)?;
    let mut observer = StpObserver::new(Duration::from_secs(5))?;

    let first = observer.observe(MonoTime::from_nanos(10), observed_on, &first_frame)?;
    assert_eq!(
        first,
        StpUpdate::RootChanged {
            previous: None,
            current: Some(first_root)
        }
    );
    assert_eq!(observer.current_root(), Some(first_root));

    let unchanged = observer.observe(MonoTime::from_nanos(11), observed_on, &first_frame)?;
    assert_eq!(unchanged, StpUpdate::Unchanged);

    let same_time = observer.observe(MonoTime::from_nanos(11), observed_on, &first_frame)?;
    assert_eq!(same_time, StpUpdate::Unchanged);

    let changed = observer.observe(MonoTime::from_nanos(12), observed_on, &second_frame)?;
    assert_eq!(
        changed,
        StpUpdate::RootChanged {
            previous: Some(first_root),
            current: Some(second_root),
        }
    );
    assert_eq!(
        observer.expire(MonoTime::from_nanos(5_000_000_012))?,
        StpUpdate::RootAged { root: second_root }
    );
    assert_eq!(observer.current_root(), None);
    assert_eq!(observer.root_changes(), 3);
    Ok(())
}

#[test]
fn time_regressions_without_state() -> Result<(), Box<dyn Error>> {
    let mut observer = StpObserver::new(Duration::from_secs(5))?;
    let root = BridgeId::from_wire(0x8000, [1; 6]);
    let bridge = BridgeId::from_wire(0x9000, [2; 6]);
    let bytes = configuration_bpdu(root, bridge);
    let bpdu = decode_stp(&bytes)?;
    observer.observe(MonoTime::from_nanos(20), interface(0, 1), &bpdu)?;
    assert!(
        observer
            .observe(MonoTime::from_nanos(19), interface(0, 1), &bpdu)
            .is_err()
    );
    assert_eq!(observer.current_root(), Some(root));
    Ok(())
}

#[test]
fn reports_interface_removal_separately_age() -> Result<(), Box<dyn Error>> {
    let interface = interface(0, 4);
    let root = BridgeId::from_wire(0x8000, [1; 6]);
    let bridge = BridgeId::from_wire(0x9000, [2; 6]);
    let bytes = configuration_bpdu(root, bridge);
    let bpdu = decode_stp(&bytes)?;
    let mut observer = StpObserver::new(Duration::from_secs(5))?;
    observer.observe(MonoTime::from_nanos(1), interface, &bpdu)?;
    assert_eq!(
        observer.interface_down(MonoTime::from_nanos(2), interface)?,
        StpUpdate::InterfaceRemoved {
            previous: Some(root),
            current: None,
        }
    );
    assert_eq!(observer.interface_root(interface), None);
    Ok(())
}

#[test]
fn bounds_new_interfaces_without_state() -> Result<(), Box<dyn Error>> {
    let root = BridgeId::from_wire(0x8000, [1; 6]);
    let bridge = BridgeId::from_wire(0x9000, [2; 6]);
    let bytes = configuration_bpdu(root, bridge);
    let bpdu = decode_stp(&bytes)?;
    let mut observer = StpObserver::with_capacity(Duration::from_secs(5), 1)?;
    observer.observe(MonoTime::from_nanos(1), interface(0, 1), &bpdu)?;
    assert!(
        observer
            .observe(MonoTime::from_nanos(2), interface(0, 2), &bpdu)
            .is_err()
    );
    assert_eq!(observer.sample_count(), 1);
    assert_eq!(observer.interface_root(interface(0, 1)), Some(root));
    Ok(())
}

#[test]
fn rejects_invalid_observer_limits() {
    assert!(matches!(
        StpObserver::new(Duration::ZERO),
        Err(l2_engine::StpObserverError::InvalidAge)
    ));
    assert!(matches!(
        StpObserver::with_capacity(Duration::from_nanos(1), 0),
        Err(l2_engine::StpObserverError::InvalidSampleCapacity { capacity: 0, .. })
    ));
    assert!(matches!(
        StpObserver::with_capacity(
            Duration::from_nanos(1),
            l2_engine::ABSOLUTE_MAX_STP_SAMPLES + 1
        ),
        Err(l2_engine::StpObserverError::InvalidSampleCapacity { .. })
    ));
}

#[test]
fn ages_root_after_topology_change() -> Result<(), Box<dyn Error>> {
    let interface = interface(0, 5);
    let root = BridgeId::from_wire(0x8000, [3; 6]);
    let bridge = BridgeId::from_wire(0x9000, [4; 6]);
    let configuration = configuration_bpdu(root, bridge);
    let tcn = [0, 0, 0, 0x80];
    let configuration = decode_stp(&configuration)?;
    let tcn = decode_stp(&tcn)?;
    let mut observer = StpObserver::new(Duration::from_nanos(5))?;

    assert_eq!(
        observer.observe(MonoTime::from_nanos(1), interface, &configuration)?,
        StpUpdate::RootChanged {
            previous: None,
            current: Some(root),
        }
    );
    assert_eq!(
        observer.observe(MonoTime::from_nanos(2), interface, &tcn)?,
        StpUpdate::Unchanged
    );
    assert_eq!(observer.current_root(), Some(root));
    assert_eq!(observer.sample_count(), 1);
    Ok(())
}

#[test]
fn tracks_latest_root_interface_roots() -> Result<(), Box<dyn Error>> {
    let first_interface = interface(0, 1);
    let second_interface = interface(0, 2);
    let first_root = BridgeId::from_wire(0x8000, [1; 6]);
    let second_root = BridgeId::from_wire(0x8000, [2; 6]);
    let bridge = BridgeId::from_wire(0x9000, [3; 6]);
    let first_bytes = configuration_bpdu(first_root, bridge);
    let second_bytes = configuration_bpdu(second_root, bridge);
    let first = decode_stp(&first_bytes)?;
    let second = decode_stp(&second_bytes)?;
    let mut observer = StpObserver::new(Duration::from_secs(5))?;

    observer.observe(MonoTime::from_nanos(1), first_interface, &first)?;
    assert_eq!(
        observer.observe(MonoTime::from_nanos(2), second_interface, &second)?,
        StpUpdate::RootChanged {
            previous: Some(first_root),
            current: Some(second_root),
        }
    );
    assert_eq!(observer.current_root(), Some(second_root));
    assert_eq!(observer.interface_root(first_interface), Some(first_root));
    assert_eq!(observer.interface_root(second_interface), Some(second_root));
    assert_eq!(observer.sample_count(), 2);
    assert_eq!(observer.root_changes(), 2);
    Ok(())
}

#[test]
fn enforces_sample_capacity_at_expiry() -> Result<(), Box<dyn Error>> {
    let root = BridgeId::from_wire(0x8000, [5; 6]);
    let bridge = BridgeId::from_wire(0x9000, [6; 6]);
    let bytes = configuration_bpdu(root, bridge);
    let bpdu = decode_stp(&bytes)?;
    let mut observer = StpObserver::with_capacity(Duration::from_nanos(5), 1)?;
    observer.observe(MonoTime::from_nanos(1), interface(0, 1), &bpdu)?;

    // Four nanoseconds old is still live, so a second interface is rejected
    assert!(
        observer
            .observe(MonoTime::from_nanos(5), interface(0, 2), &bpdu)
            .is_err()
    );
    // Reaching the five-nanosecond age expires the first sample
    assert!(
        observer
            .observe(MonoTime::from_nanos(6), interface(0, 2), &bpdu)
            .is_ok()
    );
    assert_eq!(observer.sample_count(), 1);
    assert_eq!(observer.interface_root(interface(0, 1)), None);
    Ok(())
}

#[test]
fn ages_by_elapsed_capture_time() -> Result<(), Box<dyn Error>> {
    let interface = interface(0, 6);
    let root = BridgeId::from_wire(0x8000, [7; 6]);
    let bridge = BridgeId::from_wire(0x9000, [8; 6]);
    let bytes = configuration_bpdu(root, bridge);
    let bpdu = decode_stp(&bytes)?;
    let mut observer = StpObserver::new(Duration::from_nanos(5))?;
    observer.observe(MonoTime::from_nanos(3), interface, &bpdu)?;

    assert_eq!(
        observer.expire(MonoTime::from_nanos(4))?,
        StpUpdate::Unchanged
    );
    assert_eq!(observer.current_root(), Some(root));
    assert_eq!(observer.sample_count(), 1);
    Ok(())
}

#[test]
fn preserves_observer_clock_sources() {
    let error = l2_engine::StpObserverError::InvalidAge;
    assert!(!error.to_string().is_empty());
    let clock = l2_engine::ClockError::DurationTooLarge { nanos: 9 };
    let wrapped = l2_engine::StpObserverError::Clock(clock);
    assert!(!wrapped.to_string().is_empty());
    assert!(std::error::Error::source(&wrapped).is_some());
}
