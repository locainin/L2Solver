use std::{
    error::Error,
    future,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use super::{QueryFailure, bounded_query, from_failure, from_inventory};
use wifi_linux::{
    CapabilityState, DiscoveryError, InterfaceInfo, PhyCapabilities, WirelessInventory,
    WirelessMode,
};

fn inventory() -> Result<WirelessInventory, DiscoveryError> {
    let first = PhyCapabilities::new(
        1,
        Some("phy1".into()),
        vec![WirelessMode::Station],
        vec![],
        CapabilityState::Unknown,
    )?;
    let second = PhyCapabilities::new(
        2,
        Some("phy2".into()),
        vec![
            WirelessMode::Station,
            WirelessMode::Monitor,
            WirelessMode::Other(42),
        ],
        vec![],
        CapabilityState::Supported,
    )?;
    let one = InterfaceInfo::new(4, "wlan-a".into(), 1, WirelessMode::Station)?;
    let two = InterfaceInfo::new(9, "wlan-b".into(), 2, WirelessMode::Station)?;
    WirelessInventory::new(vec![first, second], vec![one, two])
}

#[test]
fn selected_ifindex_maps_to_its_own_radio_and_reported_modes() -> Result<(), Box<dyn Error>> {
    let result = from_inventory("wlan-b", 9, &inventory()?)?;
    assert_eq!(result.status, "reported");
    assert_eq!(result.phy_id, Some(2));
    assert_eq!(result.phy_name.as_deref(), Some("phy2"));
    assert_eq!(
        result.current_mode.as_ref().map(|mode| mode.name),
        Some("station")
    );
    assert!(
        result
            .supported_modes
            .iter()
            .any(|mode| mode.name == "monitor")
    );
    assert!(
        result
            .supported_modes
            .iter()
            .any(|mode| mode.kernel_value == Some(42))
    );
    assert_eq!(result.monitor_mode, "yes");
    assert_eq!(result.injection, "unknown");
    Ok(())
}

#[test]
fn missing_interface_is_not_reported_without_claiming_unsupported() -> Result<(), Box<dyn Error>> {
    let result = from_inventory("eth0", 12, &inventory()?)?;
    assert_eq!(result.status, "not_reported");
    assert_eq!(
        result.reason.as_deref(),
        Some("interface_not_in_nl80211_dump")
    );
    assert_eq!(result.monitor_mode, "unknown");
    assert_eq!(result.injection, "unknown");
    assert_eq!(result.phy_id, None);
    Ok(())
}

#[test]
fn reused_ifindex_with_another_name_is_rejected() -> Result<(), Box<dyn Error>> {
    let result = from_inventory("wlan-replaced", 9, &inventory()?);
    assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::InvalidData));
    Ok(())
}

#[test]
fn no_monitor_evidence_remains_unknown() -> Result<(), Box<dyn Error>> {
    let result = from_inventory("wlan-a", 4, &inventory()?)?;
    assert_eq!(result.phy_id, Some(1));
    assert_eq!(result.monitor_mode, "unknown");
    Ok(())
}

#[test]
fn timeout_and_inventory_errors_stay_unknown_with_distinct_reasons() -> Result<(), Box<dyn Error>> {
    let timeout = from_failure(QueryFailure::Timeout)?;
    assert_eq!(timeout.status, "unknown");
    assert_eq!(timeout.reason.as_deref(), Some("nl80211_timeout"));
    assert_eq!(timeout.monitor_mode, "unknown");

    let failed = from_failure(QueryFailure::Discovery(DiscoveryError::Netlink(
        "permission denied".into(),
    )))?;
    assert_eq!(failed.status, "unknown");
    assert_eq!(failed.reason.as_deref(), Some("nl80211_error"));
    assert!(
        failed
            .detail
            .as_deref()
            .is_some_and(|text| text.contains("permission denied"))
    );
    assert_eq!(failed.injection, "unknown");
    Ok(())
}

#[test]
fn netlink_error_details_are_bounded_and_json_control_characters_are_escaped()
-> Result<(), Box<dyn Error>> {
    let failure = from_failure(QueryFailure::Discovery(DiscoveryError::Netlink(format!(
        "\u{1b}{}",
        "x".repeat(1_024)
    ))))?;
    let detail = failure.detail.as_deref().ok_or("missing error detail")?;
    assert!(detail.chars().count() <= 257);
    let json = serde_json::to_string(&failure)?;
    assert!(!json.contains('\u{1b}'));
    assert!(json.contains("\\u001b"));
    Ok(())
}

#[test]
fn pending_inventory_stops_at_the_requested_deadline() {
    let result = bounded_query(Duration::from_millis(20), &AtomicBool::new(false), || {
        future::pending::<Result<WirelessInventory, DiscoveryError>>()
    });
    assert!(matches!(result, Err(QueryFailure::Timeout)));
}

#[test]
fn cancellation_interrupts_a_pending_wireless_inventory() {
    let cancelled = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(20));
            cancelled.store(true, Ordering::Release);
        });
        let result = bounded_query(Duration::from_secs(5), &cancelled, || {
            future::pending::<Result<WirelessInventory, DiscoveryError>>()
        });
        assert!(matches!(result, Err(QueryFailure::Cancelled)));
    });
}

#[test]
fn late_non_yielding_inventory_is_not_reported_as_success() {
    let result = bounded_query(
        Duration::from_millis(5),
        &AtomicBool::new(false),
        || async {
            std::thread::sleep(Duration::from_millis(25));
            WirelessInventory::new(vec![], vec![])
        },
    );
    assert!(matches!(result, Err(QueryFailure::Timeout)));
}

#[test]
fn query_can_run_inside_an_existing_tokio_runtime() -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let result = runtime.block_on(async {
        bounded_query(Duration::from_secs(1), &AtomicBool::new(false), || async {
            WirelessInventory::new(vec![], vec![])
        })
    });
    assert!(result.is_ok());
    Ok(())
}
