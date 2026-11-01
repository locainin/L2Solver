use std::error::Error;

use l2_active_linux::ethernet_capabilities::{
    Capability, EthernetCapabilities, FeatureFlags, TimestampCapabilities, UnknownReason,
    VlanOffloads,
};
use l2_capture::LinuxInterfaceIdentity;

use super::EthernetView;

fn fixture() -> Result<EthernetView, Box<dyn Error>> {
    let flags = FeatureFlags {
        hw: true,
        wanted: false,
        active: true,
    };
    let evidence = EthernetCapabilities {
        identity: LinuxInterfaceIdentity::new(1, 2, 3, 4, 5)?,
        vlan: VlanOffloads {
            ctag_rx: Capability::Reported(flags),
            ctag_tx: Capability::Unsupported,
            ctag_filter: Capability::Denied,
            stag_rx: Capability::Unknown(UnknownReason::NotReported),
            stag_tx: Capability::Unknown(UnknownReason::QueryFailed(Some(5))),
            stag_filter: Capability::Unknown(UnknownReason::KernelApiUnavailable),
        },
        timestamps: TimestampCapabilities {
            tx_software: Capability::Reported(true),
            rx_software: Capability::Reported(false),
            tx_hardware: Capability::Unknown(UnknownReason::InvalidResponse),
            rx_hardware: Capability::Unsupported,
            phc_index: Capability::Reported(None),
        },
    };
    Ok(EthernetView::new(evidence))
}

#[test]
fn json_keeps_reported_denied_unsupported_and_unknown_states_distinct() -> Result<(), Box<dyn Error>>
{
    let value = serde_json::to_value(fixture()?)?;
    assert_eq!(
        value,
        serde_json::json!({
            "vlan_offload": {
                "ctag_rx": {"status": "reported", "value": {"hw": true, "wanted": false, "active": true}},
                "ctag_tx": {"status": "unsupported"},
                "ctag_filter": {"status": "denied"},
                "stag_rx": {"status": "unknown", "reason": "not_reported"},
                "stag_tx": {"status": "unknown", "reason": "query_failed", "os_error": 5},
                "stag_filter": {"status": "unknown", "reason": "kernel_api_unavailable"},
            },
            "hardware_timestamps": {
                "tx_software": {"status": "reported", "value": true},
                "rx_software": {"status": "reported", "value": false},
                "tx_hardware": {"status": "unknown", "reason": "invalid_response"},
                "rx_hardware": {"status": "unsupported"},
                "phc_index": {"status": "reported", "value": null},
            },
        })
    );
    Ok(())
}

#[test]
fn text_explains_kernel_flags_and_unavailable_evidence() -> Result<(), Box<dyn Error>> {
    let view = fixture()?;
    let mut text = Vec::new();
    view.write_text(&mut text)?;
    let text = String::from_utf8(text)?;
    assert!(
        text.contains("ctag_rx: reported hw=true wanted=false active=true"),
        "{text}"
    );
    assert!(text.contains("ctag_tx: unsupported"), "{text}");
    assert!(
        text.contains("stag_tx: unknown (query_failed, OS error 5)"),
        "{text}"
    );
    assert!(text.contains("phc_index: reported none"), "{text}");
    Ok(())
}
