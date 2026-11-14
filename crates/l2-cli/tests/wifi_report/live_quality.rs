use super::{Summary, collection_complete};

#[test]
fn replayed_source_blocks_completion() -> Result<(), Box<dyn std::error::Error>> {
    let inventory = wifi_discovery::Survey::new(wifi_discovery::SurveyLimits::default())?;
    assert!(collection_complete(&Summary::default(), &inventory, true));
    let summary = Summary {
        source_collection: l2_pcap::CollectionSummary {
            sections: 1,
            reported_sections: 1,
            incomplete_sections: 1,
            capture_dropped: 0,
            interface_dropped: 0,
            ..l2_pcap::CollectionSummary::default()
        },
        ..Summary::default()
    };
    assert!(!collection_complete(&summary, &inventory, true));
    let json = serde_json::to_value(&summary)?;
    assert_eq!(
        json.pointer("/source_collection/incomplete_sections"),
        Some(&serde_json::json!(1))
    );
    for source_collection in [
        l2_pcap::CollectionSummary {
            enhanced_packet_packets_dropped: Some(3),
            ..l2_pcap::CollectionSummary::default()
        },
        l2_pcap::CollectionSummary {
            interface_statistics_os_dropped: Some(2),
            ..l2_pcap::CollectionSummary::default()
        },
    ] {
        let summary = Summary {
            source_collection,
            ..Summary::default()
        };
        assert!(!collection_complete(&summary, &inventory, true));
    }
    Ok(())
}

#[cfg(feature = "live")]
#[test]
fn reported_live_quality_blocks_completion() -> Result<(), Box<dyn std::error::Error>> {
    let inventory = wifi_discovery::Survey::new(wifi_discovery::SurveyLimits::default())?;
    let summary = Summary {
        live: Some(crate::completion::LiveCaptureQuality::reported_for_test(
            crate::completion::LiveStopReason::PacketLimit,
            crate::completion::LiveGoal::Packets,
            1,
            0,
            0,
        )),
        ..Summary::default()
    };

    assert!(!collection_complete(&summary, &inventory, true));
    let json = serde_json::to_value(&summary)?;
    assert_eq!(
        json.pointer("/live/stop_reason"),
        Some(&serde_json::json!("packet_limit"))
    );
    assert_eq!(
        json.pointer("/live/loss_counters_authoritative"),
        Some(&serde_json::json!(false))
    );
    Ok(())
}

#[cfg(feature = "live")]
#[test]
fn wrong_stop_reason_blocks_completion() -> Result<(), Box<dyn std::error::Error>> {
    let inventory = wifi_discovery::Survey::new(wifi_discovery::SurveyLimits::default())?;
    let summary = Summary {
        live: Some(
            crate::completion::LiveCaptureQuality::authoritative_for_test(
                Some(l2_live::StopReason::Deadline),
                false,
                1,
                0,
                0,
            ),
        ),
        ..Summary::default()
    };

    assert!(!collection_complete(&summary, &inventory, true));
    Ok(())
}

#[test]
fn offline_summary_omits_live_details() -> Result<(), Box<dyn std::error::Error>> {
    let summary = Summary::default();
    let json = serde_json::to_value(&summary)?;

    assert!(json.get("live").is_none());
    assert_eq!(json.get("frames"), Some(&serde_json::json!(0)));
    Ok(())
}
