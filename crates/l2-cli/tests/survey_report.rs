#[path = "../src/forensic_report.rs"]
mod forensic_report;

#[path = "../src/presentation.rs"]
mod presentation;
#[path = "../src/render.rs"]
pub mod render;
#[path = "../src/survey_report.rs"]
mod survey_report;

#[test]
fn empty_coverage() -> Result<(), Box<dyn std::error::Error>> {
    let mut report = l2_audit::Survey::new().finish(&l2_audit::Policy::default())?;
    report.coverage.clear();
    let mut output = Vec::new();

    let options = l2_cli::arguments::ReportOptions {
        verbosity: 2,
        ..l2_cli::arguments::ReportOptions::default()
    };
    survey_report::text_with_interface(&report, &options, "capture", None, &mut output)?;

    let text = String::from_utf8(output)?;
    assert!(!text.contains("not applicable checks omitted"));
    Ok(())
}

#[test]
fn summary_names_selected_profile() -> Result<(), Box<dyn std::error::Error>> {
    let report = l2_audit::Survey::new().finish_with_profile(
        &l2_audit::Policy::default(),
        l2_audit::AssessmentProfile::Full,
    )?;
    let mut output = Vec::new();

    let options = l2_cli::arguments::ReportOptions {
        verbosity: 2,
        ..l2_cli::arguments::ReportOptions::default()
    };
    survey_report::text_with_interface(&report, &options, "capture", None, &mut output)?;

    assert!(String::from_utf8(output)?.contains("assessment_profile=full"));
    Ok(())
}

#[test]
fn live_source_label_interface_separate() -> Result<(), Box<dyn std::error::Error>> {
    let report = l2_audit::Survey::new().finish(&l2_audit::Policy::default())?;
    let mut output = Vec::new();

    survey_report::text_with_interface(
        &report,
        &l2_cli::arguments::ReportOptions::default(),
        "desk-17",
        Some("enp4s0"),
        &mut output,
    )?;

    let text = String::from_utf8(output)?;
    assert!(text.contains("Source label desk-17"));
    assert!(text.contains("Interface    enp4s0"));
    Ok(())
}

#[test]
fn forensic_chains_limits() -> Result<(), Box<dyn std::error::Error>> {
    let mut report = l2_audit::Survey::new().finish(&l2_audit::Policy::default())?;
    report
        .forensics
        .arp_changes
        .push(l2_audit::ArpBindingChange {
            scope: l2_audit::ForensicScope {
                section: 2,
                interface: 3,
                vlan_ids: vec![(0x8100, 20)],
                vlan_aux: None,
                cooked_ifindex: None,
            },
            address: l2_audit::NetworkAddress::Ipv4([192, 0, 2, 1]),
            previous_mac: "02:00:00:00:00:01".into(),
            claimed_mac: "02:00:00:00:00:02".into(),
            previous_packet: 10,
            packet: 12,
            followup_packet: Some(14),
        });
    report
        .resource_limits
        .mark(l2_audit::ResourceLimit::ForensicRecords);
    let mut output = Vec::new();
    let options = l2_cli::arguments::ReportOptions {
        verbosity: 1,
        ..Default::default()
    };
    survey_report::text_with_interface(&report, &options, "capture", None, &mut output)?;
    let text = String::from_utf8(output)?;
    assert!(text.contains("Forensic observations"));
    assert!(text.contains("DNS wire"));
    assert!(text.contains("0 / 0 UDP candidates decoded"));
    assert!(text.contains("packets 10 -> 12 -> 14"));
    assert!(text.contains("capture record order"));
    assert!(text.contains("does not establish ownership, delivery, cause, or intent"));
    assert!(text.contains("retention limit reached"));
    assert!(text.contains("192.0.2.1"));
    Ok(())
}

#[test]
fn dns_details_raw_label_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let mut report = l2_audit::Survey::new().finish(&l2_audit::Policy::default())?;
    let wire = [
        0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'a', 0x1b, b'.', 0, 0, 1, 0, 1,
    ];
    report
        .forensics
        .dns_observations
        .push(l2_audit::DnsObservation {
            scope: l2_audit::ForensicScope {
                section: 0,
                interface: 0,
                vlan_ids: Vec::new(),
                vlan_aux: None,
                cooked_ifindex: None,
            },
            source: l2_audit::NetworkAddress::Ipv4([192, 0, 2, 1]),
            destination: l2_audit::NetworkAddress::Ipv4([192, 0, 2, 2]),
            ports: (42000, 53),
            packet: 1,
            payload_offset: 42,
            payload_length: wire.len(),
            decoding: l2_discovery::dns::DnsDecoding::Decoded {
                message: l2_discovery::dns::decode(&wire)?,
            },
        });
    for (response_packet, candidate_queries) in [(2, 0), (3, 2)] {
        report
            .forensics
            .dns_matches
            .push(l2_audit::DnsResponseMatch {
                response_packet,
                query_packet: None,
                candidate_queries,
            });
    }
    let mut output = Vec::new();
    let options = l2_cli::arguments::ReportOptions {
        verbosity: 2,
        ..Default::default()
    };
    survey_report::text_with_interface(&report, &options, "capture", None, &mut output)?;
    assert!(!output.contains(&0x1b));
    let text = String::from_utf8(output)?;
    assert!(text.contains("response association records"));
    assert!(text.contains("matching outstanding queries=0 (no unique association)"));
    assert!(text.contains("matching outstanding queries=2 (no unique association)"));
    assert!(text.contains("question=a\\027\\.."));
    Ok(())
}
