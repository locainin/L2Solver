use l2_audit::{
    AuditError, Disposition, Policy, SegmentExpectations, SourceLabelMap, SourceLabelMapError,
    StablePortBinding, StableSourceLabel,
};
use l2_capture::InterfaceId;
use std::collections::{BTreeMap, BTreeSet};

const fn source(section: u32, index: u32) -> InterfaceId {
    InterfaceId { section, index }
}

fn policy_v3() -> Result<Policy, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(
        r#"{
            "schema_version": 3,
            "segments": {
                "trusted": { "allowed_vlans": [10] },
                "guest": { "allowed_vlans": [20] }
            },
            "ports": [
                { "source": "desk-17", "segment": "trusted", "role": "access" },
                { "source": "conference-2", "segment": "guest", "role": "access" }
            ]
        }"#,
    )?)
}

fn resolved_by_label(
    policy: &Policy,
    sources: &[InterfaceId],
    labels: &SourceLabelMap,
) -> Result<BTreeMap<String, l2_audit::ResolvedExpectations>, Box<dyn std::error::Error>> {
    policy.validate_source_mapping(labels, sources)?;
    let mut resolved = BTreeMap::new();
    for source in sources {
        let label = labels.label_for(*source).ok_or("missing runtime label")?;
        let expectations = policy
            .expectations_for_source(*source, labels)?
            .ok_or("missing policy binding")?;
        resolved.insert(label.to_owned(), expectations);
    }
    Ok(resolved)
}

#[test]
fn stable_labels_survive_idb_reordering() -> Result<(), Box<dyn std::error::Error>> {
    let policy = policy_v3()?;
    let first_ids = [source(0, 0), source(0, 1)];
    let first_labels =
        SourceLabelMap::new([(first_ids[0], "desk-17"), (first_ids[1], "conference-2")])?;
    let reordered_ids = [source(0, 0), source(0, 1)];
    let reordered_labels = SourceLabelMap::new([
        (reordered_ids[0], "conference-2"),
        (reordered_ids[1], "desk-17"),
    ])?;

    let first = resolved_by_label(&policy, &first_ids, &first_labels)?;
    let reordered = resolved_by_label(&policy, &reordered_ids, &reordered_labels)?;
    assert_eq!(first, reordered);
    assert_eq!(
        first
            .get("desk-17")
            .map(|expectations| expectations.segment.as_str()),
        Some("trusted")
    );
    assert_eq!(
        first
            .get("conference-2")
            .map(|expectations| expectations.segment.as_str()),
        Some("guest")
    );
    Ok(())
}

#[test]
fn duplicate_missing_runtime_labels_closed() -> Result<(), Box<dyn std::error::Error>> {
    let first = source(0, 0);
    let second = source(0, 1);
    let duplicate = SourceLabelMap::new([(first, "desk-17"), (second, "desk-17")]);
    assert!(matches!(
        duplicate,
        Err(SourceLabelMapError::DuplicateLabel { .. })
    ));

    let policy = policy_v3()?;
    let missing = SourceLabelMap::new([(first, "desk-17")])?;
    assert!(matches!(
        policy.validate_source_mapping(&missing, &[first, second]),
        Err(AuditError::SourceMapping(SourceLabelMapError::MissingSource { source: actual }))
            if actual == second
    ));

    let wrong_label = SourceLabelMap::new([(first, "unbound")])?;
    assert!(matches!(
        policy.expectations_for_source(first, &wrong_label),
        Err(AuditError::SourceMapping(
            SourceLabelMapError::UnboundLabel { .. }
        ))
    ));
    Ok(())
}

#[test]
fn schema_v2_ordinal_bindings_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let policy: Policy = serde_json::from_str(
        r#"{
            "schema_version": 2,
            "segments": { "trusted": {} },
            "ports": [
                { "section": 3, "index": 7, "segment": "trusted", "role": "access" }
            ]
        }"#,
    )?;
    policy.validate()?;
    let no_mapping = SourceLabelMap::new(std::iter::empty::<(InterfaceId, String)>())?;
    let resolved = policy
        .expectations_for_source(source(3, 7), &no_mapping)?
        .ok_or("missing v2 binding")?;
    assert_eq!(resolved.segment, "trusted");
    Ok(())
}

#[test]
fn programmatic_v3_stable_port_bindings() -> Result<(), Box<dyn std::error::Error>> {
    let policy = Policy {
        schema_version: Some(3),
        segments: Some(BTreeMap::from([(
            String::from("trusted"),
            SegmentExpectations {
                allowed_vlans: Some(BTreeSet::from([10])),
                ..SegmentExpectations::default()
            },
        )])),
        stable_ports: Some(vec![StablePortBinding {
            source: StableSourceLabel::new("desk-17")?,
            segment: String::from("trusted"),
            role: String::from("access"),
        }]),
        ..Policy::default()
    };
    policy.validate()?;
    let labels = SourceLabelMap::new([(source(4, 9), "desk-17")])?;
    let resolved = policy
        .expectations_for_source(source(4, 9), &labels)?
        .ok_or("missing stable binding")?;
    assert_eq!(resolved.segment, "trusted");
    assert_eq!(resolved.role, "access");
    assert_eq!(resolved.priority_tagged, Disposition::Unspecified);
    Ok(())
}

#[test]
fn schema_v3_serializes_stable_ports() -> Result<(), Box<dyn std::error::Error>> {
    let policy = policy_v3()?;
    let encoded = serde_json::to_value(&policy)?;
    assert_eq!(encoded.get("schema_version"), Some(&serde_json::json!(3)));
    let ports = encoded
        .get("ports")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing stable ports")?;
    let first_port = ports.first().ok_or("missing first stable port")?;
    assert_eq!(
        first_port.get("source"),
        Some(&serde_json::json!("conference-2"))
    );
    assert!(first_port.get("section").is_none());

    let decoded: Policy = serde_json::from_value(encoded)?;
    decoded.validate()?;
    Ok(())
}
