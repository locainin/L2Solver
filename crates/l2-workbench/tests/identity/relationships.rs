use super::support::{binding, event};
use l2_workbench::identity::{CorrelationOptions, CorrelationPlan, ResolutionStatus, correlate};
use std::error::Error;

#[test]
fn shared_layer_without_host_merging() -> Result<(), Box<dyn Error>> {
    let mut first = event("capture-a", "vlan-7", 3);
    first.fields = serde_json::json!({"source_mac":"02:00:00:00:00:01"});
    let mut second = event("capture-a", "vlan-7", 4);
    second.actor = Some("198.51.100.7".into());
    second.fields = first.fields.clone();
    let report = correlate(
        &[first, second],
        &CorrelationPlan::default(),
        CorrelationOptions::default(),
    )?;
    assert_eq!(report.header_associations.len(), 2);
    assert!(report.groups.is_empty());
    assert_eq!(
        report
            .header_associations
            .first()
            .ok_or("missing association")?
            .address,
        "192.0.2.9"
    );
    Ok(())
}

#[test]
fn address_reuse_produces_separate_identity() -> Result<(), Box<dyn Error>> {
    let events = vec![
        event("capture-a", "vlan-7", 3),
        event("capture-a", "vlan-7", 12),
    ];
    let plan = CorrelationPlan {
        bindings: vec![
            binding("lease-a", "device-a", 1, 9),
            binding("lease-b", "device-b", 10, 20),
        ],
        ..CorrelationPlan::default()
    };
    let report = correlate(&events, &plan, CorrelationOptions::default())?;
    assert_eq!(report.groups.len(), 2);
    assert_eq!(
        report.groups.first().ok_or("missing group")?.event_indices,
        vec![0]
    );
    assert_eq!(
        report
            .groups
            .get(1)
            .ok_or("missing second group")?
            .event_indices,
        vec![1]
    );
    Ok(())
}

#[test]
fn ambiguous_binding_identity_groups() -> Result<(), Box<dyn Error>> {
    let plan = CorrelationPlan {
        bindings: vec![
            binding("a", "device-a", 1, 9),
            binding("b", "device-b", 1, 9),
        ],
        ..CorrelationPlan::default()
    };
    let report = correlate(
        &[event("capture-a", "vlan-7", 3)],
        &plan,
        CorrelationOptions::default(),
    )?;
    let actor = report
        .events
        .first()
        .and_then(|e| e.actor.as_ref())
        .ok_or("missing actor")?;
    assert_eq!(actor.status, ResolutionStatus::Ambiguous);
    assert_eq!(actor.candidates.len(), 2);
    assert!(report.groups.is_empty());
    Ok(())
}

#[test]
fn equal_addresses_scopes_not_merged() -> Result<(), Box<dyn Error>> {
    let plan = CorrelationPlan {
        bindings: vec![binding("a", "device-a", 1, 9)],
        ..CorrelationPlan::default()
    };
    let report = correlate(
        &[
            event("capture-b", "vlan-7", 3),
            event("capture-a", "vlan-8", 3),
        ],
        &plan,
        CorrelationOptions::default(),
    )?;
    assert!(report.groups.is_empty());
    for event in report.events {
        assert_eq!(
            event.actor.ok_or("missing actor")?.status,
            ResolutionStatus::Unmapped
        );
    }
    Ok(())
}

#[test]
fn shared_bindings_create_one_group() -> Result<(), Box<dyn Error>> {
    let plan = CorrelationPlan {
        bindings: vec![
            binding("a", "device-a", 1, 9),
            binding("b", "device-a", 1, 9),
        ],
        ..CorrelationPlan::default()
    };
    let report = correlate(
        &[event("capture-a", "vlan-7", 3)],
        &plan,
        CorrelationOptions::default(),
    )?;
    let actor = report
        .events
        .first()
        .and_then(|e| e.actor.as_ref())
        .ok_or("missing actor")?;
    assert_eq!(actor.status, ResolutionStatus::Unique);
    assert_eq!(
        actor
            .candidates
            .first()
            .ok_or("missing candidate")?
            .binding_ids,
        vec!["a", "b"]
    );
    assert_eq!(report.groups.len(), 1);
    Ok(())
}

#[test]
fn work_limit_rejects_partial_results() -> Result<(), Box<dyn Error>> {
    let events = vec![
        event("capture-a", "vlan-7", 3),
        event("capture-a", "vlan-7", 4),
    ];
    let report = correlate(
        &events,
        &CorrelationPlan::default(),
        CorrelationOptions {
            max_events: 1,
            ..CorrelationOptions::default()
        },
    )?;
    assert_eq!(report.omitted_events, 1);
    assert!(!report.complete);
    let plan = CorrelationPlan {
        bindings: vec![binding("a", "device-a", 1, 9)],
        ..CorrelationPlan::default()
    };
    assert!(
        correlate(
            &events,
            &plan,
            CorrelationOptions {
                max_work_items: 1,
                ..CorrelationOptions::default()
            }
        )
        .is_err()
    );
    Ok(())
}
