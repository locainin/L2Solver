use l2_workbench::{
    evidence::SourceRange,
    identity::{ClockCalibration, IdentityBinding},
    journal::Event,
};
use serde_json::json;

pub fn evidence() -> Vec<SourceRange> {
    vec![SourceRange {
        source: "supporting-source".into(),
        packet: Some(1),
        offset: 4,
        length: 8,
    }]
}
pub fn event(source: &str, scope: &str, packet: u64) -> Event {
    Event {
        source: source.into(),
        scope: scope.into(),
        packet,
        kind: "packet_tcp".into(),
        actor: Some("192.0.2.9".into()),
        peer: Some("192.0.2.40".into()),
        clock: Some(format!("{source}:clock")),
        ticks: Some(packet),
        fields: json!({}),
        ranges: Vec::new(),
    }
}
pub fn binding(id: &str, identity: &str, first: u64, last: u64) -> IdentityBinding {
    IdentityBinding {
        id: id.into(),
        source: "capture-a".into(),
        scope: "vlan-7".into(),
        subject: "192.0.2.9".into(),
        identity: identity.into(),
        first_packet: first,
        last_packet: Some(last),
        evidence: evidence(),
        origin_claim: "supplied lease mapping".into(),
    }
}
pub fn calibration(id: &str, offset: u64, uncertainty: u64) -> ClockCalibration {
    ClockCalibration {
        id: id.into(),
        from_clock: "capture-a:clock".into(),
        to_clock: "capture-b:clock".into(),
        anchor_from: 0,
        anchor_to: offset,
        numerator: 1,
        denominator: 1,
        uncertainty_ticks: uncertainty,
        valid_from: 0,
        valid_through: Some(1000),
        evidence: evidence(),
        origin_claim: "supplied matched observations".into(),
    }
}
