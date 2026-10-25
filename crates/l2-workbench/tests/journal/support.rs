use l2_workbench::journal::Event;
use serde_json::json;

pub(super) fn event(packet: u64, kind: &str, scope: &str, actor: &str) -> Event {
    Event {
        source: "source-A".into(),
        scope: scope.into(),
        packet,
        kind: kind.into(),
        actor: Some(actor.into()),
        peer: None,
        clock: Some("clock-A".into()),
        ticks: Some(packet * 10),
        fields: json!({"result":"observed"}),
        ranges: Vec::new(),
    }
}
