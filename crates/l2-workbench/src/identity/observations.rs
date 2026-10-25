use super::{HeaderAssociation, ParticipantRole, ResolvedEvent};

pub(super) fn header_associations(events: &[ResolvedEvent]) -> Vec<HeaderAssociation> {
    let mut result = Vec::new();
    for (event_index, resolved) in events.iter().enumerate() {
        for (role, address, key) in [
            (ParticipantRole::Actor, &resolved.event.actor, "source_mac"),
            (
                ParticipantRole::Peer,
                &resolved.event.peer,
                "destination_mac",
            ),
        ] {
            let (Some(address), Some(mac)) = (
                address,
                resolved
                    .event
                    .fields
                    .get(key)
                    .and_then(serde_json::Value::as_str),
            ) else {
                continue;
            };
            // A MAC next hop can carry many remote IPs, so this is never a host binding
            if mac.len() == 17
                && mac.split(':').count() == 6
                && mac.split(':').all(|part| {
                    part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            {
                result.push(HeaderAssociation {
                    event_index,
                    role,
                    address: address.clone(),
                    mac: mac.to_owned(),
                });
            }
        }
    }
    result
}
