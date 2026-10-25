use l2_discovery::{
    NetworkAddress,
    dns::{DnsMessage, DnsSection, DnsValue},
};
use std::collections::BTreeSet;

pub fn addresses(message: &DnsMessage) -> Vec<(usize, NetworkAddress)> {
    let [question] = message.questions.as_slice() else {
        return Vec::new();
    };
    if question.qclass != 1
        || !matches!(question.qtype, 1 | 28)
        || message.flags & 0x0200 != 0
        || message.response_code() != 0
    {
        return Vec::new();
    }
    let mut current = question.name.canonical();
    let mut visited = BTreeSet::new();
    // Every CNAME hop must consume a new retained owner, so this walk is bounded by the message
    while visited.insert(current.clone()) {
        let mut aliases = BTreeSet::new();
        let mut found = Vec::new();
        let mut has_address = false;
        for (index, record) in message.records.iter().enumerate() {
            if record.section != DnsSection::Answer
                || record.class != 1
                || record.name.canonical() != current
            {
                continue;
            }
            match &record.value {
                DnsValue::Name(target) if record.rr_type == 5 => {
                    aliases.insert(target.canonical());
                }
                DnsValue::Address(address) => {
                    has_address = true;
                    if record.rr_type == question.qtype {
                        found.push((index, *address));
                    }
                }
                _ => {}
            }
        }
        match aliases.len() {
            0 => return found,
            1 if !has_address => {
                let Some(target) = aliases.into_iter().next() else {
                    return Vec::new();
                };
                current = target;
            }
            // Conflicting aliases or simultaneous alias/address data do not choose an interpretation
            _ => return Vec::new(),
        }
    }
    Vec::new()
}
