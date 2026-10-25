use super::{DnsPlan, QueryKey, answers};
use crate::ForensicScope;
use l2_discovery::{IpPacket, dns::DnsMessage};

pub fn plan(scope: &ForensicScope, ip: IpPacket<'_>, message: &DnsMessage) -> Option<DnsPlan> {
    // Other opcodes and empty question sections remain observations without transaction guesses
    if message.opcode() != 0 || message.questions.is_empty() {
        return None;
    }
    let ports = ip.ports()?;
    let response = message.is_response();
    let (client, server, client_port, server_port) = if response {
        (ip.destination, ip.source, ports.1, ports.0)
    } else {
        (ip.source, ip.destination, ports.0, ports.1)
    };
    Some(DnsPlan {
        key: QueryKey {
            scope: scope.clone(),
            client,
            server,
            client_port,
            server_port,
            id: message.id,
            questions: message
                .questions
                .iter()
                .map(|question| (question.name.canonical(), question.qtype, question.qclass))
                .collect(),
        },
        response,
        addresses: if response {
            answers::addresses(message)
        } else {
            Vec::new()
        },
    })
}
