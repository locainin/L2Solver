use super::{
    Relationship, Result, Store,
    flows::{self, Transport},
    shared,
};
use crate::evidence::SourceRange;
use l2_discovery::dns::{self, DnsMessage, DnsSection, DnsValue};
use rusqlite::{Connection, params};
use std::collections::BTreeSet;

// Separate endpoint orders keep both address fields available to the scoped index
const RELATIONSHIP_QUERY: &str = "WITH candidates AS (
    SELECT d.source,d.request,d.response,d.offset,d.length,d.status,d.address,d.owner,f.id,
        (SELECT p.number FROM packets p
         WHERE p.flow=f.id AND p.number>d.response AND p.direction=0 ORDER BY p.number LIMIT 1) AS destination_packet
    FROM dns_addresses d CROSS JOIN flows f
    WHERE f.source=d.source AND f.scope=d.scope AND f.a=d.requester AND f.b=d.address
    UNION ALL
    SELECT d.source,d.request,d.response,d.offset,d.length,d.status,d.address,d.owner,f.id,
        (SELECT p.number FROM packets p
         WHERE p.flow=f.id AND p.number>d.response AND p.direction=1 ORDER BY p.number LIMIT 1) AS destination_packet
    FROM dns_addresses d CROSS JOIN flows f
    WHERE f.source=d.source AND f.scope=d.scope AND f.b=d.requester AND f.a=d.address
)
SELECT s.sha256,c.request,c.response,MIN(c.destination_packet),c.id,c.address,c.offset,c.length,c.status,x.questions,c.owner
FROM candidates c
JOIN dns_exchanges x ON x.source=c.source AND x.response=c.response
JOIN sources s ON s.id=c.source
GROUP BY c.source,c.response,c.offset,c.id,c.request,c.length,c.status,c.address,c.owner,s.sha256,x.questions
HAVING MIN(c.destination_packet) IS NOT NULL
ORDER BY c.source,c.response,c.offset,c.id
LIMIT ?1";

pub(super) fn observe(
    connection: &Connection,
    source: i64,
    packet: u32,
    transport: &Transport<'_>,
) -> Result<()> {
    if transport.protocol != 17 || (transport.ports.0 != 53 && transport.ports.1 != 53) {
        return Ok(());
    }
    let Ok(message) = dns::decode(transport.payload) else {
        return Ok(());
    };
    if message.questions.is_empty() || message.flags & 0x7800 != 0 {
        return Ok(());
    }
    shared::observe_dns_questions(connection, source, packet, transport, &message)?;
    let key = exchange_key(source, transport, &message)?;
    if !message.is_response() {
        connection
            .prepare_cached("INSERT INTO dns_pending(key,source,packet) VALUES(?1,?2,?3)")?
            .execute(params![key, source, packet])?;
        return Ok(());
    }
    let (count, request): (u64, Option<u32>) = connection
        .prepare_cached("SELECT COUNT(*),MIN(packet) FROM dns_pending WHERE key=?1")?
        .query_row([&key], |row| Ok((row.get(0)?, row.get(1)?)))?;
    let request = if count == 1 { request } else { None };
    let status = match count {
        0 => "unmatched",
        1 => "unique",
        _ => "ambiguous",
    };
    connection
        .prepare_cached(
            "INSERT INTO dns_exchanges(source,response,request,status,questions) VALUES(?1,?2,?3,?4,?5)",
        )?
        .execute(params![source, packet, request, status, serde_json::to_string(&message.questions)?])?;
    connection
        .prepare_cached("DELETE FROM dns_pending WHERE key=?1")?
        .execute([&key])?;
    // Successful untruncated answers still describe observed records, not host acceptance
    if message.flags & 0x0200 != 0 || message.response_code() != 0 {
        return Ok(());
    }
    retain_addresses(
        connection, source, packet, request, status, transport, &message,
    )
}

fn exchange_key(source: i64, transport: &Transport<'_>, message: &DnsMessage) -> Result<Vec<u8>> {
    let mut key = source.to_be_bytes().to_vec();
    key.extend_from_slice(&transport.scope.to_be_bytes());
    let (requester, responder, ports) = if message.is_response() {
        (
            &transport.destination,
            &transport.source,
            (transport.ports.1, transport.ports.0),
        )
    } else {
        (&transport.source, &transport.destination, transport.ports)
    };
    key.push(u8::try_from(requester.len())?);
    key.extend_from_slice(requester);
    key.extend_from_slice(responder);
    key.extend_from_slice(&ports.0.to_be_bytes());
    key.extend_from_slice(&ports.1.to_be_bytes());
    key.extend_from_slice(&message.id.to_be_bytes());
    for question in &message.questions {
        let name = question.name.canonical();
        key.extend_from_slice(&u16::try_from(name.len())?.to_be_bytes());
        key.extend_from_slice(&name);
        key.extend_from_slice(&question.qtype.to_be_bytes());
        key.extend_from_slice(&question.qclass.to_be_bytes());
    }
    Ok(key)
}

fn retain_addresses(
    connection: &Connection,
    source: i64,
    packet: u32,
    request: Option<u32>,
    status: &str,
    transport: &Transport<'_>,
    message: &DnsMessage,
) -> Result<()> {
    let mut names: BTreeSet<_> = message
        .questions
        .iter()
        .filter(|question| question.qclass == 1)
        .map(|question| question.name.canonical())
        .collect();
    // At most one new name is added per parsed record, so this closure terminates
    for _ in 0..message.records.len() {
        let before = names.len();
        for record in &message.records {
            if record.section == DnsSection::Answer
                && record.class == 1
                && record.rr_type == 5
                && names.contains(&record.name.canonical())
                && let DnsValue::Name(name) = &record.value
            {
                names.insert(name.canonical());
            }
        }
        if names.len() == before {
            break;
        }
    }
    for record in &message.records {
        if record.section != DnsSection::Answer
            || record.class != 1
            || !names.contains(&record.name.canonical())
        {
            continue;
        }
        let DnsValue::Address(address) = record.value else {
            continue;
        };
        let offset = transport.payload_offset + u64::try_from(record.rdata.offset)?;
        connection.prepare_cached("INSERT INTO dns_addresses(source,scope,response,request,requester,address,offset,length,status,owner) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)")?.execute(params![source,transport.scope,packet,request,transport.destination,flows::address_bytes(address),offset,record.rdata.length,status,record.name.wire()])?;
    }
    Ok(())
}

impl Store {
    /// Stream DNS answer-to-later-destination co-occurrences across the full capture
    ///
    /// # Errors
    /// Returns storage, address-decoding, or visitor errors
    pub fn visit_relationships(
        &self,
        maximum: Option<u64>,
        mut visitor: impl FnMut(Relationship) -> Result<()>,
    ) -> Result<()> {
        // Drive exact scoped endpoint-pair probes instead of scanning shared requester fanout
        // The outer grouping merges the two branches when requester and answer are equal
        let mut statement = self.connection.prepare(RELATIONSHIP_QUERY)?;
        let mut rows = statement.query([maximum.map(i64::try_from).transpose()?.unwrap_or(-1)])?;
        while let Some(row) = rows.next()? {
            let source_id: String = row.get(0)?;
            let response_packet: u32 = row.get(2)?;
            visitor(Relationship {
                source_id: source_id.clone(),
                request_packet: row.get(1)?,
                response_packet,
                destination_packet: row.get(3)?,
                destination_flow: row.get(4)?,
                answer_address: flows::ip(&row.get::<_, Vec<u8>>(5)?)?,
                answer_range: SourceRange {
                    source: source_id,
                    packet: Some(u64::from(response_packet)),
                    offset: row.get(6)?,
                    length: row.get(7)?,
                },
                association: row.get(8)?,
                questions: serde_json::from_str(&row.get::<_, String>(9)?)?,
                answer_owner_wire: row.get(10)?,
            })?;
        }
        Ok(())
    }
}
