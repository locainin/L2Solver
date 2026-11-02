use super::{
    Result, SharedFactKind, SharedGroup, SharedGroupCursor, SharedOccurrence,
    SharedOccurrenceCursor, SharedWarning, Store, flows, invalid, scopes,
};
use crate::evidence::SourceRange;
use l2_audit::ForensicScope;
use l2_capture::{CapturedFrame, EvidenceSourceId};
use l2_core::FrameField;
use l2_discovery::{dns::DnsMessage, ip_packet_from_payload, link::decode_network_frame};
use rusqlite::{Connection, params};
use serde_json::Value;
use std::{net::IpAddr, str::FromStr};

pub(super) struct PacketFacts {
    scope: Option<i64>,
    addresses: Option<[Vec<u8>; 2]>,
}

#[derive(Clone, Copy)]
struct FactLocation {
    source: i64,
    packet: u32,
    scope: Option<i64>,
    offset: u64,
    length: u64,
}

pub(super) fn observe_packet(
    connection: &Connection,
    source: i64,
    packet: u32,
    frame: &CapturedFrame,
    offset: u64,
    digest: &[u8; 32],
    facts: PacketFacts,
) -> Result<()> {
    let length = u64::try_from(frame.bytes().len())?;
    let location = FactLocation {
        source,
        packet,
        scope: facts.scope,
        offset,
        length,
    };
    insert_fact(connection, SharedFactKind::PacketBytes, digest, location)?;
    if let Some(addresses) = facts.addresses {
        for address in addresses {
            insert_fact(connection, SharedFactKind::IpAddress, &address, location)?;
        }
    }
    Ok(())
}

pub(super) fn packet_facts(
    connection: &Connection,
    cache: &mut scopes::Cache,
    frame: &CapturedFrame,
    transport: Option<&flows::Transport<'_>>,
) -> Result<PacketFacts> {
    if let Some(transport) = transport {
        return Ok(PacketFacts {
            scope: Some(transport.scope),
            addresses: Some([transport.source.clone(), transport.destination.clone()]),
        });
    }
    let Some(decoded) = decode_network_frame(frame.metadata().link_type(), frame.bytes()) else {
        return Ok(PacketFacts {
            scope: None,
            addresses: None,
        });
    };
    let scope = cache.retain(
        connection,
        &ForensicScope::from_network_frame(frame.metadata(), &decoded),
    )?;
    // Unknown cooked protocol meanings cannot be interpreted as IP
    let ip = match decoded.field() {
        Some(FrameField::EtherType(protocol)) => {
            ip_packet_from_payload(protocol, decoded.payload())
        }
        Some(FrameField::Length(_)) | None => None,
    };
    let addresses = ip.map(|ip| {
        [
            flows::address_bytes(ip.source),
            flows::address_bytes(ip.destination),
        ]
    });
    Ok(PacketFacts {
        scope: Some(scope),
        addresses,
    })
}

pub(super) fn observe_dns_questions(
    connection: &Connection,
    source: i64,
    packet: u32,
    transport: &flows::Transport<'_>,
    message: &DnsMessage,
) -> Result<()> {
    let length = u64::try_from(transport.payload.len())?;
    let location = FactLocation {
        source,
        packet,
        scope: Some(transport.scope),
        offset: transport.payload_offset,
        length,
    };
    for question in &message.questions {
        let canonical = question.name.canonical();
        insert_fact(
            connection,
            SharedFactKind::DnsQuestion,
            &canonical,
            location,
        )?;
    }
    Ok(())
}

fn insert_fact(
    connection: &Connection,
    kind: SharedFactKind,
    key: &[u8],
    location: FactLocation,
) -> Result<()> {
    connection
        .prepare_cached("INSERT INTO shared_facts(kind,fact_key,source,packet,scope,offset,length) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(kind,fact_key,source,packet) DO NOTHING")?
        .execute(params![kind.as_str(), key, location.source, location.packet, location.scope, location.offset, location.length])?;
    Ok(())
}

impl Store {
    /// Stream exact cross-source values in deterministic keyset pages
    ///
    /// # Errors
    /// Returns storage or visitor errors and rejects malformed cursors
    pub fn visit_shared_groups(
        &self,
        after: Option<&SharedGroupCursor>,
        maximum: Option<u64>,
        mut visitor: impl FnMut(SharedGroup) -> Result<()>,
    ) -> Result<()> {
        if let Some(cursor) = after {
            validate_key(cursor.kind, &cursor.key)?;
        }
        let kind = after.map_or("", |cursor| cursor.kind.as_str());
        let key = after.map_or(&[][..], |cursor| cursor.key.as_slice());
        let limit = maximum.map(i64::try_from).transpose()?.unwrap_or(-1);
        let mut statement = self.connection.prepare_cached(
            "SELECT kind,fact_key,COUNT(DISTINCT source),COUNT(*),MIN(scope),MAX(scope),COUNT(scope) FROM shared_facts WHERE (kind,fact_key)>(?1,?2) GROUP BY kind,fact_key HAVING COUNT(DISTINCT source)>=2 ORDER BY kind,fact_key LIMIT ?3",
        )?;
        let mut rows = statement.query(params![kind, key, limit])?;
        while let Some(row) = rows.next()? {
            let kind = row.get::<_, String>(0)?.parse::<SharedFactKind>()?;
            let key: Vec<u8> = row.get(1)?;
            let first_scope: Option<i64> = row.get(4)?;
            let last_scope: Option<i64> = row.get(5)?;
            let multiple_scopes = first_scope != last_scope;
            let occurrence_count: u64 = row.get(3)?;
            let missing_scope = row.get::<_, u64>(6)? < occurrence_count;
            visitor(SharedGroup {
                kind,
                warnings: warnings(kind, &key, multiple_scopes, missing_scope)?,
                key,
                source_count: row.get(2)?,
                occurrence_count,
            })?;
        }
        Ok(())
    }

    /// Stream source-qualified packet witnesses for one exact shared value
    ///
    /// # Errors
    /// Returns storage or visitor errors and rejects invalid kinds, keys, or cursors
    pub fn visit_shared_occurrences(
        &self,
        kind: SharedFactKind,
        key: &[u8],
        after: Option<&SharedOccurrenceCursor>,
        maximum: Option<u64>,
        mut visitor: impl FnMut(SharedOccurrence) -> Result<()>,
    ) -> Result<()> {
        validate_key(kind, key)?;
        let after_source = after
            .map(|cursor| cursor_source(&self.connection, kind, key, cursor))
            .transpose()?
            .unwrap_or(0);
        let after_packet = after.map_or(0, |cursor| cursor.packet);
        let limit = maximum.map(i64::try_from).transpose()?.unwrap_or(-1);
        let mut statement = self.connection.prepare_cached(
            "SELECT s.sha256,f.packet,f.offset,f.length,c.value FROM shared_facts f JOIN sources s ON s.id=f.source LEFT JOIN scopes c ON c.id=f.scope WHERE f.kind=?1 AND f.fact_key=?2 AND (f.source,f.packet)>(?3,?4) ORDER BY f.source,f.packet LIMIT ?5",
        )?;
        let mut rows = statement.query(params![
            kind.as_str(),
            key,
            after_source,
            after_packet,
            limit
        ])?;
        while let Some(row) = rows.next()? {
            let source_id: String = row.get(0)?;
            let packet: u32 = row.get(1)?;
            let offset: u64 = row.get(2)?;
            let length: u64 = row.get(3)?;
            let scope: Option<Vec<u8>> = row.get(4)?;
            visitor(SharedOccurrence {
                kind,
                key: key.to_vec(),
                range: SourceRange {
                    source: source_id.clone(),
                    packet: Some(u64::from(packet)),
                    offset,
                    length,
                },
                scope: scope
                    .map(|bytes| serde_json::from_slice::<Value>(&bytes))
                    .transpose()?,
                source_id,
                packet,
            })?;
        }
        Ok(())
    }
}

fn cursor_source(
    connection: &Connection,
    kind: SharedFactKind,
    key: &[u8],
    cursor: &SharedOccurrenceCursor,
) -> Result<i64> {
    if cursor.packet == 0 {
        return Err(invalid("shared occurrence cursor packet must be nonzero"));
    }
    EvidenceSourceId::from_str(&cursor.source_id)
        .map_err(|_| invalid("invalid shared occurrence source identity"))?;
    let source: i64 = connection
        .prepare_cached("SELECT id FROM sources WHERE sha256=?1")?
        .query_row([&cursor.source_id], |row| row.get(0))?;
    let exists: bool = connection.prepare_cached("SELECT EXISTS(SELECT 1 FROM shared_facts WHERE kind=?1 AND fact_key=?2 AND source=?3 AND packet=?4)")?
        .query_row(params![kind.as_str(), key, source, cursor.packet], |row| row.get(0))?;
    if !exists {
        return Err(invalid(
            "shared occurrence cursor is not in this result set",
        ));
    }
    Ok(source)
}

fn validate_key(kind: SharedFactKind, key: &[u8]) -> Result<()> {
    let valid = match kind {
        SharedFactKind::IpAddress => matches!(key.len(), 4 | 16),
        SharedFactKind::DnsQuestion => !key.is_empty() && key.len() <= 255,
        SharedFactKind::PacketBytes => key.len() == 32,
    };
    if !valid {
        return Err(invalid("shared fact key length does not match its kind"));
    }
    Ok(())
}

fn warnings(
    kind: SharedFactKind,
    key: &[u8],
    multiple_scopes: bool,
    missing_scope: bool,
) -> Result<Vec<SharedWarning>> {
    let mut values = Vec::new();
    if kind == SharedFactKind::PacketBytes {
        values.push(SharedWarning::CaptureBytesMayBeCorrelated);
    }
    if missing_scope {
        values.push(SharedWarning::CaptureScopeUnavailable);
    }
    if kind == SharedFactKind::IpAddress && private_address(flows::ip(key)?) {
        values.push(SharedWarning::PrivateAddressAcrossSources);
        if multiple_scopes {
            values.push(SharedWarning::MultipleCaptureLocalScopes);
        }
    }
    Ok(values)
}

const fn private_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => address.is_unique_local(),
    }
}
