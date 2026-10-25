use super::{Event, Journal, Result, invalid};
use crate::{
    evidence::Case,
    query::packet::{mac_text, packet_facts},
    store::Store,
};
use rusqlite::params;
use serde_json::json;
use std::collections::BTreeMap;

impl Journal {
    /// Retain an explicitly supplied event and preserve its caller-provided meaning
    ///
    /// # Errors
    /// Rejects missing identity fields, invalid ranges, metadata budgets and storage errors
    pub fn record_event(&mut self, event: &Event) -> Result<()> {
        insert_event(&self.connection, self.options.max_entry_bytes, event)?;
        Ok(())
    }

    /// Import source-scoped packet and graph observations from the retained base case
    ///
    /// # Errors
    /// Rejects changed evidence, malformed metadata and storage errors
    pub fn import_base_events(&mut self) -> Result<u64> {
        let case = self.base_case()?;
        self.import_case_events(&case)
    }
    /// Import another validated case without copying its blobs into the journal
    ///
    /// # Errors
    /// Returns metadata or storage errors
    pub fn import_case_events(&mut self, case: &Case) -> Result<u64> {
        let before = self.overview()?.events;
        let options = self.options;
        let tx = self.connection.transaction()?;
        let packets = packet_facts(case);
        let by_record: BTreeMap<_, _> = packets
            .iter()
            .filter_map(|p| {
                p.source_id
                    .as_ref()
                    .map(|s| ((s.as_str(), p.packet_number), p))
            })
            .collect();
        for p in &packets {
            if let Some(event) = packet_event(p)? {
                insert_event(&tx, options.max_entry_bytes, &event)?;
            }
        }
        for node in case.nodes().iter().filter(|n| n.kind != "packet") {
            let mut ends: BTreeMap<&str, u64> = BTreeMap::new();
            for range in &node.ranges {
                if let Some(packet) = range.packet {
                    ends.entry(&range.source)
                        .and_modify(|n| *n = (*n).max(packet))
                        .or_insert(packet);
                }
            }
            for (source, packet) in ends {
                let Some(p) = by_record.get(&(source, packet)) else {
                    continue;
                };
                let scope = serde_json::to_string(&p.scope)?;
                let clock = p.timestamp.as_ref().map(|t| {
                    format!(
                        "{source}:{scope}:{}:{}:{}:{}",
                        t.radix, t.exponent, t.offset_seconds, t.source
                    )
                });
                // One graph observation may have several witnesses; its last witness orders the completed observation
                insert_event(
                    &tx,
                    options.max_entry_bytes,
                    &Event {
                        source: source.to_owned(),
                        scope,
                        packet,
                        kind: node.kind.clone(),
                        actor: p.source_ip.map(|a| a.to_string()),
                        peer: p.destination_ip.map(|a| a.to_string()),
                        clock,
                        ticks: p.timestamp.as_ref().map(|t| t.ticks),
                        fields: json!({"node_id":node.id,"details":node.details}),
                        ranges: node
                            .ranges
                            .iter()
                            .filter(|r| r.source == source)
                            .cloned()
                            .collect(),
                    },
                )?;
            }
        }
        tx.commit()?;
        Ok(self.overview()?.events - before)
    }
    /// Stream every indexed packet into durable observations without page-local context
    ///
    /// # Errors
    /// Rejects changed retained packets, invalid metadata and storage errors
    pub fn import_index_events(&mut self, store: &Store) -> Result<u64> {
        let before = self.overview()?.events;
        let options = self.options;
        let tx = self.connection.transaction()?;
        store.visit_frames(|packet, frame| {
            let facts = crate::query::packet::frame_facts(&frame, packet.range);
            if let Some(event) = packet_event(&facts)? {
                insert_event(&tx, options.max_entry_bytes, &event)?;
            }
            Ok(())
        })?;
        tx.commit()?;
        Ok(self.overview()?.events - before)
    }
}

pub(super) fn insert_event(
    connection: &rusqlite::Connection,
    budget: usize,
    event: &Event,
) -> Result<String> {
    validate_event(event)?;
    let value = String::from_utf8(super::encode_metadata(event, budget)?)?;
    let identity = crate::sha256(value.as_bytes());
    connection.execute("INSERT OR IGNORE INTO events(identity,source,scope,packet,kind,actor,peer,value) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![identity,event.source,event.scope,event.packet,event.kind,event.actor,event.peer,value])?;
    Ok(identity)
}

pub fn validate_event(event: &Event) -> Result<()> {
    if event.source.is_empty()
        || event.scope.is_empty()
        || event.kind.is_empty()
        || event.packet == 0
    {
        return Err(invalid(
            "events need source, scope, kind and one-based packet order",
        ));
    }
    if event
        .ranges
        .iter()
        .any(|r| r.source != event.source || r.offset.checked_add(r.length).is_none())
    {
        return Err(invalid(
            "event ranges must agree with its source and not overflow",
        ));
    }
    Ok(())
}

fn packet_event(p: &crate::query::packet::PacketFacts) -> Result<Option<Event>> {
    let Some(source) = &p.source_id else {
        return Ok(None);
    };
    let scope = serde_json::to_string(&p.scope)?;
    let clock = p.timestamp.as_ref().map(|t| {
        format!(
            "{source}:{scope}:{}:{}:{}:{}",
            t.radix, t.exponent, t.offset_seconds, t.source
        )
    });
    Ok(Some(Event {
        source: source.clone(),
        scope,
        packet: p.packet_number,
        kind: format!("packet_{}", p.protocol.unwrap_or("other")),
        actor: p.source_ip.or(p.arp_source_ip).map(|a| a.to_string()),
        peer: p
            .destination_ip
            .or(p.arp_destination_ip)
            .map(|a| a.to_string()),
        clock,
        ticks: p.timestamp.as_ref().map(|t| t.ticks),
        fields: json!({
            "source_port": p.source_port,
            "destination_port": p.destination_port,
            "tcp_flags": p.tcp_flags,
            "protocol_number": p.protocol_number,
            "source_mac": mac_text(p.source_mac),
            "destination_mac": mac_text(p.destination_mac),
            "arp_source_ip": p.arp_source_ip.map(|address| address.to_string()),
            "arp_destination_ip": p.arp_destination_ip.map(|address| address.to_string()),
        }),
        ranges: p.ranges.clone(),
    }))
}
