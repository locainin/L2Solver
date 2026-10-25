use super::model::PacketFilter;
use l2_workbench::evidence::SourceRange;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn filters(ranges: &[SourceRange]) -> Vec<PacketFilter> {
    let mut sources: BTreeMap<&str, BTreeSet<u64>> = BTreeMap::new();
    for range in ranges {
        if let Some(packet) = range.packet {
            sources.entry(&range.source).or_default().insert(packet);
        }
    }
    // Frame numbers restart in each source, so filters must never combine captures
    sources
        .into_iter()
        .map(|(source, packets)| PacketFilter {
            source_id: source.to_owned(),
            expression: format!(
                "frame.number in {{{}}}",
                packets
                    .into_iter()
                    .map(|packet| packet.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        })
        .collect()
}
