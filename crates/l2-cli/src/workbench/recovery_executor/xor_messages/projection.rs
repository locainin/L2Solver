//! Preserve one source-backed range per packet observation

use l2_workbench::{carrier::discovery::DiscoveryMapping, evidence::SourceRange};
use std::collections::BTreeMap;

pub(super) struct PacketProjection {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) ranges: Vec<SourceRange>,
}

pub(super) fn packet_projections(
    mappings: &[DiscoveryMapping],
    input_length: usize,
) -> (Vec<PacketProjection>, usize) {
    let mut groups: BTreeMap<(&str, u64), Vec<&DiscoveryMapping>> = BTreeMap::new();
    let mut omitted = 0;
    for mapping in mappings {
        if let Some(packet) = mapping.range.packet {
            groups
                .entry((&mapping.range.source, packet))
                .or_default()
                .push(mapping);
        } else {
            omitted += 1;
        }
    }
    let mut result = Vec::new();
    for ((_source, _packet), mut group) in groups {
        group.sort_unstable_by_key(|mapping| (mapping.offset, mapping.range.offset));
        let Some(first) = group.first().copied() else {
            continue;
        };
        let mut end = first.offset;
        let mut valid = true;
        let mut ranges = Vec::new();
        for mapping in group {
            let Some(length) = usize::try_from(mapping.range.length).ok() else {
                valid = false;
                break;
            };
            let Some(mapping_end) = mapping.offset.checked_add(length) else {
                valid = false;
                break;
            };
            let Some(expected_source) = u64::try_from(mapping.offset - first.offset)
                .ok()
                .and_then(|delta| first.range.offset.checked_add(delta))
            else {
                valid = false;
                break;
            };
            if mapping.offset > end
                || mapping_end > input_length
                || mapping.range.offset != expected_source
            {
                valid = false;
                break;
            }
            end = end.max(mapping_end);
            ranges.push(mapping.range.clone());
        }
        if valid && end > first.offset {
            result.push(PacketProjection {
                start: first.offset,
                end,
                ranges,
            });
        } else {
            omitted += 1;
        }
    }
    (result, omitted)
}
