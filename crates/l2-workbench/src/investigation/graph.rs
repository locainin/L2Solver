pub(super) use crate::evidence::ByteMapping as MappedRange;
use crate::{
    evidence::{Case, Edge, EvidenceStatus, SourceRange},
    reconstruction::Origin,
};
use l2_capture::{CaptureLocator, CapturedFrame};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
};

pub(super) struct Context<'a> {
    pub case: &'a mut Case,
    pub source: &'a str,
    pub records: &'a BTreeMap<u32, &'a CapturedFrame>,
    pub packet_nodes: BTreeMap<u32, u64>,
    pub incomplete: bool,
}

impl Context<'_> {
    pub fn mappings(&self, origins: &[Origin]) -> Result<Vec<MappedRange>, Box<dyn Error>> {
        let mut mappings = Vec::new();
        for origin in origins.iter().filter(|origin| origin.length != 0) {
            let frame = self
                .records
                .get(&origin.packet)
                .ok_or("reconstruction references a missing packet")?;
            let Some(
                CaptureLocator::ClassicPcap {
                    data_offset: offset,
                    ..
                }
                | CaptureLocator::PcapNg {
                    data_offset: offset,
                    ..
                },
            ) = frame.metadata().locator()
            else {
                continue;
            };
            let end = origin
                .frame_offset
                .checked_add(origin.length)
                .ok_or("packet source range overflow")?;
            if end > frame.bytes().len() {
                return Err("reconstruction source range exceeds its captured frame".into());
            }
            mappings.push(MappedRange {
                offset: origin.offset,
                range: SourceRange {
                    source: self.source.to_owned(),
                    packet: Some(u64::from(origin.packet)),
                    offset: offset
                        .checked_add(u64::try_from(origin.frame_offset)?)
                        .ok_or("source file offset overflow")?,
                    length: u64::try_from(origin.length)?,
                },
            });
        }
        Ok(mappings)
    }

    pub fn edge(
        &mut self,
        from: u64,
        to: u64,
        relation: &str,
        status: EvidenceStatus,
        reason: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.case.add_edge(Edge {
            from,
            to,
            relation: relation.to_owned(),
            status,
            reason: reason.to_owned(),
        })?;
        Ok(())
    }

    pub fn packet_edges(
        &mut self,
        packets: impl IntoIterator<Item = u32>,
        to: u64,
        status: EvidenceStatus,
    ) -> Result<(), Box<dyn Error>> {
        let unique: BTreeSet<_> = packets.into_iter().collect();
        for packet in unique {
            if let Some(from) = self.packet_nodes.get(&packet) {
                self.edge(
                    *from,
                    to,
                    "supports",
                    status,
                    "Retained packet contributes to this candidate or observation",
                )?;
            }
        }
        Ok(())
    }
}

pub(super) fn clip(
    mappings: &[MappedRange],
    offset: usize,
    length: usize,
) -> Result<Vec<MappedRange>, Box<dyn Error>> {
    let end = offset.checked_add(length).ok_or("byte range overflow")?;
    Ok(crate::evidence::clip_byte_mappings(mappings, offset..end)?)
}
