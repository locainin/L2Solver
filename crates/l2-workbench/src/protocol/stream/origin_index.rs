use crate::reconstruction::Origin;
use augmented_rbtree::interval_tree::{Interval, IntervalTree};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError, ser::SerializeSeq,
};
use std::{fmt, marker::PhantomData, mem::size_of, ptr::NonNull};

use super::super::ProtocolError;

/// Byte coordinate plus stable tie-breakers for overlapping capture ranges
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
struct Endpoint {
    offset: usize,
    packet: u32,
    frame_offset: usize,
}

type EstimatedNodeFields = (
    [Option<NonNull<()>>; 3],
    Interval<Endpoint>,
    (),
    Endpoint,
    augmented_rbtree::Color,
    PhantomData<(Interval<Endpoint>, (), Endpoint)>,
);

/// One canonical interval entry per exact source origin
#[derive(Debug, Default)]
pub(super) struct SourceOriginIndex {
    intervals: IntervalTree<Endpoint, ()>,
}

impl Clone for SourceOriginIndex {
    fn clone(&self) -> Self {
        let mut cloned = Self::default();
        for (interval, ()) in self.intervals.iter() {
            cloned.intervals.insert(*interval, ());
        }
        cloned
    }
}

impl SourceOriginIndex {
    /// Estimate logical interval-tree node storage, excluding allocator bookkeeping
    pub(super) const fn estimated_storage_bytes(count: usize) -> Option<usize> {
        // augmented-rbtree 0.3.0's private node stores three links, key, value, stats, color, and marker
        // This tuple estimates those field bytes and padding without claiming a physical RSS limit
        count.checked_mul(size_of::<EstimatedNodeFields>())
    }

    /// Add one checked origin and report whether this exact mapping was new
    pub(super) fn insert(&mut self, origin: &Origin) -> Result<bool, ProtocolError> {
        let interval = interval_for(origin)?;
        Ok(self.intervals.insert(interval, ()).is_none())
    }

    /// Check whether the full origin was already retained
    pub(super) fn contains(&self, origin: &Origin) -> bool {
        interval_for(origin).is_ok_and(|interval| self.intervals.contains(&interval))
    }

    /// Number of distinct retained origins
    pub(super) fn len(&self) -> usize {
        self.intervals.len()
    }

    /// Read all origins in interval order without keeping a second copy
    pub(super) fn iter(&self) -> impl Iterator<Item = Origin> + '_ {
        self.intervals
            .iter()
            .map(|(interval, ())| origin_from_interval(*interval))
    }

    /// Return complete source ranges that intersect a half-open byte interval
    pub(super) fn query_overlapping(
        &self,
        start: usize,
        end: usize,
    ) -> Option<impl Iterator<Item = Origin> + '_> {
        if start >= end {
            return None;
        }

        // Closed endpoints model the bytes in a half-open range without letting
        // packet and frame tie-breakers hide origins at either byte boundary
        let lower = Endpoint {
            offset: start,
            packet: 0,
            frame_offset: 0,
        };
        let upper = Endpoint {
            offset: end.checked_sub(1)?,
            packet: u32::MAX,
            frame_offset: usize::MAX,
        };
        Some(
            self.intervals
                .query_overlap(lower, upper)
                .map(|(interval, ())| origin_from_interval(*interval)),
        )
    }
}

impl Serialize for SourceOriginIndex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Preserve the legacy Origin field order without keeping a duplicate index
        let mut intervals = self
            .intervals
            .iter()
            .map(|(interval, ())| interval)
            .collect::<Vec<_>>();
        intervals.sort_unstable_by_key(|interval| {
            (
                interval.lo.packet,
                interval.lo.frame_offset,
                interval.lo.offset,
                interval.hi.offset,
            )
        });

        let mut sequence = serializer.serialize_seq(Some(intervals.len()))?;
        for interval in intervals {
            sequence.serialize_element(&origin_from_interval(*interval))?;
        }
        sequence.end()
    }
}

impl<'de> Deserialize<'de> for SourceOriginIndex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SourceOriginIndexVisitor;

        impl<'de> serde::de::Visitor<'de> for SourceOriginIndexVisitor {
            type Value = SourceOriginIndex;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence of valid source origins")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut index = SourceOriginIndex::default();
                while let Some(origin) = sequence.next_element::<Origin>()? {
                    // Validate each row before it can become persistent checkpoint state
                    index
                        .insert(&origin)
                        .map_err(|_| A::Error::custom("invalid source origin"))?;
                }
                Ok(index)
            }
        }

        deserializer.deserialize_seq(SourceOriginIndexVisitor)
    }
}

fn interval_for(origin: &Origin) -> Result<Interval<Endpoint>, ProtocolError> {
    if origin.packet == 0 || origin.length == 0 {
        return Err(ProtocolError::InvalidParserState);
    }

    // Keep arithmetic in the source format's half-open byte ranges until the checked end exists
    let end = origin
        .offset
        .checked_add(origin.length)
        .ok_or(ProtocolError::StreamOffsetOverflow)?;
    origin
        .frame_offset
        .checked_add(origin.length)
        .ok_or(ProtocolError::StreamOffsetOverflow)?;
    // The interval library uses closed ranges, so the last byte represents the exclusive end
    let last_byte = end
        .checked_sub(1)
        .ok_or(ProtocolError::StreamOffsetOverflow)?;

    Ok(Interval::new(
        Endpoint {
            offset: origin.offset,
            packet: origin.packet,
            frame_offset: origin.frame_offset,
        },
        Endpoint {
            offset: last_byte,
            packet: u32::MAX,
            frame_offset: usize::MAX,
        },
    ))
}

const fn origin_from_interval(interval: Interval<Endpoint>) -> Origin {
    // Every stored interval came from interval_for, which guarantees an ordered nonempty range
    Origin {
        packet: interval.lo.packet,
        frame_offset: interval.lo.frame_offset,
        offset: interval.lo.offset,
        length: interval.hi.offset - interval.lo.offset + 1,
    }
}
