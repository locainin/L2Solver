use super::{DnsError, DnsErrorKind, DnsName};

/// Message-local offsets that were already decoded as DNS name boundaries
pub(super) struct NameContext {
    // A message-sized bitmap keeps target checks constant-time and bounded
    boundaries: Vec<bool>,
}

impl NameContext {
    pub(super) fn new(message_length: usize) -> Self {
        Self {
            boundaries: vec![false; message_length],
        }
    }

    fn contains(&self, offset: usize) -> bool {
        self.boundaries.get(offset).copied().unwrap_or(false)
    }

    fn register(&mut self, offsets: &[usize]) {
        for &offset in offsets {
            if let Some(boundary) = self.boundaries.get_mut(offset) {
                *boundary = true;
            }
        }
    }
}

pub(super) fn decode(
    bytes: &[u8],
    start: usize,
    encoded_limit: usize,
    names: &mut NameContext,
) -> Result<(DnsName, usize), DnsError> {
    let mut cursor = start;
    let mut encoded_end = None;
    let mut wire = Vec::new();
    let mut boundaries = Vec::new();
    loop {
        // Before a jump, the encoded name must fit its own field as well as the message
        let limit = if encoded_end.is_some() {
            bytes.len()
        } else {
            encoded_limit
        };
        let lead = bytes
            .get(..limit)
            .and_then(|part| part.get(cursor))
            .copied()
            .ok_or(DnsError {
                kind: DnsErrorKind::Incomplete,
                offset: cursor,
            })?;
        if encoded_end.is_none() {
            // Only offsets in this encoded field can become new targets
            boundaries.push(cursor);
        }
        match lead & 0xc0 {
            0xc0 => {
                let low = bytes
                    .get(..limit)
                    .and_then(|part| part.get(cursor + 1))
                    .copied()
                    .ok_or(DnsError {
                        kind: DnsErrorKind::Incomplete,
                        offset: cursor,
                    })?;
                let target = (usize::from(lead & 0x3f) << 8) | usize::from(low);
                // Only completed names add boundaries, so known targets are prior and outside the header
                if !names.contains(target) {
                    return Err(DnsError {
                        kind: DnsErrorKind::UnsupportedNameTarget,
                        offset: cursor,
                    });
                }
                encoded_end.get_or_insert(cursor + 2);
                cursor = target;
            }
            0 => {
                let end = cursor + 1 + usize::from(lead);
                let label = bytes
                    .get(..limit)
                    .and_then(|part| part.get(cursor..end))
                    .ok_or(DnsError {
                        kind: DnsErrorKind::Incomplete,
                        offset: cursor,
                    })?;
                // Leave room for the terminating root label in the 255-byte wire limit
                if wire.len() + label.len() + usize::from(lead != 0) > 255 {
                    return Err(DnsError {
                        kind: DnsErrorKind::NameLimit,
                        offset: cursor,
                    });
                }
                wire.extend_from_slice(label);
                cursor = end;
                if lead == 0 {
                    // Commit boundaries only after the full name has decoded
                    names.register(&boundaries);
                    return Ok((DnsName { wire }, encoded_end.unwrap_or(cursor)));
                }
            }
            _ => {
                return Err(DnsError {
                    kind: DnsErrorKind::UnsupportedLabel,
                    offset: cursor,
                });
            }
        }
    }
}
