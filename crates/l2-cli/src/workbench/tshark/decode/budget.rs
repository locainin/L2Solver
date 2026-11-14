use serde::de;
use std::{error::Error, fmt, mem::size_of};

// B-tree storage is not exposed by the standard library, so charge a generous
// allowance for each object and each inserted key before the tree can grow
pub(super) const OBJECT_BYTES: usize = 1024;
pub(super) const OBJECT_ENTRY_BYTES: usize = 256;
pub(super) const SET_ENTRY_BYTES: usize = 1024;
pub(super) const MAX_DEPTH: usize = 96;

#[derive(Debug)]
pub(in crate::workbench::tshark) enum DecodeError {
    MemoryLimit {
        limit: usize,
        used: usize,
        requested: usize,
    },
    NestingLimit,
    Allocation,
    InvalidPacket(&'static str),
    Json(serde_json::Error),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemoryLimit {
                limit,
                used,
                requested,
            } => write!(
                formatter,
                "TShark decoded JSON memory budget exceeded: limit {limit}, used {used}, requested {requested} bytes"
            ),
            Self::NestingLimit => formatter.write_str("TShark decoded JSON nesting limit exceeded"),
            Self::Allocation => formatter.write_str("TShark decoded JSON allocation failed"),
            Self::InvalidPacket(message) => formatter.write_str(message),
            Self::Json(error) => write!(formatter, "invalid TShark JSON: {error}"),
        }
    }
}

impl Error for DecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

pub(super) struct DecodeBudget {
    limit: usize,
    used: usize,
    failure: Option<DecodeError>,
}

impl DecodeBudget {
    pub(super) fn new(
        limit: usize,
        raw_capacity: usize,
        bytes: &[u8],
    ) -> Result<Self, DecodeError> {
        let mut budget = Self {
            limit,
            used: 0,
            failure: None,
        };
        budget.admit(raw_capacity)?;
        let escaped_string_bytes = longest_escaped_string(bytes);
        if escaped_string_bytes != 0 {
            // Escaped strings can make serde_json grow a temporary scratch Vec
            // The wire length bounds decoded bytes; allow old and new buffers during growth
            let scratch =
                escaped_string_bytes
                    .max(8)
                    .checked_mul(3)
                    .ok_or(DecodeError::MemoryLimit {
                        limit,
                        used: budget.used,
                        requested: usize::MAX,
                    })?;
            budget.admit(scratch)?;
        }
        Ok(budget)
    }

    const fn admit(&mut self, bytes: usize) -> Result<(), DecodeError> {
        if bytes > self.limit - self.used {
            return Err(DecodeError::MemoryLimit {
                limit: self.limit,
                used: self.used,
                requested: bytes,
            });
        }
        self.used += bytes;
        Ok(())
    }

    pub(super) fn charge<E: de::Error>(&mut self, bytes: usize) -> Result<(), E> {
        self.admit(bytes).map_err(|error| self.fail(error))
    }

    pub(super) fn fail<E: de::Error>(&mut self, error: DecodeError) -> E {
        // Keep the typed failure when Serde wraps its own error
        let wrapped = E::custom(&error);
        self.failure = Some(error);
        wrapped
    }

    pub(super) const fn take_failure(&mut self) -> Option<DecodeError> {
        self.failure.take()
    }

    pub(super) fn copy_string<E: de::Error>(&mut self, text: &str) -> Result<String, E> {
        self.charge(text.len())?;
        let mut output = String::new();
        output
            .try_reserve_exact(text.len())
            .map_err(|_| self.fail(DecodeError::Allocation))?;
        // Admit any excess capacity the allocator reports before retaining it
        self.charge(output.capacity().saturating_sub(text.len()))?;
        output.push_str(text);
        Ok(output)
    }

    pub(super) fn reserve_one<T, E: de::Error>(&mut self, values: &mut Vec<T>) -> Result<(), E> {
        if values.len() < values.capacity() {
            return Ok(());
        }
        let capacity = values
            .capacity()
            .checked_mul(2)
            .map(|capacity| capacity.max(4))
            .ok_or_else(|| self.fail(DecodeError::Allocation))?;
        let bytes = capacity
            .checked_mul(size_of::<T>())
            .ok_or_else(|| self.fail(DecodeError::Allocation))?;
        // Both the old and replacement buffers remain charged during growth
        self.charge(bytes)?;
        values
            .try_reserve_exact(capacity - values.len())
            .map_err(|_| self.fail(DecodeError::Allocation))?;
        let extra = values
            .capacity()
            .saturating_sub(capacity)
            .checked_mul(size_of::<T>())
            .ok_or_else(|| self.fail(DecodeError::Allocation))?;
        self.charge(extra)
    }
}

// Count escaped wire strings without interpreting JSON; Serde validates the syntax
fn longest_escaped_string(bytes: &[u8]) -> usize {
    let mut start = None;
    let mut escaped = false;
    let mut has_escape = false;
    let mut longest = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        if let Some(open) = start {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
                has_escape = true;
            } else if byte == b'"' {
                if has_escape {
                    longest = longest.max(index - open);
                }
                start = None;
            }
        } else if byte == b'"' {
            start = Some(index + 1);
            has_escape = false;
        }
    }
    // An unfinished string can still have filled the parser's scratch buffer
    if let Some(open) = start
        && has_escape
    {
        longest = longest.max(bytes.len() - open);
    }
    longest
}
