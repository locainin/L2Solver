//! Count decoded node details before constructing their JSON values

use super::{canonical_json::CanonicalJson, scratch::Scratch};
use crate::{evidence::MAX_NODE_DETAILS_BYTES, serialization::CountWriter};
use serde::Serialize;
use serde_json::value::RawValue;
use std::io::{self, Write};

pub(super) struct DetailBudget {
    bytes: CountWriter,
    scratch: Scratch,
    fields: usize,
}

pub(super) fn count_details(
    count: impl FnOnce(&mut DetailBudget) -> io::Result<()>,
) -> io::Result<usize> {
    let mut budget = DetailBudget {
        bytes: CountWriter::new(MAX_NODE_DETAILS_BYTES),
        scratch: Scratch::new(None)?,
        fields: 0,
    };
    let result = count(&mut budget);
    // Report the size limit even when Serde wraps the counter's write error
    if budget.bytes.exceeded() {
        return Err(io::Error::other("evidence node details exceed their limit"));
    }
    result?;
    Ok(budget.bytes.written())
}

impl DetailBudget {
    pub(super) fn begin_object(&mut self) -> io::Result<()> {
        self.bytes.write_all(b"{")
    }

    pub(super) fn end_object(&mut self) -> io::Result<()> {
        self.bytes.write_all(b"}")
    }

    fn field_key(&mut self, key: &str) -> io::Result<()> {
        if self.fields != 0 {
            self.bytes.write_all(b",")?;
        }
        serde_json::to_writer(&mut self.bytes, key).map_err(io::Error::other)?;
        self.bytes.write_all(b":")?;
        self.fields += 1;
        Ok(())
    }

    pub(super) fn field<T: Serialize + ?Sized>(&mut self, key: &str, value: &T) -> io::Result<()> {
        self.field_key(key)?;
        serde_json::to_writer(&mut self.bytes, value).map_err(io::Error::other)
    }

    pub(super) fn raw_field(&mut self, key: &str, value: &RawValue) -> io::Result<()> {
        self.field_key(key)?;
        self.raw(value)
    }

    pub(super) fn raw(&mut self, value: &RawValue) -> io::Result<()> {
        // Raw values need canonical ordering and duplicate-key handling before counting
        serde_json::to_writer(
            &mut self.bytes,
            &CanonicalJson {
                bytes: value.get().as_bytes(),
                scratch: &self.scratch,
            },
        )
        .map_err(io::Error::other)
    }
}
