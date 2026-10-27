//! Shared per-receipt JSON shapes and streaming reconstruction

mod reader;
mod writer;

pub(super) use reader::DecodedSchemaJson;
pub(super) use writer::SchemaJson;

// Bound shape metadata independently of receipt size
const MAX_SCHEMAS: usize = 1024;
const MAX_SCHEMA_BYTES: usize = 512 * 1024;
const MAX_SCHEMA_FIELDS: usize = 4096;

// Encoded containers add two JSON levels plus the outer record envelope
const MAX_SCHEMA_SOURCE_DEPTH: usize = 56;

pub(super) fn within_depth(bytes: &[u8]) -> bool {
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'[' | b'{' => {
                    depth += 1;
                    if depth > MAX_SCHEMA_SOURCE_DEPTH {
                        return false;
                    }
                }
                b']' | b'}' => {
                    let Some(next) = depth.checked_sub(1) else {
                        return false;
                    };
                    depth = next;
                }
                _ => {}
            }
        }
    }
    !quoted && depth == 0
}
