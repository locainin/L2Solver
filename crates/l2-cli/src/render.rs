//! Terminal rendering never writes network-provided control bytes directly

use std::io::{self, Write};

/// Render one MAC address into the output stream
///
/// # Errors
/// Returns the output error when the destination rejects the rendered address
pub fn mac(output: &mut impl Write, address: [u8; 6]) -> io::Result<()> {
    let mut separator = "";
    for byte in address {
        write!(output, "{separator}{byte:02x}")?;
        separator = ":";
    }
    Ok(())
}

/// Render source bytes with terminal controls escaped
///
/// # Errors
/// Returns the output error when the destination rejects the rendered bytes
pub fn bytes(output: &mut impl Write, value: &[u8]) -> io::Result<()> {
    // ASCII escapes retain the original bytes without interpreting terminal commands
    for byte in value.escape_ascii() {
        output.write_all(&[byte])?;
    }
    Ok(())
}
