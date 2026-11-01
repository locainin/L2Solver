//! Fixed receive filter for the selected Ethernet ISL multicast profiles

use super::{AND, EQUAL, LOAD_BYTE, LOAD_WORD, Program};

#[cfg(test)]
#[path = "../../tests/filter/isl.rs"]
mod tests;

/// Admit Ethernet ISL candidates in both Cisco multicast prefix ranges
pub(super) fn isl(program: &mut Program) {
    // Mask only the bit that differs between the two approved 40-bit prefixes
    program.emit(LOAD_WORD, 0);
    program.emit(AND, 0xfdff_ffff);
    program.require(EQUAL, 0x0100_0c00);
    program.emit(LOAD_BYTE, 4);
    program.require(EQUAL, 0);
    // The high nibble identifies Ethernet; all sixteen USER values are allowed
    program.emit(LOAD_BYTE, 5);
    program.emit(AND, 0xf0);
    program.require(EQUAL, 0);
    // Do not inspect LLC or length here; malformed scoped frames remain visible
    program.accept();
}
