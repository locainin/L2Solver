//! Fixed capture admission for IPv4 `VRRPv3` candidates

use std::num::NonZeroU8;

use super::{
    AND, ANY_BITS, EQUAL, GREATER_EQUAL, LOAD_BYTE, LOAD_HALF, LOAD_HEADER_LENGTH, LOAD_WORD,
    Label, Program, ethernet_type, local_address,
};

// Classic BPF indexed loads and arithmetic against the IPv4-header length
const LOAD_BYTE_INDEXED: u16 = 0x50;
const GREATER_EQUAL_X: u16 = 0x3d;
const SUBTRACT_X: u16 = 0x1c;

#[cfg(test)]
#[path = "../../tests/filter/vrrp.rs"]
mod tests;

pub(super) fn vrrp(program: &mut Program, vrid: Option<NonZeroU8>) {
    ethernet_type(program, 0x0800);
    local_address(program, [1, 0, 0x5e, 0, 0, 0x12]);
    program.emit(LOAD_WORD, 30);
    program.require(EQUAL, 0xe000_0012);
    program.emit(LOAD_BYTE, 23);
    program.require(EQUAL, 112);

    // A non-initial fragment cannot reliably identify the original version
    program.emit(LOAD_HALF, 20);
    program.branch(ANY_BITS, 0x1fff, Some(Label::Reject), None);

    // Only an IPv4 header can identify the position of a VRRP version field
    program.emit(LOAD_BYTE, 14);
    program.emit(AND, 0xf0);
    program.require(EQUAL, 0x40);
    // Bound the variable IPv4 header before reading any protocol fields
    program.emit(LOAD_BYTE, 14);
    program.emit(AND, 0x0f);
    program.require(GREATER_EQUAL, 5);
    program.emit(LOAD_HEADER_LENGTH, 14);
    program.emit(LOAD_HALF, 16);
    program.require(GREATER_EQUAL_X, 0);
    program.emit(SUBTRACT_X, 0);
    program.require(GREATER_EQUAL, if vrid.is_some() { 2 } else { 1 });

    // VRRPv2 may contain authentication data, so admit only the v3 nibble
    program.emit(LOAD_BYTE_INDEXED, 14);
    program.emit(AND, 0xf0);
    program.require(EQUAL, 0x30);
    if let Some(vrid) = vrid {
        program.emit(LOAD_BYTE_INDEXED, 15);
        program.require(EQUAL, u32::from(vrid.get()));
    }
    program.accept();
}
