//! Fixed kernel admission profile for `HSRPv1` over IPv4

#[cfg(test)]
#[path = "../../tests/filter/hsrp.rs"]
mod tests;

use super::{
    AND, ANY_BITS, EQUAL, GREATER_EQUAL, LOAD_BYTE, LOAD_HALF, LOAD_HALF_INDEXED,
    LOAD_HEADER_LENGTH, LOAD_WORD, Label, Program, ethernet_type,
};

// Classic BPF operations whose right-hand operand is the header-length register
const GREATER_EQUAL_INDEX: u16 = 0x3d;
const SUBTRACT_INDEX: u16 = 0x1c;
const LOAD_BYTE_INDEXED: u16 = 0x50;
const HSRP_PORT: u32 = 1985;

pub(super) fn hsrp(program: &mut Program, group: Option<u8>) {
    // Fix the Ethernet and IPv4 multicast scope before inspecting payload bytes
    ethernet_type(program, 0x0800);
    program.emit(LOAD_WORD, 0);
    program.require(EQUAL, 0x0100_5e00);
    program.emit(LOAD_HALF, 4);
    program.require(EQUAL, 2);
    program.emit(LOAD_BYTE, 14);
    program.emit(AND, 0xf0);
    program.require(EQUAL, 0x40);
    program.emit(LOAD_BYTE, 14);
    program.emit(AND, 0x0f);
    program.require(GREATER_EQUAL, 5);
    program.emit(LOAD_BYTE, 23);
    program.require(EQUAL, 17);
    program.emit(LOAD_WORD, 30);
    program.require(EQUAL, 0xe000_0002);

    // A later fragment does not contain a UDP header; selected groups need an unfragmented datagram
    program.emit(LOAD_HALF, 20);
    let fragment_bits = if group.is_some() { 0x3fff } else { 0x1fff };
    program.branch(ANY_BITS, fragment_bits, Some(Label::Reject), None);

    // X holds the IPv4 header length, including any options
    program.emit(LOAD_HEADER_LENGTH, 14);
    program.emit(LOAD_HALF, 16);
    program.require(GREATER_EQUAL_INDEX, 0);
    program.emit(SUBTRACT_INDEX, 0);
    let minimum_udp = if group.is_some() { 15 } else { 9 };
    program.require(GREATER_EQUAL, minimum_udp);

    // Both declared lengths must cover every byte used for identification
    program.emit(LOAD_HALF_INDEXED, 14);
    program.require(EQUAL, HSRP_PORT);
    program.emit(LOAD_HALF_INDEXED, 16);
    program.require(EQUAL, HSRP_PORT);
    program.emit(LOAD_HALF_INDEXED, 18);
    program.require(GREATER_EQUAL, minimum_udp);
    program.emit(LOAD_BYTE_INDEXED, 22);
    program.require(EQUAL, 0);
    if let Some(group) = group {
        program.emit(LOAD_BYTE_INDEXED, 28);
        program.require(EQUAL, u32::from(group));
    }
    // Kernel packet loads reject an identifier that was not captured
    program.accept();
}
