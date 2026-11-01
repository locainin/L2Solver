//! Fixed receive filters for the selected DTP and VTP multicast profiles

use super::{EQUAL, GREATER, GREATER_EQUAL, LOAD_HALF, LOAD_WORD, Label, Program};

#[cfg(test)]
#[path = "../../tests/filter/switching.rs"]
mod tests;

/// Admit identifiable DTP frames, including malformed protocol content
pub(super) fn dtp(program: &mut Program) {
    cisco_snap(program, 0x2004);
}

/// Admit identifiable VTP frames, including malformed protocol content
pub(super) fn vtp(program: &mut Program) {
    cisco_snap(program, 0x2003);
}

fn cisco_snap(program: &mut Program, protocol: u32) {
    // Limit visibility to Cisco's reserved control-plane multicast address
    program.emit(LOAD_WORD, 0);
    program.require(EQUAL, 0x0100_0ccc);
    program.emit(LOAD_HALF, 4);
    program.require(EQUAL, 0xcccc);
    // The SNAP signature must fit within the declared 802.3 payload
    program.emit(LOAD_HALF, 12);
    program.require(GREATER_EQUAL, 8);
    program.branch(GREATER, 1500, Some(Label::Reject), None);
    program.emit(LOAD_WORD, 14);
    program.require(EQUAL, 0xaaaa_0300);
    program.emit(LOAD_WORD, 18);
    program.require(EQUAL, 0x000c_0000 | protocol);
    // Parsing and structural validation happen after kernel admission
    program.accept();
}
