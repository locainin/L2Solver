//! Fixed capture admission for one unicast MPLS endpoint

use super::{Program, ethernet_type, local_address};

#[cfg(test)]
#[path = "../../tests/filter/mpls.rs"]
mod tests;

pub(super) fn mpls(program: &mut Program, local_mac: [u8; 6]) {
    // Only MPLS addressed to the admitted local unicast endpoint crosses IPC
    ethernet_type(program, 0x8847);
    local_address(program, local_mac);
    program.accept();
}
