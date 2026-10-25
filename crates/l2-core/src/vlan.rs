// The typed tag preserves the original TPID and all TCI bits for later protocol layers
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VlanTag {
    /// Tag Protocol Identifier from the wire
    pub tpid: u16,
    /// Tag Control Information from the wire
    pub tci: u16,
}
