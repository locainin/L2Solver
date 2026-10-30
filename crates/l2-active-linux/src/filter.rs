//! Fixed packet admission filters for narrowly scoped helper operations

use std::io;

use rscap::{
    filter::{BpfInstruction, PacketFilter},
    linux::l2::L2Socket,
};

use crate::intent::{Intent, IntentKind, ListenKind};

#[cfg(test)]
#[path = "../tests/filter/mod.rs"]
mod tests;

// Classic BPF instructions load network-order values from the Ethernet frame
const LOAD_WORD: u16 = 0x20;
const LOAD_HALF: u16 = 0x28;
const LOAD_BYTE: u16 = 0x30;
const LOAD_HALF_INDEXED: u16 = 0x48;
const LOAD_WORD_INDEXED: u16 = 0x40;
const LOAD_HEADER_LENGTH: u16 = 0xb1;
const AND: u16 = 0x54;
const EQUAL: u16 = 0x15;
const GREATER: u16 = 0x25;
const GREATER_EQUAL: u16 = 0x35;
const ANY_BITS: u16 = 0x45;
const JUMP: u16 = 0x05;
const RETURN: u16 = 0x06;
const MAX_INSTRUCTIONS: usize = 128;
// Linux exposes a stripped VLAN tag through this classic BPF metadata offset
const VLAN_TAG_PRESENT: u32 = 0xffff_f030;
// Kernel packet direction is independent of spoofable Ethernet source bytes
const PACKET_TYPE: u32 = 0xffff_f004;
const PACKET_OUTGOING: u32 = 4;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Label {
    Reject,
    BroadcastDestination,
    LocalDestination,
    DiscoveryLldp,
    DiscoveryCdp,
    LldpSecondGroup,
    LldpThirdGroup,
    EapGroup,
    EapLocal,
    EapType,
}

#[derive(Clone, Copy)]
enum JumpField {
    True,
    False,
    Unconditional,
}

struct Patch {
    instruction: usize,
    field: JumpField,
    label: Label,
}

// A small forward-only assembler keeps each fixed rule readable and verifiable
struct Program {
    code: Vec<BpfInstruction>,
    labels: Vec<(Label, usize)>,
    patches: Vec<Patch>,
}

impl Program {
    fn new() -> io::Result<Self> {
        let mut code = Vec::new();
        let mut labels = Vec::new();
        let mut patches = Vec::new();
        code.try_reserve_exact(MAX_INSTRUCTIONS)
            .map_err(io::Error::other)?;
        labels.try_reserve_exact(16).map_err(io::Error::other)?;
        patches
            .try_reserve_exact(MAX_INSTRUCTIONS)
            .map_err(io::Error::other)?;
        Ok(Self {
            code,
            labels,
            patches,
        })
    }

    fn emit(&mut self, code: u16, value: u32) {
        self.code.push(BpfInstruction {
            code,
            jt: 0,
            jf: 0,
            k: value,
        });
    }

    fn mark(&mut self, label: Label) {
        self.labels.push((label, self.code.len()));
    }

    fn branch(&mut self, code: u16, value: u32, yes: Option<Label>, no: Option<Label>) {
        let index = self.code.len();
        self.emit(code, value);
        if let Some(label) = yes {
            self.patches.push(Patch {
                instruction: index,
                field: JumpField::True,
                label,
            });
        }
        if let Some(label) = no {
            self.patches.push(Patch {
                instruction: index,
                field: JumpField::False,
                label,
            });
        }
    }

    fn require(&mut self, code: u16, value: u32) {
        self.branch(code, value, None, Some(Label::Reject));
    }

    fn jump(&mut self, label: Label) {
        let index = self.code.len();
        self.emit(JUMP, 0);
        self.patches.push(Patch {
            instruction: index,
            field: JumpField::Unconditional,
            label,
        });
    }

    fn accept(&mut self) {
        self.emit(RETURN, u32::MAX);
    }

    fn finish(mut self) -> io::Result<Vec<BpfInstruction>> {
        self.mark(Label::Reject);
        self.emit(RETURN, 0);
        for patch in self.patches {
            let target = self
                .labels
                .iter()
                .find(|(label, _)| *label == patch.label)
                .map(|(_, position)| *position)
                .ok_or_else(|| io::Error::other("missing packet-filter label"))?;
            let offset = target
                .checked_sub(patch.instruction + 1)
                .ok_or_else(|| io::Error::other("packet-filter branch is not forward"))?;
            let instruction = self
                .code
                .get_mut(patch.instruction)
                .ok_or_else(|| io::Error::other("invalid packet-filter branch"))?;
            match patch.field {
                JumpField::True => {
                    instruction.jt = u8::try_from(offset).map_err(io::Error::other)?;
                }
                JumpField::False => {
                    instruction.jf = u8::try_from(offset).map_err(io::Error::other)?;
                }
                JumpField::Unconditional => {
                    instruction.k = u32::try_from(offset).map_err(io::Error::other)?;
                }
            }
        }
        Ok(self.code)
    }
}

/// Install and lock the operation's fixed filter before binding the socket
pub fn attach(socket: &L2Socket, intent: &Intent) -> io::Result<()> {
    let mut filter = PacketFilter::from_vec(instructions(intent)?);
    socket.set_filter(&mut filter)?;
    socket.lock_filter()
}

fn instructions(intent: &Intent) -> io::Result<Vec<BpfInstruction>> {
    let mut program = Program::new()?;
    // Reject offloaded VLAN frames before reading the visible Ethernet bytes
    program.emit(LOAD_WORD, VLAN_TAG_PRESENT);
    program.require(EQUAL, 0);
    // Sending is accounted separately; no outgoing frame enters capture
    program.emit(LOAD_WORD, PACKET_TYPE);
    program.branch(EQUAL, PACKET_OUTGOING, Some(Label::Reject), None);
    match intent.kind() {
        IntentKind::Arp { source, target } => arp(
            &mut program,
            u32::from_be_bytes(source.octets()),
            u32::from_be_bytes(target.octets()),
            intent.source_mac().bytes(),
        ),
        IntentKind::Dhcp { transaction } => {
            dhcp(&mut program, transaction.get(), intent.source_mac().bytes());
        }
        IntentKind::Ndp { source, target, .. } => ndp(
            &mut program,
            source.octets(),
            target.octets(),
            intent.source_mac().bytes(),
        ),
        IntentKind::Dot1x => dot1x(&mut program, intent.source_mac().bytes()),
        IntentKind::Listen(ListenKind::Discovery) => discovery(&mut program),
        IntentKind::Listen(ListenKind::Stp) => stp(&mut program),
    }
    program.finish()
}

fn ethernet_type(program: &mut Program, value: u32) {
    program.emit(LOAD_HALF, 12);
    program.require(EQUAL, value);
}

fn arp(program: &mut Program, source: u32, target: u32, local: [u8; 6]) {
    let (prefix, suffix) = mac_parts(local);
    ethernet_type(program, 0x0806);
    // Opcode identifies a reply even when other ARP header fields are malformed
    program.emit(LOAD_HALF, 20);
    program.require(EQUAL, 2);
    // Bind the sender and target addresses to this query's endpoints
    program.emit(LOAD_WORD, 28);
    program.require(EQUAL, target);
    program.emit(LOAD_WORD, 32);
    program.require(EQUAL, prefix);
    program.emit(LOAD_HALF, 36);
    program.require(EQUAL, suffix);
    program.emit(LOAD_WORD, 38);
    program.require(EQUAL, source);
    local_or_broadcast(program, local);
}

fn dhcp(program: &mut Program, transaction: u32, local: [u8; 6]) {
    let (prefix, suffix) = mac_parts(local);
    ethernet_type(program, 0x0800);
    program.emit(LOAD_BYTE, 14);
    program.emit(AND, 0xf0);
    program.require(EQUAL, 0x40);
    program.emit(LOAD_BYTE, 14);
    program.emit(AND, 0x0f);
    program.require(GREATER_EQUAL, 5);
    program.emit(LOAD_BYTE, 23);
    program.require(EQUAL, 17);
    // Reject fragmented datagrams before interpreting any UDP fields
    program.emit(LOAD_HALF, 20);
    program.branch(ANY_BITS, 0x3fff, Some(Label::Reject), None);
    // The IPv4 header length determines where UDP and BOOTP fields begin
    program.emit(LOAD_HEADER_LENGTH, 14);
    program.emit(LOAD_HALF_INDEXED, 14);
    program.require(EQUAL, 67);
    program.emit(LOAD_HALF_INDEXED, 16);
    program.require(EQUAL, 68);
    program.emit(LOAD_WORD_INDEXED, 26);
    program.require(EQUAL, transaction);
    // A caller-selected transaction ID alone cannot authorize another client
    program.emit(LOAD_WORD_INDEXED, 50);
    program.require(EQUAL, prefix);
    program.emit(LOAD_HALF_INDEXED, 54);
    program.require(EQUAL, suffix);
    local_or_broadcast(program, local);
}

fn ndp(program: &mut Program, source: [u8; 16], target: [u8; 16], local: [u8; 6]) {
    ethernet_type(program, 0x86dd);
    local_address(program, local);
    // Admit direct ICMPv6 advertisements addressed to the selected source
    program.emit(LOAD_BYTE, 20);
    program.require(EQUAL, 58);
    program.emit(LOAD_BYTE, 54);
    program.require(EQUAL, 136);
    ipv6_address(program, 38, source);
    ipv6_address(program, 62, target);
    program.accept();
}

fn stp(program: &mut Program) {
    // Match the bridge group and 802.3 LLC envelope before reading a BPDU
    program.emit(LOAD_WORD, 0);
    program.require(EQUAL, 0x0180_c200);
    program.emit(LOAD_HALF, 4);
    program.require(EQUAL, 0);
    program.emit(LOAD_HALF, 12);
    program.branch(GREATER, 1500, Some(Label::Reject), None);
    program.emit(LOAD_BYTE, 14);
    program.require(EQUAL, 0x42);
    program.accept();
}

fn discovery(program: &mut Program) {
    program.emit(LOAD_HALF, 12);
    program.branch(
        EQUAL,
        0x88cc,
        Some(Label::DiscoveryLldp),
        Some(Label::DiscoveryCdp),
    );
    // LLDP uses three fixed bridge multicast destinations
    program.mark(Label::DiscoveryLldp);
    program.emit(LOAD_WORD, 0);
    program.require(EQUAL, 0x0180_c200);
    program.emit(LOAD_HALF, 4);
    program.branch(EQUAL, 0, None, Some(Label::LldpSecondGroup));
    program.accept();
    program.mark(Label::LldpSecondGroup);
    program.branch(EQUAL, 3, None, Some(Label::LldpThirdGroup));
    program.accept();
    program.mark(Label::LldpThirdGroup);
    program.require(EQUAL, 14);
    program.accept();
    // CDP uses its own group with an LLC and SNAP protocol identifier
    program.mark(Label::DiscoveryCdp);
    program.branch(GREATER, 1500, Some(Label::Reject), None);
    program.emit(LOAD_WORD, 0);
    program.require(EQUAL, 0x0100_0ccc);
    program.emit(LOAD_HALF, 4);
    program.require(EQUAL, 0xcccc);
    program.emit(LOAD_WORD, 14);
    program.require(EQUAL, 0xaaaa_0300);
    program.emit(LOAD_WORD, 18);
    program.require(EQUAL, 0x000c_2000);
    program.accept();
}

fn dot1x(program: &mut Program, local: [u8; 6]) {
    let (prefix, suffix) = mac_parts(local);
    ethernet_type(program, 0x888e);
    // Requests may be addressed to the selected interface or the PAE group
    program.emit(LOAD_WORD, 0);
    program.branch(
        EQUAL,
        0x0180_c200,
        Some(Label::EapGroup),
        Some(Label::EapLocal),
    );
    program.mark(Label::EapGroup);
    program.emit(LOAD_HALF, 4);
    program.require(EQUAL, 3);
    program.jump(Label::EapType);
    program.mark(Label::EapLocal);
    program.require(EQUAL, prefix);
    program.emit(LOAD_HALF, 4);
    program.require(EQUAL, suffix);
    program.mark(Label::EapType);
    // EAPOL packet type zero carries an EAP packet; code one is a Request
    program.emit(LOAD_BYTE, 15);
    program.require(EQUAL, 0);
    program.emit(LOAD_BYTE, 18);
    program.require(EQUAL, 1);
    program.accept();
}

fn local_or_broadcast(program: &mut Program, local: [u8; 6]) {
    // Some valid replies use broadcast Ethernet while naming the local client
    program.emit(LOAD_WORD, 0);
    program.branch(
        EQUAL,
        u32::MAX,
        Some(Label::BroadcastDestination),
        Some(Label::LocalDestination),
    );
    program.mark(Label::BroadcastDestination);
    program.emit(LOAD_HALF, 4);
    program.require(EQUAL, u32::from(u16::MAX));
    program.accept();
    program.mark(Label::LocalDestination);
    local_address(program, local);
    program.accept();
}

fn local_address(program: &mut Program, local: [u8; 6]) {
    let (prefix, suffix) = mac_parts(local);
    program.emit(LOAD_WORD, 0);
    program.require(EQUAL, prefix);
    program.emit(LOAD_HALF, 4);
    program.require(EQUAL, suffix);
}

fn ipv6_address(program: &mut Program, offset: u32, address: [u8; 16]) {
    // Compare the complete address as four network-order words
    let (words, _) = address.as_chunks::<4>();
    for (relative, part) in [0_u32, 4, 8, 12].into_iter().zip(words.iter().copied()) {
        program.emit(LOAD_WORD, offset + relative);
        program.require(EQUAL, u32::from_be_bytes(part));
    }
}

fn mac_parts(mac: [u8; 6]) -> (u32, u32) {
    let [first, second, third, fourth, fifth, sixth] = mac;
    (
        u32::from_be_bytes([first, second, third, fourth]),
        u32::from(u16::from_be_bytes([fifth, sixth])),
    )
}
