//! Shared cooked TCP fixtures for consumers of retained packet facts

#[path = "../../../../tests/fixtures/cooked.rs"]
mod cooked;
use crate::{case_support::located_records, tcp};
use l2_capture::{CapturedFrame, InterfaceId};
use l2_workbench::{
    investigation::{BuildInput, BuildResult, build},
    sha256,
};
use std::error::Error;

pub fn frame(
    version: u16,
    ifindex: u32,
    destination_port: u16,
    flags: u8,
) -> Result<CapturedFrame, Box<dyn Error>> {
    let ethernet = tcp::tcp(false, 101, flags, b"data")?;
    let mut bytes = ethernet.bytes().to_vec();
    bytes
        .get_mut(36..38)
        .ok_or("TCP destination port missing")?
        .copy_from_slice(&destination_port.to_be_bytes());
    cooked::cooked(
        &bytes,
        version,
        InterfaceId {
            section: 0,
            index: 0,
        },
        ifindex,
    )
}

pub fn case(frames: Vec<CapturedFrame>) -> Result<BuildResult, Box<dyn Error>> {
    let (records, length) = located_records(frames)?;
    build(BuildInput {
        label: "cooked capture",
        length,
        sha256_hex: &sha256(b"cooked analysis fixture"),
        frames_seen: u64::try_from(records.len())?,
        records: &records,
    })
}
