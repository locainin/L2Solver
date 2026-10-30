use std::error::Error;

use super::fixture::{CLIENT, START, probe};

#[test]
fn start_matches_independent_scapy_bytes_and_selected_mac() -> Result<(), Box<dyn Error>> {
    let operation = probe(8, 4_096)?;
    assert_eq!(operation.frame(), START);
    assert_eq!(operation.frame().len(), 60);
    assert_eq!(operation.source_mac().bytes(), CLIENT);
    Ok(())
}
