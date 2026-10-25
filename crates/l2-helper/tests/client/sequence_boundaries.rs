use super::*;

#[test]
fn sequence_exhaustion_terminal_without_wrapping() -> Result<(), Box<dyn std::error::Error>> {
    let (transport, _helper) = crate::local_transport_pair()?;
    let client = FrontendClient::new(transport, SessionId::new([0x71; 16])?);
    let clone = client.try_clone()?;
    client
        .state
        .next_sequence
        .store(u64::MAX - 1, Ordering::Relaxed);
    assert_eq!(
        client
            .next_sequence()
            .map_err(|error| error.to_helper_error())?,
        u64::MAX - 1
    );
    // The terminal counter value is reserved rather than wrapping to zero
    assert!(clone.next_sequence().is_err());
    assert_eq!(client.state.next_sequence.load(Ordering::Relaxed), u64::MAX);
    assert!(matches!(client.hello(), Err(HelperError::SessionPoisoned)));
    assert!(matches!(
        clone.receive_next(),
        Err(HelperError::SessionPoisoned)
    ));
    assert!(client.next_sequence().is_err());
    assert_eq!(client.state.next_sequence.load(Ordering::Relaxed), u64::MAX);
    Ok(())
}
