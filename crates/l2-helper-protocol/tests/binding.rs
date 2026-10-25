use l2_helper_protocol::{InterfaceBindingRequest, ProtocolError};

#[test]
fn preserves_binding_identity() -> Result<(), Box<dyn std::error::Error>> {
    let binding = InterfaceBindingRequest::new(41, 99, 7, 101)?;
    let mut bytes = [0_u8; InterfaceBindingRequest::ENCODED_LENGTH];
    binding.encode(&mut bytes)?;
    assert_eq!(InterfaceBindingRequest::decode(&bytes)?, binding);
    assert_eq!(binding.namespace_device(), 41);
    assert_eq!(binding.namespace_inode(), 99);
    assert_eq!(binding.ifindex(), 7);
    assert_eq!(binding.datalink(), 101);
    Ok(())
}

#[test]
fn checks_binding_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let binding = InterfaceBindingRequest::new(41, 99, 7, 101)?;

    // Every incomplete prefix reports the missing fixed-width payload
    for length in 0..InterfaceBindingRequest::ENCODED_LENGTH {
        assert_eq!(
            InterfaceBindingRequest::decode(&vec![0; length]),
            Err(ProtocolError::InputTooShort {
                needed: InterfaceBindingRequest::ENCODED_LENGTH,
                available: length,
            })
        );
    }
    assert_eq!(
        InterfaceBindingRequest::decode(&[0; InterfaceBindingRequest::ENCODED_LENGTH + 1]),
        Err(ProtocolError::TrailingBytes)
    );

    // A short destination is rejected before any byte can be written
    let mut short = [0xa5; InterfaceBindingRequest::ENCODED_LENGTH - 1];
    assert_eq!(
        binding.encode(&mut short),
        Err(ProtocolError::OutputTooShort {
            needed: InterfaceBindingRequest::ENCODED_LENGTH,
            available: InterfaceBindingRequest::ENCODED_LENGTH - 1,
        })
    );
    assert!(short.iter().all(|byte| *byte == 0xa5));

    // Extra destination capacity remains valid and receives one complete payload
    let mut larger = [0; InterfaceBindingRequest::ENCODED_LENGTH + 1];
    assert_eq!(
        binding.encode(&mut larger)?,
        InterfaceBindingRequest::ENCODED_LENGTH
    );
    assert_eq!(
        InterfaceBindingRequest::decode(&larger[..InterfaceBindingRequest::ENCODED_LENGTH])?,
        binding
    );
    Ok(())
}

#[test]
fn zero_unknown_binding_identity_rejected() {
    assert_eq!(
        InterfaceBindingRequest::new(0, 1, 1, 1),
        Err(ProtocolError::InvalidInterfaceBinding)
    );
    assert_eq!(
        InterfaceBindingRequest::new(1, 1, 0, 1),
        Err(ProtocolError::InvalidInterfaceBinding)
    );
    assert_eq!(
        InterfaceBindingRequest::new(1, 1, 1, 0),
        Err(ProtocolError::InvalidInterfaceBinding)
    );
}
