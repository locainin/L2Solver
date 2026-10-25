use l2_capture::{CaptureMetadata, InterfaceId, LinuxInterfaceIdentity};

#[test]
fn linux_interface_identity_zero_component() {
    for (namespace_device, namespace_inode, interface_device, interface_inode) in [
        (0, 12, 13, 14),
        (11, 0, 13, 14),
        (11, 12, 0, 14),
        (11, 12, 13, 0),
    ] {
        assert!(
            LinuxInterfaceIdentity::new(
                namespace_device,
                namespace_inode,
                interface_device,
                interface_inode,
                15,
            )
            .is_err()
        );
    }
    assert!(LinuxInterfaceIdentity::new(11, 12, 13, 14, 0).is_err());
}

#[test]
fn metadata_exact_linux_interface_identity() -> Result<(), Box<dyn std::error::Error>> {
    let identity = LinuxInterfaceIdentity::new(11, 12, 13, 14, 15)?;
    let metadata = CaptureMetadata::unknown(
        InterfaceId {
            section: 0,
            index: 0,
        },
        64,
    )
    .with_linux_interface(identity);

    assert_eq!(metadata.linux_interface(), Some(identity));
    assert_eq!(identity.namespace_device(), 11);
    assert_eq!(identity.namespace_inode(), 12);
    assert_eq!(identity.interface_device(), 13);
    assert_eq!(identity.interface_inode(), 14);
    assert_eq!(identity.ifindex(), 15);
    Ok(())
}
