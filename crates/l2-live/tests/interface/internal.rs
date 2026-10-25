use super::{
    InterfaceSnapshot, LiveInterfaceIdentity, pin, snapshot as current_snapshot,
    validate_bound_identity, validate_current_identity,
};

#[cfg(target_os = "linux")]
use super::packet_socket_ifindex;

fn snapshot(ifindex: u32, interface_inode: u64) -> InterfaceSnapshot {
    InterfaceSnapshot {
        namespace_device: 11,
        namespace_inode: 22,
        interface_device: 33,
        interface_inode,
        ifindex,
    }
}

#[test]
fn name_rebinding_while_libpcap() {
    let result = validate_bound_identity(snapshot(7, 44), 7, snapshot(8, 55), 1);
    assert!(result.is_err());
}

#[test]
fn rejects_capture_socket_bound_interface() {
    let result = validate_bound_identity(snapshot(7, 44), 9, snapshot(7, 44), 1);
    assert!(result.is_err());
}

#[test]
fn socket_without_bound_interface_index() {
    let result = validate_bound_identity(snapshot(7, 44), 0, snapshot(7, 44), 1);
    assert!(result.is_err());
}

#[test]
#[cfg(target_os = "linux")]
fn non_packet_socket_address_families() -> Result<(), Box<dyn std::error::Error>> {
    let socket_address: std::net::SocketAddr = "127.0.0.1:0".parse()?;
    let address = nix::sys::socket::SockaddrStorage::from(socket_address);

    assert!(packet_socket_ifindex(&address).is_err());
    Ok(())
}

#[test]
fn interface_identity_rejects_reused_ifindex() -> Result<(), Box<dyn std::error::Error>> {
    let expected = validate_bound_identity(snapshot(7, 44), 7, snapshot(7, 44), 1)?;

    let result = validate_current_identity(expected, snapshot(7, 55), 7, snapshot(7, 55), 1);

    assert!(result.is_err());
    Ok(())
}

#[test]
fn retains_namespace_ifindex_and_datalink() -> Result<(), Box<dyn std::error::Error>> {
    let identity = validate_bound_identity(snapshot(7, 44), 7, snapshot(7, 44), 101)?;

    let _: LiveInterfaceIdentity = identity;
    assert_eq!(identity.namespace_device(), 11);
    assert_eq!(identity.namespace_inode(), 22);
    assert_eq!(identity.interface_device(), 33);
    assert_eq!(identity.interface_inode(), 44);
    assert_eq!(identity.ifindex(), 7);
    assert_eq!(identity.datalink(), 101);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn pins_real_namespace_interface_descriptors() -> Result<(), Box<dyn std::error::Error>> {
    let pinned = pin("lo")?;

    assert_eq!(pinned.identity(), current_snapshot("lo")?);
    super::validate_pinned_descriptors(&pinned)?;
    Ok(())
}
