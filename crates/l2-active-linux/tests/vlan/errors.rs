use std::io;

#[test]
fn revalidation_preserves_unrelated_unsupported_transport_error() {
    let transport_error = io::Error::from_raw_os_error(nix::libc::EOPNOTSUPP);
    let result = super::changed_if_scope_gone_or_unsupported(transport_error);
    assert_eq!(result.raw_os_error(), Some(nix::libc::EOPNOTSUPP));
}

#[test]
fn revalidation_classifies_unsupported_vlan_metadata_as_changed_scope() {
    let unsupported = super::super::unsupported("unsupported VLAN metadata");
    assert_eq!(unsupported.kind(), io::ErrorKind::Unsupported);
    let result = super::changed_if_scope_gone_or_unsupported(unsupported);
    assert_eq!(result.kind(), io::ErrorKind::InvalidData);
    assert!(
        matches!(result.get_ref(), Some(source) if source.is::<super::super::VlanScopeChanged>())
    );
}
