use l2_audit::AuditError;

#[test]
fn displays_terminal_error_reasons() {
    assert_eq!(
        AuditError::Limit("frame count").to_string(),
        "survey frame count limit exceeded"
    );
    assert_eq!(
        AuditError::Policy("bad VLAN").to_string(),
        "invalid survey policy: bad VLAN"
    );
    assert_eq!(
        AuditError::Terminated.to_string(),
        "survey is terminal after an earlier collection error"
    );
}
