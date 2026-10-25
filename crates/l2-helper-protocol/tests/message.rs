use l2_helper_protocol::MessageKind;

#[test]
fn message_kind_wire_values_stable() {
    // Names and numbers are part of the small helper protocol contract
    let cases = [
        (MessageKind::Hello, 1, "hello"),
        (MessageKind::OpenReceive, 2, "open-receive"),
        (MessageKind::ReceiveNext, 3, "receive-next"),
        (MessageKind::Cancel, 4, "cancel"),
        (MessageKind::Close, 5, "close"),
    ];
    for (kind, wire_value, name) in cases {
        assert_eq!(kind.wire_value(), wire_value);
        assert_eq!(kind.to_string(), name);
    }
}
