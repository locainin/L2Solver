use l2_active_linux::InterfaceSelector;
use std::io;

#[test]
fn explicit_linux_names_are_preserved() -> io::Result<()> {
    for name in ["eth0", "wlp2s0", "veth-1234", "abcdefghijklmno"] {
        assert_eq!(InterfaceSelector::new(name)?.name(), name);
    }
    Ok(())
}

#[test]
fn invalid_names_cannot_select_an_interface() {
    for name in [
        "",
        ".",
        "..",
        "eth/0",
        "eth:0",
        "eth 0",
        "eth\n0",
        "eth\0x",
        "abcdefghijklmnop",
    ] {
        assert_eq!(
            InterfaceSelector::new(name).err().map(|error| error.kind()),
            Some(io::ErrorKind::InvalidInput),
            "invalid selector {name:?} was accepted"
        );
    }
}
