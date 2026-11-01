use std::{
    error::Error,
    io,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use crate::{InterfaceSelector, pin::PinnedInterface};

#[test]
fn link_query_names_only_the_selected_interface_index() -> Result<(), Box<dyn Error>> {
    use netlink_packet_core::{NLM_F_REQUEST, NetlinkPayload};
    use netlink_packet_route::RouteNetlinkMessage;

    let packet = super::query::request(7, 11, 13);
    assert_eq!(packet.header.flags, NLM_F_REQUEST);
    assert_eq!(packet.header.sequence_number, 11);
    assert_eq!(packet.header.port_number, 13);
    let NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetLink(link)) = packet.payload else {
        return Err("query is not RTM_GETLINK".into());
    };
    assert_eq!(link.header.index, 7);
    assert!(link.attributes.is_empty());
    Ok(())
}

#[test]
fn cancellation_and_expired_deadline_stop_vlan_discovery() -> Result<(), Box<dyn Error>> {
    let selector = InterfaceSelector::new("lo")?;
    let selected = PinnedInterface::open(&selector)?;
    let cancelled = AtomicBool::new(true);
    let result = super::pin(
        &selector,
        &selected,
        Instant::now() + Duration::from_secs(1),
        &cancelled,
    );
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::Interrupted)
    );
    let cancelled = AtomicBool::new(false);
    let result = super::pin(&selector, &selected, Instant::now(), &cancelled);
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}

#[test]
fn non_vlan_interface_is_reported_without_a_vlan_pin() -> Result<(), Box<dyn Error>> {
    let selector = InterfaceSelector::new("lo")?;
    let selected = PinnedInterface::open(&selector)?;
    let result = super::pin(
        &selector,
        &selected,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
    )?;
    assert!(result.is_none());
    super::check_unscoped(
        &selector,
        &selected,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
    )?;
    Ok(())
}

#[test]
#[ignore = "uses only a proved private namespace and owned VLAN interfaces"]
fn vlan_pin_retains_parent_and_rejects_stale_or_stacked_scope() -> Result<(), Box<dyn Error>> {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vlan/kernel.py");
    let result = std::process::Command::new("python3")
        .arg(script)
        .arg("--")
        .arg(std::env::current_exe()?)
        .output()?;
    assert!(
        result.status.success(),
        "{} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("cleanup_confirmed=true"));
    Ok(())
}

#[test]
#[ignore = "invoked only by the proved private VLAN namespace fixture"]
fn owned_vlan_pin_child_checks_scope_and_parent() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::MetadataExt;

    let parent_device: u64 = std::env::var("L2_TEST_PARENT_NET_DEVICE")?.parse()?;
    let parent_inode: u64 = std::env::var("L2_TEST_PARENT_NET_INODE")?.parse()?;
    let namespace = std::fs::metadata("/proc/thread-self/ns/net")?;
    assert_ne!(
        (namespace.dev(), namespace.ino()),
        (parent_device, parent_inode)
    );
    let case = std::env::var("L2_TEST_VLAN_PIN_CASE")?;
    let selector = InterfaceSelector::new(&std::env::var("L2_TEST_VLAN_INTERFACE")?)?;
    let selected = PinnedInterface::open(&selector)?;
    let cancelled = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(3);
    let result = super::pin(&selector, &selected, deadline, &cancelled);
    if case == "stacked" {
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );
        return Ok(());
    }
    let pinned = result?.ok_or("VLAN pin missing")?;
    assert_scope_changed(
        super::check_unscoped(&selector, &selected, deadline, &cancelled).err(),
        "VLAN interface was accepted as unscoped",
    )?;
    let info = pinned.info();
    assert_eq!(info.id(), 37);
    assert_eq!(info.protocol(), super::VlanProtocol::Ieee8021Q);
    assert!(info.reorders_headers());
    assert_eq!(
        info.parent_identity().ifindex(),
        std::env::var("L2_TEST_VLAN_PARENT_INDEX")?.parse()?
    );
    assert_eq!(
        info.parent_identity().namespace_device(),
        selected.identity.namespace_device()
    );
    assert_eq!(
        info.parent_identity().namespace_inode(),
        selected.identity.namespace_inode()
    );
    pinned.revalidate(&selector, &selected, deadline, &cancelled)?;
    check_reorder_change(&pinned, &selector, &selected, deadline, &cancelled)?;
    check_parent_change(&pinned, &selector, &selected, deadline, &cancelled)?;
    check_selected_change(&pinned, &selector, &selected, deadline, &cancelled)
}

fn check_reorder_change(
    pinned: &super::VlanPin,
    selector: &InterfaceSelector,
    selected: &PinnedInterface,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(), Box<dyn Error>> {
    ip(&[
        "link",
        "set",
        "dev",
        selector.name(),
        "type",
        "vlan",
        "reorder_hdr",
        "off",
    ])?;
    let changed = pinned
        .revalidate(selector, selected, deadline, cancelled)
        .err();
    ip(&[
        "link",
        "set",
        "dev",
        selector.name(),
        "type",
        "vlan",
        "reorder_hdr",
        "on",
    ])?;
    assert_scope_changed(changed, "changed VLAN scope was accepted")?;
    pinned.revalidate(selector, selected, deadline, cancelled)?;
    Ok(())
}

fn check_parent_change(
    pinned: &super::VlanPin,
    selector: &InterfaceSelector,
    selected: &PinnedInterface,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(), Box<dyn Error>> {
    ip(&["link", "set", "dev", "l2src0", "name", "l2renamed0"])?;
    let renamed = pinned
        .revalidate(selector, selected, deadline, cancelled)
        .err();
    ip(&["link", "set", "dev", "l2renamed0", "name", "l2src0"])?;
    assert_scope_changed(renamed, "a stale parent name remained admitted")?;

    // A new link with the old name must not replace the retained parent
    ip(&["link", "set", "dev", "l2src0", "name", "l2renamed0"])?;
    ip(&["link", "add", "name", "l2src0", "type", "dummy"])?;
    let replaced = pinned
        .revalidate(selector, selected, deadline, cancelled)
        .err();
    ip(&["link", "del", "dev", "l2src0"])?;
    ip(&["link", "set", "dev", "l2renamed0", "name", "l2src0"])?;
    assert_scope_changed(replaced, "a replacement parent remained admitted")
}

fn check_selected_change(
    pinned: &super::VlanPin,
    selector: &InterfaceSelector,
    selected: &PinnedInterface,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(), Box<dyn Error>> {
    // Losing the selected name also invalidates the retained scope
    ip(&["link", "set", "dev", selector.name(), "name", "l2vrenamed0"])?;
    let vlan_renamed = pinned
        .revalidate(selector, selected, deadline, cancelled)
        .err();
    let unscoped_renamed = super::check_unscoped(selector, selected, deadline, cancelled).err();
    ip(&["link", "set", "dev", "l2vrenamed0", "name", selector.name()])?;
    for result in [vlan_renamed, unscoped_renamed] {
        assert_scope_changed(result, "a stale selected interface remained admitted")?;
    }

    ip(&["link", "set", "dev", selector.name(), "name", "l2vrenamed0"])?;
    ip(&["link", "add", "name", selector.name(), "type", "dummy"])?;
    let vlan_replaced = pinned
        .revalidate(selector, selected, deadline, cancelled)
        .err();
    let unscoped_replaced = super::check_unscoped(selector, selected, deadline, cancelled).err();
    ip(&["link", "del", "dev", selector.name()])?;
    ip(&["link", "set", "dev", "l2vrenamed0", "name", selector.name()])?;
    for result in [vlan_replaced, unscoped_replaced] {
        assert_scope_changed(result, "a replacement interface remained admitted")?;
    }
    Ok(())
}

fn assert_scope_changed(error: Option<io::Error>, context: &str) -> Result<(), Box<dyn Error>> {
    let error = error.ok_or_else(|| io::Error::other(context.to_owned()))?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        error
            .get_ref()
            .ok_or("missing VLAN change source")?
            .is::<super::VlanScopeChanged>()
    );
    Ok(())
}

fn ip(arguments: &[&str]) -> Result<(), Box<dyn Error>> {
    let output = std::process::Command::new("ip").args(arguments).output()?;
    if !output.status.success() {
        return Err(io::Error::other(String::from_utf8_lossy(&output.stderr).into_owned()).into());
    }
    Ok(())
}
