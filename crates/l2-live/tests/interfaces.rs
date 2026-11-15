#[test]
fn sorted_interface_names() -> Result<(), Box<dyn std::error::Error>> {
    let names = l2_live::interfaces()?;
    assert!(names.iter().any(|name| name == "lo"));
    assert!(names.windows(2).all(|pair| match pair {
        [left, right] => left < right,
        _ => false,
    }));
    assert!(names.windows(2).all(|pair| pair.first() != pair.get(1)));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn excludes_sources_without_interface_indices() -> Result<(), Box<dyn std::error::Error>> {
    let names = l2_live::interfaces()?;
    for name in names {
        assert!(
            nix::net::if_::if_nametoindex(name.as_str()).is_ok(),
            "capture source has no kernel interface index: {name}"
        );
    }
    Ok(())
}
