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
