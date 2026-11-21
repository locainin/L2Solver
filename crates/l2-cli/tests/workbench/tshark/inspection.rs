use std::error::Error;

#[test]
fn plugin_inventory_fields() -> Result<(), Box<dyn Error>> {
    let records = super::parse_plugins(
        b"one.so\t1.2\tdissector\t/path/one.so\n\ntwo\t2\tcodec\t/path/two\n",
    )?;
    let fields: Vec<_> = records
        .iter()
        .map(|record| {
            (
                record.name.as_str(),
                record.version.as_str(),
                record.kind.as_str(),
                record.path.as_str(),
            )
        })
        .collect();
    assert_eq!(
        fields,
        [
            ("one.so", "1.2", "dissector", "/path/one.so"),
            ("two", "2", "codec", "/path/two")
        ]
    );

    for malformed in [
        "one\t1\tdissector\t/path\textra\n",
        "\t1\tdissector\t/path\n",
        "one\t\tdissector\t/path\n",
        "one\t1\t\t/path\n",
        "one\t1\tdissector\t\n",
        "one\t1\tdissector\n",
    ] {
        assert!(
            super::parse_plugins(malformed.as_bytes()).is_err(),
            "{malformed:?}"
        );
    }
    assert!(super::parse_plugins(b"\xff").is_err());
    Ok(())
}

#[test]
fn preference_record_count() -> Result<(), Box<dyn Error>> {
    assert_eq!(super::preference_count(b"")?, 0);
    assert_eq!(
        super::preference_count(b"\n  \n# comment\n  # indented\n")?,
        0
    );
    assert_eq!(
        super::preference_count(
            b"\n # comment\nfirst: one\n\nsecond: two\n # another\nthird: three\n"
        )?,
        3
    );
    assert!(super::preference_count(b"\xff").is_err());
    Ok(())
}
