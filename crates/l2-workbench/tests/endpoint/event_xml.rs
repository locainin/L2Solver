use super::support::sysmon_event_xml;
use l2_workbench::endpoint::parse_event_xml;
use std::{error::Error, fmt::Write};

fn event_with_attributes(duplicate: bool) -> Result<String, std::fmt::Error> {
    let mut attributes = String::new();
    // Extra attributes exercise the parser's larger duplicate-name set
    for index in 0..256 {
        write!(attributes, " field{index}=\"value\"")?;
    }
    if duplicate {
        attributes.push_str(" field0=\"repeated\"");
    }
    Ok(sysmon_event_xml().replace("<Provider ", &format!("<Provider{attributes} ")))
}

#[test]
fn many_unique_selected_event_fields() -> Result<(), Box<dyn Error>> {
    let xml = event_with_attributes(false)?;
    let report = parse_event_xml(xml.as_bytes())?;
    let event = report.events.first().ok_or("event missing")?;
    assert_eq!(event.provider.as_deref(), Some("Microsoft-Windows-Sysmon"));
    assert_eq!(event.event_id.as_deref(), Some("2"));
    Ok(())
}

#[test]
fn duplicate_unselected_many_unique_names() -> Result<(), Box<dyn Error>> {
    let xml = event_with_attributes(true)?;
    assert!(parse_event_xml(xml.as_bytes()).is_err());
    Ok(())
}
