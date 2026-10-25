use super::common::{
    EndpointImportError, MAX_ENDPOINT_RECORDS, error, source_id, source_length, source_range,
};
use quick_xml::{Reader, events::Event};
use serde::Serialize;
use std::collections::BTreeMap;

const MAX_EVENT_XML_BYTES: usize = 16 * 1024 * 1024;
const MAX_EVENT_FIELDS: usize = 256;
const MAX_EVENT_TEXT_BYTES: usize = 4096;

/// Sysmon Event 2 fields retained as source-reported text
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SysmonTimeChange {
    /// Process GUID reported by Sysmon
    pub process_guid: String,
    /// Decimal process ID reported by Sysmon, when valid
    pub process_id: Option<u32>,
    /// Process image path reported by Sysmon
    pub image: String,
    /// Target file path reported by Sysmon
    pub target_filename: String,
    /// Previous creation-time text reported by Sysmon
    pub previous_creation_time: String,
    /// New creation-time text reported by Sysmon
    pub creation_time: String,
}

/// One parsed Windows Event XML record with its exact original element range
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventXmlRecord {
    /// Provider name from the System/Provider element
    pub provider: Option<String>,
    /// Event ID text from the System/EventID element
    pub event_id: Option<String>,
    /// Event record ID text from System/EventRecordID
    pub record_id: Option<String>,
    /// `SystemTime` attribute retained as original text
    pub system_time: Option<String>,
    /// Named event data in the order-independent canonical map
    pub named_data: BTreeMap<String, String>,
    /// Parsed Sysmon Event 2 fields when the required values are present
    pub sysmon_time_change: Option<SysmonTimeChange>,
    /// Exact element range in the exported XML bytes
    pub source_range: crate::evidence::SourceRange,
}

/// Bounded event XML import with source identity and parser omissions
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EventXmlReport {
    /// SHA-256 identity of the exact exported XML bytes
    pub source_sha256: String,
    /// Exact XML source length in bytes
    pub source_length: u64,
    /// Parsed Event elements in source order
    pub events: Vec<EventXmlRecord>,
    /// Event elements omitted after the retained-record limit
    pub omitted_events: u64,
    /// False when parsed event detail was omitted
    pub complete: bool,
    /// Limits on source authenticity and event interpretation
    pub limitations: Vec<String>,
}

struct EventXmlOutput {
    report: EventXmlReport,
}

/// Parse exported Windows Event XML without converting timestamps or asserting authenticity
///
/// # Errors
/// Rejects malformed XML, duplicate named fields, oversized values, or incomplete elements
pub fn parse_event_xml(bytes: &[u8]) -> Result<EventXmlReport, EndpointImportError> {
    if bytes.len() > MAX_EVENT_XML_BYTES {
        return Err(error("event XML source exceeds its byte limit"));
    }
    let report = empty_report(bytes)?;
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut buffer = Vec::new();
    let mut path = Vec::new();
    let mut active: Option<EventBuilder> = None;
    let mut output = EventXmlOutput { report };
    loop {
        let event_start = reader_offset(&reader)?;
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|_| error("event XML is malformed or truncated"))?;
        if !process_xml_event(
            event,
            event_start,
            &reader,
            &mut path,
            &mut active,
            &mut output,
        )? {
            break;
        }
        buffer.clear();
    }
    if active.is_some() || !path.is_empty() {
        return Err(error("event XML ended with an open element"));
    }
    output.report.complete = output.report.omitted_events == 0;
    Ok(output.report)
}

fn reader_offset(reader: &Reader<&[u8]>) -> Result<usize, EndpointImportError> {
    usize::try_from(reader.buffer_position())
        .map_err(|_| error("event XML byte offset exceeds the platform limit"))
}

fn process_xml_event(
    event: Event<'_>,
    event_start: usize,
    reader: &Reader<&[u8]>,
    path: &mut Vec<String>,
    active: &mut Option<EventBuilder>,
    output: &mut EventXmlOutput,
) -> Result<bool, EndpointImportError> {
    match event {
        Event::Start(start) => {
            reject_nested_scalar(active.as_ref())?;
            process_start(&start, path, active, event_start, reader)?;
        }
        Event::Empty(start) => {
            reject_nested_scalar(active.as_ref())?;
            process_empty(
                &start,
                path,
                active,
                event_start,
                reader_offset(reader)?,
                reader,
                output,
            )?;
        }
        Event::Text(text) => {
            if let Some(builder) = active.as_mut() {
                let decoded = text
                    .decode()
                    .map_err(|_| error("event XML text encoding is invalid"))?;
                let unescaped = quick_xml::escape::unescape(&decoded)
                    .map_err(|_| error("event XML text entity is invalid"))?;
                builder.append_text(unescaped.as_ref())?;
            }
        }
        Event::CData(text) => {
            if let Some(builder) = active.as_mut() {
                let decoded = text
                    .decode()
                    .map_err(|_| error("event XML CDATA encoding is invalid"))?;
                builder.append_text(decoded.as_ref())?;
            }
        }
        Event::GeneralRef(reference) => {
            if let Some(builder) = active.as_mut() {
                builder.append_text(&decode_reference(&reference)?)?;
            }
        }
        Event::End(end) => {
            close_element(&end, path, active, reader_offset(reader)?, output)?;
        }
        Event::Eof => return Ok(false),
        Event::Decl(_) | Event::Comment(_) | Event::PI(_) | Event::DocType(_) => {}
    }
    Ok(true)
}

fn reject_nested_scalar(active: Option<&EventBuilder>) -> Result<(), EndpointImportError> {
    if active
        .as_ref()
        .is_some_and(|builder| builder.capture.is_some())
    {
        return Err(error(
            "event XML scalar fields cannot contain nested elements",
        ));
    }
    Ok(())
}

fn empty_report(bytes: &[u8]) -> Result<EventXmlReport, EndpointImportError> {
    Ok(EventXmlReport {
        source_sha256: source_id(bytes),
        source_length: source_length(bytes)?,
        events: Vec::new(),
        omitted_events: 0,
        complete: true,
        limitations: vec![
            "Exported XML is parsed as event content; provider identity and log authenticity are not authenticated".to_owned(),
            "Event fields remain source-reported; timestamps are retained as text without clock conversion".to_owned(),
        ],
    })
}

#[derive(Default)]
struct EventBuilder {
    start: usize,
    provider: Option<String>,
    event_id: Option<String>,
    record_id: Option<String>,
    system_time: Option<String>,
    named_data: BTreeMap<String, String>,
    capture: Option<CapturedField>,
}

#[derive(Clone)]
enum CapturedField {
    EventId(String),
    RecordId(String),
    Data(String, String),
}

impl EventBuilder {
    fn append_text(&mut self, value: &str) -> Result<(), EndpointImportError> {
        let Some(capture) = self.capture.as_mut() else {
            return Ok(());
        };
        let target = match capture {
            CapturedField::EventId(text)
            | CapturedField::RecordId(text)
            | CapturedField::Data(_, text) => text,
        };
        if target.len().saturating_add(value.len()) > MAX_EVENT_TEXT_BYTES {
            return Err(error("event XML field exceeds its text limit"));
        }
        target.push_str(value);
        Ok(())
    }

    fn finish_capture(&mut self) -> Result<(), EndpointImportError> {
        let Some(capture) = self.capture.take() else {
            return Ok(());
        };
        match capture {
            CapturedField::EventId(value) => set_unique(&mut self.event_id, value.trim())?,
            CapturedField::RecordId(value) => set_unique(&mut self.record_id, value.trim())?,
            CapturedField::Data(name, value) => {
                if self.named_data.insert(name, value).is_some() {
                    return Err(error("event XML named data field is duplicated"));
                }
                if self.named_data.len() > MAX_EVENT_FIELDS {
                    return Err(error("event XML field count exceeds its limit"));
                }
            }
        }
        Ok(())
    }
}

fn set_unique(target: &mut Option<String>, value: &str) -> Result<(), EndpointImportError> {
    if target.replace(value.to_owned()).is_some() {
        return Err(error("event XML system field is duplicated"));
    }
    Ok(())
}

fn process_start(
    element: &quick_xml::events::BytesStart<'_>,
    path: &mut Vec<String>,
    active: &mut Option<EventBuilder>,
    event_start: usize,
    reader: &Reader<&[u8]>,
) -> Result<(), EndpointImportError> {
    let name = local_name(element.name().as_ref())?;
    if name == "Event" {
        begin_event(active, event_start)?;
    }
    path.push(name);
    if let Some(builder) = active.as_mut() {
        start_capture(element, path, builder, reader)?;
        read_element_attributes(element, path, builder, reader)?;
    }
    Ok(())
}

fn begin_event(active: &mut Option<EventBuilder>, start: usize) -> Result<(), EndpointImportError> {
    if active.is_some() {
        return Err(error("nested Event elements are unsupported"));
    }
    *active = Some(EventBuilder {
        start,
        ..EventBuilder::default()
    });
    Ok(())
}

fn process_empty(
    element: &quick_xml::events::BytesStart<'_>,
    path: &mut Vec<String>,
    active: &mut Option<EventBuilder>,
    start: usize,
    end: usize,
    reader: &Reader<&[u8]>,
    output: &mut EventXmlOutput,
) -> Result<(), EndpointImportError> {
    let name = local_name(element.name().as_ref())?;
    if name == "Event" {
        begin_event(active, start)?;
        let builder = active
            .take()
            .ok_or_else(|| error("empty Event builder is missing"))?;
        push_event(builder, end, output)?;
        return Ok(());
    }
    path.push(name);
    if let Some(builder) = active.as_mut() {
        read_element_attributes(element, path, builder, reader)?;
        if path_is(path, &["Event", "EventData", "Data"]) {
            builder.finish_capture()?;
            let field_name = attribute(element, b"Name", reader)?
                .ok_or_else(|| error("event XML Data element has no Name attribute"))?;
            if builder
                .named_data
                .insert(field_name, String::new())
                .is_some()
            {
                return Err(error("event XML named data field is duplicated"));
            }
        }
    }
    path.pop()
        .ok_or_else(|| error("event XML path stack is inconsistent"))?;
    Ok(())
}

fn start_capture(
    element: &quick_xml::events::BytesStart<'_>,
    path: &[String],
    builder: &mut EventBuilder,
    reader: &Reader<&[u8]>,
) -> Result<(), EndpointImportError> {
    if path_is(path, &["Event", "System", "EventID"]) {
        builder.capture = Some(CapturedField::EventId(String::new()));
    } else if path_is(path, &["Event", "System", "EventRecordID"]) {
        builder.capture = Some(CapturedField::RecordId(String::new()));
    } else if path_is(path, &["Event", "EventData", "Data"]) {
        let name = attribute(element, b"Name", reader)?
            .ok_or_else(|| error("event XML Data element has no Name attribute"))?;
        builder.capture = Some(CapturedField::Data(name, String::new()));
    }
    Ok(())
}

fn read_element_attributes(
    element: &quick_xml::events::BytesStart<'_>,
    path: &[String],
    builder: &mut EventBuilder,
    reader: &Reader<&[u8]>,
) -> Result<(), EndpointImportError> {
    if path_is(path, &["Event", "System", "Provider"]) {
        set_unique(
            &mut builder.provider,
            &attribute(element, b"Name", reader)?
                .ok_or_else(|| error("event XML Provider has no Name attribute"))?,
        )?;
    }
    if path_is(path, &["Event", "System", "TimeCreated"]) {
        set_unique(
            &mut builder.system_time,
            &attribute(element, b"SystemTime", reader)?
                .ok_or_else(|| error("event XML TimeCreated has no SystemTime attribute"))?,
        )?;
    }
    Ok(())
}

fn close_element(
    element: &quick_xml::events::BytesEnd<'_>,
    path: &mut Vec<String>,
    active: &mut Option<EventBuilder>,
    end: usize,
    output: &mut EventXmlOutput,
) -> Result<(), EndpointImportError> {
    let name = local_name(element.name().as_ref())?;
    if path.last().is_none_or(|open| open != &name) {
        return Err(error("event XML closing element does not match"));
    }
    if let Some(builder) = active.as_mut()
        && (path_is(path, &["Event", "System", "EventID"])
            || path_is(path, &["Event", "System", "EventRecordID"])
            || path_is(path, &["Event", "EventData", "Data"]))
    {
        builder.finish_capture()?;
    }
    path.pop()
        .ok_or_else(|| error("event XML path stack is inconsistent"))?;
    if name == "Event" {
        let builder = active
            .take()
            .ok_or_else(|| error("Event element has no active parser state"))?;
        push_event(builder, end, output)?;
    }
    Ok(())
}

fn push_event(
    mut builder: EventBuilder,
    end: usize,
    output: &mut EventXmlOutput,
) -> Result<(), EndpointImportError> {
    builder.finish_capture()?;
    if end < builder.start {
        return Err(error("event XML source range is reversed"));
    }
    let sysmon_time_change = parse_sysmon_time_change(
        builder.provider.as_deref(),
        builder.event_id.as_deref(),
        &builder.named_data,
    );
    let event = EventXmlRecord {
        provider: builder.provider,
        event_id: builder.event_id,
        record_id: builder.record_id,
        system_time: builder.system_time,
        named_data: builder.named_data,
        sysmon_time_change,
        source_range: source_range(
            &output.report.source_sha256,
            builder.start,
            end - builder.start,
        )?,
    };
    if output.report.events.len() < MAX_ENDPOINT_RECORDS {
        output.report.events.push(event);
    } else {
        output.report.omitted_events = output.report.omitted_events.saturating_add(1);
    }
    Ok(())
}

fn parse_sysmon_time_change(
    provider: Option<&str>,
    event_id: Option<&str>,
    fields: &BTreeMap<String, String>,
) -> Option<SysmonTimeChange> {
    if provider != Some("Microsoft-Windows-Sysmon") || event_id != Some("2") {
        return None;
    }
    Some(SysmonTimeChange {
        process_guid: field(fields, "ProcessGuid")?.to_owned(),
        process_id: field(fields, "ProcessId")?.parse().ok(),
        image: field(fields, "Image")?.to_owned(),
        target_filename: field(fields, "TargetFilename")?.to_owned(),
        previous_creation_time: field(fields, "PreviousCreationUtcTime")?.to_owned(),
        creation_time: field(fields, "CreationUtcTime")?.to_owned(),
    })
}

fn field<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    fields.get(name).map(String::as_str)
}

fn path_is(path: &[String], suffix: &[&str]) -> bool {
    path.len() >= suffix.len()
        && path
            .get(path.len() - suffix.len()..)
            .is_some_and(|actual| actual.iter().map(String::as_str).eq(suffix.iter().copied()))
}

fn local_name(name: &[u8]) -> Result<String, EndpointImportError> {
    let text = std::str::from_utf8(name).map_err(|_| error("event XML element name is invalid"))?;
    Ok(text
        .rsplit_once(':')
        .map_or(text, |(_, local)| local)
        .to_owned())
}

fn attribute(
    element: &quick_xml::events::BytesStart<'_>,
    name: &[u8],
    reader: &Reader<&[u8]>,
) -> Result<Option<String>, EndpointImportError> {
    let mut found = None;
    for item in element.attributes().with_checks(true) {
        let item = item.map_err(|_| error("event XML attribute is malformed"))?;
        if item.key.local_name().as_ref() == name {
            let value = item
                .decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, reader.decoder())
                .map_err(|_| error("event XML attribute value is invalid"))?;
            if found.replace(value.into_owned()).is_some() {
                return Err(error("event XML attribute is duplicated"));
            }
        }
    }
    Ok(found)
}

fn decode_reference(
    reference: &quick_xml::events::BytesRef<'_>,
) -> Result<String, EndpointImportError> {
    if let Some(character) = reference
        .resolve_char_ref()
        .map_err(|_| error("event XML character reference is invalid"))?
    {
        return Ok(character.to_string());
    }
    let name = reference
        .decode()
        .map_err(|_| error("event XML entity reference is invalid"))?;
    match name.as_ref() {
        "amp" => Ok("&".to_owned()),
        "lt" => Ok("<".to_owned()),
        "gt" => Ok(">".to_owned()),
        "apos" => Ok("'".to_owned()),
        "quot" => Ok("\"".to_owned()),
        _ => Err(error("event XML declares an unsupported entity")),
    }
}
