use super::bundle_budget::charge_document;
use super::stream::{Page, Source};
use super::{load, read_bounded};
use l2_workbench::{
    evidence::{Case, MAX_CASE_JSON_BYTES},
    sha256,
};
use serde::{
    Deserialize, Serialize,
    de::{self, SeqAccess, Visitor},
};
use std::{collections::BTreeSet, error::Error, fmt, fs, io, marker::PhantomData, path::Path};

const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_PAGES: usize = 16_384;
const MAX_CONTEXT_RECORDS: u16 = 128;
const MAX_PRIMARY_RECORDS: u64 = 768;

#[derive(Serialize)]
pub(super) struct VisitSummary {
    pub collection_complete: bool,
    pub pages: usize,
    pub source_ids: Vec<String>,
    pub bundle_limitations: Vec<String>,
}

pub(super) struct PageContext<'a> {
    pub path: Option<&'a str>,
    pub primary: Option<(u32, u32)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    source: Source,
    raw_collection_complete: bool,
    analysis_complete: bool,
    context_records: u16,
    #[serde(deserialize_with = "deserialize_pages")]
    pages: Vec<Page>,
    #[serde(deserialize_with = "deserialize_limitations")]
    limitations: Vec<String>,
}

struct BoundedVec<T, const MAXIMUM: usize>(PhantomData<T>);

impl<'de, T, const MAXIMUM: usize> Visitor<'de> for BoundedVec<T, MAXIMUM>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "an array with at most {MAXIMUM} items")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let capacity = sequence.size_hint().unwrap_or_default().min(MAXIMUM);
        let mut values = Vec::with_capacity(capacity);
        while let Some(value) = sequence.next_element()? {
            if values.len() == MAXIMUM {
                return Err(de::Error::custom("array item limit exceeded"));
            }
            values.push(value);
        }
        Ok(values)
    }
}

fn deserialize_pages<'de, D>(deserializer: D) -> Result<Vec<Page>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedVec::<Page, MAX_PAGES>(PhantomData))
}

fn deserialize_limitations<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedVec::<String, 128>(PhantomData))
}

pub(super) fn cases(
    path: &Path,
    mut visitor: impl FnMut(&Case, PageContext<'_>) -> Result<(), Box<dyn Error>>,
) -> Result<VisitSummary, Box<dyn Error>> {
    if path != Path::new("-") && path.is_dir() {
        return visit_bundle(path, &mut visitor);
    }
    let case = load(path)?;
    let source_ids = source_ids(&case);
    visitor(
        &case,
        PageContext {
            path: None,
            primary: None,
        },
    )?;
    Ok(VisitSummary {
        collection_complete: case.collection_complete(),
        pages: 1,
        source_ids,
        bundle_limitations: Vec::new(),
    })
}

fn visit_bundle(
    directory: &Path,
    visitor: &mut impl FnMut(&Case, PageContext<'_>) -> Result<(), Box<dyn Error>>,
) -> Result<VisitSummary, Box<dyn Error>> {
    require_directory(directory)?;
    let manifest_bytes = read_regular(&directory.join("manifest.json"), MAX_MANIFEST_BYTES)?;
    let mut total_bytes = charge_document(0, manifest_bytes.len())?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest)?;
    let page_directory = directory.join("pages");
    require_directory(&page_directory)?;

    let mut source_ids = BTreeSet::new();
    source_ids.insert(manifest.source.id.clone());
    let mut all_pages_complete = !l2_workbench::capture_collection::reports_incomplete_collection(
        manifest.source.collection_summary,
    );
    let mut all_packets_retained = true;
    for (index, page) in manifest.pages.iter().enumerate() {
        // Rebuild a fixed path instead of joining caller-supplied manifest text
        let expected_path = page_path(index + 1);
        if page.path != expected_path {
            return Err(invalid("bundle page path is not canonical"));
        }
        let page_path = directory.join(&expected_path);
        let document = read_regular(&page_path, MAX_CASE_JSON_BYTES)?;
        total_bytes = charge_document(total_bytes, document.len())?;
        // The digest binds the manifest entry to this exact page document
        if sha256(&document) != page.sha256 {
            return Err(invalid("bundle page hash does not match its document"));
        }
        let case = Case::from_json(&document)?;
        let expected_count = validate_page(&case, &manifest.source, page)?;
        let fully_retained = u64::try_from(page.packet_nodes)? == expected_count;
        all_packets_retained &= fully_retained;
        all_pages_complete &= case.collection_complete();
        if page.collection_complete != case.collection_complete() {
            return Err(invalid("page completeness does not match its case"));
        }
        if !fully_retained && case.collection_complete() {
            return Err(invalid(
                "a page with missing packet nodes claims completeness",
            ));
        }
        visitor(
            &case,
            PageContext {
                path: Some(&page.path),
                primary: Some((page.first_record, page.last_record)),
            },
        )?;
    }
    if manifest.analysis_complete != all_pages_complete {
        return Err(invalid(
            "manifest analysis completeness disagrees with its pages",
        ));
    }
    if manifest.raw_collection_complete != all_packets_retained {
        return Err(invalid(
            "manifest raw completeness disagrees with retained packet coverage",
        ));
    }
    Ok(VisitSummary {
        collection_complete: manifest.analysis_complete && all_pages_complete,
        pages: manifest.pages.len(),
        source_ids: source_ids.into_iter().collect(),
        bundle_limitations: manifest.limitations,
    })
}

fn validate_manifest(manifest: &Manifest) -> Result<(), Box<dyn Error>> {
    if manifest.schema_version != 1 {
        return Err(invalid("unsupported bundle schema version"));
    }
    if !valid_digest(&manifest.source.id, "sha256:")
        || manifest.source.label.is_empty()
        || manifest.source.label.len() > 256
        || manifest.source.label.chars().any(char::is_control)
        || matches!(manifest.source.label.as_str(), "." | "..")
        || manifest.source.label.contains(['/', '\\'])
    {
        return Err(invalid("bundle source metadata is invalid"));
    }
    if manifest.context_records > MAX_CONTEXT_RECORDS {
        return Err(invalid("bundle context record limit is invalid"));
    }
    let mut next_primary = 1_u64;
    for page in &manifest.pages {
        if !valid_digest(&page.sha256, "")
            || page.first_record == 0
            || u64::from(page.first_record) != next_primary
            || page.last_record < page.first_record
            || u64::from(page.last_record) > u64::from(manifest.source.frames)
            || u64::from(page.last_record) - u64::from(page.first_record) + 1 > MAX_PRIMARY_RECORDS
        {
            return Err(invalid(
                "bundle primary page ranges are invalid or discontinuous",
            ));
        }
        let minimum_context = page
            .first_record
            .saturating_sub(u32::from(manifest.context_records))
            .max(1);
        if page.context_first_record < minimum_context
            || page.context_first_record > page.first_record
            || page.last_record < page.context_first_record
        {
            return Err(invalid("bundle context range is invalid"));
        }
        next_primary = u64::from(page.last_record) + 1;
    }
    if next_primary != u64::from(manifest.source.frames) + 1 {
        return Err(invalid(
            "bundle primary pages do not cover the source record count",
        ));
    }
    for limitation in &manifest.limitations {
        if limitation.is_empty()
            || limitation.len() > 1024
            || limitation.chars().any(char::is_control)
        {
            return Err(invalid("bundle limitation metadata is invalid"));
        }
    }
    Ok(())
}

fn validate_page(case: &Case, source: &Source, page: &Page) -> Result<u64, Box<dyn Error>> {
    // Page hashes bind stored JSON; original capture bytes are not loaded here
    let [retained_source] = case.sources() else {
        return Err(invalid(
            "bundle page must retain exactly one source identity",
        ));
    };
    if retained_source.id != source.id
        || retained_source.length != source.length
        || retained_source.label != source.label
        || retained_source.kind != "capture"
    {
        return Err(invalid(
            "bundle page source identity disagrees with the manifest",
        ));
    }
    validate_collection_summary(case, source)?;
    let expected_count = u64::from(page.last_record) - u64::from(page.context_first_record) + 1;
    let retained_frames = validate_summary(case, source, page)?;
    validate_packet_nodes(case, source, page, expected_count, retained_frames)?;
    Ok(expected_count)
}

fn validate_collection_summary(case: &Case, source: &Source) -> Result<(), Box<dyn Error>> {
    let mut summaries = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "capture_collection_summary");
    let Some(summary) = summaries.next() else {
        // Historical bundles have neither the manifest field nor a collection node
        return if source.collection_summary == l2_pcap::CollectionSummary::default() {
            Ok(())
        } else {
            Err(invalid("bundle page collection declaration is missing"))
        };
    };
    if summaries.next().is_some() {
        return Err(invalid("bundle page repeats its collection declaration"));
    }
    let expected = l2_workbench::capture_collection::to_value(source.collection_summary)?;
    if summary
        .details
        .get("source_id")
        .and_then(serde_json::Value::as_str)
        != Some(&source.id)
        || summary.details.get("summary") != Some(&expected)
    {
        return Err(invalid(
            "bundle page collection declaration disagrees with the manifest",
        ));
    }
    if l2_workbench::capture_collection::reports_incomplete_collection(source.collection_summary)
        && case.collection_complete()
    {
        return Err(invalid(
            "bundle page claims completeness despite its collection declaration",
        ));
    }
    Ok(())
}

fn validate_summary(case: &Case, source: &Source, page: &Page) -> Result<u64, Box<dyn Error>> {
    let mut summaries = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "capture_summary");
    let summary = summaries
        .next()
        .ok_or_else(|| invalid("bundle page capture summary is missing"))?;
    if summaries.next().is_some() {
        return Err(invalid("bundle page must contain one capture summary"));
    }
    let details = summary
        .details
        .as_object()
        .ok_or_else(|| invalid("capture summary details are invalid"))?;
    let window = details
        .get("record_window")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid("capture summary record window is missing"))?;
    if details
        .get("frames_seen")
        .and_then(serde_json::Value::as_u64)
        != Some(u64::from(source.frames))
        || window.get("first").and_then(serde_json::Value::as_u64)
            != Some(u64::from(page.context_first_record))
        || window.get("last").and_then(serde_json::Value::as_u64)
            != Some(u64::from(page.last_record))
    {
        return Err(invalid(
            "capture summary source count or record window disagrees with the manifest",
        ));
    }
    let retained_frames = details
        .get("retained_frames")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid("capture summary retained frame count is invalid"))?;
    Ok(retained_frames)
}

fn validate_packet_nodes(
    case: &Case,
    source: &Source,
    page: &Page,
    expected_count: u64,
    retained_frames: u64,
) -> Result<(), Box<dyn Error>> {
    let packet_node_count = case
        .nodes()
        .iter()
        .filter(|node| node.kind == "packet")
        .count();
    if packet_node_count != page.packet_nodes
        || retained_frames < u64::try_from(packet_node_count)?
        || retained_frames > expected_count
    {
        return Err(invalid(
            "capture summary and retained packet count disagree",
        ));
    }
    // Packet retention stops at the first omission, so surviving records form a prefix
    for (offset, node) in case
        .nodes()
        .iter()
        .filter(|node| node.kind == "packet")
        .enumerate()
    {
        let expected_record = page
            .context_first_record
            .checked_add(u32::try_from(offset)?)
            .ok_or_else(|| invalid("packet record number overflow"))?;
        let record = node
            .details
            .get("record")
            .and_then(serde_json::Value::as_u64);
        let captured_length = node
            .details
            .get("captured_length")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| invalid("packet captured length is invalid"))?;
        let valid_ranges = match node.ranges.as_slice() {
            [] => captured_length == 0,
            [range] => {
                range.source == source.id
                    && range.packet == Some(u64::from(expected_record))
                    && range.length == captured_length
            }
            _ => false,
        };
        if record != Some(u64::from(expected_record)) || !valid_ranges {
            return Err(invalid(
                "packet nodes are not a consecutive source-record prefix",
            ));
        }
    }
    Ok(())
}

fn source_ids(case: &Case) -> Vec<String> {
    case.sources()
        .iter()
        .map(|source| source.id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn page_path(number: usize) -> String {
    format!("pages/{number:06}.json")
}

fn valid_digest(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn require_directory(path: &Path) -> Result<(), Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid("bundle directory must be a real directory"));
    }
    Ok(())
}

fn read_regular(path: &Path, maximum: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = crate::input::regular_no_follow(path)?;
    read_bounded(file, maximum)
}

fn invalid(message: &'static str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}
