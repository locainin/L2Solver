use super::{input, label, load};
use l2_workbench::evidence::{Case, Edge, EvidenceStatus, ImportScanMode, ImportScanOptions};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    io::{Read, Write},
    path::Path,
};

const LINK_TYPE_ETHERNET: u64 = 1;

pub(super) struct Options<'a> {
    kind: &'a str,
    scan_mode: &'a str,
    max_scan_bytes: usize,
    max_findings: usize,
    max_input_bytes: Option<usize>,
}

impl<'a> Options<'a> {
    pub(super) const fn new(
        kind: &'a str,
        scan_mode: &'a str,
        max_scan_bytes: usize,
        max_findings: usize,
        max_input_bytes: Option<usize>,
    ) -> Self {
        Self {
            kind,
            scan_mode,
            max_scan_bytes,
            max_findings,
            max_input_bytes,
        }
    }
}

pub(super) fn run(
    case: &Path,
    path: &Path,
    options: &Options<'_>,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let mut case = load(case)?;
    add(&mut case, path, options)?;
    case.write_json(output)?;
    Ok(case.collection_complete())
}

fn add(case: &mut Case, path: &Path, options: &Options<'_>) -> Result<(), Box<dyn Error>> {
    let bytes = read_import_bytes(input::regular(path)?, options.max_input_bytes)?;
    let mode = match options.scan_mode {
        "none" => ImportScanMode::None,
        "literal-signature" => ImportScanMode::LiteralsAndSignatures,
        _ => return Err("import scan mode must be none or literal-signature".into()),
    };
    let scan = case.scan_import_with_options(
        label(path, "import"),
        options.kind,
        &bytes,
        ImportScanOptions {
            mode,
            max_scan_bytes: options.max_scan_bytes,
            max_findings: options.max_findings,
        },
    )?;
    case.add_limitation("Imported file bytes do not establish code execution, key use, ownership, or causal network behavior")?;
    link_import_relationships(case, scan.source_node_id, scan.node_ids.iter().copied())
}

fn read_import_bytes(
    mut file: input::InputFile,
    maximum: Option<usize>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let initial_length = file.metadata()?.len();
    let length = usize::try_from(initial_length)
        .map_err(|_| "import source length does not fit this platform")?;
    if let Some(ceiling) = maximum
        && length > ceiling
    {
        return Err(format!(
            "import source has {length} bytes; exceeds the input byte ceiling {ceiling}"
        )
        .into());
    }

    // Reserve against the opened file's observed size before reading its bytes
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| "could not reserve memory for the import source")?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)?;

    // A one-byte read detects growth after the initial metadata check
    let mut extra = [0_u8; 1];
    match file.read_exact(&mut extra) {
        Ok(()) => return Err("import source length changed while it was being read".into()),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(error.into()),
    }
    if file.metadata()?.len() != initial_length {
        return Err("import source length changed while it was being read".into());
    }
    Ok(bytes)
}

fn link_import_relationships(
    case: &mut Case,
    source_node: u64,
    imported_nodes: impl Iterator<Item = u64>,
) -> Result<(), Box<dyn Error>> {
    let addresses = packet_addresses(case);
    let imported_ids: BTreeSet<_> = imported_nodes.collect();
    let signature_nodes: Vec<_> = case
        .nodes()
        .iter()
        .filter(|node| imported_ids.contains(&node.id) && node.kind == "file_signature_match")
        .map(|node| node.id)
        .collect();
    let mut pairs = BTreeSet::new();
    let available = l2_workbench::evidence::MAX_EDGES - case.edges().len();
    // Preserve direct object provenance before adding optional cross-source correlations
    let retained_signature_nodes = signature_nodes.len().min(available);
    let signature_relationships_omitted = retained_signature_nodes != signature_nodes.len();
    let address_capacity = available.saturating_sub(retained_signature_nodes);
    let mut address_relationships_omitted = false;
    for node in case
        .nodes()
        .iter()
        .filter(|node| imported_ids.contains(&node.id))
    {
        if matches!(node.kind.as_str(), "ipv4_literal" | "ipv6_literal")
            && let Some(value) = node
                .details
                .get("parsed")
                .and_then(serde_json::Value::as_str)
            && let Some(matches) = addresses.get(value)
        {
            for target in matches {
                let pair = (node.id, *target);
                // Source and destination fields can name the same packet and address
                if pairs.contains(&pair) {
                    continue;
                }
                if pairs.len() == address_capacity {
                    address_relationships_omitted = true;
                    break;
                }
                pairs.insert(pair);
            }
        }
        if address_relationships_omitted {
            break;
        }
    }
    for target in signature_nodes.into_iter().take(retained_signature_nodes) {
        case.add_edge(Edge {
            from: source_node,
            to: target,
            relation: "contains_signature".to_owned(),
            status: EvidenceStatus::Observed,
            reason: l2_workbench::artifact::FILE_SIGNATURE_RELATION_REASON.to_owned(),
        })?;
    }
    for (from, to) in pairs {
        case.add_edge(Edge { from,to,relation:"same_address_value".to_owned(),status:EvidenceStatus::Observed,
            reason:"A parsed file address equals an IP address decoded from retained packet bytes under the declared Ethernet link type; ownership and causality are unresolved".to_owned() })?;
    }
    if signature_relationships_omitted {
        case.add_limitation(
            "Some imported file-signature relationships were omitted after the relationship budget",
        )?;
    }
    if address_relationships_omitted {
        case.add_limitation(
            "Some cross-source address relationships were omitted after the relationship budget",
        )?;
    }
    Ok(())
}

fn packet_addresses(case: &Case) -> BTreeMap<String, Vec<u64>> {
    let blobs: BTreeMap<_, _> = case
        .blobs()
        .iter()
        .map(|blob| (blob.id.as_str(), blob.bytes.as_slice()))
        .collect();
    let mut addresses: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for node in case.nodes().iter().filter(|node| node.kind == "packet") {
        if node
            .details
            .get("link_type")
            .and_then(serde_json::Value::as_u64)
            != Some(LINK_TYPE_ETHERNET)
        {
            continue;
        }
        let Some(blob_id) = node.blob.as_deref() else {
            continue;
        };
        let Some(bytes) = blobs.get(blob_id).copied() else {
            continue;
        };
        let Ok(frame) = l2_core::decode(bytes) else {
            continue;
        };
        let Some(header) = l2_discovery::ip_header(&frame) else {
            continue;
        };
        for address in [header.source, header.destination] {
            addresses
                .entry(address.to_string())
                .or_default()
                .push(node.id);
        }
    }
    addresses
}
