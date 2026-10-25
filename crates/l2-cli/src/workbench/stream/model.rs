use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub label: String,
    pub length: u64,
    pub frames: u32,
    #[serde(
        default,
        serialize_with = "l2_workbench::capture_collection::serialize",
        deserialize_with = "l2_workbench::capture_collection::deserialize"
    )]
    pub collection_summary: l2_pcap::CollectionSummary,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub path: String,
    pub sha256: String,
    pub first_record: u32,
    pub last_record: u32,
    pub context_first_record: u32,
    pub packet_nodes: usize,
    pub collection_complete: bool,
}

#[derive(Serialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub source: Source,
    pub raw_collection_complete: bool,
    pub analysis_complete: bool,
    pub context_records: u16,
    pub pages: Vec<Page>,
    pub limitations: Vec<String>,
}

#[derive(Serialize)]
pub struct Receipt {
    pub schema_version: u32,
    pub source_id: String,
    pub pages: usize,
    pub manifest_sha256: String,
    pub raw_collection_complete: bool,
    pub analysis_complete: bool,
}
