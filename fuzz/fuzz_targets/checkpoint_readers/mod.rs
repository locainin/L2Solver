pub mod cache;
pub mod case;
pub mod job;

use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits},
    job::{Job, cache::JOB_SNAPSHOT_VERSION},
};

const MAX_INPUT_BYTES: usize = 65_536;

thread_local! {
    // Reuse one isolated database without accumulating rows between inputs
    static CACHE: cache::Fixture = cache::Fixture::new().expect("private fuzz cache could not initialize");
}

pub fn exercise(data: &[u8]) {
    let input = data.get(..data.len().min(MAX_INPUT_BYTES)).unwrap();
    let selector = usize::from(u16::from_le_bytes([
        input.first().copied().unwrap_or_default(),
        input.get(1).copied().unwrap_or_default(),
    ]));
    let split = selector.min(input.len());
    let (graph, pack) = input.split_at(split);
    let _ = case::read(graph, pack);
    let _ = job::restore(input);

    // Generated valid state keeps restoration reachable beyond malformed headers
    let mut original = Case::new();
    let payload = input.get(..input.len().min(4096)).unwrap();
    original
        .add_bytes_node("fuzz_input", payload, Vec::new(), serde_json::json!({}))
        .unwrap();
    let mut graph = Vec::new();
    let mut pack = Vec::new();
    original
        .write_snapshot(
            &mut graph,
            &mut pack,
            CaseSnapshotLimits::new(65_536, 65_536),
        )
        .unwrap();
    assert_eq!(case::read(&graph, &pack).unwrap(), original);
    if !pack.is_empty() {
        let position = selector % pack.len();
        *pack.get_mut(position).unwrap() ^= 1;
        // Retained content must reject even a one-bit change against its recorded digest
        assert!(case::read(&graph, &pack).is_err());
        *pack.get_mut(position).unwrap() ^= 1;
    }
    if let Some(byte) = input.first() {
        let length = graph.len();
        *graph.get_mut(selector % length).unwrap() ^= *byte;
        let _ = case::read(&graph, &pack);
    }

    CACHE.with(|cache| {
        // Arbitrary row bytes exercise UTF-8, JSON, version and topology checks
        let metadata_selector = input.first().copied().unwrap_or_default();
        let status = if metadata_selector & 1 == 0 {
            1
        } else {
            i64::from(metadata_selector)
        };
        let version = if metadata_selector & 2 == 0 {
            i64::from(JOB_SNAPSHOT_VERSION)
        } else {
            i64::from(metadata_selector)
        };
        let _ = cache.read(input, status, version);
        let snapshot = Job::new("fuzz checkpoint").snapshot().unwrap();
        let encoded = serde_json::to_vec(&snapshot).unwrap();
        let loaded = cache
            .read(&encoded, 1, i64::from(JOB_SNAPSHOT_VERSION))
            .unwrap()
            .unwrap();
        assert_eq!(loaded.snapshot, snapshot);
        assert!(loaded.snapshot.is_valid_checkpoint());
        let mut changed = encoded;
        let length = changed.len();
        *changed.get_mut(selector % length).unwrap() ^= input.last().copied().unwrap_or(1);
        let _ = job::restore(&changed);
        let _ = cache.read(&changed, 1, i64::from(JOB_SNAPSHOT_VERSION));
    });
}
