use super::support::run;
use l2_workbench::evidence::{Case, Edge, EvidenceStatus, SourceRange};
use serde_json::{Value, json};
use std::error::Error;

const FIRST: &str = "first";
const SECOND: &str = "second";

#[test]
fn explicitly_labeled_complete_message_samples() -> Result<(), Box<dyn Error>> {
    let case = contextual_runs(&[
        (1, FIRST, b"\x01q"),
        (1, SECOND, b"r\x01"),
        (2, FIRST, b"\x02s"),
        (2, SECOND, b"t\x02"),
    ])?;
    let ids = run_ids(&case)?;
    let [
        first_request,
        first_response,
        second_request,
        second_response,
    ] = ids.as_slice()
    else {
        return Err("expected four complete TCP messages".into());
    };
    let args = [
        "protocol",
        "-",
        "--sample",
        &format!("{first_request}:request"),
        "--sample",
        &format!("{first_response}:response"),
        "--sample",
        &format!("{second_request}:request"),
        "--sample",
        &format!("{second_response}:response"),
        "--field",
        "0:1:1",
    ];

    let output = run(&args, &case.to_json()?)?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert!(
        report
            .pointer("/framing")
            .is_some_and(|value| !value.is_null())
    );
    assert_eq!(report.pointer("/boundary_extractions"), Some(&json!([])));
    assert_eq!(
        report.pointer("/samples/0/context/direction"),
        Some(&json!("first_to_second"))
    );
    assert!(
        report
            .pointer("/samples/0/context/session")
            .and_then(Value::as_u64)
            .is_some_and(|session| session > 0)
    );
    assert!(
        report
            .pointer("/samples/0/boundary_assumption")
            .and_then(Value::as_str)
            .is_some_and(|value| value.contains("caller_selected_message"))
    );
    assert_eq!(
        report.pointer("/framing/split_basis"),
        Some(&json!("complete_sessions"))
    );
    assert_eq!(
        report.pointer("/correlation/holdout/transitions/0/status"),
        Some(&json!("unique"))
    );
    assert_eq!(
        report.pointer("/correlation_candidates/split_basis"),
        Some(&json!("complete_sessions"))
    );
    Ok(())
}

#[test]
fn unclassified_tcp_boundary_hypotheses_respect_search_and_report_limits()
-> Result<(), Box<dyn Error>> {
    let case = contextual_runs(&[(1, FIRST, b"one\ntwo\nthree")])?;
    let id = *run_ids(&case)?.first().ok_or("missing TCP run")?;
    let sample = format!("{id}:unclassified");
    let input = case.to_json()?;

    let disabled = run(&["protocol", "-", "--sample", &sample], &input)?;
    assert_eq!(disabled.status.code(), Some(1));

    for (report_bytes, retain_candidate) in [(32, false), (4096, true)] {
        let report_bytes_argument = report_bytes.to_string();
        let enabled = run(
            &[
                "protocol",
                "-",
                "--sample",
                &sample,
                "--infer-run-boundaries",
                "--protocol-max-retained-frames",
                "1",
                "--protocol-max-prefix-offset",
                "20",
                "--protocol-max-candidates",
                "1",
                "--protocol-max-report-bytes",
                &report_bytes_argument,
            ],
            &input,
        )?;
        assert!(
            enabled.status.success(),
            "{}",
            String::from_utf8_lossy(&enabled.stderr)
        );
        let report: Value = serde_json::from_slice(&enabled.stdout)?;
        let boundaries = report
            .pointer("/boundary_extractions/0")
            .ok_or("boundary report is missing")?;
        assert_eq!(
            report.pointer("/protocol_limits/max_retained_frames"),
            Some(&json!(1))
        );
        assert_eq!(
            report.pointer("/protocol_limits/max_report_bytes"),
            Some(&json!(report_bytes))
        );
        assert_eq!(
            report.pointer("/protocol_limits/max_prefix_offset"),
            Some(&json!(20))
        );
        assert_eq!(boundaries.get("prefix_offset_limit"), Some(&json!(20)));
        assert_eq!(
            boundaries.get("search_exhaustive_within_plan"),
            Some(&json!(false))
        );
        assert_eq!(boundaries.get("sample"), Some(&json!(id)));
        assert_eq!(
            boundaries.get("report_details_complete"),
            Some(&json!(false))
        );
        let candidates = boundaries
            .get("candidates")
            .and_then(Value::as_array)
            .ok_or("boundary candidates are missing")?;
        if retain_candidate {
            assert!(candidates.iter().any(|candidate| {
                candidate.pointer("/kind/kind") == Some(&json!("delimiter"))
                    && candidate.pointer("/kind/byte") == Some(&json!(10))
            }));
        } else {
            // Missing detail stays an omission rather than an invented empty search
            assert!(candidates.is_empty());
            assert_eq!(boundaries.get("omitted_candidate_details"), Some(&json!(1)));
        }
        assert!(
            report
                .pointer("/samples/0/boundary_assumption")
                .and_then(Value::as_str)
                .is_some_and(|value| value.contains("candidate_boundaries"))
        );
    }
    Ok(())
}

#[test]
fn configured_cli_above_u16_max() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let mut args = vec!["protocol".to_owned(), "-".to_owned()];
    for length in [65_536_usize, 65_537, 65_538, 65_539] {
        let mut bytes = vec![0x5a; length];
        let encoded = u32::try_from(length)?.to_be_bytes();
        bytes
            .get_mut(..encoded.len())
            .ok_or("message is shorter than its length field")?
            .copy_from_slice(&encoded);
        let id = case.add_bytes_node("candidate", &bytes, Vec::new(), json!({}))?;
        args.extend(["--sample".to_owned(), format!("{id}:unclassified")]);
    }
    args.extend(["--field".to_owned(), "0:0:24".to_owned()]);
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();

    let output = run(&args, &case.to_json()?)?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report.pointer("/correlation/width"), Some(&json!(24)));
    assert!(
        report
            .pointer("/framing/candidates")
            .and_then(Value::as_array)
            .is_some_and(|candidates| candidates.iter().any(|candidate| {
                candidate.pointer("/kind/kind") == Some(&json!("length_prefix"))
                    && candidate.pointer("/kind/offset") == Some(&json!(0))
                    && candidate.pointer("/kind/width") == Some(&json!(4))
                    && candidate.pointer("/kind/meaning") == Some(&json!("whole_message"))
                    && candidate.pointer("/discovery/supported") == Some(&json!(2))
                    && candidate.pointer("/holdout/supported") == Some(&json!(2))
            }))
    );
    Ok(())
}

#[test]
fn cli_samples_selected_message_budget() -> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let mut args = vec![
        "protocol".to_owned(),
        "-".to_owned(),
        "--protocol-max-message-bytes".to_owned(),
        "2".to_owned(),
    ];
    for bytes in [b"abc".as_slice(), b"def", b"ghi", b"jkl"] {
        let id = case.add_bytes_node("candidate", bytes, Vec::new(), json!({}))?;
        args.extend(["--sample".to_owned(), format!("{id}:unclassified")]);
    }
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();

    let output = run(&args, &case.to_json()?)?;

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("maximum is 2"));
    Ok(())
}

#[test]
fn equal_depth_message_context_unresolved() -> Result<(), Box<dyn Error>> {
    let case = lineage_case(false)?;
    let ids = message_ids(&case)?;
    let args = protocol_sample_args(&ids);

    let output = run(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert!(
        report
            .pointer("/samples")
            .and_then(Value::as_array)
            .is_some_and(|samples| samples.iter().all(|sample| sample["context"].is_null()))
    );
    assert_eq!(
        report.pointer("/framing/split_basis"),
        Some(&json!("sample_order"))
    );
    Ok(())
}

#[test]
fn shared_owner_unique_direction_context() -> Result<(), Box<dyn Error>> {
    let case = lineage_case(true)?;
    let ids = message_ids(&case)?;
    let args = protocol_sample_args(&ids);

    let output = run(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert!(
        report
            .pointer("/samples")
            .and_then(Value::as_array)
            .is_some_and(|samples| samples.iter().all(|sample| !sample["context"].is_null()))
    );
    assert_eq!(
        report.pointer("/framing/split_basis"),
        Some(&json!("complete_sessions"))
    );
    Ok(())
}

fn contextual_runs(messages: &[(u64, &str, &[u8])]) -> Result<Case, Box<dyn Error>> {
    let source_bytes = messages
        .iter()
        .flat_map(|(_, _, bytes)| *bytes)
        .copied()
        .collect::<Vec<_>>();
    let mut case = Case::new();
    let source = case.add_source(
        "capture.pcap",
        "capture",
        u64::try_from(source_bytes.len())?,
        &l2_workbench::sha256(&source_bytes),
        None,
    )?;
    let endpoints = [json!({"endpoint": "first"}), json!({"endpoint": "second"})];
    let mut sessions = Vec::new();
    let mut offset = 0_u64;
    let mut packet = 1_u64;
    for (session_number, direction, bytes) in messages {
        let session_index = usize::try_from(*session_number - 1)?;
        let session = contextual_session(&mut case, &mut sessions, session_index, &endpoints)?;
        let (source_endpoint, destination_endpoint) = if *direction == FIRST {
            (&endpoints[0], &endpoints[1])
        } else {
            (&endpoints[1], &endpoints[0])
        };
        let direction_node = case.add_node(
            "tcp_direction",
            None,
            Vec::new(),
            json!({"source": source_endpoint, "destination": destination_endpoint}),
        )?;
        case.add_edge(Edge {
            from: session,
            to: direction_node,
            relation: "contains".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "Test direction belongs to its session".to_owned(),
        })?;
        let length = add_contextual_run(&mut case, direction_node, &source, bytes, packet, offset)?;
        offset = offset.checked_add(length).ok_or("source range overflow")?;
        packet = packet.checked_add(1).ok_or("packet number overflow")?;
    }
    Ok(case)
}

fn contextual_session(
    case: &mut Case,
    sessions: &mut Vec<u64>,
    session_index: usize,
    endpoints: &[Value; 2],
) -> Result<u64, Box<dyn Error>> {
    if sessions.get(session_index).is_none() {
        let session = case.add_node(
            "tcp_episode",
            None,
            Vec::new(),
            json!({
                "scope": {"capture": "test"},
                "endpoints": endpoints,
            }),
        )?;
        sessions.push(session);
    }
    sessions
        .get(session_index)
        .copied()
        .ok_or_else(|| "missing test session".into())
}

fn add_contextual_run(
    case: &mut Case,
    direction: u64,
    source: &str,
    bytes: &[u8],
    packet: u64,
    offset: u64,
) -> Result<u64, Box<dyn Error>> {
    let mut parent = direction;
    for _ in 0..6 {
        let layer = case.add_node("context_layer", None, Vec::new(), json!({}))?;
        case.add_edge(Edge {
            from: parent,
            to: layer,
            relation: "contains".to_owned(),
            status: EvidenceStatus::Hypothesis,
            reason: "Test wrapper retains its parent context".to_owned(),
        })?;
        parent = layer;
    }
    let length = u64::try_from(bytes.len())?;
    let run = case.add_bytes_node(
        "tcp_byte_run",
        bytes,
        vec![SourceRange {
            source: source.to_owned(),
            packet: Some(packet),
            offset,
            length,
        }],
        json!({"offset": 0, "length": bytes.len()}),
    )?;
    case.add_edge(Edge {
        from: parent,
        to: run,
        relation: "contains".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "Test run is linked to its direction".to_owned(),
    })?;
    Ok(length)
}

fn lineage_case(shared_direction_owner: bool) -> Result<Case, Box<dyn Error>> {
    let messages: [(&str, &[u8]); 4] = [
        (FIRST, b"\x01q"),
        (SECOND, b"r\x01"),
        (FIRST, b"\x02s"),
        (SECOND, b"t\x02"),
    ];
    let source_bytes = messages
        .iter()
        .flat_map(|(_, bytes)| *bytes)
        .copied()
        .collect::<Vec<_>>();
    let mut fixture = LineageFixture::new(shared_direction_owner, &source_bytes)?;
    for (index, (role, bytes)) in messages.iter().enumerate() {
        fixture.append(index, role, bytes)?;
    }
    Ok(fixture.case)
}

struct LineageFixture {
    case: Case,
    source: String,
    endpoints: [Value; 2],
    sessions: Vec<u64>,
    shared_direction_owner: bool,
    offset: u64,
}

impl LineageFixture {
    fn new(shared_direction_owner: bool, source_bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let mut case = Case::new();
        let source = case.add_source(
            "lineage.bin",
            "lineage",
            u64::try_from(source_bytes.len())?,
            &l2_workbench::sha256(source_bytes),
            None,
        )?;
        Ok(Self {
            case,
            source,
            endpoints: [json!({"endpoint": "first"}), json!({"endpoint": "second"})],
            sessions: Vec::new(),
            shared_direction_owner,
            offset: 0,
        })
    }

    fn append(&mut self, index: usize, role: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        let session_index = index / 2;
        if self.sessions.get(session_index).is_none() {
            let session = self.case.add_node(
                "tcp_episode",
                None,
                Vec::new(),
                json!({"scope": {"capture": "lineage"}, "endpoints": self.endpoints}),
            )?;
            self.sessions.push(session);
        }
        let session = self
            .sessions
            .get(session_index)
            .copied()
            .ok_or("missing session fixture")?;
        let directions: &[&str] = if self.shared_direction_owner {
            std::slice::from_ref(&role)
        } else {
            &[FIRST, SECOND]
        };
        let layers = self.direction_layers(session, directions)?;
        let length = u64::try_from(bytes.len())?;
        let message = self.case.add_bytes_node(
            "message",
            bytes,
            vec![SourceRange {
                source: self.source.clone(),
                packet: Some(u64::try_from(index + 1)?),
                offset: self.offset,
                length,
            }],
            json!({"session_index": session_index}),
        )?;
        for layer in layers {
            self.case.add_edge(Edge {
                from: layer,
                to: message,
                relation: "contains".to_owned(),
                status: EvidenceStatus::Observed,
                reason: "Message is reached through a direction wrapper".to_owned(),
            })?;
        }
        self.offset = self
            .offset
            .checked_add(length)
            .ok_or("source range overflow")?;
        Ok(())
    }

    fn direction_layers(
        &mut self,
        session: u64,
        directions: &[&str],
    ) -> Result<Vec<u64>, Box<dyn Error>> {
        let mut layers = Vec::new();
        for direction_name in directions {
            let (source_endpoint, destination_endpoint) = if *direction_name == FIRST {
                (&self.endpoints[0], &self.endpoints[1])
            } else {
                (&self.endpoints[1], &self.endpoints[0])
            };
            let direction = self.case.add_node(
                "tcp_direction",
                None,
                Vec::new(),
                json!({"source": source_endpoint, "destination": destination_endpoint}),
            )?;
            self.case.add_edge(Edge {
                from: session,
                to: direction,
                relation: "contains".to_owned(),
                status: EvidenceStatus::Hypothesis,
                reason: "Direction belongs to one test session".to_owned(),
            })?;
            let branch_count = if self.shared_direction_owner { 2 } else { 1 };
            for _ in 0..branch_count {
                let layer = self
                    .case
                    .add_node("context_layer", None, Vec::new(), json!({}))?;
                self.case.add_edge(Edge {
                    from: direction,
                    to: layer,
                    relation: "contains".to_owned(),
                    status: EvidenceStatus::Hypothesis,
                    reason: "Wrapper preserves the direction owner".to_owned(),
                })?;
                layers.push(layer);
            }
        }
        Ok(layers)
    }
}

fn protocol_sample_args(ids: &[u64]) -> Vec<String> {
    let roles = ["request", "response", "request", "response"];
    let mut args = vec!["protocol".to_owned(), "-".to_owned()];
    for (id, role) in ids.iter().zip(roles) {
        args.extend(["--sample".to_owned(), format!("{id}:{role}")]);
    }
    args
}

fn message_ids(case: &Case) -> Result<Vec<u64>, Box<dyn Error>> {
    let value: Value = serde_json::from_slice(&case.to_json()?)?;
    value
        .pointer("/nodes")
        .and_then(Value::as_array)
        .ok_or("missing case nodes")?
        .iter()
        .filter(|node| node.get("kind") == Some(&json!("message")))
        .map(|node| {
            node.get("id")
                .and_then(Value::as_u64)
                .ok_or_else(|| "message has no identifier".into())
        })
        .collect()
}

fn run_ids(case: &Case) -> Result<Vec<u64>, Box<dyn Error>> {
    let value: Value = serde_json::from_slice(&case.to_json()?)?;
    value
        .pointer("/nodes")
        .and_then(Value::as_array)
        .ok_or("missing case nodes")?
        .iter()
        .filter(|node| node.get("kind") == Some(&json!("tcp_byte_run")))
        .map(|node| {
            node.get("id")
                .and_then(Value::as_u64)
                .ok_or_else(|| "TCP run has no identifier".into())
        })
        .collect()
}
