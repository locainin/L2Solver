use l2_workbench::experiment::{ExperimentMode, Mutation, MutationPlan, run};
use std::error::Error;

#[test]
fn loopback_mode_received_owned_server() -> Result<(), Box<dyn Error>> {
    let input = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let plan = MutationPlan {
        mutations: vec![Mutation::FlipBit { offset: 4, bit: 0 }],
    };

    let report = run(input, &plan, ExperimentMode::Loopback)?;

    assert_eq!(report.steps.len(), 2);
    for step in &report.steps {
        let receipt = step.transport.as_ref().ok_or("loopback receipt missing")?;
        assert_eq!(receipt.sent_length, receipt.received_length);
        assert!(receipt.matches_sent);
        assert_eq!(receipt.received_sha256, step.output_sha256);
        assert_ne!(receipt.port, 0);
    }
    let parser = report
        .steps
        .get(1)
        .and_then(|step| step.parser.as_ref())
        .ok_or("server parser summary missing")?;
    assert_eq!(parser.http.finding_count, 1);
    Ok(())
}
