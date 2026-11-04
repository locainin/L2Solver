use crate::cooked_analysis;
use l2_workbench::behavior::{BehaviorConfig, BehaviorKind, analyze_case};
use std::error::Error;

#[test]
fn cooked_tcp_syn_service_sweep_retains_packet_witnesses() -> Result<(), Box<dyn Error>> {
    for version in [113, 276] {
        let frames = [80, 443, 8443]
            .into_iter()
            .map(|port| cooked_analysis::frame(version, 37, port, 0x02))
            .collect::<Result<Vec<_>, _>>()?;
        let result = cooked_analysis::case(frames)?;
        let report = analyze_case(&result.case, &BehaviorConfig::default())?;
        assert!(
            report.findings.iter().any(|finding| {
                finding.kind == BehaviorKind::TcpSynServiceSweep
                    && finding.packet_numbers == [1, 2, 3]
            }),
            "link type {version}"
        );
    }
    Ok(())
}
