use super::LiveStatistics;

#[test]
fn libpcap_counters_without_loss_coverage() {
    let statistics = LiveStatistics::from_pcap(pcap::Stat {
        received: 17,
        dropped: 0,
        if_dropped: 0,
    });

    assert_eq!(statistics.received(), 17);
    assert_eq!(statistics.capture_dropped(), 0);
    assert_eq!(statistics.interface_dropped(), 0);
    assert!(!statistics.loss_counters_authoritative());
}

#[test]
fn libpcap_nonzero_loss_counters() {
    let statistics = LiveStatistics::from_pcap(pcap::Stat {
        received: 17,
        dropped: 3,
        if_dropped: 5,
    });

    assert_eq!(statistics.received(), 17);
    assert_eq!(statistics.capture_dropped(), 3);
    assert_eq!(statistics.interface_dropped(), 5);
    assert!(!statistics.loss_counters_authoritative());
}
