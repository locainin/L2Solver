include!("../../src/policy.rs");

#[test]
fn rejects_invalid_policies() -> Result<(), Box<dyn std::error::Error>> {
    let address = wifi_core::MacAddress::new([2, 0, 0, 0, 0, 1]);
    let cases = vec![
        (
            vec![address, address],
            vec![wifi_discovery::SecurityMode::Wpa3Personal],
            vec![36],
        ),
        (
            vec![address],
            vec![
                wifi_discovery::SecurityMode::Wpa3Personal,
                wifi_discovery::SecurityMode::Wpa3Personal,
            ],
            vec![36],
        ),
        (
            vec![address],
            vec![wifi_discovery::SecurityMode::Wpa3Personal],
            vec![36, 36],
        ),
    ];

    for (allowed_bssids, security_modes, allowed_channels) in cases {
        let network = WirelessNetworkPolicy {
            ssid: b"Corp".to_vec(),
            allowed_bssids,
            security_modes,
            pmf: PmfRequirement::Optional,
            wps_allowed: false,
            allowed_channels,
        };
        assert!(network.validate().is_err());
    }

    let network = WirelessNetworkPolicy::new(b"Corp".to_vec())?;
    assert_eq!(network.ssid(), b"Corp");
    assert_eq!(network.allowed_bssids(), []);
    assert_eq!(network.security_modes(), []);
    assert_eq!(network.pmf(), PmfRequirement::Optional);
    assert!(!network.wps_allowed());
    assert_eq!(network.allowed_channels(), []);
    let policy = WirelessPolicy {
        networks: vec![network.clone(), network],
        unlisted_ssids_forbidden: false,
    };
    assert!(policy.network(b"Corp").is_some());
    assert!(!policy.unlisted_ssids_forbidden());
    assert!(policy.validate().is_err());
    Ok(())
}
