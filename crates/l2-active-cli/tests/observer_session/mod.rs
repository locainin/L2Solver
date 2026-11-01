use std::{
    error::Error,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

use clap::Parser;

use crate::{ActiveCommand, Cli, VrrpCommand, observer_session::prepare};

fn options(interface: &str, timeout: &str) -> Result<crate::ObserveArgs, Box<dyn Error>> {
    let cli = Cli::try_parse_from([
        "l2solver-active",
        "vrrp",
        "observe",
        "--interface",
        interface,
        "--timeout-ms",
        timeout,
    ])?;
    let ActiveCommand::Vrrp {
        command: VrrpCommand::Observe(options),
    } = cli.active.command
    else {
        return Err("expected VRRP observation".into());
    };
    Ok(options.observe)
}

#[test]
fn cancellation_stops_observer_before_any_interface_lookup() -> Result<(), Box<dyn Error>> {
    let result = prepare(&options("l2s-no-test", "500")?, &AtomicBool::new(true));
    assert!(
        matches!(result, Err(crate::Error::Discovery(error)) if error.kind() == std::io::ErrorKind::Interrupted)
    );
    Ok(())
}

#[test]
fn discovered_observer_has_the_requested_limits_and_bounded_deadline() -> Result<(), Box<dyn Error>>
{
    let options = options("lo", "5000")?;
    let before = Instant::now();
    let prepared = prepare(&options, &AtomicBool::new(false))?;
    let after = Instant::now();
    assert_eq!(prepared.info.name(), "lo");
    assert_eq!(prepared.limits.timeout(), Duration::from_secs(5));
    assert!(prepared.deadline >= before + Duration::from_secs(5));
    assert!(prepared.deadline <= after + Duration::from_secs(5));
    Ok(())
}

#[test]
fn missing_interface_is_an_error_without_opening_a_helper() -> Result<(), Box<dyn Error>> {
    let result = prepare(&options("l2s-no-test", "500")?, &AtomicBool::new(false));
    assert!(
        matches!(result, Err(crate::Error::Discovery(error)) if error.kind() == std::io::ErrorKind::NotFound)
    );
    Ok(())
}
