//! Bounded two-interface ARP canary assessment

#[cfg(target_os = "linux")]
mod budget;
#[cfg(target_os = "linux")]
mod decision;
#[cfg(target_os = "linux")]
mod engine;
#[cfg(target_os = "linux")]
mod output;
#[cfg(target_os = "linux")]
mod prepare;
#[cfg(target_os = "linux")]
mod scope;

use std::{io::Write, sync::atomic::AtomicBool};

use crate::{ActiveOutcome, Error, OutputFormat, vlan_arguments::VlanAssessmentArgs};

pub fn run(
    options: &VlanAssessmentArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    run_platform(options, format, cancelled, output).map_err(Error::codes_only)
}

#[cfg(target_os = "linux")]
fn run_platform(
    options: &VlanAssessmentArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    use std::{io, sync::atomic::Ordering};

    use crate::session_options;

    use self::engine::SkipReason;

    if cancelled.load(Ordering::Acquire) {
        return stopped(options, SkipReason::Cancelled, format, output);
    }
    let budget = session_options::limits(&options.session)?;
    // One absolute deadline includes discovery and all helper sessions
    let deadline = session_options::deadline(budget)?;
    let prepared = match prepare::prepare(options, deadline, cancelled) {
        Ok(prepared) => prepared,
        Err(Error::Discovery(error))
            if error.kind() == io::ErrorKind::Interrupted && cancelled.load(Ordering::Acquire) =>
        {
            return stopped(options, SkipReason::Cancelled, format, output);
        }
        Err(Error::Discovery(error)) if error.kind() == io::ErrorKind::TimedOut => {
            return stopped(options, SkipReason::Deadline, format, output);
        }
        Err(error) => return Err(error),
    };
    let helper = session_options::helper(options.session.helper.as_deref())?;
    let result = engine::run(budget, deadline, cancelled, |phase, limits, end| {
        let selected = match phase {
            engine::Phase::ControlBefore | engine::Phase::ControlAfter => &prepared.control,
            engine::Phase::Test => &prepared.test,
        };
        attempt(selected, options, &helper, limits, end, cancelled)
    });
    let context = output::Context {
        control: prepared.control.endpoint(),
        test: prepared.test.endpoint(),
        target: options.target,
        expected: options.expected_mac,
        budget,
        disclosure: if options.include_raw {
            crate::listen_output::collection::Disclosure::IncludeRaw
        } else {
            crate::listen_output::collection::Disclosure::OmitRaw
        },
    };
    output::write(&context, &result, cancelled, format, output)
}

#[cfg(target_os = "linux")]
fn attempt(
    selected: &prepare::Selected<'_>,
    options: &VlanAssessmentArgs,
    helper: &std::path::Path,
    limits: l2_active::Limits,
    deadline: std::time::Instant,
    cancelled: &AtomicBool,
) -> engine::Attempt {
    use std::io;

    use l2_active::ArpProbe;
    use l2_active_linux::HelperLink;

    use self::engine::{Attempt, FailureStage};

    // Rebuild the same admitted ARP request with this phase's remaining limits
    let probe = match ArpProbe::new(
        selected.mac,
        selected.source,
        options.target,
        Some(options.expected_mac),
        limits,
    ) {
        Ok(probe) => probe,
        Err(error) => {
            return Attempt::Failure {
                stage: FailureStage::Prepare,
                error: io::Error::other(error),
                close_error: None,
            };
        }
    };
    let mut link = match HelperLink::open(
        helper,
        selected.selector,
        &selected.info,
        &probe,
        deadline,
        cancelled,
    ) {
        Ok(link) => link,
        Err(error) => {
            return Attempt::Failure {
                stage: FailureStage::Open,
                error,
                close_error: None,
            };
        }
    };
    let admitted = link.deadline().min(deadline);
    let report = probe.run_until(&mut link, cancelled, admitted);
    let close_error = link.close().err();
    match report {
        Ok(report) => Attempt::Report {
            report,
            close_error,
        },
        Err(error) => Attempt::Failure {
            stage: FailureStage::Run,
            error: io::Error::other(error),
            close_error,
        },
    }
}

#[cfg(target_os = "linux")]
fn stopped(
    options: &VlanAssessmentArgs,
    reason: engine::SkipReason,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    output::write_stopped(
        options.control_interface.name(),
        options.interface.name(),
        options.target,
        options.expected_mac,
        reason,
        format,
        output,
    )
}

#[cfg(not(target_os = "linux"))]
fn run_platform(
    _options: &VlanAssessmentArgs,
    _format: OutputFormat,
    _cancelled: &AtomicBool,
    _output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    Err(Error::Helper(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "active packet I/O requires Linux",
    )))
}
