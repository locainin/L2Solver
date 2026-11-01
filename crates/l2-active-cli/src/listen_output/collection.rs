//! One presentation envelope for receive-only collection

use std::io::{self, Write};

use l2_active::{Limits, RunSummary};
use l2_active_linux::InterfaceSelector;
use l2_capture::CapturedFrame;
use serde::Serialize;
use serde_json::ser::{CompactFormatter, PrettyFormatter};

use crate::{
    ActiveOutcome, Error, OutputFormat,
    interface_view::InterfaceView,
    report_common::{self, Evidence, LimitsView, QualityView, SendMode},
    safe_json::write_json,
};

#[derive(Serialize)]
pub(crate) struct FrameView {
    captured_bytes: usize,
    original_bytes: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    frame_hex: Option<String>,
}

impl FrameView {
    pub(crate) fn new(frame: &CapturedFrame) -> Result<Self, Error> {
        Self::for_disclosure(frame, Disclosure::IncludeRaw)
    }

    pub(crate) fn for_disclosure(
        frame: &CapturedFrame,
        disclosure: Disclosure,
    ) -> Result<Self, Error> {
        Ok(Self {
            captured_bytes: frame.captured_len(),
            original_bytes: frame.metadata().original_len(),
            frame_hex: match disclosure {
                Disclosure::OmitRaw => None,
                Disclosure::IncludeRaw => Some(report_common::frame_hex(frame.bytes())?),
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Disclosure {
    OmitRaw,
    IncludeRaw,
}

#[derive(Clone, Copy)]
pub(crate) enum Diagnostics {
    Detailed,
    CodesOnly,
}

pub(crate) struct Context<'a> {
    pub interface: &'a InterfaceSelector,
    pub vlan: Option<l2_active_linux::VlanInfo>,
    pub limits: Limits,
    pub close_error: Option<&'a io::Error>,
    pub disclosure: Disclosure,
}

impl<'a> Context<'a> {
    pub fn new(
        options: &'a crate::ObserveArgs,
        vlan: Option<l2_active_linux::VlanInfo>,
        limits: Limits,
        close_error: Option<&'a io::Error>,
    ) -> Self {
        Self {
            interface: &options.interface,
            vlan,
            limits,
            close_error,
            disclosure: if options.include_raw {
                Disclosure::IncludeRaw
            } else {
                Disclosure::OmitRaw
            },
        }
    }
}

pub(crate) struct Operation {
    pub name: &'static str,
    pub status: &'static str,
    pub evidence: Evidence,
    pub limitation: &'static str,
}

#[derive(Serialize)]
struct Report<'a, T, D> {
    operation: &'static str,
    status: &'static str,
    completion: &'static str,
    scope: InterfaceView<'a>,
    limits: LimitsView,
    #[serde(flatten)]
    quality: QualityView,
    authenticated: bool,
    details: D,
    observations: Vec<T>,
    limitation: &'static str,
}

pub(crate) struct Collection<'a, T, D> {
    pub operation: Operation,
    pub interface: &'a InterfaceSelector,
    pub vlan: Option<l2_active_linux::VlanInfo>,
    pub limits: Limits,
    pub summary: &'a RunSummary,
    pub observations: Vec<T>,
    pub details: D,
    pub close_error: Option<&'a io::Error>,
    pub diagnostics: Diagnostics,
}

impl<T: Serialize, D: Serialize> Collection<'_, T, D> {
    pub(crate) fn write(
        self,
        format: OutputFormat,
        output: &mut impl Write,
    ) -> Result<ActiveOutcome, Error> {
        let outcome = report_common::outcome(
            self.summary,
            SendMode::Listen,
            self.operation.evidence,
            self.close_error,
        );
        let value = Report {
            operation: self.operation.name,
            status: self.operation.status,
            completion: report_common::completion_name(outcome),
            scope: InterfaceView::new(self.interface.name(), self.summary.interface(), self.vlan),
            limits: LimitsView::new(self.limits),
            quality: match self.diagnostics {
                Diagnostics::Detailed => QualityView::new(self.summary, self.close_error),
                Diagnostics::CodesOnly => QualityView::codes_only(self.summary, self.close_error),
            },
            authenticated: false,
            details: self.details,
            observations: self.observations,
            limitation: self.operation.limitation,
        };
        match format {
            OutputFormat::Json => write_json(output, &value, CompactFormatter),
            OutputFormat::Text => {
                writeln!(
                    output,
                    "{} on {}: {}; completion: {}",
                    value.operation,
                    self.interface.name().escape_debug(),
                    value.status,
                    value.completion
                )
                .map_err(Error::Output)?;
                // Preserve the readable layout without writing terminal control characters
                write_json(output, &value, PrettyFormatter::new())
            }
        }
        .map_err(Error::Json)?;
        writeln!(output).map_err(Error::Output)?;
        Ok(outcome)
    }
}
