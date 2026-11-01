//! One presentation envelope for receive-only collection

use std::io::{self, Write};

use l2_active::{Limits, RunSummary};
use l2_active_linux::InterfaceSelector;
use l2_capture::CapturedFrame;
use serde::Serialize;
use serde_json::ser::{CompactFormatter, Formatter, PrettyFormatter};

use crate::{
    ActiveOutcome, Error, OutputFormat,
    interface_view::InterfaceView,
    report_common::{self, Evidence, LimitsView, QualityView, SendMode},
};

#[derive(Serialize)]
pub(super) struct FrameView {
    captured_bytes: usize,
    original_bytes: u32,
    frame_hex: String,
}

impl FrameView {
    pub(super) fn new(frame: &CapturedFrame) -> Result<Self, Error> {
        Ok(Self {
            captured_bytes: frame.captured_len(),
            original_bytes: frame.metadata().original_len(),
            frame_hex: report_common::frame_hex(frame.bytes())?,
        })
    }
}

pub(super) struct Operation {
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

pub(super) struct Collection<'a, T, D> {
    pub operation: Operation,
    pub interface: &'a InterfaceSelector,
    pub vlan: Option<l2_active_linux::VlanInfo>,
    pub limits: Limits,
    pub summary: &'a RunSummary,
    pub observations: Vec<T>,
    pub details: D,
    pub close_error: Option<&'a io::Error>,
}

impl<T: Serialize, D: Serialize> Collection<'_, T, D> {
    pub(super) fn write(
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
            quality: QualityView::new(self.summary, self.close_error),
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

fn write_json<T: Serialize, F: Formatter>(
    output: &mut impl Write,
    value: &T,
    formatter: F,
) -> serde_json::Result<()> {
    let mut serializer = serde_json::Serializer::with_formatter(output, SafeFormatter(formatter));
    value.serialize(&mut serializer)
}

// JSON escapes preserve the original value when a consumer decodes it
struct SafeFormatter<F>(F);

impl<F: Formatter> Formatter for SafeFormatter<F> {
    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        for chunk in fragment.split_inclusive(needs_escape) {
            let mut chars = chunk.chars();
            if let Some(character) = chars.next_back()
                && needs_escape(character)
            {
                writer.write_all(chars.as_str().as_bytes())?;
                let mut units = [0_u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    write!(writer, "\\u{unit:04x}")?;
                }
            } else {
                writer.write_all(chunk.as_bytes())?;
            }
        }
        Ok(())
    }

    fn begin_array<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.0.begin_array(writer)
    }

    fn end_array<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.0.end_array(writer)
    }

    fn begin_array_value<W>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.0.begin_array_value(writer, first)
    }

    fn end_array_value<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.0.end_array_value(writer)
    }

    fn begin_object<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.0.begin_object(writer)
    }

    fn end_object<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.0.end_object(writer)
    }

    fn begin_object_key<W>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.0.begin_object_key(writer, first)
    }

    fn begin_object_value<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.0.begin_object_value(writer)
    }

    fn end_object_value<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.0.end_object_value(writer)
    }
}

fn needs_escape(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{206f}'
        )
}
