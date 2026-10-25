//! Dynamic PCAPNG recording for validated receive-side frames

use crate::FrameRecorder;
use l2_capture::{CapturedFrame, InterfaceId};
use l2_pcap::{InterfaceConfig, MAX_FRAME_LENGTH, PcapNgWriter, WriterError};
use std::{collections::BTreeSet, io::Write};

/// A bounded PCAPNG recorder that registers each source on first use
pub struct PcapNgRecorder<Output> {
    writer: PcapNgWriter<Output>,
    interfaces: BTreeSet<InterfaceId>,
}

impl<Output: Write> PcapNgRecorder<Output> {
    /// Start a PCAPNG evidence stream with an absolute output quota
    ///
    /// # Errors
    /// Returns a writer error for an invalid quota or initial output failure
    pub fn new(output: Output, output_limit: u64) -> Result<Self, WriterError> {
        Ok(Self {
            writer: PcapNgWriter::new(output, output_limit)?,
            interfaces: BTreeSet::new(),
        })
    }

    /// Start with acquisition conditions that can be finalized before publication
    ///
    /// # Errors
    /// Returns a quota or output error
    pub fn new_with_collection_report(
        output: Output,
        output_limit: u64,
        report: l2_pcap::CollectionReport,
    ) -> Result<Self, WriterError> {
        Ok(Self {
            writer: PcapNgWriter::new_with_collection_report(output, output_limit, report)?,
            interfaces: BTreeSet::new(),
        })
    }

    /// Finalize the acquisition declaration while retaining packet offsets
    ///
    /// # Errors
    /// Returns the writer's metadata, seek, or output error
    pub fn update_collection_report(
        &mut self,
        report: l2_pcap::CollectionReport,
    ) -> Result<(), WriterError>
    where
        Output: std::io::Seek,
    {
        self.writer.update_collection_report(report)
    }

    /// Flush and close the logical PCAPNG stream
    ///
    /// # Errors
    /// Returns the first writer or sink failure
    pub fn finish(&mut self) -> Result<(), WriterError> {
        self.writer.finish()
    }

    /// Return the number of complete packet blocks committed to the stream
    #[must_use]
    pub const fn packet_count(&self) -> u32 {
        self.writer.packet_count()
    }

    /// Return the complete number of PCAPNG bytes committed to the stream
    #[must_use]
    pub const fn bytes_written(&self) -> u64 {
        self.writer.bytes_written()
    }

    /// Return the number of registered capture sources
    #[must_use]
    pub fn interface_count(&self) -> usize {
        self.interfaces.len()
    }

    /// Recover the caller-owned output after recording is complete
    #[must_use]
    pub fn into_inner(self) -> Output {
        self.writer.into_inner()
    }

    fn config_for_frame(frame: &CapturedFrame) -> Result<InterfaceConfig, WriterError> {
        let metadata = frame.metadata();
        let timestamp = metadata.timestamp().ok_or(WriterError::MissingTimestamp)?;
        let config = InterfaceConfig::new_with_link_type(
            metadata.link_type(),
            MAX_FRAME_LENGTH,
            timestamp.resolution(),
            timestamp.offset_seconds(),
            metadata.fcs(),
        )?;
        Ok(metadata
            .linux_interface()
            .map_or(config, |identity| config.with_linux_interface(identity)))
    }
}

impl<Output> FrameRecorder for PcapNgRecorder<Output>
where
    Output: Write,
{
    type Error = WriterError;

    fn record(&mut self, frame: &CapturedFrame) -> Result<(), Self::Error> {
        let source = frame.metadata().interface();
        if self.interfaces.contains(&source) {
            return self.writer.write_frame(frame);
        }

        // The writer validates and sizes the IDB plus first EPB before either
        // block is sent, so failed first frames leave no logical interface
        let config = Self::config_for_frame(frame)?;
        self.writer
            .add_interface_and_write_frame(source, config, frame)?;
        self.interfaces.insert(source);
        Ok(())
    }
}
