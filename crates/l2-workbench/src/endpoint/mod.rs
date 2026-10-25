//! Native endpoint evidence adapters with raw-source ranges

mod common;
mod event_xml;
mod evtx;
mod mft;
mod strace;
mod trace_match;
mod usn;

pub use common::{EndpointImportError, MAX_ENDPOINT_RECORDS};
pub use event_xml::{EventXmlRecord, EventXmlReport, SysmonTimeChange, parse_event_xml};
pub use evtx::{EvtxBinXmlStatus, EvtxChunk, EvtxRecordEnvelope, EvtxReport, parse_evtx_envelope};
pub use mft::{
    MftFileName, MftRecord, MftReport, MftTimestampSet, MftVisitError, parse_mft, parse_mft_reader,
    visit_mft_records,
};
pub use strace::{
    IoDirection, SocketEndpoint, SocketTuple, TraceCodeFrame, TraceIoEvent, TraceIoReport,
    TraceTransport, parse_strace,
};
pub use trace_match::{
    TraceCorrelation, TraceMatchStatus, TracePacketRange, correlate_trace_with_capture,
};
pub use usn::{
    UsnFileReference, UsnRecord, UsnReport, UsnUnsupportedRecord, parse_usn_device_buffer,
    parse_usn_records,
};
