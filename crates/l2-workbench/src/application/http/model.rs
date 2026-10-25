use super::ByteRange;
use crate::application::{ParseStatus, ParserBudget};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HttpMessage {
    pub range: ByteRange,
    pub status: ParseStatus,
    pub line_ending: HttpLineEnding,
    pub start_line: ByteRange,
    pub start: HttpStart,
    pub headers: Vec<HttpHeader>,
    pub framing: HttpFraming,
    pub body: HttpBody,
}

/// Line ending used by the start line and header fields
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpLineEnding {
    CrLf,
    Lf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HttpStart {
    Request {
        method: ByteRange,
        target: ByteRange,
    },
    Response {
        status_code: u16,
    },
}

/// Method associated with a response in the opposite TCP direction
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpRequestMethod {
    Head,
    Connect,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct HttpHeader {
    pub range: ByteRange,
    pub name: ByteRange,
    pub value: ByteRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HttpFraming {
    NoBody,
    ContentLength { expected: usize },
    Chunked,
    CloseDelimited,
    Tunnel,
    Unsupported,
    Ambiguous,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HttpBody {
    Empty,
    Contiguous {
        range: ByteRange,
        complete: bool,
    },
    Chunked {
        chunks: Vec<ByteRange>,
        trailers: Vec<HttpHeader>,
        trailer_range: Option<ByteRange>,
        raw_remainder: Option<ByteRange>,
        complete: bool,
    },
    Unresolved {
        range: ByteRange,
    },
    Tunnel {
        range: ByteRange,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HeadScan {
    pub line_ending: HttpLineEnding,
    pub start_line: ByteRange,
    pub start: HttpStart,
    pub headers: Vec<HttpHeader>,
    pub body_offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BodyPolicy {
    NoBody(ParseStatus),
    ContentLength(usize),
    Chunked,
    CloseDelimited,
    Tunnel(ParseStatus),
    Unsupported,
    Ambiguous,
}

pub(super) struct ChunkScan {
    pub chunks: Vec<ByteRange>,
    pub trailers: Vec<HttpHeader>,
    pub trailer_range: Option<ByteRange>,
    pub raw_remainder: Option<ByteRange>,
    pub next_offset: usize,
    pub status: ParseStatus,
    pub budget: Option<ParserBudget>,
    pub complete: bool,
}
