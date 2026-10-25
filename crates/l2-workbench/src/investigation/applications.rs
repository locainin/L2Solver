use super::{
    artifacts,
    graph::{Context, MappedRange, clip},
    network::value_node,
};
use crate::{
    application::{
        ByteRange, ParseContext, ParseReport, ParseStatus,
        dns_tcp::decode_dns_tcp,
        ftp::{FtpItem, decode_ftp},
        http::{HttpBody, HttpRequestMethod, decode_http_with_methods},
    },
    evidence::EvidenceStatus,
};
use serde_json::json;
use std::error::Error;

pub(super) fn add(
    context: &mut Context<'_>,
    input_node: u64,
    bytes: &[u8],
    mappings: &[MappedRange],
    parse_context: ParseContext,
    request_methods: &[Option<HttpRequestMethod>],
) -> Result<ParseReport<FtpItem>, Box<dyn Error>> {
    let dns = decode_dns_tcp(bytes, parse_context);
    let http = decode_http_with_methods(bytes, parse_context, request_methods);
    let ftp = decode_ftp(bytes, parse_context);
    if !dns.budget_omissions.is_empty()
        || !http.budget_omissions.is_empty()
        || !ftp.budget_omissions.is_empty()
    {
        context.incomplete = true;
        context.case.add_limitation(
            "Optional application parser candidates were omitted after configured byte or entry budgets; exact untested ranges appear in application_checks while the retained capture bytes remain available",
        )?;
    }
    // A failed format attempt remains a check result, not a protocol identification
    let checks = value_node(
        context,
        "application_checks",
        json!({
            "dns_tcp": {"status": dns.status, "structural_messages": dns.findings.iter().filter(|item| item.message.is_some()).count(),
                "unparsed": &dns.unparsed, "budget_omissions": &dns.budget_omissions},
            "http": {"status": http.status, "messages": http.findings.len(),
                "unparsed": &http.unparsed, "budget_omissions": &http.budget_omissions},
            "ftp": {"status": ftp.status, "items": ftp.findings.len(),
                "unparsed": &ftp.unparsed, "budget_omissions": &ftp.budget_omissions},
            "start_known": parse_context.start_known, "end_observed": parse_context.end_observed,
            "interpretation": "Independent framing candidates; ports and printable data do not select a protocol",
        }),
        &[],
    )?;
    context.edge(
        input_node,
        checks,
        "tested_by",
        EvidenceStatus::Observed,
        "Bounded parsers were applied to these exact bytes",
    )?;
    for frame in dns.findings.iter().filter(|item| item.message.is_some()) {
        let ranges = clip(mappings, frame.frame_range.offset, frame.frame_range.length)?;
        let id = value_node(
            context,
            "dns_tcp_candidate",
            serde_json::to_value(frame)?,
            &ranges,
        )?;
        context.edge(
            input_node,
            id,
            "parsed_as",
            EvidenceStatus::Hypothesis,
            "A length-prefixed candidate passes the supported DNS wire decoder",
        )?;
    }
    http_candidates(context, input_node, bytes, mappings, &http)?;
    Ok(ftp)
}

fn http_candidates(
    context: &mut Context<'_>,
    input_node: u64,
    bytes: &[u8],
    mappings: &[MappedRange],
    http: &crate::application::ParseReport<crate::application::http::HttpMessage>,
) -> Result<(), Box<dyn Error>> {
    for message in &http.findings {
        let ranges = clip(mappings, message.range.offset, message.range.length)?;
        let id = value_node(
            context,
            "http_message_candidate",
            serde_json::to_value(message)?,
            &ranges,
        )?;
        context.edge(
            input_node,
            id,
            "parsed_as",
            EvidenceStatus::Hypothesis,
            "Supported HTTP syntax and framing were tested on retained contiguous bytes",
        )?;
        match &message.body {
            HttpBody::Contiguous { range, complete } => {
                body(
                    context,
                    id,
                    bytes,
                    mappings,
                    &[*range],
                    message.status,
                    *complete,
                )?;
            }
            HttpBody::Chunked {
                chunks, complete, ..
            } => {
                body(
                    context,
                    id,
                    bytes,
                    mappings,
                    chunks,
                    message.status,
                    *complete,
                )?;
            }
            // Unresolved framing and tunnels have no justified HTTP body boundary
            HttpBody::Empty | HttpBody::Unresolved { .. } | HttpBody::Tunnel { .. } => {}
        }
    }
    Ok(())
}

fn body(
    context: &mut Context<'_>,
    message: u64,
    input: &[u8],
    mappings: &[MappedRange],
    chunks: &[ByteRange],
    status: ParseStatus,
    complete: bool,
) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::new();
    let mut origins = Vec::new();
    for chunk in chunks {
        let data = chunk
            .slice(input)
            .ok_or("HTTP body range exceeds its input")?;
        let start = bytes.len();
        origins.extend(clip(mappings, chunk.offset, chunk.length)?.into_iter().map(
            |mut mapping| {
                mapping.offset += start;
                mapping
            },
        ));
        bytes.extend_from_slice(data);
    }
    let id = context.case.add_mapped_bytes_node("http_body", &bytes, &origins, json!({
        "status": status, "framing_complete": complete, "body_length": bytes.len(), "input_ranges": chunks,
        "interpretation": "Body bytes under this framing candidate; content encoding and authenticity are unresolved",
    }))?;
    context.edge(
        message,
        id,
        "derived_from",
        if status == ParseStatus::Complete && complete {
            EvidenceStatus::ConstraintSatisfied
        } else {
            EvidenceStatus::Unresolved
        },
        "HTTP body framing supplies the listed byte ranges; chunk metadata is excluded",
    )?;
    artifacts::add(context, id, &bytes, &origins)?;
    Ok(())
}
