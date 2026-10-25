use l2_discovery::NetworkAddress;
use l2_discovery::dns::{DnsErrorKind, DnsRecord, DnsSection, DnsValue, decode};

use crate::support::{
    MultiSectionRecordFixture, append_record, header, labels, multi_section_record_fixture,
    range_bytes, root_name,
};

#[test]
fn decoded_section_supported_values() -> Result<(), &'static str> {
    let fixture = multi_section_record_fixture()?;
    let message = decode(&fixture.bytes).map_err(|_| "multi-section DNS response should decode")?;
    assert_eq!(message.id, 0x8a30);
    assert_eq!(message.flags, 0xa803);
    assert!(message.is_response());
    assert_eq!(message.opcode(), 5);
    assert_eq!(message.response_code(), 3);
    let [question] = message.questions.as_slice() else {
        return Err("expected exactly one question");
    };
    assert_eq!(question.qtype, 1);
    assert_eq!(question.qclass, 1);

    let records = &message.records;
    let [a, aaaa, cname, ns, ptr, opt] = records.as_slice() else {
        return Err("expected exactly six records");
    };

    // Check each value family after confirming the complete record order
    assert_address_records(a, aaaa, &fixture)?;
    assert_name_records(cname, ns, ptr, &fixture)?;
    assert_eq!(opt.section, DnsSection::Additional);
    assert!(matches!(&opt.value, DnsValue::Opaque));
    Ok(())
}

#[test]
fn rdata_ranges_absolute_message_offsets() -> Result<(), &'static str> {
    let fixture = multi_section_record_fixture()?;
    let message = decode(&fixture.bytes).map_err(|_| "multi-section DNS response should decode")?;

    for (index, (record, expected_range)) in
        message.records.iter().zip(fixture.rdata_ranges).enumerate()
    {
        assert_eq!(record.rdata.offset, expected_range.start);
        assert_eq!(record.rdata.length, expected_range.len());
        assert_eq!(
            range_bytes(
                &fixture.bytes,
                record.rdata.offset,
                record.rdata.offset + record.rdata.length
            )?,
            range_bytes(&fixture.bytes, expected_range.start, expected_range.end)?
        );
        if index == 3 {
            assert_eq!(
                record.rdata.length, 2,
                "compressed name value keeps its original RDATA range"
            );
        }
    }
    Ok(())
}

#[test]
fn unknown_types_including_empty_rdata() -> Result<(), &'static str> {
    let mut bytes = header(4, 0, 0, 3, 0, 0);
    let owner = root_name();
    let unknown_type_range = append_record(&mut bytes, &owner, 65000, 1, 1, &[1, 2, 3])?;
    let unknown_class_range = append_record(&mut bytes, &owner, 1, 3, 2, &[1])?;
    let empty_range = append_record(&mut bytes, &owner, 65001, 1, 3, &[])?;

    let message = decode(&bytes).map_err(|_| "unknown records should decode as opaque")?;
    assert_eq!(message.records.len(), 3);
    for (record, expected) in
        message
            .records
            .iter()
            .zip([unknown_type_range, unknown_class_range, empty_range])
    {
        assert_eq!(record.value, DnsValue::Opaque);
        assert_eq!(record.rdata.offset, expected.start);
        assert_eq!(record.rdata.length, expected.len());
    }
    assert_eq!(
        message
            .records
            .last()
            .ok_or("empty-RDATA record missing")?
            .rdata
            .length,
        0
    );
    Ok(())
}

#[test]
fn malformed_address_rdata_lengths_rejected() -> Result<(), &'static str> {
    for (rr_type, length) in [(1_u16, 0_usize), (1, 3), (1, 5), (28, 15), (28, 17)] {
        let mut bytes = header(5, 0x8000, 0, 1, 0, 0);
        let data = vec![0x5a; length];
        append_record(&mut bytes, &root_name(), rr_type, 1, 0, &data)?;
        assert!(
            decode(&bytes).is_err(),
            "type {rr_type} with RDATA length {length} accepted"
        );
    }

    let mut non_in_a = header(5, 0, 0, 1, 0, 0);
    append_record(&mut non_in_a, &root_name(), 1, 3, 0, &[0xaa])?;
    let message = decode(&non_in_a).map_err(|_| "non-IN A record should remain opaque")?;
    assert_eq!(
        message.records.first().ok_or("record missing")?.value,
        DnsValue::Opaque
    );
    Ok(())
}

#[test]
fn edns_extended_ttl_high_byte() -> Result<(), &'static str> {
    let mut bytes = header(6, 0x8003, 0, 0, 0, 1);
    append_record(
        &mut bytes,
        &root_name(),
        41,
        1232,
        0x0100_0000,
        &[0, 10, 0, 0],
    )?;
    let message = decode(&bytes).map_err(|_| "OPT record should decode")?;

    assert_eq!(message.response_code(), 19);
    let opt = message.records.first().ok_or("OPT record missing")?;
    assert_eq!(opt.section, DnsSection::Additional);
    assert_eq!(opt.rr_type, 41);
    assert_eq!(opt.ttl, 0x0100_0000);
    assert_eq!(
        range_bytes(
            &bytes,
            opt.rdata.offset,
            opt.rdata.offset + opt.rdata.length
        )?,
        [0, 10, 0, 0]
    );
    Ok(())
}

#[test]
fn duplicate_opt_rcode() -> Result<(), &'static str> {
    let mut bytes = header(9, 0x8003, 0, 0, 0, 2);
    append_record(&mut bytes, &root_name(), 41, 1232, 0x0100_0000, &[])?;
    append_record(&mut bytes, &root_name(), 41, 1232, 0x0200_0000, &[])?;

    // Multiple extension records leave the effective response code ambiguous
    let decoded = decode(&bytes);
    assert!(
        decoded.is_err(),
        "duplicate OPT records were accepted with response code {:?}",
        decoded.ok().map(|message| message.response_code())
    );
    Ok(())
}

#[test]
fn non_root_not_response_code() -> Result<(), &'static str> {
    let mut bytes = header(10, 0x8003, 0, 0, 0, 1);
    let owner = labels(&[b"not-root", b"example"])?;
    append_record(&mut bytes, &owner, 41, 1232, 0x0100_0000, &[])?;

    // EDNS extension fields belong to the root-owned OPT pseudo-record
    let decoded = decode(&bytes);
    assert!(
        decoded.is_err(),
        "non-root OPT owner was accepted with response code {:?}",
        decoded.ok().map(|message| message.response_code())
    );
    Ok(())
}

#[test]
fn dns_message_size_boundary() -> Result<(), &'static str> {
    const MAX_MESSAGE_BYTES: usize = 16_384;
    let rdata_length = MAX_MESSAGE_BYTES - 23;
    let data = vec![0x5a; rdata_length];
    let mut exact = header(7, 0, 0, 1, 0, 0);
    append_record(&mut exact, &root_name(), 65000, 1, 0, &data)?;
    assert_eq!(exact.len(), MAX_MESSAGE_BYTES);
    assert!(
        decode(&exact).is_ok(),
        "exact byte limit should be accepted"
    );

    let mut over = header(7, 0, 0, 1, 0, 0);
    let mut extended = Vec::with_capacity(data.len() + 1);
    extended.extend_from_slice(&data);
    extended.push(0x33);
    append_record(&mut over, &root_name(), 65000, 1, 0, &extended)?;
    assert!(over.len() > MAX_MESSAGE_BYTES);
    assert_eq!(
        decode(&over)
            .err()
            .ok_or("over-limit DNS message was accepted")?
            .kind,
        DnsErrorKind::MessageLimit
    );
    Ok(())
}

fn assert_address_records(
    a: &DnsRecord,
    aaaa: &DnsRecord,
    fixture: &MultiSectionRecordFixture,
) -> Result<(), &'static str> {
    assert_eq!(a.section, DnsSection::Answer);
    assert_eq!(aaaa.section, DnsSection::Answer);
    // The A owner expands from the compressed question name
    assert_eq!(a.name.wire(), fixture.question_wire);
    assert_eq!(a.rr_type, 1);
    assert_eq!(a.class, 1);
    assert_eq!(a.ttl, 60);
    assert_eq!(aaaa.rr_type, 28);
    assert!(matches!(
        &a.value,
        DnsValue::Address(NetworkAddress::Ipv4([192, 0, 2, 7]))
    ));
    let DnsValue::Address(NetworkAddress::Ipv6(address)) = &aaaa.value else {
        return Err("AAAA record did not decode as an IPv6 address");
    };
    assert_eq!(address.as_slice(), fixture.aaaa_address.as_slice());
    Ok(())
}

fn assert_name_records(
    cname: &DnsRecord,
    ns: &DnsRecord,
    ptr: &DnsRecord,
    fixture: &MultiSectionRecordFixture,
) -> Result<(), &'static str> {
    assert_eq!(cname.section, DnsSection::Authority);
    assert_eq!(ns.section, DnsSection::Authority);
    assert_eq!(ptr.section, DnsSection::Additional);
    assert_eq!(cname.rr_type, 5);
    assert_eq!(ns.rr_type, 2);
    assert_eq!(ptr.rr_type, 12);
    // Name values preserve both literal and compressed RDATA targets
    assert_name_wire(&cname.value, &fixture.cname_wire)?;
    assert_name_wire(&ns.value, &fixture.question_wire)?;
    assert_name_wire(&ptr.value, &fixture.question_wire)?;
    Ok(())
}

fn assert_name_wire(value: &DnsValue, expected: &[u8]) -> Result<(), &'static str> {
    let DnsValue::Name(name) = value else {
        return Err("record did not decode as a DNS name");
    };
    assert_eq!(name.wire(), expected);
    Ok(())
}
