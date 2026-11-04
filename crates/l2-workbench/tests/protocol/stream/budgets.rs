use super::common::context;
use l2_workbench::protocol::{
    FramingKind, MessageOrigin, ProtocolError, ProtocolLimits, StreamMessageParser,
};
use l2_workbench::reconstruction::Origin;
use std::error::Error;

fn accepts_two_frame_report(max_report_bytes: usize, origins: &[Origin]) -> bool {
    let limits = ProtocolLimits {
        max_report_bytes,
        ..ProtocolLimits::default()
    };
    let Ok(mut parser) = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        limits,
    ) else {
        return false;
    };
    parser.push_chunk(0, b"abcd", origins).is_ok() && parser.into_report().is_ok()
}

fn minimum_two_frame_budget(origins: &[Origin]) -> Result<usize, Box<dyn Error>> {
    let mut lower = 0;
    let mut upper = ProtocolLimits::default().max_report_bytes;
    if !accepts_two_frame_report(upper, origins) {
        return Err("default report budget did not accept the complete fixture".into());
    }
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        if accepts_two_frame_report(middle, origins) {
            upper = middle;
        } else {
            lower = middle + 1;
        }
    }
    Ok(lower)
}

#[test]
fn empty_parser_respects_report_budget() -> Result<(), Box<dyn Error>> {
    let framing = vec![FramingKind::Delimiter { byte: b'\n' }];
    let baseline = StreamMessageParser::new(
        context(),
        false,
        false,
        framing.clone(),
        ProtocolLimits::default(),
    )?;
    let base_bytes = serde_json::to_value(&baseline)?
        .get("retained_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or("empty parser has no retained byte estimate")?;
    let exact_bytes = usize::try_from(base_bytes)?;
    let exact_limits = ProtocolLimits {
        max_report_bytes: exact_bytes,
        ..ProtocolLimits::default()
    };
    let exact = StreamMessageParser::new(context(), false, false, framing.clone(), exact_limits)?;
    let mut resumed: StreamMessageParser = serde_json::from_value(serde_json::to_value(exact)?)?;
    resumed.finalize()?;
    assert_eq!(resumed.into_report()?.messages.len(), 0);

    let one_byte_less = ProtocolLimits {
        max_report_bytes: exact_bytes
            .checked_sub(1)
            .ok_or("empty parser estimate must be nonzero")?,
        ..ProtocolLimits::default()
    };
    assert!(matches!(
        StreamMessageParser::new(context(), false, false, framing, one_byte_less),
        Err(l2_workbench::protocol::ProtocolError::TotalBytesTooLarge { .. })
    ));
    Ok(())
}

#[test]
fn budget_charges_strings_recording_frames() -> Result<(), Box<dyn Error>> {
    let mut context = context();
    context.source = "s".repeat(4_096);
    let limits = ProtocolLimits {
        max_report_bytes: 8_192,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context,
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        limits,
    )?;
    let before = serde_json::to_value(&parser)?;

    let result = parser.push_chunk(
        0,
        b"x\n",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 2,
        }],
    );

    assert!(matches!(
        result,
        Err(l2_workbench::protocol::ProtocolError::TotalBytesTooLarge { .. })
    ));
    assert_eq!(serde_json::to_value(parser)?, before);
    Ok(())
}

#[test]
fn gap_budget_parser_state_unchanged() -> Result<(), Box<dyn Error>> {
    let limits = ProtocolLimits {
        max_report_bytes: 800,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        limits,
    )?;
    parser.push_chunk(
        0,
        b"a",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 1,
        }],
    )?;
    let before = serde_json::to_value(&parser)?;
    let result = parser.push_chunk(
        5,
        b"b",
        &[Origin {
            packet: 2,
            frame_offset: 60,
            offset: 5,
            length: 1,
        }],
    );

    assert!(matches!(
        result,
        Err(l2_workbench::protocol::ProtocolError::TotalBytesTooLarge { .. })
    ));
    assert_eq!(serde_json::to_value(parser)?, before);
    Ok(())
}

#[test]
fn final_gap_checkpoint_state_unchanged() -> Result<(), Box<dyn Error>> {
    let limits = ProtocolLimits {
        max_report_bytes: 800,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::Delimiter { byte: b'\n' }],
        limits,
    )?;
    parser.push_chunk(
        5,
        b"ab",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 5,
            length: 2,
        }],
    )?;
    let before = serde_json::to_value(&parser)?;

    let result = parser.finalize();
    assert!(
        matches!(
            &result,
            Err(l2_workbench::protocol::ProtocolError::TotalBytesTooLarge { .. })
        ),
        "unexpected finalization result: {result:?}"
    );
    assert_eq!(serde_json::to_value(parser)?, before);
    Ok(())
}

#[test]
fn source_map_covers_supplied_bytes() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        ProtocolLimits::default(),
    )?;

    let result = parser.push_chunk(
        0,
        b"ab",
        &[Origin {
            packet: 4,
            frame_offset: 54,
            offset: 0,
            length: 1,
        }],
    );

    assert!(result.is_err());
    assert_eq!(parser.into_report()?.messages.len(), 0);
    Ok(())
}

#[test]
fn source_map_origins_byte_coverage() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        ProtocolLimits::default(),
    )?;
    let origins = [
        Origin {
            packet: 4,
            frame_offset: 50,
            offset: 0,
            length: 2,
        },
        Origin {
            packet: 5,
            frame_offset: usize::MAX,
            offset: 100,
            length: 2,
        },
    ];

    assert!(matches!(
        parser.push_chunk(0, b"ab", &origins),
        Err(ProtocolError::StreamOffsetOverflow)
    ));
    assert_eq!(parser.into_report()?.messages.len(), 0);
    Ok(())
}

#[test]
fn zero_packet_skipped_range_validation() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        ProtocolLimits::default(),
    )?;
    let origins = [
        Origin {
            packet: 0,
            frame_offset: usize::MAX,
            offset: usize::MAX,
            length: 1,
        },
        Origin {
            packet: 5,
            frame_offset: usize::MAX,
            offset: usize::MAX,
            length: 0,
        },
        Origin {
            packet: 4,
            frame_offset: 50,
            offset: 0,
            length: 2,
        },
    ];

    parser.push_chunk(0, b"ab", &origins)?;
    let report = parser.into_report()?;
    let message = report
        .messages
        .first()
        .ok_or("expected one parsed message")?;
    assert_eq!(
        message.origins,
        [MessageOrigin {
            packet: 4,
            frame_offset: 50,
            message_offset: 0,
            length: 2,
        }]
    );
    Ok(())
}

#[test]
fn byte_limit_source_map_validation() -> Result<(), Box<dyn Error>> {
    let limits = ProtocolLimits {
        max_run_bytes: 1,
        max_total_bytes: 1,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        limits,
    )?;
    let incomplete = [Origin {
        packet: 4,
        frame_offset: 50,
        offset: 0,
        length: 1,
    }];

    assert!(matches!(
        parser.push_chunk(0, b"ab", &incomplete),
        Err(ProtocolError::RunTooLarge { .. })
    ));
    assert_eq!(parser.into_report()?.messages.len(), 0);
    Ok(())
}

#[test]
fn byte_limit_malformed_origin_validation() -> Result<(), Box<dyn Error>> {
    let limits = ProtocolLimits {
        max_run_bytes: 1,
        max_total_bytes: 1,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        limits,
    )?;
    let overflowing = [Origin {
        packet: 4,
        frame_offset: usize::MAX,
        offset: 0,
        length: 2,
    }];

    assert!(matches!(
        parser.push_chunk(0, b"ab", &overflowing),
        Err(ProtocolError::RunTooLarge { .. })
    ));
    assert_eq!(parser.into_report()?.messages.len(), 0);
    Ok(())
}

#[test]
fn duplicate_input_charged_once_budget() -> Result<(), Box<dyn Error>> {
    let limits = ProtocolLimits {
        max_report_bytes: 1_200,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        limits,
    )?;
    let origin = Origin {
        packet: 1,
        frame_offset: 40,
        offset: 0,
        length: 2,
    };

    parser.push_chunk(0, b"a", std::slice::from_ref(&origin))?;
    parser.push_chunk(1, b"b", &[origin.clone(), origin])?;

    assert_eq!(parser.into_report()?.input_bytes, 2);
    Ok(())
}

#[test]
fn duplicate_new_origins_deduplicated_budgeting() -> Result<(), Box<dyn Error>> {
    let origin = Origin {
        packet: 1,
        frame_offset: 40,
        offset: 0,
        length: 4,
    };
    let exact_budget = minimum_two_frame_budget(std::slice::from_ref(&origin))?;
    let limits = ProtocolLimits {
        max_report_bytes: exact_budget,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        limits,
    )?;

    parser.push_chunk(0, b"abcd", &[origin.clone(), origin])?;

    let report = parser.into_report()?;
    assert_eq!(report.input_bytes, 4);
    assert_eq!(report.messages.len(), 2);
    Ok(())
}

#[test]
fn distinct_origins_rows_budgeted_mutation() -> Result<(), Box<dyn Error>> {
    let adjacent = [
        Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 2,
        },
        Origin {
            packet: 1,
            frame_offset: 42,
            offset: 2,
            length: 2,
        },
    ];
    let overlapping = [
        Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 2,
        },
        Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 4,
        },
    ];
    let adjacent_minimum = minimum_two_frame_budget(&adjacent)?;
    let maximum = adjacent_minimum + std::mem::size_of::<l2_workbench::protocol::MessageOrigin>();
    assert!(accepts_two_frame_report(maximum, &adjacent));

    let limits = ProtocolLimits {
        max_report_bytes: maximum,
        ..ProtocolLimits::default()
    };
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        limits,
    )?;
    let before = serde_json::to_value(&parser)?;
    let result = parser.push_chunk(0, b"abcd", &overlapping);

    assert!(matches!(
        result,
        Err(l2_workbench::protocol::ProtocolError::TotalBytesTooLarge { .. })
    ));
    assert_eq!(serde_json::to_value(parser)?, before);
    Ok(())
}

#[test]
fn invalid_frame_rejected_parser_mutation() -> Result<(), Box<dyn Error>> {
    let mut parser = StreamMessageParser::new(
        context(),
        false,
        false,
        vec![FramingKind::FixedSize { bytes: 2 }],
        ProtocolLimits::default(),
    )?;
    let invalid = [Origin {
        packet: 1,
        frame_offset: usize::MAX,
        offset: 0,
        length: 2,
    }];

    assert!(matches!(
        parser.push_chunk(0, b"ab", &invalid),
        Err(l2_workbench::protocol::ProtocolError::StreamOffsetOverflow)
    ));
    parser.push_chunk(
        0,
        b"ab",
        &[Origin {
            packet: 1,
            frame_offset: 40,
            offset: 0,
            length: 2,
        }],
    )?;
    assert_eq!(parser.into_report()?.messages.len(), 1);
    Ok(())
}
