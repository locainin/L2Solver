use l2_workbench::{
    derivation::{Operation, run},
    job::{MemoryBudget, MemoryClass},
    recovery::xor::{propose_xor, propose_xor_with_memory, xor_proposal_scan_work_bound},
};

fn encoded(input: &[u8], key: &[u8]) -> Vec<u8> {
    input
        .iter()
        .copied()
        .zip(key.iter().copied().cycle())
        .map(|(byte, key)| byte ^ key)
        .collect()
}

#[test]
fn admitted_search_charges_allocations_and_restores_failed_attempts()
-> Result<(), Box<dyn std::error::Error>> {
    let lines =
        b"one: this line has content\ntwo: another distinct line\nthree: final record is ready\n";
    let input = encoded(lines, &[0xb3]);
    let budget = MemoryBudget::new(256 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 7)?;
    let report = propose_xor_with_memory(&input, 7, &mut lease)?;
    assert_ne!(report.proposals.len(), 0);
    assert!(lease.bytes() > 7);
    assert_eq!(budget.snapshot()?.used_bytes, lease.bytes());
    drop(report);
    lease.try_resize(7)?;
    let limited = MemoryBudget::new(8);
    let mut denied = limited.try_reserve(MemoryClass::Executor, 7)?;
    assert!(propose_xor_with_memory(&input, 7, &mut denied).is_err());
    assert_eq!(denied.bytes(), 7);
    assert_eq!(limited.snapshot()?.used_bytes, 7);
    Ok(())
}

fn contains_plaintext(input: &[u8], plaintext: &[u8]) -> bool {
    propose_xor(input, 7)
        .proposals
        .iter()
        .any(|proposal| run(input, &proposal.recipe).is_ok_and(|report| report.output == plaintext))
}

#[test]
fn discovers_generated_messages_with_varied_keys_and_periods() {
    let lines = b"status: completed 42 items\r\nfolder: reports and notes\r\nmessage: account ready &amp; active\r\nresult: saved 18 records\r\n";
    for key in [
        &[0x83][..],
        &[0x51][..],
        &[0xa3, 0x46][..],
        &[0x91, 0x37, 0xee][..],
        &[0x94, 0xb1, 0x27, 0x68][..],
    ] {
        let input = encoded(lines, key);
        assert!(contains_plaintext(&input, lines), "key {key:?}");
    }
}

#[test]
fn discovers_held_out_message_layout_without_predefined_words() {
    let lines = b"17 | North parcel arrived!\n32 | West road is open.\n08 | Blue room is ready?\n61 | Third gate has closed.\n";
    let input = encoded(lines, &[0xd5, 0x3a]);
    assert!(contains_plaintext(&input, lines));
}

#[test]
fn discovers_messages_containing_valid_utf8_text() {
    let lines = "01: café opened near the blue station\n02: résumé is ready to review\n03: meeting moved to mañana afternoon\n04: voilà, the final report is ready\n".as_bytes();
    let input = encoded(lines, &[0xd3]);
    assert!(contains_plaintext(&input, lines));
    assert_eq!(propose_xor(lines, 7).proposals.len(), 0);
}

#[test]
fn rejects_cleartext_short_and_pseudorandom_data() {
    let lines = b"status: completed 42 items\nfolder: reports and notes\nmessage: account ready\nresult: saved 18 records\n";
    assert_eq!(propose_xor(lines, 32).proposals.len(), 0);
    assert_eq!(
        propose_xor(&encoded(b"hi\n", &[0x53]), 32).proposals.len(),
        0
    );
    let mut state = 0x9e37_79b9_u32;
    let random: Vec<u8> = (0..4096)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect();
    assert_eq!(propose_xor(&random, 32).proposals.len(), 0);
    let repeated_binary: Vec<u8> = (0..=u8::MAX).cycle().take(4096).collect();
    assert_eq!(propose_xor(&repeated_binary, 32).proposals.len(), 0);
}

#[test]
fn reports_candidate_budget_and_bounded_sample() {
    let lines = b"17 | North parcel arrived!\n32 | West road is open.\n08 | Blue room is ready?\n61 | Third gate has closed.\n";
    let input = encoded(lines, &[0xd5]);
    let all = propose_xor(&input, 32);
    let none = propose_xor(&input, 0);
    assert_ne!(all.proposals.len(), 0);
    let debug = format!("{all:?}");
    assert!(!debug.contains("XorRepeat"));
    assert!(!debug.contains("key:"));
    assert_eq!(none.proposals.len(), 0);
    assert_eq!(
        none.omitted_candidates,
        all.proposals.len() + all.omitted_candidates
    );
    assert!(all.proposals.iter().all(|candidate| matches!(
        candidate.recipe.steps.as_slice(),
        [Operation::XorRepeat { offset: 0, .. }]
    )));
    assert_eq!(xor_proposal_scan_work_bound(47), Some(0));
    assert_eq!(
        xor_proposal_scan_work_bound(1024),
        Some(655_360 + 327 * 1024)
    );
    assert_eq!(
        xor_proposal_scan_work_bound(usize::MAX),
        xor_proposal_scan_work_bound(4096)
    );
    let longer = encoded(&lines.repeat(50), &[0xd5]);
    let report = propose_xor(&longer, 7);
    assert!(report.sample_truncated);
    assert!(report.search_truncated);
    assert!(contains_plaintext(&longer, &lines.repeat(50)));
}

#[test]
fn scan_reserves_work_at_the_minimum_input_length() {
    let short = vec![0xd1; 47];
    let minimum = vec![0xd1; 48];
    assert!(!propose_xor(&short, 7).search_truncated);
    assert_eq!(xor_proposal_scan_work_bound(short.len()), Some(0));
    assert!(propose_xor(&minimum, 7).search_truncated);
    assert!(xor_proposal_scan_work_bound(minimum.len()).is_some_and(|work| work > 0));
}

#[test]
fn sample_truncation_reports_only_omitted_input() {
    let exact: Vec<u8> = (0..=u8::MAX).cycle().take(4096).collect();
    let mut longer = exact.clone();
    longer.push(0);
    assert!(!propose_xor(&exact, 7).sample_truncated);
    assert!(propose_xor(&longer, 7).sample_truncated);
}

#[test]
fn search_omits_repeated_key_aliases() -> Result<(), Box<dyn std::error::Error>> {
    let lines = b"status: completed 42 items\r\nfolder: reports and notes\r\nmessage: account ready &amp; active\r\nresult: saved 18 records\r\n";
    let input = encoded(lines, &[0x83]);
    let report = propose_xor(&input, 32);
    assert_ne!(report.proposals.len(), 0);
    for proposal in report.proposals {
        let [Operation::XorRepeat { key, .. }] = proposal.recipe.steps.as_slice() else {
            return Err("expected a repeating XOR recipe".into());
        };
        for period in 1..key.len() {
            if key.len().is_multiple_of(period) {
                assert!(
                    !key.iter().copied().eq(key
                        .iter()
                        .copied()
                        .take(period)
                        .cycle()
                        .take(key.len())),
                    "repeated key alias {key:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn truncated_utf8_character_preserves_the_valid_sample_prefix() {
    let block = b"01: parcel arrived at the station\n02: review the status report\n03: client response is ready now\n";
    let mut plaintext: Vec<u8> = block.iter().copied().cycle().take(4095).collect();
    plaintext.extend_from_slice("é is available\n".as_bytes());
    let input = encoded(&plaintext, &[0xd3]);
    let report = propose_xor(&input, 7);
    assert!(report.sample_truncated);
    assert!(contains_plaintext(&input, &plaintext));
}
