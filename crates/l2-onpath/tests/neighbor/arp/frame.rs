use std::error::Error;

use l2_onpath::{CommitmentSubject, neighbor::arp::ValidatedArpAnnouncement};

use super::fixture;

#[test]
fn valid_announcements_commit_exact_bytes_for_both_role_types() -> Result<(), Box<dyn Error>> {
    for scope in [fixture::control()?, fixture::conflict()?] {
        let bytes = fixture::announcement(scope.sender());
        let proof = ValidatedArpAnnouncement::from_frame(fixture::run_id()?, scope, &bytes)?;
        let tx = proof.commitment();
        assert_eq!(proof.scope(), scope);
        assert_eq!(tx.run_id(), fixture::run_id()?.into_bytes());
        assert_eq!(tx.sequence(), scope.stimulus().sequence());
        assert_eq!(tx.interface(), scope.sender().interface());
        assert_eq!(tx.frame_length(), u64::try_from(bytes.len())?);
        assert_eq!(tx.subject(), CommitmentSubject::UnboundFrameClaim);
    }
    let scope = fixture::conflict()?;
    let proof = ValidatedArpAnnouncement::from_frame(
        fixture::run_id()?,
        scope,
        &fixture::announcement(scope.sender()),
    )?;
    assert_eq!(
        proof.commitment().frame_hash(),
        [
            0x44, 0x5f, 0x13, 0xc3, 0xc7, 0x6a, 0xd8, 0x86, 0x02, 0x47, 0x29, 0xbb, 0xd0, 0x57,
            0xf9, 0x9b, 0xd9, 0xcf, 0x11, 0x9a, 0xea, 0x57, 0x1c, 0x31, 0x36, 0xb4, 0x07, 0xfc,
            0x9c, 0x76, 0x27, 0x5a,
        ]
    );
    Ok(())
}

#[test]
fn every_truncated_prefix_is_rejected() -> Result<(), Box<dyn Error>> {
    let scope = fixture::conflict()?;
    let bytes = fixture::announcement(scope.sender());
    assert_eq!(bytes.len(), fixture::FRAME_LENGTH);
    for end in 0..fixture::FRAME_LENGTH {
        let prefix = bytes.get(..end).ok_or("bad fixture prefix")?;
        assert!(
            ValidatedArpAnnouncement::from_frame(fixture::run_id()?, scope, prefix).is_err(),
            "accepted truncated length {end}"
        );
    }
    Ok(())
}

#[test]
fn mismatched_ethernet_and_arp_fields_are_rejected() -> Result<(), Box<dyn Error>> {
    let scope = fixture::conflict()?;
    let bytes = fixture::announcement(scope.sender());
    let cases: &[(usize, &[u8])] = &[
        (0, &[2]),
        (6, &[4]),
        (12, &[8, 0]),
        (14, &[0, 2]),
        (16, &[0x86, 0xdd]),
        (18, &[5]),
        (19, &[16]),
        (20, &[0, 2]),
        (20, &[0, 3]),
        (22, &[4]),
        (28, &[192, 0, 2, 2]),
        (32, &[2]),
        (38, &[192, 0, 2, 2]),
    ];
    for (offset, replacement) in cases {
        let mut changed = bytes.clone();
        fixture::overwrite(&mut changed, *offset, replacement)?;
        assert!(
            ValidatedArpAnnouncement::from_frame(fixture::run_id()?, scope, &changed).is_err(),
            "accepted mismatch at offset {offset}"
        );
    }
    Ok(())
}

#[test]
fn tagged_and_overlong_frames_are_rejected_but_padding_is_committed() -> Result<(), Box<dyn Error>>
{
    let scope = fixture::conflict()?;
    let bytes = fixture::announcement(scope.sender());
    let original = ValidatedArpAnnouncement::from_frame(fixture::run_id()?, scope, &bytes)?;
    let mut tagged = Vec::new();
    tagged.extend_from_slice(bytes.get(..12).ok_or("missing ethernet addresses")?);
    tagged.extend_from_slice(&[0x81, 0, 0, 10, 8, 6]);
    tagged.extend_from_slice(bytes.get(14..).ok_or("missing arp payload")?);
    assert!(ValidatedArpAnnouncement::from_frame(fixture::run_id()?, scope, &tagged).is_err());
    for length in 0..=18 {
        let mut padded = bytes.clone();
        padded.extend(std::iter::repeat_n(0xa5, length));
        let proof = ValidatedArpAnnouncement::from_frame(fixture::run_id()?, scope, &padded)?;
        assert_eq!(
            proof.commitment().frame_length(),
            u64::try_from(padded.len())?
        );
        if length > 0 {
            assert_ne!(
                proof.commitment().frame_hash(),
                original.commitment().frame_hash()
            );
        }
    }
    let mut first_padding = bytes.clone();
    first_padding.extend_from_slice(&[0; 18]);
    let mut second_padding = first_padding.clone();
    fixture::overwrite(&mut second_padding, fixture::FRAME_LENGTH, &[1])?;
    let first_proof =
        ValidatedArpAnnouncement::from_frame(fixture::run_id()?, scope, &first_padding)?;
    let second_proof =
        ValidatedArpAnnouncement::from_frame(fixture::run_id()?, scope, &second_padding)?;
    assert_ne!(
        first_proof.commitment().frame_hash(),
        second_proof.commitment().frame_hash()
    );
    let mut overlong = bytes;
    overlong.extend_from_slice(&[0; 19]);
    assert!(ValidatedArpAnnouncement::from_frame(fixture::run_id()?, scope, &overlong).is_err());
    Ok(())
}
