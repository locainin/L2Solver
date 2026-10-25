use super::super::{model::Manifest, source};
use super::write_pages;
use l2_capture::{
    CaptureMetadata, CaptureTimestamp, CapturedFrame, Direction, FcsStatus, InterfaceId,
    TimestampResolution, TimestampSource,
};
use l2_pcap::{InterfaceConfig, PcapNgWriter};
use std::{error::Error, fs::File, io::Write};

fn ipv4_header_frame(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&[0x08, 0x00, 0x45, 0x00]);
    frame.extend_from_slice(&20_u16.to_be_bytes());
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&[64, 17, 0, 0]);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame
}

#[test]
fn pages_total_emitted_page_documents() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let capture_path = directory.path().join("capture.pcapng");
    let interface = InterfaceId {
        section: 0,
        index: 0,
    };
    let mut writer = PcapNgWriter::new(Vec::new(), 1_048_576)?;
    writer.add_interface(
        interface,
        InterfaceConfig::new(
            65_535,
            TimestampResolution::MICROSECOND,
            0,
            FcsStatus::Unknown,
        )?,
    )?;
    for (index, source) in [[192, 0, 2, 1], [192, 0, 2, 3]].into_iter().enumerate() {
        let timestamp = CaptureTimestamp::new(
            u64::try_from(index)?,
            TimestampResolution::MICROSECOND,
            0,
            TimestampSource::Unknown,
        );
        writer.write_frame(&CapturedFrame::new(
            ipv4_header_frame(source, [192, 0, 2, 2]),
            CaptureMetadata::new(
                interface,
                34,
                None,
                Some(timestamp),
                Direction::Unknown,
                None,
                FcsStatus::Unknown,
            ),
        )?)?;
    }
    writer.finish()?;
    File::create(&capture_path)?.write_all(&writer.into_inner())?;

    let mut capture = File::open(&capture_path)?;
    let source = source::scan(&mut capture, &capture_path)?;
    let mut manifest = Manifest {
        schema_version: 1,
        source,
        raw_collection_complete: true,
        analysis_complete: true,
        context_records: 0,
        pages: Vec::new(),
        limitations: Vec::new(),
    };

    let page_bytes = write_pages(&mut capture, directory.path(), &mut manifest, 1)?;
    assert_eq!(manifest.pages.len(), 2);
    // Read the emitted files so the assertion does not trust manifest byte estimates
    let actual_page_bytes =
        manifest
            .pages
            .iter()
            .try_fold(0_u64, |total, page| -> Result<u64, Box<dyn Error>> {
                Ok(total + std::fs::metadata(directory.path().join(&page.path))?.len())
            })?;

    assert!(page_bytes > 0);
    assert_eq!(page_bytes, actual_page_bytes);
    Ok(())
}
