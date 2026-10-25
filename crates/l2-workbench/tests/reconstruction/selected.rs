use super::support::tcp;
use l2_workbench::reconstruction::{InputSelection, Reconstructor};
use std::error::Error;

#[test]
fn sparse_selected_packet_numbers_provenance() -> Result<(), Box<dyn Error>> {
    let mut reconstructor = Reconstructor::new();
    reconstructor.observe_selected(4, &tcp(false, 100, 0x02, b"")?)?;
    reconstructor.observe_selected(19, &tcp(false, 101, 0x10, b"data")?)?;
    reconstructor.observe_selected(31, &tcp(false, 105, 0x11, b"")?)?;
    let report = reconstructor.finish()?;
    let session = report
        .sessions
        .first()
        .ok_or("missing selected TCP session")?;
    let stream = session
        .directions
        .first()
        .ok_or("missing selected stream")?;

    assert_eq!(report.frames, 3);
    assert_eq!(
        report.input_selection,
        Some(InputSelection::SelectedRecords)
    );
    assert!(report.complete);
    assert_eq!(stream.packets, [4, 19, 31]);
    assert_eq!(
        stream
            .origins
            .iter()
            .find(|origin| origin.length != 0)
            .map(|origin| origin.packet),
        Some(19)
    );
    assert_eq!(
        stream.runs().first().map(|run| run.bytes),
        Some(b"data".as_slice())
    );
    Ok(())
}

#[test]
fn selected_zero_decreasing_packet_numbers() -> Result<(), Box<dyn Error>> {
    let packet = tcp(false, 100, 0x02, b"")?;
    let mut reconstructor = Reconstructor::new();

    assert!(reconstructor.observe_selected(0, &packet).is_err());
    reconstructor.observe_selected(7, &packet)?;
    assert!(reconstructor.observe_selected(7, &packet).is_err());
    assert!(reconstructor.observe_selected(6, &packet).is_err());
    reconstructor.observe_selected(11, &packet)?;
    let report = reconstructor.finish()?;
    let session = report.sessions.first().ok_or("missing selected session")?;

    assert_eq!(report.frames, 2);
    assert_eq!(
        session
            .directions
            .first()
            .map(|stream| stream.packets.as_slice()),
        Some([7, 11].as_slice())
    );
    Ok(())
}

#[test]
fn consecutive_selected_apis_cannot_mixed() -> Result<(), Box<dyn Error>> {
    let packet = tcp(false, 100, 0x02, b"")?;
    let mut consecutive = Reconstructor::new();
    consecutive.observe(1, &packet)?;
    assert!(consecutive.observe_selected(2, &packet).is_err());
    consecutive.observe(2, &packet)?;
    assert_eq!(consecutive.finish()?.frames, 2);

    let mut selected = Reconstructor::new();
    selected.observe_selected(7, &packet)?;
    assert!(selected.observe(8, &packet).is_err());
    selected.observe_selected(8, &packet)?;
    let report = selected.finish()?;
    assert_eq!(report.frames, 2);
    assert_eq!(
        report.input_selection,
        Some(InputSelection::SelectedRecords)
    );
    Ok(())
}
