use super::discover::validate_dump_termination;
use std::error::Error;
use wl_nl80211::{
    Nl80211Error, Nl80211Message,
    packet_core::{DoneMessage, NLM_F_DUMP_INTR, NetlinkHeader, NetlinkMessage, NetlinkPayload},
    packet_generic::GenlMessage,
};

fn done(flags: u16, code: i32) -> Nl80211Error {
    let mut header = NetlinkHeader::default();
    header.flags = flags;
    let mut done = DoneMessage::default();
    done.code = code;
    let payload = NetlinkPayload::Done(done);
    let message: NetlinkMessage<GenlMessage<Nl80211Message>> = NetlinkMessage::new(header, payload);
    Nl80211Error::UnexpectedMessage(message)
}

#[test]
fn ordinary_stream_not_complete_dump() -> Result<(), Box<dyn Error>> {
    let Err(error) = validate_dump_termination(None) else {
        return Err("EOF unexpectedly completed the dump".into());
    };
    assert!(error.to_string().contains("without NLMSG_DONE"));
    Ok(())
}

#[test]
fn explicit_successful_completes_dump() {
    assert_eq!(validate_dump_termination(Some(done(0, 0))), Ok(()));
}

#[test]
fn interrupted_not_claim_complete_dump() -> Result<(), Box<dyn Error>> {
    let Err(error) = validate_dump_termination(Some(done(NLM_F_DUMP_INTR, 0))) else {
        return Err("interrupted dump unexpectedly completed".into());
    };
    assert!(error.to_string().contains("interrupted"));
    Ok(())
}

#[test]
fn nonzero_status_not_complete_dump() -> Result<(), Box<dyn Error>> {
    let Err(error) = validate_dump_termination(Some(done(0, -4))) else {
        return Err("failed dump unexpectedly completed".into());
    };
    assert!(error.to_string().contains("status -4"));
    Ok(())
}
