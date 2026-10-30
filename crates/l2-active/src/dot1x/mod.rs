//! One bounded, opt-in EAPOL Start and scoped EAP Request observation

mod plan;
mod report;
mod session;
mod wire;

pub use plan::Dot1xProbe;
pub use report::{
    Dot1xDestination, Dot1xMalformed, Dot1xObservation, Dot1xReport, Dot1xStatus, MalformedReason,
};
