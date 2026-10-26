use super::*;
use std::error::Error;

#[test]
fn observed_initiator_groups_client_ports_but_keeps_services_separate() -> Result<(), Box<dyn Error>>
{
    let first = episode(41_001, 23_779, false, true);
    let second = episode(41_002, 23_779, false, true);
    let other_service = episode(41_002, 23_780, false, true);
    let direction = Direction::FirstToSecond;
    assert_eq!(
        for_episode(&first, direction)?,
        for_episode(&second, direction)?
    );
    assert_ne!(
        for_episode(&first, direction)?,
        for_episode(&other_service, direction)?
    );
    Ok(())
}

#[test]
fn observed_roles_normalize_endpoint_order_and_keep_data_directions_separate()
-> Result<(), Box<dyn Error>> {
    let forward = episode(41_001, 23_779, false, true);
    let reversed = episode(41_002, 23_779, true, true);
    let expected = for_episode(&forward, Direction::FirstToSecond)?;
    assert_eq!(expected, for_episode(&reversed, Direction::SecondToFirst)?);
    assert_ne!(expected, for_episode(&reversed, Direction::FirstToSecond)?);
    Ok(())
}

#[test]
fn missing_roles_keep_exact_endpoint_identity() -> Result<(), Box<dyn Error>> {
    let first = episode(41_001, 23_779, false, false);
    let second = episode(41_002, 23_779, false, false);
    let direction = Direction::FirstToSecond;
    assert_ne!(
        for_episode(&first, direction)?,
        for_episode(&second, direction)?
    );
    Ok(())
}

#[test]
fn initiator_outside_observed_endpoints_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut invalid = episode(41_001, 23_779, false, true);
    *invalid
        .details
        .get_mut("initiator")
        .ok_or("initiator missing from fixture")? = endpoint([192, 0, 2, 99], 41_001);
    assert!(for_episode(&invalid, Direction::FirstToSecond).is_err());
    Ok(())
}

fn episode(client_port: u16, service_port: u16, reversed: bool, observed_role: bool) -> Node {
    let initiator = endpoint([192, 0, 2, 10], client_port);
    let responder = endpoint([192, 0, 2, 20], service_port);
    let endpoints = if reversed {
        json!([responder, initiator])
    } else {
        json!([initiator, responder])
    };
    Node {
        id: 1,
        kind: "tcp_episode".into(),
        blob: None,
        ranges: Vec::new(),
        details: json!({
            "endpoints": endpoints,
            "initiator": observed_role.then_some(initiator),
        }),
    }
}

fn endpoint(octets: [u8; 4], port: u16) -> Value {
    json!({"address":{"family":"ipv4","octets":octets},"port":port})
}
