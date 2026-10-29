mod evaluation;
mod execution;
mod state;

use std::{error::Error, net::Ipv4Addr};

use l2_canary::{AgentId, RunId};
use l2_lab::dhcp::{Config, Server};
use l2_onpath::Budget;

fn fixture() -> Result<Config, Box<dyn Error>> {
    Ok(Config {
        run_id: RunId::from_recorded([7; 16])?,
        control_client: AgentId::new([1; 16])?,
        client: AgentId::new([2; 16])?,
        authorized_server: Server::new(AgentId::new([3; 16])?, Ipv4Addr::new(192, 0, 2, 1)),
        rogue_server: Server::new(AgentId::new([4; 16])?, Ipv4Addr::new(192, 0, 2, 2)),
        control_address: Ipv4Addr::new(192, 0, 2, 10),
        authorized_address: Ipv4Addr::new(192, 0, 2, 11),
        rogue_address: Ipv4Addr::new(192, 0, 2, 200),
        control_transaction: 100,
        transaction: 101,
        authorized_lease_limit: 2,
    })
}

fn budget() -> Result<Budget, Box<dyn Error>> {
    Ok(Budget::new(10, 5_760, 10)?)
}
