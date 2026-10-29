//! Admission, deterministic dispatch, and observed restoration

use std::net::Ipv4Addr;

use l2_onpath::Budget;
use l2_scenario::{Cleanup, Control, Runner, Schedule, Stimulus};

use crate::{Cancellation, ObservationMode};

use super::{
    Config, Error, IngressPolicy, Message, Options, Outcome, Run, evaluation, state::Machine,
};

// A fixed conservative charge for each virtual message opportunity, not wire bytes
const OPPORTUNITY_BYTES: u64 = 576;
const OPPORTUNITIES: usize = 10;

/// One validated, reproducible `DHCPv4` model
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scenario {
    config: Config,
}

impl Scenario {
    /// Validate distinct synthetic attachments, addresses, and transactions
    ///
    /// # Errors
    /// Rejects duplicate agents or addresses, non-unicast addresses, zero or
    /// repeated transaction IDs, and limits outside the modeled two-client run
    pub fn new(config: Config) -> Result<Self, Error> {
        let agents = [
            config.control_client,
            config.client,
            config.authorized_server.agent(),
            config.rogue_server.agent(),
        ];
        if agents
            .iter()
            .enumerate()
            .any(|(index, agent)| agents.iter().take(index).any(|other| other == agent))
        {
            return Err(Error::DuplicateAgent);
        }
        let addresses = [
            config.authorized_server.identifier(),
            config.rogue_server.identifier(),
            config.control_address,
            config.authorized_address,
            config.rogue_address,
        ];
        if addresses.iter().enumerate().any(|(index, address)| {
            !is_unicast(*address) || addresses.iter().take(index).any(|other| other == address)
        }) {
            return Err(Error::InvalidAddress);
        }
        if config.transaction == 0
            || config.control_transaction == 0
            || config.transaction == config.control_transaction
        {
            return Err(Error::InvalidTransaction);
        }
        if !(1..=2).contains(&config.authorized_lease_limit) {
            return Err(Error::InvalidLeaseLimit);
        }
        Ok(Self { config })
    }

    /// Run a fixed virtual workload under an independently configured ingress policy
    ///
    /// Every scheduled opportunity is charged 576 modeled bytes, even when its
    /// prerequisites are absent and no message is emitted. State is always local
    /// to this invocation; the report confirms restoration only after comparing
    /// observable complete snapshots before and after cleanup
    ///
    /// # Errors
    /// Returns a scheduler admission/report error or bounded allocation failure
    pub fn run(
        &self,
        policy: IngressPolicy,
        budget: Budget,
        options: Options,
    ) -> Result<Run, Error> {
        let stimuli = [1_u64, 2, 3, 4, 5, 6, 7, 8, 9, 10]
            .map(|sequence| Stimulus::new(sequence, sequence, OPPORTUNITY_BYTES));
        let mut runner = Schedule::new(&stimuli, budget)?.start();
        let mut machine = Machine::new(self.config);
        let before = observed_snapshot(&machine, options.state);
        let (sent, received) = collect(&mut machine, &mut runner, policy, options)?;
        let during = observed_snapshot(&machine, options.state);
        machine.restore(options.fault);
        let after = observed_snapshot(&machine, options.state);
        let cleanup = if before.is_some() && before == after {
            Cleanup::Confirmed
        } else {
            Cleanup::Unconfirmed
        };
        let execution = runner.report(cleanup)?;
        let mut run = Run {
            config: self.config,
            policy,
            options,
            sent,
            received,
            before,
            during,
            after,
            execution,
            outcome: Outcome::IncompleteRun,
        };
        run.outcome = evaluation::assess(&run);
        Ok(run)
    }
}

// Collect sender and receiver views without changing scheduler accounting
fn collect(
    machine: &mut Machine,
    runner: &mut Runner,
    policy: IngressPolicy,
    options: Options,
) -> Result<(Vec<Message>, Vec<Message>), Error> {
    let mut sent = Vec::new();
    sent.try_reserve_exact(OPPORTUNITIES)
        .map_err(|_| Error::Allocation)?;
    let mut received = Vec::new();
    received
        .try_reserve_exact(OPPORTUNITIES)
        .map_err(|_| Error::Allocation)?;
    let mut dispatched = 0_u64;
    loop {
        let control = match options.cancellation {
            Cancellation::After(limit) if dispatched >= limit => Control::Cancel,
            Cancellation::Never | Cancellation::After(_) => Control::Continue,
        };
        let Some(dispatch) = runner.next(control) else {
            break;
        };
        if let Some((message, delivered)) =
            machine.dispatch(dispatch.sequence(), policy, options.fault)
        {
            // Capture independently of the client's actual state transition
            sent.push(message);
            if delivered && options.receiver == ObservationMode::Healthy {
                received.push(message);
            }
        }
        dispatched += 1;
    }
    Ok((sent, received))
}

const fn is_unicast(address: Ipv4Addr) -> bool {
    let [first, _, _, _] = address.octets();
    first != 0 && first != 127 && first < 224
}

fn observed_snapshot(machine: &Machine, observer: ObservationMode) -> Option<super::StateSnapshot> {
    if observer == ObservationMode::Healthy {
        Some(machine.snapshot())
    } else {
        None
    }
}
