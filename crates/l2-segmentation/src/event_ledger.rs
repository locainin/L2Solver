//! Per-consumer ownership tracking for controller causal events

use std::collections::BTreeMap;

use crate::{ControllerEvent, ObservationWindowReceipt, ReceiptError, TxReceipt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventRole {
    Transmit,
    WindowArm,
    WindowClose,
    WindowComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EventOwner {
    sequence: u64,
    role: EventRole,
}

/// Bounded ownership ledger for one evaluator or assessment session
///
/// Exact duplicate evidence is idempotent. Reusing one controller ordinal for
/// another sequence or lifecycle role is rejected
#[derive(Clone, Debug, Default)]
pub struct ControllerEventLedger {
    owners: BTreeMap<([u8; 16], u64), EventOwner>,
}

impl ControllerEventLedger {
    /// Reserve the commit event carried by one transmit receipt
    ///
    /// # Errors
    /// Rejects an ordinal already owned by another operation
    pub fn reserve_transmit(&mut self, receipt: TxReceipt) -> Result<(), ReceiptError> {
        self.reserve(&[(receipt.committed_event(), EventRole::Transmit)])
    }

    /// Reserve all three lifecycle events carried by one receiver window
    ///
    /// # Errors
    /// Rejects an ordinal already owned by another operation
    pub fn reserve_window(
        &mut self,
        receipt: ObservationWindowReceipt,
    ) -> Result<(), ReceiptError> {
        let timing = receipt.timing();
        self.reserve(&[
            (timing.arm_ack(), EventRole::WindowArm),
            (timing.close_issued(), EventRole::WindowClose),
            (timing.complete(), EventRole::WindowComplete),
        ])
    }

    /// Reserve one transmit and its receiver window as one atomic bundle
    ///
    /// # Errors
    /// Rejects an ordinal already owned by another operation
    pub fn reserve_transmit_and_window(
        &mut self,
        transmit: TxReceipt,
        window: ObservationWindowReceipt,
    ) -> Result<(), ReceiptError> {
        let timing = window.timing();
        self.reserve(&[
            (transmit.committed_event(), EventRole::Transmit),
            (timing.arm_ack(), EventRole::WindowArm),
            (timing.close_issued(), EventRole::WindowClose),
            (timing.complete(), EventRole::WindowComplete),
        ])
    }

    fn reserve(&mut self, claims: &[(ControllerEvent, EventRole)]) -> Result<(), ReceiptError> {
        // Validate the whole group before changing ownership state
        for (index, (event, role)) in claims.iter().copied().enumerate() {
            let owner = EventOwner {
                sequence: event.sequence(),
                role,
            };
            if self
                .owners
                .get(&(event.run_id(), event.ordinal()))
                .is_some_and(|existing| *existing != owner)
            {
                return Err(ReceiptError::ControllerEventReuse {
                    ordinal: event.ordinal(),
                });
            }
            if claims
                .iter()
                .take(index)
                .copied()
                .any(|(other, other_role)| {
                    other.run_id() == event.run_id()
                        && other.ordinal() == event.ordinal()
                        && EventOwner {
                            sequence: other.sequence(),
                            role: other_role,
                        } != owner
                })
            {
                return Err(ReceiptError::ControllerEventReuse {
                    ordinal: event.ordinal(),
                });
            }
        }

        for (event, role) in claims.iter().copied() {
            self.owners.insert(
                (event.run_id(), event.ordinal()),
                EventOwner {
                    sequence: event.sequence(),
                    role,
                },
            );
        }
        Ok(())
    }
}
