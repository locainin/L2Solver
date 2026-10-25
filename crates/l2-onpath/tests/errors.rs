use l2_onpath::{
    AddressFamily, AssessmentStatus, Budget, BudgetError, CheckKind, MAX_BYTE_BUDGET,
    MAX_DURATION_BUDGET_MILLIS, MAX_PACKET_BUDGET, ModelError, PlanError, ReceiptError,
    SessionError,
};

#[test]
fn budgets_reject_zero_excessive_values() {
    assert_eq!(Budget::new(0, 1, 1), Err(BudgetError::ZeroPackets));
    assert_eq!(Budget::new(1, 0, 1), Err(BudgetError::ZeroBytes));
    assert_eq!(Budget::new(1, 1, 0), Err(BudgetError::ZeroDuration));
    assert!(Budget::new(1, 1, 1).is_ok());
}

#[test]
fn budget_limits_checked_readable() -> Result<(), BudgetError> {
    let budget = Budget::new(
        MAX_PACKET_BUDGET,
        MAX_BYTE_BUDGET,
        MAX_DURATION_BUDGET_MILLIS,
    )?;

    assert_eq!(budget.packets(), MAX_PACKET_BUDGET);
    assert_eq!(budget.bytes(), MAX_BYTE_BUDGET);
    assert_eq!(budget.duration_millis(), MAX_DURATION_BUDGET_MILLIS);

    assert_eq!(
        Budget::new(
            MAX_PACKET_BUDGET + 1,
            MAX_BYTE_BUDGET,
            MAX_DURATION_BUDGET_MILLIS
        ),
        Err(BudgetError::PacketsExceeded {
            value: MAX_PACKET_BUDGET + 1,
            maximum: MAX_PACKET_BUDGET,
        })
    );
    assert_eq!(
        Budget::new(
            MAX_PACKET_BUDGET,
            MAX_BYTE_BUDGET + 1,
            MAX_DURATION_BUDGET_MILLIS
        ),
        Err(BudgetError::BytesExceeded {
            value: MAX_BYTE_BUDGET + 1,
            maximum: MAX_BYTE_BUDGET,
        })
    );
    assert_eq!(
        Budget::new(
            MAX_PACKET_BUDGET,
            MAX_BYTE_BUDGET,
            MAX_DURATION_BUDGET_MILLIS + 1
        ),
        Err(BudgetError::DurationExceeded {
            value: MAX_DURATION_BUDGET_MILLIS + 1,
            maximum: MAX_DURATION_BUDGET_MILLIS,
        })
    );
    Ok(())
}

#[test]
fn check_kinds_have_stable_labels() {
    assert_eq!(
        CheckKind::ArpSpoofSusceptibility.as_str(),
        "arp-spoof-susceptibility"
    );
    assert_eq!(CheckKind::Dhcpv6Guard.as_str(), "dhcpv6-guard");
    assert_eq!(
        CheckKind::DisruptiveCamProtection.as_str(),
        "disruptive-cam-protection"
    );
    assert_eq!(AssessmentStatus::Protected.as_str(), "protected");
}

#[test]
fn error_message_text() {
    assert_eq!(
        ModelError::ZeroIdentity.to_string(),
        "on-path identity must not be all zeroes"
    );
    assert_eq!(
        BudgetError::ZeroPackets.to_string(),
        "packet budget must be nonzero"
    );
    assert_eq!(
        PlanError::WrongFamily {
            check: CheckKind::ArpSpoofSusceptibility,
            family: AddressFamily::Ipv6,
        }
        .to_string(),
        "check ArpSpoofSusceptibility cannot target Ipv6"
    );
    assert_eq!(
        ReceiptError::WrongFamily {
            expected: AddressFamily::Ipv4,
            actual: AddressFamily::Ipv6,
        }
        .to_string(),
        "receipt family is Ipv6, expected Ipv4"
    );
    assert_eq!(
        SessionError::PrecheckIncomplete.to_string(),
        "precheck did not complete cleanly"
    );
    assert!(std::error::Error::source(&PlanError::Model(ModelError::ZeroIdentity)).is_some());
    assert!(std::error::Error::source(&PlanError::InvalidRunId).is_none());
    assert!(std::error::Error::source(&SessionError::Receipt(ReceiptError::WrongRun)).is_some());
    assert!(std::error::Error::source(&SessionError::PrecheckIncomplete).is_none());
}
