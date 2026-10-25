use l2_workbench::recovery::proposals::{
    TRANSFORM_PROPOSAL_OPERATION_COUNT, transform_proposal_operations,
};
use std::error::Error;

#[test]
fn candidate_identity_budget_covers_every_closed_default_template() -> Result<(), Box<dyn Error>> {
    let templates = super::candidate_task_identity_templates();
    let maximum = super::maximum_task_identity_bytes(&templates)?;

    assert!(!templates.is_empty());
    for task in &templates {
        assert!(super::serialized_task_identity_bytes(task)? <= maximum);
    }
    assert_eq!(
        super::candidate_task_identity_byte_budget(3)?,
        maximum
            .checked_mul(3)
            .ok_or_else(|| { std::io::Error::other("candidate identity test budget overflow") })?
    );
    assert!(super::candidate_task_identity_byte_budget(usize::MAX).is_err());

    Ok(())
}

#[test]
fn proposal_identity_budget_covers_the_canonical_operation_set() -> Result<(), Box<dyn Error>> {
    let tasks = transform_proposal_operations()
        .map(l2_workbench::recovery::RecoveryTask::transform)
        .collect::<Vec<_>>();
    assert_eq!(tasks.len(), TRANSFORM_PROPOSAL_OPERATION_COUNT);

    let maximum = tasks
        .iter()
        .map(super::serialized_task_identity_bytes)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .max()
        .ok_or("transform proposal templates are empty")?;
    let association_count = 4;
    let budget = super::transform_proposal_identity_byte_budget(association_count)?;
    for task in &tasks {
        let total = super::serialized_task_identity_bytes(task)?
            .checked_mul(association_count)
            .ok_or_else(|| std::io::Error::other("proposal identity test budget overflow"))?;
        assert!(total <= budget);
    }
    assert_eq!(
        budget,
        maximum
            .checked_mul(association_count)
            .ok_or_else(|| std::io::Error::other("proposal identity test budget overflow"))?
    );

    Ok(())
}
