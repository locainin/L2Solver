use l2_workbench::{
    experiment::{self, ExperimentMode, Mutation, MutationPlan},
    sha256,
};

pub(super) fn exercise(input: &[u8]) {
    let bytes = input.get(..input.len().min(512)).unwrap_or_default();
    let plan = MutationPlan {
        mutations: vec![
            Mutation::FlipBit {
                offset: input.first().map_or(0, |byte| usize::from(*byte)),
                bit: input.get(1).copied().unwrap_or_default(),
            },
            Mutation::Delete {
                offset: input.get(2).map_or(0, |byte| usize::from(*byte)),
                length: input.get(3).map_or(0, |byte| usize::from(*byte)),
            },
        ],
    };
    let report = experiment::run(bytes, &plan, ExperimentMode::Offline)
        .unwrap_or_else(|_| panic!("bounded experiment failed outside its mutation receipt"));
    assert_eq!(report.input_sha256, sha256(bytes));
    assert_eq!(report.steps.len(), plan.mutations.len() + 1);
    assert!(report.inspected_bytes <= experiment::MAX_TOTAL_BYTES);
    assert!(
        report
            .steps
            .iter()
            .all(|step| step.output_length <= experiment::MAX_OUTPUT_BYTES)
    );
}
