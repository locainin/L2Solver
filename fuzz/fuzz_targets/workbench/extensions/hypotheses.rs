use l2_workbench::{
    derivation::{self, Constraint},
    hypothesis::{self, Family, SearchPlan},
};

pub(super) fn exercise(input: &[u8]) {
    let bytes = input.get(..input.len().min(512)).unwrap_or_default();
    let plan = SearchPlan {
        families: vec![Family::Hex, Family::Base64, Family::Reverse],
        constraints: vec![Constraint::Sha256 {
            expected_hex: l2_workbench::sha256(bytes),
        }],
        max_depth: 2,
        max_candidates: 16,
    };
    let report = hypothesis::search(bytes, &plan)
        .unwrap_or_else(|_| panic!("bounded hypothesis plan was rejected"));
    assert!(report.candidates.len() <= plan.max_candidates);
    for (id, candidate) in report.candidates.iter().enumerate() {
        assert_eq!(candidate.id, id);
        assert!(candidate.parent.is_none_or(|parent| parent < id));
        assert_eq!(candidate.steps.len(), candidate.recipe.steps.len());
        // Replaying the complete recipe checks receipts assembled from incremental steps
        let replay = derivation::run(bytes, &candidate.recipe)
            .unwrap_or_else(|_| panic!("generated recipe exceeded its checked bounds"));
        assert_eq!(candidate.output_sha256, replay.output_sha256);
        assert_eq!(candidate.output_length, replay.output.len());
        assert_eq!(candidate.constraints, replay.constraints);
    }
}
