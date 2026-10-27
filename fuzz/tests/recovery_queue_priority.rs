#[path = "../fuzz_targets/workbench/queue_priority.rs"]
mod queue_priority;
#[path = "../fuzz_targets/workbench/recovery_support.rs"]
mod support;

fn seed(settings: [u8; 4], operations: &[(u8, u8, u8)]) -> Vec<u8> {
    let mut input = Vec::with_capacity(4 + operations.len() * 3);
    input.extend_from_slice(&settings);
    for (kind, first, second) in operations {
        input.extend_from_slice(&[*kind, *first, *second]);
    }
    input
}

#[test]
fn recovery_queue_priority_promotes_and_reuses_merged_child_work() {
    let input = seed(
        [3, 3, 3, 31],
        &[
            (0, 0, 0), // Queue root work
            (2, 0, 0), // Promote the new tail
            (0, 2, 0), // Leave another root behind
            (4, 0, 0), // Run the prioritized root
            (5, 0, 2), // Finish it with retained output evidence
            (1, 0, 4), // Queue one derived child
            (1, 0, 4), // Merge the same child identity
            (3, 6, 0), // Promote the merged child from its parent
            (3, 6, 0), // Repeat promotion without charging more work
            (4, 0, 0), // Pop the promoted child once
            (5, 2, 2), // Finish the child with retained output evidence
        ],
    );
    queue_priority::exercise(&input);
}

#[test]
fn recovery_queue_priority_respects_frontier_candidate_and_depth_limits() {
    let input = seed(
        [1, 0, 0, 0],
        &[
            (0, 0, 0), // Fill the one-entry frontier
            (0, 2, 0), // Reject another root at the frontier limit
            (4, 0, 0), // Free the frontier slot
            (0, 2, 0), // Admit the second distinct candidate
            (4, 0, 0), // Run that candidate
            (5, 1, 2), // Retain a derived result
            (1, 1, 4), // Reject its child at the depth limit
            (0, 4, 0), // Reject a third identity at the candidate limit
            (5, 0, 0), // Complete the first running candidate
            (4, 0, 0), // Confirm no queued candidate remains
        ],
    );
    queue_priority::exercise(&input);
}

#[test]
fn recovery_queue_priority_keeps_state_after_invalid_finish_and_parent() {
    let input = seed(
        [3, 3, 2, 8],
        &[
            (0, 0, 2), // Queue structural validation
            (4, 0, 0), // Start the candidate
            (6, 0, 0), // Reject a derived result for this task stage
            (5, 0, 0), // Finish it with a supported terminal result
            (1, 0, 4), // Reject derivation from a non-derived parent
            (2, 0, 0), // Reject priority after the candidate left the queue
            (3, 0, 0), // Keep a non-priority parent from changing the queue
        ],
    );
    queue_priority::exercise(&input);
}
