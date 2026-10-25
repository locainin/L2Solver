//! Process outcomes keep runtime health separate from security findings

use std::process::ExitCode;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunOutcome {
    Completed,
    Incomplete,
    Findings,
    Interrupted,
}

impl RunOutcome {
    #[must_use]
    pub fn exit_code(self) -> ExitCode {
        match self {
            Self::Completed => ExitCode::SUCCESS,
            Self::Incomplete => ExitCode::from(3),
            Self::Findings => ExitCode::from(4),
            Self::Interrupted => ExitCode::from(130),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssessmentOutcome {
    pub complete: bool,
    pub failed_findings: bool,
}

impl AssessmentOutcome {
    #[must_use]
    pub const fn process_outcome(self, fail_on_findings: bool) -> RunOutcome {
        if !self.complete {
            RunOutcome::Incomplete
        } else if self.failed_findings && fail_on_findings {
            RunOutcome::Findings
        } else {
            RunOutcome::Completed
        }
    }
}
