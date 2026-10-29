use super::{RecoveryOmission, RecoveryRunSummary};

impl RecoveryRunSummary {
    pub(crate) fn test_omissions_mut(&mut self) -> &mut Vec<RecoveryOmission> {
        &mut self.omissions
    }
}
