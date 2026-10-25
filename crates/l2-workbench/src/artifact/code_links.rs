//! Explicit, source-qualified links from runtime stack frames to static functions

mod engine;
mod model;
mod validation;

pub use engine::link_code_to_trace;
pub use model::{
    CodeLink, CodeLinkError, CodeLinkLimits, CodeLinkReport, CodeLinkSourceChecks,
    CodeLinkSourceVerification, CodeLinkStatus, MAX_CODE_LINKS, MAX_RUNTIME_MODULE_MAPPINGS,
    RuntimeModuleMap, RuntimeModuleMapping,
};
