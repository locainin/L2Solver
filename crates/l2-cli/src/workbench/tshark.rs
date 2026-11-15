mod budget;
mod cache_identity;
mod count;
mod decode;
mod executable;
mod inspection;
mod model;
mod objects;
mod output_storage;
mod phase;
mod preparation;
mod process;
mod profile;
mod receipt;
#[cfg(target_os = "linux")]
mod resource_scope;
#[cfg(not(target_os = "linux"))]
#[path = "tshark/resource_scope_unsupported.rs"]
#[expect(
    dead_code,
    reason = "non-Linux builds have no supported resource scope"
)]
mod resource_scope;
mod resources;
mod runner;
mod sandbox;
mod secure_files;
mod snapshot;
mod version;

pub use budget::{ObjectExportBudget, ObjectExportStatus, ObjectExportUsage};
pub use cache_identity::identity as tshark_cache_identity;
pub use objects::{ExportObjectSet, export_objects_with_job};
pub(super) use runner::run;
#[cfg(test)]
pub use secure_files::Workspace;

#[cfg(test)]
#[path = "../../tests/workbench/tshark.rs"]
mod tests;
