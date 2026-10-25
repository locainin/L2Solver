#[path = "extensions/artifacts.rs"]
mod artifacts;
#[path = "extensions/carriers.rs"]
mod carriers;
#[path = "extensions/endpoints.rs"]
mod endpoints;
#[path = "extensions/experiments.rs"]
mod experiments;
#[path = "extensions/hypotheses.rs"]
mod hypotheses;
#[path = "extensions/native_endpoints.rs"]
mod native_endpoints;
#[path = "extensions/protocols.rs"]
mod protocols;

pub fn exercise(input: &[u8]) {
    artifacts::exercise(input);
    carriers::exercise(input);
    endpoints::exercise(input);
    experiments::exercise(input);
    hypotheses::exercise(input);
    native_endpoints::exercise(input);
    protocols::exercise(input);
}
