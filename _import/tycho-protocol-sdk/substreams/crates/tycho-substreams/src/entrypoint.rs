use crate::models::{entry_point_params::TraceData, EntryPoint, EntryPointParams};

fn get_entrypoint_id(target: &[u8], signature: &str) -> String {
    let target = hex::encode(target);
    format!("{target}:{signature}")
}

/// Creates an entrypoint and its parameters.
pub fn create_entrypoint(
    target: Vec<u8>,
    signature: String,
    component_id: String,
    trace_data: TraceData,
) -> (EntryPoint, EntryPointParams) {
    let entrypoint_id = get_entrypoint_id(&target, &signature);
    let entrypoint = EntryPoint {
        id: entrypoint_id.clone(),
        target,
        signature,
        component_id: component_id.clone(),
    };
    let entrypoint_params = EntryPointParams {
        entrypoint_id,
        component_id: Some(component_id),
        trace_data: Some(trace_data),
    };
    (entrypoint, entrypoint_params)
}

// Adds EntryPointParams associated with an already existing Entrypoint.
pub fn add_entrypoint_params(
    target: Vec<u8>,
    signature: String,
    trace_data: TraceData,
    component_id: Option<String>,
) -> EntryPointParams {
    EntryPointParams {
        entrypoint_id: get_entrypoint_id(&target, &signature),
        component_id,
        trace_data: Some(trace_data),
    }
}

// Adds a component to an existing Entrypoint.
pub fn add_component_to_entrypoint(
    target: Vec<u8>,
    signature: String,
    component_id: String,
) -> EntryPoint {
    let entrypoint_id = get_entrypoint_id(&target, &signature);
    EntryPoint { id: entrypoint_id, target, signature, component_id }
}
