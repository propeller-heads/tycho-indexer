use crate::models::{entry_point_params::TraceData, EntryPoint, EntryPointParams};

fn get_entrypoint_id(target: &[u8], signature: &str) -> String {
    let target = hex::encode(target);
    format!("{target}:{signature}")
}

/// Creates an entrypoint and its parameters.
///
/// These are used by the Dynamic Contract Indexer (DCI) to dynamically trace contract calls and
/// index relevant code and storage.
///
/// # Parameters
/// - `target`: The target contract to analyse this entrypoint on.
/// - `signature`: The signature of the function to analyse.
/// - `component_id`: The id of the component that uses this entrypoint.
/// - `trace_data`: The trace data to be used to trace the entrypoint.
///
/// # Returns
/// - `(EntryPoint, EntryPointParams)`: A tuple containing the entrypoint and parameter messages.
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
