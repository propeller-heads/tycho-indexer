use tycho_common::dto::{
    AccountOverrides, AccountUpdate, BlockParam, Chain, ChangeType, ComponentTvlRequestBody,
    ComponentTvlRequestResponse, ContractId, EntryPoint, EntryPointWithTracingParams, Health,
    PaginationParams, PaginationResponse, ProtocolComponent, ProtocolComponentRequestResponse,
    ProtocolComponentsRequestBody, ProtocolId, ProtocolStateDelta, ProtocolStateRequestBody,
    ProtocolStateRequestResponse, ProtocolSystemsRequestBody, ProtocolSystemsRequestResponse,
    RPCTracerParams, ResponseAccount, ResponseProtocolState, ResponseToken, StateRequestBody,
    StateRequestResponse, StorageOverride, TokensRequestBody, TokensRequestResponse,
    TracedEntryPointRequestBody, TracedEntryPointRequestResponse, TracingParams, TracingResult,
    VersionParam,
};
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
    Modify, OpenApi,
};

use super::rpc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();
        components.add_security_scheme(
            "apiKey",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "authorization",
                "Use 'sampletoken' as value for testing",
            ))),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(title = "Tycho-Indexer RPC",),
    paths(
        rpc::health,
        rpc::protocol_systems,
        rpc::tokens,
        rpc::protocol_components,
        rpc::traced_entry_points,
        rpc::protocol_state,
        rpc::contract_state,
        rpc::component_tvl,
    ),
    components(
        schemas(VersionParam),
        schemas(BlockParam),
        schemas(ContractId),
        schemas(StateRequestResponse),
        schemas(StateRequestBody),
        schemas(Chain),
        schemas(ResponseAccount),
        schemas(TokensRequestBody),
        schemas(TokensRequestResponse),
        schemas(PaginationParams),
        schemas(PaginationResponse),
        schemas(ResponseToken),
        schemas(ProtocolComponentsRequestBody),
        schemas(ProtocolComponentRequestResponse),
        schemas(ProtocolComponent),
        schemas(ProtocolStateRequestBody),
        schemas(TracedEntryPointRequestBody),
        schemas(TracedEntryPointRequestResponse),
        schemas(ProtocolStateRequestResponse),
        schemas(AccountUpdate),
        schemas(ProtocolId),
        schemas(ResponseProtocolState),
        schemas(ChangeType),
        schemas(ProtocolStateDelta),
        schemas(Health),
        schemas(ProtocolSystemsRequestBody),
        schemas(ProtocolSystemsRequestResponse),
        schemas(ComponentTvlRequestBody),
        schemas(ComponentTvlRequestResponse),
        schemas(EntryPoint),
        schemas(EntryPointWithTracingParams),
        schemas(TracingResult),
        schemas(TracingParams),
        schemas(RPCTracerParams),
        schemas(AccountOverrides),
        schemas(StorageOverride),
    ),
    modifiers(&SecurityAddon),
)]
pub(super) struct ApiDoc;

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use utoipa::OpenApi;

    use super::ApiDoc;

    /// Recursively collects every `$ref` value in the document and checks that the
    /// referenced JSON Pointer exists in the document root.  Missing entries indicate
    /// "Could not resolve reference" errors in Swagger UI.
    fn collect_refs(node: &Value, root: &Value, missing: &mut Vec<String>) {
        match node {
            Value::Object(map) => {
                for (key, value) in map {
                    if key == "$ref" {
                        if let Some(reference) = value.as_str() {
                            if let Some(pointer) = reference.strip_prefix('#') {
                                if root.pointer(pointer).is_none() {
                                    missing.push(reference.to_string());
                                }
                            }
                        }
                    } else {
                        collect_refs(value, root, missing);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect_refs(item, root, missing);
                }
            }
            _ => {}
        }
    }

    /// Finds schema properties whose value is an empty object `{}`.  In utoipa this
    /// happens when a field's type does not implement `ToSchema` and no explicit
    /// `#[schema(value_type = ...)]` override is present.  An empty schema renders as
    /// "any type" in Swagger UI and almost always indicates a missing annotation.
    fn collect_empty_schemas(node: &Value, path: &str, found: &mut Vec<String>) {
        match node {
            Value::Object(map) => {
                if map.is_empty() && !path.is_empty() {
                    found.push(path.to_string());
                    return; // nothing to recurse into
                }
                for (key, value) in map {
                    let child_path = format!("{path}.{key}");
                    collect_empty_schemas(value, &child_path, found);
                }
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    let child_path = format!("{path}[{i}]");
                    collect_empty_schemas(item, &child_path, found);
                }
            }
            _ => {}
        }
    }

    /// Finds places where an `items` schema uses `allOf` with **more than one entry**.
    ///
    /// utoipa represents Rust tuples as `allOf: [schema_a, schema_b]` inside `items`.
    /// In OpenAPI 3.0 `allOf` means "satisfy ALL constraints simultaneously", not "a
    /// sequence of typed positions", so Swagger UI merges them into a single object
    /// instead of showing a proper two-element array.  This is a known utoipa
    /// limitation; new occurrences must either be fixed or added to the allow-list
    /// below with a comment explaining why they cannot be avoided.
    fn collect_tuple_allofs_in_items(node: &Value, path: &str, found: &mut Vec<String>) {
        match node {
            Value::Object(map) => {
                if let Some(items_value) = map.get("items") {
                    if let Value::Object(items_map) = items_value {
                        if let Some(Value::Array(allof)) = items_map.get("allOf") {
                            if allof.len() > 1 {
                                let types: Vec<String> = allof
                                    .iter()
                                    .map(|s| {
                                        s.get("$ref")
                                            .and_then(|v| v.as_str())
                                            .map(|r| {
                                                r.split('/').next_back().unwrap_or(r).to_string()
                                            })
                                            .or_else(|| {
                                                s.get("type")
                                                    .and_then(|v| v.as_str())
                                                    .map(str::to_string)
                                            })
                                            .unwrap_or_else(|| "?".to_string())
                                    })
                                    .collect();
                                found.push(format!("{path}.items → allOf{types:?}"));
                            }
                        }
                    }
                }
                for (key, value) in map {
                    let child_path = format!("{path}.{key}");
                    collect_tuple_allofs_in_items(value, &child_path, found);
                }
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    let child_path = format!("{path}[{i}]");
                    collect_tuple_allofs_in_items(item, &child_path, found);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn test_openapi_has_no_unresolved_refs() {
        let doc = ApiDoc::openapi();
        let json =
            serde_json::to_value(&doc).expect("OpenAPI document should serialize to JSON value");
        let mut missing = Vec::new();
        collect_refs(&json, &json, &mut missing);
        assert!(
            missing.is_empty(),
            "unresolved $ref targets present in OpenAPI document: {:?}",
            missing
        );
    }

    #[test]
    fn test_openapi_has_no_empty_schemas() {
        let doc = ApiDoc::openapi();
        let json =
            serde_json::to_value(&doc).expect("OpenAPI document should serialize to JSON value");
        let mut found = Vec::new();
        collect_empty_schemas(&json, "", &mut found);
        assert!(
            found.is_empty(),
            "empty schemas {{}} found in OpenAPI document — add a `#[schema(value_type = ...)]` \
             annotation to the offending field:\n  {}",
            found.join("\n  ")
        );
    }

    #[test]
    fn test_openapi_no_tuple_allof_in_items() {
        // Allow-list for known cases where utoipa generates allOf inside items due to Rust
        // tuple fields.  Each entry must document WHY it cannot be fixed and what the
        // actual wire format looks like.
        //
        // - TracedEntryPointRequestResponse.traced_entry_points: the value type is
        //   HashMap<ComponentId, Vec<(EntryPointWithTracingParams, TracingResult)>>.
        //   The inner tuple serialises as a 2-element JSON array.  OpenAPI 3.0 has no
        //   native tuple type; expressing it as a proper `items` array would require
        //   either OAS 3.1 `prefixItems` or a named wrapper struct that changes the
        //   wire format.  The refs DO resolve, so Swagger UI shows a merged object view
        //   rather than erroring.
        let allowed: &[&str] = &[
            "components.schemas.TracedEntryPointRequestResponse.properties\
             .traced_entry_points.additionalProperties.items.items → \
             allOf[\"EntryPointWithTracingParams\", \"TracingResult\"]",
        ];

        let doc = ApiDoc::openapi();
        let json =
            serde_json::to_value(&doc).expect("OpenAPI document should serialize to JSON value");
        let mut found = Vec::new();
        collect_tuple_allofs_in_items(&json, "", &mut found);

        let unexpected: Vec<&str> = found
            .iter()
            .map(String::as_str)
            .filter(|s| !allowed.iter().any(|a| s.contains(a.trim())))
            .collect();

        assert!(
            unexpected.is_empty(),
            "unexpected tuple allOf patterns found in OpenAPI document items — replace the \
             Rust tuple with a named struct or add an explicit allow-list entry:\n  {}",
            unexpected.join("\n  ")
        );
    }
}
