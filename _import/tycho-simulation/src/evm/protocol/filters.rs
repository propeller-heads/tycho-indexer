use crate::evm::protocol::vm::utils::json_deserialize_be_bigint_list;
use num_bigint::BigInt;
use std::collections::HashSet;
use tracing::info;
use tycho_client::feed::synchronizer::ComponentWithState;

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
pub fn balancer_pool_filter(component: &ComponentWithState) -> bool {
    // Check for rate_providers in static_attributes
    info!("Checking Balancer pool {}", component.component.id);
    if let Some(rate_providers_data) = component
        .component
        .static_attributes
        .get("rate_providers")
    {
        let rate_providers_str =
            std::str::from_utf8(rate_providers_data).expect("Invalid UTF-8 data");
        let parsed_rate_providers =
            serde_json::from_str::<Vec<String>>(rate_providers_str).expect("Invalid JSON format");

        info!("Parsed rate providers: {:?}", parsed_rate_providers);
        let has_dynamic_rate_provider = parsed_rate_providers
            .iter()
            .any(|provider| provider != ZERO_ADDRESS);

        info!("Has dynamic rate provider: {:?}", has_dynamic_rate_provider);
        if has_dynamic_rate_provider {
            info!(
                "Filtering out Balancer pool {} because it has dynamic rate_providers",
                component.component.id
            );
            return false;
        }
    } else {
        info!("Balancer pool does not have `rate_providers` attribute");
    }
    let unsupported_pool_types: HashSet<&str> = [
        "ERC4626LinearPoolFactory",
        "EulerLinearPoolFactory",
        "SiloLinearPoolFactory",
        "YearnLinearPoolFactory",
        "ComposableStablePoolFactory",
    ]
    .iter()
    .cloned()
    .collect();

    // Check pool_type in static_attributes
    if let Some(pool_type_data) = component
        .component
        .static_attributes
        .get("pool_type")
    {
        // Convert the decoded bytes to a UTF-8 string
        let pool_type = std::str::from_utf8(pool_type_data).expect("Invalid UTF-8 data");
        if unsupported_pool_types.contains(pool_type) {
            info!(
                "Filtering out Balancer pool {} because it has type {}",
                component.component.id, pool_type
            );
            return false;
        } else {
            info!("Balancer pool with type {} will not be filtered out.", pool_type);
        }
    }
    info!(
        "Balancer pool with static attributes {:?} will not be filtered out.",
        component.component.static_attributes
    );
    info!("Balancer pool will not be filtered out.");
    true
}
pub fn curve_pool_filter(component: &ComponentWithState) -> bool {
    if let Some(asset_types) = component
        .component
        .static_attributes
        .get("asset_types")
    {
        if json_deserialize_be_bigint_list(asset_types)
            .unwrap()
            .iter()
            .any(|t| t != &BigInt::ZERO)
        {
            info!(
                "Filtering out Curve pool {} because it has unsupported token type",
                component.component.id
            );
            return false;
        }
    }

    if let Some(asset_type) = component
        .component
        .static_attributes
        .get("asset_type")
    {
        let types_str = std::str::from_utf8(asset_type).expect("Invalid UTF-8 data");
        if types_str != "0x00" {
            info!(
                "Filtering out Curve pool {} because it has unsupported token type",
                component.component.id
            );
            return false;
        }
    }

    if let Some(stateless_addrs) = component
        .state
        .attributes
        .get("stateless_contract_addr_0")
    {
        let impl_str = std::str::from_utf8(stateless_addrs).expect("Invalid UTF-8 data");
        // Uses oracles
        if impl_str == "0x847ee1227a9900b73aeeb3a47fac92c52fd54ed9" {
            info!(
                "Filtering out Curve pool {} because it has proxy implementation {}",
                component.component.id, impl_str
            );
            return false;
        }
    }
    true
}
