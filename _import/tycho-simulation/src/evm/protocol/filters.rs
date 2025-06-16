use std::collections::HashSet;

use num_bigint::BigInt;
use tracing::debug;
use tycho_client::feed::synchronizer::ComponentWithState;

use crate::evm::protocol::vm::utils::json_deserialize_be_bigint_list;

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
const ZERO_ADDRESS_ARR: [u8; 20] = [0u8; 20];

/// Filters out pools that have dynamic rate providers or unsupported pool types
/// in Balancer V2
pub fn balancer_pool_filter(component: &ComponentWithState) -> bool {
    // Check for rate_providers in static_attributes
    if let Some(rate_providers_data) = component
        .component
        .static_attributes
        .get("rate_providers")
    {
        let rate_providers_str =
            std::str::from_utf8(rate_providers_data).expect("Invalid UTF-8 data");
        let parsed_rate_providers =
            serde_json::from_str::<Vec<String>>(rate_providers_str).expect("Invalid JSON format");

        let has_dynamic_rate_provider = parsed_rate_providers
            .iter()
            .any(|provider| provider != ZERO_ADDRESS);

        if has_dynamic_rate_provider {
            debug!(
                "Filtering out Balancer pool {} because it has dynamic rate_providers",
                component.component.id
            );
            return false;
        }
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
            debug!(
                "Filtering out Balancer pool {} because it has type {}",
                component.component.id, pool_type
            );
            return false;
        }
    }

    true
}

/// Filters out pools that have unsupported token types in Curve
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
            debug!(
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
            debug!(
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
            debug!(
                "Filtering out Curve pool {} because it has proxy implementation {}",
                component.component.id, impl_str
            );
            return false;
        }
    }
    if let Some(factory_attribute) = component
        .component
        .static_attributes
        .get("factory")
    {
        let factory = std::str::from_utf8(factory_attribute).expect("Invalid UTF-8 data");
        if factory.to_lowercase() == "0xf18056bbd320e96a48e3fbf8bc061322531aac99" {
            debug!(
                "Filtering out Curve pool {} because it belongs to an unsupported factory",
                component.component.id
            );
            return false
        }
    };

    // Curve pools with rebasing tokens that are not supported
    const UNSUPPORTED_REBASING_COMPONENT_IDS: [&str; 2] = [
        "0xdc24316b9ae028f1497c275eb9192a3ea0f67022",
        "0x828b154032950c8ff7cf8085d841723db2696056",
    ];
    if UNSUPPORTED_REBASING_COMPONENT_IDS.contains(
        &component
            .component
            .id
            .to_lowercase()
            .as_str(),
    ) {
        debug!(
            "Filtering out Curve pool {} because it has a rebasing token that is not supported",
            component.component.id
        );
        return false
    }

    true
}

/// Filters out pools that have hooks in Uniswap V4
pub fn uniswap_v4_pool_with_hook_filter(component: &ComponentWithState) -> bool {
    if let Some(hooks) = component
        .component
        .static_attributes
        .get("hooks")
    {
        if hooks.to_vec() != ZERO_ADDRESS_ARR {
            debug!("Filtering out UniswapV4 pool {} because it has hooks", component.component.id);
            return false;
        }
    }
    true
}
