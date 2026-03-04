use std::{collections::HashMap, fmt::Display, path::Path};

use serde::Deserialize;
use tycho_common::dto;

use crate::services::rpc::RpcError;

/// Comparison operator for a plan field constraint.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConstraintOp {
    /// Request value must equal the configured threshold exactly.
    Eq,
    /// Request value must be greater than or equal to the configured threshold.
    Gte,
    /// Request value must be less than or equal to the configured threshold.
    Lte,
}

impl ConstraintOp {
    pub fn symbol(&self) -> &'static str {
        match self {
            ConstraintOp::Eq => "=",
            ConstraintOp::Gte => ">=",
            ConstraintOp::Lte => "<=",
        }
    }

    pub fn check<T: PartialOrd>(&self, actual: T, threshold: T) -> bool {
        match self {
            ConstraintOp::Eq => actual == threshold,
            ConstraintOp::Gte => actual >= threshold,
            ConstraintOp::Lte => actual <= threshold,
        }
    }
}

/// A configurable restriction on a single numeric field in a request.
#[derive(Debug, Clone, Deserialize)]
pub struct ParamConstraint<T> {
    pub op: ConstraintOp,
    pub value: T,
}

impl<T: PartialOrd + Copy> ParamConstraint<T> {
    pub fn check(&self, actual: T) -> bool {
        self.op.check(actual, self.value)
    }
}

/// Per-plan restriction configuration controlling API access based on user plans.
///
/// Config example:
/// ```yaml
/// plans:
///   default:
///     component_tvl:
///       op: gte
///       value: 10000.0
///     token_quality:
///       op: gte
///       value: 50
///     traded_n_days_ago:
///       op: lte
///       value: 30
///   strict:
///     allowed_protocol_systems:
///       - uniswap_v3
///     token_quality:
///       op: eq
///       value: 100
///     traded_n_days_ago:
///       op: eq
///       value: 7
/// ```
///
/// The plan named `default` is used as the fallback for unrecognised or missing plan names.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PlanConfig {
    /// Plan name — populated by the registry from the YAML key, not read from YAML.
    #[serde(skip)]
    pub name: String,
    /// If set, only requests for these protocol systems are permitted.
    /// Always enforced — not bypassed by the presence of specific IDs.
    pub allowed_protocol_systems: Option<Vec<String>>,
    /// Constraint on the `tvl_gt` request field for component queries (unless component_ids are
    /// provided).
    pub component_tvl: Option<ParamConstraint<f64>>,
    /// Constraint on the `min_quality` request field for token queries (unless token_addresses are
    /// provided).
    pub token_quality: Option<ParamConstraint<i32>>,
    /// Constraint on the `traded_n_days_ago` request field for token queries (unless
    /// token_addresses are provided).
    pub traded_n_days_ago: Option<ParamConstraint<u64>>,
}

impl PlanConfig {
    pub fn has_restrictions(&self) -> bool {
        self.allowed_protocol_systems.is_some() ||
            self.component_tvl.is_some() ||
            self.token_quality.is_some() ||
            self.traded_n_days_ago.is_some()
    }
}

/// Trait for enforcing a plan's restrictions against a request body.
///
/// Implement this on request body types to enable plan-level enforcement for that endpoint.
/// The default [`validate`] implementation calls [`protocol_system`] and [`check_fields`] in
/// order. Override only the methods relevant to each endpoint.
pub trait PlanEnforcement {
    /// Returns the protocol system from the request, if any.
    ///
    /// Checked against [`PlanConfig::allowed_protocol_systems`] when a non-empty value is
    /// returned. Defaults to `None` (no protocol-system check).
    fn protocol_system(&self) -> Option<&str> {
        None
    }

    /// Enforces endpoint-specific field restrictions (TVL, quality, etc.).
    ///
    /// Defaults to `Ok(())` (no field restrictions).
    fn check_fields(&self, _plan: &PlanConfig) -> Result<(), RpcError> {
        Ok(())
    }

    /// Validates the request against the plan by checking the protocol system and field
    /// restrictions. Override [`protocol_system`] and/or [`check_fields`] instead of this.
    fn validate(&self, plan: &PlanConfig) -> Result<(), RpcError> {
        check_protocol_system(plan, self.protocol_system())?;
        self.check_fields(plan)
    }
}

/// Validates that a request's protocol system is permitted by the plan.
///
/// If the plan has no allowlist, or `system` is `None`, the check is skipped.
pub fn check_protocol_system(plan: &PlanConfig, system: Option<&str>) -> Result<(), RpcError> {
    let (Some(allowed), Some(system)) = (&plan.allowed_protocol_systems, system) else {
        return Ok(());
    };
    if !allowed.iter().any(|s| s == system) {
        let allowed_list = if allowed.is_empty() { "none".to_string() } else { allowed.join(", ") };
        return Err(RpcError::MinimumFilterNotMet(
            "protocol_system".to_string(),
            format!(
                "Plan '{}' does not permit access to '{}'. Allowed: {allowed_list}.",
                plan.name, system
            ),
        ));
    }
    Ok(())
}

/// Checks a request field value against a plan constraint.
///
/// Returns `Ok(())` if there is no constraint or the value satisfies it. Returns `Err` if the
/// constraint is set but the value is missing or fails the comparison.
fn check_field_constraint<T>(
    plan: &PlanConfig,
    constraint: Option<&ParamConstraint<T>>,
    actual: Option<T>,
    field: &str,
) -> Result<(), RpcError>
where
    T: PartialOrd + Copy + Display,
{
    let Some(c) = constraint else { return Ok(()) };
    match actual {
        None => Err(RpcError::MinimumFilterNotMet(
            field.to_string(),
            format!("Plan '{}' requires '{}' {} {}.", plan.name, field, c.op.symbol(), c.value),
        )),
        Some(v) if !c.check(v) => Err(RpcError::MinimumFilterNotMet(
            field.to_string(),
            format!(
                "Plan '{}' requires '{}' {} {} (got {v}).",
                plan.name,
                field,
                c.op.symbol(),
                c.value,
            ),
        )),
        _ => Ok(()),
    }
}

impl PlanEnforcement for dto::TokensRequestBody {
    fn check_fields(&self, plan: &PlanConfig) -> Result<(), RpcError> {
        if self.token_addresses.is_some() {
            return Ok(());
        }
        check_field_constraint(plan, plan.token_quality.as_ref(), self.min_quality, "min_quality")?;
        check_field_constraint(
            plan,
            plan.traded_n_days_ago.as_ref(),
            self.traded_n_days_ago,
            "traded_n_days_ago",
        )
    }
}

impl PlanEnforcement for dto::ProtocolComponentsRequestBody {
    fn protocol_system(&self) -> Option<&str> {
        if self.protocol_system.is_empty() {
            None
        } else {
            Some(&self.protocol_system)
        }
    }

    fn check_fields(&self, plan: &PlanConfig) -> Result<(), RpcError> {
        if self.component_ids.is_some() {
            return Ok(());
        }
        check_field_constraint(plan, plan.component_tvl.as_ref(), self.tvl_gt, "tvl_gt")
    }
}

impl PlanEnforcement for dto::StateRequestBody {
    fn protocol_system(&self) -> Option<&str> {
        if self.protocol_system.is_empty() {
            None
        } else {
            Some(&self.protocol_system)
        }
    }
}

impl PlanEnforcement for dto::ProtocolStateRequestBody {
    fn protocol_system(&self) -> Option<&str> {
        if self.protocol_system.is_empty() {
            None
        } else {
            Some(&self.protocol_system)
        }
    }
}

impl PlanEnforcement for dto::ComponentTvlRequestBody {
    fn protocol_system(&self) -> Option<&str> {
        self.protocol_system.as_deref()
    }
}

impl PlanEnforcement for dto::TracedEntryPointRequestBody {
    fn protocol_system(&self) -> Option<&str> {
        if self.protocol_system.is_empty() {
            None
        } else {
            Some(&self.protocol_system)
        }
    }
}

#[derive(Debug, Deserialize)]
struct PlansFile {
    plans: HashMap<String, PlanConfig>,
}

/// Maps plan names to their [`PlanConfig`]s.
///
/// Unknown or missing plan names fall back to the plan named `default` in the config,
/// or to unrestricted access if no `default` plan is defined.
#[derive(Debug, Clone)]
pub struct PlanRegistry {
    plans: HashMap<String, PlanConfig>,
    default: PlanConfig,
}

impl PlanRegistry {
    /// Creates an empty registry (no restrictions for any plan).
    pub fn empty() -> Self {
        Self { plans: HashMap::new(), default: PlanConfig::default() }
    }

    /// Loads plan configurations from a YAML file.
    ///
    /// The plan keyed `default` is used as the fallback for unrecognised plan names. All plans
    /// (including `default`) are also accessible by their YAML key.
    pub fn from_file(path: &Path) -> Result<Self, anyhow::Error> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("Failed to read plans config '{}': {}", path.display(), e)
        })?;
        let file: PlansFile = serde_yaml::from_str(&contents).map_err(|e| {
            anyhow::anyhow!("Failed to parse plans config '{}': {}", path.display(), e)
        })?;
        let mut plans = file.plans;

        // Set the name field from the YAML key for each plan.
        for (name, config) in &mut plans {
            config.name = name.clone();
        }

        let default = plans
            .get("default")
            .cloned()
            .unwrap_or_default();

        Ok(Self { plans, default })
    }

    /// Returns the config for the named plan, falling back to the default if not found.
    ///
    /// Pass `None` (e.g. when no `X-User-Plan` header is present) to get the default plan.
    pub fn get_plan(&self, name: Option<&str>) -> &PlanConfig {
        name.and_then(|n| self.plans.get(n))
            .unwrap_or(&self.default)
    }

    /// Creates a registry with a single default plan applied to all requests.
    /// Useful for testing.
    #[cfg(test)]
    pub fn with_default_plan(default: PlanConfig) -> Self {
        Self { plans: HashMap::new(), default }
    }

    #[cfg(test)]
    pub(crate) fn from_file_plans(mut plans: HashMap<String, PlanConfig>) -> Self {
        for (name, config) in &mut plans {
            config.name = name.clone();
        }
        let default = plans
            .get("default")
            .cloned()
            .unwrap_or_default();
        Self { plans, default }
    }
}

/// Extracts the plan name from the `X-User-Plan` request header.
///
/// Returns `None` if the header is absent or not valid UTF-8, which causes
/// [`PlanRegistry::get_plan`] to fall back to the default plan.
pub fn plan_name_from_request(req: &actix_web::HttpRequest) -> Option<&str> {
    req.headers()
        .get("x-user-plan")
        .and_then(|v| v.to_str().ok())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rstest::rstest;
    use tycho_common::{dto, Bytes};

    use super::*;
    use crate::services::rpc::RpcError;

    fn plan_with_quality(constraint: Option<ParamConstraint<i32>>) -> PlanConfig {
        PlanConfig { token_quality: constraint, ..Default::default() }
    }

    fn plan_with_traded(constraint: Option<ParamConstraint<u64>>) -> PlanConfig {
        PlanConfig { traded_n_days_ago: constraint, ..Default::default() }
    }

    fn plan_with_tvl(constraint: Option<ParamConstraint<f64>>) -> PlanConfig {
        PlanConfig { component_tvl: constraint, ..Default::default() }
    }

    fn plan_with_systems(systems: Option<Vec<&str>>) -> PlanConfig {
        PlanConfig {
            allowed_protocol_systems: systems.map(|v| {
                v.into_iter()
                    .map(String::from)
                    .collect()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_plan_registry_unknown_plan_returns_default() {
        let registry = PlanRegistry::empty();
        let plan = registry.get_plan(Some("unknown"));
        assert!(!plan.has_restrictions());
    }

    #[test]
    fn test_plan_registry_no_header_returns_default() {
        let registry = PlanRegistry::empty();
        let plan = registry.get_plan(None);
        assert!(!plan.has_restrictions());
    }

    #[test]
    fn test_plan_registry_known_plan() {
        let mut plans = HashMap::new();
        plans.insert(
            "strict".to_string(),
            PlanConfig {
                name: "strict".to_string(),
                allowed_protocol_systems: Some(vec!["uniswap_v3".to_string()]),
                token_quality: Some(ParamConstraint { op: ConstraintOp::Eq, value: 100 }),
                component_tvl: None,
                traded_n_days_ago: None,
            },
        );
        let registry = PlanRegistry { plans, default: PlanConfig::default() };
        let plan = registry.get_plan(Some("strict"));
        assert!(plan.has_restrictions());
        assert_eq!(plan.allowed_protocol_systems, Some(vec!["uniswap_v3".to_string()]));
        assert!(matches!(
            plan.token_quality,
            Some(ParamConstraint { op: ConstraintOp::Eq, value: 100 })
        ));
    }

    #[test]
    fn test_plan_registry_default_plan_used_as_fallback() {
        let mut plans = HashMap::new();
        plans.insert(
            "default".to_string(),
            PlanConfig {
                name: "default".to_string(),
                component_tvl: Some(ParamConstraint { op: ConstraintOp::Gte, value: 10000.0 }),
                ..Default::default()
            },
        );
        let registry = PlanRegistry::from_file_plans(plans);
        let plan = registry.get_plan(Some("unknown"));
        assert!(plan.component_tvl.is_some());
    }

    #[test]
    fn test_check_protocol_system_no_allowlist_passes() {
        let plan = PlanConfig::default();
        assert!(check_protocol_system(&plan, Some("any_system")).is_ok());
    }

    #[test]
    fn test_check_protocol_system_none_system_skips_check() {
        let plan = PlanConfig {
            allowed_protocol_systems: Some(vec!["uniswap_v3".to_string()]),
            ..Default::default()
        };
        assert!(check_protocol_system(&plan, None).is_ok());
    }

    #[test]
    fn test_check_protocol_system_allowed_passes() {
        let plan = PlanConfig {
            allowed_protocol_systems: Some(vec!["uniswap_v3".to_string()]),
            ..Default::default()
        };
        assert!(check_protocol_system(&plan, Some("uniswap_v3")).is_ok());
    }

    #[test]
    fn test_check_protocol_system_disallowed_fails() {
        let plan = PlanConfig {
            name: "strict".to_string(),
            allowed_protocol_systems: Some(vec!["uniswap_v3".to_string()]),
            ..Default::default()
        };
        let result = check_protocol_system(&plan, Some("uniswap_v2"));
        assert!(matches!(result, Err(RpcError::MinimumFilterNotMet(_, _))));
    }

    #[test]
    fn test_constraint_op_symbols() {
        assert_eq!(ConstraintOp::Eq.symbol(), "=");
        assert_eq!(ConstraintOp::Gte.symbol(), ">=");
        assert_eq!(ConstraintOp::Lte.symbol(), "<=");
    }

    #[test]
    fn test_param_constraint_check() {
        assert!(ParamConstraint { op: ConstraintOp::Gte, value: 50 }.check(50));
        assert!(ParamConstraint { op: ConstraintOp::Gte, value: 50 }.check(100));
        assert!(!ParamConstraint { op: ConstraintOp::Gte, value: 50 }.check(49));

        assert!(ParamConstraint { op: ConstraintOp::Lte, value: 30u64 }.check(30));
        assert!(ParamConstraint { op: ConstraintOp::Lte, value: 30u64 }.check(10));
        assert!(!ParamConstraint { op: ConstraintOp::Lte, value: 30u64 }.check(31));

        assert!(ParamConstraint { op: ConstraintOp::Eq, value: 75 }.check(75));
        assert!(!ParamConstraint { op: ConstraintOp::Eq, value: 75 }.check(74));
        assert!(!ParamConstraint { op: ConstraintOp::Eq, value: 75 }.check(76));
    }

    // --- TokensRequestBody: token_quality ---

    #[rstest]
    #[case::gte_rejects_missing(ConstraintOp::Gte, 50, None, Some("min_quality"))]
    #[case::gte_rejects_below(ConstraintOp::Gte, 50, Some(30), Some("min_quality"))]
    #[case::gte_accepts_equal(ConstraintOp::Gte, 50, Some(50), None)]
    #[case::gte_accepts_above(ConstraintOp::Gte, 50, Some(80), None)]
    #[case::lte_rejects_missing(ConstraintOp::Lte, 50, None, Some("min_quality"))]
    #[case::lte_rejects_above(ConstraintOp::Lte, 50, Some(80), Some("min_quality"))]
    #[case::lte_accepts_equal(ConstraintOp::Lte, 50, Some(50), None)]
    #[case::lte_accepts_below(ConstraintOp::Lte, 50, Some(30), None)]
    #[case::eq_rejects_missing(ConstraintOp::Eq, 75, None, Some("min_quality"))]
    #[case::eq_rejects_different(ConstraintOp::Eq, 75, Some(50), Some("min_quality"))]
    #[case::eq_accepts_match(ConstraintOp::Eq, 75, Some(75), None)]
    fn test_tokens_quality_constraint(
        #[case] op: ConstraintOp,
        #[case] threshold: i32,
        #[case] req_quality: Option<i32>,
        #[case] error_contains: Option<&str>,
    ) {
        let plan = plan_with_quality(Some(ParamConstraint { op, value: threshold }));
        let body = dto::TokensRequestBody {
            chain: dto::Chain::Ethereum,
            token_addresses: None,
            min_quality: req_quality,
            traded_n_days_ago: None,
            pagination: dto::PaginationParams::new(0, 10),
        };
        let result = body.validate(&plan);
        match error_contains {
            None => assert!(result.is_ok(), "expected ok, got {result:?}"),
            Some(msg) => {
                assert!(result.is_err());
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains(msg));
            }
        }
    }

    #[test]
    fn test_tokens_quality_bypass_with_addresses() {
        let plan = plan_with_quality(Some(ParamConstraint { op: ConstraintOp::Gte, value: 50 }));
        let body = dto::TokensRequestBody {
            chain: dto::Chain::Ethereum,
            token_addresses: Some(vec![Bytes::from("0x0123")]),
            min_quality: None,
            traded_n_days_ago: None,
            pagination: dto::PaginationParams::new(0, 10),
        };
        assert!(body.validate(&plan).is_ok());
    }

    // --- TokensRequestBody: traded_n_days_ago ---

    #[rstest]
    #[case::lte_rejects_missing(ConstraintOp::Lte, 30, None, Some("traded_n_days_ago"))]
    #[case::lte_rejects_above(ConstraintOp::Lte, 30, Some(60), Some("traded_n_days_ago"))]
    #[case::lte_accepts_equal(ConstraintOp::Lte, 30, Some(30), None)]
    #[case::lte_accepts_below(ConstraintOp::Lte, 30, Some(15), None)]
    #[case::gte_rejects_missing(ConstraintOp::Gte, 7, None, Some("traded_n_days_ago"))]
    #[case::gte_rejects_below(ConstraintOp::Gte, 7, Some(3), Some("traded_n_days_ago"))]
    #[case::gte_accepts_equal(ConstraintOp::Gte, 7, Some(7), None)]
    #[case::eq_rejects_different(ConstraintOp::Eq, 7, Some(8), Some("traded_n_days_ago"))]
    #[case::eq_accepts_match(ConstraintOp::Eq, 7, Some(7), None)]
    fn test_tokens_traded_n_days_ago_constraint(
        #[case] op: ConstraintOp,
        #[case] threshold: u64,
        #[case] req_days: Option<u64>,
        #[case] error_contains: Option<&str>,
    ) {
        let plan = plan_with_traded(Some(ParamConstraint { op, value: threshold }));
        let body = dto::TokensRequestBody {
            chain: dto::Chain::Ethereum,
            token_addresses: None,
            min_quality: None,
            traded_n_days_ago: req_days,
            pagination: dto::PaginationParams::new(0, 10),
        };
        let result = body.validate(&plan);
        match error_contains {
            None => assert!(result.is_ok(), "expected ok, got {result:?}"),
            Some(msg) => {
                assert!(result.is_err());
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains(msg));
            }
        }
    }

    // --- ProtocolComponentsRequestBody: component_tvl ---

    #[rstest]
    #[case::gte_rejects_missing(ConstraintOp::Gte, 1000.0, None, None, Some("tvl_gt"))]
    #[case::gte_rejects_below(ConstraintOp::Gte, 1000.0, Some(500.0), None, Some("tvl_gt"))]
    #[case::gte_accepts_equal(ConstraintOp::Gte, 1000.0, Some(1000.0), None, None)]
    #[case::gte_accepts_above(ConstraintOp::Gte, 1000.0, Some(5000.0), None, None)]
    #[case::eq_rejects_different(ConstraintOp::Eq, 1000.0, Some(999.0), None, Some("tvl_gt"))]
    #[case::eq_accepts_match(ConstraintOp::Eq, 1000.0, Some(1000.0), None, None)]
    #[case::bypass_with_component_ids(ConstraintOp::Gte, 1000.0, None, Some(vec!["c1".to_string()]), None)]
    fn test_components_tvl_constraint(
        #[case] op: ConstraintOp,
        #[case] threshold: f64,
        #[case] req_tvl: Option<f64>,
        #[case] component_ids: Option<Vec<String>>,
        #[case] error_contains: Option<&str>,
    ) {
        let plan = plan_with_tvl(Some(ParamConstraint { op, value: threshold }));
        let body = dto::ProtocolComponentsRequestBody {
            protocol_system: "ambient".to_string(),
            component_ids,
            tvl_gt: req_tvl,
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::new(0, 10),
        };
        let result = body.validate(&plan);
        match error_contains {
            None => assert!(result.is_ok(), "expected ok, got {result:?}"),
            Some(msg) => {
                assert!(result.is_err());
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains(msg));
            }
        }
    }

    #[rstest]
    #[case::allowed_system_passes("uniswap_v3", Some(vec!["uniswap_v3"]), true)]
    #[case::disallowed_system_fails("uniswap_v2", Some(vec!["uniswap_v3"]), false)]
    #[case::no_allowlist_passes("anything", None, true)]
    fn test_components_protocol_system(
        #[case] system: &str,
        #[case] allowed: Option<Vec<&str>>,
        #[case] should_pass: bool,
    ) {
        let plan = plan_with_systems(allowed);
        let body = dto::ProtocolComponentsRequestBody {
            protocol_system: system.to_string(),
            component_ids: None,
            tvl_gt: None,
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::new(0, 10),
        };
        let result = body.validate(&plan);
        assert_eq!(result.is_ok(), should_pass, "result: {result:?}");
    }

    #[test]
    fn test_components_protocol_system_not_bypassed_by_component_ids() {
        let plan = PlanConfig {
            name: "strict".to_string(),
            allowed_protocol_systems: Some(vec!["uniswap_v3".to_string()]),
            component_tvl: Some(ParamConstraint { op: ConstraintOp::Gte, value: 1000.0 }),
            ..Default::default()
        };
        let body = dto::ProtocolComponentsRequestBody {
            protocol_system: "uniswap_v2".to_string(),
            component_ids: Some(vec!["comp1".to_string()]),
            tvl_gt: None,
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::new(0, 10),
        };
        // component_ids bypasses tvl check but not protocol system check
        let result = body.validate(&plan);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RpcError::MinimumFilterNotMet(_, _)));
    }

    // --- Protocol system check on other endpoints ---

    #[rstest]
    #[case::allowed_passes("uniswap_v2", Some(vec!["uniswap_v2"]), true)]
    #[case::disallowed_fails("uniswap_v3", Some(vec!["uniswap_v2"]), false)]
    #[case::no_allowlist_passes("anything", None, true)]
    #[case::empty_system_skips_check("", Some(vec!["uniswap_v2"]), true)]
    fn test_contract_state_protocol_system(
        #[case] system: &str,
        #[case] allowed: Option<Vec<&str>>,
        #[case] should_pass: bool,
    ) {
        let plan = plan_with_systems(allowed);
        let body = dto::StateRequestBody {
            protocol_system: system.to_string(),
            contract_ids: None,
            version: Default::default(),
            chain: Default::default(),
            pagination: dto::PaginationParams::new(0, 10),
        };
        let result = body.validate(&plan);
        assert_eq!(result.is_ok(), should_pass, "result: {result:?}");
    }

    #[rstest]
    #[case::allowed_passes("uniswap_v2", Some(vec!["uniswap_v2"]), true)]
    #[case::disallowed_fails("uniswap_v3", Some(vec!["uniswap_v2"]), false)]
    #[case::no_allowlist_passes("anything", None, true)]
    #[case::empty_system_skips_check("", Some(vec!["uniswap_v2"]), true)]
    fn test_protocol_state_protocol_system(
        #[case] system: &str,
        #[case] allowed: Option<Vec<&str>>,
        #[case] should_pass: bool,
    ) {
        let plan = plan_with_systems(allowed);
        let body = dto::ProtocolStateRequestBody {
            protocol_system: system.to_string(),
            protocol_ids: None,
            chain: Default::default(),
            include_balances: true,
            version: Default::default(),
            pagination: dto::PaginationParams::new(0, 10),
        };
        let result = body.validate(&plan);
        assert_eq!(result.is_ok(), should_pass, "result: {result:?}");
    }

    #[rstest]
    #[case::allowed_passes(Some("uniswap_v2"), Some(vec!["uniswap_v2"]), true)]
    #[case::disallowed_fails(Some("uniswap_v3"), Some(vec!["uniswap_v2"]), false)]
    #[case::no_system_skips_check(None, Some(vec!["uniswap_v2"]), true)]
    #[case::no_allowlist_passes(Some("anything"), None, true)]
    fn test_component_tvl_protocol_system(
        #[case] system: Option<&str>,
        #[case] allowed: Option<Vec<&str>>,
        #[case] should_pass: bool,
    ) {
        let plan = plan_with_systems(allowed);
        let body = dto::ComponentTvlRequestBody {
            protocol_system: system.map(str::to_string),
            chain: Default::default(),
            component_ids: None,
            pagination: dto::PaginationParams::new(0, 10),
        };
        let result = body.validate(&plan);
        assert_eq!(result.is_ok(), should_pass, "result: {result:?}");
    }

    #[rstest]
    #[case::allowed_passes("uniswap_v2", Some(vec!["uniswap_v2"]), true)]
    #[case::disallowed_fails("uniswap_v3", Some(vec!["uniswap_v2"]), false)]
    #[case::no_allowlist_passes("anything", None, true)]
    #[case::empty_system_skips_check("", Some(vec!["uniswap_v2"]), true)]
    fn test_traced_entry_points_protocol_system(
        #[case] system: &str,
        #[case] allowed: Option<Vec<&str>>,
        #[case] should_pass: bool,
    ) {
        let plan = plan_with_systems(allowed);
        let body = dto::TracedEntryPointRequestBody {
            protocol_system: system.to_string(),
            chain: Default::default(),
            component_ids: None,
            pagination: dto::PaginationParams::new(0, 10),
        };
        let result = body.validate(&plan);
        assert_eq!(result.is_ok(), should_pass, "result: {result:?}");
    }
}
