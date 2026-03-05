use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    path::Path,
};

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::services::rpc::RpcError;

/// Comparison operator for numerical restrictions.
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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Operator {
    Gte,
    Lte,
    Eq,
}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operator::Gte => write!(f, ">="),
            Operator::Lte => write!(f, "<="),
            Operator::Eq => write!(f, "=="),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct NumericRestriction {
    pub op: Operator,
    pub value: f64,
}

impl NumericRestriction {
    fn check(&self, actual: f64) -> bool {
        match self.op {
            Operator::Gte => actual >= self.value,
            Operator::Lte => actual <= self.value,
            Operator::Eq => (actual - self.value).abs() < f64::EPSILON,
        }
    }

    fn violation_message(&self, param_name: &str, actual: f64) -> String {
        format!(
            "{param_name} must be {op} {expected} (got {actual})",
            op = self.op,
            expected = self.value,
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
pub struct PlanRestrictions {
    #[serde(default)]
    pub allowed_protocol_systems: Option<HashSet<String>>,
    #[serde(default)]
    pub component_tvl: Option<NumericRestriction>,
    #[serde(default)]
    pub token_quality: Option<NumericRestriction>,
    #[serde(default)]
    pub traded_n_days_ago: Option<NumericRestriction>,
}

impl PlanRestrictions {
    pub fn check_protocol_system(&self, protocol_system: &str) -> Result<(), RpcError> {
        if let Some(allowed) = &self.allowed_protocol_systems {
            if !allowed.contains(protocol_system) {
                return Err(RpcError::PlanRestrictionViolation(format!(
                    "protocol_system '{protocol_system}' is not available on this plan \
                     (allowed: {})",
                    allowed
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                )));
            }
        }
        Ok(())
    }

    pub fn check_numeric(
        &self,
        param_name: &str,
        restriction: &Option<NumericRestriction>,
        actual: Option<f64>,
    ) -> Result<(), RpcError> {
        if let Some(restriction) = restriction {
            match actual {
                None => {
                    return Err(RpcError::PlanRestrictionViolation(format!(
                        "{param_name} parameter is required on this plan"
                    )));
                }
                Some(actual) if !restriction.check(actual) => {
                    return Err(RpcError::PlanRestrictionViolation(
                        restriction.violation_message(param_name, actual),
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PlansConfig {
    #[serde(default)]
    plans: HashMap<String, PlanRestrictions>,
}

impl PlansConfig {
    pub fn resolve(&self, plan_name: &str) -> Result<&PlanRestrictions, RpcError> {
        self.plans
            .get(plan_name)
            .ok_or_else(|| {
                RpcError::PlanRestrictionViolation(format!("unknown plan: '{plan_name}'"))
            })
    }

    pub fn is_empty(&self) -> bool {
        self.plans.is_empty()
    }

    /// Loads the plans config from a YAML file.
    ///
    /// If the file does not exist, returns a default instance (no restrictions).
    pub fn from_yaml(path: &str) -> Self {
        let path = Path::new(path);
        if !path.exists() {
            warn!("No plans config found at {}, running without plan restrictions", path.display());
            return Self::default();
        }
        match fs::read_to_string(path) {
            Ok(contents) => match serde_yaml::from_str(&contents) {
                Ok(config) => config,
                Err(e) => {
                    warn!("Failed to parse plans config at {}: {e}, running without plan restrictions", path.display());
                    Self::default()
                }
            },
            Err(e) => {
                warn!(
                    "Failed to read plans config at {}: {e}, running without plan restrictions",
                    path.display()
                );
                Self::default()
            }
        }
    }
}

/// Trait for request types that can be validated against plan restrictions.
///
/// The `is_targeted` method indicates whether the request specifies explicit IDs
/// (e.g. component_ids, token_addresses), in which case numerical restrictions are skipped.
pub trait ValidateRestrictions {
    fn validate_restrictions(&self, restrictions: &PlanRestrictions) -> Result<(), RpcError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yaml_deserialization() {
        let yaml = r#"
plans:
  default:
    component_tvl:
      op: gte
      value: 10000.0
    token_quality:
      op: gte
      value: 50
    traded_n_days_ago:
      op: lte
      value: 30
  strict:
    allowed_protocol_systems:
      - uniswap_v3
    token_quality:
      op: eq
      value: 100
    traded_n_days_ago:
      op: eq
      value: 7
"#;
        let config: PlansConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.plans.len(), 2);

        let default = config.resolve("default").unwrap();
        assert!(default
            .allowed_protocol_systems
            .is_none());
        assert_eq!(
            default
                .component_tvl
                .as_ref()
                .unwrap()
                .op,
            Operator::Gte
        );
        assert_eq!(
            default
                .component_tvl
                .as_ref()
                .unwrap()
                .value,
            10000.0
        );

        let strict = config.resolve("strict").unwrap();
        assert!(strict
            .allowed_protocol_systems
            .as_ref()
            .unwrap()
            .contains("uniswap_v3"));
        assert_eq!(
            strict
                .token_quality
                .as_ref()
                .unwrap()
                .op,
            Operator::Eq
        );
        assert_eq!(
            strict
                .traded_n_days_ago
                .as_ref()
                .unwrap()
                .value,
            7.0
        );
    }

    #[test]
    fn test_resolve_unknown_plan() {
        let config = PlansConfig::default();
        let result = config.resolve("nonexistent");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unknown plan"));
    }

    #[test]
    fn test_protocol_system_allowed() {
        let restrictions = PlanRestrictions {
            allowed_protocol_systems: Some(
                ["uniswap_v2", "uniswap_v3"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
            ..Default::default()
        };
        assert!(restrictions
            .check_protocol_system("uniswap_v2")
            .is_ok());
        assert!(restrictions
            .check_protocol_system("sushiswap")
            .is_err());
    }

    #[test]
    fn test_protocol_system_unrestricted() {
        let restrictions = PlanRestrictions::default();
        assert!(restrictions
            .check_protocol_system("anything")
            .is_ok());
    }

    mod numeric_checks {
        use rstest::rstest;

        use super::*;

        #[rstest]
        #[case::gte_passes(Operator::Gte, 100.0, Some(100.0), true)]
        #[case::gte_above(Operator::Gte, 100.0, Some(200.0), true)]
        #[case::gte_below(Operator::Gte, 100.0, Some(50.0), false)]
        #[case::lte_passes(Operator::Lte, 30.0, Some(30.0), true)]
        #[case::lte_below(Operator::Lte, 30.0, Some(15.0), true)]
        #[case::lte_above(Operator::Lte, 30.0, Some(60.0), false)]
        #[case::eq_passes(Operator::Eq, 100.0, Some(100.0), true)]
        #[case::eq_fails(Operator::Eq, 100.0, Some(99.0), false)]
        #[case::missing_param(Operator::Gte, 100.0, None, false)]
        fn test_numeric_restriction(
            #[case] op: Operator,
            #[case] threshold: f64,
            #[case] actual: Option<f64>,
            #[case] should_pass: bool,
        ) {
            let restrictions = PlanRestrictions {
                component_tvl: Some(NumericRestriction { op, value: threshold }),
                ..Default::default()
            };
            let result =
                restrictions.check_numeric("component_tvl", &restrictions.component_tvl, actual);
            assert_eq!(result.is_ok(), should_pass);
        }
    }

    #[test]
    fn test_missing_file_returns_empty() {
        let config = PlansConfig::from_yaml("/nonexistent/plans.yaml");
        assert!(config.is_empty());
    }

    #[test]
    fn test_check_numeric_no_restriction() {
        let restrictions = PlanRestrictions::default();
        assert!(restrictions
            .check_numeric("component_tvl", &restrictions.component_tvl, None)
            .is_ok());
        assert!(restrictions
            .check_numeric("component_tvl", &restrictions.component_tvl, Some(1.0))
            .is_ok());
    }

    #[test]
    fn test_violation_message_is_descriptive() {
        let restrictions = PlanRestrictions {
            component_tvl: Some(NumericRestriction { op: Operator::Gte, value: 10000.0 }),
            ..Default::default()
        };
        let result =
            restrictions.check_numeric("component_tvl", &restrictions.component_tvl, Some(500.0));
        let err = result.unwrap_err().to_string();
        assert!(err.contains("component_tvl"));
        assert!(err.contains(">="));
        assert!(err.contains("10000"));
        assert!(err.contains("500"));
    }
}
