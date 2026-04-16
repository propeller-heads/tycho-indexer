use std::env;

use crate::rfq::errors::RFQError;

/// Hashflow authentication configuration
pub struct HashflowAuth {
    pub user: String,
    pub key: String,
}

/// Bebop authentication configuration
pub struct BebopAuth {
    pub user: String,
    pub key: String,
}

/// Read Hashflow authentication from environment variables
/// Returns the HASHFLOW_USER and HASHFLOW_KEY environment variables
pub fn get_hashflow_auth() -> Result<HashflowAuth, RFQError> {
    let user = env::var("HASHFLOW_USER").map_err(|_| {
        RFQError::InvalidInput("HASHFLOW_USER environment variable is required".into())
    })?;

    let key = env::var("HASHFLOW_KEY").map_err(|_| {
        RFQError::InvalidInput("HASHFLOW_KEY environment variable is required".into())
    })?;

    Ok(HashflowAuth { user, key })
}

/// Read Bebop authentication from environment variables
/// Returns the BEBOP_USER and BEBOP_KEY environment variables
pub fn get_bebop_auth() -> Result<BebopAuth, RFQError> {
    let user = env::var("BEBOP_USER").map_err(|_| {
        RFQError::InvalidInput("BEBOP_USER environment variable is required".into())
    })?;

    let key = env::var("BEBOP_KEY")
        .map_err(|_| RFQError::InvalidInput("BEBOP_KEY environment variable is required".into()))?;

    Ok(BebopAuth { user, key })
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;

    #[test]
    fn test_hashflow_auth_success() {
        env::set_var("HASHFLOW_USER", "test_user");
        env::set_var("HASHFLOW_KEY", "test_key");

        let auth = get_hashflow_auth().unwrap();
        assert_eq!(auth.user, "test_user");
        assert_eq!(auth.key, "test_key");

        env::remove_var("HASHFLOW_USER");
        env::remove_var("HASHFLOW_KEY");
    }

    #[test]
    fn test_hashflow_auth_missing_user() {
        env::remove_var("HASHFLOW_USER");
        env::set_var("HASHFLOW_KEY", "test_key");

        let result = get_hashflow_auth();
        assert!(result.is_err());

        env::remove_var("HASHFLOW_KEY");
    }

    #[test]
    fn test_hashflow_auth_missing_key() {
        env::set_var("HASHFLOW_USER", "test_user");
        env::remove_var("HASHFLOW_KEY");

        let result = get_hashflow_auth();
        assert!(result.is_err());

        env::remove_var("HASHFLOW_USER");
    }

    #[test]
    fn test_bebop_auth_success() {
        env::set_var("BEBOP_USER", "test_user");
        env::set_var("BEBOP_KEY", "test_key");

        let auth = get_bebop_auth().unwrap();
        assert_eq!(auth.user, "test_user");
        assert_eq!(auth.key, "test_key");

        env::remove_var("BEBOP_USER");
        env::remove_var("BEBOP_KEY");
    }

    #[test]
    fn test_bebop_auth_missing_user() {
        env::remove_var("BEBOP_USER");
        env::set_var("BEBOP_KEY", "test_key");

        let result = get_bebop_auth();
        assert!(result.is_err());

        env::remove_var("BEBOP_KEY");
    }

    #[test]
    fn test_bebop_auth_missing_key() {
        env::set_var("BEBOP_USER", "test_user");
        env::remove_var("BEBOP_KEY");

        let result = get_bebop_auth();
        assert!(result.is_err());

        env::remove_var("BEBOP_USER");
    }
}
