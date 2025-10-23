use chrono::{NaiveDateTime, Utc};
use clap::{Args, Parser, Subcommand};
use tycho_common::{models::Chain, Bytes};

/// Tycho Indexer using Substreams
///
/// Extracts state from the Ethereum blockchain and stores it in a Postgres database.
#[derive(Parser, PartialEq, Debug)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(flatten)]
    global_args: GlobalArgs,
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub fn args(&self) -> GlobalArgs {
        self.global_args.clone()
    }

    pub fn command(&self) -> Command {
        self.command.clone()
    }
}

#[derive(Subcommand, Clone, PartialEq, Debug)]
pub enum Command {
    /// Starts the indexing service.
    Index(IndexArgs),
    /// Runs a single substream, intended for testing.
    Run(RunSpkgArgs),
    /// Starts a job to analyze stored tokens for tax and gas cost.
    AnalyzeTokens(AnalyzeTokenArgs),
    /// Starts Tycho RPC only. No extractors.
    Rpc,
}

#[derive(Parser, Debug, Clone, PartialEq, Eq)]
#[command(version, about, long_about = None)]
pub struct GlobalArgs {
    /// PostgresDB Connection Url
    #[clap(
        long,
        env,
        hide_env_values = true,
        default_value = "postgres://postgres:mypassword@localhost:5431/tycho_indexer_0"
    )]
    pub database_url: String,

    /// Batch size for the database inserts
    #[clap(long, default_value = "0")]
    pub database_insert_batch_size: usize,

    /// Name of the s3 bucket used to retrieve spkgs
    #[clap(env = "TYCHO_S3_BUCKET", long, default_value = "repo.propellerheads-propellerheads")]
    //Default is for backward compatibility but needs to be removed later
    pub s3_bucket: Option<String>,

    /// The RPC URL to connect to the Ethereum node
    #[clap(env = "RPC_URL", long, hide_env_values = true)]
    pub rpc_url: String,

    /// Substreams API endpoint
    #[clap(name = "endpoint", long, default_value = "https://mainnet.eth.streamingfast.io")]
    pub endpoint_url: String,

    /// The server IP
    #[clap(long, default_value = "0.0.0.0")]
    pub server_ip: String,

    /// The server port
    #[clap(long, default_value = "4242")]
    pub server_port: u16,

    /// The server version prefix
    #[clap(long, default_value = "v1")]
    pub server_version_prefix: String,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub struct SubstreamsArgs {
    /// Substreams API token
    #[clap(long, env, hide_env_values = true, alias = "api_token")]
    pub substreams_api_token: String,
}

#[derive(Args, Debug, Clone, PartialEq)]
pub struct IndexArgs {
    #[clap(flatten)]
    pub substreams_args: SubstreamsArgs,

    /// Extractors configuration file
    #[clap(long, env, default_value = "./extractors.yaml")]
    pub extractors_config: String,

    /// A comma separated list of blockchains to index on
    #[clap(long, default_value = "ethereum", value_delimiter = ',')]
    pub chains: Vec<String>,

    /// Any data before this date is not kept in storage.
    /// Can be specified as:
    ///
    /// - A date string in format "YYYY-MM-DDTHH:MM:SS" (e.g. "2024-01-01T00:00:00")
    ///
    /// - A number of days (e.g. "30" for 30 days ago)
    #[clap(long, env, default_value = "30")]
    pub retention_horizon: String,
}

impl IndexArgs {
    /// Calculates the retention horizon as a NaiveDateTime
    ///
    /// First tries to parse the input as a date string (YYYY-MM-DDTHH:MM:SS format)
    /// If that fails, tries to parse it as a number of days and calculates the datetime
    /// by subtracting days from now
    ///
    /// Validates that days are greater than 0
    pub fn get_retention_horizon(&self) -> Result<NaiveDateTime, String> {
        // First try to parse as a date string
        if let Ok(datetime) = self
            .retention_horizon
            .parse::<NaiveDateTime>()
        {
            return Ok(datetime);
        }

        // If that fails, try to parse as number of days
        let days= self.retention_horizon.parse::<u32>()
            .map_err(|_| format!("Failed to parse retention horizon '{}' as either a date (YYYY-MM-DDTHH:MM:SS) or number of days", self.retention_horizon))?;

        if days == 0 {
            return Err("Retention horizon days must be greater than 0".to_string());
        }

        let days_horizon = Utc::now().naive_utc() - chrono::Duration::days(days as i64);
        Ok(days_horizon)
    }
}

#[derive(Args, Debug, Clone, PartialEq)]
pub struct RunSpkgArgs {
    /// The blockchain to index on
    #[clap(long, default_value = "ethereum")]
    pub chain: String,

    #[clap(flatten)]
    pub substreams_args: SubstreamsArgs,

    /// Substreams Package file
    #[clap(long)]
    pub spkg: String,

    /// Substreams Module name
    #[clap(long)]
    pub module: String,

    // The names of the protocol_types to index
    #[clap(long, value_delimiter = ',')]
    pub protocol_type_names: Vec<String>,

    // Protocol system to index
    #[clap(long)]
    pub protocol_system: String,

    /// Substreams start block
    #[clap(long)]
    pub start_block: i64,

    /// Substreams stop block
    ///
    /// Optional. If not provided, the extractor will run until the latest block.
    /// If prefixed with a `+` the value is interpreted as an increment to the start block.
    /// Defaults to STOP_BLOCK env var or None.
    #[clap(long)]
    stop_block: Option<String>,

    /// Account addresses to be initialized before indexing
    #[clap(long, value_delimiter = ',')]
    pub initialized_accounts: Vec<Bytes>,

    /// Block number to initialize the accounts at
    #[clap(long, default_value = "0")]
    pub initialization_block: i64,

    /// DCI plugin to use
    ///
    /// Optional. If not provided, the extractor will not use DCI. Available plugins:
    /// - `rpc` - RPC is used to trace and retrieve detected accounts.
    #[clap(long)]
    pub dci_plugin: Option<String>,
}

impl RunSpkgArgs {
    pub fn stop_block(&self) -> Option<i64> {
        if let Some(s) = &self.stop_block {
            if s.starts_with('+') {
                let increment: i64 = s
                    .strip_prefix('+')
                    .expect("stripped stop block value")
                    .parse()
                    .expect("stop block value");
                Some(self.start_block + increment)
            } else {
                Some(s.parse().expect("stop block value"))
            }
        } else {
            None
        }
    }
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct AnalyzeTokenArgs {
    /// Ethereum node rpc url
    #[clap(env, long)]
    pub rpc_url: String,
    /// Blockchain to execute analysis for.
    #[clap(long)]
    pub chain: Chain,
    /// How many concurrent threads to use for token analysis.
    #[clap(long)]
    pub concurrency: usize,
    /// How many tokens to update in a batch per thread.
    #[clap(long)]
    pub update_batch_size: usize,
    /// How many tokens to fetch from the db to distribute to threads (page size). This
    /// should be at least `concurrency * update_batch_size`.
    #[clap(long)]
    pub fetch_batch_size: usize,
}

#[cfg(test)]
mod cli_tests {
    use rstest::rstest;

    use super::*;

    #[tokio::test]
    async fn test_arg_parsing_run_cmd() {
        let cli = Cli::try_parse_from(vec![
            "tycho-indexer",
            "--endpoint",
            "http://example.com",
            "--database-url",
            "my_db",
            "--database-insert-batch-size",
            "256",
            "--rpc-url",
            "http://example.com",
            "run",
            "--api_token",
            "your_api_token",
            "--spkg",
            "package.spkg",
            "--module",
            "module_name",
            "--start-block",
            "17361664",
            "--protocol-type-names",
            "pt1,pt2",
            "--protocol-system",
            "test_protocol",
        ])
        .expect("parse errored");

        let expected_args = Cli {
            global_args: GlobalArgs {
                endpoint_url: "http://example.com".to_string(),
                database_url: "my_db".to_string(),
                database_insert_batch_size: 256,
                rpc_url: "http://example.com".to_string(),
                s3_bucket: Some("repo.propellerheads-propellerheads".to_string()),
                server_ip: "0.0.0.0".to_string(),
                server_port: 4242,
                server_version_prefix: "v1".to_string(),
            },
            command: Command::Run(RunSpkgArgs {
                chain: "ethereum".to_string(),
                spkg: "package.spkg".to_string(),
                module: "module_name".to_string(),
                protocol_type_names: vec!["pt1".to_string(), "pt2".to_string()],
                protocol_system: "test_protocol".to_string(),
                start_block: 17361664,
                stop_block: None,
                substreams_args: SubstreamsArgs {
                    substreams_api_token: "your_api_token".to_string(),
                },
                initialized_accounts: vec![],
                initialization_block: 0,
                dci_plugin: None,
            }),
        };

        assert_eq!(cli, expected_args);
    }

    // Helper function to create basic CLI indexargs
    fn create_basic_index_args() -> Vec<String> {
        [
            "tycho-indexer",
            "--endpoint",
            "http://example.com",
            "--database-url",
            "my_db",
            "--rpc-url",
            "http://example.com",
            "index",
            "--api_token",
            "token",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    // Helper function to parse CLI args and extract IndexArgs
    fn parse_index_args(args: Vec<String>) -> IndexArgs {
        let cli = Cli::try_parse_from(args).expect("parse errored");
        match cli.command() {
            Command::Index(index_args) => index_args.clone(),
            _ => panic!("Expected Index command"),
        }
    }

    #[test]
    fn test_arg_parsing_index_cmd() {
        let mut args = create_basic_index_args();
        args.push("--extractors-config".to_string());
        args.push("/opt/extractors.yaml".to_string());

        let cli = Cli::try_parse_from(args).expect("parse errored");

        let expected_args = Cli {
            global_args: GlobalArgs {
                endpoint_url: "http://example.com".to_string(),
                database_url: "my_db".to_string(),
                database_insert_batch_size: 0,
                rpc_url: "http://example.com".to_string(),
                s3_bucket: Some("repo.propellerheads-propellerheads".to_string()),
                server_ip: "0.0.0.0".to_string(),
                server_port: 4242,
                server_version_prefix: "v1".to_string(),
            },
            command: Command::Index(IndexArgs {
                substreams_args: SubstreamsArgs { substreams_api_token: "token".to_string() },
                chains: vec!["ethereum".to_string()],
                extractors_config: "/opt/extractors.yaml".to_string(),
                retention_horizon: "30".to_string(),
            }),
        };

        assert_eq!(cli, expected_args);
    }

    #[test]
    fn test_arg_parsing_missing_val() {
        let args = Cli::try_parse_from(vec![
            "tycho-indexer",
            "--spkg",
            "package.spkg",
            "--module",
            "module_name",
        ]);

        assert!(args.is_err());
    }

    #[test]
    fn test_retention_horizon_date_parsing() {
        let mut args = create_basic_index_args();
        args.push("--retention-horizon".to_string());
        args.push("2024-01-01T00:00:00".to_string());

        let index_args = parse_index_args(args);
        let horizon = index_args
            .get_retention_horizon()
            .expect("Should parse successfully");

        assert_eq!(
            horizon
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
            "2024-01-01 00:00:00"
        );
    }

    #[rstest]
    #[case::days("7", "7")]
    #[case::default("none", "30")]
    fn test_retention_horizon_days_parsing(
        #[case] horizon_input: &str,
        #[case] expected_days: &str,
    ) {
        let mut args = create_basic_index_args();

        if horizon_input != "none" {
            args.push("--retention-horizon".to_string());
            args.push(horizon_input.to_string());
        }

        let index_args = parse_index_args(args);
        let horizon = index_args
            .get_retention_horizon()
            .expect("Should calculate successfully");

        let now = Utc::now().naive_utc();
        let expected_days: u32 = expected_days.parse().unwrap();
        let expected = now - chrono::Duration::days(expected_days as i64);
        let diff = (horizon - expected).num_seconds().abs();
        assert!(diff < 5, "Expected horizon within 5 seconds of calculated value");
    }

    #[test]
    fn test_retention_horizon_validation() {
        let mut args = create_basic_index_args();
        args.push("--retention-horizon".to_string());
        args.push("0".to_string());

        let index_args = parse_index_args(args);

        let result = index_args.get_retention_horizon();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Retention horizon days must be greater than 0"));
    }
}
