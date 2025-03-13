use std::{collections::HashMap, path::PathBuf};

use figment::{
    providers::{Format, Yaml},
    Figment,
};
use postgres::{Client, Error, NoTls};
use tokio::runtime::Runtime;
use tracing::{debug, info};
use tycho_core::dto::{Chain, ProtocolComponent};

use crate::{
    config::{IntegrationTest, IntegrationTestsConfig},
    tycho_rpc::TychoClient,
    tycho_runner::TychoRunner,
    utils::build_spkg,
};

pub struct TestRunner {
    package: String,
    tycho_logs: bool,
    db_url: String,
    vm_traces: bool,

    substreams_path: PathBuf,
}

impl TestRunner {
    pub fn new(package: String, tycho_logs: bool, db_url: String, vm_traces: bool) -> Self {
        let substreams_path = PathBuf::from("../substreams").join(&package);
        Self { package, tycho_logs, db_url, vm_traces, substreams_path }
    }

    pub fn run_tests(&self) {
        info!("Running tests...");
        let config_yaml_path = self
            .substreams_path
            .join("integration_test.tycho.yaml");

        info!("Config YAML: {}", config_yaml_path.display());
        let figment = Figment::new().merge(Yaml::file(&config_yaml_path));

        match figment.extract::<IntegrationTestsConfig>() {
            Ok(config) => {
                info!("Loaded test configuration:");
                info!("Protocol types: {:?}", config.protocol_type_names);
                info!("Found {} tests to run", config.tests.len());

                for test in &config.tests {
                    self.run_test(test, &config);
                }
            }
            Err(e) => {
                eprintln!("Failed to load test configuration: {}", e);
            }
        }
    }

    fn run_test(&self, test: &IntegrationTest, config: &IntegrationTestsConfig) {
        info!("Running test: {}", test.name);
        self.empty_database()
            .expect("Failed to empty the database");

        let substreams_yaml_path = self
            .substreams_path
            .join(&config.substreams_yaml_path);
        debug!("Building SPKG on {:?}", substreams_yaml_path);

        let mut initialized_accounts = config
            .initialized_accounts
            .clone()
            .unwrap_or_default();
        initialized_accounts.extend(
            test.initialized_accounts
                .clone()
                .unwrap_or_default(),
        );

        let spkg_path =
            build_spkg(&substreams_yaml_path, test.start_block).expect("Failed to build spkg");

        let tycho_runner =
            TychoRunner::new(self.db_url.clone(), initialized_accounts, self.tycho_logs);

        tycho_runner
            .run_tycho(
                spkg_path.as_str(),
                test.start_block,
                test.stop_block,
                &config.protocol_type_names,
            )
            .expect("Failed to run Tycho");

        tycho_runner.run_with_rpc_server(validate_state);
    }

    fn empty_database(&self) -> Result<(), Error> {
        debug!("Emptying the database");

        // Remove db name from URL. This is required because we cannot drop a database that we are
        // currently connected to.
        let base_url = match self.db_url.rfind('/') {
            Some(pos) => &self.db_url[..pos],
            None => self.db_url.as_str(),
        };
        let mut client = Client::connect(base_url, NoTls)?;

        client.execute("DROP DATABASE IF EXISTS \"tycho_indexer_0\" WITH (FORCE)", &[])?;
        client.execute("CREATE DATABASE \"tycho_indexer_0\"", &[])?;

        Ok(())
    }
}

fn validate_state() {
    let rt = Runtime::new().unwrap();

    // Create Tycho client for the RPC server
    let tycho_client =
        TychoClient::new("http://localhost:4242").expect("Failed to create Tycho client");

    let chain = Chain::Ethereum;
    let protocol_system = "test_protocol";

    let protocol_components = rt
        .block_on(tycho_client.get_protocol_components(protocol_system, chain))
        .expect("Failed to get protocol components");

    let protocol_states = rt
        .block_on(tycho_client.get_protocol_state(protocol_system, chain))
        .expect("Failed to get protocol state");

    // Create a map of component IDs to components for easy lookup
    let components_by_id: HashMap<String, ProtocolComponent> = protocol_components
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();

    info!("Found {} protocol components", components_by_id.len());
    info!("Found {} protocol states", protocol_states.len());

    // TODO: Implement complete validation logic similar to Python code
    info!("Validating state...");
}
