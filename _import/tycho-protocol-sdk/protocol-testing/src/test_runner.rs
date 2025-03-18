use std::{collections::HashMap, env, ops::Deref, path::PathBuf};

use alloy::{
    primitives::{bytes, U256},
    providers::Provider,
};
use figment::{
    providers::{Format, Yaml},
    Figment,
};
use postgres::{Client, Error, NoTls};
use tokio::runtime::Runtime;
use tracing::{debug, field::debug, info};
use tycho_core::{
    dto::{Chain, ProtocolComponent, ResponseProtocolState},
    Bytes,
};
use tycho_core::models::Address;
use tycho_simulation::evm::protocol::u256_num::{bytes_to_u256, u256_to_f64};

use crate::{
    config::{IntegrationTest, IntegrationTestsConfig, ProtocolComponentWithTestConfig},
    tycho_rpc::TychoClient,
    tycho_runner::TychoRunner,
    utils::build_spkg,
};
use crate::rpc::RPCProvider;

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

    fn run_test(&self, test: &IntegrationTest, config: &IntegrationTestsConfig, skip_balance_check: bool) {
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

        tycho_runner.run_with_rpc_server(validate_state, &test.expected_components, test.start_block, skip_balance_check);
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

fn validate_state(expected_components: &Vec<ProtocolComponentWithTestConfig>, start_block: u64, skip_balance_check: bool) {
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
        .map(|c| (c.id.to_lowercase(), c))
        .collect();

    let protocol_states_by_id: HashMap<String, ResponseProtocolState> = protocol_states
        .into_iter()
        .map(|s| (s.component_id.to_lowercase(), s))
        .collect();

    info!("Found {} protocol components", components_by_id.len());
    info!("Found {} protocol states", protocol_states_by_id.len());

    info!("Validating state...");

    // Step 1: Validate that all expected components are present on Tycho after indexing
    debug!("Validating {:?} expected components", expected_components.len());
    for expected_component in expected_components {
        let component_id = expected_component
            .base
            .id
            .to_lowercase();

        assert!(
            components_by_id.contains_key(&component_id),
            "Component {:?} was not found on Tycho",
            component_id
        );

        let component = components_by_id
            .get(&component_id)
            .unwrap();

        let diff = expected_component
            .base
            .compare(&component, true);
        match diff {
            Some(diff) => {
                panic!("Component {} does not match the expected state:\n{}", component_id, diff);
            }
            None => {
                info!("Component {} matches the expected state", component_id);
            }
        }
    }
    info!("All expected components were successfully found on Tycho and match the expected state");

    // Step 2: Validate Token Balances
    // In this step, we validate that the token balances of the components match the values
    // on-chain, extracted by querying the token balances using a node.
    let rpc_url = env::var("RPC_URL").expect("Missing ETH_RPC_URL in environment");
    let rpc_provider = RPCProvider::new(rpc_url.to_string());

    for (id_lower, component) in components_by_id.iter() {
        let component_state = protocol_states_by_id.get(id_lower);

        for token in &component.tokens {
            let mut balance: U256 = U256::from(0);

            if let Some(state) = component_state {
                let bal = state.balances.get(token);
                if let Some(bal) = bal {
                    let bal = bal.clone().into();
                    balance = bytes_to_u256(bal);
                }
            }

            if (!skip_balance_check) {
                let token_address: Address
                let node_balance = rpc_provider.get_token_balance(token, component.id, start_block)
            }
        }
    }
}
