use std::{collections::HashMap, env, path::PathBuf, str::FromStr};

use alloy::primitives::U256;
use figment::{
    providers::{Format, Yaml},
    Figment,
};
use miette::{miette, IntoDiagnostic, WrapErr};
use postgres::{Client, Error, NoTls};
use tokio::runtime::Runtime;
use tracing::{debug, info};
use tycho_client::feed::BlockHeader;
use tycho_common::{
    dto::{Chain, ProtocolComponent, ResponseAccount, ResponseProtocolState},
    models::token::Token,
    Bytes,
};
use tycho_simulation::{
    evm::{
        decoder::TychoStreamDecoder,
        engine_db::tycho_db::PreCachedDB,
        protocol::{u256_num::bytes_to_u256, vm::state::EVMPoolState},
    },
    tycho_client::feed::{
        synchronizer::{ComponentWithState, Snapshot, StateSyncMessage},
        FeedMessage,
    },
};

use crate::{
    config::{IntegrationTest, IntegrationTestsConfig, ProtocolComponentWithTestConfig},
    rpc::RPCProvider,
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

    pub fn run_tests(&self) -> miette::Result<()> {
        let config_yaml_path = self
            .substreams_path
            .join("integration_test.tycho.yaml");

        let config = Self::parse_config(&config_yaml_path)?;

        info!("Running {} tests ...\n", config.tests.len());
        info!("--------------------------------\n");

        let mut failed_tests: Vec<String> = Vec::new();
        let mut count = 1;

        for test in &config.tests {
            info!("TEST {}: {}", count, test.name);

            match self.run_test(test, &config, config.skip_balance_check) {
                Ok(_) => {
                    info!("\n✅ {} passed.\n", test.name);
                }
                Err(e) => {
                    failed_tests.push(test.name.clone());
                    info!("\n❗️ {} failed: {}\n", test.name, e);
                }
            }

            info!("--------------------------------\n");
            count += 1;
        }

        info!(
            "\nTests finished! \nRESULTS: {}/{} passed.\n",
            config.tests.len() - failed_tests.len(),
            config.tests.len()
        );
        if !failed_tests.is_empty() {
            info!("Failed tests:");
            for failed_test in &failed_tests {
                info!("- {}", failed_test);
            }
        }
        info!("\n");

        Ok(())
    }

    fn parse_config(config_yaml_path: &PathBuf) -> miette::Result<IntegrationTestsConfig> {
        info!("Config YAML: {}", config_yaml_path.display());
        let yaml = Yaml::file(&config_yaml_path);
        let figment = Figment::new().merge(yaml);
        let config = figment
            .extract::<IntegrationTestsConfig>()
            .into_diagnostic()
            .wrap_err("Failed to load test configuration:")?;
        Ok(config)
    }

    fn run_test(
        &self,
        test: &IntegrationTest,
        config: &IntegrationTestsConfig,
        skip_balance_check: bool,
    ) -> miette::Result<()> {
        self.empty_database()
            .into_diagnostic()
            .wrap_err("Failed to empty the database")?;

        let substreams_yaml_path = self
            .substreams_path
            .join(&config.substreams_yaml_path);

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
            build_spkg(&substreams_yaml_path, test.start_block).wrap_err("Failed to build spkg")?;

        let tycho_runner =
            TychoRunner::new(self.db_url.clone(), initialized_accounts, self.tycho_logs);

        tycho_runner
            .run_tycho(
                spkg_path.as_str(),
                test.start_block,
                test.stop_block,
                &config.protocol_type_names,
            )
            .wrap_err("Failed to run Tycho")?;

        let _ = tycho_runner.run_with_rpc_server(
            validate_state,
            &test.expected_components,
            test.start_block,
            test.stop_block,
            skip_balance_check,
        )?;

        Ok(())
    }

    fn empty_database(&self) -> Result<(), Error> {
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

fn validate_state(
    expected_components: &Vec<ProtocolComponentWithTestConfig>,
    start_block: u64,
    stop_block: u64,
    skip_balance_check: bool,
) -> miette::Result<()> {
    let rt = Runtime::new().unwrap();

    // Create Tycho client for the RPC server
    let tycho_client = TychoClient::new("http://localhost:4242")
        .into_diagnostic()
        .wrap_err("Failed to create Tycho client")?;

    let chain = Chain::Ethereum;
    let protocol_system = "test_protocol";

    // Fetch data from Tycho RPC. We use block_on to avoid using async functions on the testing
    // module, in order to simplify debugging
    let protocol_components = rt
        .block_on(tycho_client.get_protocol_components(protocol_system, chain))
        .into_diagnostic()
        .wrap_err("Failed to get protocol components")?;

    let expected_ids = expected_components
        .iter()
        .map(|c| c.base.id.clone())
        .collect::<Vec<String>>();

    let protocol_states = rt
        .block_on(tycho_client.get_protocol_state(protocol_system, expected_ids, chain))
        .into_diagnostic()
        .wrap_err("Failed to get protocol state")?;

    let vm_storages = rt
        .block_on(tycho_client.get_contract_state(protocol_system, chain))
        .into_diagnostic()
        .wrap_err("Failed to get contract state")?;

    // Create a map of component IDs to components for easy lookup
    let components_by_id: HashMap<String, ProtocolComponent> = protocol_components
        .clone()
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();

    let protocol_states_by_id: HashMap<String, ResponseProtocolState> = protocol_states
        .into_iter()
        .map(|s| (s.component_id.clone(), s))
        .collect();

    info!("Found {} protocol components", components_by_id.len());
    info!("Found {} protocol states", protocol_states_by_id.len());

    info!("Validating state...");

    // Step 1: Validate that all expected components are present on Tycho after indexing
    debug!("Validating {:?} expected components", expected_components.len());
    for expected_component in expected_components {
        let component_id = expected_component.base.id.clone();

        assert!(
            components_by_id.contains_key(&component_id),
            "Component {:?} was not found on Tycho",
            component_id
        );

        let component = components_by_id
            .get(&component_id)
            .expect("Failed to get component from Tycho");

        let diff = expected_component
            .base
            .compare(component, true);
        match diff {
            Some(diff) => {
                return Err(miette!(
                    "Component {} does not match the expected state:\n{}",
                    component_id,
                    diff
                ));
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
    let rpc_url = env::var("RPC_URL")
        .into_diagnostic()
        .wrap_err("Missing ETH_RPC_URL in environment")?;
    let rpc_provider = RPCProvider::new(rpc_url.to_string());

    for (id, component) in components_by_id.iter() {
        let component_state = protocol_states_by_id.get(id);

        for token in &component.tokens {
            let mut balance: U256 = U256::from(0);

            if let Some(state) = component_state {
                let bal = state.balances.get(token);
                if let Some(bal) = bal {
                    let bal = bal.clone().into();
                    balance = bytes_to_u256(bal);
                }
            }

            // TODO: Test if balance check works
            if !skip_balance_check {
                info!(
                    "Validating token balance for component {} and token {}",
                    component.id, token
                );
                let token_address = alloy::primitives::Address::from_slice(&token[..20]);
                let component_address = alloy::primitives::Address::from_str(component.id.as_str())
                    .expect("Failed to parse component address");
                let node_balance = rt.block_on(rpc_provider.get_token_balance(
                    token_address,
                    component_address,
                    start_block,
                ));
                assert_eq!(
                    balance, node_balance,
                    "Token balance mismatch for component {} and token {}",
                    component.id, token
                );
                info!(
                    "Token balance for component {} and token {} matches the expected value",
                    component.id, token
                );
            }
        }
    }
    match skip_balance_check {
        true => info!("Skipping balance check"),
        false => info!("All token balances match the values found onchain"),
    }

    // Step 3: Run Tycho Simulation
    let mut decoder = TychoStreamDecoder::new();
    decoder.register_decoder::<EVMPoolState<PreCachedDB>>("test_protocol");

    // Mock a stream message, with only a Snapshot and no deltas
    let mut states: HashMap<String, ComponentWithState> = HashMap::new();
    for (id, component) in components_by_id {
        let component_id = &id.clone();
        let state = protocol_states_by_id
            .get(component_id)
            .wrap_err("Failed to get state for component")?
            .clone();
        let component_with_state =
            ComponentWithState { state, component, component_tvl: None, entrypoints: vec![] }; // TODO
        states.insert(component_id.clone(), component_with_state);
    }
    let vm_storage: HashMap<Bytes, ResponseAccount> = vm_storages
        .into_iter()
        .map(|x| (x.address.clone(), x))
        .collect();
    let snapshot = Snapshot { states, vm_storage };

    let bytes = [0u8; 32];

    let state_msgs: HashMap<String, StateSyncMessage<BlockHeader>> = HashMap::from([(
        String::from("test_protocol"),
        StateSyncMessage {
            header: BlockHeader {
                hash: Bytes::from(bytes),
                number: stop_block,
                parent_hash: Bytes::from(bytes),
                revert: false,
                timestamp: 0, // TODO
            },
            snapshots: snapshot,
            deltas: None,
            removed_components: HashMap::new(),
        },
    )]);

    let all_tokens = rt
        .block_on(tycho_client.get_tokens(Chain::Ethereum, None, None))
        .into_diagnostic()
        .wrap_err("Failed to get tokens")?;
    info!("Loaded {} tokens", all_tokens.len());

    rt.block_on(decoder.set_tokens(all_tokens));

    let mut pairs: HashMap<String, Vec<Token>> = HashMap::new();

    let message: FeedMessage = FeedMessage { state_msgs, sync_states: Default::default() };

    let block_msg = rt
        .block_on(decoder.decode(message))
        .into_diagnostic()
        .wrap_err("Failed to decode message")?;

    for (id, comp) in block_msg.new_pairs.iter() {
        pairs
            .entry(id.clone())
            .or_insert_with(|| comp.tokens.clone());
    }

    // This is where we get blocked. Currently, Tycho Simulation expects the runtime to be
    // prebuild and accessible from TychoSim - we should allow passing it when parsing the block

    // TODO: Since we don't have balances on the VM State, we could try to use Limits, otherwise ask
    //  the user to specify a set of values on the YAML file.
    for (id, state) in block_msg.states.iter() {
        if let Some(tokens) = pairs.get(id) {
            let formatted_token_str = format!("{:}/{:}", &tokens[0].symbol, &tokens[1].symbol);
            info!("Amount out for {}: calculating for tokens {:?}", id, formatted_token_str);
            state
                .spot_price(&tokens[0], &tokens[1])
                .map(|price| info!("Spot price {:?}: {:?}", formatted_token_str, price))
                .map_err(|e| info!("Error calculating spot price for Pool {:?}: {:?}", id, e))
                .ok();
            // let amount_in =
            //     BigUint::from(1u32) * BigUint::from(10u32).pow(tokens[0].decimals as u32);
            // state
            //     .get_amount_out(amount_in, &tokens[0], &tokens[1])
            //     .map(|result| {
            //         println!(
            //             "Amount out for trading 1 {:?} -> {:?}: {:?} (takes {:?} gas)",
            //             &tokens[0].symbol, &tokens[1].symbol, result.amount, result.gas
            //         )
            //     })
            //     .map_err(|e| eprintln!("Error calculating amount out for Pool {:?}: {:?}", id,
            // e))     .ok();
        }
    }

    info!("\n✅ Simulation validation passed.\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use glob::glob;

    use super::*;

    #[test]
    fn test_parse_all_configs() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let curr_dir = PathBuf::from(manifest_dir);
        let parent_dir = curr_dir.parent().unwrap();
        env::set_current_dir(parent_dir).expect("Failed to set working directory");

        let pattern = "./substreams/*/integration_test.tycho.yaml";
        let mut results = Vec::new();

        if glob(pattern).unwrap().count() == 0 {
            panic!("No integration_test.tycho.yaml files found in substreams/*/");
        }
        for entry in glob(pattern).unwrap() {
            match entry {
                Ok(path) => {
                    if !path.is_file() {
                        results.push(Err(format!("Path is not a file: {}", path.display())));
                    } else {
                        let result = TestRunner::parse_config(&path);
                        if let Err(e) = &result {
                            results.push(Err(format!(
                                "Failed to parse config at {}: {e:?}",
                                path.display(),
                            )));
                        } else {
                            results.push(Ok(()));
                        }
                    }
                }
                Err(e) => results.push(Err(format!("Glob error: {e:?}"))),
            }
        }

        let errors: Vec<_> = results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .collect();
        if !errors.is_empty() {
            for error in errors {
                println!("{error}");
            }
            panic!("One or more config files failed to parse.");
        }
    }
}
