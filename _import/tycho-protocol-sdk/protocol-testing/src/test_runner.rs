use std::{collections::HashMap, env, path::PathBuf, str::FromStr};

use alloy::primitives::U256;
use figment::{
    providers::{Format, Yaml},
    Figment,
};
use miette::{miette, IntoDiagnostic, WrapErr};
use num_bigint::BigUint;
use num_traits::Zero;
use postgres::{Client, Error, NoTls};
use tokio::runtime::Runtime;
use tracing::{debug, error, info};
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
    protocol::models::DecoderContext,
    tycho_client::feed::{
        synchronizer::{ComponentWithState, Snapshot, StateSyncMessage},
        FeedMessage,
    },
};

use crate::{
    adapter_builder::AdapterContractBuilder,
    config::{IntegrationTest, IntegrationTestsConfig, ProtocolComponentWithTestConfig},
    rpc::RPCProvider,
    tycho_rpc::TychoClient,
    tycho_runner::TychoRunner,
    utils::build_spkg,
};

pub struct TestRunner {
    tycho_logs: bool,
    db_url: String,
    vm_traces: bool,
    substreams_path: PathBuf,
    adapter_contract_builder: AdapterContractBuilder,
    match_test: Option<String>,
}

impl TestRunner {
    pub fn new(
        substreams_path: PathBuf,
        match_test: Option<String>,
        tycho_logs: bool,
        db_url: String,
        vm_traces: bool,
    ) -> Self {
        let repo_root = env::current_dir().expect("Failed to get current directory");
        let evm_path = repo_root.join("../evm");
        let adapter_contract_builder =
            AdapterContractBuilder::new(evm_path.to_string_lossy().to_string());
        Self {
            tycho_logs,
            db_url,
            vm_traces,
            substreams_path,
            adapter_contract_builder,
            match_test,
        }
    }

    pub fn run_tests(&self) -> miette::Result<()> {
        let terminal_width = termsize::get()
            .map(|size| size.cols as usize - 35) // Remove length of log prefix (35)
            .unwrap_or(80);
        info!("{}\n", "-".repeat(terminal_width));

        let config_yaml_path = self
            .substreams_path
            .join("integration_test.tycho.yaml");

        let config = Self::parse_config(&config_yaml_path)?;

        let tests = match &self.match_test {
            Some(filter) => config
                .tests
                .iter()
                .filter(|test| test.name.contains(filter))
                .collect::<Vec<&IntegrationTest>>(),
            None => config
                .tests
                .iter()
                .collect::<Vec<&IntegrationTest>>(),
        };
        let tests_count = tests.len();

        info!("Running {} tests ...\n", tests_count);

        let mut failed_tests: Vec<String> = Vec::new();
        let mut count = 1;

        for test in &tests {
            info!("TEST {}: {}", count, test.name);

            match self.run_test(test, &config, config.skip_balance_check) {
                Ok(_) => {
                    info!("✅ {} passed\n", test.name);
                }
                Err(e) => {
                    failed_tests.push(test.name.clone());
                    error!("❗️{} failed: {}\n", test.name, e);
                }
            }

            info!("{}\n", "-".repeat(terminal_width));
            count += 1;
        }

        info!("Tests finished!");
        info!("Passed {}/{}\n", tests_count - failed_tests.len(), tests_count);
        if !failed_tests.is_empty() {
            error!("Failed: {}", failed_tests.join(", "));
        }

        Ok(())
    }

    fn parse_config(config_yaml_path: &PathBuf) -> miette::Result<IntegrationTestsConfig> {
        info!("Config YAML: {}", config_yaml_path.display());
        let yaml = Yaml::file(config_yaml_path);
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
            |expected_components, start_block, stop_block, skip_balance_check| {
                validate_state(
                    expected_components,
                    start_block,
                    stop_block,
                    skip_balance_check,
                    config,
                    &self.adapter_contract_builder,
                )
            },
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
    config: &IntegrationTestsConfig,
    adapter_contract_builder: &AdapterContractBuilder,
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

        let component = components_by_id
            .get(&component_id)
            .ok_or_else(|| miette!("Component {:?} was not found on Tycho", component_id))?;

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
    match skip_balance_check {
        true => info!("Skipping balance check"),
        false => {
            validate_token_balances(&components_by_id, &protocol_states_by_id, start_block, &rt)?;
            info!("All token balances match the values found onchain")
        }
    }

    // Step 3: Run Tycho Simulation

    // Build/find the adapter contract
    let adapter_contract_path =
        match adapter_contract_builder.find_contract(&config.adapter_contract) {
            Ok(path) => {
                info!("Found adapter contract at: {}", path.display());
                path
            }
            Err(_) => {
                info!("Adapter contract not found, building it...");
                adapter_contract_builder
                    .build_target(
                        &config.adapter_contract,
                        config
                            .adapter_build_signature
                            .as_deref(),
                        config.adapter_build_args.as_deref(),
                    )
                    .wrap_err("Failed to build adapter contract")?
            }
        };

    info!("Using adapter contract: {}", adapter_contract_path.display());
    let adapter_contract_path_str: &str = adapter_contract_path.to_str().unwrap();

    let mut decoder = TychoStreamDecoder::new();
    let decoder_context = DecoderContext::new().vm_adapter_path(adapter_contract_path_str);
    decoder.register_decoder_with_context::<EVMPoolState<PreCachedDB>>(
        "test_protocol",
        decoder_context,
    );

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

            // Test get_amount_out with different percentages of limits. The reserves or limits are
            // relevant because we need to know how much to test with. We don’t know if a pool is
            // going to revert with 10 or 10 million USDC, for example, so by using the limits we
            // can use “safe values” where the sim shouldn’t break.
            let percentages = [0.001, 0.01, 0.1];
            for percentage in &percentages {
                // Get limits for this token pair
                let limits = state
                    .get_limits(tokens[0].address.clone(), tokens[1].address.clone())
                    .map_err(|e| info!("Error getting limits for Pool {:?}: {:?}", id, e))
                    .ok();

                if let Some((max_input, _max_output)) = limits {
                    // Calculate test amount as percentage of max input
                    let percentage_biguint = BigUint::from((percentage * 1000.0) as u32);
                    let thousand = BigUint::from(1000u32);
                    let amount_in = (&max_input * &percentage_biguint) / &thousand;

                    // Skip if amount is zero
                    if amount_in.is_zero() {
                        continue;
                    }

                    state
                        .get_amount_out(amount_in.clone(), &tokens[0], &tokens[1])
                        .map(|result| {
                            info!(
                                "Amount out for trading {:.1}% of max ({} -> {}): {} {} (gas: {})",
                                percentage * 100.0,
                                &tokens[0].symbol,
                                &tokens[1].symbol,
                                result.amount,
                                &tokens[1].symbol,
                                result.gas
                            )
                        })
                        .map_err(|e| {
                            info!(
                                "Error calculating amount out for Pool {:?} at {:.1}%: {:?}",
                                id,
                                percentage * 100.0,
                                e
                            )
                        })
                        .ok();
                }
            }
        }
    }

    info!("✅ Simulation validation passed");
    Ok(())
}

/// Validate that the token balances of the components match the values
/// on-chain, extracted by querying the token balances using a node.
fn validate_token_balances(
    components_by_id: &HashMap<String, ProtocolComponent>,
    protocol_states_by_id: &HashMap<String, ResponseProtocolState>,
    start_block: u64,
    rt: &Runtime,
) -> miette::Result<()> {
    let rpc_url = env::var("RPC_URL")
        .into_diagnostic()
        .wrap_err("Missing RPC_URL in environment")?;
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

            info!("Validating token balance for component {} and token {}", component.id, token);
            let token_address = alloy::primitives::Address::from_slice(&token[..20]);
            let component_address = alloy::primitives::Address::from_str(component.id.as_str())
                .expect("Failed to parse component address");
            let node_balance = rt.block_on(rpc_provider.get_token_balance(
                token_address,
                component_address,
                start_block,
            ))?;
            if balance != node_balance {
                return Err(miette!(
                    "Token balance mismatch for component {} and token {}",
                    component.id,
                    token
                ));
            }
            info!(
                "Token balance for component {} and token {} matches the expected value",
                component.id, token
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use dotenv::dotenv;
    use glob::glob;
    use tycho_common::{
        dto::{ProtocolComponent, ResponseProtocolState},
        Bytes,
    };

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

    #[test]
    fn test_token_balance_validation() {
        // Setup mock data
        let block_number = 21998530;
        let token_bytes = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let component_id = "0x787B8840100d9BaAdD7463f4a73b5BA73B00C6cA".to_string();

        let component = ProtocolComponent {
            id: component_id.clone(),
            tokens: vec![token_bytes.clone()],
            ..Default::default()
        };

        let mut balances = HashMap::new();
        let balance_bytes = Bytes::from(
            U256::from_str("1070041574684539264153")
                .unwrap()
                .to_be_bytes::<32>(),
        );
        balances.insert(token_bytes.clone(), balance_bytes.clone());
        let protocol_state = ResponseProtocolState {
            component_id: component_id.clone(),
            balances,
            ..Default::default()
        };

        let mut components_by_id = HashMap::new();
        components_by_id.insert(component_id.clone(), component.clone());
        let mut protocol_states_by_id = HashMap::new();
        protocol_states_by_id.insert(component_id.clone(), protocol_state.clone());

        let rt = Runtime::new().unwrap();
        dotenv().ok();
        let result =
            validate_token_balances(&components_by_id, &protocol_states_by_id, block_number, &rt);
        assert!(result.is_ok(), "Should pass when balance check is performed and balances match");
    }

    #[test]
    fn test_token_balance_validation_fails_on_mismatch() {
        // Setup mock data
        let block_number = 21998530;
        let token_bytes = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let component_id = "0x787B8840100d9BaAdD7463f4a73b5BA73B00C6cA".to_string();

        let component = ProtocolComponent {
            id: component_id.clone(),
            tokens: vec![token_bytes.clone()],
            ..Default::default()
        };

        // Set expected balance to zero
        let mut balances = HashMap::new();
        let balance_bytes = Bytes::from(U256::from(0).to_be_bytes::<32>());
        balances.insert(token_bytes.clone(), balance_bytes.clone());
        let protocol_state = ResponseProtocolState {
            component_id: component_id.clone(),
            balances,
            ..Default::default()
        };

        let mut components_by_id = HashMap::new();
        components_by_id.insert(component_id.clone(), component.clone());
        let mut protocol_states_by_id = HashMap::new();
        protocol_states_by_id.insert(component_id.clone(), protocol_state.clone());

        let rt = Runtime::new().unwrap();
        dotenv().ok();
        let result =
            validate_token_balances(&components_by_id, &protocol_states_by_id, block_number, &rt);
        assert!(
            result.is_err(),
            "Should fail when balance check is performed and balances do not match"
        );
    }
}
