use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    str::FromStr,
    sync::LazyLock,
};

use alloy::{
    primitives::{Address, U256},
    rpc::types::Block,
};
use figment::{
    providers::{Format, Yaml},
    Figment,
};
use itertools::Itertools;
use miette::{miette, IntoDiagnostic, WrapErr};
use num_bigint::{BigInt, BigUint};
use num_rational::BigRational;
use num_traits::{Signed, ToPrimitive, Zero};
use postgres::{Client, Error, NoTls};
use regex::Regex;
use tokio::runtime::Runtime;
use tracing::{debug, error, info, warn};
use tycho_execution::encoding::evm::utils::bytes_to_address;
use tycho_simulation::{
    evm::{decoder::TychoStreamDecoder, protocol::u256_num::bytes_to_u256},
    protocol::models::{DecoderContext, Update},
    tycho_client::feed::{
        synchronizer::{ComponentWithState, Snapshot, StateSyncMessage},
        BlockHeader, FeedMessage,
    },
    tycho_common::{
        dto::{
            Chain, EntryPointWithTracingParams, ProtocolComponent, ResponseAccount,
            ResponseProtocolState, TracingResult,
        },
        models::token::Token,
        Bytes,
    },
};

use crate::{
    adapter_builder::AdapterContractBuilder,
    config::{IntegrationTest, IntegrationTestsConfig, ProtocolComponentWithTestConfig},
    encoding::encode_swap,
    execution,
    rpc::RPCProvider,
    state_registry::register_decoder_for_protocol,
    tycho_rpc::TychoClient,
    tycho_runner::TychoRunner,
    utils::build_spkg,
};

static CLONE_TO_BASE_PROTOCOL: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        ("ethereum-sushiswap-v2", "ethereum-uniswap-v2"),
        ("ethereum-pancakeswap-v2", "ethereum-uniswap-v2"),
    ])
});

pub enum TestType {
    Full(TestTypeFull),
    Range(TestTypeRange),
}

pub struct TestTypeFull {
    pub initial_block: Option<u64>,
    pub stop_block: Option<u64>,
}

pub struct TestTypeRange {
    pub match_test: Option<String>,
}

pub struct TestRunner {
    test_type: TestType,
    db_url: String,
    substreams_path: PathBuf,
    config_file_path: PathBuf,
    vm_simulation_traces: bool,
    adapter_contract_builder: AdapterContractBuilder,
    runtime: Runtime,
    rpc_provider: RPCProvider,
}

impl TestRunner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        test_type: TestType,
        root_path: PathBuf,
        protocol: String,
        db_url: String,
        rpc_url: String,
        vm_simulation_traces: bool,
        execution_traces: bool,
    ) -> miette::Result<Self> {
        let base_protocol = CLONE_TO_BASE_PROTOCOL
            .get(protocol.as_str())
            .unwrap_or(&protocol.as_str())
            .to_string();
        let substreams_path = root_path
            .join("substreams")
            .join(&base_protocol);
        let evm_path = root_path.join("evm");
        let adapter_contract_builder =
            AdapterContractBuilder::new(evm_path.to_string_lossy().to_string());

        // Calculate config file path based on protocol. If the protocol is a clone of another
        // protocol, we assume this protocol name will be appended to the integration test filename.
        let config_file_name = if protocol != base_protocol {
            format!(
                "integration_test_{}.tycho.yaml",
                protocol
                    .replace("ethereum-", "")
                    .replace('-', "_")
            )
        } else {
            "integration_test.tycho.yaml".to_string()
        };
        let config_file_path = substreams_path.join(&config_file_name);

        let rpc_provider = RPCProvider::new(rpc_url, execution_traces);
        let runtime = Runtime::new().into_diagnostic()?;

        Ok(Self {
            test_type,
            db_url,
            substreams_path,
            config_file_path,
            vm_simulation_traces,
            adapter_contract_builder,
            runtime,
            rpc_provider,
        })
    }

    pub fn run(&self) -> miette::Result<()> {
        let terminal_width = termsize::get()
            .map(|size| size.cols as usize - 35) // Remove length of log prefix (35)
            .unwrap_or(80);
        info!("{}\n", "-".repeat(terminal_width));

        // Skip if test files don't exist
        if !self.config_file_path.exists() {
            warn!("Config file not found at {}.", self.config_file_path.display());
            return Ok(());
        }

        let config = match Self::parse_config(&self.config_file_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("Failed to parse config: {:?}", e);
                return Ok(());
            }
        };

        let substreams_yaml_path = self
            .substreams_path
            .join(&config.substreams_yaml_path);
        if !substreams_yaml_path.exists() {
            warn!("substreams.yaml file not found at {}", substreams_yaml_path.display());
            return Ok(());
        }

        match &self.test_type {
            TestType::Full(test_type) => {
                self.run_full_test(config, &substreams_yaml_path, test_type)?;
            }
            TestType::Range(test_type) => {
                self.run_tests_in_range(config, &substreams_yaml_path, test_type, terminal_width)?;
            }
        }

        Ok(())
    }

    fn parse_config(config_yaml_path: &PathBuf) -> miette::Result<IntegrationTestsConfig> {
        info!("Parsing config YAML at {}", config_yaml_path.display());
        let yaml = Yaml::file(config_yaml_path);
        let figment = Figment::new().merge(yaml);
        let config = figment
            .extract::<IntegrationTestsConfig>()
            .into_diagnostic()
            .wrap_err("Failed to load test configuration:")?;
        Ok(config)
    }

    fn run_full_test(
        &self,
        config: IntegrationTestsConfig,
        substreams_yaml_path: &PathBuf,
        test_type: &TestTypeFull,
    ) -> miette::Result<()> {
        let start_block = match &test_type.initial_block {
            Some(b) => *b,
            None => {
                let content = std::fs::read_to_string(substreams_yaml_path).into_diagnostic()?;
                let re = Regex::new(r"initialBlock:\s*(\d+)").unwrap();
                re.captures(&content)
                    .and_then(|cap| cap.get(1))
                    .and_then(|m| m.as_str().parse::<u64>().ok())
                    .ok_or_else(|| {
                        miette!("Failed to extract initialBlock from substreams.yaml. Please specify it explicitly.")
                    })?
            }
        };
        let spkg_path =
            build_spkg(substreams_yaml_path, start_block).wrap_err("Failed to build spkg")?;
        let initialized_accounts = config
            .initialized_accounts
            .clone()
            .unwrap_or_default();
        let tycho_runner = self.tycho_runner(initialized_accounts.clone())?;
        let stop_block = match &test_type.stop_block {
            Some(b) => *b,
            None => {
                let rpc_server = tycho_runner.start_rpc_server()?;
                let block = self
                    .runtime
                    .block_on(self.rpc_provider.get_current_block())
                    .wrap_err("Failed to get current block number");
                tycho_runner.stop_rpc_server(rpc_server)?;
                match block {
                    Ok(b) => b.header.number,
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
        };
        tycho_runner
            .run_tycho(
                &spkg_path,
                start_block,
                stop_block,
                &config.protocol_type_names,
                &config.protocol_system,
                config.module_name.clone(),
            )
            .wrap_err("Failed to run Tycho")?;
        let test = IntegrationTest {
            name: "full_run".to_string(),
            start_block,
            stop_block,
            expected_components: vec![],
            initialized_accounts: Some(initialized_accounts),
        };
        let rpc_server = tycho_runner.start_rpc_server()?;
        let res = match self.run_test(&test, &config, stop_block) {
            Ok(_) => {
                info!("✅ {} passed\n", test.name);
                Ok(())
            }
            Err(e) => {
                error!("❗️{} failed: {:?}\n", test.name, e);
                Err(e)
            }
        };
        tycho_runner.stop_rpc_server(rpc_server)?;
        res
    }

    fn run_tests_in_range(
        &self,
        config: IntegrationTestsConfig,
        substreams_yaml_path: &PathBuf,
        test_type: &TestTypeRange,
        terminal_width: usize,
    ) -> miette::Result<()> {
        let tests = match &test_type.match_test {
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
            let mut initialized_accounts = config
                .initialized_accounts
                .clone()
                .unwrap_or_default();
            initialized_accounts.extend(
                test.initialized_accounts
                    .clone()
                    .unwrap_or_default(),
            );
            let tycho_runner = self.tycho_runner(initialized_accounts)?;
            let spkg_path = build_spkg(substreams_yaml_path, test.start_block)
                .wrap_err("Failed to build spkg")?;
            tycho_runner
                .run_tycho(
                    &spkg_path,
                    test.start_block,
                    test.stop_block,
                    &config.protocol_type_names,
                    &config.protocol_system,
                    config.module_name.clone(),
                )
                .wrap_err("Failed to run Tycho")?;
            let rpc_server = tycho_runner.start_rpc_server()?;
            match self.run_test(test, &config, test.stop_block) {
                Ok(_) => {
                    info!("✅ {} passed\n", test.name);
                }
                Err(e) => {
                    failed_tests.push(test.name.clone());
                    error!("❗️{} failed: {e}\n", test.name);
                }
            }
            tycho_runner.stop_rpc_server(rpc_server)?;
            info!("{}\n", "-".repeat(terminal_width));
            count += 1;
        }

        info!("Tests finished!");
        info!("Passed {}/{}\n", tests_count - failed_tests.len(), tests_count);
        if !failed_tests.is_empty() {
            Err(miette!("Failed tests: {}", failed_tests.join(", ")))
        } else {
            Ok(())
        }
    }

    fn run_test(
        &self,
        test: &IntegrationTest,
        config: &IntegrationTestsConfig,
        stop_block: u64,
    ) -> miette::Result<()> {
        // Fetch protocol data from Tycho RPC
        let expected_ids = test
            .expected_components
            .iter()
            .map(|c| c.base.id.to_lowercase())
            .collect::<Vec<String>>();
        let (update, component_tokens, response_protocol_states_by_id, block) = self
            .fetch_from_tycho_rpc(
                &config.protocol_system,
                expected_ids,
                &config.adapter_contract,
                &config.adapter_build_signature,
                &config.adapter_build_args,
                self.vm_simulation_traces,
                stop_block,
            )?;
        if update.states.is_empty() {
            return Err(miette!("No protocol states were found on Tycho"));
        }

        // Step 1: Validate that all expected components are present on Tycho after indexing
        self.validate_state(&test.expected_components, &update)?;

        // Step 2: Validate Token Balances
        match config.skip_balance_check {
            true => info!("Skipping balance check"),
            false => {
                self.validate_token_balances(
                    &component_tokens,
                    &response_protocol_states_by_id,
                    stop_block,
                )?;
                info!("All token balances match the values found onchain")
            }
        }

        // Step 3: Run Tycho Simulation and Execution
        self.simulate_and_execute(&update, &component_tokens, &block, &test.expected_components)?;

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

    fn tycho_runner(&self, initialized_accounts: Vec<String>) -> miette::Result<TychoRunner> {
        self.empty_database()
            .into_diagnostic()
            .wrap_err("Failed to empty the database")?;
        Ok(TychoRunner::new(self.db_url.to_string(), initialized_accounts))
    }

    /// Fetches protocol data from the Tycho RPC server and prepares it for validation and
    /// simulation.
    ///
    /// This method connects to the running Tycho RPC server to retrieve protocol components,
    /// states, and contract storage. It then sets up the Tycho Decoder and creates an update
    /// message that can be used for validation and simulation testing.
    ///
    /// # Arguments
    /// * `protocol_system` - The protocol system identifier (e.g., "uniswap_v2", "balancer_v2")
    /// * `expected_component_ids` - List of component IDs to fetch from Tycho
    /// * `adapter_contract` - Optional adapter contract name for VM-based protocols
    /// * `adapter_build_signature` - Optional build signature for the adapter contract
    /// * `adapter_build_args` - Optional build arguments for the adapter contract
    /// * `vm_simulation_traces` - Whether to enable VM simulation traces
    /// * `stop_block` - The block number to fetch data for
    ///
    /// # Returns
    /// A tuple containing:
    /// - `Update` - Decoded protocol state update for simulation
    /// - `HashMap<String, Vec<Token>>` - Token mappings for each component
    /// - `HashMap<String, ResponseProtocolState>` - Protocol states by component ID
    /// - `Block` - The block header for the specified block
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    fn fetch_from_tycho_rpc(
        &self,
        protocol_system: &str,
        expected_component_ids: Vec<String>,
        adapter_contract: &Option<String>,
        adapter_build_signature: &Option<String>,
        adapter_build_args: &Option<String>,
        vm_simulation_traces: bool,
        stop_block: u64,
    ) -> miette::Result<(
        Update,
        HashMap<String, Vec<Token>>,
        HashMap<String, ResponseProtocolState>,
        Block,
    )> {
        info!("Fetching protocol data from Tycho with stop block {}...", stop_block);

        // Create Tycho client for the RPC server
        let tycho_client = TychoClient::new("http://localhost:4242")
            .into_diagnostic()
            .wrap_err("Failed to create Tycho client")?;

        let chain = Chain::Ethereum;

        // Fetch data from Tycho RPC. We use block_on to avoid using async functions on the testing
        // module, in order to simplify debugging
        let protocol_components = self
            .runtime
            .block_on(tycho_client.get_protocol_components(protocol_system, chain))
            .into_diagnostic()
            .wrap_err("Failed to get protocol components")?;

        // If no expected component IDs are provided, use all components from the protocol
        let expected_component_ids = if expected_component_ids.is_empty() {
            protocol_components
                .iter()
                .map(|c| c.id.to_lowercase())
                .collect::<Vec<String>>()
        } else {
            expected_component_ids
        };

        let protocol_states = self
            .runtime
            .block_on(tycho_client.get_protocol_state(
                protocol_system,
                expected_component_ids.clone(),
                chain,
            ))
            .into_diagnostic()
            .wrap_err("Failed to get protocol state")?;

        let vm_storages = self
            .runtime
            .block_on(tycho_client.get_contract_state(protocol_system, chain))
            .into_diagnostic()
            .wrap_err("Failed to get contract state")?;

        let traced_entry_points = self
            .runtime
            .block_on(tycho_client.get_traced_entry_points(
                protocol_system,
                expected_component_ids.clone(),
                chain,
            ))
            .into_diagnostic()
            .wrap_err("Failed to get trace points")?;

        // Create a map of component IDs to components for easy lookup
        let mut components_by_id: HashMap<String, ProtocolComponent> = protocol_components
            .clone()
            .into_iter()
            .map(|c| (c.id.to_lowercase(), c))
            .collect();
        if !expected_component_ids.is_empty() {
            components_by_id.retain(|id, _| expected_component_ids.contains(id))
        };

        let protocol_states_by_id: HashMap<String, ResponseProtocolState> = protocol_states
            .into_iter()
            .map(|s| (s.component_id.to_lowercase(), s))
            .collect();

        debug!("Found {} protocol components", components_by_id.len());
        debug!("Found {} protocol states", protocol_states_by_id.len());
        debug!("Found {} traced entry points", traced_entry_points.len());

        let adapter_contract_path;
        let mut adapter_contract_path_str: Option<&str> = None;

        // Adapter contract will only be configured for VM protocols, not natively implemented
        // protocols.
        if let Some(adapter_contract_name) = &adapter_contract {
            // Build/find the adapter contract
            adapter_contract_path = match self
                .adapter_contract_builder
                .find_contract(adapter_contract_name)
            {
                Ok(path) => {
                    debug!("Found adapter contract at: {}", path.display());
                    path
                }
                Err(_) => {
                    info!("Adapter contract not found, building it...");
                    self.adapter_contract_builder
                        .build_target(
                            adapter_contract_name,
                            adapter_build_signature.as_deref(),
                            adapter_build_args.as_deref(),
                        )
                        .wrap_err("Failed to build adapter contract")?
                }
            };

            debug!("Using adapter contract: {}", adapter_contract_path.display());
            adapter_contract_path_str = Some(adapter_contract_path.to_str().unwrap());
        }

        // Clear the shared database state to ensure test isolation
        // This prevents state from previous tests from affecting the current test
        tycho_simulation::evm::engine_db::SHARED_TYCHO_DB.clear();

        let mut decoder = TychoStreamDecoder::new();
        decoder.skip_state_decode_failures(true);
        let mut decoder_context = DecoderContext::new().vm_traces(vm_simulation_traces);

        if let Some(vm_adapter_path) = adapter_contract_path_str {
            decoder_context = decoder_context.vm_adapter_path(vm_adapter_path);
        }
        register_decoder_for_protocol(&mut decoder, protocol_system, decoder_context)?;

        // Mock a stream message, with only a Snapshot and no deltas
        let mut states: HashMap<String, ComponentWithState> = HashMap::new();
        for (id, component) in &components_by_id {
            let component_id = id;

            let state = protocol_states_by_id
                .get(component_id)
                .wrap_err(format!("No state found for component: {id}"))?
                .clone();

            let traced_entry_points: Vec<(EntryPointWithTracingParams, TracingResult)> =
                traced_entry_points
                    .get(component_id)
                    .map(|inner| {
                        inner
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

            let component_with_state = ComponentWithState {
                state,
                component: component.clone(),
                component_tvl: None,
                // Neither UniswapV4 with hooks not certain balancer pools are currently supported
                // for SDK testing
                entrypoints: traced_entry_points,
            };
            states.insert(component_id.clone(), component_with_state);
        }

        // Convert vm_storages to a HashMap
        let vm_storage: HashMap<Bytes, ResponseAccount> = vm_storages
            .into_iter()
            .map(|x| (x.address.clone(), x))
            .collect();

        let snapshot = Snapshot { states, vm_storage };

        // Get block header to extract the timestamp
        let block_header = self
            .runtime
            .block_on(
                self.rpc_provider
                    .get_block_header(stop_block),
            )
            .wrap_err("Failed to get block header")?;

        let state_msgs: HashMap<String, StateSyncMessage<BlockHeader>> = HashMap::from([(
            String::from(protocol_system),
            StateSyncMessage {
                header: BlockHeader {
                    hash: (*block_header.hash()).into(),
                    number: stop_block,
                    parent_hash: Bytes::default(),
                    revert: false,
                    timestamp: block_header.header.timestamp,
                },
                snapshots: snapshot,
                deltas: None,
                removed_components: HashMap::new(),
            },
        )]);

        let all_tokens = self
            .runtime
            .block_on(tycho_client.get_tokens(Chain::Ethereum, None, None))
            .into_diagnostic()
            .wrap_err("Failed to get tokens")?;
        debug!("Loaded {} tokens", all_tokens.len());

        self.runtime
            .block_on(decoder.set_tokens(all_tokens));

        let message: FeedMessage = FeedMessage { state_msgs, sync_states: Default::default() };

        let block_msg = self
            .runtime
            .block_on(decoder.decode(&message))
            .into_diagnostic()
            .wrap_err("Failed to decode message")?;
        debug!("Decoded message for block {}", block_msg.block_number_or_timestamp);
        debug!("Update contains {} component states", block_msg.states.len());

        let mut component_tokens: HashMap<String, Vec<Token>> = HashMap::new();

        for (id, comp) in block_msg.new_pairs.iter() {
            component_tokens
                .entry(id.clone())
                .or_insert_with(|| comp.tokens.clone());
        }
        debug!("Mapped tokens for {} components", component_tokens.len());

        Ok((block_msg, component_tokens, protocol_states_by_id, block_header))
    }

    /// Validates that the protocol components retrieved from Tycho match the expected
    /// configuration.
    ///
    /// This method compares each expected component from the test configuration against
    /// the actual components found in the protocol state update. It ensures that all
    /// expected components are present and their properties (tokens, addresses, fees, etc.)
    /// match the expected values.
    ///
    /// # Arguments
    /// * `expected_components` - Vector of expected protocol components with their test
    ///   configuration
    /// * `block_msg` - The decoded protocol state update containing the actual component data
    ///
    /// # Returns
    /// Returns `Ok(())` if all expected components are found and match their expected state.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Any expected component is missing from the Tycho state
    /// - Any component's properties don't match the expected values (shows detailed diff)
    fn validate_state(
        &self,
        expected_components: &Vec<ProtocolComponentWithTestConfig>,
        block_msg: &Update,
    ) -> miette::Result<()> {
        if expected_components.is_empty() {
            debug!("No expected components defined for this test. Skipping state validation.");
            return Ok(());
        }

        debug!("Validating {:?} expected components", expected_components.len());
        for expected_component in expected_components {
            let component_id = expected_component
                .base
                .id
                .to_lowercase();

            let component = block_msg
                .new_pairs
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
        info!(
            "All expected components were successfully found on Tycho and match the expected state"
        );
        Ok(())
    }

    /// Performs comprehensive simulation and execution testing on protocol components.
    ///
    /// This method tests each protocol component by:
    /// 1. Computing spot prices for all token pairs
    /// 2. Simulating swaps with different input amounts (0.1%, 1%, 10% of limits)
    /// 3. Testing all possible swap directions between tokens
    /// 4. Simulating actual execution using historical block state
    /// 5. Comparing simulation results with execution results for accuracy
    ///
    /// The simulation uses the Tycho SDK to calculate expected outputs, while execution
    /// uses `debug_traceCall` with state overwrites to simulate actual on-chain behavior
    /// at historical blocks.
    ///
    /// # Arguments
    /// * `update` - The decoded protocol state containing all component data
    /// * `component_tokens` - Mapping of component IDs to their associated tokens
    /// * `block` - The historical block to use for execution testing
    /// * `expected_components` - Optional test configuration to determine which components to skip
    ///
    /// # Returns
    /// Returns `Ok(())` if all simulations and executions complete successfully within tolerance.
    ///
    /// # Errors
    /// Returns an error if:
    ///   - Spot price calculation fails for any component
    ///   - Simulation fails to calculate amount out
    ///   - Execution simulation fails or reverts
    ///   - Difference between simulation and execution exceeds 5% slippage tolerance
    ///
    /// Components can be skipped using `skip_simulation` or `skip_execution` flags
    /// in the test configuration.
    fn simulate_and_execute(
        &self,
        update: &Update,
        component_tokens: &HashMap<String, Vec<Token>>,
        block: &Block,
        expected_components: &[ProtocolComponentWithTestConfig],
    ) -> miette::Result<()> {
        let skip_simulation: HashSet<_> = expected_components
            .iter()
            .filter(|c| c.skip_simulation)
            .map(|c| c.base.id.to_lowercase())
            .collect();
        let skip_execution: HashSet<_> = expected_components
            .iter()
            .filter(|c| c.skip_execution)
            .map(|c| c.base.id.to_lowercase())
            .collect();

        for (id, state) in update.states.iter() {
            if skip_simulation.contains(id) {
                info!("Skipping simulation for component {id}");
                continue
            }
            if let Some(tokens) = component_tokens.get(id) {
                let formatted_token_str = format!("{:}/{:}", &tokens[0].symbol, &tokens[1].symbol);
                state
                    .spot_price(&tokens[0], &tokens[1])
                    .map(|price| info!("Spot price {:?}: {:?}", formatted_token_str, price))
                    .into_diagnostic()
                    .wrap_err(format!("Error calculating spot price for Pool {id:?}."))?;

                // Test get_amount_out with different percentages of limits. The reserves or limits
                // are relevant because we need to know how much to test with. We
                // don't know if a pool is going to revert with 10 or 10 million
                // USDC, for example, so by using the limits we can use "safe
                // values" where the sim shouldn't break. We then retrieve the
                // amount out for 0.1%, 1% and 10%.
                let percentages = [0.001, 0.01, 0.1];

                // Test all permutations of swap directions
                let swap_directions: Vec<_> = tokens
                    .iter()
                    .permutations(2)
                    .map(|perm| (perm[0], perm[1]))
                    .collect();

                for (token_in, token_out) in &swap_directions {
                    let (max_input, max_output) = state
                        .get_limits(token_in.address.clone(), token_out.address.clone())
                        .into_diagnostic()
                        .wrap_err(format!(
                            "Error getting limits for Pool {id:?} for in token: {}, and out token: {}",
                            token_in.address, token_out.address
                        ))?;

                    info!(
                    "Retrieved limits. | Max input: {max_input} {} | Max output: {max_output} {}",
                    token_in.symbol, token_out.symbol
                );

                    for percentage in &percentages {
                        // For precision, multiply by 1000 then divide by 1000
                        let percentage_biguint = BigUint::from((percentage * 1000.0) as u32);
                        let thousand = BigUint::from(1000u32);
                        let amount_in = (&max_input * &percentage_biguint) / &thousand;

                        // Skip if amount is zero
                        if amount_in.is_zero() {
                            info!("Amount in multiplied by percentage {percentage} is zero. Skipping pool {id}.");
                            continue;
                        }

                        let amount_out_result = state
                            .get_amount_out(amount_in.clone(), token_in, token_out)
                            .into_diagnostic()
                            .wrap_err(format!(
                                "Error calculating amount out for Pool {id:?} at {:.1}% with input of {amount_in} {}.",
                                percentage * 100.0,
                                token_in.symbol,
                            ))?;

                        info!(
                        "Simulated amount out for trading {:.1}% of max: ({} {} -> {} {}) (gas: {})",
                        percentage * 100.0,
                        amount_in,
                        token_in.symbol,
                        amount_out_result.amount,
                        token_out.symbol,
                        amount_out_result.gas
                    );

                        // Only execute for components that should have execution
                        if skip_execution.contains(id) {
                            info!("Skipping execution for component {id}");
                            continue;
                        }

                        let protocol_component = update.new_pairs.get(id).unwrap();

                        let (calldata, solution) = encode_swap(
                            protocol_component,
                            &token_in.address,
                            &token_out.address,
                            &amount_in,
                            &amount_out_result.amount,
                        )?;

                        info!("Simulating swap at historical block {}", block.number());
                        // Simulate the trade using debug_traceCall with overwrites
                        let execution_amount_out =
                            self.runtime
                                .block_on(execution::simulate_trade_with_eth_call(
                                    &self.rpc_provider,
                                    &calldata,
                                    &solution,
                                    block,
                                ));

                        match execution_amount_out {
                            Ok(amount_out) => {
                                info!(
                                    "Simulating execution passed with {} {} -> {} {}",
                                    solution.given_amount,
                                    token_in.symbol,
                                    amount_out,
                                    token_out.symbol
                                );

                                // Compare execution amount out with simulation amount out
                                let diff = BigInt::from(amount_out_result.amount) -
                                    BigInt::from(amount_out.clone());

                                let slippage: BigRational =
                                    BigRational::new(diff.abs(), BigInt::from(amount_out));
                                if slippage.to_f64() > Some(0.05) {
                                    return Err(miette!(
                                    "Execution amount and simulation amount differ more than 5%!"
                                ));
                                }
                            }
                            Err(e) => {
                                return Err(miette!(
                                    "Simulating execution failed for {} -> {}: {}",
                                    token_in.symbol,
                                    token_out.symbol,
                                    e
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate that the token balances of the components match the values
    /// on-chain, extracted by querying the token balances using a node.
    fn validate_token_balances(
        &self,
        component_tokens: &HashMap<String, Vec<Token>>,
        protocol_states_by_id: &HashMap<String, ResponseProtocolState>,
        stop_block: u64,
    ) -> miette::Result<()> {
        for (id, component) in protocol_states_by_id.iter() {
            let tokens = component_tokens.get(id);
            if let Some(tokens) = tokens {
                for token in tokens {
                    let mut balance: U256 = U256::from(0);
                    let bal = component.balances.get(&token.address);
                    if let Some(bal) = bal {
                        let bal = bal.clone().into();
                        balance = bytes_to_u256(bal);
                    }

                    info!(
                        "Validating token balance for component {} and token {}",
                        id, token.symbol
                    );
                    let token_address = bytes_to_address(&token.address).into_diagnostic()?;
                    let component_address =
                        Address::from_str(id.as_str()).expect("Failed to parse component address");
                    let node_balance =
                        self.runtime
                            .block_on(self.rpc_provider.get_token_balance(
                                token_address,
                                component_address,
                                stop_block,
                            ))?;
                    if balance != node_balance {
                        return Err(miette!(
                            "Token balance mismatch for component {id} and token {}. Balance: {balance}, Node balance: {node_balance}",
                            token.symbol
                        ));
                    }
                    info!(
                        "Token balance for component {} and token {} matches the expected value",
                        id, token.symbol
                    );
                }
            } else {
                return Err(miette!("Couldn't find tokens for component {}", id,));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, env, str::FromStr};

    use dotenv::dotenv;
    use glob::glob;
    use tycho_simulation::tycho_common::{dto::ResponseProtocolState, Bytes};

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

    fn get_mocked_runner() -> TestRunner {
        dotenv().ok();
        let rpc_url = env::var("RPC_URL").unwrap();
        let current_dir = std::env::current_dir().unwrap();
        TestRunner::new(
            TestType::Range(TestTypeRange { match_test: None }),
            current_dir,
            "test-protocol".to_string(),
            "".to_string(),
            rpc_url,
            false,
            false,
        )
        .unwrap()
    }
    #[test]
    fn test_token_balance_validation() {
        let runner = get_mocked_runner();
        // Setup mock data
        let block_number = 21998530;
        let token_bytes = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let component_id = "0x787B8840100d9BaAdD7463f4a73b5BA73B00C6cA".to_string();
        let token = Token::new(&token_bytes, "FAKE", 18, 0, &[], Chain::Ethereum.into(), 100);

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

        let mut component_tokens = HashMap::new();
        component_tokens.insert(component_id.clone(), vec![token]);
        let mut protocol_states_by_id = HashMap::new();
        protocol_states_by_id.insert(component_id.clone(), protocol_state.clone());

        let result =
            runner.validate_token_balances(&component_tokens, &protocol_states_by_id, block_number);
        assert!(result.is_ok(), "Should pass when balance check is performed and balances match");
    }

    #[test]
    fn test_token_balance_validation_fails_on_mismatch() {
        let runner = get_mocked_runner();

        // Setup mock data
        let block_number = 21998530;
        let token_bytes = Bytes::from_str("0x0000000000000000000000000000000000000000").unwrap();
        let component_id = "0x787B8840100d9BaAdD7463f4a73b5BA73B00C6cA".to_string();
        let token = Token::new(&token_bytes, "FAKE", 18, 0, &[], Chain::Ethereum.into(), 100);

        // Set expected balance to zero
        let mut balances = HashMap::new();
        let balance_bytes = Bytes::from(U256::from(0).to_be_bytes::<32>());
        balances.insert(token_bytes.clone(), balance_bytes.clone());
        let protocol_state = ResponseProtocolState {
            component_id: component_id.clone(),
            balances,
            ..Default::default()
        };

        let mut component_tokens = HashMap::new();
        component_tokens.insert(component_id.clone(), vec![token]);
        let mut protocol_states_by_id = HashMap::new();
        protocol_states_by_id.insert(component_id.clone(), protocol_state.clone());

        dotenv().ok();
        let result =
            runner.validate_token_balances(&component_tokens, &protocol_states_by_id, block_number);
        assert!(
            result.is_err(),
            "Should fail when balance check is performed and balances do not match"
        );
    }
}
