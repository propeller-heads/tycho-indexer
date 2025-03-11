use std::{
    path::{Path, PathBuf},
    thread::sleep,
    time::Duration,
};

use figment::{
    providers::{Format, Yaml},
    Figment,
};
use postgres::{Client, Error, NoTls};
use tracing::{debug, field::debug, info};

use crate::{
    config::{IntegrationTest, IntegrationTestsConfig},
    tycho_runner::TychoRunner,
    utils::{build_spkg, modify_initial_block},
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

        tycho_runner.run_with_rpc_server(validate_state)
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

pub fn validate_state() {
    // TODO: Implement
    info!("Validating state...");
}
