use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::Duration,
};

use miette::{IntoDiagnostic, WrapErr};
use tracing::{debug, info};
use tycho_simulation::tycho_common::dto::Chain;
pub struct TychoRunner {
    chain: Chain,
    db_url: String,
    initialized_accounts: Vec<String>,
}

pub struct TychoRpcServer {
    sender: Sender<bool>,
    thread_handle: thread::JoinHandle<()>,
}

impl TychoRunner {
    pub fn new(chain: Chain, db_url: String, initialized_accounts: Vec<String>) -> Self {
        Self { chain, db_url, initialized_accounts }
    }

    pub fn run_tycho(
        &self,
        spkg_path: &str,
        start_block: u64,
        end_block: u64,
        protocol_type_names: &[String],
        protocol_system: &str,
        module_name: Option<String>,
    ) -> miette::Result<()> {
        info!("Running Tycho indexer from block {start_block} to {end_block}...",);

        let mut cmd = Command::new("tycho-indexer");
        cmd.env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or("tycho_indexer=info".to_string()))
            .env("AUTH_API_KEY", "dummy");

        let all_accounts = self.initialized_accounts.clone();

        cmd.args([
            "--database-url",
            self.db_url.as_str(),
            "--endpoint",
            get_default_endpoint(&self.chain)
                .unwrap_or_else(|| panic!("Unknown endpoint for chain {}", self.chain))
                .as_str(),
            "run",
            "--chain",
            self.chain.to_string().as_str(),
            "--spkg",
            spkg_path,
            "--module",
            module_name
                .as_deref()
                .unwrap_or("map_protocol_changes"),
            "--protocol-type-names",
            &protocol_type_names.join(","),
            "--protocol-system",
            protocol_system,
            "--start-block",
            &start_block.to_string(),
            "--stop-block",
            &(end_block + 2).to_string(), // +2 is to make up for the cache in the index side
            "--dci-plugin",
            "rpc",
        ]);

        if !all_accounts.is_empty() {
            cmd.args([
                "--initialized-accounts",
                &all_accounts.join(","),
                "--initialization-block",
                &start_block.to_string(),
            ]);
        }

        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut process = cmd
            .spawn()
            .into_diagnostic()
            .wrap_err("Error running Tycho indexer")?;

        Self::handle_process_output(&mut process);

        let status = process
            .wait()
            .into_diagnostic()
            .wrap_err("Failed to wait on Tycho indexer process")?;

        // Note: tycho-indexer may exit with non-zero status when stream ends normally
        // This is expected behavior and should not be treated as an error
        if !status.success() {
            debug!("Tycho indexer process exited with status: {status}");
        }

        Ok(())
    }

    pub fn start_rpc_server(&self) -> miette::Result<TychoRpcServer> {
        let (tx, rx): (Sender<bool>, Receiver<bool>) = mpsc::channel();
        let db_url = self.db_url.clone();

        // Start the RPC server in a separate thread
        let thread_handle = thread::spawn(move || {
            let mut cmd = Command::new("tycho-indexer")
                .args(["--database-url", db_url.as_str(), "rpc"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env(
                    "RUST_LOG",
                    std::env::var("RUST_LOG").unwrap_or("tycho_indexer=info".to_string()),
                )
                .env("AUTH_API_KEY", "dummy")
                .spawn()
                .expect("Failed to start RPC server");

            Self::handle_process_output(&mut cmd);

            match rx.recv() {
                Ok(_) => {
                    debug!("Received termination message, stopping RPC server...");
                    cmd.kill()
                        .expect("Failed to kill RPC server");
                    let _ = cmd.wait();
                }
                Err(_) => {
                    // Channel closed, terminate anyway
                    let _ = cmd.kill();
                    let _ = cmd.wait();
                }
            }
        });

        // Give the RPC server time to start
        thread::sleep(Duration::from_secs(3));

        Ok(TychoRpcServer { sender: tx, thread_handle })
    }

    pub fn stop_rpc_server(&self, server: TychoRpcServer) -> miette::Result<()> {
        server
            .sender
            .send(true)
            .into_diagnostic()
            .wrap_err("Failed to send termination message")?;

        // Wait for the RPC thread to finish
        if server.thread_handle.join().is_err() {
            eprintln!("Failed to join RPC thread");
        }

        Ok(())
    }

    // Helper method to handle process output in separate threads
    fn handle_process_output(child: &mut Child) {
        if let Some(stdout) = child.stdout.take() {
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines().map_while(Result::ok) {
                    println!("{line}");
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines().map_while(Result::ok) {
                    eprintln!("{line}");
                }
            });
        }
    }
}

pub fn get_default_endpoint(chain: &Chain) -> Option<String> {
    match chain {
        Chain::Ethereum => Some("https://mainnet.eth.streamingfast.io:443".to_string()),
        Chain::Base => Some("https://base-mainnet.streamingfast.io:443".to_string()),
        Chain::Unichain => Some("https://mainnet.unichain.streamingfast.io:443".to_string()),
        _ => None,
    }
}
