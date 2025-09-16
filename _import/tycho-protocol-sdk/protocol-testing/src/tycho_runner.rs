use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::Duration,
};

use miette::{IntoDiagnostic, WrapErr};
use tracing::{debug, info};

use crate::config::ProtocolComponentWithTestConfig;

pub struct TychoRunner {
    db_url: String,
    initialized_accounts: Vec<String>,
}

// TODO: Currently Tycho-Indexer cannot be run as a lib. We need to expose the entrypoints to allow
//  running it as a lib
impl TychoRunner {
    pub fn new(db_url: String, initialized_accounts: Vec<String>) -> Self {
        Self { db_url, initialized_accounts }
    }

    pub fn run_tycho(
        &self,
        spkg_path: &str,
        start_block: u64,
        end_block: u64,
        protocol_type_names: &[String],
        protocol_system: &str,
    ) -> miette::Result<()> {
        info!("Running Tycho indexer from block {start_block} to {end_block}...");

        let mut cmd = Command::new("tycho-indexer");
        cmd.env("RUST_LOG", std::env::var("RUST_LOG").unwrap_or("tycho_indexer=info".to_string()))
            .env("AUTH_API_KEY", "dummy");

        let all_accounts = self.initialized_accounts.clone();

        cmd.args([
            "--database-url",
            self.db_url.as_str(),
            "run",
            "--spkg",
            spkg_path,
            "--module",
            "map_protocol_changes",
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

    pub fn run_with_rpc_server<F, R>(
        &self,
        func: F,
        expected_components: &Vec<ProtocolComponentWithTestConfig>,
        start_block: u64,
        stop_block: u64,
        skip_balance_check: bool,
    ) -> miette::Result<R>
    where
        F: FnOnce(&Vec<ProtocolComponentWithTestConfig>, u64, u64, bool) -> R,
    {
        let (tx, rx): (Sender<bool>, Receiver<bool>) = mpsc::channel();
        let db_url = self.db_url.clone();

        // Start the RPC server in a separate thread
        let rpc_thread = thread::spawn(move || {
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

        // Run the provided function
        let result = func(expected_components, start_block, stop_block, skip_balance_check);

        tx.send(true)
            .expect("Failed to send termination message");

        // Wait for the RPC thread to finish
        if rpc_thread.join().is_err() {
            eprintln!("Failed to join RPC thread");
        }

        Ok(result)
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
