use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

use miette::{miette, IntoDiagnostic, WrapErr};

pub struct AdapterContractBuilder {
    src_path: String,
}

impl AdapterContractBuilder {
    pub fn new(src_path: String) -> Self {
        Self { src_path }
    }

    /// Finds the contract file in the provided source path.
    ///
    /// # Parameters
    /// - `adapter_contract`: The contract name to be passed to the script.
    ///
    /// # Returns
    /// The path to the contract file.
    pub fn find_contract(&self, adapter_contract: &str) -> miette::Result<PathBuf> {
        let contract_path = Path::new(&self.src_path)
            .join("out")
            .join(format!("{adapter_contract}.sol"))
            .join(format!("{adapter_contract}.evm.runtime"));
        if !contract_path.exists() {
            return Err(miette!("Contract {adapter_contract} not found."));
        }
        Ok(contract_path)
    }

    /// Runs the buildRuntime Bash script in a subprocess with the provided arguments.
    ///
    /// # Parameters
    /// - `adapter_contract`: The contract name to be passed to the script.
    /// - `signature`: The constructor signature to be passed to the script (optional).
    /// - `args`: The constructor arguments to be passed to the script (optional).
    ///
    /// # Returns
    /// The path to the contract file.
    pub fn build_target(
        &self,
        adapter_contract: &str,
        signature: Option<&str>,
        args: Option<&str>,
    ) -> miette::Result<PathBuf> {
        let script_path = "scripts/buildRuntime.sh";
        let mut cmd = Command::new(script_path);
        cmd.current_dir(&self.src_path)
            .arg("-c")
            .arg(adapter_contract);

        if let (Some(sig), Some(arg)) = (signature, args) {
            cmd.arg("-s")
                .arg(sig)
                .arg("-a")
                .arg(arg);
        }

        let output: Output = cmd
            .output()
            .into_diagnostic()
            .wrap_err(miette!("Error running '{script_path}'"))?;

        println!("Output:\n{}", String::from_utf8_lossy(&output.stdout));
        if !output.stderr.is_empty() {
            println!("Errors:\n{}", String::from_utf8_lossy(&output.stderr));
        }

        if !output.status.success() {
            return Err(miette!("An error occurred: {}", String::from_utf8_lossy(&output.stderr)));
        }

        self.find_contract(adapter_contract)
    }
}
