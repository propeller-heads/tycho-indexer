use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use figment::{
    providers::{Format, Yaml},
    value::Value,
    Figment,
};
use tracing::error;

/// Build a Substreams package with modifications to the YAML file.
pub fn build_spkg(yaml_file_path: &PathBuf, initial_block: u64) -> Result<String, Box<dyn Error>> {
    // Create a backup file of the unmodified Substreams protocol YAML config file.
    let backup_file_path = yaml_file_path.with_extension("backup");
    fs::copy(yaml_file_path, &backup_file_path)?;

    let figment = Figment::new().merge(Yaml::file(yaml_file_path));
    let mut data: Value = figment.extract()?;

    // Apply the modification function to update the YAML files
    modify_initial_block(&mut data, initial_block);

    let parent_dir = Path::new(yaml_file_path)
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_str()
        .unwrap_or("");

    let package_name = data
        .clone()
        .find("package")
        .expect("Package not found on YAML")
        .find("name")
        .expect("Name not found on YAML")
        .as_str()
        .expect("Failed to convert name to string.")
        .replace("_", "-");

    let binding = data
        .clone()
        .find("package")
        .expect("Package not found on YAML")
        .find("version")
        .expect("Version not found on YAML");

    let package_version = binding.as_str().unwrap_or("");

    let spkg_name = format!("{}/{}-{}.spkg", parent_dir, package_name, package_version);

    // Write the modified YAML back to the file
    let yaml_string = serde_yaml::to_string(&data)?;
    fs::write(yaml_file_path, yaml_string)?;

    // Run the substreams pack command to create the spkg
    // WARNING: Ensure substreams is in the PATH
    match Command::new("substreams")
        .arg("pack")
        .arg(yaml_file_path)
        .output()
    {
        Ok(output) => {
            if !output.status.success() {
                error!(
                    "Substreams pack command failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        Err(e) => {
            error!("Error running substreams pack command: {}. \
            Ensure that the wasm target was built and that substreams CLI\
             is installed and exported on PATH", e);
        }
    }

    // Restore the original YAML from backup
    fs::copy(&backup_file_path, yaml_file_path)?;
    fs::remove_file(&backup_file_path)?;

    Ok(spkg_name)
}

/// Update the initial block for all modules in the configuration data.
pub fn modify_initial_block(data: &mut Value, start_block: u64) {
    if let Value::Dict(_, ref mut dict) = data {
        if let Some(Value::Array(_, modules)) = dict.get_mut("modules") {
            for module in modules.iter_mut() {
                if let Value::Dict(_, ref mut module_dict) = module {
                    module_dict.insert("initialBlock".to_string(), Value::from(start_block));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use figment::value::Value;

    use super::*;

    fn create_test_data() -> Value {
        let file_path = Path::new("src/assets/substreams_example.yaml");
        let figment = Figment::new().merge(Yaml::file(file_path));

        figment
            .extract()
            .expect("Failed to parse YAML file")
    }

    #[test]
    fn test_modify_initial_block_normal_case() {
        let mut data = create_test_data();

        // Apply modification
        let new_block = 12345;
        modify_initial_block(&mut data, new_block);

        // Verify all modules now have the correct initialBlock
        if let Value::Dict(_, dict) = &data {
            if let Some(Value::Array(_, modules)) = dict.get("modules") {
                for module in modules {
                    if let Value::Dict(_, module_dict) = module {
                        if let Some(Value::Num(_, block)) = module_dict.get("initialBlock") {
                            assert_eq!(block.to_u128().unwrap(), new_block as u128);
                        } else {
                            panic!("initialBlock not found or has wrong type");
                        }
                    }
                }
            } else {
                panic!("modules not found or has wrong type");
            }
        }
    }
}
