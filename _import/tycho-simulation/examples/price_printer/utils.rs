use std::{fs, path::Path};

use tracing_subscriber::{fmt, EnvFilter};

pub fn setup_tracing() {
    // Archive existing log file if it exists
    archive_existing_log();

    // Create a non-rolling file writer for fresh logs each run
    let log_file =
        std::fs::File::create("logs/price_printer.log").expect("Failed to create log file");

    // Create a subscriber with the file appender
    let subscriber = fmt()
        .with_writer(log_file)
        .with_env_filter(EnvFilter::from_default_env())
        .finish();

    // Set the subscriber as the global default
    tracing::subscriber::set_global_default(subscriber).unwrap();
}

fn archive_existing_log() {
    let log_path = Path::new("logs/price_printer.log");
    let archive_path = Path::new("logs/price_printer_old.log");

    // Create logs directory if it doesn't exist
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).ok();
    }

    // If log file exists, move it to the archive
    if log_path.exists() {
        // Remove old archive if it exists
        if archive_path.exists() {
            fs::remove_file(archive_path).ok();
        }

        // Move current log to archive
        if let Err(e) = fs::rename(log_path, archive_path) {
            eprintln!("Warning: Failed to archive existing log: {e}");
        }
    }
}
