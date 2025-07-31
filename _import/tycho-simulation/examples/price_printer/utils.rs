use tracing_subscriber::{fmt, EnvFilter};

pub fn setup_tracing() {
    let writer = tracing_appender::rolling::daily("logs", "price_printer.log");
    // Create a subscriber with the file appender
    let subscriber = fmt()
        .with_writer(writer)
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    // Set the subscriber as the global default
    tracing::subscriber::set_global_default(subscriber).unwrap();
}
