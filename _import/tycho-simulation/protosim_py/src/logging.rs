use pyo3::prelude::*;
use tracing::{level_filters::LevelFilter, Event, Subscriber};
use tracing_subscriber::{layer::Context, prelude::*, registry::LookupSpan, EnvFilter, Layer};

struct PythonLoggerLayer;

impl<S> Layer<S> for PythonLoggerLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        Python::with_gil(|py| {
            // Safely import the Python logging module
            match py.import("logging") {
                Ok(logger) => {
                    // Determine the log level
                    let level = match *event.metadata().level() {
                        tracing::Level::ERROR => logger
                            .getattr("ERROR")
                            .unwrap_or_else(|_| py.None().into_ref(py)),
                        tracing::Level::WARN => logger
                            .getattr("WARNING")
                            .unwrap_or_else(|_| py.None().into_ref(py)),
                        tracing::Level::INFO => logger
                            .getattr("INFO")
                            .unwrap_or_else(|_| py.None().into_ref(py)),
                        tracing::Level::DEBUG => logger
                            .getattr("DEBUG")
                            .unwrap_or_else(|_| py.None().into_ref(py)),
                        tracing::Level::TRACE => logger
                            .getattr("NOTSET")
                            .unwrap_or_else(|_| py.None().into_ref(py)), /* Python logging
                                                                          * doesn't have a
                                                                          * TRACE level, using
                                                                          * NOTSET as a
                                                                          * fallback */
                    };

                    // Extract the message from the event
                    let message = format!("{:?}", event);
                    // Log the message in Python
                    // Here we ignore the result. In production code, you might want to handle this
                    // differently.
                    let _ = logger.call_method1("log", (level, message));
                }
                Err(_) => {
                    // Handle the error of importing the logging module
                    // For now, we do nothing, but you might want to log this situation or handle it
                    // differently.
                }
            }
        });
    }
}

/// Initialize forwarding from Rust logs to Python logs
#[pyfunction]
pub fn init_custom_logging() -> PyResult<()> {
    // Set up Rust logging with the mapped level
    let env_filter = EnvFilter::from_default_env().add_directive(LevelFilter::DEBUG.into());
    let layer = PythonLoggerLayer;
    let subscriber: tracing_subscriber::layer::Layered<
        EnvFilter,
        tracing_subscriber::layer::Layered<_, tracing_subscriber::Registry>,
    > = tracing_subscriber::registry()
        .with(layer)
        .with(env_filter);
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Error: {}", e)))?;
    Ok(())
}
