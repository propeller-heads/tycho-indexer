use pyo3::prelude::*;
use tracing::{Event, Subscriber};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

pub struct PythonLoggerLayer;

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
                            .getattr("TRACE")
                            .unwrap_or_else(|_| {
                                logger
                                    .getattr("NOTSET") // Fallback to NOTSET if TRACE is not available
                                    .unwrap_or_else(|_| py.None().into_ref(py))
                            }), // TRACE is set as a custom level by defibot
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
