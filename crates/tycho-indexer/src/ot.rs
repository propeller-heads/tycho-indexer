use anyhow::{Context, Result};
use opentelemetry::{global, trace::TracerProvider as _};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{
    propagation::TraceContextPropagator,
    trace::{BatchConfigBuilder, BatchSpanProcessor, SdkTracerProvider},
    Resource,
};
use serde::Deserialize;
use tracing::Subscriber;
use tracing_subscriber::{
    layer::SubscriberExt, registry::LookupSpan, util::SubscriberInitExt, EnvFilter, Layer,
};

#[derive(Debug, Clone, Deserialize)]
pub struct TracingConfig {
    pub otlp_exporter_endpoint: String,
}

/// Handle tying the OTel tracer provider's lifetime to the application's. Drop
/// or call [`TracingHandle::shutdown`] before exit to flush any spans the
/// `BatchSpanProcessor` has buffered; otherwise the most recent batch is lost.
pub struct TracingHandle {
    provider: Option<SdkTracerProvider>,
}

impl TracingHandle {
    /// Block on a final flush + processor shutdown. Logs and swallows the error
    /// rather than propagating, so callers can place this on the shutdown path
    /// without complicating their error type. Idempotent: subsequent calls and
    /// `Drop` become no-ops once the provider is consumed.
    ///
    /// Diagnostics go via `eprintln!` rather than `tracing::warn!` because the
    /// OTel layer wired up by `init_tracing` is precisely the subsystem being
    /// shut down — emitting a `tracing` event here can recurse into the SDK's
    /// internal-log path or be silently dropped by the in-flight batch
    /// processor.
    pub fn shutdown(&mut self) {
        if let Some(provider) = self.provider.take() {
            if let Err(err) = provider.shutdown() {
                eprintln!("OTel tracer provider shutdown failed: {err:#}");
            }
        }
    }
}

impl Drop for TracingHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Initialize tracing: apply an `EnvFilter` using the `RUST_LOG` environment variable to define the
/// log levels, add a formatter layer logging trace events as JSON and on OpenTelemetry layer
/// exporting trace data.
///
/// The OTLP layer uses `RUST_LOG_OTLP` if set, otherwise falls back to `RUST_LOG`. This allows
/// exporting detailed spans to Tempo without flooding stdout logs:
///
/// ```sh
/// RUST_LOG=info RUST_LOG_OTLP=tycho_storage::postgres=debug
/// ```
///
/// Returns a [`TracingHandle`] the caller must hold for the lifetime of the
/// process; dropping it flushes the OTLP batch processor.
pub fn init_tracing(config: TracingConfig) -> Result<TracingHandle> {
    global::set_text_map_propagator(TraceContextPropagator::new());

    let format = tracing_subscriber::fmt::format()
        .with_level(true)
        .with_target(false)
        .compact();

    // OpenTelemetry 0.30 has no equivalent of the 0.21 `global::set_error_handler`
    // callback: BatchSpanProcessor.ExportError / .Emit.ProcessorShutdown and friends
    // emit straight through `tracing::error!`. The internal-log macros set
    // `target = env!("CARGO_PKG_NAME")`, which Cargo expands to the crate's
    // `package.name` with hyphens converted to underscores — i.e.
    // `opentelemetry_sdk`, `opentelemetry`, `opentelemetry_otlp`. Operators who
    // want silence can scope `RUST_LOG` to those targets, e.g.
    //   RUST_LOG=info,opentelemetry_sdk=off
    let fmt_filter = EnvFilter::from_default_env();
    let otlp_filter = otlp_env_filter();

    let (otlp, handle) = otlp_layer(config)?;

    tracing_subscriber::registry()
        .with(otlp.with_filter(otlp_filter))
        .with(
            tracing_subscriber::fmt::layer()
                .event_format(format)
                .with_filter(fmt_filter),
        )
        .try_init()
        .context("initialize tracing subscriber")?;

    Ok(handle)
}

/// Build the `EnvFilter` for the OTLP layer.
/// Uses `RUST_LOG_OTLP` if set and parseable, otherwise falls back to `RUST_LOG` / default.
/// A malformed override does not crash startup — it is logged and ignored, mirroring
/// the lenient behaviour of `EnvFilter::from_default_env()` on `RUST_LOG`.
fn otlp_env_filter() -> EnvFilter {
    match std::env::var("RUST_LOG_OTLP").ok() {
        Some(val) => EnvFilter::try_new(&val).unwrap_or_else(|err| {
            eprintln!("RUST_LOG_OTLP={val:?} is invalid ({err}); falling back to RUST_LOG");
            EnvFilter::from_default_env()
        }),
        None => EnvFilter::from_default_env(),
    }
}

/// Create an OTLP layer exporting tracing data and a [`TracingHandle`] tied to
/// the underlying [`SdkTracerProvider`].
fn otlp_layer<S>(config: TracingConfig) -> Result<(impl Layer<S>, TracingHandle)>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(config.otlp_exporter_endpoint)
        .build()
        .context("build OTLP span exporter")?;

    let batch_config = BatchConfigBuilder::default()
        .with_max_queue_size(20_480)
        .with_max_export_batch_size(2_560)
        .build();

    let batch_processor = BatchSpanProcessor::builder(exporter)
        .with_batch_config(batch_config)
        .build();

    // `Resource::builder()` runs the SDK detectors (telemetry.sdk.*, env-var
    // service.name/attributes). Setting `service.name` explicitly here gives
    // Tempo / Jaeger a stable label even when `OTEL_SERVICE_NAME` is not set in
    // the deployment env.
    let resource = Resource::builder()
        .with_service_name("tycho-indexer")
        .build();

    let provider = SdkTracerProvider::builder()
        .with_span_processor(batch_processor)
        .with_resource(resource)
        .build();

    let tracer = provider.tracer("tycho-indexer");
    global::set_tracer_provider(provider.clone());

    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    Ok((layer, TracingHandle { provider: Some(provider) }))
}
