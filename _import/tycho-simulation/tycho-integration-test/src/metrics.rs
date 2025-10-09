use actix_web::{rt::System, web, App, HttpResponse, HttpServer, Responder};
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use miette::{Context, IntoDiagnostic, Result};
use num_bigint::BigUint;
use tracing::info;
use tycho_client::feed::SynchronizerState;
use tycho_common::Bytes;

/// Initialize the metrics registry and describe all metrics
pub fn init_metrics() {
    describe_histogram!(
        "block_processing_latency_seconds",
        "Time between block timestamp and when protocol components are received"
    );
    describe_counter!("get_limits_failures_total", "Total number of failed get limits");
    describe_counter!("get_amount_out_failures_total", "Total number of failed get amount out");
    describe_histogram!(
        "get_amount_out_duration_seconds",
        "Time taken to execute get_amount_out for each protocol"
    );
    describe_counter!(
        "simulation_execution_success_total",
        "Total number of successful simulations of execution"
    );
    describe_counter!(
        "simulation_execution_failure_total",
        "Total number of failed simulations of execution with revert reason as label"
    );
    describe_counter!(
        "simulation_execution_success_by_protocol",
        "Total number of successful simulations of execution by protocol, component, and block"
    );
    describe_counter!(
        "simulation_execution_failure_by_protocol",
        "Total number of failed simulations of execution by protocol with detailed error information"
    );
    describe_histogram!(
        "slippage_between_simulation_and_execution",
        "Slippage between simulated amount out and simulated execution amount out"
    );
    describe_gauge!(
        "protocol_sync_state_current",
        "Current sync state per protocol as numeric value"
    );
    describe_counter!(
        "skipped_updates_total",
        "Total number of updates skipped because they are behind the current block"
    );
    describe_histogram!(
        "block_delay",
        "The amount of blocks behind that we receive protocol updates"
    );
}

/// Record the latency between block timestamp and component receipt
pub fn record_block_processing_latency(latency_seconds: f64) {
    histogram!("block_processing_latency_seconds").record(latency_seconds);
}

pub fn record_get_limits_failures(
    protocol: &str,
    component_id: &str,
    block_number: u64,
    token_in: &Bytes,
    token_out: &Bytes,
    error_msg: String,
) {
    counter!("get_limits_failures_total", "protocol" => protocol.to_string(),
        "component_id" => component_id.to_string(),
        "block" => block_number.to_string(),
        "token_in" => token_in.to_string(),
        "token_out" => token_out.to_string(),
        "error_msg" => error_msg,
    )
    .increment(1);
}

pub fn record_get_amount_out_failures(
    protocol: &str,
    component_id: &str,
    block_number: u64,
    token_in: &Bytes,
    token_out: &Bytes,
    amount_in: &BigUint,
    error_msg: String,
) {
    counter!("get_amount_out_failures_total", "protocol" => protocol.to_string(),
        "component_id" => component_id.to_string(),
        "block" => block_number.to_string() ,       "token_in" => token_in.to_string(),
        "token_out" => token_out.to_string(),
        "amount_in" => amount_in.to_string(),
        "error_msg" => error_msg,
    )
    .increment(1);
}

/// Record the time taken to execute get_amount_out
pub fn record_get_amount_out_duration(protocol: &str, duration_seconds: f64, component_id: &str) {
    histogram!(
        "get_amount_out_duration_seconds",
        "protocol" => protocol.to_string(),
        "component_id" => component_id.to_string()
    )
    .record(duration_seconds);
}

/// Record a successful simulation
pub fn record_simulation_execution_success() {
    counter!("simulation_execution_success_total").increment(1);
}

/// Record a failed simulation with the revert reason
pub fn record_simulation_execution_failure(revert_reason: &str) {
    counter!("simulation_execution_failure_total", "reason" => revert_reason.to_string())
        .increment(1);
}

/// Record a successful simulation with detailed protocol information
pub fn record_simulation_execution_success_detailed(
    protocol: &str,
    component_id: &str,
    block_number: u64,
) {
    counter!(
        "simulation_execution_success_by_protocol",
        "protocol" => protocol.to_string(),
        "component_id" => component_id.to_string(),
        "block" => block_number.to_string()
    )
    .increment(1);
}

/// Record a failed simulation with detailed protocol and error information
pub fn record_simulation_execution_failure_detailed(
    protocol: &str,
    component_id: &str,
    block_number: u64,
    error_message: &str,
    error_name: &str,
    tenderly_url: &str,
    overwrites: &str,
) {
    counter!(
        "simulation_execution_failure_by_protocol",
        "protocol" => protocol.to_string(),
        "component_id" => component_id.to_string(),
        "block" => block_number.to_string(),
        "error_message" => error_message.to_string(),
        "error_name" => error_name.to_string(),
        "tenderly_url" => tenderly_url.to_string(),
        "overwrites" => overwrites.to_string()
    )
    .increment(1);
}

pub fn record_slippage(block_number: u64, protocol: &str, component_id: &str, slippage: f64) {
    histogram!("slippage_between_simulation_and_execution","block" => block_number.to_string(), "protocol"=>protocol.to_string(), "component_id" => component_id.to_string(),)
        .record(slippage);
}

pub fn record_protocol_sync_state(protocol: &str, sync_state: &SynchronizerState) {
    let state_value = match sync_state {
        SynchronizerState::Started => 1.0,
        SynchronizerState::Ready(_) => 2.0,
        SynchronizerState::Delayed(_) => 3.0,
        SynchronizerState::Stale(_) => 4.0,
        SynchronizerState::Advanced(_) => 5.0,
        SynchronizerState::Ended(_) => 6.0,
    };
    gauge!("protocol_sync_state_current", "protocol" => protocol.to_string()).set(state_value);
}

/// Record when an update is skipped because it's behind the current block
pub fn record_skipped_update() {
    counter!("skipped_updates_total").increment(1);
}

/// Record block delay of protocol updates
pub fn record_block_delay(block_delay: u64) {
    histogram!("block_delay").record(block_delay as f64);
}

/// Creates and runs the Prometheus metrics exporter using Actix Web.
/// Returns a JoinHandle that should be awaited to detect server failures.
pub async fn create_metrics_exporter(port: u16) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let exporter_builder = PrometheusBuilder::new();
    let handle = exporter_builder
        .install_recorder()
        .into_diagnostic()
        .wrap_err("Failed to install Prometheus recorder")?;

    // Verify port is available by attempting to bind
    let test_bind = std::net::TcpListener::bind(("0.0.0.0", port))
        .into_diagnostic()
        .wrap_err(format!("Failed to bind metrics server to port {} - port may be in use", port))?;
    drop(test_bind);

    info!("Starting Prometheus metrics server on 0.0.0.0:{}", port);

    // Spawn in a separate thread with its own Actix runtime
    let task = std::thread::spawn(move || {
        System::new().block_on(async move {
            HttpServer::new(move || {
                App::new().route(
                    "/metrics",
                    web::get().to({
                        let handle = handle.clone();
                        move || metrics_handler(handle.clone())
                    }),
                )
            })
            .bind(("0.0.0.0", port))
            .into_diagnostic()
            .wrap_err(format!("Failed to bind metrics server to port {}", port))?
            .run()
            .await
            .into_diagnostic()
            .wrap_err("Metrics server failed")
        })
    });

    // Wrap the thread handle in a tokio task
    let join_handle = tokio::spawn(async move {
        task.join()
            .map_err(|_| miette::miette!("Metrics server thread panicked"))?
    });

    Ok(join_handle)
}

/// Handles requests to the /metrics endpoint, rendering Prometheus metrics.
async fn metrics_handler(handle: PrometheusHandle) -> impl Responder {
    let metrics = handle.render();
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(metrics)
}
