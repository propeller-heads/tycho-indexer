use actix_web::{rt::System, web, App, HttpResponse, HttpServer, Responder};
use metrics::{counter, describe_counter};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use miette::{Context, IntoDiagnostic, Result};
use tracing::info;

/// Initialize the metrics registry and describe all metrics
pub fn init_metrics() {
    describe_counter!("simulation_success_total", "Total number of successful simulations");
    describe_counter!(
        "simulation_failure_total",
        "Total number of failed simulations with revert reason as label"
    );
}

/// Record a successful simulation
pub fn record_simulation_success() {
    counter!("simulation_success_total").increment(1);
}

/// Record a failed simulation with the revert reason
pub fn record_simulation_failure(revert_reason: &str) {
    counter!("simulation_failure_total", "reason" => revert_reason.to_string()).increment(1);
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
