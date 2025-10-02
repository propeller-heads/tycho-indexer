use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use metrics::{counter, describe_counter};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing::{error, info};

/// Initialize the metrics registry and describe all metrics
pub fn init_metrics() {
    describe_counter!(
        "simulation_success_total",
        "Total number of successful simulations"
    );
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
    counter!("simulation_failure_total", "reason" => revert_reason).increment(1);
}

/// Creates and runs the Prometheus metrics exporter using Actix Web.
pub fn create_metrics_exporter() -> tokio::task::JoinHandle<()> {
    let exporter_builder = PrometheusBuilder::new();
    let handle = exporter_builder
        .install_recorder()
        .expect("Failed to install Prometheus recorder");

    info!("Starting Prometheus metrics server on 0.0.0.0:9898");

    tokio::spawn(async move {
        if let Err(e) = HttpServer::new(move || {
            App::new().route(
                "/metrics",
                web::get().to({
                    let handle = handle.clone();
                    move || metrics_handler(handle.clone())
                }),
            )
        })
        .bind(("0.0.0.0", 9898))
        .expect("Failed to bind metrics server")
        .run()
        .await
        {
            error!("Metrics server failed: {}", e);
        }
    })
}

/// Handles requests to the /metrics endpoint, rendering Prometheus metrics.
async fn metrics_handler(handle: PrometheusHandle) -> impl Responder {
    let metrics = handle.render();
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(metrics)
}
