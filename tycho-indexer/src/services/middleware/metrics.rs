use std::time::Instant;

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
};
use metrics::{counter, histogram};
use tracing::{instrument, Span};

/// Middleware to record metrics for RPC requests.
#[instrument(skip_all, fields(user_identity))]
pub(in crate::services) async fn rpc_metrics_middleware<B>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error>
where
    B: MessageBody + 'static,
{
    let start = Instant::now();

    let endpoint = req
        .match_pattern()
        .unwrap_or_else(|| req.path().to_owned());

    let user_identity = req
        .headers()
        .get("user-identity")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    Span::current().record("user_identity", &user_identity);

    counter!("rpc_requests", "endpoint" => endpoint.clone(), "user_identity" => user_identity.clone()).increment(1);

    let res = next.call(req).await;

    histogram!(
        "rpc_request_duration_seconds",
        "endpoint" => endpoint.clone(),
    )
    .record(start.elapsed().as_millis() as f64);

    match res {
        Ok(srv_res) => {
            if srv_res.status().is_client_error() || srv_res.status().is_server_error() {
                counter!(
                    "rpc_requests_failed",
                    "endpoint" => endpoint.clone(),
                    "status" => srv_res.status().as_u16().to_string(),
                    "user_identity" => user_identity.clone()
                )
                .increment(1);
            }

            Ok(srv_res.map_into_boxed_body())
        }
        Err(e) => {
            let resp_e = e.as_response_error();
            let status = resp_e.status_code().as_u16();

            counter!(
                "rpc_requests_failed",
                "endpoint" => endpoint.clone(),
                "status" => status.to_string(),
                "user_identity" => user_identity.clone()
            )
            .increment(1);

            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use actix_web::{http::StatusCode, middleware, test, web, App, HttpResponse, ResponseError};
    use metrics_util::{
        debugging::{DebugValue, DebuggingRecorder, Snapshotter},
        MetricKind,
    };
    use once_cell::sync::OnceCell;

    use super::*;
    use crate::services::rpc::RpcError;

    fn init_metrics() -> Snapshotter {
        static SNAPSHOTTER: OnceCell<Snapshotter> = OnceCell::new();
        SNAPSHOTTER
            .get_or_init(|| {
                let recorder = DebuggingRecorder::new();
                let snapshotter = recorder.snapshotter();
                recorder
                    .install()
                    .expect("failed to install metrics recorder");
                snapshotter
            })
            .clone()
    }

    fn snapshot_to_map(
        snapshot: metrics_util::debugging::Snapshot,
    ) -> HashMap<(MetricKind, String, BTreeMap<String, String>), DebugValue> {
        snapshot
            .into_vec()
            .into_iter()
            .map(|(ck, _unit, _desc, value)| {
                let name = ck.key().name().to_string();
                let labels = ck
                    .key()
                    .labels()
                    .map(|l| (l.key().to_string(), l.value().to_string()))
                    .collect::<BTreeMap<_, _>>();

                ((ck.kind(), name, labels), value)
            })
            .collect()
    }

    fn counter_value(
        map: &HashMap<(MetricKind, String, BTreeMap<String, String>), DebugValue>,
        name: &str,
        labels: &[(&str, &str)],
    ) -> u64 {
        let labels_map = labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>();

        match map.get(&(MetricKind::Counter, name.to_owned(), labels_map)) {
            Some(DebugValue::Counter(value)) => *value,
            _ => 0,
        }
    }

    fn histogram_samples(
        map: &HashMap<(MetricKind, String, BTreeMap<String, String>), DebugValue>,
        name: &str,
        labels: &[(&str, &str)],
    ) -> usize {
        let labels_map = labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>();

        match map.get(&(MetricKind::Histogram, name.to_owned(), labels_map)) {
            Some(DebugValue::Histogram(values)) => values.len(),
            _ => 0,
        }
    }

    /// Both success and failure cases run in a single test to share one actix System.
    /// The DebuggingRecorder uses thread-local handle caching, and `#[actix_web::test]`
    /// creates a new System (and thread) per test. When two tests run on different threads,
    /// metric handles registered on the first thread aren't visible to the snapshotter
    /// from the second thread's actix System.
    #[actix_web::test]
    async fn test_rpc_metrics() {
        let snapshotter = init_metrics();

        // --- Success case ---
        let app = test::init_service(
            App::new()
                .wrap(middleware::from_fn(rpc_metrics_middleware))
                .route("/v1/health", web::get().to(|| async { HttpResponse::Ok().finish() }))
                .route(
                    "/v1/fail",
                    web::get().to(|| async { Err::<HttpResponse, _>(RpcError::Pagination(100)) }),
                ),
        )
        .await;

        let before = snapshot_to_map(snapshotter.snapshot());

        let request = test::TestRequest::get()
            .uri("/v1/health")
            .insert_header(("user-identity", "alice"))
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let after = snapshot_to_map(snapshotter.snapshot());

        let success_labels = [("endpoint", "/v1/health"), ("user_identity", "alice")];
        assert_eq!(
            counter_value(&after, "rpc_requests", &success_labels)
                - counter_value(&before, "rpc_requests", &success_labels),
            1
        );

        let no_failure_labels =
            [("endpoint", "/v1/health"), ("status", "400"), ("user_identity", "alice")];
        assert_eq!(
            counter_value(&after, "rpc_requests_failed", &no_failure_labels),
            counter_value(&before, "rpc_requests_failed", &no_failure_labels),
        );

        assert_eq!(
            histogram_samples(
                &after,
                "rpc_request_duration_seconds",
                &[("endpoint", "/v1/health")]
            ),
            1
        );

        // --- Failure case ---
        let expected_error = RpcError::Pagination(100);
        let expected_status = expected_error.status_code();

        let before = snapshot_to_map(snapshotter.snapshot());

        let request = test::TestRequest::get()
            .uri("/v1/fail")
            .to_request();
        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), expected_status);

        let after = snapshot_to_map(snapshotter.snapshot());

        let fail_request_labels = [("endpoint", "/v1/fail"), ("user_identity", "unknown")];
        assert_eq!(
            counter_value(&after, "rpc_requests", &fail_request_labels)
                - counter_value(&before, "rpc_requests", &fail_request_labels),
            1
        );

        let fail_labels = [
            ("endpoint", "/v1/fail"),
            ("status", expected_status.as_str()),
            ("user_identity", "unknown"),
        ];
        assert_eq!(
            counter_value(&after, "rpc_requests_failed", &fail_labels)
                - counter_value(&before, "rpc_requests_failed", &fail_labels),
            1
        );

        assert_eq!(
            histogram_samples(
                &after,
                "rpc_request_duration_seconds",
                &[("endpoint", "/v1/fail")]
            ),
            1
        );
    }
}
