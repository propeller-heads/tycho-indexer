use std::time::Instant;

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::{self, Next},
};
use metrics::{counter, histogram};
use tracing::instrument;

/// Middleware to record metrics for RPC requests.
#[instrument(skip_all, fields(user_identity))]
pub(super) async fn rpc_metrics_middleware<B>(
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

    tracing::Span::current().record("user_identity", &user_identity);

    counter!("rpc_requests", "endpoint" => endpoint.clone(), "user_identity" => user_identity.clone()).increment(1);

    // call next
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
            // record failure metric
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

/// Creates the compression middleware for RPC responses.
///
/// Enables zstd compression while being backwards compatible with clients that do not support it.
/// The middleware automatically handles Accept-Encoding negotiation:
/// - Clients that send "Accept-Encoding: zstd" will receive compressed responses
/// - Clients that don't specify Accept-Encoding will receive uncompressed responses
/// - Clients that explicitly send "Accept-Encoding: identity" will receive uncompressed responses
pub(super) fn compression_middleware() -> middleware::Compress {
    middleware::Compress::default()
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
    ) -> Option<u64> {
        let labels_map = labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>();

        match map.get(&(MetricKind::Counter, name.to_owned(), labels_map)) {
            Some(DebugValue::Counter(value)) => Some(*value),
            _ => None,
        }
    }

    fn histogram_samples(
        map: &HashMap<(MetricKind, String, BTreeMap<String, String>), DebugValue>,
        name: &str,
        labels: &[(&str, &str)],
    ) -> Option<usize> {
        let labels_map = labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>();

        match map.get(&(MetricKind::Histogram, name.to_owned(), labels_map)) {
            Some(DebugValue::Histogram(values)) => Some(values.len()),
            _ => None,
        }
    }

    #[actix_web::test]
    async fn test_middleware_rpc_success() {
        let snapshotter = init_metrics();

        let app = test::init_service(
            App::new()
                .wrap(middleware::from_fn(rpc_metrics_middleware))
                .route("/v1/health", web::get().to(|| async { HttpResponse::Ok().finish() })),
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

        let expected_labels = [("endpoint", "/v1/health"), ("user_identity", "alice")];

        let before_requests = counter_value(&before, "rpc_requests", &expected_labels).unwrap_or(0);
        let after_requests = counter_value(&after, "rpc_requests", &expected_labels).unwrap_or(0);
        assert_eq!(after_requests.saturating_sub(before_requests), 1);

        let failure_labels =
            [("endpoint", "/v1/health"), ("status", "400"), ("user_identity", "alice")];
        let before_failures =
            counter_value(&before, "rpc_requests_failed", &failure_labels).unwrap_or(0);
        let after_failures =
            counter_value(&after, "rpc_requests_failed", &failure_labels).unwrap_or(0);
        assert_eq!(after_failures.saturating_sub(before_failures), 0);

        assert_eq!(
            histogram_samples(
                &after,
                "rpc_request_duration_seconds",
                &[("endpoint", "/v1/health")]
            )
            .unwrap_or_default(),
            1
        );
    }

    #[actix_web::test]
    async fn test_middleware_rpc_failer() {
        let snapshotter = init_metrics();

        let expected_error = RpcError::Pagination(100);
        let expected_status = expected_error.status_code();

        let app = test::init_service(
            App::new()
                .wrap(middleware::from_fn(rpc_metrics_middleware))
                .route(
                    "/v1/fail",
                    web::get().to(|| async { Err::<HttpResponse, _>(RpcError::Pagination(100)) }),
                ),
        )
        .await;

        let before = snapshot_to_map(snapshotter.snapshot());

        let request = test::TestRequest::get()
            .uri("/v1/fail")
            .to_request();

        let response = test::call_service(&app, request).await;
        assert_eq!(response.status(), expected_error.status_code());

        let after = snapshot_to_map(snapshotter.snapshot());

        let base_labels = [("endpoint", "/v1/fail"), ("user_identity", "unknown")];
        let before_requests = counter_value(&before, "rpc_requests", &base_labels).unwrap_or(0);
        let after_requests = counter_value(&after, "rpc_requests", &base_labels).unwrap_or(0);
        assert_eq!(after_requests.saturating_sub(before_requests), 1);

        let failure_labels = [
            ("endpoint", "/v1/fail"),
            ("status", expected_status.as_str()),
            ("user_identity", "unknown"),
        ];

        let before_failures =
            counter_value(&before, "rpc_requests_failed", &failure_labels).unwrap_or(0);
        let after_failures =
            counter_value(&after, "rpc_requests_failed", &failure_labels).unwrap_or(0);
        assert_eq!(after_failures.saturating_sub(before_failures), 1);

        let histogram_count =
            histogram_samples(&after, "rpc_request_duration_seconds", &[("endpoint", "/v1/fail")])
                .unwrap_or_default();
        assert_eq!(histogram_count, 1);
    }

    #[actix_web::test]
    async fn test_compression_without_accept_encoding_header() {
        let app = test::init_service(
            App::new()
                .wrap(compression_middleware())
                .service(
                    web::resource("/health").route(web::get().to(crate::services::rpc::health)),
                ),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/health")
            .to_request();

        let resp = test::call_service(&app, req).await;

        // Should succeed with 200 OK
        assert!(resp.status().is_success());

        // Should NOT have Content-Encoding header (uncompressed)
        assert!(resp
            .headers()
            .get("content-encoding")
            .is_none());

        let body = test::read_body(resp).await;
        assert!(!body.is_empty());
    }

    #[actix_web::test]
    async fn test_compression_with_zstd_encoding() {
        let app = test::init_service(
            App::new()
                .wrap(compression_middleware())
                .service(
                    web::resource("/health").route(web::get().to(crate::services::rpc::health)),
                ),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/health")
            .insert_header(("accept-encoding", "zstd"))
            .to_request();

        let resp = test::call_service(&app, req).await;

        // Should succeed with 200 OK
        assert!(resp.status().is_success());

        // Should have Content-Encoding: zstd header
        let content_encoding = resp
            .headers()
            .get("content-encoding")
            .and_then(|h| h.to_str().ok());
        assert_eq!(content_encoding, Some("zstd"));

        // Body should be compressed (we won't decompress in test, just verify it exists)
        let body = test::read_body(resp).await;
        assert!(!body.is_empty());
    }

    #[actix_web::test]
    async fn test_compression_with_explicit_identity() {
        let app = test::init_service(
            App::new()
                .wrap(compression_middleware())
                .service(
                    web::resource("/health").route(web::get().to(crate::services::rpc::health)),
                ),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/health")
            .insert_header(("accept-encoding", "identity"))
            .to_request();

        let resp = test::call_service(&app, req).await;

        // Should succeed with 200 OK
        assert!(resp.status().is_success());

        // Should NOT have Content-Encoding header (identity means no encoding)
        assert!(resp
            .headers()
            .get("content-encoding")
            .is_none());

        let body = test::read_body(resp).await;
        assert!(!body.is_empty());
    }
}
