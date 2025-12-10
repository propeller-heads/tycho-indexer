use std::time::Instant;

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::{self, Next},
};
use metrics::{counter, histogram};
use tracing::instrument;
use tycho_common::dto::{self, PaginationLimits};

use crate::services::{rpc::RpcError, RpcConfig};

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

/// Validates pagination limits with compression-aware maximums.
pub trait RequestPaginationValidation: PaginationLimits {
    fn validate_pagination(
        &self,
        req: &actix_web::HttpRequest,
    ) -> Result<(), super::rpc::RpcError> {
        let page_size = self.pagination().page_size;

        let supports_compression = req
            .headers()
            .get("accept-encoding")
            .and_then(|h| h.to_str().ok())
            .map(|enc| enc.contains("zstd"))
            .unwrap_or(false);

        let max_allowed = Self::effective_max_page_size(supports_compression);

        if page_size > max_allowed {
            Err(super::rpc::RpcError::Pagination(max_allowed as usize))
        } else {
            Ok(())
        }
    }
}

impl<T: PaginationLimits> RequestPaginationValidation for T {}

/// Trait for validating filter parameters on RPC requests to prevent overly broad queries.
///
/// Request types implement this trait to define their validation logic against
/// configured thresholds. Validation happens at the endpoint level before cache lookups
/// or database queries, enabling early rejection of invalid requests.
pub trait ValidateFilter {
    /// Validates the filter parameters against the provided RPC configuration.
    ///
    /// # Errors
    /// Returns `RpcError::MinimumFilterNotMet` if the request doesn't meet filtering requirements.
    fn validate_filter(&self, config: &RpcConfig) -> Result<(), RpcError>;
}

/// Validation implementation for protocol components requests.
///
/// When `min_component_tvl` is configured, clients must either:
/// - Provide specific `component_ids`, OR
/// - Include a `tvl_gt` parameter that meets or exceeds the minimum threshold
impl ValidateFilter for dto::ProtocolComponentsRequestBody {
    fn validate_filter(&self, config: &RpcConfig) -> Result<(), RpcError> {
        // Allow requests with specific component IDs (targeted queries don't cause broad scans)
        if self.component_ids.is_some() {
            return Ok(());
        }
        match (config.min_component_tvl(), self.tvl_gt) {
            (Some(min_tvl), None) => Err(RpcError::MinimumFilterNotMet(
                "/protocol_components".to_string(),
                format!(
                    "tvl_gt parameter is required (minimum: {}) to prevent overly broad queries. \
                     Alternatively, specify component_ids for targeted queries.",
                    min_tvl
                ),
            )),
            (Some(min_tvl), Some(requested_tvl)) if requested_tvl < min_tvl => {
                Err(RpcError::MinimumFilterNotMet(
                    "/protocol_components".to_string(),
                    format!(
                        "tvl_gt must be at least {} (requested: {}) to prevent overly broad queries. \
                         Alternatively, specify component_ids for targeted queries.",
                        min_tvl, requested_tvl
                    ),
                ))
            }
            _ => Ok(()),
        }
    }
}

/// Validation implementation for tokens requests.
///
/// When `min_token_quality` is configured, clients must either:
/// - Provide specific `token_addresses`, OR
/// - Include a `min_quality` parameter that meets or exceeds the minimum threshold
impl ValidateFilter for dto::TokensRequestBody {
    fn validate_filter(&self, config: &RpcConfig) -> Result<(), RpcError> {
        // Allow requests with specific token addresses (targeted queries don't cause broad scans)
        if self.token_addresses.is_some() {
            return Ok(());
        }
        match (config.min_token_quality(), self.min_quality) {
            (Some(min_quality), None) => Err(RpcError::MinimumFilterNotMet(
                "/tokens".to_string(),
                format!(
                    "min_quality parameter is required (minimum: {}) to prevent overly broad queries. \
                     Alternatively, specify token_addresses for targeted queries.",
                    min_quality
                ),
            )),
            (Some(min_quality), Some(requested_quality)) if requested_quality < min_quality => {
                Err(RpcError::MinimumFilterNotMet(
                    "/tokens".to_string(),
                    format!(
                        "min_quality must be at least {} (requested: {}) to prevent overly broad queries. \
                         Alternatively, specify token_addresses for targeted queries.",
                        min_quality, requested_quality
                    ),
                ))
            }
            _ => Ok(()),
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
    use rstest::rstest;
    use tycho_common::{dto::PaginationParams, Bytes};

    use super::*;
    use crate::services::rpc::RpcError;

    // Test struct for pagination validation
    #[derive(Clone)]
    struct TestPaginationRequest {
        pagination: PaginationParams,
    }

    // Define constants that match TestPaginationRequest implementation
    const MAX_PAGE_SIZE_UNCOMPRESSED: i64 = 100;
    const MAX_PAGE_SIZE_COMPRESSED: i64 = 200;

    impl PaginationLimits for TestPaginationRequest {
        const MAX_PAGE_SIZE_COMPRESSED: i64 = MAX_PAGE_SIZE_COMPRESSED;
        const MAX_PAGE_SIZE_UNCOMPRESSED: i64 = MAX_PAGE_SIZE_UNCOMPRESSED;

        fn pagination(&self) -> &PaginationParams {
            &self.pagination
        }
    }

    #[rstest]
    #[case::at_uncompressed_limit(MAX_PAGE_SIZE_UNCOMPRESSED, None, true)]
    #[case::over_uncompressed_limit(MAX_PAGE_SIZE_UNCOMPRESSED + 1, None, false)]
    #[case::over_uncompressed_with_zstd(MAX_PAGE_SIZE_UNCOMPRESSED + 1, Some("zstd"), true)]
    #[case::at_compressed_limit_with_zstd(MAX_PAGE_SIZE_COMPRESSED, Some("zstd"), true)]
    #[case::over_compressed_limit_with_zstd(MAX_PAGE_SIZE_COMPRESSED + 1, Some("zstd"), false)]
    #[case::over_uncompressed_with_gzip(MAX_PAGE_SIZE_UNCOMPRESSED + 1, Some("gzip"), false)]
    #[case::over_uncompressed_with_multiple_encodings(
        MAX_PAGE_SIZE_UNCOMPRESSED + 1,
        Some("gzip, zstd, br"),
        true
    )]
    #[actix_web::test]
    async fn test_pagination_validation(
        #[case] page_size: i64,
        #[case] accept_encoding: Option<&str>,
        #[case] should_pass: bool,
    ) {
        let request = TestPaginationRequest { pagination: PaginationParams { page: 0, page_size } };

        let mut req_builder = test::TestRequest::get();
        if let Some(encoding) = accept_encoding {
            req_builder = req_builder.insert_header(("accept-encoding", encoding));
        }
        let req = req_builder.to_http_request();

        let result = request.validate_pagination(&req);

        if should_pass {
            assert!(result.is_ok(), "Expected validation to pass for page_size={page_size}, encoding={accept_encoding:?}");
        } else {
            assert!(result.is_err(), "Expected validation to fail for page_size={page_size}, encoding={accept_encoding:?}");

            if let Err(RpcError::Pagination(limit)) = result {
                let has_zstd = accept_encoding.is_some_and(|e| e.contains("zstd"));
                let expected_limit = if has_zstd {
                    MAX_PAGE_SIZE_COMPRESSED as usize
                } else {
                    MAX_PAGE_SIZE_UNCOMPRESSED as usize
                };
                assert_eq!(limit, expected_limit, "Wrong limit reported");
            }
        }
    }

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

    #[rstest]
    #[case::rejects_none_when_min_tvl_set(
        Some(1000.0),
        None,
        false,
        Some("tvl_gt parameter is required")
    )]
    #[case::rejects_below_threshold(
        Some(1000.0),
        Some(500.0),
        false,
        Some("tvl_gt must be at least")
    )]
    #[case::accepts_equal_threshold(Some(1000.0), Some(1000.0), true, None)]
    #[case::accepts_above_threshold(Some(1000.0), Some(5000.0), true, None)]
    #[case::accepts_none_when_no_min_tvl(None, None, true, None)]
    #[case::accepts_any_value_when_no_min_tvl(None, Some(100.0), true, None)]
    #[tokio::test]
    async fn test_min_tvl_validation(
        #[case] min_tvl: Option<f64>,
        #[case] request_tvl_gt: Option<f64>,
        #[case] should_succeed: bool,
        #[case] error_message_contains: Option<&str>,
    ) {
        let config = RpcConfig::new().with_min_tvl(min_tvl);

        let request = dto::ProtocolComponentsRequestBody {
            protocol_system: "ambient".to_string(),
            component_ids: None,
            tvl_gt: request_tvl_gt,
            chain: dto::Chain::Ethereum,
            pagination: dto::PaginationParams::new(0, 10),
        };

        // Test validation trait method directly (called at endpoint level before cache lookup)
        let result = request.validate_filter(&config);

        if should_succeed {
            assert!(result.is_ok(), "Expected success but got error: {:?}", result);
        } else {
            assert!(result.is_err(), "Expected error but got success");
            let err = result.unwrap_err();
            assert!(matches!(err, RpcError::MinimumFilterNotMet(_, _)));
            if let Some(msg) = error_message_contains {
                assert!(
                    err.to_string().contains(msg),
                    "Error message '{}' does not contain '{}'",
                    err,
                    msg
                );
            }
        }
    }

    #[rstest]
    #[case::rejects_none_when_min_quality_set(
        Some(50),
        None,
        None,
        false,
        Some("min_quality parameter is required")
    )]
    #[case::rejects_below_threshold(
        Some(50),
        Some(30),
        None,
        false,
        Some("min_quality must be at least")
    )]
    #[case::accepts_equal_threshold(Some(50), Some(50), None, true, None)]
    #[case::accepts_above_threshold(Some(50), Some(80), None, true, None)]
    #[case::accepts_none_when_no_min_quality(None, None, None, true, None)]
    #[case::accepts_any_value_when_no_min_quality(None, Some(10), None, true, None)]
    #[case::accepts_specific_addresses_without_quality(
        Some(50),
        None,
        Some(vec![Bytes::from("0x0123")]),
        true,
        None
    )]
    #[tokio::test]
    async fn test_min_token_quality_validation(
        #[case] min_token_quality: Option<i32>,
        #[case] request_min_quality: Option<i32>,
        #[case] token_addresses: Option<Vec<Bytes>>,
        #[case] should_succeed: bool,
        #[case] error_message_contains: Option<&str>,
    ) {
        let config = RpcConfig::new().with_min_quality(min_token_quality);

        let request = dto::TokensRequestBody {
            chain: dto::Chain::Ethereum,
            token_addresses,
            min_quality: request_min_quality,
            traded_n_days_ago: None,
            pagination: dto::PaginationParams::new(0, 10),
        };

        // Test validation trait method directly (called at endpoint level before cache lookup)
        let result = request.validate_filter(&config);

        if should_succeed {
            assert!(result.is_ok(), "Expected success but got error: {:?}", result);
        } else {
            assert!(result.is_err(), "Expected error but got success");
            let err = result.unwrap_err();
            assert!(matches!(err, RpcError::MinimumFilterNotMet(_, _)));
            if let Some(msg) = error_message_contains {
                assert!(
                    err.to_string().contains(msg),
                    "Error message '{}' does not contain '{}'",
                    err,
                    msg
                );
            }
        }
    }
}
