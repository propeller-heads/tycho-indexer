use std::time::Instant;

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    HttpResponse,
};
use metrics::{counter, histogram};
use tracing::instrument;

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

    // Clone the ServiceRequest for the error path.
    // `ServiceRequest` implements `Clone` in actix-web 4.
    let req_for_error = req.request().clone();

    // call next
    let res = next.call(req).await;

    let resp = match res {
        Ok(srv_res) => {
            let typed_res = srv_res.map_into_boxed_body();
            Ok(typed_res)
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

            // build an HttpResponse from the error and wrap into ServiceResponse
            let response: HttpResponse = resp_e.error_response();
            let srv_res = ServiceResponse::new(req_for_error, response);

            Ok(srv_res)
        }
    };

    histogram!(
        "rpc_request_duration_seconds",
        "endpoint" => endpoint.clone(),
    )
    .record(start.elapsed().as_millis() as f64);

    resp
}
