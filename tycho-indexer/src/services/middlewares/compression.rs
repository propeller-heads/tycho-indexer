use actix_web::middleware;

/// Creates the compression middleware for RPC responses.
///
/// Enables zstd compression while being backwards compatible with clients that do not support it.
pub fn compression_middleware() -> middleware::Compress {
    middleware::Compress::default()
}

#[cfg(test)]
mod tests {
    use actix_web::{test, web, App};

    use super::*;

    #[actix_web::test]
    async fn test_no_encoding_header_returns_uncompressed() {
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

        assert!(resp.status().is_success());
        assert!(resp
            .headers()
            .get("content-encoding")
            .is_none());

        let body = test::read_body(resp).await;
        assert!(!body.is_empty());
    }

    #[actix_web::test]
    async fn test_zstd_encoding_header_returns_compressed() {
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

        assert!(resp.status().is_success());
        let content_encoding = resp
            .headers()
            .get("content-encoding")
            .and_then(|h| h.to_str().ok());
        assert_eq!(content_encoding, Some("zstd"));

        let body = test::read_body(resp).await;
        assert!(!body.is_empty());
    }

    #[actix_web::test]
    async fn test_identity_encoding_header_returns_uncompressed() {
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

        assert!(resp.status().is_success());
        assert!(resp
            .headers()
            .get("content-encoding")
            .is_none());

        let body = test::read_body(resp).await;
        assert!(!body.is_empty());
    }
}
