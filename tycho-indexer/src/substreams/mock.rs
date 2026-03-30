//! Generic mock for the Substreams Stream/Blocks gRPC service.
//!
//! Captures every `Request` protobuf sent by the client and returns an empty
//! stream (trailers-only `grpc-status: 0`), which makes `stream_blocks` yield
//! `BlockResponse::Ended` and the runner exit cleanly.
use std::{
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use prost::Message;
use tonic::{
    body::BoxBody,
    codegen::{http, Body as HttpBody},
    server::NamedService,
};

use crate::pb::sf::substreams::rpc::v3::Request;

/// Mock gRPC server that captures Substreams `Request` messages.
///
/// Implements `tower::Service` directly — no generated server code needed.
/// Every incoming request is decoded from the gRPC wire format and pushed into
/// [`captured`]. The response is always a trailers-only OK (empty stream).
#[derive(Clone)]
pub struct MockSubstreamsServer {
    captured: Arc<Mutex<Vec<Request>>>,
}

impl MockSubstreamsServer {
    fn new() -> (Self, Arc<Mutex<Vec<Request>>>) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        (Self { captured: captured.clone() }, captured)
    }
}

impl NamedService for MockSubstreamsServer {
    const NAME: &'static str = "sf.substreams.rpc.v3.Stream";
}

impl tonic::codegen::Service<http::Request<tonic::transport::Body>> for MockSubstreamsServer {
    type Response = http::Response<BoxBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::transport::Body>) -> Self::Future {
        let captured = self.captured.clone();
        Box::pin(async move {
            // Collect the request body using http_body::Body::poll_data
            let mut body = req.into_body();
            let mut buf = Vec::new();
            while let Some(chunk) =
                std::future::poll_fn(|cx| Pin::new(&mut body).poll_data(cx)).await
            {
                if let Ok(data) = chunk {
                    buf.extend_from_slice(&data);
                }
            }

            // gRPC frame: 1 byte compressed flag + 4 bytes length + protobuf message
            if buf.len() > 5 {
                if let Ok(request) = Request::decode(&buf[5..]) {
                    captured.lock().unwrap().push(request);
                }
            }

            // Trailers-only gRPC OK → client sees an empty response stream
            Ok(http::Response::builder()
                .header("content-type", "application/grpc")
                .header("grpc-status", "0")
                .body(BoxBody::default())
                .unwrap())
        })
    }
}

/// Start a mock Substreams gRPC server on an ephemeral port.
///
/// Returns the captured requests and the address the server is listening on.
pub async fn start_mock_substreams() -> (Arc<Mutex<Vec<Request>>>, SocketAddr) {
    let (server, captured) = MockSubstreamsServer::new();

    // Bind to find an available port, then release so tonic can rebind.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(server)
            .serve(addr)
            .await
            .unwrap();
    });

    // Give the server a moment to bind
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (captured, addr)
}
