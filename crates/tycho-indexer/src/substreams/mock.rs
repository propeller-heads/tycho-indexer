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

use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use prost::Message;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{codegen::http, server::NamedService};

use crate::pb::sf::substreams::rpc::v3::Request;

type ResponseBody = BoxBody<bytes::Bytes, Infallible>;

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

impl tower::Service<http::Request<tonic::body::Body>> for MockSubstreamsServer {
    type Response = http::Response<ResponseBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let captured = self.captured.clone();
        Box::pin(async move {
            let collected = match req.into_body().collect().await {
                Ok(body) => body.to_bytes(),
                Err(_) => bytes::Bytes::new(),
            };

            // gRPC frame: 1 byte compressed flag + 4 bytes length + protobuf message
            if collected.len() > 5 {
                if let Ok(request) = Request::decode(&collected[5..]) {
                    captured.lock().unwrap().push(request);
                }
            }

            // Trailers-only gRPC OK → client sees an empty response stream
            let body: ResponseBody = Empty::<bytes::Bytes>::new()
                .map_err(|never| match never {})
                .boxed();
            Ok(http::Response::builder()
                .header("content-type", "application/grpc")
                .header("grpc-status", "0")
                .body(body)
                .unwrap())
        })
    }
}

/// Start a mock Substreams gRPC server on an ephemeral port.
///
/// Returns the captured requests and the address the server is listening on.
/// Hands the bound listener directly to tonic via `serve_with_incoming` so the
/// previous bind / drop / rebind window — and the 50 ms sleep that hid it — go
/// away.
pub async fn start_mock_substreams() -> (Arc<Mutex<Vec<Request>>>, SocketAddr) {
    let (server, captured) = MockSubstreamsServer::new();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock substreams server to 127.0.0.1:0");
    let addr = listener
        .local_addr()
        .expect("mock substreams listener has no local address");
    let incoming = TcpListenerStream::new(listener);

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(server)
            .serve_with_incoming(incoming)
            .await
            .unwrap_or_else(|err| panic!("mock substreams server on {addr} failed: {err}"));
    });

    (captured, addr)
}
