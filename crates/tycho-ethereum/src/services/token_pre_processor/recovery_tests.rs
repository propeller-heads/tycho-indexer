use std::{
    future::pending,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

use alloy::sol_types::SolValue;
use mockito::Server;
use serde_json::{json, Value};
use tycho_common::models::token::{TokenMetadataStatus, TokenOwnerStore};

use super::*;
use crate::rpc::config::RPCRetryConfig;

fn rpc_error_mock(code: i64, message: &'static str) -> impl Fn(&mockito::Request) -> Vec<u8> {
    move |request| {
        let calls: Vec<Value> = serde_json::from_slice(request.body().unwrap()).unwrap();
        serde_json::to_vec(
            &calls
                .iter()
                .map(|call| {
                    json!({
                        "jsonrpc": "2.0", "id": call["id"],
                        "error": {"code": code, "message": message}
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }
}

#[derive(Debug)]
struct HangingOwnerFinder {
    active: Arc<AtomicUsize>,
}

struct ActiveAttempt(Arc<AtomicUsize>);

impl Drop for ActiveAttempt {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl TokenOwnerFinding for HangingOwnerFinder {
    async fn find_owner(&self, token: Bytes, _: Bytes) -> Result<Option<(Bytes, Bytes)>, String> {
        // One token completes; every other token holds its concurrency slot until cancelled.
        if token == Address::repeat_byte(1).to_bytes() {
            return Ok(None);
        }
        self.active
            .fetch_add(1, Ordering::SeqCst);
        let _attempt = ActiveAttempt(self.active.clone());
        pending().await
    }
}

fn metadata_response(request: &Value) -> Value {
    let result =
        if request["params"][0]["input"] == Bytes::from(symbolCall {}.abi_encode()).to_string() {
            "TEST".abi_encode()
        } else {
            decimalsCall::abi_encode_returns(&6)
        };
    json!({"jsonrpc": "2.0", "id": request["id"], "result": Bytes::from(result)})
}

#[tokio::test]
async fn collection_deadline_preserves_completed_tokens_and_cancels_queued_work() {
    let mut server = Server::new_async().await;
    let _metadata = server
        .mock("POST", "/")
        .with_body_from_request(|request| {
            let calls: Vec<Value> = serde_json::from_slice(request.body().unwrap()).unwrap();
            serde_json::to_vec(
                &calls
                    .iter()
                    .map(metadata_response)
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        })
        .create_async()
        .await;
    let rpc = EthereumRpcClient::new(&server.url()).unwrap();
    let processor = EthereumTokenPreProcessor::new(&rpc, Chain::Ethereum, Address::ZERO)
        .with_enrichment_budget(Duration::from_millis(200));
    let active = Arc::new(AtomicUsize::new(0));
    let addresses: Vec<_> = (1..=12)
        .map(|id| Address::repeat_byte(id).to_bytes())
        .collect();
    let mut duplicated = addresses.clone();
    duplicated.push(addresses[0].clone());
    // A per-token timeout would need several waves, exceeding this outer bound.
    let tokens = tokio::time::timeout(
        Duration::from_millis(500),
        processor.get_tokens(
            duplicated,
            Arc::new(HangingOwnerFinder { active: active.clone() }),
            BlockTag::Latest,
        ),
    )
    .await
    .expect("the entire collection must share a deadline");
    assert_eq!(
        tokens
            .iter()
            .map(|t| t.address.clone())
            .collect::<Vec<_>>(),
        addresses
    );
    assert_eq!(tokens[0].metadata_status, TokenMetadataStatus::Ready);
    assert_eq!(tokens[0].decimals, 6);
    assert!(tokens[1..]
        .iter()
        .all(|t| t.metadata_status == TokenMetadataStatus::Pending));
    assert_eq!(active.load(Ordering::SeqCst), 0, "unfinished analyses must be dropped");
}

#[tokio::test]
async fn stalled_metadata_is_pending_even_when_analysis_finishes() {
    // Accepting a connection without sending headers stalls both batched metadata calls.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let rpc =
        EthereumRpcClient::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let processor = EthereumTokenPreProcessor::new(&rpc, Chain::Ethereum, Address::ZERO)
        .with_enrichment_budget(Duration::from_millis(20));
    let address = Address::repeat_byte(1).to_bytes();
    let tokens = tokio::time::timeout(
        Duration::from_millis(300),
        processor.get_tokens(
            vec![address],
            Arc::new(TokenOwnerStore::new(Default::default())),
            BlockTag::Latest,
        ),
    )
    .await
    .unwrap();
    assert_eq!(tokens[0].metadata_status, TokenMetadataStatus::Pending);
    assert_eq!(tokens[0].quality, 0);
}

#[tokio::test]
async fn strict_recovery_stays_pending_when_the_rpc_does_not_answer() {
    // A provider error that is neither transient nor a revert: the RPC did not evaluate the
    // call, so no fallback may be stored and the token must stay pending.
    let mut server = Server::new_async().await;
    let _failure = server
        .mock("POST", "/")
        .with_body_from_request(rpc_error_mock(-32601, "method not found"))
        .create_async()
        .await;
    let rpc = EthereumRpcClient::new(&server.url()).unwrap();
    let processor = EthereumTokenPreProcessor::new(&rpc, Chain::Ethereum, Address::ZERO);
    let result = processor
        .recover_token(
            Address::repeat_byte(1).to_bytes(),
            Arc::new(TokenOwnerStore::new(Default::default())),
            BlockTag::Latest,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn strict_recovery_uses_legacy_fallbacks_when_metadata_reverts() {
    // The contract answered and reverted: retrying later cannot change that, so the token gets
    // the same address symbol and 18 decimals the hot path always stored, and analysis
    // (no funded owner here) still decides the quality.
    let mut server = Server::new_async().await;
    let _revert = server
        .mock("POST", "/")
        .with_body_from_request(rpc_error_mock(3, "execution reverted"))
        .create_async()
        .await;
    let rpc = EthereumRpcClient::new(&server.url()).unwrap();
    let processor = EthereumTokenPreProcessor::new(&rpc, Chain::Ethereum, Address::ZERO);
    let address = Address::repeat_byte(1);
    let token = processor
        .recover_token(
            address.to_bytes(),
            Arc::new(TokenOwnerStore::new(Default::default())),
            BlockTag::Latest,
        )
        .await
        .expect("a revert is a definitive answer");
    assert_eq!(token.metadata_status, TokenMetadataStatus::Ready);
    assert_eq!(token.symbol, format!("0x{address:x}"));
    assert_eq!(token.decimals, 18);
    assert_eq!(token.quality, 10);
}

#[tokio::test]
async fn every_token_is_pending_when_all_requests_stall() {
    // More tokens than concurrency slots: the ones still queued when the deadline hits must
    // come back pending too, in input order.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let rpc =
        EthereumRpcClient::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let processor = EthereumTokenPreProcessor::new(&rpc, Chain::Ethereum, Address::ZERO)
        .with_enrichment_budget(Duration::from_millis(50));
    let addresses: Vec<_> = (1..=(MAX_CONCURRENT_TOKENS as u8 + 2))
        .map(|id| Address::repeat_byte(id).to_bytes())
        .collect();
    let tokens = tokio::time::timeout(
        Duration::from_millis(500),
        processor.get_tokens(
            addresses.clone(),
            Arc::new(TokenOwnerStore::new(Default::default())),
            BlockTag::Latest,
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        tokens
            .iter()
            .map(|t| t.address.clone())
            .collect::<Vec<_>>(),
        addresses
    );
    assert!(tokens
        .iter()
        .all(|t| t.metadata_status == TokenMetadataStatus::Pending));
}

#[tokio::test]
async fn deadline_covers_retry_backoff() {
    // A retryable transport error with a one-second backoff would exceed the budget several
    // times over. The deadline must cut through the backoff sleep, not wait for it.
    let mut server = Server::new_async().await;
    let _unavailable = server
        .mock("POST", "/")
        .with_status(503)
        .expect_at_least(1)
        .create_async()
        .await;
    let rpc = EthereumRpcClient::new(&server.url())
        .unwrap()
        .with_retry(RPCRetryConfig::new(3, 1_000, 1_000));
    let processor = EthereumTokenPreProcessor::new(&rpc, Chain::Ethereum, Address::ZERO)
        .with_enrichment_budget(Duration::from_millis(200));
    let started = Instant::now();
    let tokens = tokio::time::timeout(
        Duration::from_millis(700),
        processor.get_tokens(
            vec![Address::repeat_byte(1).to_bytes()],
            Arc::new(TokenOwnerStore::new(Default::default())),
            BlockTag::Latest,
        ),
    )
    .await
    .expect("budget must bound retry backoff");
    assert!(started.elapsed() < Duration::from_millis(700));
    assert_eq!(tokens[0].metadata_status, TokenMetadataStatus::Pending);
}
