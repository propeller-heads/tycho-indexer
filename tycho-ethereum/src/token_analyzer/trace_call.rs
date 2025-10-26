use std::{cmp, sync::Arc};

use alloy::{
    primitives::{keccak256, Address, U256},
    rpc::{
        client::{ClientBuilder, ReqwestClient},
        types::{
            trace::parity::{TraceOutput, TraceResults},
            TransactionInput, TransactionRequest,
        },
    },
};
use anyhow::{bail, ensure, Context, Result};
use tycho_common::{
    models::{
        blockchain::BlockTag,
        token::{TokenQuality, TransferCost, TransferTax},
    },
    traits::{TokenAnalyzer, TokenOwnerFinding},
    Bytes,
};

use crate::{
    erc20::{encode_approve, encode_balance_of, encode_transfer},
    token_analyzer::trace_many,
    BytesCodec,
};

/// Detects whether a token is "bad" (works in unexpected ways that are
/// problematic for solving) by simulating several transfers of a token. To find
/// an initial address to transfer from we use the amm pair providers.
/// Tokens are bad if:
/// - we cannot find an amm pool of the token to one of the base tokens
/// - transfer into the settlement contract or back out fails
/// - a transfer loses total balance
pub struct TraceCallDetector {
    pub rpc: ReqwestClient,
    pub finder: Arc<dyn TokenOwnerFinding>,
    pub settlement_contract: Address,
}

#[async_trait::async_trait]
impl TokenAnalyzer for TraceCallDetector {
    type Error = String;

    async fn analyze(
        &self,
        token: Bytes,
        block: BlockTag,
    ) -> std::result::Result<(TokenQuality, Option<TransferCost>, Option<TransferTax>), String>
    {
        let (quality, transfer_cost, tax) = self
            .detect_impl(Address::from_bytes(&token), block)
            .await
            .map_err(|e| e.to_string())?;
        tracing::debug!(?token, ?quality, "determined token quality");
        Ok((
            quality,
            transfer_cost.map(|cost| cost.try_into().unwrap_or(8_000_000)),
            tax.map(|cost| cost.try_into().unwrap_or(10_000)),
        ))
    }
}

enum TraceRequestType {
    SimpleTransfer,
    DoubleTransfer(U256),
}

impl TraceCallDetector {
    pub fn new_from_url(rpc_url: &str, finder: Arc<dyn TokenOwnerFinding>) -> Self {
        let url = rpc_url
            .parse()
            .expect("Invalid RPC URL");
        let client = ClientBuilder::default().http(url);
        Self::new(client, finder)
    }

    pub fn new(rpc: ReqwestClient, finder: Arc<dyn TokenOwnerFinding>) -> Self {
        Self {
            rpc,
            finder,
            // middle contract used to check for fees, set to cowswap settlement
            settlement_contract: "0xc9f2e6ea1637E499406986ac50ddC92401ce1f58"
                .parse()
                .unwrap(),
        }
    }

    pub async fn detect_impl(
        &self,
        token: Address,
        block: BlockTag,
    ) -> Result<(TokenQuality, Option<U256>, Option<U256>), String> {
        // Arbitrary amount that is large enough that small relative fees should be
        // visible.
        const MIN_AMOUNT: u64 = 100_000;
        let (take_from, amount) = match self
            .finder
            .find_owner(token.to_bytes(), MIN_AMOUNT.into())
            .await
            .map_err(|e| e.to_string())?
        {
            Some((address, balance)) => {
                // Don't use the full balance, but instead a portion of it. This
                // makes the trace call less racy and prone to the transfer
                // failing because of a balance change from one block to the
                // next. This can happen because of either:
                // - Block propagation - the trace_callMany is handled by a node that is 1 block in
                //   the past
                // - New block observed - the trace_callMany is executed on a block that came in
                //   since we read the balance
                let amount = cmp::max(
                    U256::from_be_bytes::<32>(
                        balance
                            .lpad(32, 0)
                            .as_ref()
                            .try_into()
                            .expect("balance should be 32 bytes"),
                    ) / U256::from(2),
                    U256::from(MIN_AMOUNT),
                );

                tracing::debug!(?token, ?address, ?amount, "found owner");
                (Address::from_bytes(&address), amount)
            }
            None => {
                return Ok((
                    TokenQuality::bad(format!(
                        "Could not find on chain source of the token with at least {MIN_AMOUNT} \
                     balance.",
                    )),
                    None,
                    None,
                ))
            }
        };

        // We transfer the full available amount of the token from the amm pool into the
        // settlement contract and then to an arbitrary address.
        // Note that gas use can depend on the recipient because for the standard
        // implementation sending to an address that does not have any balance
        // yet (implicitly 0) causes an allocation.
        let request = self
            .create_trace_request(token, amount, take_from, TraceRequestType::SimpleTransfer)
            .map_err(|e| e.to_string())?;
        let traces = trace_many::trace_many(request, &self.rpc, block)
            .await
            .map_err(|e| e.to_string())?;

        let message = "\
        Failed to decode the token's balanceOf response because it did not \
        return 32 bytes. A common cause of this is a bug in the Vyper \
        smart contract compiler. See \
        https://github.com/cowprotocol/services/pull/781 for more \
        information.\
        ";
        let bad = TokenQuality::Bad { reason: message.to_string() };
        let middle_balance = match decode_u256(&traces[2]) {
            Some(balance) => balance,
            None => return Ok((bad, None, None)),
        };

        let request = self
            .create_trace_request(
                token,
                amount,
                take_from,
                TraceRequestType::DoubleTransfer(middle_balance),
            )
            .map_err(|e| e.to_string())?;
        let traces = trace_many::trace_many(request, &self.rpc, block)
            .await
            .map_err(|e| e.to_string())?;
        Self::handle_response(&traces, amount, middle_balance, take_from).map_err(|e| e.to_string())
    }

    // For the out transfer we use an arbitrary address without balance to detect
    // tokens that usually apply fees but not if the the sender or receiver is
    // specifically exempt like their own uniswap pools.
    fn arbitrary_recipient() -> Address {
        // Create a deterministic address from hash
        let hash = keccak256(b"propeller");
        Address::from_slice(&hash[..20])
    }

    fn create_trace_request(
        &self,
        token: Address,
        amount: U256,
        take_from: Address,
        request_type: TraceRequestType,
    ) -> Result<Vec<TransactionRequest>, Box<dyn std::error::Error + Send + Sync>> {
        let mut requests = Vec::new();

        // 0 Get balance of settlement_contract before
        let calldata = encode_balance_of(self.settlement_contract);
        requests.push(call_request(None, token, calldata));

        // 1 Transfer from take_from to settlement_contract
        let calldata = encode_transfer(self.settlement_contract, amount);
        requests.push(call_request(Some(take_from), token, calldata));

        // 2 Get balance of settlement_contract after
        let calldata = encode_balance_of(self.settlement_contract);
        requests.push(call_request(None, token, calldata));

        // 3 Get balance of arbitrary_recipient before
        let recipient = Self::arbitrary_recipient();
        let calldata = encode_balance_of(recipient);
        requests.push(call_request(None, token, calldata));

        match request_type {
            TraceRequestType::SimpleTransfer => Ok(requests),
            TraceRequestType::DoubleTransfer(middle_amount) => {
                // 4 Transfer from settlement_contract to arbitrary_recipient
                let calldata = encode_transfer(recipient, middle_amount);
                requests.push(call_request(Some(self.settlement_contract), token, calldata));

                // 5 Get balance of settlement_contract after
                let calldata = encode_balance_of(self.settlement_contract);
                requests.push(call_request(None, token, calldata));

                // 6 Get balance of arbitrary_recipient after
                let calldata = encode_balance_of(recipient);
                requests.push(call_request(None, token, calldata));

                // 7 Approve max with settlement_contract
                let calldata = encode_approve(recipient, U256::MAX);
                requests.push(call_request(Some(self.settlement_contract), token, calldata));

                Ok(requests)
            }
        }
    }

    fn handle_response(
        traces: &[TraceResults],
        amount: U256,
        middle_amount: U256,
        take_from: Address,
    ) -> Result<(TokenQuality, Option<U256>, Option<U256>)> {
        ensure!(traces.len() == 8, "unexpected number of traces");

        let gas_in = match ensure_transaction_ok_and_get_gas(&traces[1])? {
            Ok(gas) => gas,
            Err(reason) => {
                return Ok((
                    TokenQuality::bad(format!(
                        "Transfer of token from on chain source {take_from:?} into settlement \
                     contract failed: {reason}"
                    )),
                    None,
                    None,
                ))
            }
        };
        let arbitrary = Self::arbitrary_recipient();
        let gas_out = match ensure_transaction_ok_and_get_gas(&traces[4])? {
            Ok(gas) => gas,
            Err(reason) => {
                return Ok((
                    TokenQuality::bad(format!(
                        "Transfer token out of settlement contract to arbitrary recipient \
                     {arbitrary:?} failed: {reason}",
                    )),
                    None,
                    None,
                ))
            }
        };

        let gas_per_transfer = (gas_in + gas_out) / U256::from(2);

        let message = "\
            Failed to decode the token's balanceOf response because it did not \
            return 32 bytes. A common cause of this is a bug in the Vyper \
            smart contract compiler. See \
            https://github.com/cowprotocol/services/pull/781 for more \
            information.\
        ";
        let bad = TokenQuality::Bad { reason: message.to_string() };
        let balance_before_in = match decode_u256(&traces[0]) {
            Some(balance) => balance,
            None => return Ok((bad, Some(gas_per_transfer), None)),
        };
        let balance_after_in = match decode_u256(&traces[2]) {
            Some(balance) => balance,
            None => return Ok((bad, Some(gas_per_transfer), None)),
        };
        let balance_after_out = match decode_u256(&traces[5]) {
            Some(balance) => balance,
            None => return Ok((bad, Some(gas_per_transfer), None)),
        };
        let balance_recipient_before = match decode_u256(&traces[3]) {
            Some(balance) => balance,
            None => return Ok((bad, Some(gas_per_transfer), None)),
        };
        let balance_recipient_after = match decode_u256(&traces[6]) {
            Some(balance) => balance,
            None => return Ok((bad, Some(gas_per_transfer), None)),
        };

        let fees = Self::calculate_fee(
            amount,
            middle_amount,
            balance_before_in,
            balance_after_in,
            balance_recipient_before,
            balance_recipient_after,
        );

        tracing::debug!(%amount, %balance_before_in, %balance_after_in, %balance_after_out);

        // todo: Maybe do >= checks in case token transfer for whatever reason grants
        // user more than an amount transferred like an anti fee.

        let fees = match fees {
            Ok(f) => f,
            Err(e) => {
                return Ok((
                    TokenQuality::bad(format!("Failed to calculate fees for token transfer: {e}")),
                    None,
                    None,
                ))
            }
        };

        let computed_balance_after_in = match balance_before_in.checked_add(amount) {
            Some(amount) => amount,
            None => {
                return Ok((
                    TokenQuality::bad(format!(
                    "Transferring {amount} into settlement contract would overflow its balance."
                )),
                    Some(gas_per_transfer),
                    Some(fees),
                ))
            }
        };
        if balance_after_in != computed_balance_after_in {
            return Ok((
                TokenQuality::bad(format!(
                    "Transferring {amount} into settlement contract was expected to result in a \
                 balance of {computed_balance_after_in} but actually resulted in \
                 {balance_after_in}. A common cause for this is that the token takes a fee on \
                 transfer."
                )),
                Some(gas_per_transfer),
                Some(fees),
            ));
        }
        if balance_after_out != balance_before_in {
            return Ok((
                TokenQuality::bad(format!(
                "Transferring {amount} out of settlement contract was expected to result in the \
                 original balance of {balance_before_in} but actually resulted in \
                 {balance_after_out}."
            )),
                Some(gas_per_transfer),
                Some(fees),
            ));
        }
        let computed_balance_recipient_after = match balance_recipient_before.checked_add(amount) {
            Some(amount) => amount,
            None => {
                return Ok((
                    TokenQuality::bad(format!(
                    "Transferring {amount} into arbitrary recipient {arbitrary:?} would overflow \
                     its balance."
                )),
                    Some(gas_per_transfer),
                    Some(fees),
                ))
            }
        };
        if computed_balance_recipient_after != balance_recipient_after {
            return Ok((
                TokenQuality::bad(format!(
                    "Transferring {amount} into arbitrary recipient {arbitrary:?} was expected to \
                 result in a balance of {computed_balance_recipient_after} but actually resulted \
                 in {balance_recipient_after}. A common cause for this is that the token takes a \
                 fee on transfer."
                )),
                Some(gas_per_transfer),
                Some(fees),
            ));
        }

        if let Err(err) = ensure_transaction_ok_and_get_gas(&traces[7])? {
            return Ok((
                TokenQuality::bad(format!("Approval of U256::MAX failed: {err}")),
                Some(gas_per_transfer),
                Some(fees),
            ));
        }

        Ok((TokenQuality::Good, Some(gas_per_transfer), Some(fees)))
    }

    fn calculate_fee(
        amount: U256,
        middle_amount: U256,
        balance_before_in: U256,
        balance_after_in: U256,
        balance_recipient_before: U256,
        balance_recipient_after: U256,
    ) -> Result<U256, anyhow::Error> {
        Ok(
            match (
                balance_after_in != error_add(balance_before_in, amount)?,
                balance_recipient_after != error_add(balance_recipient_before, middle_amount)?,
            ) {
                (true, true) => {
                    let first_transfer_fees = error_div(
                        error_mul(
                            error_add(balance_before_in, error_sub(amount, balance_after_in)?)?,
                            U256::from(10_000),
                        )?,
                        amount,
                    )?;
                    let second_transfer_fees = error_div(
                        error_mul(
                            error_add(
                                balance_recipient_before,
                                error_sub(middle_amount, balance_recipient_after)?,
                            )?,
                            U256::from(10_000),
                        )?,
                        middle_amount,
                    )?;
                    if first_transfer_fees >= second_transfer_fees {
                        first_transfer_fees
                    } else {
                        second_transfer_fees
                    }
                }
                (true, false) => error_div(
                    error_mul(
                        error_add(balance_before_in, error_sub(amount, balance_after_in)?)?,
                        U256::from(10_000),
                    )?,
                    amount,
                )?,
                (false, true) => error_div(
                    error_mul(
                        error_add(
                            balance_recipient_before,
                            error_sub(middle_amount, balance_recipient_after)?,
                        )?,
                        U256::from(10_000),
                    )?,
                    middle_amount,
                )?,
                (false, false) => U256::ZERO,
            },
        )
    }
}

fn call_request(from: Option<Address>, to: Address, calldata: Vec<u8>) -> TransactionRequest {
    let mut req = TransactionRequest::default()
        .to(to)
        .input(TransactionInput::both(calldata.into()));

    if let Some(addr) = from {
        req = req.from(addr);
    }

    req
}

fn error_add(a: U256, b: U256) -> Result<U256, anyhow::Error> {
    a.checked_add(b)
        .ok_or_else(|| anyhow::format_err!("overflow"))
}

fn error_sub(a: U256, b: U256) -> Result<U256, anyhow::Error> {
    a.checked_sub(b)
        .ok_or_else(|| anyhow::format_err!("overflow"))
}

fn error_div(a: U256, b: U256) -> Result<U256, anyhow::Error> {
    a.checked_div(b)
        .ok_or_else(|| anyhow::format_err!("overflow"))
}

fn error_mul(a: U256, b: U256) -> Result<U256, anyhow::Error> {
    a.checked_mul(b)
        .ok_or_else(|| anyhow::format_err!("overflow"))
}

/// Returns none if the length of the bytes in the trace output is not 32.
fn decode_u256(trace: &TraceResults) -> Option<U256> {
    let bytes = trace.output.iter().as_slice();
    if bytes.len() != 32 {
        return None;
    }
    Some(U256::from_be_bytes::<32>(bytes.try_into().unwrap()))
}

// The outer result signals communication failure with the node.
// The inner result is Ok(gas_price) or Err if the transaction failed.
fn ensure_transaction_ok_and_get_gas(trace: &TraceResults) -> Result<Result<U256, String>> {
    let transaction_traces = &trace.trace;
    let first = transaction_traces
        .first()
        .context("expected at least one trace")?;
    if let Some(error) = &first.error {
        return Ok(Err(format!("transaction failed: {error}")));
    }
    let call_result = match &first.result {
        Some(TraceOutput::Call(call)) => call,
        _ => bail!("no error but also no call result"),
    };
    Ok(Ok(U256::from(call_result.gas_used)))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, env, str::FromStr, sync::Arc};

    use alloy::primitives::Address;
    use tycho_common::{models::token::TokenOwnerStore, Bytes};

    use super::*;

    #[tokio::test]
    #[ignore = "This test requires real RPC connection"]
    async fn test_detect_impl_usdc() {
        let rpc_url = env::var("RPC_URL").expect("RPC_URL environment variable must be set");

        // USDC mainnet address
        let usdc_address = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();

        // Using USV4 pool manager
        let holder = Bytes::from_str("0x000000000004444c5dc75cB358380D2e3dE08A90").unwrap();
        let large_balance = Bytes::from_str("0x43f6e8f16703").unwrap(); // Large balance

        let token_finder = TokenOwnerStore::new(HashMap::from([(
            usdc_address.to_bytes(),
            (holder, large_balance),
        )]));

        let detector = TraceCallDetector::new_from_url(&rpc_url, Arc::new(token_finder));

        // Test with the latest block
        let result = detector
            .detect_impl(usdc_address, BlockTag::Number(23475728))
            .await;

        match result {
            Ok((quality, gas_cost, transfer_tax)) => {
                println!("USDC Analysis Results:");
                println!("  Quality: {:?}", quality);
                println!("  Gas Cost: {:?}", gas_cost);
                println!("  Transfer Tax: {:?}", transfer_tax);

                // USDC should be a good token (no fees, standard behavior)
                assert!(matches!(quality, TokenQuality::Good));
                assert!(gas_cost.is_some());
                assert!(transfer_tax.is_some());

                // USDC should have 0 transfer tax
                if let Some(tax) = transfer_tax {
                    assert_eq!(tax, U256::ZERO, "USDC should not have transfer fees");
                }
            }
            Err(e) => {
                panic!("Failed to analyze USDC: {}", e);
            }
        }
    }
}
