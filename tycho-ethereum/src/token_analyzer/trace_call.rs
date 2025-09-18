use std::{cmp, str::FromStr, sync::Arc};

use anyhow::{bail, ensure, Context, Result};
use contracts::ERC20;
use ethcontract::{dyns::DynTransport, transaction::TransactionBuilder, PrivateKey};
use ethers::types::{H160, U256};
use ethrpc::Web3;
use tycho_common::{
    models::{
        blockchain::BlockTag,
        token::{TokenQuality, TransferCost, TransferTax},
    },
    traits::{TokenAnalyzer, TokenOwnerFinding},
    Bytes,
};
use web3::{
    signing::keccak256,
    types::{BlockNumber, BlockTrace, CallRequest, Res},
};

use crate::{token_analyzer::trace_many, BlockTagWrapper, BytesCodec};

/// Detects whether a token is "bad" (works in unexpected ways that are
/// problematic for solving) by simulating several transfers of a token. To find
/// an initial address to transfer from we use the amm pair providers.
/// Tokens are bad if:
/// - we cannot find an amm pool of the token to one of the base tokens
/// - transfer into the settlement contract or back out fails
/// - a transfer loses total balance
pub struct TraceCallDetector {
    pub web3: Web3,
    pub finder: Arc<dyn TokenOwnerFinding>,
    pub settlement_contract: H160,
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
            .detect_impl(H160::from_bytes(&token), BlockTagWrapper(block).into())
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
    pub fn new(url: &str, finder: Arc<dyn TokenOwnerFinding>) -> Self {
        Self {
            web3: Web3::new_from_url(url),
            finder,
            // middle contract used to check for fees, set to cowswap settlement
            settlement_contract: H160::from_str("0xc9f2e6ea1637E499406986ac50ddC92401ce1f58")
                .unwrap(),
        }
    }
    pub async fn detect_impl(
        &self,
        token: H160,
        block: BlockNumber,
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
                let amount = cmp::max(U256::from_bytes(&balance) / 2, MIN_AMOUNT.into());

                tracing::debug!(?token, ?address, ?amount, "found owner");
                (H160::from_bytes(&address), amount)
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
        let request =
            self.create_trace_request(token, amount, take_from, TraceRequestType::SimpleTransfer);
        let traces = trace_many::trace_many(request, &self.web3, block)
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

        let request = self.create_trace_request(
            token,
            amount,
            take_from,
            TraceRequestType::DoubleTransfer(middle_balance),
        );
        let traces = trace_many::trace_many(request, &self.web3, block)
            .await
            .map_err(|e| e.to_string())?;
        Self::handle_response(&traces, amount, middle_balance, take_from).map_err(|e| e.to_string())
    }

    // For the out transfer we use an arbitrary address without balance to detect
    // tokens that usually apply fees but not if the the sender or receiver is
    // specifically exempt like their own uniswap pools.
    fn arbitrary_recipient() -> H160 {
        PrivateKey::from_raw(keccak256(b"propeller"))
            .unwrap()
            .public_address()
    }

    fn create_trace_request(
        &self,
        token: H160,
        amount: U256,
        take_from: H160,
        request_type: TraceRequestType,
    ) -> Vec<CallRequest> {
        let instance = ERC20::at(&self.web3, token);

        let mut requests = Vec::new();

        // 0 Get balance of settlement_contract before
        let tx = instance
            .balance_of(self.settlement_contract)
            .m
            .tx;
        requests.push(call_request(None, token, tx));
        // 1 Transfer from take_from to settlement_contract
        let tx = instance
            .transfer(self.settlement_contract, amount)
            .tx;
        requests.push(call_request(Some(take_from), token, tx));
        // 2 Get balance of settlement_contract after
        let tx = instance
            .balance_of(self.settlement_contract)
            .m
            .tx;
        requests.push(call_request(None, token, tx));
        // 3 Get balance of arbitrary_recipient before
        let recipient = Self::arbitrary_recipient();
        let tx = instance.balance_of(recipient).m.tx;
        requests.push(call_request(None, token, tx));

        match request_type {
            TraceRequestType::SimpleTransfer => requests,
            TraceRequestType::DoubleTransfer(middle_amount) => {
                // 4 Transfer from settlement_contract to arbitrary_recipient
                let tx = instance
                    .transfer(recipient, middle_amount)
                    .tx;
                requests.push(call_request(Some(self.settlement_contract), token, tx));
                // 5 Get balance of settlement_contract after
                let tx = instance
                    .balance_of(self.settlement_contract)
                    .m
                    .tx;
                requests.push(call_request(None, token, tx));
                // 6 Get balance of arbitrary_recipient after
                let tx = instance.balance_of(recipient).m.tx;
                requests.push(call_request(None, token, tx));

                // 7 Approve max with settlement_contract
                let tx = instance
                    .approve(recipient, U256::MAX)
                    .tx;
                requests.push(call_request(Some(self.settlement_contract), token, tx));

                requests
            }
        }
    }

    fn handle_response(
        traces: &[BlockTrace],
        amount: U256,
        middle_amount: U256,
        take_from: H160,
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

        let gas_per_transfer = (gas_in + gas_out) / 2;

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
                (false, false) => U256::zero(),
            },
        )
    }
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

fn call_request(
    from: Option<H160>,
    to: H160,
    transaction: TransactionBuilder<DynTransport>,
) -> CallRequest {
    let calldata = transaction.data.unwrap();
    CallRequest { from, to: Some(to), data: Some(calldata), ..Default::default() }
}

/// Returns none if the length of the bytes in the trace output is not 32.
fn decode_u256(trace: &BlockTrace) -> Option<U256> {
    let bytes = trace.output.0.as_slice();
    if bytes.len() != 32 {
        return None;
    }
    Some(U256::from_big_endian(bytes))
}

// The outer result signals communication failure with the node.
// The inner result is Ok(gas_price) or Err if the transaction failed.
fn ensure_transaction_ok_and_get_gas(trace: &BlockTrace) -> Result<Result<U256, String>> {
    let transaction_traces = trace
        .trace
        .as_ref()
        .context("trace not set")?;
    let first = transaction_traces
        .first()
        .context("expected at least one trace")?;
    if let Some(error) = &first.error {
        return Ok(Err(format!("transaction failed: {error}")));
    }
    let call_result = match &first.result {
        Some(Res::Call(call)) => call,
        _ => bail!("no error but also no call result"),
    };
    Ok(Ok(call_result.gas_used))
}
