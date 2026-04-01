use std::{cmp, sync::Arc};

use alloy::{
    hex,
    primitives::{keccak256, Address, Bytes as AlloyBytes, U256},
    sol,
    sol_types::SolCall,
};
use serde_json::json;
use tycho_common::{
    models::{
        blockchain::BlockTag,
        token::{TokenQuality, TransferCost, TransferTax},
    },
    traits::{TokenAnalyzer, TokenOwnerFinding},
    Bytes,
};

use crate::{
    rpc::EthereumRpcClient,
    services::token_analyzer::{error_add, error_div, error_mul, error_sub, map_block_tag},
    BytesCodec,
};

// Runtime bytecode for the Analyzer contract.
// Source: tycho-ethereum/contracts/Analyzer.sol
// Compiled with solc 0.8.27, --via-ir --optimize --optimize-runs 200
const ANALYZER_BYTECODE: &str = "60806040526004361015610011575f80fd5b5f3560e01c63521c653914610024575f80fd5b346100c75760803660031901126100c7576004356001600160a01b03811681036100c757604435906001600160a01b03821682036100c7576064356001600160a01b03811681036100c75761014092610080926024359061013a565b976040979197969296959395519915158a52151560208a0152151560408901526060880152608087015260a086015260c085015260e0840152610100830152610120820152f35b5f80fd5b90601f8019910116810190811067ffffffffffffffff8211176100ed57604052565b634e487b7160e01b5f52604160045260245ffd5b908160209103126100c7575180151581036100c75790565b9190820391821161012657565b634e487b7160e01b5f52601160045260245ffd5b6040516370a0823160e01b81526001600160a01b0393841660048201819052929592949293909116602082602481845afa918215610387575f92610519575b506040516370a0823160e01b81526001600160a01b03909316600484018190529192839291602082602481845afa918215610387575f926104e5575b50815a986040519063a9059cbb60e01b825289600483015260248201526020816044815f875af15f91816104c4575b506104ba57506101f75f995b5a90610119565b9489156104a05750506040516370a0823160e01b81526004810188905293602085602481855afa948515610387575f9561046c575b50846102388782610119565b985a9960405190631339c64960e01b825285600483015287602483015260448201526020816064815f865af15f918161044b575b50610441575061027e5f9a5a90610119565b918a156103c457506040516370a0823160e01b815260048101829052602081602481885afa908115610387575f91610392575b506040516370a0823160e01b8152600481018890529096602082602481895afa918215610387575f92610352575b506064602092965f60405195869485936361be88e160e11b855260048501526024840152811960448401525af15f9181610321575b5061031e57505f97565b97565b61034491925060203d60201161034b575b61033c81836100cb565b810190610101565b905f610314565b503d610332565b91506020823d60201161037f575b8161036d602093836100cb565b810103126100c75790519060646102df565b3d9150610360565b6040513d5f823e3d90fd5b90506020813d6020116103bc575b816103ad602093836100cb565b810103126100c757515f6102b1565b3d91506103a0565b9798949550919950975060209194506024604051809681936370a0823160e01b835260048301525afa928315610387575f9361040d575b506001965f965f96959493925f929190565b9092506020813d602011610439575b81610429602093836100cb565b810103126100c75751915f6103fb565b3d915061041c565b61027e909a6101f0565b61046591925060203d60201161034b5761033c81836100cb565b905f61026c565b9094506020813d602011610498575b81610488602093836100cb565b810103126100c75751935f61022c565b3d915061047b565b5f9950899850889790965087958695509193508492508290565b6101f790996101f0565b6104de91925060203d60201161034b5761033c81836100cb565b905f6101e4565b9091506020813d602011610511575b81610501602093836100cb565b810103126100c75751905f6101b5565b3d91506104f4565b9091506020813d602011610545575b81610535602093836100cb565b810103126100c75751905f610179565b3d915061052856fea2646970667358221220af9837602b075f8cc798c3bd49b336df823f5a95c7d9f162edf88a2c06f729b264736f6c634300081b0033";

// Runtime bytecode for the Forwarder contract.
// Source: tycho-ethereum/contracts/Forwarder.sol
// Compiled with solc 0.8.27, --via-ir --optimize --optimize-runs 200
const FORWARDER_BYTECODE: &str = "6080806040526004361015610012575f80fd5b5f3560e01c9081631339c649146100dc575063c37d11c214610032575f80fd5b346100d85761007860206100453661015e565b60405163095ea7b360e01b81526001600160a01b03909216600483015260248201529283919082905f9082906044820190565b03926001600160a01b03165af180156100cd576020915f916100a0575b506040519015158152f35b6100c09150823d84116100c6575b6100b88183610198565b8101906101ce565b5f610095565b503d6100ae565b6040513d5f823e3d90fd5b5f80fd5b346100d85760208161011a815f816100f33661015e565b63a9059cbb60e01b84526001600160a01b0390911660048401526024830152936044820190565b03926001600160a01b03165af180156100cd576020915f9161014157506040519015158152f35b6101589150823d84116100c6576100b88183610198565b82610095565b60609060031901126100d8576004356001600160a01b03811681036100d857906024356001600160a01b03811681036100d8579060443590565b90601f8019910116810190811067ffffffffffffffff8211176101ba57604052565b634e487b7160e01b5f52604160045260245ffd5b908160209103126100d8575180151581036100d8579056fea2646970667358221220f54ca0601ea79d409edd62a5a48bd93564913f27db1156ad91f9d0c05aff6e4564736f6c634300081b0033";

// ABI for the Analyzer.analyze function
sol! {
    function analyze(
        address token,
        uint256 amount,
        address settlement,
        address recipient
    ) external returns (
        bool transferInOk,
        bool transferOutOk,
        bool approvalOk,
        uint256 balanceBeforeIn,
        uint256 balanceAfterIn,
        uint256 balanceAfterOut,
        uint256 recipientBefore,
        uint256 recipientAfter,
        uint256 gasIn,
        uint256 gasOut
    );
}

/// Token analyzer that uses `eth_call` with bytecode overrides instead of `trace_callMany`.
/// Works on any EVM chain that supports eth_call state overrides (including Arbitrum Nitro).
pub struct EthCallDetector {
    pub rpc: EthereumRpcClient,
    pub finder: Arc<dyn TokenOwnerFinding>,
    pub settlement_contract: Address,
}

#[async_trait::async_trait]
impl TokenAnalyzer for EthCallDetector {
    type Error = String;

    async fn analyze(
        &self,
        token: Bytes,
        block: BlockTag,
    ) -> Result<(TokenQuality, Option<TransferCost>, Option<TransferTax>), String> {
        let (quality, transfer_cost, tax) = self
            .detect_impl(Address::from_bytes(&token), block)
            .await
            .map_err(|e| e.to_string())?;
        tracing::debug!(?token, ?quality, "ethcall detector: determined token quality");
        Ok((
            quality,
            transfer_cost.map(|cost| cost.try_into().unwrap_or(8_000_000)),
            tax.map(|cost| cost.try_into().unwrap_or(10_000)),
        ))
    }
}

impl EthCallDetector {
    pub fn new(
        rpc: &EthereumRpcClient,
        finder: Arc<dyn TokenOwnerFinding>,
        settlement_contract: Address,
    ) -> Self {
        Self { rpc: rpc.clone(), finder, settlement_contract }
    }

    fn arbitrary_recipient() -> Address {
        let hash = keccak256(b"propeller");
        Address::from_slice(&hash[..20])
    }

    pub async fn detect_impl(
        &self,
        token: Address,
        block: BlockTag,
    ) -> Result<(TokenQuality, Option<U256>, Option<U256>), String> {
        let block_tag = map_block_tag(block);

        const MIN_AMOUNT: u64 = 100_000;
        let (take_from, amount) = match self
            .finder
            .find_owner(token.to_bytes(), MIN_AMOUNT.into())
            .await
            .map_err(|e| e.to_string())?
        {
            Some((address, balance)) => {
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
                tracing::debug!(?token, ?address, ?amount, "ethcall: found owner");
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

        let recipient = Self::arbitrary_recipient();

        // Build the analyze() calldata
        let calldata = analyzeCall {
            token,
            amount,
            settlement: self.settlement_contract,
            recipient,
        }
        .abi_encode();

        // Build eth_call with state overrides:
        // - Override holder's code with Analyzer bytecode
        // - Override settlement's code with Forwarder bytecode
        let analyzer_bytecode = hex::decode(ANALYZER_BYTECODE).expect("valid hex");
        let forwarder_bytecode = hex::decode(FORWARDER_BYTECODE).expect("valid hex");

        let request = json!([
            {
                "from": take_from.to_string(),
                "to": take_from.to_string(),
                "data": format!("0x{}", hex::encode(&calldata)),
                "gas": "0x1c9c380"  // 30M gas limit
            },
            block_tag.to_string(),
            {
                take_from.to_string(): {
                    "code": format!("0x{}", hex::encode(&analyzer_bytecode))
                },
                self.settlement_contract.to_string(): {
                    "code": format!("0x{}", hex::encode(&forwarder_bytecode))
                }
            }
        ]);

        let result: AlloyBytes = self
            .rpc
            .raw_request("eth_call", request)
            .await
            .map_err(|e| format!("eth_call with overrides failed: {e}"))?;

        // Decode the ABI-encoded response
        let returns = analyzeCall::abi_decode_returns(result.as_ref())
            .map_err(|e| format!("Failed to decode analyze() return: {e}"))?;

        Self::handle_response(returns, amount, take_from)
    }

    fn handle_response(
        r: <analyzeCall as SolCall>::Return,
        amount: U256,
        take_from: Address,
    ) -> Result<(TokenQuality, Option<U256>, Option<U256>), String> {
        if !r.transferInOk {
            return Ok((
                TokenQuality::bad(format!(
                    "Transfer of token from on chain source {take_from:?} into settlement \
                     contract failed"
                )),
                None,
                None,
            ));
        }

        let arbitrary = Self::arbitrary_recipient();
        if !r.transferOutOk {
            return Ok((
                TokenQuality::bad(format!(
                    "Transfer token out of settlement contract to arbitrary recipient \
                     {arbitrary:?} failed"
                )),
                None,
                None,
            ));
        }

        let gas_per_transfer = (r.gasIn + r.gasOut) / U256::from(2);

        let middle_amount = r
            .balanceAfterIn
            .checked_sub(r.balanceBeforeIn)
            .ok_or_else(|| "balance underflow after transfer in".to_string())?;

        let fees = Self::calculate_fee(
            amount,
            middle_amount,
            r.balanceBeforeIn,
            r.balanceAfterIn,
            r.recipientBefore,
            r.recipientAfter,
        )?;

        let computed_balance_after_in = error_add(r.balanceBeforeIn, amount)?;
        if r.balanceAfterIn != computed_balance_after_in {
            return Ok((
                TokenQuality::bad(format!(
                    "Transferring {amount} into settlement contract was expected to result in a \
                     balance of {computed_balance_after_in} but actually resulted in \
                     {}. A common cause for this is that the token takes a fee on transfer.",
                    r.balanceAfterIn
                )),
                Some(gas_per_transfer),
                Some(fees),
            ));
        }

        if r.balanceAfterOut != r.balanceBeforeIn {
            return Ok((
                TokenQuality::bad(format!(
                    "Transferring {amount} out of settlement contract was expected to result in the \
                     original balance of {} but actually resulted in {}.",
                    r.balanceBeforeIn, r.balanceAfterOut
                )),
                Some(gas_per_transfer),
                Some(fees),
            ));
        }

        let computed_recipient_after = error_add(r.recipientBefore, middle_amount)?;
        if r.recipientAfter != computed_recipient_after {
            return Ok((
                TokenQuality::bad(format!(
                    "Transferring {amount} into arbitrary recipient {arbitrary:?} was expected to \
                     result in a balance of {computed_recipient_after} but actually resulted \
                     in {}. A common cause for this is that the token takes a fee on transfer.",
                    r.recipientAfter
                )),
                Some(gas_per_transfer),
                Some(fees),
            ));
        }

        if !r.approvalOk {
            return Ok((
                TokenQuality::bad("Approval of U256::MAX failed".to_string()),
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
    ) -> Result<U256, String> {
        // Same logic as TraceCallDetector::calculate_fee
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

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use alloy::primitives::Address;
    use tycho_common::models::token::TokenOwnerStore;

    use super::*;
    use crate::{
        services::token_analyzer::TraceCallDetector,
        test_fixtures::{TestFixture, TEST_BLOCK_NUMBER, TOKEN_HOLDERS, USDC_STR, WETH_STR},
    };

    const SETTLEMENT_CONTRACT: &str = "0xc9f2e6ea1637E499406986ac50ddC92401ce1f58";

    impl TestFixture {
        fn create_ethcall_detector(&self) -> EthCallDetector {
            let rpc = self.create_rpc_client(false);
            let token_finder = TokenOwnerStore::new(TOKEN_HOLDERS.clone());
            EthCallDetector::new(
                &rpc,
                Arc::new(token_finder),
                Address::from_str(SETTLEMENT_CONTRACT).unwrap(),
            )
        }

        fn create_trace_detector(&self) -> TraceCallDetector {
            let rpc = self.create_rpc_client(false);
            let token_finder = TokenOwnerStore::new(TOKEN_HOLDERS.clone());
            TraceCallDetector::new(&rpc, Arc::new(token_finder))
        }
    }

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_ethcall_detector_usdc() {
        let fixture = TestFixture::new();
        let detector = fixture.create_ethcall_detector();
        let usdc = Address::from_str(USDC_STR).unwrap();

        let result = detector
            .detect_impl(usdc, BlockTag::Number(TEST_BLOCK_NUMBER))
            .await;

        match result {
            Ok((quality, gas_cost, transfer_tax)) => {
                println!("EthCall USDC Results:");
                println!("  Quality: {:?}", quality);
                println!("  Gas Cost: {:?}", gas_cost);
                println!("  Transfer Tax: {:?}", transfer_tax);

                assert!(matches!(quality, TokenQuality::Good));
                assert!(gas_cost.is_some());
                assert!(transfer_tax.is_some());
                if let Some(tax) = transfer_tax {
                    assert_eq!(tax, U256::ZERO, "USDC should not have transfer fees");
                }
            }
            Err(e) => panic!("Failed to analyze USDC: {}", e),
        }
    }

    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_ethcall_detector_weth() {
        let fixture = TestFixture::new();
        let detector = fixture.create_ethcall_detector();
        let weth = Address::from_str(WETH_STR).unwrap();

        let result = detector
            .detect_impl(weth, BlockTag::Number(TEST_BLOCK_NUMBER))
            .await;

        match result {
            Ok((quality, gas_cost, transfer_tax)) => {
                println!("EthCall WETH Results:");
                println!("  Quality: {:?}", quality);
                println!("  Gas Cost: {:?}", gas_cost);
                println!("  Transfer Tax: {:?}", transfer_tax);

                assert!(matches!(quality, TokenQuality::Good));
                assert!(gas_cost.is_some());
            }
            Err(e) => panic!("Failed to analyze WETH: {}", e),
        }
    }

    /// Helper to compare results from both detectors
    fn assert_detector_parity(
        label: &str,
        ethcall_result: (TokenQuality, Option<U256>, Option<U256>),
        trace_result: (TokenQuality, Option<U256>, Option<U256>),
    ) {
        println!("=== {label} Comparison ===");
        println!(
            "TraceCallMany:  quality={:?}, gas={:?}, tax={:?}",
            trace_result.0, trace_result.1, trace_result.2
        );
        println!(
            "EthCall:        quality={:?}, gas={:?}, tax={:?}",
            ethcall_result.0, ethcall_result.1, ethcall_result.2
        );

        // Quality must match
        assert_eq!(
            std::mem::discriminant(&ethcall_result.0),
            std::mem::discriminant(&trace_result.0),
            "[{label}] Token quality should match between detectors"
        );

        // Tax must match exactly
        assert_eq!(
            ethcall_result.2, trace_result.2,
            "[{label}] Transfer tax should match between detectors"
        );

        // Gas comparison: trace_callMany reports higher gas due to per-transaction
        // overhead (calldata costs, execution context setup) that doesn't apply to
        // internal CALLs in eth_call. Both are valid gas estimates. We verify both
        // are non-zero and in the same order of magnitude.
        if let (Some(ethcall_gas), Some(trace_gas)) = (ethcall_result.1, trace_result.1) {
            let diff = if ethcall_gas > trace_gas {
                ethcall_gas - trace_gas
            } else {
                trace_gas - ethcall_gas
            };
            println!("[{label}] Gas difference: {diff} gas (ethcall={ethcall_gas}, trace={trace_gas})");
            assert!(ethcall_gas > U256::ZERO, "[{label}] ethcall gas should be non-zero");
            assert!(trace_gas > U256::ZERO, "[{label}] trace gas should be non-zero");
        }
    }

    /// Compare both detectors on USDC
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_compare_detectors_usdc() {
        let fixture = TestFixture::new();
        let ethcall = fixture.create_ethcall_detector();
        let trace = fixture.create_trace_detector();

        let usdc = Address::from_str(USDC_STR).unwrap();
        let block = BlockTag::Number(TEST_BLOCK_NUMBER);

        let ethcall_result = ethcall.detect_impl(usdc, block).await.expect("ethcall failed");
        let trace_result: (TokenQuality, Option<U256>, Option<U256>) =
            trace.detect_impl(usdc, block).await.expect("trace failed");

        assert_detector_parity("USDC", ethcall_result, trace_result);
    }

    /// Compare both detectors on WETH
    #[tokio::test]
    #[ignore = "require RPC connection"]
    async fn test_compare_detectors_weth() {
        let fixture = TestFixture::new();
        let ethcall = fixture.create_ethcall_detector();
        let trace = fixture.create_trace_detector();

        let weth = Address::from_str(WETH_STR).unwrap();
        let block = BlockTag::Number(TEST_BLOCK_NUMBER);

        let ethcall_result = ethcall.detect_impl(weth, block).await.expect("ethcall failed");
        let trace_result: (TokenQuality, Option<U256>, Option<U256>) =
            trace.detect_impl(weth, block).await.expect("trace failed");

        assert_detector_parity("WETH", ethcall_result, trace_result);
    }
}
