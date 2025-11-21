use std::sync::Arc;

use alloy::{
    network::Ethereum,
    providers::{ProviderBuilder, RootProvider},
};
use alloy_chains::NamedChain;
use miette::{IntoDiagnostic, WrapErr};
use tycho_ethereum::{
    rpc::EthereumRpcClient,
    services::entrypoint_tracer::{
        allowance_slot_detector::EVMAllowanceSlotDetector,
        balance_slot_detector::EVMBalanceSlotDetector, slot_detector::SlotDetectorConfig,
    },
};
use tycho_simulation::tycho_common::models::Chain;

#[derive(Clone)]
pub struct RPCTools {
    pub rpc_url: String,
    pub provider: RootProvider<Ethereum>,
    pub evm_balance_slot_detector: Arc<EVMBalanceSlotDetector>,
    pub evm_allowance_slot_detector: Arc<EVMAllowanceSlotDetector>,
}

impl RPCTools {
    pub async fn new(rpc_url: &str, chain: &Chain) -> miette::Result<Self> {
        let provider: RootProvider<Ethereum> = ProviderBuilder::default()
            .with_chain(
                NamedChain::try_from(chain.id())
                    .into_diagnostic()
                    .wrap_err("Invalid chain")?,
            )
            .connect(rpc_url)
            .await
            .into_diagnostic()
            .wrap_err("Failed to connect to provider")?;

        let rpc = EthereumRpcClient::new(rpc_url)
            .into_diagnostic()
            .wrap_err("Failed to create Ethereum RPC client")?;
        let config = SlotDetectorConfig { ..Default::default() };

        let evm_balance_slot_detector = Arc::new(EVMBalanceSlotDetector::new(config.clone(), &rpc));
        let evm_allowance_slot_detector = Arc::new(EVMAllowanceSlotDetector::new(config, &rpc));

        Ok(Self {
            rpc_url: rpc_url.to_string(),
            provider,
            evm_balance_slot_detector,
            evm_allowance_slot_detector,
        })
    }
}
