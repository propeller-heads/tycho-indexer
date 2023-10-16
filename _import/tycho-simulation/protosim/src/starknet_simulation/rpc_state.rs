use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use core::fmt;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use starknet::core::types::ContractClass as SNContractClass;
use starknet_api::{
    block::{BlockNumber, BlockTimestamp},
    core::{ChainId, ClassHash, ContractAddress},
    hash::{StarkFelt, StarkHash},
    state::StorageKey,
    transaction::{InvokeTransaction, Transaction as SNTransaction, TransactionHash},
};
use starknet_in_rust::definitions::block_context::StarknetChainId;
use std::{collections::HashMap, env, error::Error};

/// Starknet chains supported in Infura.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum RpcChain {
    MainNet,
    TestNet,
    TestNet2,
}

impl From<RpcChain> for StarknetChainId {
    fn from(network: RpcChain) -> StarknetChainId {
        match network {
            RpcChain::MainNet => StarknetChainId::MainNet,
            RpcChain::TestNet => StarknetChainId::TestNet,
            RpcChain::TestNet2 => StarknetChainId::TestNet2,
        }
    }
}

impl fmt::Display for RpcChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpcChain::MainNet => write!(f, "starknet-mainnet"),
            RpcChain::TestNet => write!(f, "starknet-goerli"),
            RpcChain::TestNet2 => write!(f, "starknet-goerli2"),
        }
    }
}

impl From<RpcChain> for ChainId {
    fn from(value: RpcChain) -> Self {
        ChainId(match value {
            RpcChain::MainNet => "alpha-mainnet".to_string(),
            RpcChain::TestNet => "alpha4".to_string(),
            RpcChain::TestNet2 => "alpha4-2".to_string(),
        })
    }
}

/// A [StateReader] that holds all the data in memory.
///
/// This implementation is uses HTTP requests to call the RPC endpoint,
/// using Infura.
/// In order to use it an Infura API key is necessary.
#[derive(Debug, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct RpcState {
    /// Enum with one of the supported Infura chains/
    pub chain: RpcChain,
    /// RPC Endpoint URL.
    rpc_endpoint: String,
    /// The url to the starknet feeder.
    feeder_url: String,
    /// Struct that holds information on the block where we are going to use to read the state.
    pub block: BlockValue,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
enum RpcError {
    RpcCall(String),
    Request(String),
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RpcError::RpcCall(ref e) => write!(f, "RPC call failed with error: {}", e),
            RpcError::Request(ref e) => write!(f, "Request failed with error: {}", e),
        }
    }
}

impl Error for RpcError {}

/// Represents the tag of a block value.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum BlockTag {
    Latest,
    Pending,
}

impl fmt::Display for BlockTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = match self {
            BlockTag::Latest => "latest",
            BlockTag::Pending => "pending",
        };
        write!(f, "{}", string)
    }
}

/// [`BlockValue`] is an Enum that represent which block we are going to use to retrieve
/// information.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum BlockValue {
    /// String one of: ["latest", "pending"]
    Tag(BlockTag),
    /// Integer
    Number(BlockNumber),
    /// String with format: 0x{felt252}
    Hash(StarkHash),
}

impl From<BlockTag> for BlockValue {
    fn from(value: BlockTag) -> Self {
        BlockValue::Tag(value)
    }
}

impl From<BlockNumber> for BlockValue {
    fn from(value: BlockNumber) -> Self {
        BlockValue::Number(value)
    }
}

impl From<StarkHash> for BlockValue {
    fn from(value: StarkHash) -> Self {
        BlockValue::Hash(value)
    }
}

impl BlockValue {
    fn to_value(self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(match self {
            BlockValue::Tag(block_tag) => block_tag.to_string().into(),
            BlockValue::Number(block_number) => json!({ "block_number": block_number }),
            BlockValue::Hash(block_hash) => json!({ "block_hash": block_hash }),
        })
    }
}

/// The RPC block info.
#[derive(Debug, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct RpcBlockInfo {
    /// The sequence number of the last block created.
    pub block_number: BlockNumber,
    /// Timestamp of the beginning of the last block creation attempt.
    pub block_timestamp: BlockTimestamp,
    /// The sequencer address of this block.
    pub sequencer_address: ContractAddress,
    /// The transactions of this block.
    pub transactions: Vec<SNTransaction>,
}

/// A RPC response.
#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct RpcResponse<T> {
    result: T,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
pub struct TransactionTrace {
    pub validate_invocation: RpcCallInfo,
    pub function_invocation: Option<RpcCallInfo>,
    pub fee_transfer_invocation: RpcCallInfo,
    pub signature: Vec<StarkFelt>,
    pub revert_error: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct RpcExecutionResources {
    pub n_steps: usize,
    pub n_memory_holes: usize,
    pub builtin_instance_counter: HashMap<String, usize>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RpcCallInfo {
    pub execution_resources: VmExecutionResources,
    pub retdata: Option<Vec<StarkFelt>>,
    pub calldata: Option<Vec<StarkFelt>>,
    pub internal_calls: Vec<RpcCallInfo>,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
pub struct RpcTransactionReceipt {
    #[serde(deserialize_with = "actual_fee_deser")]
    pub actual_fee: u128,
    pub block_hash: StarkHash,
    pub block_number: u64,
    pub execution_status: String,
    #[serde(rename = "type")]
    pub tx_type: String,
}

fn actual_fee_deser<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    let hex: String = Deserialize::deserialize(deserializer)?;
    Ok(u128::from_str_radix(&hex[2..], 16).unwrap())
}

impl<'de> Deserialize<'de> for RpcCallInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: serde_json::Value = Deserialize::deserialize(deserializer)?;

        // Parse execution_resources
        let execution_resources_value = value["execution_resources"].clone();

        let execution_resources = VmExecutionResources {
            n_steps: serde_json::from_value(execution_resources_value["n_steps"].clone())
                .map_err(serde::de::Error::custom)?,
            n_memory_holes: serde_json::from_value(
                execution_resources_value["n_memory_holes"].clone(),
            )
            .map_err(serde::de::Error::custom)?,
            builtin_instance_counter: serde_json::from_value(
                execution_resources_value["builtin_instance_counter"].clone(),
            )
            .map_err(serde::de::Error::custom)?,
        };

        // Parse retdata
        let retdata_value = value["result"].clone();
        let retdata = serde_json::from_value(retdata_value).unwrap();

        // Parse calldata
        let calldata_value = value["calldata"].clone();
        let calldata = serde_json::from_value(calldata_value).unwrap();

        // Parse internal calls
        let internal_calls_value = value["internal_calls"].clone();
        let mut internal_calls = vec![];

        for call in internal_calls_value.as_array().unwrap() {
            internal_calls
                .push(serde_json::from_value(call.clone()).map_err(serde::de::Error::custom)?);
        }

        Ok(RpcCallInfo { execution_resources, retdata, calldata, internal_calls })
    }
}

/// Freestanding deserialize method to avoid a new type.
pub fn deserialize_transaction_json(
    transaction: serde_json::Value,
) -> serde_json::Result<SNTransaction> {
    let tx_type: String = serde_json::from_value(transaction["type"].clone())?;
    let tx_version: String = serde_json::from_value(transaction["version"].clone())?;

    match tx_type.as_str() {
        "INVOKE" => match tx_version.as_str() {
            "0x0" => Ok(SNTransaction::Invoke(InvokeTransaction::V0(serde_json::from_value(
                transaction,
            )?))),
            "0x1" => Ok(SNTransaction::Invoke(InvokeTransaction::V1(serde_json::from_value(
                transaction,
            )?))),
            x => Err(serde::de::Error::custom(format!("unimplemented invoke version: {x}"))),
        },
        x => Err(serde::de::Error::custom(format!(
            "unimplemented transaction type deserialization: {x}"
        ))),
    }
}

impl RpcState {
    pub fn new(chain: RpcChain, block: BlockValue, rpc_endpoint: &str, feeder_url: &str) -> Self {
        Self {
            chain,
            rpc_endpoint: rpc_endpoint.to_string(),
            feeder_url: feeder_url.to_string(),
            block,
        }
    }

    pub fn new_infura(chain: RpcChain, block: BlockValue) -> Self {
        let rpc_endpoint = format!(
            "https://{}.infura.io/v3/{}",
            chain,
            env::var("INFURA_API_KEY").expect("Please set 'INFURA_API_KEY' env variable!")
        );

        let chain_id: ChainId = chain.into();
        let feeder_url = format!("https://{}.starknet.io/feeder_gateway", chain_id);

        Self::new(chain, block, &rpc_endpoint, &feeder_url)
    }

    fn rpc_call_result<T: for<'a> Deserialize<'a>>(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<T, RpcError> {
        Ok(self
            .rpc_call::<RpcResponse<T>>(method, params)?
            .result)
    }

    fn rpc_call<T: for<'a> Deserialize<'a>>(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<T, RpcError> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });
        let response = self
            .rpc_call_no_deserialize(&payload)?
            .into_json()
            .unwrap();
        Self::deserialize_call(response)
    }

    fn rpc_call_no_deserialize(
        &self,
        params: &serde_json::Value,
    ) -> Result<ureq::Response, RpcError> {
        ureq::post(&self.rpc_endpoint)
            .set("Content-Type", "application/json")
            .set("accept", "application/json")
            .send_json(params)
            .map_err(|err| RpcError::Request(err.to_string()))
    }

    fn deserialize_call<T: for<'a> Deserialize<'a>>(
        response: serde_json::Value,
    ) -> Result<T, RpcError> {
        serde_json::from_value(response).map_err(|err| RpcError::RpcCall(err.to_string()))
    }

    /// Gets the url of the feeder endpoint
    fn get_feeder_endpoint(&self, path: &str) -> String {
        format!("{}/{}", self.feeder_url, path)
    }

    /// Requests the transaction trace to the Feeder Gateway API.
    /// It's useful for testing the transaction outputs like:
    /// - execution resources
    /// - actual fee
    /// - events
    /// - return data
    pub fn get_transaction_trace(&self, hash: &TransactionHash) -> TransactionTrace {
        let response = ureq::get(&self.get_feeder_endpoint("get_transaction_trace"))
            .query("transactionHash", &hash.0.to_string())
            .call()
            .unwrap();

        serde_json::from_value(response.into_json().unwrap()).unwrap()
    }

    /// Requests the given transaction to the Feeder Gateway API.
    pub fn get_transaction(&self, hash: &TransactionHash) -> SNTransaction {
        let result = self
            .rpc_call::<serde_json::Value>(
                "starknet_getTransactionByHash",
                &json!([hash.to_string()]),
            )
            .unwrap()["result"]
            .clone();
        deserialize_transaction_json(result).unwrap()
    }

    /// Gets the gas price of a given block.
    pub fn get_gas_price(&self, block_number: u64) -> serde_json::Result<u128> {
        let response = ureq::get(&self.get_feeder_endpoint("get_block"))
            .query("blockNumber", &block_number.to_string())
            .call()
            .unwrap();

        let res: serde_json::Value = response
            .into_json()
            .expect("should be json");

        let gas_price_hex = res["gas_price"].as_str().unwrap();
        let gas_price = u128::from_str_radix(gas_price_hex.trim_start_matches("0x"), 16).unwrap();
        Ok(gas_price)
    }

    pub fn get_chain_name(&self) -> ChainId {
        self.chain.into()
    }

    pub fn get_block_info(&self) -> RpcBlockInfo {
        let block_info: serde_json::Value = self
            .rpc_call("starknet_getBlockWithTxs", &json!([self.block.to_value().unwrap()]))
            .unwrap();
        let sequencer_address: StarkFelt =
            serde_json::from_value(block_info["result"]["sequencer_address"].clone()).unwrap();

        let transactions: Vec<_> = block_info["result"]["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|result| deserialize_transaction_json(result.clone()).ok())
            .collect();

        RpcBlockInfo {
            block_number: BlockNumber(
                block_info["result"]["block_number"]
                    .to_string()
                    .parse::<u64>()
                    .unwrap(),
            ),
            block_timestamp: BlockTimestamp(
                block_info["result"]["timestamp"]
                    .to_string()
                    .parse::<u64>()
                    .unwrap(),
            ),
            sequencer_address: ContractAddress(sequencer_address.try_into().unwrap()),
            transactions,
        }
    }

    pub fn get_contract_class(&self, class_hash: &ClassHash) -> SNContractClass {
        self.rpc_call_result(
            "starknet_getClass",
            &json!([self.block.to_value().unwrap(), class_hash.0.to_string()]),
        )
        .unwrap()
    }

    pub fn get_class_hash_at(&self, contract_address: &ContractAddress) -> ClassHash {
        let hash = self
            .rpc_call_result(
                "starknet_getClassHashAt",
                &json!([
                    self.block.to_value().unwrap(),
                    contract_address
                        .0
                        .key()
                        .clone()
                        .to_string()
                ]),
            )
            .unwrap();

        ClassHash(hash)
    }

    pub fn get_nonce_at(&self, contract_address: &ContractAddress) -> StarkFelt {
        self.rpc_call_result(
            "starknet_getNonce",
            &json!([
                self.block.to_value().unwrap(),
                contract_address
                    .0
                    .key()
                    .clone()
                    .to_string()
            ]),
        )
        .unwrap()
    }

    pub fn get_storage_at(
        &self,
        contract_address: &ContractAddress,
        key: &StorageKey,
    ) -> StarkFelt {
        let contract_address = contract_address.0.key();
        let key = key.0.key();

        self.rpc_call_result(
            "starknet_getStorageAt",
            &json!([contract_address.to_string(), key.to_string(), self.block.to_value().unwrap()]),
        )
        .unwrap()
    }

    /// Requests the given transaction to the Feeder Gateway API.
    pub fn get_transaction_receipt(&self, hash: &TransactionHash) -> RpcTransactionReceipt {
        self.rpc_call_result("starknet_getTransactionReceipt", &json!([hash.to_string()]))
            .unwrap()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_gas_price() {
        let block = BlockValue::Number(BlockNumber(169928));
        let rpc_state = RpcState::new_infura(RpcChain::MainNet, block);

        let price = rpc_state.get_gas_price(169928).unwrap();
        assert_eq!(price, 22804578690);
    }
}
