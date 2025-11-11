use std::{collections::HashMap, fmt::Debug, str::FromStr};

use alloy::{core::sol, dyn_abi::SolType, primitives::U256, sol_types::SolCall};
use revm::DatabaseRef;
use tycho_client::feed::{synchronizer::ComponentWithState, BlockHeader};
use tycho_common::{
    models::{token::Token, Address},
    Bytes,
};

use crate::{
    evm::{
        engine_db::{create_engine, engine_db_interface::EngineDatabaseInterface, SHARED_TYCHO_DB},
        protocol::fluid::v1::FluidV1,
        simulation::{SimulationEngine, SimulationParameters},
    },
    protocol::{
        errors::InvalidSnapshotError,
        models::{DecoderContext, TryFromWithBlock},
    },
};

impl TryFromWithBlock<ComponentWithState, BlockHeader> for FluidV1 {
    type Error = InvalidSnapshotError;

    async fn try_from_with_header(
        value: ComponentWithState,
        _block: BlockHeader,
        _account_balances: &HashMap<Bytes, HashMap<Bytes, Bytes>>,
        all_tokens: &HashMap<Bytes, Token>,
        decoder_context: &DecoderContext,
    ) -> Result<Self, Self::Error> {
        let pool_address = Bytes::from_str(value.component.id.as_str()).map_err(|e| {
            InvalidSnapshotError::ValueError(format!(
                "Expected component id to be pool contract address: {e}"
            ))
        })?;
        let token0_address = value
            .component
            .tokens
            .first()
            .ok_or_else(|| {
                InvalidSnapshotError::ValueError("Missing token0 in component".to_string())
            })?;
        let token0 = all_tokens
            .get(token0_address)
            .ok_or_else(|| {
                InvalidSnapshotError::ValueError(format!(
                    "Missing token0 in state: {token0_address}"
                ))
            })?;
        let token1_address = value
            .component
            .tokens
            .get(1)
            .ok_or_else(|| {
                InvalidSnapshotError::ValueError("Missing token1 in component".to_string())
            })?;
        let token1 = all_tokens
            .get(token1_address)
            .ok_or_else(|| {
                InvalidSnapshotError::ValueError(format!(
                    "Missing token1 in state: {token1_address}"
                ))
            })?;
        let resolver_address = value
            .component
            .static_attributes
            .get("reserves_resolver_address")
            .ok_or_else(|| {
                InvalidSnapshotError::ValueError(
                    "Missing reserves resolver address in component".to_string(),
                )
            })?;
        let engine = create_engine(
            SHARED_TYCHO_DB.clone(),
            decoder_context
                .vm_traces
                .unwrap_or_default(),
        )
        .expect("Infallible");
        let state = decode_from_vm(&pool_address, token0, token1, resolver_address, engine)?;

        Ok(state)
    }
}

sol! {
    struct CollateralReserves {
        uint token0RealReserves;
        uint token1RealReserves;
        uint token0ImaginaryReserves;
        uint token1ImaginaryReserves;
    }

    struct DebtReserves {
        uint token0Debt;
        uint token1Debt;
        uint token0RealReserves;
        uint token1RealReserves;
        uint token0ImaginaryReserves;
        uint token1ImaginaryReserves;
    }

    struct TokenLimit {
        uint256 available; // maximum available swap amount
        uint256 expandsTo; // maximum amount the available swap amount expands to
        uint256 expandDuration; // duration for `available` to grow to `expandsTo`
    }

    struct DexLimits {
        TokenLimit withdrawableToken0;
        TokenLimit withdrawableToken1;
        TokenLimit borrowableToken0;
        TokenLimit borrowableToken1;
    }

    struct PoolWithReserves {
        address pool;
        address token0;
        address token1;
        uint256 fee;
        uint256 centerPrice;
        CollateralReserves collateralReserves;
        DebtReserves debtReserves;
        DexLimits limits;
    }

    function getPoolReservesAdjusted(address pool_) public returns (PoolWithReserves memory poolReserves_);
}

fn decode_from_vm<D: EngineDatabaseInterface + Clone + Debug>(
    pool: &Address,
    token0: &Token,
    token1: &Token,
    resolver_address: &Address,
    vm: SimulationEngine<D>,
) -> Result<FluidV1, InvalidSnapshotError>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    let reserves_call = getPoolReservesAdjustedCall {
        pool_: alloy::primitives::Address::from_slice(pool.as_ref()),
    };
    let data = reserves_call.abi_encode();

    let to = alloy::primitives::Address::from_slice(resolver_address.as_ref());
    let params = SimulationParameters {
        caller: alloy::primitives::Address::ZERO,
        to,
        data,
        value: U256::ZERO,
        overrides: None,
        gas_limit: None,
        transient_storage: None,
    };

    let res = vm
        .simulate(&params)
        .map_err(|e| InvalidSnapshotError::ValueError(format!("{e}")))?;

    let pool_w_reserves = PoolWithReserves::abi_decode(res.result.as_ref()).map_err(|e| {
        InvalidSnapshotError::ValueError(format!(
            "Failed to decode pool reserves: {e} {}",
            res.result
        ))
    })?;
    let state = FluidV1::new(
        token0,
        token1,
        super::v1::CollateralReserves {
            token0_real_reserves: pool_w_reserves
                .collateralReserves
                .token0RealReserves,
            token1_real_reserves: pool_w_reserves
                .collateralReserves
                .token1RealReserves,
            token0_imaginary_reserves: pool_w_reserves
                .collateralReserves
                .token0ImaginaryReserves,
            token1_imaginary_reserves: pool_w_reserves
                .collateralReserves
                .token1ImaginaryReserves,
        },
        super::v1::DebtReserves {
            token0_real_reserves: pool_w_reserves
                .debtReserves
                .token0RealReserves,
            token1_real_reserves: pool_w_reserves
                .debtReserves
                .token1RealReserves,
            token0_imaginary_reserves: pool_w_reserves
                .debtReserves
                .token0ImaginaryReserves,
            token1_imaginary_reserves: pool_w_reserves
                .debtReserves
                .token1ImaginaryReserves,
        },
        super::v1::DexLimits {
            borrowable_token0: super::v1::TokenLimit {
                available: pool_w_reserves
                    .limits
                    .borrowableToken0
                    .available,
                expands_to: pool_w_reserves
                    .limits
                    .borrowableToken0
                    .expandsTo,
                expand_duration: pool_w_reserves
                    .limits
                    .borrowableToken0
                    .expandDuration,
            },
            borrowable_token1: super::v1::TokenLimit {
                available: pool_w_reserves
                    .limits
                    .borrowableToken1
                    .available,
                expands_to: pool_w_reserves
                    .limits
                    .borrowableToken1
                    .expandsTo,
                expand_duration: pool_w_reserves
                    .limits
                    .borrowableToken1
                    .expandDuration,
            },
            withdrawable_token0: super::v1::TokenLimit {
                available: pool_w_reserves
                    .limits
                    .withdrawableToken0
                    .available,
                expands_to: pool_w_reserves
                    .limits
                    .withdrawableToken0
                    .expandsTo,
                expand_duration: pool_w_reserves
                    .limits
                    .withdrawableToken0
                    .expandDuration,
            },
            withdrawable_token1: super::v1::TokenLimit {
                available: pool_w_reserves
                    .limits
                    .withdrawableToken1
                    .available,
                expands_to: pool_w_reserves
                    .limits
                    .withdrawableToken1
                    .expandsTo,
                expand_duration: pool_w_reserves
                    .limits
                    .withdrawableToken1
                    .expandDuration,
            },
        },
        pool_w_reserves.centerPrice,
        pool_w_reserves.fee,
        vm.state
            .get_current_block()
            .expect("block should be set")
            .timestamp,
    );
    Ok(state)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use tycho_client::feed::BlockHeader;
    use tycho_common::{
        models::{token::Token, Chain},
        Bytes,
    };

    use crate::evm::{
        engine_db::{
            simulation_db::SimulationDB,
            utils::{get_client, get_runtime},
        },
        protocol::fluid::decoder::decode_from_vm,
        simulation::SimulationEngine,
    };

    #[test]
    fn test_decode_simulation_db() {
        let wsteth = Token::new(
            &Bytes::from_str("0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0").unwrap(),
            "wsteth",
            18,
            0,
            &[Some(20000)],
            Chain::Ethereum,
            100,
        );
        let eth = Token::new(
            &Bytes::from_str("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE").unwrap(),
            "ETH",
            18,
            0,
            &[Some(2000)],
            Chain::Ethereum,
            100,
        );

        let block = BlockHeader {
            number: 23526115,
            hash: Bytes::from_str(
                "0xfe5df4d77d2e4ce5660f2329084d5ef238b6671bdcf961ce0a510071af7a2275",
            )
            .unwrap(),
            timestamp: 1759842947,
            ..Default::default()
        };
        let mut db = SimulationDB::new(get_client(None).unwrap(), get_runtime().unwrap(), None);
        db.set_block(Some(block));
        let vm = SimulationEngine::new(db, false);

        decode_from_vm(
            &Bytes::from("0x0B1a513ee24972DAEf112bC777a5610d4325C9e7"),
            &wsteth,
            &eth,
            &Bytes::from("0xC93876C0EEd99645DD53937b25433e311881A27C"),
            vm,
        )
        .expect("decoding failed");
    }
}
