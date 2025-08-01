use std::{any::Any, collections::HashMap, fmt::Debug, str::FromStr};

use alloy::{
    primitives::{keccak256, Address, Signed, Uint, I128, U256},
    sol_types::SolType,
};
use revm::DatabaseRef;
use tycho_client::feed::BlockHeader;
use tycho_common::{
    dto::ProtocolStateDelta,
    models::token::Token,
    simulation::{
        errors::{SimulationError, TransitionError},
        protocol_sim::Balances,
    },
    Bytes,
};

use crate::evm::{
    engine_db::engine_db_interface::EngineDatabaseInterface,
    protocol::{
        uniswap_v4::{
            hooks::{
                hook_handler::HookHandler,
                models::{
                    AfterSwapDelta, AfterSwapParameters, AfterSwapSolReturn, AmountRanges,
                    BeforeSwapOutput, BeforeSwapParameters, BeforeSwapSolOutput, SwapParams,
                    WithGasEstimate,
                },
            },
            state::UniswapV4State,
        },
        vm::tycho_simulation_contract::TychoSimulationContract,
    },
    simulation::SimulationEngine,
};

#[derive(Debug, Clone)]
pub(crate) struct GenericVMHookHandler<D: EngineDatabaseInterface + Clone + Debug>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    contract: TychoSimulationContract<D>,
    address: Address,
    pool_manager: Address,
    limits_entrypoint: Option<String>,
}

impl<D: EngineDatabaseInterface + Clone + Debug> PartialEq for GenericVMHookHandler<D>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address &&
            self.pool_manager == other.pool_manager &&
            self.limits_entrypoint == other.limits_entrypoint
    }
}

impl<D: EngineDatabaseInterface + Clone + Debug> GenericVMHookHandler<D>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    pub fn new(
        address: Address,
        engine: SimulationEngine<D>,
        pool_manager: Address,
        _all_tokens: HashMap<Bytes, Token>,
        _account_balances: HashMap<Bytes, HashMap<Bytes, Bytes>>,
        limits_entrypoint: Option<String>,
    ) -> Result<Self, SimulationError> {
        Ok(GenericVMHookHandler {
            contract: TychoSimulationContract::new(address, engine)?,
            address,
            pool_manager,
            limits_entrypoint,
        })
    }

    pub fn unlock_pool_manager(&self) -> HashMap<Address, HashMap<U256, U256>> {
        let is_unlocked_slot = U256::from_be_bytes(keccak256("Unlocked").0) - U256::from(1);
        HashMap::from([(self.pool_manager, HashMap::from([(is_unlocked_slot, U256::from(1u64))]))])
        // the slot is here https://github.com/Uniswap/v4-core/blob/main/src/libraries/Lock.sol#L8C5-L8C117
    }
}

impl<D: EngineDatabaseInterface + Clone + Debug + 'static> HookHandler for GenericVMHookHandler<D>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    fn address(&self) -> Address {
        self.address
    }

    fn before_swap(
        &self,
        params: BeforeSwapParameters,
        block: BlockHeader,
        overwrites: Option<HashMap<Address, HashMap<U256, U256>>>,
        transient_storage: Option<HashMap<Address, HashMap<U256, U256>>>,
    ) -> Result<WithGasEstimate<BeforeSwapOutput>, SimulationError> {
        let mut transient_storage_params = self.unlock_pool_manager();
        if let Some(input_params) = transient_storage {
            transient_storage_params.extend(input_params);
        }
        let args = (
            params.sender,
            (
                params.context.currency_0,
                params.context.currency_1,
                Uint::<24, 1>::from(params.context.fees.lp_fee),
                Signed::<24, 1>::try_from(params.context.tick_spacing).map_err(|e| {
                    SimulationError::FatalError(format!("Failed to convert tick: {e:?}"))
                })?,
                self.address,
            ),
            (
                params.swap_params.zero_for_one,
                params.swap_params.amount_specified,
                params.swap_params.sqrt_price_limit,
            ),
            params.hook_data.to_vec(),
        );
        let selector = "beforeSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),bytes)";

        let res = self.contract.call(
            selector,
            args,
            block.number,
            Some(block.timestamp),
            overwrites,
            Some(self.pool_manager),
            U256::from(0u64),
            Some(transient_storage_params),
        )?;

        let decoded = BeforeSwapSolOutput::abi_decode(&res.return_value).map_err(|e| {
            SimulationError::FatalError(format!("Failed to decode before swap return value: {e:?}"))
        })?;
        let state_updates = res.simulation_result.state_updates;
        let overwrites: HashMap<Address, HashMap<U256, U256>> = state_updates
            .into_iter()
            .filter_map(|(address, update)| {
                update
                    .storage
                    .map(|storage| (address, storage))
            })
            .collect();
        Ok(WithGasEstimate {
            gas_estimate: res.simulation_result.gas_used,
            result: BeforeSwapOutput::new(
                decoded,
                overwrites,
                res.simulation_result.transient_storage,
            ),
        })
    }

    fn after_swap(
        &self,
        params: AfterSwapParameters,
        block: BlockHeader,
        overwrites: Option<HashMap<Address, HashMap<U256, U256>>>,
        transient_storage: Option<HashMap<Address, HashMap<U256, U256>>>,
    ) -> Result<WithGasEstimate<AfterSwapDelta>, SimulationError> {
        let mut transient_storage_params = self.unlock_pool_manager();
        if let Some(input_params) = transient_storage {
            transient_storage_params.extend(input_params);
        }
        let args = (
            params.sender,
            (
                params.context.currency_0,
                params.context.currency_1,
                Uint::<24, 1>::from(params.context.fees.lp_fee),
                Signed::<24, 1>::try_from(params.context.tick_spacing).map_err(|e| {
                    SimulationError::FatalError(format!("Failed to convert tick: {e:?}"))
                })?,
                self.address,
            ),
            (
                params.swap_params.zero_for_one,
                params.swap_params.amount_specified,
                params.swap_params.sqrt_price_limit,
            ),
            params.delta.as_i256(),
            params.hook_data.to_vec(),
        );
        let selector = "afterSwap(address,(address,address,uint24,int24,address),(bool,int256,uint160),int256,bytes)";

        let res = self.contract.call(
            selector,
            args,
            block.number,
            Some(block.timestamp),
            overwrites,
            Some(self.pool_manager),
            U256::from(0u64),
            Some(transient_storage_params),
        )?;

        let decoded = AfterSwapSolReturn::abi_decode(&res.return_value).map_err(|e| {
            SimulationError::FatalError(format!("Failed to decode before swap return value: {e:?}"))
        })?;
        Ok(WithGasEstimate {
            gas_estimate: res.simulation_result.gas_used,
            result: I128::try_from(decoded.delta).map_err(|e| {
                SimulationError::FatalError(format!("Failed to convert delta: {e:?}"))
            })?,
        })
    }

    fn fee(&self, _context: &UniswapV4State, _params: SwapParams) -> Result<f64, SimulationError> {
        Err(SimulationError::RecoverableError(
            "fee is not implemented for GenericVMHookHandler".to_string(),
        ))
    }

    fn spot_price(&self, _base: &Token, _quote: &Token) -> Result<f64, SimulationError> {
        Err(SimulationError::RecoverableError(
            "spot_price is not implemented for GenericVMHookHandler".to_string(),
        ))
    }

    fn get_amount_ranges(
        &self,
        token_in: Bytes,
        token_out: Bytes,
    ) -> Result<AmountRanges, SimulationError> {
        match &self.limits_entrypoint {
            Some(entrypoint) => {
                let parts: Vec<&str> = entrypoint.split(':').collect();
                if parts.len() != 2 {
                    return Err(SimulationError::FatalError(
                        "Invalid limits_entrypoint format. Expected 'address:signature'"
                            .to_string(),
                    ));
                }

                let contract_address = Address::from_str(parts[0]).map_err(|e| {
                    SimulationError::FatalError(format!("Failed to parse contract address: {e:?}"))
                })?;

                let function_signature = parts[1];

                let token_in_addr = Address::from_slice(&token_in.0);
                let token_out_addr = Address::from_slice(&token_out.0);

                let limits_contract =
                    TychoSimulationContract::new(contract_address, self.contract.engine.clone())?;

                let args = (token_in_addr, token_out_addr);

                let res = limits_contract.call(
                    function_signature,
                    args,
                    0,                // block number (not used to get limits)
                    None,             // timestamp
                    None,             // overwrites
                    None,             // caller
                    U256::from(0u64), // value
                    None,             // transient_storage
                )?;

                println!("Return value {:?}", res.clone());

                let decoded: (U256, U256) = (
                    U256::from_be_slice(&res.return_value[..32]),
                    U256::from_be_slice(&res.return_value[32..64]),
                );

                // For now, we only care about upper limits
                Ok(AmountRanges {
                    amount_in_range: (U256::ZERO, decoded.0),
                    amount_out_range: (U256::ZERO, decoded.1),
                })
            }
            None => Err(SimulationError::RecoverableError(
                "limits_entrypoint is not set for this GenericVMHookHandler".to_string(),
            )),
        }
    }

    fn delta_transition(
        &mut self,
        delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        if let Some(limits_entrypoint_bytes) = delta
            .updated_attributes
            .get("limits_entrypoint")
        {
            // TODO double check how exactly this is encoded
            let limits_entrypoint =
                String::from_utf8(limits_entrypoint_bytes.0.to_vec()).map_err(|e| {
                    TransitionError::SimulationError(SimulationError::FatalError(format!(
                        "Failed to parse limits_entrypoint from delta: {e:?}"
                    )))
                })?;

            self.limits_entrypoint = Some(limits_entrypoint);
        }

        Ok(())
    }

    fn clone_box(&self) -> Box<dyn HookHandler> {
        Box::new((*self).clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_equal(&self, other: &dyn HookHandler) -> bool {
        other.as_any().downcast_ref::<Self>() == Some(self)
    }
}

#[cfg(test)]
mod tests {
    use std::{default::Default, str::FromStr};

    use alloy::primitives::{aliases::U24, Bytes as AlloyBytes, B256, I256, U256};
    use revm::state::{AccountInfo, Bytecode};
    use tycho_client::feed::BlockHeader;

    use super::*;
    use crate::evm::{
        engine_db::{
            create_engine,
            simulation_db::SimulationDB,
            utils::{get_client, get_runtime},
        },
        protocol::{
            uniswap_v4::{
                hooks::{
                    constants::POOL_MANAGER_BYTECODE,
                    models::{BalanceDelta, BeforeSwapDelta, StateContext},
                },
                state::UniswapV4Fees,
            },
            vm::constants::MAX_BALANCE,
        },
    };

    #[test]
    fn test_before_swap() {
        let block = BlockHeader {
            number: 22578103,
            hash: Bytes::from_str(
                "0x035c0e674c3bf3384a74b766908ab41c1968e989360aa26bea1dd64b1626f5f0",
            )
            .unwrap(),
            timestamp: 1748397011,
            ..Default::default()
        };
        let db = SimulationDB::new(get_client(None), get_runtime(), Some(block.clone()));
        let engine = create_engine(db, true).expect("Failed to create simulation engine");

        let hook_address = Address::from_str("0x0010d0d5db05933fa0d9f7038d365e1541a41888")
            .expect("Invalid hook address");

        let pool_manager = Address::from_str("0x000000000004444c5dc75cB358380D2e3dE08A90")
            .expect("Invalid pool manager address");

        let hook_handler = GenericVMHookHandler::new(
            hook_address,
            engine,
            pool_manager,
            HashMap::new(),
            HashMap::new(),
            None,
        )
        .expect("Failed to create GenericVMHookHandler");

        // simulating this tx: 0x6eef1c491d72edf73efd007b152b18d5f7814c5f3bd1c7d9be465fb9b4920f17
        let params = BeforeSwapParameters {
            context: StateContext {
                currency_0: Address::from_str("0x0000000000000000000000000000000000000000")
                    .unwrap(),
                currency_1: Address::from_str("0x000000c396558ffbab5ea628f39658bdf61345b3")
                    .unwrap(), // BUNNI
                fees: UniswapV4Fees { zero_for_one: 0, one_for_zero: 0, lp_fee: 1 },
                tick_spacing: 60,
            },
            sender: Address::from_str("0x66a9893cc07d91d95644aedd05d03f95e1dba8af").unwrap(),
            swap_params: SwapParams {
                zero_for_one: true,
                amount_specified: I256::try_from(-200000000000000000i128).unwrap(),
                sqrt_price_limit: U256::from(4295128740u64),
            },
            hook_data: Default::default(),
        };

        let result = hook_handler.before_swap(params, block, None, None);

        let res = result.unwrap().result;
        assert_eq!(
            res.amount_delta,
            BeforeSwapDelta(I256::from_raw(
                U256::from_str("68056473384187693032957288407292048885944984507633924869").unwrap()
            ))
        );
        assert_eq!(res.fee, U24::from(0));

        let expected_pool_manager_overwrites =            HashMap::from([
            (U256::from_str("79713336399215462747684527778665522702705876308670869673494720303103901230619").unwrap(), U256::from_str("78844352340497850335").unwrap()),
            (U256::from_str("108879414307233709404675130083871591294970341372768375199199972515051197806561").unwrap(), U256::from_str("21221083610867514702322193").unwrap()),
            (U256::from_str("66040010302484169318109846669699282294419705743047365478864291677462571000427").unwrap(), U256::from_str("6979725958049348898386").unwrap()),
            (U256::from_str("102130606322871718988206911149349113780831816677661791942959449920066266765719").unwrap(), U256::from_str("8016423715570101954005").unwrap()),
        ]);
        assert_eq!(
            *res.overwrites
                .get(&pool_manager)
                .unwrap(),
            expected_pool_manager_overwrites
        );

        // TODO: once transient storage is retrieved in the simulation, uncomment this
        // let expected_pool_manager_transient_storage =            HashMap::from([
        //         (U256::from_str("55705082733434384960622358509877205174921948415007105780397939750626106833531").unwrap(), U256::from_str("56868629622924134286587").unwrap()),
        //         (U256::from_str("72349358219047000942299849320276948455843849691036087799430587987856838543874").unwrap(), U256::from_str("115792089237316195423570985008687907853269984665640564039457384007913129639936").unwrap()),
        //         (U256::from_str("87100234046427240614499661373387320107015461065347489303548037305558901893923").unwrap(), U256::from_str("1").unwrap()),
        //         (U256::from_str("56671960505278111519104690822132496699113179860588238901689140059013086026251").unwrap(), U256::from_str("2").unwrap()),
        //     ]);
        // assert_eq!(
        //     *res.transient_storage
        //         .get(&pool_manager)
        //         .unwrap(),
        //     expected_pool_manager_transient_storage
        // );
    }

    #[test]
    fn test_after_swap() {
        let block = BlockHeader {
            number: 15797251,
            hash: Bytes::from_str(
                "0x7032b93c5b0d419f2001f7c77c19ade6da92d2df147712eac1a27c7ffedfe410",
            )
            .unwrap(),
            timestamp: 1748397011,
            ..Default::default()
        };
        let db = SimulationDB::new(get_client(None), get_runtime(), Some(block.clone()));
        let engine = create_engine(db, true).expect("Failed to create simulation engine");

        // pool manager on ethereum
        let pool_manager = Address::from_str("0x000000000004444c5dc75cB358380D2e3dE08A90")
            .expect("Invalid pool manager address");

        let pool_manager_bytecode = Bytecode::new_raw(POOL_MANAGER_BYTECODE.into());

        engine.state.init_account(
            pool_manager,
            AccountInfo {
                balance: *MAX_BALANCE,
                nonce: 0,
                code_hash: B256::from(keccak256(pool_manager_bytecode.clone().bytes())),
                code: Some(pool_manager_bytecode),
            },
            None,
            false,
        );

        let hook_address = Address::from_str("0x0010d0d5db05933fa0d9f7038d365e1541a41888")
            .expect("Invalid hook address");

        // This bytecode corresponds to LimitOrder example hook https://github.com/Uniswap/v4-periphery/blob/example-contracts/contracts/hooks/examples/LimitOrder.sol
        // To get the bytecode:
        //  - we had to change the `IPoolManager public immutable manager` from an immutable to a
        //    constant and hardcode the pool manager address. This is necessary because the
        //    immutable variables are only filled in at (real) deployment time, if we just want to
        //    inspect the bytecode they will be set to zero.
        //  - `forge inspect LimitOrder deployedBytecode` to get the bytecode.
        let bytecode =
            Bytecode::new_raw(include_bytes!("assets/after_swap_test_hook_bytecode.bin").into());

        engine.state.init_account(
            hook_address,
            AccountInfo {
                balance: *MAX_BALANCE,
                nonce: 0,
                code_hash: B256::from(keccak256(bytecode.clone().bytes())),
                code: Some(bytecode),
            },
            None,
            true,
        );

        let hook_handler = GenericVMHookHandler::new(
            hook_address,
            engine,
            pool_manager,
            HashMap::new(),
            HashMap::new(),
            None,
        )
        .expect("Failed to create GenericVMHookHandler");

        let context = StateContext {
            currency_0: Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            currency_1: Address::from_str("0x000000c396558ffbab5ea628f39658bdf61345b3").unwrap(),
            fees: UniswapV4Fees { zero_for_one: 0, one_for_zero: 0, lp_fee: 1 },
            tick_spacing: 60,
        };
        let swap_params = SwapParams {
            zero_for_one: true,
            amount_specified: I256::try_from(-200000000000000000i128).unwrap(),
            sqrt_price_limit: U256::from(4295128740u64),
        };

        let after_swap_params = AfterSwapParameters {
            context,
            sender: Address::from_str("0x66a9893cc07d91d95644aedd05d03f95e1dba8af").unwrap(),
            swap_params,
            delta: BalanceDelta(
                I256::from_dec_str("-3777134272822416944443458142492627143113384069767150805")
                    .unwrap(),
            ),
            hook_data: Bytes::new(),
        };

        let result = hook_handler.after_swap(after_swap_params, block, None, None);

        let res = result.unwrap().result;
        // This hook does not return any delta, so we expect it to be zero.
        assert_eq!(res, I128::ZERO);
    }

    #[test]
    fn test_before_and_after_swap() {
        let block = BlockHeader {
            number: 15797251,
            hash: Bytes::from_str(
                "0x7032b93c5b0d419f2001f7c77c19ade6da92d2df147712eac1a27c7ffedfe410",
            )
            .unwrap(),
            timestamp: 1746562410,
            ..Default::default()
        };
        let db = SimulationDB::new(
            get_client(Some("https://unichain.drpc.org".into())),
            get_runtime(),
            Some(block.clone()),
        );
        let engine = create_engine(db, true).expect("Failed to create simulation engine");

        let hook_address = Address::from_str("0x7f7d7e4a9d4da8997730997983c5ca64846868c0")
            .expect("Invalid hook address");

        let pool_manager = Address::from_str("0x1F98400000000000000000000000000000000004")
            .expect("Invalid pool manager address");

        let hook_handler = GenericVMHookHandler::new(
            hook_address,
            engine,
            pool_manager,
            HashMap::new(),
            HashMap::new(),
            None,
        )
        .expect("Failed to create GenericVMHookHandler");

        let universal_router =
            Address::from_str("0xef740bf23acae26f6492b10de645d6b98dc8eaf3").unwrap();

        // simulating this tx: 0x6f471e490570c89482e44edd286db35b2dd93c52307bfe6f28dbe8ed3326470d on
        // unichain
        let context = StateContext {
            currency_0: Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            currency_1: Address::from_str("0x7edc481366a345d7f9fcecb207408b5f2887ff99").unwrap(),
            fees: UniswapV4Fees { zero_for_one: 0, one_for_zero: 0, lp_fee: 100 },
            tick_spacing: 1,
        };
        let swap_params = SwapParams {
            zero_for_one: true,
            amount_specified: I256::from_dec_str("-11100000000000000").unwrap(),
            sqrt_price_limit: U256::from_str("4295128740").unwrap(),
        };
        let params = BeforeSwapParameters {
            context: context.clone(),
            sender: universal_router,
            swap_params: swap_params.clone(),
            hook_data: Default::default(),
        };
        // Setting the sender in UniversalRouter transient storage
        let sender = Address::from_str("0xceeb96f4733ba07ca56d0052fb132ffa1e0d7b16").unwrap();
        let is_unlocked_slot = U256::from_be_bytes(keccak256("Locker").0) - U256::from(1);
        let mut transient_storage = HashMap::from([(
            universal_router,
            HashMap::from([(is_unlocked_slot, U256::from_be_slice(sender.as_slice()))]),
        )]);

        let result = hook_handler
            .before_swap(params, block.clone(), None, Some(transient_storage.clone()))
            .unwrap();

        assert_eq!(result.result.amount_delta, BeforeSwapDelta(I256::from_dec_str("0").unwrap()));

        let after_swap_params = AfterSwapParameters {
            context,
            sender: universal_router,
            swap_params,
            delta: BalanceDelta(
                I256::from_dec_str("-3777134272822416944443458142492627143113384069767150805")
                    .unwrap(),
            ),
            hook_data: Bytes::new(),
        };

        transient_storage.extend(result.result.transient_storage);
        let result = hook_handler.after_swap(
            after_swap_params,
            block,
            Some(result.result.overwrites),
            Some(transient_storage),
        );

        let res = result.unwrap().result;
        // This hook does not return any delta, so we expect it to be zero.
        assert_eq!(res, I128::ZERO);
    }

    #[test]
    fn test_get_amount_ranges() {
        let block = BlockHeader {
            number: 15797251,
            hash: Bytes::from_str(
                "0x7032b93c5b0d419f2001f7c77c19ade6da92d2df147712eac1a27c7ffedfe410",
            )
            .unwrap(),
            timestamp: 1748397011,
            ..Default::default()
        };
        let db = SimulationDB::new(get_client(None), get_runtime(), Some(block.clone()));
        let engine = create_engine(db, true).expect("Failed to create simulation engine");

        let hook_address = Address::from_str("0x0010d0d5db05933fa0d9f7038d365e1541a41888")
            .expect("Invalid hook address");

        let pool_manager = Address::from_str("0x000000000004444c5dc75cB358380D2e3dE08A90")
            .expect("Invalid pool manager address");

        // The limits contract address from the provided entrypoint
        let limits_contract_address =
            Address::from_str("0x69058613588536167ba0aa94f0cc1fe420ef28a8")
                .expect("Invalid limits contract address");

        // Deploy mock getLimits contract to avoid intricacies of existing contracts
        //
        // Bytecode retrieved by running `forge inspect Limits deployedBytecode` on the following
        // contract (must be converted to a Solidity file):
        //
        // // SPDX-License-Identifier: UNLICENSED
        // pragma solidity ^0.8.26;
        //
        // contract Limits {
        //     function getLimits(address a, address b) external pure returns (uint256, uint256) {
        //         require(a != address(0) && b != address(0));
        //         return (1000, 2000);
        //     }
        // }
        let limits_bytecode = {
            Bytecode::new_raw(
                AlloyBytes::from_str("0x60808060405260043610156011575f80fd5b5f3560e01c63aaed87a3146023575f80fd5b34607a576040366003190112607a576004356001600160a01b03811690819003607a576024356001600160a01b0381169190829003607a5715159081607e575b5015607a57806103e8604092526107d06020820152f35b5f80fd5b905015155f606356fea2646970667358221220dba2ce58a718a2bf997701d130cb01ae2e5da7c456269ba47dd0c405b90862f064736f6c634300081c0033").unwrap()
            )
        };

        // Initialize the limits contract with the mock bytecode
        engine.state.init_account(
            limits_contract_address,
            AccountInfo {
                balance: *MAX_BALANCE,
                nonce: 0,
                code_hash: B256::from(keccak256(limits_bytecode.clone().bytes())),
                code: Some(limits_bytecode),
            },
            None,
            true,
        );

        // Encode function signature as expected in TychoSimulationContract.encode_input
        let limits_entrypoint =
            "0x69058613588536167ba0aa94f0cc1fe420ef28a8:getLimits(address,address)";
        let hook_handler = GenericVMHookHandler::new(
            hook_address,
            engine,
            pool_manager,
            HashMap::new(),
            HashMap::new(),
            Some(limits_entrypoint.to_string()),
        )
        .expect("Failed to create GenericVMHookHandler");

        let token_in = Bytes::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap(); // USDC
        let token_out = Bytes::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap(); // WETH

        let result = hook_handler.get_amount_ranges(token_in, token_out);

        match result {
            Ok(ranges) => {
                assert_eq!(ranges.amount_in_range.0, U256::ZERO);
                assert_eq!(ranges.amount_out_range.0, U256::ZERO);

                let expected_limit_1 = U256::from_str("1000").unwrap();
                let expected_limit_2 = U256::from_str("2000").unwrap();

                assert_eq!(ranges.amount_in_range.1, expected_limit_1);
                assert_eq!(ranges.amount_out_range.1, expected_limit_2);
            }
            Err(e) => {
                panic!("get_amount_out ranges failed {e}");
            }
        }
    }
}
