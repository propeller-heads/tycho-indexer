#![allow(dead_code)]

use std::{any::Any, collections::HashMap, fmt::Debug};

use alloy::{
    primitives::{keccak256, Address, Signed, Uint, B256, I256, U256},
    sol_types::SolType,
};
use revm::{
    state::{AccountInfo, Bytecode},
    DatabaseRef,
};
use tycho_common::{dto::ProtocolStateDelta, Bytes};

use crate::{
    evm::{
        engine_db::{engine_db_interface::EngineDatabaseInterface, simulation_db::BlockHeader},
        protocol::{
            uniswap_v4::{
                hooks::{
                    constants::POOL_MANAGER_BYTECODE,
                    hook_handler::{
                        AfterSwapParameters, AfterSwapSolReturn, AmountRanges, BeforeSwapDelta,
                        BeforeSwapOutput, BeforeSwapParameters, BeforeSwapSolOutput, HookHandler,
                        SwapParams, WithGasEstimate,
                    },
                },
                state::UniswapV4State,
            },
            vm::{constants::MAX_BALANCE, tycho_simulation_contract::TychoSimulationContract},
        },
        simulation::SimulationEngine,
    },
    models::{Balances, Token},
    protocol::errors::{SimulationError, TransitionError},
};

#[derive(Debug, Clone)]
pub struct GenericVMHookHandler<D: EngineDatabaseInterface + Clone + Debug>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    contract: TychoSimulationContract<D>,
    address: Address,
    pool_manager: Address,
}

impl<D: EngineDatabaseInterface + Clone + Debug> PartialEq for GenericVMHookHandler<D>
where
    <D as DatabaseRef>::Error: Debug,
    <D as EngineDatabaseInterface>::Error: Debug,
{
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.pool_manager == other.pool_manager
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
    ) -> Result<Self, SimulationError> {
        // TODO overwrite token balances (see how it's done in EVMPoolState)

        // Init pool manager
        // For now we use saved bytecode, but tycho-indexer should be able to provide this
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

        Ok(GenericVMHookHandler {
            contract: TychoSimulationContract::new(address, engine)?,
            address,
            pool_manager,
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
                Signed::<24, 1>::try_from(params.context.tick).map_err(|e| {
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
    ) -> Result<WithGasEstimate<BeforeSwapDelta>, SimulationError> {
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
                Signed::<24, 1>::try_from(params.context.tick).map_err(|e| {
                    SimulationError::FatalError(format!("Failed to convert tick: {e:?}"))
                })?,
                self.address,
            ),
            (
                params.swap_params.zero_for_one,
                params.swap_params.amount_specified,
                params.swap_params.sqrt_price_limit,
            ),
            params.delta,
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
            result: I256::try_from(decoded.delta).map_err(|e| {
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
        _token_in: Address,
        _token_out: Address,
    ) -> Result<AmountRanges, SimulationError> {
        Err(SimulationError::RecoverableError(
            "get_amount_ranges is not implemented for GenericVMHookHandler".to_string(),
        ))
    }

    fn delta_transition(
        &mut self,
        _delta: ProtocolStateDelta,
        _tokens: &HashMap<Bytes, Token>,
        _balances: &Balances,
    ) -> Result<(), TransitionError<String>> {
        Err(TransitionError::SimulationError(SimulationError::RecoverableError(
            "delta_transition is not implemented for GenericVMHookHandler".to_string(),
        )))
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
    use std::str::FromStr;

    use alloy::primitives::{aliases::U24, Bytes as AlloyBytes, B256, I256};

    use super::*;
    use crate::evm::{
        engine_db::{
            create_engine,
            simulation_db::{BlockHeader, SimulationDB},
            utils::{get_client, get_runtime},
        },
        protocol::uniswap_v4::{hooks::hook_handler::StateContext, state::UniswapV4Fees},
    };

    #[test]
    fn test_before_swap() {
        let block = BlockHeader {
            number: 22578103,
            hash: B256::from_str(
                "0x035c0e674c3bf3384a74b766908ab41c1968e989360aa26bea1dd64b1626f5f0",
            )
            .unwrap(),
            timestamp: 1748397011,
        };
        let db = SimulationDB::new(get_client(None), get_runtime(), Some(block));
        let engine = create_engine(db, true).expect("Failed to create simulation engine");

        let hook_address = Address::from_str("0x0010d0d5db05933fa0d9f7038d365e1541a41888")
            .expect("Invalid hook address");

        let pool_manager = Address::from_str("0x000000000004444c5dc75cb358380d2e3de08a90")
            .expect("Invalid pool manager address");

        let hook_handler = GenericVMHookHandler::new(
            hook_address,
            engine,
            pool_manager,
            HashMap::new(),
            HashMap::new(),
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
                tick: 60,
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
            I256::from_raw(
                U256::from_str("68056473384187693032957288407292048885944984507633924869").unwrap()
            )
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

        let expected_pool_manager_transient_storage =            HashMap::from([
                (U256::from_str("55705082733434384960622358509877205174921948415007105780397939750626106833531").unwrap(), U256::from_str("56868629622924134286587").unwrap()),
                (U256::from_str("72349358219047000942299849320276948455843849691036087799430587987856838543874").unwrap(), U256::from_str("115792089237316195423570985008687907853269984665640564039457384007913129639936").unwrap()),
                (U256::from_str("87100234046427240614499661373387320107015461065347489303548037305558901893923").unwrap(), U256::from_str("1").unwrap()),
                (U256::from_str("56671960505278111519104690822132496699113179860588238901689140059013086026251").unwrap(), U256::from_str("2").unwrap()),
            ]);
        assert_eq!(
            *res.transient_storage
                .get(&pool_manager)
                .unwrap(),
            expected_pool_manager_transient_storage
        );
    }

    #[test]
    fn test_after_swap() {
        let block = BlockHeader {
            number: 15797251,
            hash: B256::from_str(
                "0x7032b93c5b0d419f2001f7c77c19ade6da92d2df147712eac1a27c7ffedfe410",
            )
            .unwrap(),
            timestamp: 1748397011,
        };
        let db = SimulationDB::new(get_client(None), get_runtime(), Some(block));
        let engine = create_engine(db, true).expect("Failed to create simulation engine");

        // pool manager on ethereum
        let pool_manager = Address::from_str("0x000000000004444c5dc75cB358380D2e3dE08A90")
            .expect("Invalid pool manager address");

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
        )
        .expect("Failed to create GenericVMHookHandler");

        let context = StateContext {
            currency_0: Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            currency_1: Address::from_str("0x000000c396558ffbab5ea628f39658bdf61345b3").unwrap(),
            fees: UniswapV4Fees { zero_for_one: 0, one_for_zero: 0, lp_fee: 1 },
            tick: 60,
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
            delta: I256::from_dec_str("-3777134272822416944443458142492627143113384069767150805")
                .unwrap(),
            hook_data: Bytes::new(),
        };

        let result = hook_handler.after_swap(after_swap_params, block, None, None);

        let res = result.unwrap().result;
        // This hook does not return any delta, so we expect it to be zero.
        assert_eq!(res, I256::from_raw(U256::from_str("0").unwrap()));
    }
    #[test]
    fn test_before_and_after_swap() {
        let block = BlockHeader {
            number: 15797251,
            hash: B256::from_str(
                "0x7032b93c5b0d419f2001f7c77c19ade6da92d2df147712eac1a27c7ffedfe410",
            )
            .unwrap(),
            timestamp: 1746562410,
        };
        let db = SimulationDB::new(
            get_client(Some("https://unichain.drpc.org".into())),
            get_runtime(),
            Some(block),
        );
        let engine = create_engine(db, true).expect("Failed to create simulation engine");

        let hook_address = Address::from_str("0x7f7d7e4a9d4da8997730997983c5ca64846868c0")
            .expect("Invalid hook address");

        // Unimon bytecode obtained from blockchain explorer.
        let bytecode = Bytecode::new_raw(AlloyBytes::from_str("0x608060405234801561000f575f80fd5b5060043610610340575f3560e01c806373bd699a116101b6578063b7c9ce4211610102578063d24513bd116100a0578063e1b4af691161007a578063e1b4af6914610a7c578063e985e9c514610aac578063eb79f87714610adc578063f2fde38b14610afa57610340565b8063d24513bd146109fe578063dc4c90d314610a2e578063dc98354e14610a4c57610340565b8063c002d23d116100dc578063c002d23d14610976578063c4e833ce14610994578063c87b56dd146109b2578063c9886dc3146109e257610340565b8063b7c9ce421461090c578063b88d4fde1461093c578063bd60b83f1461095857610340565b8063a0cf0aea1161016f578063a49062d411610149578063a49062d41461085c578063aff261571461087a578063b47b2fb1146108ab578063b6a8b0fa146108dc57610340565b8063a0cf0aea14610804578063a22cb46514610822578063a242a7ad1461083e57610340565b806373bd699a1461073d57806375794a3c1461075b57806386074985146107795780638da5cb5b1461079757806395d89b41146107b55780639f063efc146107d357610340565b80633691699511610290578063575e24b41161022e5780636c2bbe7e116102085780636c2bbe7e146106a25780636fe7e6eb146106d357806370a0823114610703578063715018a61461073357610340565b8063575e24b4146106225780636352211e146106545780636c0360eb1461068457610340565b806342842e0e1161026a57806342842e0e1461058a5780634abe17fd146105a65780634f6ccce7146105d657806355f804b31461060657610340565b8063369169951461053457806339433a09146105505780633e592ccb1461056c57610340565b806321d0ee70116102fd578063259982e5116102d7578063259982e51461049a5780632f745c59146104ca57806332cb6b0c146104fa57806333c3d0591461051857610340565b806321d0ee701461041e57806323b872dd1461044e578063240ff4d41461046a57610340565b806301ffc9a71461034457806306fdde0314610374578063081812fc14610392578063095ea7b3146103c257806318160ddd146103de578063182148ef146103fc575b5f80fd5b61035e60048036038101906103599190613e5e565b610b16565b60405161036b9190613ea3565b60405180910390f35b61037c610b27565b6040516103899190613f2c565b60405180910390f35b6103ac60048036038101906103a79190613f7f565b610bb7565b6040516103b99190613fe9565b60405180910390f35b6103dc60048036038101906103d7919061402c565b610bd2565b005b6103e6610be8565b6040516103f39190614079565b60405180910390f35b610404610bf4565b604051610415959493929190614145565b60405180910390f35b61043860048036038101906104339190614237565b610c90565b60405161044591906142cc565b60405180910390f35b610468600480360381019061046391906142e5565b610d2e565b005b610484600480360381019061047f9190613f7f565b610e2d565b60405161049191906143e4565b60405180910390f35b6104b460048036038101906104af9190614237565b610e9b565b6040516104c191906142cc565b60405180910390f35b6104e460048036038101906104df919061402c565b610f39565b6040516104f19190614079565b60405180910390f35b610502610fdd565b60405161050f9190614079565b60405180910390f35b610532600480360381019061052d91906143fd565b610fe3565b005b61054e6004803603810190610549919061443b565b61142e565b005b61056a60048036038101906105659190614490565b611479565b005b61057461149d565b6040516105819190614079565b60405180910390f35b6105a4600480360381019061059f91906142e5565b6114a2565b005b6105c060048036038101906105bb919061443b565b6114c1565b6040516105cd9190613ea3565b60405180910390f35b6105f060048036038101906105eb9190613f7f565b6114de565b6040516105fd9190614079565b60405180910390f35b610620600480360381019061061b91906145e3565b611550565b005b61063c60048036038101906106379190614648565b61156b565b60405161064b93929190614707565b60405180910390f35b61066e60048036038101906106699190613f7f565b611611565b60405161067b9190613fe9565b60405180910390f35b61068c611622565b6040516106999190613f2c565b60405180910390f35b6106bc60048036038101906106b79190614766565b6116ae565b6040516106ca929190614823565b60405180910390f35b6106ed60048036038101906106e8919061489e565b611754565b6040516106fa91906142cc565b60405180910390f35b61071d6004803603810190610718919061443b565b6117f0565b60405161072a9190614079565b60405180910390f35b61073b6118a6565b005b6107456118b9565b6040516107529190613ea3565b60405180910390f35b6107636118cc565b6040516107709190614079565b60405180910390f35b6107816118d2565b60405161078e9190614079565b60405180910390f35b61079f6118d7565b6040516107ac9190613fe9565b60405180910390f35b6107bd6118fe565b6040516107ca9190613f2c565b60405180910390f35b6107ed60048036038101906107e89190614766565b61198e565b6040516107fb929190614823565b60405180910390f35b61080c611a34565b6040516108199190613fe9565b60405180910390f35b61083c60048036038101906108379190614903565b611a38565b005b610846611a4e565b6040516108539190614961565b60405180910390f35b610864611a73565b6040516108719190614079565b60405180910390f35b610894600480360381019061088f9190613f7f565b611a78565b6040516108a2929190614989565b60405180910390f35b6108c560048036038101906108c091906149b0565b611aa4565b6040516108d3929190614a64565b60405180910390f35b6108f660048036038101906108f19190614a8b565b611b48565b60405161090391906142cc565b60405180910390f35b61092660048036038101906109219190614b56565b611be8565b6040516109339190613fe9565b60405180910390f35b61095660048036038101906109519190614c1f565b611c18565b005b610960611c3d565b60405161096d9190614079565b60405180910390f35b61097e611c42565b60405161098b9190614079565b60405180910390f35b61099c611c4d565b6040516109a99190614dcc565b60405180910390f35b6109cc60048036038101906109c79190613f7f565b611cd8565b6040516109d99190613f2c565b60405180910390f35b6109fc60048036038101906109f7919061443b565b611d34565b005b610a186004803603810190610a139190613f7f565b611ddd565b604051610a259190614de6565b60405180910390f35b610a36611e05565b604051610a439190614e1f565b60405180910390f35b610a666004803603810190610a619190614e38565b611e29565b604051610a7391906142cc565b60405180910390f35b610a966004803603810190610a919190614a8b565b611ec3565b604051610aa391906142cc565b60405180910390f35b610ac66004803603810190610ac19190614e88565b611f63565b604051610ad39190613ea3565b60405180910390f35b610ae4611ff1565b604051610af19190613ea3565b60405180910390f35b610b146004803603810190610b0f919061443b565b612003565b005b5f610b2082612087565b9050919050565b606060018054610b3690614ef3565b80601f0160208091040260200160405190810160405280929190818152602001828054610b6290614ef3565b8015610bad5780601f10610b8457610100808354040283529160200191610bad565b820191905f5260205f20905b815481529060010190602001808311610b9057829003601f168201915b5050505050905090565b5f610bc182612100565b50610bcb82612186565b9050919050565b610be48282610bdf6121bf565b6121c6565b5050565b5f600980549050905090565b600e805f015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690806001015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060010160149054906101000a900462ffffff16908060010160179054906101000a900460020b90806002015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905085565b5f7f0000000000000000000000001f9840000000000000000000000000000000000473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610d16576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b610d2386868686866121d8565b905095945050505050565b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603610d9e575f6040517f64a0ae92000000000000000000000000000000000000000000000000000000008152600401610d959190613fe9565b60405180910390fd5b5f610db18383610dac6121bf565b61220b565b90508373ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614610e27578382826040517f64283d7b000000000000000000000000000000000000000000000000000000008152600401610e1e93929190614f23565b60405180910390fd5b50505050565b610e35613d51565b60125f8381526020019081526020015f206040518060400160405290815f82015f9054906101000a900460ff166001811115610e7457610e73614335565b5b6001811115610e8657610e85614335565b5b81526020016001820154815250509050919050565b5f7f0000000000000000000000001f9840000000000000000000000000000000000473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610f21576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b610f2e8686868686612220565b905095945050505050565b5f610f43836117f0565b8210610f885782826040517fa57d13dc000000000000000000000000000000000000000000000000000000008152600401610f7f929190614f58565b60405180910390fd5b60075f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8381526020019081526020015f2054905092915050565b61271081565b600d5f9054906101000a900460ff16611028576040517f5a1d5f0a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff1661104883611611565b73ffffffffffffffffffffffffffffffffffffffff1614611095576040517f4c084f1400000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b60018110806110a45750600a81115b156110db576040517f2160733900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f60018111156110ee576110ed614335565b5b60125f8481526020019081526020015f205f015f9054906101000a900460ff1660018111156111205761111f614335565b5b14611157576040517ff8b09edb00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f60115f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663313ce5676040518163ffffffff1660e01b8152600401602060405180830381865afa1580156111c2573d5f803e3d5ffd5b505050506040513d601f19601f820116820180604052508101906111e69190614fb5565b600a6111f2919061513c565b826111fd9190615186565b90508060115f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166370a08231336040518263ffffffff1660e01b815260040161125a9190613fe9565b602060405180830381865afa158015611275573d5f803e3d5ffd5b505050506040513d601f19601f8201168201806040525081019061129991906151db565b10156112d1576040517fe4455cae00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b60115f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16639dc29fac33836040518363ffffffff1660e01b815260040161132d929190614f58565b5f604051808303815f87803b158015611344575f80fd5b505af1158015611356573d5f803e3d5ffd5b505050505f42443386604051602001611372949392919061526b565b6040516020818303038152906040528051906020012090505f611395848361229f565b9050600160125f8781526020019081526020015f205f015f6101000a81548160ff021916908360018111156113cd576113cc614335565b5b02179055508060125f8781526020019081526020015f2060010181905550847f978b8e1356eff37256f702d03805c160030dacc08cc13ac5552f4679fe5b30ec85838560405161141f939291906152c7565b60405180910390a25050505050565b611436612383565b8060115f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b611481612383565b80600d5f6101000a81548160ff02191690831515021790555050565b606481565b6114bc83838360405180602001604052805f815250611c18565b505050565b6013602052805f5260405f205f915054906101000a900460ff1681565b5f6114e7610be8565b821061152c575f826040517fa57d13dc000000000000000000000000000000000000000000000000000000008152600401611523929190614f58565b60405180910390fd5b600982815481106115405761153f6152fc565b5b905f5260205f2001549050919050565b611558612383565b80600b908161156791906154bd565b5050565b5f805f7f0000000000000000000000001f9840000000000000000000000000000000000473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146115f3576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b611600888888888861240a565b925092509250955095509592505050565b5f61161b82612100565b9050919050565b600b805461162f90614ef3565b80601f016020809104026020016040519081016040528092919081815260200182805461165b90614ef3565b80156116a65780601f1061167d576101008083540402835291602001916116a6565b820191905f5260205f20905b81548152906001019060200180831161168957829003601f168201915b505050505081565b5f807f0000000000000000000000001f9840000000000000000000000000000000000473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614611735576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b61174489898989898989612685565b9150915097509795505050505050565b5f7f0000000000000000000000001f9840000000000000000000000000000000000473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146117da576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b6117e6858585856126b9565b9050949350505050565b5f8073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603611861575f6040517f89c62b640000000000000000000000000000000000000000000000000000000081526004016118589190613fe9565b60405180910390fd5b60045f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20549050919050565b6118ae612383565b6118b75f6126ec565b565b600d60019054906101000a900460ff1681565b600c5481565b602081565b5f805f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b60606002805461190d90614ef3565b80601f016020809104026020016040519081016040528092919081815260200182805461193990614ef3565b80156119845780601f1061195b57610100808354040283529160200191611984565b820191905f5260205f20905b81548152906001019060200180831161196757829003601f168201915b5050505050905090565b5f807f0000000000000000000000001f9840000000000000000000000000000000000473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614611a15576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b611a24898989898989896127ad565b9150915097509795505050505050565b5f81565b611a4a611a436121bf565b83836127e1565b5050565b60115f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600a81565b6012602052805f5260405f205f91509050805f015f9054906101000a900460ff16908060010154905082565b5f807f0000000000000000000000001f9840000000000000000000000000000000000473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614611b2b576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b611b3988888888888861294a565b91509150965096945050505050565b5f7f0000000000000000000000001f9840000000000000000000000000000000000473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614611bce576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b611bdc878787878787612c94565b90509695505050505050565b6014602052805f5260405f205f915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b611c23848484610d2e565b611c37611c2e6121bf565b85858585612cc7565b50505050565b600181565b66276f642501c00081565b611c55613d7b565b604051806101c001604052806001151581526020015f151581526020016001151581526020015f151581526020015f151581526020015f151581526020016001151581526020016001151581526020015f151581526020015f151581526020015f151581526020015f151581526020015f151581526020015f1515815250905090565b60605f611ce3612e73565b90505f815111611d015760405180602001604052805f815250611d2c565b80611d0b84612f03565b604051602001611d1c9291906155c6565b6040516020818303038152906040525b915050919050565b611d3c612383565b60135f8273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f9054906101000a900460ff161560135f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f6101000a81548160ff02191690831515021790555050565b5f60125f8381526020019081526020015f205f015f9054906101000a900460ff169050919050565b7f0000000000000000000000001f9840000000000000000000000000000000000481565b5f7f0000000000000000000000001f9840000000000000000000000000000000000473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614611eaf576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b611eba848484612fcd565b90509392505050565b5f7f0000000000000000000000001f9840000000000000000000000000000000000473ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614611f49576040517fae18210a00000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b611f5787878787878761307a565b90509695505050505050565b5f60065f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f9054906101000a900460ff16905092915050565b600d5f9054906101000a900460ff1681565b61200b612383565b5f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff160361207b575f6040517f1e4fbdf70000000000000000000000000000000000000000000000000000000081526004016120729190613fe9565b60405180910390fd5b612084816126ec565b50565b5f7f780e9d63000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff191614806120f957506120f8826130ad565b5b9050919050565b5f8061210b8361318e565b90505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff160361217d57826040517f7e2732890000000000000000000000000000000000000000000000000000000081526004016121749190614079565b60405180910390fd5b80915050919050565b5f60055f8381526020019081526020015f205f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b5f33905090565b6121d383838360016131c7565b505050565b5f6040517f0a85dc2900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f612217848484613386565b90509392505050565b5f600d60019054906101000a900460ff1615612271576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161226890615659565b60405180910390fd5b6001600d60016101000a81548160ff02191690831515021790555063259982e560e01b905095945050505050565b5f808242336040516020016122b693929190615697565b604051602081830303815290604052805190602001205f1c90505f6002856122de9190615700565b60016122ea9190615730565b90505f81866122f99190615763565b90505f6064846123099190615796565b90505f6006886123199190615186565b60146123259190615730565b821015612355575f8311612339575f612352565b82856123459190615796565b60016123519190615730565b5b90505b5f81856123629190615730565b9050600a81116123725780612375565b600a5b965050505050505092915050565b61238b6121bf565b73ffffffffffffffffffffffffffffffffffffffff166123a96118d7565b73ffffffffffffffffffffffffffffffffffffffff1614612408576123cc6121bf565b6040517f118cdaa70000000000000000000000000000000000000000000000000000000081526004016123ff9190613fe9565b60405180910390fd5b565b5f805f60135f8973ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f9054906101000a900460ff1661248d576040517fbeebc0d200000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f8873ffffffffffffffffffffffffffffffffffffffff1663d737d0c76040518163ffffffff1660e01b8152600401602060405180830381865afa1580156124d7573d5f803e3d5ffd5b505050506040513d601f19601f820116820180604052508101906124fb91906157da565b90505f4282896020013560405160200161251793929190615825565b6040516020818303038152906040528051906020012090508160145f8381526020019081526020015f205f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505f885f0160208101906125919190614490565b6125db575f73ffffffffffffffffffffffffffffffffffffffff168a60200160208101906125bf919061588b565b73ffffffffffffffffffffffffffffffffffffffff161461261c565b5f73ffffffffffffffffffffffffffffffffffffffff168a5f016020810190612604919061588b565b73ffffffffffffffffffffffffffffffffffffffff16145b90508061265e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161265590615926565b60405180910390fd5b63575e24b460e01b6126705f806134a0565b5f955095509550505050955095509592505050565b5f806040517f0a85dc2900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f6040517f0a85dc2900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f805f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050815f806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b5f806040517f0a85dc2900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff160361285157816040517f5b08ba180000000000000000000000000000000000000000000000000000000081526004016128489190613fe9565b60405180910390fd5b8060065f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f6101000a81548160ff0219169083151502179055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c318360405161293d9190613ea3565b60405180910390a3505050565b5f805f428973ffffffffffffffffffffffffffffffffffffffff1663d737d0c76040518163ffffffff1660e01b8152600401602060405180830381865afa158015612997573d5f803e3d5ffd5b505050506040513d601f19601f820116820180604052508101906129bb91906157da565b88602001356040516020016129d293929190615825565b6040516020818303038152906040528051906020012090505f60145f8381526020019081526020015f205f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690505f66276f642501c0008960200135612a3590615944565b612a3f9190615700565b90505f8103612a905760145f8481526020019081526020015f205f6101000a81549073ffffffffffffffffffffffffffffffffffffffff021916905563b47b2fb160e01b5f94509450505050612c89565b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603612afe576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401612af5906159d4565b60405180910390fd5b6064811115612b42576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401612b3990615a62565b60405180910390fd5b61271081600c54612b539190615730565b10612b93576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401612b8a90615aca565b60405180910390fd5b5f5b81811015612c44575f600c549050612bad84826134b7565b60405180604001604052805f6001811115612bcb57612bca614335565b5b81526020015f81525060125f8381526020019081526020015f205f820151815f015f6101000a81548160ff02191690836001811115612c0d57612c0c614335565b5b021790555060208201518160010155905050600c5f815480929190612c3190615ae8565b9190505550508080600101915050612b95565b5060145f8481526020019081526020015f205f6101000a81549073ffffffffffffffffffffffffffffffffffffffff021916905563b47b2fb160e01b5f945094505050505b965096945050505050565b5f6040517f0a85dc2900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f8373ffffffffffffffffffffffffffffffffffffffff163b1115612e6c578273ffffffffffffffffffffffffffffffffffffffff1663150b7a02868685856040518563ffffffff1660e01b8152600401612d259493929190615b81565b6020604051808303815f875af1925050508015612d6057506040513d601f19601f82011682018060405250810190612d5d9190615bdf565b60015b612de1573d805f8114612d8e576040519150601f19603f3d011682016040523d82523d5f602084013e612d93565b606091505b505f815103612dd957836040517f64a0ae92000000000000000000000000000000000000000000000000000000008152600401612dd09190613fe9565b60405180910390fd5b805181602001fd5b63150b7a0260e01b7bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916817bffffffffffffffffffffffffffffffffffffffffffffffffffffffff191614612e6a57836040517f64a0ae92000000000000000000000000000000000000000000000000000000008152600401612e619190613fe9565b60405180910390fd5b505b5050505050565b6060600b8054612e8290614ef3565b80601f0160208091040260200160405190810160405280929190818152602001828054612eae90614ef3565b8015612ef95780601f10612ed057610100808354040283529160200191612ef9565b820191905f5260205f20905b815481529060010190602001808311612edc57829003601f168201915b5050505050905090565b60605f6001612f11846135aa565b0190505f8167ffffffffffffffff811115612f2f57612f2e6144bf565b5b6040519080825280601f01601f191660200182016040528015612f615781602001600182028036833780820191505090505b5090505f82602001820190505b600115612fc2578080600190039150507f3031323334353637383961626364656600000000000000000000000000000000600a86061a8153600a8581612fb757612fb66156d3565b5b0494505f8503612f6e575b819350505050919050565b5f8073ffffffffffffffffffffffffffffffffffffffff16600e6002015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614613057576040517f0dc149f000000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b82600e81816130669190615f21565b90505063dc98354e60e01b90509392505050565b5f6040517f0a85dc2900000000000000000000000000000000000000000000000000000000815260040160405180910390fd5b5f7f80ac58cd000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916148061317757507f5b5e139f000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916145b806131875750613186826136fb565b5b9050919050565b5f60035f8381526020019081526020015f205f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b80806131ff57505f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614155b15613331575f61320e84612100565b90505f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415801561327857508273ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614155b801561328b57506132898184611f63565b155b156132cd57826040517fa9fbf51f0000000000000000000000000000000000000000000000000000000081526004016132c49190613fe9565b60405180910390fd5b811561332f57838573ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92560405160405180910390a45b505b8360055f8581526020019081526020015f205f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050505050565b5f80613393858585613764565b90505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16036133d6576133d18461396f565b613415565b8473ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16146134145761341381856139b3565b5b5b5f73ffffffffffffffffffffffffffffffffffffffff168573ffffffffffffffffffffffffffffffffffffffff16036134565761345184613a8a565b613495565b8473ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614613494576134938585613b4a565b5b5b809150509392505050565b5f8160018060801b03168360801b17905092915050565b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603613527575f6040517f64a0ae9200000000000000000000000000000000000000000000000000000000815260040161351e9190613fe9565b60405180910390fd5b5f61353383835f61220b565b90505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16146135a5575f6040517f73c6ac6e00000000000000000000000000000000000000000000000000000000815260040161359c9190613fe9565b60405180910390fd5b505050565b5f805f90507a184f03e93ff9f4daa797ed6e38ed64bf6a1f0100000000000000008310613606577a184f03e93ff9f4daa797ed6e38ed64bf6a1f01000000000000000083816135fc576135fb6156d3565b5b0492506040810190505b6d04ee2d6d415b85acef81000000008310613643576d04ee2d6d415b85acef81000000008381613639576136386156d3565b5b0492506020810190505b662386f26fc10000831061367257662386f26fc100008381613668576136676156d3565b5b0492506010810190505b6305f5e100831061369b576305f5e1008381613691576136906156d3565b5b0492506008810190505b61271083106136c05761271083816136b6576136b56156d3565b5b0492506004810190505b606483106136e357606483816136d9576136d86156d3565b5b0492506002810190505b600a83106136f2576001810190505b80915050919050565b5f7f01ffc9a7000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916149050919050565b5f8061376f8461318e565b90505f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16146137b0576137af818486613bce565b5b5f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161461383b576137ef5f855f806131c7565b600160045f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825403925050819055505b5f73ffffffffffffffffffffffffffffffffffffffff168573ffffffffffffffffffffffffffffffffffffffff16146138ba57600160045f8773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825401925050819055505b8460035f8681526020019081526020015f205f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550838573ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef60405160405180910390a4809150509392505050565b600980549050600a5f8381526020019081526020015f2081905550600981908060018154018082558091505060019003905f5260205f20015f909190919091505550565b5f6139bd836117f0565b90505f60085f8481526020019081526020015f205490505f60075f8673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f209050828214613a5c575f815f8581526020019081526020015f2054905080825f8581526020019081526020015f20819055508260085f8381526020019081526020015f2081905550505b60085f8581526020019081526020015f205f9055805f8481526020019081526020015f205f90555050505050565b5f6001600980549050613a9d9190615763565b90505f600a5f8481526020019081526020015f205490505f60098381548110613ac957613ac86152fc565b5b905f5260205f20015490508060098381548110613ae957613ae86152fc565b5b905f5260205f20018190555081600a5f8381526020019081526020015f2081905550600a5f8581526020019081526020015f205f90556009805480613b3157613b30615f2f565b5b600190038181905f5260205f20015f9055905550505050565b5f6001613b56846117f0565b613b609190615763565b90508160075f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8381526020019081526020015f20819055508060085f8481526020019081526020015f2081905550505050565b613bd9838383613c91565b613c8c575f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1603613c4d57806040517f7e273289000000000000000000000000000000000000000000000000000000008152600401613c449190614079565b60405180910390fd5b81816040517f177e802f000000000000000000000000000000000000000000000000000000008152600401613c83929190614f58565b60405180910390fd5b505050565b5f8073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1614158015613d4857508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff161480613d095750613d088484611f63565b5b80613d4757508273ffffffffffffffffffffffffffffffffffffffff16613d2f83612186565b73ffffffffffffffffffffffffffffffffffffffff16145b5b90509392505050565b60405180604001604052805f6001811115613d6f57613d6e614335565b5b81526020015f81525090565b604051806101c001604052805f151581526020015f151581526020015f151581526020015f151581526020015f151581526020015f151581526020015f151581526020015f151581526020015f151581526020015f151581526020015f151581526020015f151581526020015f151581526020015f151581525090565b5f604051905090565b5f80fd5b5f80fd5b5f7fffffffff0000000000000000000000000000000000000000000000000000000082169050919050565b613e3d81613e09565b8114613e47575f80fd5b50565b5f81359050613e5881613e34565b92915050565b5f60208284031215613e7357613e72613e01565b5b5f613e8084828501613e4a565b91505092915050565b5f8115159050919050565b613e9d81613e89565b82525050565b5f602082019050613eb65f830184613e94565b92915050565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f601f19601f8301169050919050565b5f613efe82613ebc565b613f088185613ec6565b9350613f18818560208601613ed6565b613f2181613ee4565b840191505092915050565b5f6020820190508181035f830152613f448184613ef4565b905092915050565b5f819050919050565b613f5e81613f4c565b8114613f68575f80fd5b50565b5f81359050613f7981613f55565b92915050565b5f60208284031215613f9457613f93613e01565b5b5f613fa184828501613f6b565b91505092915050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f613fd382613faa565b9050919050565b613fe381613fc9565b82525050565b5f602082019050613ffc5f830184613fda565b92915050565b61400b81613fc9565b8114614015575f80fd5b50565b5f8135905061402681614002565b92915050565b5f806040838503121561404257614041613e01565b5b5f61404f85828601614018565b925050602061406085828601613f6b565b9150509250929050565b61407381613f4c565b82525050565b5f60208201905061408c5f83018461406a565b92915050565b5f819050919050565b5f6140b56140b06140ab84613faa565b614092565b613faa565b9050919050565b5f6140c68261409b565b9050919050565b5f6140d7826140bc565b9050919050565b6140e7816140cd565b82525050565b5f62ffffff82169050919050565b614104816140ed565b82525050565b5f8160020b9050919050565b61411f8161410a565b82525050565b5f61412f826140bc565b9050919050565b61413f81614125565b82525050565b5f60a0820190506141585f8301886140de565b61416560208301876140de565b61417260408301866140fb565b61417f6060830185614116565b61418c6080830184614136565b9695505050505050565b5f80fd5b5f60a082840312156141af576141ae614196565b5b81905092915050565b5f608082840312156141cd576141cc614196565b5b81905092915050565b5f80fd5b5f80fd5b5f80fd5b5f8083601f8401126141f7576141f66141d6565b5b8235905067ffffffffffffffff811115614214576142136141da565b5b6020830191508360018202830111156142305761422f6141de565b5b9250929050565b5f805f805f610160868803121561425157614250613e01565b5b5f61425e88828901614018565b955050602061426f8882890161419a565b94505060c0614280888289016141b8565b93505061014086013567ffffffffffffffff8111156142a2576142a1613e05565b5b6142ae888289016141e2565b92509250509295509295909350565b6142c681613e09565b82525050565b5f6020820190506142df5f8301846142bd565b92915050565b5f805f606084860312156142fc576142fb613e01565b5b5f61430986828701614018565b935050602061431a86828701614018565b925050604061432b86828701613f6b565b9150509250925092565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602160045260245ffd5b6002811061437357614372614335565b5b50565b5f81905061438382614362565b919050565b5f61439282614376565b9050919050565b6143a281614388565b82525050565b6143b181613f4c565b82525050565b604082015f8201516143cb5f850182614399565b5060208201516143de60208501826143a8565b50505050565b5f6040820190506143f75f8301846143b7565b92915050565b5f806040838503121561441357614412613e01565b5b5f61442085828601613f6b565b925050602061443185828601613f6b565b9150509250929050565b5f602082840312156144505761444f613e01565b5b5f61445d84828501614018565b91505092915050565b61446f81613e89565b8114614479575f80fd5b50565b5f8135905061448a81614466565b92915050565b5f602082840312156144a5576144a4613e01565b5b5f6144b28482850161447c565b91505092915050565b5f80fd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b6144f582613ee4565b810181811067ffffffffffffffff82111715614514576145136144bf565b5b80604052505050565b5f614526613df8565b905061453282826144ec565b919050565b5f67ffffffffffffffff821115614551576145506144bf565b5b61455a82613ee4565b9050602081019050919050565b828183375f83830152505050565b5f61458761458284614537565b61451d565b9050828152602081018484840111156145a3576145a26144bb565b5b6145ae848285614567565b509392505050565b5f82601f8301126145ca576145c96141d6565b5b81356145da848260208601614575565b91505092915050565b5f602082840312156145f8576145f7613e01565b5b5f82013567ffffffffffffffff81111561461557614614613e05565b5b614621848285016145b6565b91505092915050565b5f6060828403121561463f5761463e614196565b5b81905092915050565b5f805f805f610140868803121561466257614661613e01565b5b5f61466f88828901614018565b95505060206146808882890161419a565b94505060c06146918882890161462a565b93505061012086013567ffffffffffffffff8111156146b3576146b2613e05565b5b6146bf888289016141e2565b92509250509295509295909350565b5f819050919050565b5f6146f16146ec6146e7846146ce565b614092565b6146ce565b9050919050565b614701816146d7565b82525050565b5f60608201905061471a5f8301866142bd565b61472760208301856146f8565b61473460408301846140fb565b949350505050565b614745816146ce565b811461474f575f80fd5b50565b5f813590506147608161473c565b92915050565b5f805f805f805f6101a0888a03121561478257614781613e01565b5b5f61478f8a828b01614018565b97505060206147a08a828b0161419a565b96505060c06147b18a828b016141b8565b9550506101406147c38a828b01614752565b9450506101606147d58a828b01614752565b93505061018088013567ffffffffffffffff8111156147f7576147f6613e05565b5b6148038a828b016141e2565b925092505092959891949750929550565b61481d816146d7565b82525050565b5f6040820190506148365f8301856142bd565b6148436020830184614814565b9392505050565b61485381613faa565b811461485d575f80fd5b50565b5f8135905061486e8161484a565b92915050565b61487d8161410a565b8114614887575f80fd5b50565b5f8135905061489881614874565b92915050565b5f805f8061010085870312156148b7576148b6613e01565b5b5f6148c487828801614018565b94505060206148d58782880161419a565b93505060c06148e687828801614860565b92505060e06148f78782880161488a565b91505092959194509250565b5f806040838503121561491957614918613e01565b5b5f61492685828601614018565b92505060206149378582860161447c565b9150509250929050565b5f61494b826140bc565b9050919050565b61495b81614941565b82525050565b5f6020820190506149745f830184614952565b92915050565b61498381614388565b82525050565b5f60408201905061499c5f83018561497a565b6149a9602083018461406a565b9392505050565b5f805f805f8061016087890312156149cb576149ca613e01565b5b5f6149d889828a01614018565b96505060206149e989828a0161419a565b95505060c06149fa89828a0161462a565b945050610120614a0c89828a01614752565b93505061014087013567ffffffffffffffff811115614a2e57614a2d613e05565b5b614a3a89828a016141e2565b92509250509295509295509295565b5f81600f0b9050919050565b614a5e81614a49565b82525050565b5f604082019050614a775f8301856142bd565b614a846020830184614a55565b9392505050565b5f805f805f806101208789031215614aa657614aa5613e01565b5b5f614ab389828a01614018565b9650506020614ac489828a0161419a565b95505060c0614ad589828a01613f6b565b94505060e0614ae689828a01613f6b565b93505061010087013567ffffffffffffffff811115614b0857614b07613e05565b5b614b1489828a016141e2565b92509250509295509295509295565b5f819050919050565b614b3581614b23565b8114614b3f575f80fd5b50565b5f81359050614b5081614b2c565b92915050565b5f60208284031215614b6b57614b6a613e01565b5b5f614b7884828501614b42565b91505092915050565b5f67ffffffffffffffff821115614b9b57614b9a6144bf565b5b614ba482613ee4565b9050602081019050919050565b5f614bc3614bbe84614b81565b61451d565b905082815260208101848484011115614bdf57614bde6144bb565b5b614bea848285614567565b509392505050565b5f82601f830112614c0657614c056141d6565b5b8135614c16848260208601614bb1565b91505092915050565b5f805f8060808587031215614c3757614c36613e01565b5b5f614c4487828801614018565b9450506020614c5587828801614018565b9350506040614c6687828801613f6b565b925050606085013567ffffffffffffffff811115614c8757614c86613e05565b5b614c9387828801614bf2565b91505092959194509250565b614ca881613e89565b82525050565b6101c082015f820151614cc35f850182614c9f565b506020820151614cd66020850182614c9f565b506040820151614ce96040850182614c9f565b506060820151614cfc6060850182614c9f565b506080820151614d0f6080850182614c9f565b5060a0820151614d2260a0850182614c9f565b5060c0820151614d3560c0850182614c9f565b5060e0820151614d4860e0850182614c9f565b50610100820151614d5d610100850182614c9f565b50610120820151614d72610120850182614c9f565b50610140820151614d87610140850182614c9f565b50610160820151614d9c610160850182614c9f565b50610180820151614db1610180850182614c9f565b506101a0820151614dc66101a0850182614c9f565b50505050565b5f6101c082019050614de05f830184614cae565b92915050565b5f602082019050614df95f83018461497a565b92915050565b5f614e09826140bc565b9050919050565b614e1981614dff565b82525050565b5f602082019050614e325f830184614e10565b92915050565b5f805f60e08486031215614e4f57614e4e613e01565b5b5f614e5c86828701614018565b9350506020614e6d8682870161419a565b92505060c0614e7e86828701614860565b9150509250925092565b5f8060408385031215614e9e57614e9d613e01565b5b5f614eab85828601614018565b9250506020614ebc85828601614018565b9150509250929050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f6002820490506001821680614f0a57607f821691505b602082108103614f1d57614f1c614ec6565b5b50919050565b5f606082019050614f365f830186613fda565b614f43602083018561406a565b614f506040830184613fda565b949350505050565b5f604082019050614f6b5f830185613fda565b614f78602083018461406a565b9392505050565b5f60ff82169050919050565b614f9481614f7f565b8114614f9e575f80fd5b50565b5f81519050614faf81614f8b565b92915050565b5f60208284031215614fca57614fc9613e01565b5b5f614fd784828501614fa1565b91505092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f8160011c9050919050565b5f808291508390505b60018511156150625780860481111561503e5761503d614fe0565b5b600185161561504d5780820291505b808102905061505b8561500d565b9450615022565b94509492505050565b5f8261507a5760019050615135565b81615087575f9050615135565b816001811461509d57600281146150a7576150d6565b6001915050615135565b60ff8411156150b9576150b8614fe0565b5b8360020a9150848211156150d0576150cf614fe0565b5b50615135565b5060208310610133831016604e8410600b841016171561510b5782820a90508381111561510657615105614fe0565b5b615135565b6151188484846001615019565b9250905081840481111561512f5761512e614fe0565b5b81810290505b9392505050565b5f61514682613f4c565b915061515183614f7f565b925061517e7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff848461506b565b905092915050565b5f61519082613f4c565b915061519b83613f4c565b92508282026151a981613f4c565b915082820484148315176151c0576151bf614fe0565b5b5092915050565b5f815190506151d581613f55565b92915050565b5f602082840312156151f0576151ef613e01565b5b5f6151fd848285016151c7565b91505092915050565b5f819050919050565b61522061521b82613f4c565b615206565b82525050565b5f8160601b9050919050565b5f61523c82615226565b9050919050565b5f61524d82615232565b9050919050565b61526561526082613fc9565b615243565b82525050565b5f615276828761520f565b602082019150615286828661520f565b6020820191506152968285615254565b6014820191506152a6828461520f565b60208201915081905095945050505050565b6152c181614b23565b82525050565b5f6060820190506152da5f83018661406a565b6152e7602083018561406a565b6152f460408301846152b8565b949350505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b5f819050815f5260205f209050919050565b5f6020601f8301049050919050565b5f82821b905092915050565b5f600883026153857fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8261534a565b61538f868361534a565b95508019841693508086168417925050509392505050565b5f6153c16153bc6153b784613f4c565b614092565b613f4c565b9050919050565b5f819050919050565b6153da836153a7565b6153ee6153e6826153c8565b848454615356565b825550505050565b5f90565b6154026153f6565b61540d8184846153d1565b505050565b5b81811015615430576154255f826153fa565b600181019050615413565b5050565b601f8211156154755761544681615329565b61544f8461533b565b8101602085101561545e578190505b61547261546a8561533b565b830182615412565b50505b505050565b5f82821c905092915050565b5f6154955f198460080261547a565b1980831691505092915050565b5f6154ad8383615486565b9150826002028217905092915050565b6154c682613ebc565b67ffffffffffffffff8111156154df576154de6144bf565b5b6154e98254614ef3565b6154f4828285615434565b5f60209050601f831160018114615525575f8415615513578287015190505b61551d85826154a2565b865550615584565b601f19841661553386615329565b5f5b8281101561555a57848901518255600182019150602085019450602081019050615535565b868310156155775784890151615573601f891682615486565b8355505b6001600288020188555050505b505050505050565b5f81905092915050565b5f6155a082613ebc565b6155aa818561558c565b93506155ba818560208601613ed6565b80840191505092915050565b5f6155d18285615596565b91506155dd8284615596565b91508190509392505050565b7f43616e206f6e6c7920616464206c6971756964697479206f6e63652c20646f6e5f8201527f2774206675636b2075702e000000000000000000000000000000000000000000602082015250565b5f615643602b83613ec6565b915061564e826155e9565b604082019050919050565b5f6020820190508181035f83015261567081615637565b9050919050565b5f819050919050565b61569161568c82614b23565b615677565b82525050565b5f6156a28286615680565b6020820191506156b2828561520f565b6020820191506156c28284615254565b601482019150819050949350505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f61570a82613f4c565b915061571583613f4c565b925082615725576157246156d3565b5b828204905092915050565b5f61573a82613f4c565b915061574583613f4c565b925082820190508082111561575d5761575c614fe0565b5b92915050565b5f61576d82613f4c565b915061577883613f4c565b92508282039050818111156157905761578f614fe0565b5b92915050565b5f6157a082613f4c565b91506157ab83613f4c565b9250826157bb576157ba6156d3565b5b828206905092915050565b5f815190506157d481614002565b92915050565b5f602082840312156157ef576157ee613e01565b5b5f6157fc848285016157c6565b91505092915050565b5f819050919050565b61581f61581a826146ce565b615805565b82525050565b5f615830828661520f565b6020820191506158408285615254565b601482019150615850828461580e565b602082019150819050949350505050565b61586a81613fc9565b8114615874575f80fd5b50565b5f8135905061588581615861565b92915050565b5f602082840312156158a05761589f613e01565b5b5f6158ad84828501615877565b91505092915050565b7f496e70757420746f6b656e206d757374206265206e61746976652063757272655f8201527f6e63790000000000000000000000000000000000000000000000000000000000602082015250565b5f615910602383613ec6565b915061591b826158b6565b604082019050919050565b5f6020820190508181035f83015261593d81615904565b9050919050565b5f61594e826146ce565b91507f800000000000000000000000000000000000000000000000000000000000000082036159805761597f614fe0565b5b815f039050919050565b7f496e76616c696420737761702073656e646572000000000000000000000000005f82015250565b5f6159be601383613ec6565b91506159c98261598a565b602082019050919050565b5f6020820190508181035f8301526159eb816159b2565b9050919050565b7f546f6f206d616e79204e465473206d696e74656420696e20612073696e676c655f8201527f2073776170000000000000000000000000000000000000000000000000000000602082015250565b5f615a4c602583613ec6565b9150615a57826159f2565b604082019050919050565b5f6020820190508181035f830152615a7981615a40565b9050919050565b7f43616e6e6f74206d696e74206d6f7265207468616e206d617820737570706c795f82015250565b5f615ab4602083613ec6565b9150615abf82615a80565b602082019050919050565b5f6020820190508181035f830152615ae181615aa8565b9050919050565b5f615af282613f4c565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203615b2457615b23614fe0565b5b600182019050919050565b5f81519050919050565b5f82825260208201905092915050565b5f615b5382615b2f565b615b5d8185615b39565b9350615b6d818560208601613ed6565b615b7681613ee4565b840191505092915050565b5f608082019050615b945f830187613fda565b615ba16020830186613fda565b615bae604083018561406a565b8181036060830152615bc08184615b49565b905095945050505050565b5f81519050615bd981613e34565b92915050565b5f60208284031215615bf457615bf3613e01565b5b5f615c0184828501615bcb565b91505092915050565b5f8135615c1681615861565b80915050919050565b5f815f1b9050919050565b5f73ffffffffffffffffffffffffffffffffffffffff615c4984615c1f565b9350801983169250808416831791505092915050565b5f819050919050565b615c71826140cd565b615c84615c7d82615c5f565b8354615c2a565b8255505050565b615c94816140ed565b8114615c9e575f80fd5b50565b5f8135615cad81615c8b565b80915050919050565b5f8160a01b9050919050565b5f76ffffff0000000000000000000000000000000000000000615ce484615cb6565b9350801983169250808416831791505092915050565b5f615d14615d0f615d0a846140ed565b614092565b6140ed565b9050919050565b5f819050919050565b615d2d82615cfa565b615d40615d3982615d1b565b8354615cc2565b8255505050565b5f8135615d5381614874565b80915050919050565b5f8160b81b9050919050565b5f79ffffff0000000000000000000000000000000000000000000000615d8d84615d5c565b9350801983169250808416831791505092915050565b5f615dbd615db8615db38461410a565b614092565b61410a565b9050919050565b5f819050919050565b615dd682615da3565b615de9615de282615dc4565b8354615d68565b8255505050565b5f615dfa82613fc9565b9050919050565b615e0a81615df0565b8114615e14575f80fd5b50565b5f8135615e2381615e01565b80915050919050565b5f615e368261409b565b9050919050565b5f615e4782615e2c565b9050919050565b5f819050919050565b615e6082615e3d565b615e73615e6c82615e4e565b8354615c2a565b8255505050565b5f81015f830180615e8a81615c0a565b9050615e968184615c68565b505050600181016020830180615eab81615c0a565b9050615eb78184615c68565b505050600181016040830180615ecc81615ca1565b9050615ed88184615d24565b505050600181016060830180615eed81615d47565b9050615ef98184615dcd565b505050600281016080830180615f0e81615e17565b9050615f1a8184615e57565b5050505050565b615f2b8282615e7a565b5050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603160045260245ffdfea264697066735822122067694ca968bcf85c8f035f1925fe07a383829ad08c73839598ca083e65d0037264736f6c634300081a0033").unwrap());

        let pool_manager = Address::from_str("0x1F98400000000000000000000000000000000004")
            .expect("Invalid pool manager address");

        let hook_handler = GenericVMHookHandler::new(hook_address, bytecode, engine, pool_manager)
            .expect("Failed to create GenericVMHookHandler");

        let universal_router =
            Address::from_str("0xef740bf23acae26f6492b10de645d6b98dc8eaf3").unwrap();

        // simulating this tx: 0x6f471e490570c89482e44edd286db35b2dd93c52307bfe6f28dbe8ed3326470d on
        // unichain
        let context = StateContext {
            currency_0: Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
            currency_1: Address::from_str("0x7edc481366a345d7f9fcecb207408b5f2887ff99").unwrap(),
            fees: UniswapV4Fees { zero_for_one: 0, one_for_zero: 0, lp_fee: 100 },
            tick: 1,
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
            .before_swap(params, block, None, Some(transient_storage.clone()))
            .unwrap();

        assert_eq!(result.result.amount_delta, I256::from_dec_str("0").unwrap());

        let after_swap_params = AfterSwapParameters {
            context,
            sender: universal_router,
            swap_params,
            delta: I256::from_dec_str("-3777134272822416944443458142492627143113384069767150805")
                .unwrap(),
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
        assert_eq!(res, I256::from_raw(U256::from_str("0").unwrap()));
    }
}
