//! Executors are modeled as variants of an [Executor] enum.
//! Functions like [Executor::swap] implement each [Executor]'s functionality
//! via pattern matching.
//!
//! While having an executor trait that is implemented by individual executor types
//! would keep each executor's code closer together,
//! it would require passing executors around as trait objects.
//! Trait objects require dynamic dispatch at runtime,
//! which is more costly than a pattern match,
//! prevents compiler optimizations like inlining,
//! and prevents CPU optimizations like branch prediction.
//! Since we want to execute millions of simulations per second,
//! pattern matching over enum variants was chosen.
//! If performance mattered less, trait objects would likely be chosen.
//!
//! <https://github.com/propeller-heads/tycho-execution/tree/main/foundry/src/executors>
use crate::address::Address;
use crate::error::Error;
use crate::log::Log;
use crate::model::dispatcher::_call_handle_callback_on_executor;
use crate::model::transfer_manager::TransferType;
use crate::model::vault::Vault;
use crate::params::{ParamKey, Params};
use crate::state::State;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
pub enum Executor {
    // TODO this list is incomplete.
    Curve,
    ERC4626,
    FluidV1,
    MaverickV2,
    Slipstreams,
    UniswapV2,
    UniswapV3,
    Weth,
}

/// Return value of [Executor::get_transfer_data]
#[derive(Serialize, Clone)]
pub struct TransferData {
    pub transfer_type: TransferType,
    pub receiver: Address,
    pub token_in: Address,
    pub token_out: Address,
    pub output_to_router: bool,
}

/// Return value of [Executor::get_callback_transfer_data]
pub struct CallbackTransferData {
    pub transfer_type: TransferType,
    pub receiver: Address,
}

impl Executor {
    /// Array containing all [Executor]s.
    pub const VARIANTS: [Executor; 8] = [
        Executor::Curve,
        Executor::ERC4626,
        Executor::FluidV1,
        Executor::MaverickV2,
        Executor::Slipstreams,
        Executor::UniswapV2,
        Executor::UniswapV3,
        Executor::Weth,
    ];

    /// <https://github.com/propeller-heads/tycho-execution/blob/9b0512c9580617224c7a0d7de781674a2cdc6b62/foundry/interfaces/IExecutor.sol#L41>
    pub fn get_transfer_data(
        &self,
        params: &Params,
        _state: &mut State,
        swap_index: u8,
    ) -> Result<TransferData, Error> {
        match self {
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/CurveExecutor.sol#L139
            Self::Curve => {
                let mut token_in = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 0,
                        end: 20,
                    },
                    Address::CURVE_TOKENS,
                )?;
                let mut token_out = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 20,
                        end: 40,
                    },
                    Address::CURVE_TOKENS,
                )?;

                if token_in == Address::CurveNative {
                    token_in = Address::Zero;
                }

                let transfer_type = if token_in == Address::CurveNative {
                    TransferType::TransferNativeInExecutor
                } else {
                    TransferType::ProtocolWillDebit
                };

                if token_out == Address::CurveNative {
                    token_out = Address::Zero;
                }

                Ok(TransferData {
                    transfer_type,
                    receiver: params.request(
                        ParamKey::ProtocolData {
                            swap_index,
                            start: 40,
                            end: 60,
                        },
                        // trying more variants might find some very obscure bugs
                        // in the future but slows down simulation a lot
                        // and currently is ignored anyway
                        Address::SENDER_CONTROLLED,
                    )?,
                    token_in,
                    token_out,
                    output_to_router: true,
                })
            }
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/ERC4626Executor.sol#L67
            Self::ERC4626 => {
                let token_in = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 0,
                        end: 20,
                    },
                    Address::POSSIBLY_ERC20_AND_ZERO,
                )?;
                let receiver = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 20,
                        end: 40,
                    },
                    // trying more variants might find some very obscure bugs
                    // in the future but slows down simulation a lot
                    // and currently is ignored anyway
                    Address::SENDER_CONTROLLED,
                )?;

                let is_redeem = token_in == receiver;

                let token_out = if is_redeem {
                    params.request(
                        ParamKey::SwapIndexed {
                            prefix: "IERC4626.asset()",
                            swap_index,
                        },
                        Address::POSSIBLY_ERC20_AND_ZERO,
                    )?
                } else {
                    receiver
                };

                Ok(TransferData {
                    transfer_type: TransferType::ProtocolWillDebit,
                    receiver,
                    token_in,
                    token_out,
                    output_to_router: false,
                })
            }
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/FluidV1Executor.sol#L132
            Self::FluidV1 => {
                let is_native_sell = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 61,
                        end: 62,
                    },
                    [true, false],
                )?;
                Ok(TransferData {
                    transfer_type: if is_native_sell {
                        TransferType::TransferNativeInExecutor
                    } else {
                        TransferType::None
                    },
                    receiver: Address::Zero,
                    token_in: if is_native_sell {
                        Address::Zero
                    } else {
                        params.request(
                            ParamKey::ProtocolData {
                                swap_index,
                                start: 21,
                                end: 41,
                            },
                            Address::POSSIBLY_ERC20_AND_ZERO,
                        )?
                    },
                    token_out: params.request(
                        ParamKey::ProtocolData {
                            swap_index,
                            start: 41,
                            end: 61,
                        },
                        Address::POSSIBLY_ERC20_AND_ZERO,
                    )?,
                    output_to_router: false,
                })
            }
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/MaverickV2Executor.sol#L64
            Self::MaverickV2 => Ok(TransferData {
                transfer_type: TransferType::Transfer,
                receiver: params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 0,
                        end: 20,
                    },
                    // trying more variants might find some very obscure bugs
                    // in the future but slows down simulation a lot
                    // and currently is ignored anyway
                    Address::SENDER_CONTROLLED,
                )?,
                token_in: params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 20,
                        end: 40,
                    },
                    Address::POSSIBLY_ERC20_AND_ZERO,
                )?,
                token_out: params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 40,
                        end: 60,
                    },
                    Address::POSSIBLY_ERC20_AND_ZERO,
                )?,
                output_to_router: false,
            }),
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/SlipstreamsExecutor.sol#L96
            Self::Slipstreams => Ok(TransferData {
                transfer_type: TransferType::None,
                receiver: Address::Zero,
                token_in: params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 0,
                        end: 20,
                    },
                    Address::POSSIBLY_ERC20_AND_ZERO,
                )?,
                token_out: params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 20,
                        end: 40,
                    },
                    Address::POSSIBLY_ERC20_AND_ZERO,
                )?,
                output_to_router: false,
            }),
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/UniswapV2Executor.sol#L102
            Self::UniswapV2 => Ok(TransferData {
                transfer_type: TransferType::Transfer,
                receiver: params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 0,
                        end: 20,
                    },
                    // trying more variants might find some very obscure bugs
                    // in the future but slows down simulation a lot
                    // and currently is ignored anyway
                    Address::SENDER_CONTROLLED,
                )?,
                token_in: params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 20,
                        end: 40,
                    },
                    Address::POSSIBLY_ERC20_AND_ZERO,
                )?,
                token_out: params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 40,
                        end: 60,
                    },
                    Address::POSSIBLY_ERC20_AND_ZERO,
                )?,
                output_to_router: false,
            }),
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/UniswapV3Executor.sol#L107
            Self::UniswapV3 => Ok(TransferData {
                transfer_type: TransferType::None,
                receiver: Address::Zero,
                token_in: params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 0,
                        end: 20,
                    },
                    Address::POSSIBLY_ERC20_AND_ZERO,
                )?,
                token_out: params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 20,
                        end: 40,
                    },
                    Address::POSSIBLY_ERC20_AND_ZERO,
                )?,
                output_to_router: false,
            }),
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/WethExecutor.sol#L76
            Self::Weth => {
                let is_wrapping = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 0,
                        end: 1,
                    },
                    [true, false],
                )?;
                Ok(TransferData {
                    transfer_type: if is_wrapping {
                        TransferType::TransferNativeInExecutor
                    } else {
                        TransferType::ProtocolWillDebit
                    },
                    receiver: Address::Router,
                    token_in: if is_wrapping {
                        Address::Zero
                    } else {
                        Address::WETH
                    },
                    token_out: if is_wrapping {
                        Address::WETH
                    } else {
                        Address::Zero
                    },
                    output_to_router: true,
                })
            }
        }
    }

    /// <https://github.com/propeller-heads/tycho-execution/blob/9b0512c9580617224c7a0d7de781674a2cdc6b62/foundry/interfaces/IExecutor.sol#L23>
    pub fn swap(
        &self,
        params: &Params,
        state: &mut State,
        vault: &mut Vault,
        log: &mut impl Log,
        amount: i64,
        _receiver: Address,
        swap_index: u8,
    ) -> Result<(), Error> {
        match self {
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/CurveExecutor.sol#L70
            Self::Curve => {
                let pool = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 40,
                        end: 60,
                    },
                    // trying more variants might find some very obscure bugs
                    // in the future but slows down simulation a lot
                    // and currently is ignored anyway
                    Address::SENDER_CONTROLLED,
                )?;

                if !pool.is_sender_controlled() {
                    return Err(Error::Ignore {
                        reason: "curve pool not sender controlled. not low hanging fruit. would require simulating real pool".into(),
                    });
                }

                let token_in = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 0,
                        end: 20,
                    },
                    Address::VARIANTS,
                )?;

                // this simulates the transfer of eth to the pool
                if token_in == Address::CurveNative {
                    state.eth_send_value(Address::Router, pool, amount)?;
                }

                // if the sender controls the pool,
                // the actual swap logic doesn't matter

                let transfer_allowances_during_swap = params.request(
                    ParamKey::SwapIndexed {
                        prefix: "transfer_allowances_during_swap",
                        swap_index,
                    },
                    [true, false],
                )?;
                if transfer_allowances_during_swap {
                    for token in Address::VARIANTS {
                        for spender in Address::SENDER_CONTROLLED {
                            let allowance =
                                state.erc20_allowance(token, Address::Router, spender)?;
                            if allowance > 0 {
                                state.erc20_safe_transfer_from(
                                    token,
                                    spender,
                                    Address::Router,
                                    spender,
                                    allowance,
                                )?;
                            }
                        }
                    }
                }
                Ok(())
            }
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/ERC4626Executor.sol#L32
            Self::ERC4626 => {
                let target = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 20,
                        end: 40,
                    },
                    // trying more variants might find some very obscure bugs
                    // in the future but slows down simulation a lot
                    // and currently is ignored anyway
                    Address::SENDER_CONTROLLED,
                )?;
                if target.is_sender_controlled() {
                    // if the sender controls the pool,
                    // the actual swap logic doesn't matter
                    Ok(())
                } else {
                    Err(Error::Ignore {
                        reason: "erc4626 target not sender controlled. not low hanging fruit. would require simulating real pool".into(),
                    })
                }
            }
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/FluidV1Executor.sol#L60
            Self::FluidV1 => {
                let dex = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 0,
                        end: 20,
                    },
                    // trying more variants might find some very obscure bugs
                    // in the future but slows down simulation a lot
                    // and currently is ignored anyway
                    Address::SENDER_CONTROLLED,
                )?;
                if !dex.is_sender_controlled() {
                    return Err(Error::Ignore {
                        reason: "fluidv1 dex not sender controlled. not low hanging fruit. would require simulating real pool".into(),
                    });
                }
                let is_native_sell = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 61,
                        end: 62,
                    },
                    [true, false],
                )?;
                if !is_native_sell {
                    state.tstore("fluid_v1_current_dex", dex);
                    state.enter_callback(dex);
                    _call_handle_callback_on_executor(params, state, vault, log, swap_index)?;
                    state.leave_callback();
                } else {
                    state.eth_send_value(Address::Router, dex, amount)?;
                }
                Ok(())
            }
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/CurveExecutor.sol#L70
            Self::MaverickV2 => {
                let pool = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 0,
                        end: 20,
                    },
                    // trying more variants might find some very obscure bugs
                    // in the future but slows down simulation a lot
                    // and currently is ignored anyway
                    Address::SENDER_CONTROLLED,
                )?;
                if pool.is_sender_controlled() {
                    // if the sender controls the pool,
                    // the actual swap logic doesn't matter
                    Ok(())
                } else {
                    Err(Error::Ignore {
                        reason: "maverickv2 pool not sender controlled. not low hanging fruit. would require simulating real pool".into(),
                    })
                }
            }
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/SlipstreamsExecutor.sol#L37
            Self::Slipstreams => {
                let pool = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 43,
                        end: 63,
                    },
                    // trying more variants might find some very obscure bugs
                    // in the future but slows down simulation a lot
                    // and currently is ignored anyway
                    Address::SENDER_CONTROLLED,
                )?;
                if pool.is_sender_controlled() {
                    state.enter_callback(pool);
                    _call_handle_callback_on_executor(params, state, vault, log, swap_index)?;
                    state.leave_callback();
                    Ok(())
                } else {
                    Err(Error::Ignore {
                        reason: "slipstreams pool not sender controlled. not low hanging fruit. would require simulating real pool".into(),
                    })
                }
            }
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/UniswapV2Executor.sol#L39
            Self::UniswapV2 => {
                let pool = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 0,
                        end: 20,
                    },
                    // trying more variants might find some very obscure bugs
                    // in the future but slows down simulation a lot
                    // and currently is ignored anyway
                    Address::SENDER_CONTROLLED,
                )?;
                if pool.is_sender_controlled() {
                    // if the sender controls the pool,
                    // the actual swap logic doesn't matter
                    Ok(())
                } else {
                    Err(Error::Ignore {
                        reason: "uniswapv2 pool not sender controlled. not low hanging fruit. would require simulating real pool".into(),
                    })
                }
            }
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/UniswapV3Executor.sol#L37
            Self::UniswapV3 => {
                let target = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 43,
                        end: 63,
                    },
                    // trying more variants might find some very obscure bugs
                    // in the future but slows down simulation a lot
                    // and currently is ignored anyway
                    Address::SENDER_CONTROLLED,
                )?;
                if target.is_sender_controlled() {
                    // if the sender controls the pool,
                    // the actual swap logic doesn't matter
                    // TODO theoretically it doesn't have to be the target that does the callback
                    state.enter_callback(target);
                    _call_handle_callback_on_executor(params, state, vault, log, swap_index)?;
                    state.leave_callback();
                    Ok(())
                } else {
                    Err(Error::Ignore {
                        reason: "uniswapv3 target not sender controlled. not low hanging fruit. would require simulating real pool".into(),
                    })
                }
            }
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/WethExecutor.sol#L44
            Self::Weth => {
                let is_wrapping = params.request(
                    ParamKey::ProtocolData {
                        swap_index,
                        start: 0,
                        end: 1,
                    },
                    [true, false],
                )?;
                if is_wrapping {
                    state.eth_send_value(Address::Router, Address::WETH, amount)?;
                    state.erc20_safe_transfer(
                        Address::WETH,
                        Address::WETH,
                        Address::Router,
                        amount,
                    )?;
                } else {
                    state.erc20_safe_transfer(
                        Address::WETH,
                        Address::Router,
                        Address::WETH,
                        amount,
                    )?;
                    state.eth_send_value(Address::WETH, Address::Router, amount)?;
                }
                Ok(())
            }
        }
    }

    pub fn get_callback_transfer_data(
        &self,
        _params: &Params,
        state: &State,
        _swap_index: u8,
    ) -> Result<CallbackTransferData, Error> {
        match self {
            Self::Curve => unimplemented!(),
            Self::ERC4626 => unimplemented!(),
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/FluidV1Executor.sol#L155
            Self::FluidV1 => Ok(CallbackTransferData {
                transfer_type: TransferType::Transfer,
                receiver: Address::Named("fluid-v1-liquidity"),
            }),
            Self::MaverickV2 => unimplemented!(),
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/SlipstreamsExecutor.sol#L120
            Self::Slipstreams => Ok(CallbackTransferData {
                transfer_type: TransferType::Transfer,
                // called via delegatecall. therefore not the router
                receiver: state.msg_sender(),
            }),
            Self::UniswapV2 => unimplemented!(),
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/UniswapV3Executor.sol#L131
            Self::UniswapV3 => Ok(CallbackTransferData {
                transfer_type: TransferType::Transfer,
                // called via delegatecall. therefore not the router
                receiver: state.msg_sender(),
            }),
            Self::Weth => unimplemented!(),
        }
    }

    pub fn handle_callback(&self, _params: &Params, state: &mut State) -> Result<(), Error> {
        match self {
            Self::Curve => unimplemented!("Curve doesn't use callbacks"),
            Self::ERC4626 => unimplemented!("ERC4626 doesn't use callbacks"),
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/FluidV1Executor.sol#L115
            Self::FluidV1 => {
                let dex: Address = state.tload("fluid_v1_current_dex")?;
                if state.msg_sender() != dex {
                    return Err(Error::revert("FluidV1.handle_callback: msg.sender != dex"));
                }
                Ok(())
            }
            Self::MaverickV2 => unimplemented!("MaverickV2 doesn't use callbacks"),
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/SlipstreamsExecutor.sol#L60
            // not worth modeling as it has no reverts or side effects
            Self::Slipstreams => Ok(()),
            Self::UniswapV2 => unimplemented!("UniswapV2 doesn't use callbacks"),
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/UniswapV3Executor.sol#L60
            // not worth modeling as it has no reverts or side effects
            Self::UniswapV3 => Ok(()),
            Self::Weth => unimplemented!("Weth doesn't use callbacks"),
        }
    }

    /// <https://github.com/propeller-heads/tycho-execution/blob/9b0512c9580617224c7a0d7de781674a2cdc6b62/foundry/interfaces/IExecutor.sol#L63>
    ///
    /// Most executors return `msg.sender` which translates to the router
    /// because the function is called via staticcall.
    pub fn funds_expected_address(
        &self,
        params: &Params,
        _state: &mut State,
        swap_index: u8,
    ) -> Result<Address, Error> {
        Ok(match self {
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/CurveExecutor.sol#L59
            Self::Curve => Address::Router,
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/ERC4626Executor.sol#L21
            Self::ERC4626 => Address::Router,
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/FluidV1Executor.sol#L49
            Self::FluidV1 => Address::Router,
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/MaverickV2Executor.sol#L18
            Self::MaverickV2 => params.request(
                ParamKey::ProtocolData {
                    swap_index,
                    start: 0,
                    end: 20,
                },
                // trying more variants might find some very obscure bugs
                // in the future but slows down simulation a lot
                // and currently is ignored anyway
                Address::SENDER_CONTROLLED,
            )?,
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/SlipstreamsExecutor.sol#L26
            Self::Slipstreams => Address::Router,
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/UniswapV2Executor.sol#L29
            Self::UniswapV2 => params.request(
                ParamKey::ProtocolData {
                    swap_index,
                    start: 0,
                    end: 20,
                },
                // trying more variants might find some very obscure bugs
                // in the future but slows down simulation a lot
                // and currently is ignored anyway
                Address::SENDER_CONTROLLED,
            )?,
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/UniswapV3Executor.sol#L26
            Self::UniswapV3 => Address::Router,
            // https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/src/executors/WethExecutor.sol#L33
            Self::Weth => Address::Router,
        })
    }
}
