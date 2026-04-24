//! <https://github.com/propeller-heads/tycho-execution/blob/main/foundry/src/FeeCalculator.sol>
use crate::address::Address;
use crate::error::Error;
use crate::math::checked_subtract;
use crate::params::Params;

pub const MAX_FEE_BPS: i64 = 10000;

/// <https://github.com/propeller-heads/tycho-execution/blob/9b0512c9580617224c7a0d7de781674a2cdc6b62/foundry/lib/FeeStructs.sol#L9>
pub struct FeeRecipient {
    pub recipient: Address,
    pub fee_amount: i64,
}

struct FeeInfo {
    router_fee_on_output_bps: i64,
    router_fee_on_client_fee_bps: i64,
}

fn _get_fee_info(params: &Params) -> Result<FeeInfo, Error> {
    if crate::config::ENABLE_NONZERO_FEE_BPS {
        let has_client_custom_fee_on_input =
            params.request("has_client_custom_fee_on_input", vec![true, false])?;

        let router_fee_on_output_bps = if has_client_custom_fee_on_input {
            params.request("client_fee_bps_on_output", vec![0, MAX_FEE_BPS])?
        } else {
            params.request("router_fee_on_output_bps", vec![0, MAX_FEE_BPS])?
        };

        let has_client_custom_fee_on_client_fee =
            params.request("has_client_custom_fee_on_client_fee", vec![true, false])?;
        let router_fee_on_client_fee_bps = if has_client_custom_fee_on_client_fee {
            params.request("client_fee_bps_on_client_fee", vec![0, MAX_FEE_BPS])?
        } else {
            params.request("router_fee_on_client_fee_bps", vec![0, MAX_FEE_BPS])?
        };

        Ok(FeeInfo {
            router_fee_on_output_bps,
            router_fee_on_client_fee_bps,
        })
    } else {
        Ok(FeeInfo {
            router_fee_on_output_bps: 0,
            router_fee_on_client_fee_bps: 0,
        })
    }
}

/// <https://github.com/propeller-heads/tycho-execution/blob/9b0512c9580617224c7a0d7de781674a2cdc6b62/foundry/src/FeeCalculator.sol#L78>
pub fn calculate_fee(
    params: &Params,
    amount_in: i64,
    client_fee_bps: i64,
) -> Result<(i64, Vec<FeeRecipient>), Error> {
    let fee_info = _get_fee_info(params)?;

    if (client_fee_bps + fee_info.router_fee_on_output_bps > MAX_FEE_BPS)
        || fee_info.router_fee_on_client_fee_bps > MAX_FEE_BPS
    {
        return Err(Error::revert("calculate_fee: fee bps too large"));
    }

    let mut amount_out = amount_in;
    let mut router_fee_on_client_fee = 0;
    let mut client_portion = 0;

    if client_fee_bps > 0 {
        let client_fee_numerator = amount_out * client_fee_bps;
        let total_client_fee = client_fee_numerator / 10000;

        if fee_info.router_fee_on_client_fee_bps > 0 {
            router_fee_on_client_fee =
                client_fee_numerator * fee_info.router_fee_on_client_fee_bps / 100_000_000;
        }

        client_portion = checked_subtract(total_client_fee, router_fee_on_client_fee)?;
    }

    let mut total_router_fee = router_fee_on_client_fee;

    if fee_info.router_fee_on_output_bps > 0 {
        total_router_fee += amount_out * fee_info.router_fee_on_output_bps / 10000;
    }

    amount_out = checked_subtract(amount_out, client_portion + total_router_fee)?;

    Ok((
        amount_out,
        vec![
            FeeRecipient {
                recipient: Address::RouterFeeReceiver,
                fee_amount: total_router_fee,
            },
            FeeRecipient {
                recipient: Address::ClientFeeReceiver,
                fee_amount: client_portion,
            },
        ],
    ))
}
