use tycho_simulation::{
    evm::{
        decoder::TychoStreamDecoder,
        engine_db::tycho_db::PreCachedDB,
        protocol::{
            ekubo::state::EkuboState, pancakeswap_v2::state::PancakeswapV2State,
            uniswap_v2::state::UniswapV2State, uniswap_v3::state::UniswapV3State,
            vm::state::EVMPoolState,
        },
    },
    protocol::models::DecoderContext,
    tycho_client::feed::BlockHeader,
};

/// Register decoder based on protocol system. Defaults to EVMPoolState.
/// To add a new protocol, just add a case to the match statement.
pub fn register_decoder_for_protocol(
    decoder: &mut TychoStreamDecoder<BlockHeader>,
    protocol_system: &str,
    decoder_context: DecoderContext,
) -> miette::Result<()> {
    match protocol_system {
        "uniswap_v2" | "sushiswap_v2" => {
            decoder
                .register_decoder_with_context::<UniswapV2State>(protocol_system, decoder_context);
        }
        "pancakeswap_v2" => {
            decoder.register_decoder_with_context::<PancakeswapV2State>(
                protocol_system,
                decoder_context,
            );
        }
        "uniswap_v3" | "pancakeswap_v3" => {
            decoder
                .register_decoder_with_context::<UniswapV3State>(protocol_system, decoder_context);
        }
        "ekubo_v2" => {
            decoder.register_decoder_with_context::<EkuboState>(protocol_system, decoder_context);
        }
        // Default to EVMPoolState for all other protocols
        _ => {
            decoder.register_decoder_with_context::<EVMPoolState<PreCachedDB>>(
                protocol_system,
                decoder_context,
            );
        }
    }

    Ok(())
}
