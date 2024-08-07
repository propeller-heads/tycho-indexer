use foundry_config::{Chain, Config};
use foundry_evm::traces::{
    decode_trace_arena,
    identifier::{EtherscanIdentifier, SignaturesIdentifier},
    render_trace_arena, CallTraceDecoder, CallTraceDecoderBuilder, DebugTraceIdentifier, Traces,
};

/// A slimmed down return from the executor used for returning minimal trace + gas metering info
#[derive(Debug)]
pub struct TraceResult {
    pub success: bool,
    pub traces: Option<Traces>,
    pub gas_used: u64,
}

pub async fn handle_traces(
    mut result: TraceResult,
    config: &Config,
    chain: Option<Chain>,
    decode_internal: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut decoder = CallTraceDecoderBuilder::new()
        .with_signature_identifier(SignaturesIdentifier::new(
            Config::foundry_cache_dir(),
            config.offline,
        )?)
        .build();

    let mut etherscan_identifier = EtherscanIdentifier::new(config, chain)?;
    if let Some(etherscan_identifier) = &mut etherscan_identifier {
        for (_, trace) in result
            .traces
            .as_deref_mut()
            .unwrap_or_default()
        {
            decoder.identify(trace, etherscan_identifier);
        }
    }

    if decode_internal {
        let sources = if let Some(etherscan_identifier) = &etherscan_identifier {
            etherscan_identifier
                .get_compiled_contracts()
                .await?
        } else {
            Default::default()
        };
        decoder.debug_identifier = Some(DebugTraceIdentifier::new(sources));
    }

    print_traces(&mut result, &decoder).await?;

    Ok(())
}

pub async fn print_traces(
    result: &mut TraceResult,
    decoder: &CallTraceDecoder,
) -> Result<(), Box<dyn std::error::Error>> {
    let traces = result
        .traces
        .as_mut()
        .expect("No traces found");

    println!("Traces:");
    for (_, arena) in traces {
        decode_trace_arena(arena, decoder).await?;
        println!("{}", render_trace_arena(arena));
    }
    println!();

    if result.success {
        println!("Transaction successfully executed.");
    } else {
        println!("Transaction failed.");
    }

    println!("Gas used: {}", result.gas_used);
    Ok(())
}
