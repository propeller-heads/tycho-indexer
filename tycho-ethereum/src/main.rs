use std::str::FromStr;

use clap::{Args, Parser, Subcommand};
use tycho_common::{
    hex_bytes::ParseBytesError,
    models::blockchain::{
        EntryPoint, EntryPointTracingData, EntryPointWithData, RPCTracerEntryPoint,
    },
    traits::EntryPointTracer,
    Bytes,
};
use tycho_ethereum::entrypoint_tracer::tracer::EVMEntrypointService;
#[derive(Parser, PartialEq, Debug)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(flatten)]
    global_args: GlobalArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Parser, Debug, Clone, PartialEq, Eq)]
#[command(version, about, long_about = None)]
struct GlobalArgs {
    /// Ethereum node client rpc url
    #[clap(env, long)]
    rpc_url: String,
}

#[derive(Subcommand, Clone, PartialEq, Debug)]
enum Command {
    /// Trace an entrypoint and print results to stdout. Requires a node that support
    /// the Geth method: `debug_traceCall`.
    Trace(TraceArgs),
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct HexBytes<const N: usize = 0>(Bytes);

impl<const N: usize> FromStr for HexBytes<N> {
    type Err = ParseBytesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let cleaned = s.strip_prefix("0x").unwrap_or(s);
        let val = Bytes::from_str(cleaned)?;
        if N > 0 && val.len() != N {
            return Err(ParseBytesError::new(&format!(
                "Invalid length for {}! Expected {}, got {}",
                s,
                N,
                val.len()
            )));
        }
        Ok(HexBytes(val))
    }
}

impl<const N: usize> From<HexBytes<N>> for Bytes {
    fn from(val: HexBytes<N>) -> Self {
        val.0
    }
}

#[derive(Args, Clone, PartialEq, Debug)]
struct TraceArgs {
    /// The block hash to load state from
    block_hash: HexBytes<32>,
    /// Target contract address to call
    target: HexBytes<20>,
    /// Call data for the call
    data: HexBytes,
    /// Specify a caller address
    #[clap(long)]
    caller: Option<HexBytes<20>>,
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let cli: Cli = Cli::parse();
    match cli.command {
        Command::Trace(args) => {
            let entrypoint_service = EVMEntrypointService::new_from_url(&cli.global_args.rpc_url);
            let entrypoint = EntryPointWithData::new(
                EntryPoint::new(args.target.into(), "call()".to_string()),
                EntryPointTracingData::RPCTracer(RPCTracerEntryPoint::new(
                    args.caller.map(|x| x.into()),
                    args.data.into(),
                )),
            );
            let res = entrypoint_service
                .trace(args.block_hash.into(), vec![entrypoint])
                .await?;
            dbg!(&res[0]);
        }
    };
    Ok(())
}
