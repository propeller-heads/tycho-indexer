use anyhow::Result;
use substreams_ethereum::Abigen;

fn main() -> Result<(), anyhow::Error> {
    Abigen::new("RocketDAOProtocolProposal", "abi/RocketDAOProtocolProposal.json")?
        .generate()?
        .write_to_file("src/abi/rocket_dao_protocol_proposal.rs")?;
    Abigen::new("RocketDepositPool", "abi/RocketDepositPool.json")?
        .generate()?
        .write_to_file("src/abi/rocket_deposit_pool.rs")?;
    Abigen::new("RocketNetworkBalances", "abi/RocketNetworkBalances.json")?
        .generate()?
        .write_to_file("src/abi/rocket_network_balances.rs")?;
    Abigen::new("RocketMinipoolQueue", "abi/RocketMinipoolQueue.json")?
        .generate()?
        .write_to_file("src/abi/rocket_minipool_queue.rs")?;
    Abigen::new("RocketTokenRETH", "abi/RocketTokenRETH.json")?
        .generate()?
        .write_to_file("src/abi/rocket_token_reth.rs")?;
    anyhow::Ok(())
}
