use crate::abi;

use abi::erc20::functions;
use substreams::scalar::BigInt;
use substreams::Hex;

pub struct Erc20Token {
    pub address: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u64,
    pub total_supply: BigInt,
}

pub fn get_erc20_token(token_address: String) -> Option<Erc20Token> {
    let token_address_vec = Hex::decode(token_address.clone()).unwrap();

    let name = functions::Name {}
        .call(token_address_vec.clone())
        .unwrap_or(String::new());
    let symbol = functions::Symbol {}
        .call(token_address_vec.clone())
        .unwrap_or(String::new());
    let decimals = functions::Decimals {}
        .call(token_address_vec.clone())
        .unwrap_or(BigInt::zero())
        .to_u64();
    let total_supply = functions::TotalSupply {}
        .call(token_address_vec.clone())
        .unwrap_or(BigInt::zero());

    Some(Erc20Token {
        address: token_address.clone(),
        name: name,
        symbol: symbol,
        decimals: decimals,
        total_supply: total_supply,
    })
}
