use anyhow::anyhow;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct StringParams {
    start_block: String,
    planner: String,
    info: String,
    mint_impl: String,
    swap_impl: String,
}

impl StringParams {
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        serde_qs::from_str(input).map_err(|e| anyhow!("Failed to parse query params: {}", e))
    }
}

pub(crate) struct Params {
    pub start_block: u64,
    pub planner: Vec<u8>,
    #[allow(dead_code)] // We keep the unused info field for future pricing/view operations
    pub info: Vec<u8>,
    pub mint_impl: Vec<u8>,
    pub swap_impl: Vec<u8>,
}

pub fn encode_addr(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(&bytes))
    // hex::encode(&bytes)
}

pub fn decode_addr(s: &str) -> anyhow::Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 40 {
        return Err(anyhow!("address must be 20 bytes (40 hex chars), got len={}", s.len()));
    }
    let bytes = hex::decode(s)?;
    if bytes.len() != 20 {
        return Err(anyhow!("decoded address is not 20 bytes"));
    }
    Ok(bytes)
}

pub fn encode_addrs(bytes: &[Vec<u8>]) -> String {
    format!(
        "{}",
        bytes
            .iter()
            .map(|b| encode_addr(b))
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub fn decode_addrs(s: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let parts: Vec<&str> = s.split(',').collect();
    let mut decoded = Vec::new();
    for part in parts {
        decoded.push(decode_addr(part.trim())?);
    }
    Ok(decoded)
}

impl Params {
    pub fn parse(input: &str) -> anyhow::Result<Self> {
        let params = StringParams::parse(input)?;

        Ok(Self {
            start_block: params.start_block.parse()?,
            planner: decode_addr(&params.planner)?,
            info: decode_addr(&params.info)?,
            mint_impl: decode_addr(&params.mint_impl)?,
            swap_impl: decode_addr(&params.swap_impl)?,
        })
    }
}
