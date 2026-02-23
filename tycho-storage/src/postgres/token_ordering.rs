use phf::phf_set;
use tycho_common::models::protocol::ProtocolComponent;

// These protocol systems will have their protocol components sorted
// lexicographically instead of preserving the order reported by Substreams
pub const SORTED_TOKEN_PROTOCOL_SYSTEMS: phf::Set<&'static str> = phf_set! {
    "uniswap_v2","sushiswap_v2","pancakeswap_v2","vm:balancer_v2","uniswap_v3",
    "pancakeswap_v3","uniswap_v4","ekubo_v2","ekubo_v3","vm:curve","vm:maverick_v2",
    "vm:balancer_v3","rfq:bebop","rfq:hashflow","fluid_v1","aerodrome_slipstreams",
    "rocketpool","erc4626","lido","velodrome_slipstreams","etherfi",
};

pub fn sort_tokens_by_protocol_system(component: &mut ProtocolComponent) {
    if SORTED_TOKEN_PROTOCOL_SYSTEMS.contains(component.protocol_system.as_str()) {
        component.tokens.sort_unstable();
    }
}
