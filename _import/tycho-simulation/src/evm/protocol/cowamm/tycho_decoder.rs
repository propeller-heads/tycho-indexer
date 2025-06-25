use std::collections::HashMap;

use alloy_primitives::U256;
use rstest::rstest;
use tycho_client::feed::{synchronizer::ComponentWithState, Header};
use tycho_common::{dto::ResponseProtocolState, Bytes};

use crate::{
    evm::protocol::{
        cowamm::{
            state::CowAMMState,
            bmath,
        },
    },
    models::{Balances, Token},
    protocol::{
        errors::{SimulationError, TransitionError, InvalidSnapshotError},
        models::TryFromWithBlock
    },
};

const BYTES: usize = 32;

fn header() -> Header {
    Header {
        number: 1,
        hash: Bytes::from(vec![0; 32]),
        parent_hash: Bytes::from(vec![0; 32]),
        revert: false,
    }
}

impl TryFromWithBlock<ComponentWithState> for CowAMMState {
    type Error = InvalidSnapshotError;

    async fn try_from_with_block(
        snapshot: ComponentWithState,
        _block: Header,
        _account_balances: &HashMap<Bytes, HashMap<Bytes, Bytes>>,
        _all_tokens: &HashMap<Bytes, Token>,
    ) -> Result<Self, Self::Error> {
       //technically all of these attributes can't change so they are static
        //so change this code to attributes not tokens
        let token_a = snapshot
                .component
                .static_attributes
                .get("token_a")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("token_a".to_string()))?
                .clone();

        let token_b = snapshot
                .component
                .static_attributes
                .get("token_b")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("token_b".to_string()))?
                .clone();

        let lp_token = snapshot
                .component
                .static_attributes
                .get("lp_token")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("lp_token".to_string()))?
                .clone();

        let fee = 0u64;

        //weight_a and weight_b are left padded big endian numbers of 32 bytes
        let weight_a =  U256::from_be_bytes::<BYTES>(
            snapshot
                .component
                .static_attributes
                .get("weight_a")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("weight_a".to_string()))?
                .as_ref()
                .try_into()
                .map_err(|err| {
                    InvalidSnapshotError::ValueError(format!("weight_a length mismatch: {err:?}"))
                })?,
        );

        let weight_b = U256::from_be_bytes::<BYTES>(
            snapshot
                .component
                .static_attributes
                .get("weight_b")
                .ok_or_else(|| InvalidSnapshotError::MissingAttribute("weight_b".to_string()))?
                .as_ref()
                .try_into()
                .map_err(|err| {
                    InvalidSnapshotError::ValueError(format!("weight_b length mismatch: {err:?}"))
                })?,
        );

        Ok(Self::new(token_a, token_b, lp_token, weight_a, weight_b, fee))
    }
}

//what is a static attribute?
//saw it as input in the integration.test.tycho.yaml
//add something as a static attribute through the integration.test.tycho.yaml

//what is an attribute?
// the one we specify as part of the component 
//where do we get them from surely ? tokens?
//why are there some that are attributes and some that are static attributes \

//understanding delta transitions?
//delta transition fn does not return anything

//snapshot.state

//snapshot.component 

//so we have to make the three tokens both tokens and attributes 
//reason is because of the simulation
//https://github.com/propeller-heads/tycho-protocol-sdk/blob/main/substreams/ethereum-ekubo-v2/src/modules/2_map_components.rs#L66

pub fn component() -> ProtocolComponent {
    ProtocolComponent {
        static_attributes: HashMap::from([
            ("token_a".to_string(), U256([1, 0, 0, 0]).to_big_endian().into()),
            ("token_b".to_string(), U256([2, 0, 0, 0]).to_big_endian().into()),
            ("lp_token".to_string(), U256([2, 0, 0, 0]).to_big_endian().into()), // Base pool
        ]),
        ..Default::default()
    }
}
#[tokio::test]
    async fn test_cowamm_try_from() {
        let snapshot = ComponentWithState {
            state: ResponseProtocolState {
                component_id: "State1".to_owned(),
                attributes: HashMap::from([
                    ("weight_a".to_string(), Bytes::from(vec![0; 32])),
                    ("weight_b".to_string(), Bytes::from(vec![0; 32])),
                    ("fee".to_string(), Bytes::from(vec![0; 32])),
                ]),
                balances: HashMap::new(),
            },
            component: component(),
            component_tvl: None,
        };

        let result = CowAMMState::try_from_with_block(
            snapshot,
            header(),
            &HashMap::new(),
            &HashMap::new(),
        )
        .await;

        println!("result {:?}", result);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CowAMMState::new(Bytes::from(vec![0; 32]), Bytes::from(vec![0; 32]), Bytes::from(vec![0; 32]),U256::from(0), U256::from(0), 0u64));
    }

//     #[tokio::test]
//     #[rstest]
//     #[case::missing_fee("fee")]
//     #[case::missing_weight_a("weight_a")]
//     #[case::missing_weight_b("weight_b")]
//     async fn test_cowamm_try_from_missing_attribute(#[case] missing_attribute: &str) {
//         let mut attributes = HashMap::from([
//             ("fee".to_string(), Bytes::from()),
//             ("weight_a".to_string(), Bytes::from(vec![0; 32])),
//             ("weight_b".to_string(), Bytes::from(vec![0; 32])),
//         ]);

//         attributes.remove(&missing_attribute);

//         let snapshot = ComponentWithState {
//             state: ResponseProtocolState {
//                 component_id: "State1".to_owned(),
//                 attributes,
//                 balances: HashMap::new(),
//             },
//             component: Default::default(),
//             component_tvl: None,
//         };

//         let result = CowAMMState::try_from_with_block(
//             snapshot,
//             header(),
//             &HashMap::new(),
//             &HashMap::new(),
//         )
//         .await;

//         assert!(result.is_err());
//         assert!(matches!(
//             result.unwrap_err(),
//             InvalidSnapshotError::MissingAttribute(ref x) if x == missing_attribute 
//         ));
// }

//where is the snapshot coming from ? Will investigate 

//current test failure :

// failures:

// ---- evm::protocol::cowamm::tycho_decoder::test_cowamm_try_from stdout ----
// result Err(MissingAttribute("token_a"))

// thread 'evm::protocol::cowamm::tycho_decoder::test_cowamm_try_from' panicked at src/evm/protocol/cowamm/tycho_decoder.rs:124:9:
// assertion failed: result.is_ok()

// So its either you use an actual snapshot like in uniswap v4
// let project_root = env!("CARGO_MANIFEST_DIR");
// let asset_path = Path::new(project_root)
//     .join("tests/assets/decoder/uniswap_v4_snapshot_sepolia_block_7239119.json");
// let json_data = fs::read_to_string(asset_path).expect("Failed to read test asset");
// let data: Value = serde_json::from_str(&json_data).expect("Failed to parse JSON");

// let state: ComponentWithState = serde_json::from_value(data)
//   .expect("Expected json to match ComponentWithState structure");

// or just use a snapshot object like we did above

//There are some attributes that are static attributes, and some are just attributes 

//add something as a 