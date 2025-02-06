#[cfg(test)]
pub mod fixtures {
    use prost::Message;
    use std::str::FromStr;

    use std::collections::HashSet;

    use crate::extractor::models::fixtures::HASH_256_0;
    use tycho_core::{models::protocol::ProtocolComponentStateDelta, Bytes};
    use tycho_storage::postgres::db_fixtures::yesterday_midnight;

    pub fn pb_state_changes() -> crate::pb::tycho::evm::v1::EntityChanges {
        use crate::pb::tycho::evm::v1::*;
        let res1_value = Bytes::from(1_000u64)
            .lpad(32, 0)
            .to_vec();
        let res2_value = Bytes::from(500u64).lpad(32, 0).to_vec();
        EntityChanges {
            component_id: "State1".to_owned(),
            attributes: vec![
                Attribute {
                    name: "reserve1".to_owned(),
                    value: res1_value,
                    change: ChangeType::Update.into(),
                },
                Attribute {
                    name: "reserve2".to_owned(),
                    value: res2_value,
                    change: ChangeType::Update.into(),
                },
            ],
        }
    }

    pub fn protocol_state_delta() -> ProtocolComponentStateDelta {
        let res1_value = Bytes::from(1_000u64)
            .lpad(32, 0)
            .to_vec();
        let res2_value = Bytes::from(500u64).lpad(32, 0).to_vec();
        ProtocolComponentStateDelta {
            component_id: "State1".to_string(),
            updated_attributes: vec![
                ("reserve1".to_owned(), Bytes::from(res1_value)),
                ("reserve2".to_owned(), Bytes::from(res2_value)),
            ]
            .into_iter()
            .collect(),
            deleted_attributes: HashSet::new(),
        }
    }

    pub fn pb_protocol_component() -> crate::pb::tycho::evm::v1::ProtocolComponent {
        use crate::pb::tycho::evm::v1::*;
        ProtocolComponent {
            id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902".to_owned(),
            tokens: vec![address_from_str(DAI_ADDRESS), address_from_str(DAI_ADDRESS)],
            contracts: vec![
                Bytes::from_str("0x31fF2589Ee5275a2038beB855F44b9Be993aA804")
                    .unwrap()
                    .0
                    .to_vec(),
                address_from_str(WETH_ADDRESS),
            ],
            static_att: vec![
                Attribute {
                    name: "balance".to_owned(),
                    value: Bytes::from(100u64).lpad(32, 0).to_vec(),
                    change: ChangeType::Creation.into(),
                },
                Attribute {
                    name: "factory_address".to_owned(),
                    value: b"0x0fwe0g240g20".to_vec(),
                    change: ChangeType::Creation.into(),
                },
            ],
            change: ChangeType::Creation.into(),
            protocol_type: Some(ProtocolType {
                name: "WeightedPool".to_string(),
                financial_type: 0,
                attribute_schema: vec![],
                implementation_type: 0,
            }),
        }
    }

    pub fn pb_blocks(version: u64) -> crate::pb::tycho::evm::v1::Block {
        if version == 0 {
            panic!("Block version 0 doesn't exist. It starts at 1");
        }
        let base_ts = yesterday_midnight().timestamp() as u64;

        crate::pb::tycho::evm::v1::Block {
            number: version,
            hash: Bytes::from(version)
                .lpad(32, 0)
                .to_vec(),
            parent_hash: Bytes::from(version - 1)
                .lpad(32, 0)
                .to_vec(),
            ts: base_ts + version * 1000,
        }
    }

    pub fn pb_transactions(version: u64, index: u64) -> crate::pb::tycho::evm::v1::Transaction {
        crate::pb::tycho::evm::v1::Transaction {
            hash: Bytes::from(version * 10_000 + index)
                .lpad(32, 0)
                .to_vec(),
            from: Bytes::from(version * 100_000 + index)
                .lpad(20, 0)
                .to_vec(),
            to: Bytes::from(version * 1_000_000 + index)
                .lpad(20, 0)
                .to_vec(),
            index,
        }
    }

    const WETH_ADDRESS: &str = "C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const USDC_ADDRESS: &str = "A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const DAI_ADDRESS: &str = "6B175474E89094C44Da98b954EedeAC495271d0F";
    const USDT_ADDRESS: &str = "dAC17F958D2ee523a2206206994597C13D831ec7";

    pub fn address_from_str(token: &str) -> Vec<u8> {
        Bytes::from_str(token)
            .unwrap()
            .0
            .to_vec()
    }

    pub fn pb_block_contract_changes(
        version: u8,
    ) -> crate::pb::tycho::evm::v1::BlockContractChanges {
        use crate::pb::tycho::evm::v1::*;

        match version {
            0 => BlockContractChanges {
                block: Some(Block {
                    hash: Bytes::from(vec![0x31, 0x32, 0x33, 0x34])
                        .lpad(32, 0)
                        .to_vec(),
                    parent_hash: Bytes::from(vec![0x21, 0x22, 0x23, 0x24])
                        .lpad(32, 0)
                        .to_vec(),
                    number: 1,
                    ts: 1000,
                }),

                changes: vec![
                    TransactionContractChanges {
                        tx: Some(Transaction {
                            hash: Bytes::from(vec![0x11, 0x12, 0x13, 0x14])
                                .lpad(32, 0)
                                .to_vec(),
                            from: Bytes::from(vec![0x41, 0x42, 0x43, 0x44])
                                .lpad(20, 0)
                                .to_vec(),
                            to: Bytes::from(vec![0x51, 0x52, 0x53, 0x54])
                                .lpad(20, 0)
                                .to_vec(),
                            index: 2,
                        }),
                        contract_changes: vec![ContractChange {
                            address: Bytes::from(vec![0x61, 0x62, 0x63, 0x64])
                                .lpad(20, 0)
                                .to_vec(),
                            balance: Bytes::from(vec![0x71, 0x72, 0x73, 0x74])
                                .lpad(32, 0)
                                .to_vec(),
                            code: vec![0x81, 0x82, 0x83, 0x84],
                            slots: vec![
                                ContractSlot {
                                    slot: Bytes::from(vec![0xc1, 0xc2, 0xc3, 0xc4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                    value: Bytes::from(vec![0xd1, 0xd2, 0xd3, 0xd4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                },
                                ContractSlot {
                                    slot: Bytes::from(vec![0xa1, 0xa2, 0xa3, 0xa4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                    value: Bytes::from(vec![0xb1, 0xb2, 0xb3, 0xb4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                },
                            ],
                            change: ChangeType::Update.into(),
                            token_balances: vec![AccountBalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 50000000.encode_to_vec(),
                            }],
                        }],
                        component_changes: vec![ProtocolComponent {
                            id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                .to_owned(),
                            tokens: vec![
                                address_from_str(DAI_ADDRESS),
                                address_from_str(DAI_ADDRESS),
                            ],
                            contracts: vec![
                                address_from_str(WETH_ADDRESS),
                                address_from_str(WETH_ADDRESS),
                            ],
                            static_att: vec![
                                Attribute {
                                    name: "key1".to_owned(),
                                    value: b"value1".to_vec(),
                                    change: ChangeType::Creation.into(),
                                },
                                Attribute {
                                    name: "key2".to_owned(),
                                    value: b"value2".to_vec(),
                                    change: ChangeType::Creation.into(),
                                },
                            ],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "WeightedPool".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 50000000.encode_to_vec(),
                            component_id:
                                "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                    .as_bytes()
                                    .to_vec(),
                        }],
                    },
                    TransactionContractChanges {
                        tx: Some(Transaction {
                            hash: Bytes::from(vec![0x01])
                                .lpad(32, 0)
                                .to_vec(),
                            from: Bytes::from(vec![0x41, 0x42, 0x43, 0x44])
                                .lpad(20, 0)
                                .to_vec(),
                            to: Bytes::from(vec![0x51, 0x52, 0x53, 0x54])
                                .lpad(20, 0)
                                .to_vec(),
                            index: 5,
                        }),
                        contract_changes: vec![ContractChange {
                            address: Bytes::from(vec![0x61, 0x62, 0x63, 0x64])
                                .lpad(20, 0)
                                .to_vec(),
                            balance: Bytes::from(vec![0xf1, 0xf2, 0xf3, 0xf4])
                                .lpad(32, 0)
                                .to_vec(),
                            code: vec![0x01, 0x02, 0x03, 0x04],
                            slots: vec![
                                ContractSlot {
                                    slot: Bytes::from(vec![0x91, 0x92, 0x93, 0x94])
                                        .lpad(32, 0)
                                        .to_vec(),
                                    value: Bytes::from(vec![0xa1, 0xa2, 0xa3, 0xa4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                },
                                ContractSlot {
                                    slot: Bytes::from(vec![0xa1, 0xa2, 0xa3, 0xa4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                    value: Bytes::from(vec![0xc1, 0xc2, 0xc3, 0xc4])
                                        .lpad(32, 0)
                                        .to_vec(),
                                },
                            ],
                            change: ChangeType::Update.into(),
                            token_balances: vec![AccountBalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 10.encode_to_vec(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 10.encode_to_vec(),
                            component_id:
                                "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                    .to_string()
                                    .as_bytes()
                                    .to_vec(),
                        }],
                    },
                ],
            },
            1 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionContractChanges {
                    tx: Some(pb_transactions(1, 1)),
                    contract_changes: vec![ContractChange {
                        address: address_from_str("0000000000000000000000000000000000000001"),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        code: 123_i32.to_be_bytes().to_vec(),
                        slots: vec![ContractSlot {
                            slot: Bytes::from("0x01").into(),
                            value: Bytes::from("0x01").into(),
                        }],
                        change: ChangeType::Creation.into(),
                        token_balances: vec![
                            AccountBalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 1_i32.to_be_bytes().to_vec(),
                            },
                            AccountBalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 1_i32.to_be_bytes().to_vec(),
                            },
                        ],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_1".to_owned(),
                        tokens: vec![
                            address_from_str(WETH_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            2 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionContractChanges {
                    tx: Some(pb_transactions(2, 1)),
                    contract_changes: vec![
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000002"),
                            balance: 2_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_be_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x02").into(),
                            }],
                            change: ChangeType::Creation.into(),
                            token_balances: vec![],
                        },
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 10_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_be_bytes().to_vec(),
                            slots: vec![
                                ContractSlot {
                                    slot: Bytes::from("0x01").into(),
                                    value: Bytes::from(10u8).lpad(32, 0).into(),
                                },
                                ContractSlot {
                                    slot: Bytes::from("0x02").into(),
                                    value: Bytes::from("0x0a").into(),
                                },
                            ],
                            change: ChangeType::Update.into(),
                            token_balances: vec![AccountBalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 10.encode_to_vec(),
                            }],
                        },
                    ],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![address_from_str(
                            "0000000000000000000000000000000000000002",
                        )],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 20_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDT_ADDRESS),
                            balance: 20_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 10_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            3 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionContractChanges {
                        tx: Some(pb_transactions(3, 1)),
                        contract_changes: vec![
                            ContractChange {
                                address: address_from_str(
                                    "0000000000000000000000000000000000000001",
                                ),
                                balance: 1_i32.to_be_bytes().to_vec(),
                                code: 123_i32.to_le_bytes().to_vec(),
                                slots: vec![ContractSlot {
                                    slot: Bytes::from("0x01").into(),
                                    value: Bytes::from("0x01").into(),
                                }],
                                change: ChangeType::Update.into(),
                                token_balances: vec![],
                            },
                            ContractChange {
                                address: address_from_str(
                                    "0000000000000000000000000000000000000002",
                                ),
                                balance: 20_i32.to_be_bytes().to_vec(),
                                code: 123_i32.to_le_bytes().to_vec(),
                                slots: vec![ContractSlot {
                                    slot: Bytes::from("0x02").into(),
                                    value: Bytes::from(200u8).lpad(32, 0).into(),
                                }],
                                change: ChangeType::Update.into(),
                                token_balances: vec![AccountBalanceChange {
                                    token: address_from_str(USDC_ADDRESS),
                                    balance: 1_i32.to_be_bytes().to_vec(),
                                }],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        }],
                    },
                    TransactionContractChanges {
                        tx: Some(pb_transactions(3, 2)),
                        contract_changes: vec![ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x01").into(),
                            }],
                            change: ChangeType::Update.into(),
                            token_balances: vec![AccountBalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 2_i32.to_be_bytes().to_vec(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 100_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 2_i32.to_be_bytes().to_vec(),
                                component_id: "pc_2".into(),
                            },
                        ],
                    },
                ],
            },
            4 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionContractChanges {
                    tx: Some(pb_transactions(4, 1)),
                    contract_changes: vec![ContractChange {
                        address: address_from_str("0000000000000000000000000000000000000001"),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        code: 123_i32.to_le_bytes().to_vec(),
                        slots: vec![ContractSlot {
                            slot: Bytes::from(3u8).lpad(32, 0).into(),
                            value: Bytes::from(10u8).lpad(32, 0).into(),
                        }],
                        change: ChangeType::Update.into(),
                        token_balances: vec![],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_3".to_owned(),
                        tokens: vec![address_from_str(DAI_ADDRESS), address_from_str(USDC_ADDRESS)],
                        contracts: vec![address_from_str(
                            "0000000000000000000000000000000000000001",
                        )],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![],
                }],
            },
            5 => BlockContractChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionContractChanges {
                    tx: Some(pb_transactions(5, 1)),
                    contract_changes: vec![
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from(10u8).lpad(32, 0).into(),
                            }],
                            change: ChangeType::Update.into(),
                            token_balances: vec![AccountBalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 1_i32.to_be_bytes().to_vec(),
                            }],
                        },
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000002"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from(10u8).lpad(32, 0).into(),
                            }],
                            change: ChangeType::Update.into(),
                            token_balances: vec![AccountBalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 1_i32.to_be_bytes().to_vec(),
                            }],
                        },
                    ],
                    component_changes: vec![],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_3".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            _ => panic!("Requested BlockContractChanges version doesn't exist"),
        }
    }

    pub fn pb_block_entity_changes(version: u8) -> crate::pb::tycho::evm::v1::BlockEntityChanges {
        use crate::pb::tycho::evm::v1::*;

        match version {
            0 => BlockEntityChanges {
                block: Some(Block {
                    hash: Bytes::zero(32).to_vec(),
                    parent_hash: Bytes::from(vec![0x21, 0x22, 0x23, 0x24])
                        .lpad(32, 0)
                        .to_vec(),
                    number: 1,
                    ts: yesterday_midnight().timestamp() as u64,
                }),
                changes: vec![
                    TransactionEntityChanges {
                        tx: Some(Transaction {
                            hash: Bytes::zero(32).to_vec(),
                            from: Bytes::zero(20).to_vec(),
                            to: Bytes::zero(20).to_vec(),
                            index: 10,
                        }),
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "State1".to_owned(),
                                attributes: vec![
                                    Attribute {
                                        name: "reserve1".to_owned(),
                                        value: Bytes::from(1000u64)
                                            .lpad(32, 0)
                                            .to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "reserve2".to_owned(),
                                        value: Bytes::from(500u64).lpad(32, 0).to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "static_attribute".to_owned(),
                                        value: Bytes::from(1u64).lpad(32, 0).to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                ],
                            },
                            EntityChanges {
                                component_id: "State2".to_owned(),
                                attributes: vec![
                                    Attribute {
                                        name: "reserve1".to_owned(),
                                        value: Bytes::from(1000u64)
                                            .lpad(32, 0)
                                            .to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "reserve2".to_owned(),
                                        value: Bytes::from(500u64).lpad(32, 0).to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "static_attribute".to_owned(),
                                        value: Bytes::from(1u64).lpad(32, 0).to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                ],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![],
                    },
                    TransactionEntityChanges {
                        tx: Some(Transaction {
                            hash: Bytes::from(vec![0x11, 0x12, 0x13, 0x14])
                                .lpad(32, 0)
                                .to_vec(),
                            from: Bytes::from(vec![0x41, 0x42, 0x43, 0x44])
                                .lpad(20, 0)
                                .to_vec(),
                            to: Bytes::from(vec![0x51, 0x52, 0x53, 0x54])
                                .lpad(20, 0)
                                .to_vec(),
                            index: 11,
                        }),
                        entity_changes: vec![EntityChanges {
                            component_id: "State1".to_owned(),
                            attributes: vec![
                                Attribute {
                                    name: "reserve".to_owned(),
                                    value: Bytes::from(600u64).lpad(32, 0).to_vec(),
                                    change: ChangeType::Update.into(),
                                },
                                Attribute {
                                    name: "new".to_owned(),
                                    value: Bytes::zero(32).to_vec(),
                                    change: ChangeType::Update.into(),
                                },
                            ],
                        }],
                        component_changes: vec![ProtocolComponent {
                            id: "Pool".to_owned(),
                            tokens: vec![
                                address_from_str(DAI_ADDRESS),
                                address_from_str(DAI_ADDRESS),
                            ],
                            contracts: vec![address_from_str(WETH_ADDRESS)],
                            static_att: vec![Attribute {
                                name: "key".to_owned(),
                                value: Bytes::from(600u64).lpad(32, 0).to_vec(),
                                change: ChangeType::Creation.into(),
                            }],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "WeightedPool".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(DAI_ADDRESS),
                            balance: 1_i32.to_le_bytes().to_vec(),
                            component_id: "Balance1".into(),
                        }],
                    },
                ],
            },
            1 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionEntityChanges {
                    tx: Some(pb_transactions(1, 1)),
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![
                            Attribute {
                                name: "attr_1".to_owned(),
                                value: Bytes::from(1u64).lpad(32, 0).to_vec(),
                                change: ChangeType::Update.into(),
                            },
                            Attribute {
                                name: "attr_2".to_owned(),
                                value: Bytes::from(2u64).lpad(32, 0).to_vec(),
                                change: ChangeType::Update.into(),
                            },
                        ],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_1".to_owned(),
                        tokens: vec![
                            address_from_str(WETH_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![Attribute {
                            name: "st_attr_1".to_owned(),
                            value: Bytes::from(1u64).lpad(32, 0).to_vec(),
                            change: ChangeType::Creation.into(),
                        }],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![BalanceChange {
                        token: address_from_str(USDC_ADDRESS),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        component_id: "pc_1".into(),
                    }],
                }],
            },
            2 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionEntityChanges {
                    tx: Some(pb_transactions(2, 1)),
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![Attribute {
                            name: "attr_1".to_owned(),
                            value: Bytes::from(10u64).lpad(32, 0).to_vec(),
                            change: ChangeType::Update.into(),
                        }],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDT_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            3 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionEntityChanges {
                        tx: Some(pb_transactions(3, 2)),
                        entity_changes: vec![EntityChanges {
                            component_id: "pc_1".to_owned(),
                            attributes: vec![Attribute {
                                name: "attr_1".to_owned(),
                                value: Bytes::from(1000u64)
                                    .lpad(32, 0)
                                    .to_vec(),
                                change: ChangeType::Update.into(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 3_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        }],
                    },
                    TransactionEntityChanges {
                        tx: Some(pb_transactions(3, 1)),
                        entity_changes: vec![EntityChanges {
                            component_id: "pc_1".to_owned(),
                            attributes: vec![Attribute {
                                name: "attr_1".to_owned(),
                                value: Bytes::from(99999u64)
                                    .lpad(32, 0)
                                    .to_vec(),
                                change: ChangeType::Update.into(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 99999_i32.to_be_bytes().to_vec(),
                                component_id: "pc_2".into(),
                            },
                            BalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 1000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                        ],
                    },
                ],
            },
            4 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionEntityChanges {
                        tx: Some(pb_transactions(4, 1)),
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "pc_1".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: Bytes::from(10_000u64)
                                        .lpad(32, 0)
                                        .to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                            EntityChanges {
                                component_id: "pc_3".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: Bytes::from(3u64).lpad(32, 0).to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                        ],
                        component_changes: vec![ProtocolComponent {
                            id: "pc_3".to_owned(),
                            tokens: vec![
                                address_from_str(DAI_ADDRESS),
                                address_from_str(WETH_ADDRESS),
                            ],
                            contracts: vec![],
                            static_att: vec![],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "pt_2".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![],
                    },
                    TransactionEntityChanges {
                        tx: Some(pb_transactions(4, 2)),
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "pc_3".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: Bytes::from(300u64).lpad(32, 0).to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                            EntityChanges {
                                component_id: "pc_1".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: Bytes::from(100_000u64)
                                        .lpad(32, 0)
                                        .to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 3000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_3".into(),
                            },
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 1000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                        ],
                    },
                ],
            },
            5 => BlockEntityChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionEntityChanges {
                    tx: Some(pb_transactions(5, 1)),
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![Attribute {
                            name: "attr_2".to_owned(),
                            value: Bytes::from(1_000_000u64)
                                .lpad(32, 0)
                                .to_vec(),
                            change: ChangeType::Update.into(),
                        }],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Deletion.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![BalanceChange {
                        token: address_from_str(WETH_ADDRESS),
                        balance: 1000_i32.to_be_bytes().to_vec(),
                        component_id: "pc_1".into(),
                    }],
                }],
            },
            _ => panic!("Requested unknown version of block entity changes"),
        }
    }

    pub fn pb_block_scoped_data(
        msg: impl prost::Message,
        cursor: Option<&str>,
        final_block_height: Option<u64>,
    ) -> crate::pb::sf::substreams::rpc::v2::BlockScopedData {
        use crate::pb::sf::substreams::{rpc::v2::*, v1::Clock};
        let val = msg.encode_to_vec();
        BlockScopedData {
            output: Some(MapModuleOutput {
                name: "map_changes".to_owned(),
                map_output: Some(prost_types::Any {
                    type_url: "tycho.evm.v1.BlockChanges".to_owned(),
                    value: val,
                }),
                debug_info: None,
            }),
            clock: Some(Clock {
                id: HASH_256_0.to_owned(),
                number: 420,
                timestamp: Some(prost_types::Timestamp { seconds: 1000, nanos: 0 }),
            }),
            cursor: cursor
                .unwrap_or("cursor@420")
                .to_owned(),
            final_block_height: final_block_height.unwrap_or(420),
            debug_map_outputs: vec![],
            debug_store_outputs: vec![],
        }
    }

    pub fn pb_vm_block_changes(version: u8) -> crate::pb::tycho::evm::v1::BlockChanges {
        use crate::pb::tycho::evm::v1::*;

        match version {
            0 => BlockChanges {
                block: Some(Block {
                    hash: vec![0x31, 0x32, 0x33, 0x34],
                    parent_hash: vec![0x21, 0x22, 0x23, 0x24],
                    number: 1,
                    ts: 1000,
                }),

                changes: vec![
                    TransactionChanges {
                        tx: Some(Transaction {
                            hash: vec![0x11, 0x12, 0x13, 0x14],
                            from: vec![0x41, 0x42, 0x43, 0x44],
                            to: vec![0x51, 0x52, 0x53, 0x54],
                            index: 2,
                        }),
                        contract_changes: vec![ContractChange {
                            address: vec![0x61, 0x62, 0x63, 0x64],
                            balance: vec![0x71, 0x72, 0x73, 0x74],
                            code: vec![0x81, 0x82, 0x83, 0x84],
                            slots: vec![
                                ContractSlot {
                                    slot: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                    value: vec![0xb1, 0xb2, 0xb3, 0xb4],
                                },
                                ContractSlot {
                                    slot: vec![0xc1, 0xc2, 0xc3, 0xc4],
                                    value: vec![0xd1, 0xd2, 0xd3, 0xd4],
                                },
                            ],
                            change: ChangeType::Update.into(),
                            token_balances: vec![AccountBalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 50000000.encode_to_vec(),
                            }],
                        }],
                        entity_changes: vec![],
                        component_changes: vec![ProtocolComponent {
                            id: "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                .to_owned(),
                            tokens: vec![
                                address_from_str(DAI_ADDRESS),
                                address_from_str(DAI_ADDRESS),
                            ],
                            contracts: vec![
                                address_from_str(WETH_ADDRESS),
                                address_from_str(WETH_ADDRESS),
                            ],
                            static_att: vec![
                                Attribute {
                                    name: "key1".to_owned(),
                                    value: b"value1".to_vec(),
                                    change: ChangeType::Creation.into(),
                                },
                                Attribute {
                                    name: "key2".to_owned(),
                                    value: b"value2".to_vec(),
                                    change: ChangeType::Creation.into(),
                                },
                            ],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "WeightedPool".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 50000000.encode_to_vec(),
                            component_id:
                                "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                    .as_bytes()
                                    .to_vec(),
                        }],
                    },
                    TransactionChanges {
                        tx: Some(Transaction {
                            hash: vec![
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                            ],
                            from: vec![0x41, 0x42, 0x43, 0x44],
                            to: vec![0x51, 0x52, 0x53, 0x54],
                            index: 5,
                        }),
                        contract_changes: vec![ContractChange {
                            address: vec![0x61, 0x62, 0x63, 0x64],
                            balance: vec![0xf1, 0xf2, 0xf3, 0xf4],
                            code: vec![0x01, 0x02, 0x03, 0x04],
                            slots: vec![
                                ContractSlot {
                                    slot: vec![0x91, 0x92, 0x93, 0x94],
                                    value: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                },
                                ContractSlot {
                                    slot: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                    value: vec![0xc1, 0xc2, 0xc3, 0xc4],
                                },
                            ],
                            change: ChangeType::Update.into(),
                            token_balances: vec![AccountBalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 10.encode_to_vec(),
                            }],
                        }],
                        entity_changes: vec![],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 10.encode_to_vec(),
                            component_id:
                                "d417ff54652c09bd9f31f216b1a2e5d1e28c1dce1ba840c40d16f2b4d09b5902"
                                    .to_string()
                                    .as_bytes()
                                    .to_vec(),
                        }],
                    },
                ],
            },
            1 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(1, 1)),
                    contract_changes: vec![ContractChange {
                        address: address_from_str("0000000000000000000000000000000000000001"),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        code: 123_i32.to_be_bytes().to_vec(),
                        slots: vec![ContractSlot {
                            slot: Bytes::from("0x01").into(),
                            value: Bytes::from("0x01").into(),
                        }],
                        change: ChangeType::Creation.into(),
                        token_balances: vec![
                            AccountBalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 1_i32.to_be_bytes().to_vec(),
                            },
                            AccountBalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 1_i32.to_be_bytes().to_vec(),
                            },
                        ],
                    }],
                    entity_changes: vec![],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_1".to_owned(),
                        tokens: vec![
                            address_from_str(WETH_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            2 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(2, 1)),
                    contract_changes: vec![
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000002"),
                            balance: 2_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_be_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x02").into(),
                            }],
                            change: ChangeType::Creation.into(),
                            token_balances: vec![
                                AccountBalanceChange {
                                    token: address_from_str(USDT_ADDRESS),
                                    balance: 20_i32.to_be_bytes().to_vec(),
                                },
                                AccountBalanceChange {
                                    token: address_from_str(USDC_ADDRESS),
                                    balance: 20_i32.to_be_bytes().to_vec(),
                                },
                            ],
                        },
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 10_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_be_bytes().to_vec(),
                            slots: vec![
                                ContractSlot {
                                    slot: Bytes::from("0x01").into(),
                                    value: Bytes::from("0x10").into(),
                                },
                                ContractSlot {
                                    slot: Bytes::from("0x02").into(),
                                    value: Bytes::from("0x0a").into(),
                                },
                            ],
                            change: ChangeType::Update.into(),
                            token_balances: vec![AccountBalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 10_i32.to_be_bytes().to_vec(),
                            }],
                        },
                    ],
                    entity_changes: vec![],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![address_from_str(
                            "0000000000000000000000000000000000000002",
                        )],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 20_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDT_ADDRESS),
                            balance: 20_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 10_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            3 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionChanges {
                        tx: Some(pb_transactions(3, 1)),
                        contract_changes: vec![
                            ContractChange {
                                address: address_from_str(
                                    "0000000000000000000000000000000000000001",
                                ),
                                balance: 1_i32.to_be_bytes().to_vec(),
                                code: 123_i32.to_le_bytes().to_vec(),
                                slots: vec![ContractSlot {
                                    slot: Bytes::from("0x01").into(),
                                    value: Bytes::from("0x01").into(),
                                }],
                                change: ChangeType::Update.into(),
                                token_balances: vec![],
                            },
                            ContractChange {
                                address: address_from_str(
                                    "0000000000000000000000000000000000000002",
                                ),
                                balance: 20_i32.to_be_bytes().to_vec(),
                                code: 123_i32.to_le_bytes().to_vec(),
                                slots: vec![ContractSlot {
                                    slot: Bytes::from("0x02").into(),
                                    value: Bytes::from("0xc8").into(),
                                }],
                                change: ChangeType::Update.into(),
                                token_balances: vec![AccountBalanceChange {
                                    token: address_from_str(USDC_ADDRESS),
                                    balance: 1_i32.to_be_bytes().to_vec(),
                                }],
                            },
                        ],
                        entity_changes: vec![],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        }],
                    },
                    TransactionChanges {
                        tx: Some(pb_transactions(3, 2)),
                        contract_changes: vec![ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x01").into(),
                            }],
                            change: ChangeType::Update.into(),
                            token_balances: vec![AccountBalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 100_i32.to_be_bytes().to_vec(),
                            }],
                        }],
                        entity_changes: vec![],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 100_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 2_i32.to_be_bytes().to_vec(),
                                component_id: "pc_2".into(),
                            },
                        ],
                    },
                ],
            },
            4 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(4, 1)),
                    contract_changes: vec![ContractChange {
                        address: address_from_str("0000000000000000000000000000000000000001"),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        code: 123_i32.to_le_bytes().to_vec(),
                        slots: vec![ContractSlot {
                            slot: Bytes::from("0x03").into(),
                            value: Bytes::from("0x10").into(),
                        }],
                        change: ChangeType::Update.into(),
                        token_balances: vec![],
                    }],
                    entity_changes: vec![],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_3".to_owned(),
                        tokens: vec![address_from_str(DAI_ADDRESS), address_from_str(USDC_ADDRESS)],
                        contracts: vec![address_from_str(
                            "0000000000000000000000000000000000000001",
                        )],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![],
                }],
            },
            5 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(5, 1)),
                    contract_changes: vec![
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000001"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x10").into(),
                            }],
                            change: ChangeType::Update.into(),
                            token_balances: vec![
                                AccountBalanceChange {
                                    token: address_from_str(USDC_ADDRESS),
                                    balance: 100_i32.to_be_bytes().to_vec(),
                                },
                                AccountBalanceChange {
                                    token: address_from_str(WETH_ADDRESS),
                                    balance: 100_i32.to_be_bytes().to_vec(),
                                },
                            ],
                        },
                        ContractChange {
                            address: address_from_str("0000000000000000000000000000000000000002"),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            code: 123_i32.to_le_bytes().to_vec(),
                            slots: vec![ContractSlot {
                                slot: Bytes::from("0x01").into(),
                                value: Bytes::from("0x10").into(),
                            }],
                            change: ChangeType::Update.into(),
                            token_balances: vec![AccountBalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 1_i32.to_be_bytes().to_vec(),
                            }],
                        },
                    ],
                    entity_changes: vec![],
                    component_changes: vec![],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_3".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            _ => panic!("Requested BlockChanges version doesn't exist"),
        }
    }

    pub fn pb_native_block_changes(version: u8) -> crate::pb::tycho::evm::v1::BlockChanges {
        use crate::pb::tycho::evm::v1::*;

        match version {
            0 => BlockChanges {
                block: Some(Block {
                    hash: vec![0x0, 0x0, 0x0, 0x0],
                    parent_hash: vec![0x21, 0x22, 0x23, 0x24],
                    number: 1,
                    ts: yesterday_midnight().timestamp() as u64,
                }),
                changes: vec![
                    TransactionChanges {
                        tx: Some(Transaction {
                            hash: vec![0x0, 0x0, 0x0, 0x0],
                            from: vec![0x0, 0x0, 0x0, 0x0],
                            to: vec![0x0, 0x0, 0x0, 0x0],
                            index: 10,
                        }),
                        contract_changes: vec![],
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "State1".to_owned(),
                                attributes: vec![
                                    Attribute {
                                        name: "reserve".to_owned(),
                                        value: Bytes::from(1_000u64)
                                            .lpad(32, 0)
                                            .to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "static_attribute".to_owned(),
                                        value: Bytes::from(1u64).lpad(32, 0).to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                ],
                            },
                            EntityChanges {
                                component_id: "State2".to_owned(),
                                attributes: vec![
                                    Attribute {
                                        name: "reserve".to_owned(),
                                        value: Bytes::from(1_000u64)
                                            .lpad(32, 0)
                                            .to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                    Attribute {
                                        name: "static_attribute".to_owned(),
                                        value: Bytes::from(1u64).lpad(32, 0).to_vec(),
                                        change: ChangeType::Update.into(),
                                    },
                                ],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![],
                    },
                    TransactionChanges {
                        tx: Some(Transaction {
                            hash: vec![0x11, 0x12, 0x13, 0x14],
                            from: vec![0x41, 0x42, 0x43, 0x44],
                            to: vec![0x51, 0x52, 0x53, 0x54],
                            index: 11,
                        }),
                        contract_changes: vec![],
                        entity_changes: vec![EntityChanges {
                            component_id: "State1".to_owned(),
                            attributes: vec![
                                Attribute {
                                    name: "reserve".to_owned(),
                                    value: Bytes::from(600u64).lpad(32, 0).to_vec(),
                                    change: ChangeType::Update.into(),
                                },
                                Attribute {
                                    name: "new".to_owned(),
                                    value: Bytes::zero(32).to_vec(),
                                    change: ChangeType::Update.into(),
                                },
                            ],
                        }],
                        component_changes: vec![ProtocolComponent {
                            id: "Pool".to_owned(),
                            tokens: vec![
                                address_from_str(DAI_ADDRESS),
                                address_from_str(DAI_ADDRESS),
                            ],
                            contracts: vec![address_from_str(WETH_ADDRESS)],
                            static_att: vec![Attribute {
                                name: "key".to_owned(),
                                value: Bytes::from(600u64).lpad(32, 0).to_vec(),
                                change: ChangeType::Creation.into(),
                            }],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "WeightedPool".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(DAI_ADDRESS),
                            balance: 1_i32.to_le_bytes().to_vec(),
                            component_id: "Balance1".into(),
                        }],
                    },
                ],
            },
            1 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(1, 1)),
                    contract_changes: vec![],
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![
                            Attribute {
                                name: "attr_1".to_owned(),
                                value: Bytes::from(1u64).lpad(32, 0).to_vec(),
                                change: ChangeType::Update.into(),
                            },
                            Attribute {
                                name: "attr_2".to_owned(),
                                value: Bytes::from(2u64).lpad(32, 0).to_vec(),
                                change: ChangeType::Update.into(),
                            },
                        ],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_1".to_owned(),
                        tokens: vec![
                            address_from_str(WETH_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![Attribute {
                            name: "st_attr_1".to_owned(),
                            value: Bytes::from(1u64).lpad(32, 0).to_vec(),
                            change: ChangeType::Creation.into(),
                        }],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![BalanceChange {
                        token: address_from_str(USDC_ADDRESS),
                        balance: 1_i32.to_be_bytes().to_vec(),
                        component_id: "pc_1".into(),
                    }],
                }],
            },
            2 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(2, 1)),
                    contract_changes: vec![],
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![Attribute {
                            name: "attr_1".to_owned(),
                            value: Bytes::from(10u64).lpad(32, 0).to_vec(),
                            change: ChangeType::Update.into(),
                        }],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![
                        BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(USDT_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        },
                        BalanceChange {
                            token: address_from_str(WETH_ADDRESS),
                            balance: 1_i32.to_be_bytes().to_vec(),
                            component_id: "pc_1".into(),
                        },
                    ],
                }],
            },
            3 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionChanges {
                        tx: Some(pb_transactions(3, 2)),
                        contract_changes: vec![],
                        entity_changes: vec![EntityChanges {
                            component_id: "pc_1".to_owned(),
                            attributes: vec![Attribute {
                                name: "attr_1".to_owned(),
                                value: Bytes::from(1_000u64)
                                    .lpad(32, 0)
                                    .to_vec(),
                                change: ChangeType::Update.into(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![BalanceChange {
                            token: address_from_str(USDC_ADDRESS),
                            balance: 3_i32.to_be_bytes().to_vec(),
                            component_id: "pc_2".into(),
                        }],
                    },
                    TransactionChanges {
                        tx: Some(pb_transactions(3, 1)),
                        contract_changes: vec![],
                        entity_changes: vec![EntityChanges {
                            component_id: "pc_1".to_owned(),
                            attributes: vec![Attribute {
                                name: "attr_1".to_owned(),
                                value: Bytes::from(99_999u64)
                                    .lpad(32, 0)
                                    .to_vec(),
                                change: ChangeType::Update.into(),
                            }],
                        }],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 99999_i32.to_be_bytes().to_vec(),
                                component_id: "pc_2".into(),
                            },
                            BalanceChange {
                                token: address_from_str(WETH_ADDRESS),
                                balance: 1000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                        ],
                    },
                ],
            },
            4 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![
                    TransactionChanges {
                        tx: Some(pb_transactions(4, 1)),
                        contract_changes: vec![],
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "pc_1".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: Bytes::from(10_000u64)
                                        .lpad(32, 0)
                                        .to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                            EntityChanges {
                                component_id: "pc_3".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: Bytes::from(3u64).lpad(32, 0).to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                        ],
                        component_changes: vec![ProtocolComponent {
                            id: "pc_3".to_owned(),
                            tokens: vec![
                                address_from_str(DAI_ADDRESS),
                                address_from_str(WETH_ADDRESS),
                            ],
                            contracts: vec![],
                            static_att: vec![],
                            change: ChangeType::Creation.into(),
                            protocol_type: Some(ProtocolType {
                                name: "pt_2".to_string(),
                                financial_type: 0,
                                attribute_schema: vec![],
                                implementation_type: 0,
                            }),
                        }],
                        balance_changes: vec![],
                    },
                    TransactionChanges {
                        tx: Some(pb_transactions(4, 2)),
                        contract_changes: vec![],
                        entity_changes: vec![
                            EntityChanges {
                                component_id: "pc_3".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: Bytes::from(30u64).lpad(32, 0).to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                            EntityChanges {
                                component_id: "pc_1".to_owned(),
                                attributes: vec![Attribute {
                                    name: "attr_1".to_owned(),
                                    value: Bytes::from(100_000u64)
                                        .lpad(32, 0)
                                        .to_vec(),
                                    change: ChangeType::Update.into(),
                                }],
                            },
                        ],
                        component_changes: vec![],
                        balance_changes: vec![
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 3000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_3".into(),
                            },
                            BalanceChange {
                                token: address_from_str(USDC_ADDRESS),
                                balance: 1000_i32.to_be_bytes().to_vec(),
                                component_id: "pc_1".into(),
                            },
                        ],
                    },
                ],
            },
            5 => BlockChanges {
                block: Some(pb_blocks(version as u64)),
                changes: vec![TransactionChanges {
                    tx: Some(pb_transactions(5, 1)),
                    contract_changes: vec![],
                    entity_changes: vec![EntityChanges {
                        component_id: "pc_1".to_owned(),
                        attributes: vec![Attribute {
                            name: "attr_2".to_owned(),
                            value: Bytes::from(1_000_000u64)
                                .lpad(32, 0)
                                .to_vec(),
                            change: ChangeType::Update.into(),
                        }],
                    }],
                    component_changes: vec![ProtocolComponent {
                        id: "pc_2".to_owned(),
                        tokens: vec![
                            address_from_str(USDT_ADDRESS),
                            address_from_str(USDC_ADDRESS),
                        ],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Deletion.into(),
                        protocol_type: Some(ProtocolType {
                            name: "pt_1".to_string(),
                            financial_type: 0,
                            attribute_schema: vec![],
                            implementation_type: 0,
                        }),
                    }],
                    balance_changes: vec![BalanceChange {
                        token: address_from_str(WETH_ADDRESS),
                        balance: 1000_i32.to_be_bytes().to_vec(),
                        component_id: "pc_1".into(),
                    }],
                }],
            },
            _ => panic!("Requested unknown version of block entity changes"),
        }
    }
}
