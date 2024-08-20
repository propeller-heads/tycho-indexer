# Reserved attribute names

Certain attribute names are reserved exclusively for specific purposes. Please use them only for their intended applications.

## Static Attributes

The following attributes names are reserved and must be given using `ProtocolComponent.static_att`. These attributes MUST be immutable. If it can ever change, it should be given as a state attribute (see below) for this component id.

- ### <u>**manual_updates**</u>

#### Description

The `manual_updates` static attribute determines whether the component update should be manually triggered using the `update_marker` state attribute. By default, updates occur automatically whenever there is a change in any of the required contracts. However, in scenarios where a contract undergoes frequent changes, automatic updates may not be desirable. For instance, a change in Balancer Vault storage should only trigger updates for the specific pools affected by the change, rather than for all pools indiscriminately. The `manual_updates` field helps to control and prevent unnecessary updates in such cases.

If it's enable, updates on this component are only triggered by emitting an `update_marker` state attribute (described below).

#### Type

This attribute must be set to [1u8] to enable manual updates.

#### Example Usage

```rust
Attribute {
name: "manual_updates".to_string(),
value: [1u8],
change: ChangeType::Creation.into(),
}
```

- ### <u>**pool_id**</u>

#### Description

The `pool_id` static attribute is used to specify the identifier of the pool when it differs from the `ProtocolComponent.id`. For example, Balancer pools have a component ID that corresponds to their contract address, and a separate pool ID used for registration on the Balancer Vault contract.

**Notice**: In most of the cases, using `ProtocolComponent.id` directly is preferred over `pool_id`.

#### Type

This attribute value must be provided as a UTF-8 encoded string in bytes.

#### Example Usage

```rust
Attribute {
name: "pool_id".to_string(),
value: format!("0x{}", hex::encode(pool_registered.pool_id)).as_bytes(),
change: ChangeType::Creation.into(),
}
```

## State Attributes

The following attributes names are reserved and must be given using `EntityChanges`. Unlike [Static Attributes](#static-attributes), state attributes are used for dynamic attributes and are allowed to change at anytime.

- ### <u>**stateless_contract_addr**</u>

#### Description

The `stateless_contract_addr_{index}` field is used to specify the address of a stateless contract required by the component. This field is essential for components that interact with stateless contracts, particularly in scenarios involving `DELEGATECALL`. If the bytecode of this stateless contract can be retreived in Substreams, it must be passed using the `stateless_contract_code` attribute (see below).

An index is used if multiple stateless contracts are needed. This index should start at 0 and increment by 1 for each additional `stateless_contract_addr`.

The value for `stateless_contract_addr_{index}` can be provided in two ways:

1. **Direct Contract Address**: A static contract address can be specified directly.
2. **Dynamic Address Resolution**: Alternatively, you can define a function or method that dynamically resolves and retrieves the stateless contract address at runtime. This can be particularly useful in complex contract architectures, such as those using a dynamic proxy pattern. It is important to note that the called contract must be indexed by the Substreams module.

#### Type

This attribute value must be provided as a UTF-8 encoded string in bytes.

#### Example Usage

##### 1. Direct Contract Address

To specify a direct contract address:

```rust
Attribute {
    name: "stateless_contract_addr_0".into(),
    value: format!("0x{}", hex::encode(address)).into_bytes(),
    change: ChangeType::Creation.into(),
}
Attribute {
    name: "stateless_contract_addr_1".into(),
    value: format!("0x{}", hex::encode(other_address)).into_bytes(),
    change: ChangeType::Creation.into(),
}
```

##### 2. Dynamic Address Resolution

To specify a function that dynamically resolves the address:

```rust
Attribute {
name: "stateless_contract_addr_0".into(),
// Call views_implementation() on TRICRYPTO_FACTORY
value: format!("call:0x{}:views_implementation()", hex::encode(TRICRYPTO_FACTORY)).into_bytes(),
change: ChangeType::Creation.into(),
}
```

- ### <u>**stateless_contract_code**</u>

#### Description

The `stateless_contract_code_{index}` field is used to specify the code for a given `stateless_contract_addr`.

An index is used if multiple stateless contracts are needed. This index must match with the related `stateless_contract_addr`.

#### Type

This attribute value must be provided as bytes.

#### Example Usage

```rust
Attribute {
name: "stateless_contract_code_0".to_string(),
value: code.to_vec(),
change: ChangeType::Creation.into(),
}
```

- ### <u>**balance_owner**</u>

#### Description

The `balance_owner` field is used to specify the address of the account that owns the protocol component tokens, in cases where the tokens are not owned by the protocol component itself or the component specifies multiple contract addresses. This is particularly useful for protocols that use a vault, for example Balancer.

#### Type

This attribute value must be provided as bytes.

#### Example Usage

```rust
Attribute {
name: "balance_owner".to_string(),
value: VAULT_ADDRESS.to_vec(),
change: ChangeType::Creation.into(),
}
```

- ### <u>**update_marker**</u>

#### Description

The `update_marker` field is used to indicate that a pool has changed, thereby triggering an update on the protocol component when `manual_update` is enabled.

#### Type

This attribute value must be provided as bytes.

#### Example Usage

```rust
Attribute {
    name: "update_marker".to_string(),
    value: vec![1u8],
    change: ChangeType::Update.into(),
};
```
