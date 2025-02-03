// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "financial_type"))]
    pub struct FinancialType;

    #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "implementation_type"))]
    pub struct ImplementationType;
}

diesel::table! {
    account (id) {
        id -> Int8,
        chain_id -> Int8,
        #[max_length = 255]
        title -> Varchar,
        address -> Bytea,
        creation_tx -> Nullable<Int8>,
        created_at -> Nullable<Timestamptz>,
        deleted_at -> Nullable<Timestamptz>,
        deletion_tx -> Nullable<Int8>,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    account_balance (id) {
        id -> Int8,
        balance -> Bytea,
        account_id -> Int8,
        modify_tx -> Int8,
        valid_from -> Timestamptz,
        valid_to -> Nullable<Timestamptz>,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
        token_id -> Int8,
    }
}

diesel::table! {
    block (id) {
        id -> Int8,
        hash -> Bytea,
        parent_hash -> Bytea,
        main -> Bool,
        number -> Int8,
        ts -> Timestamptz,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
        chain_id -> Int8,
    }
}

diesel::table! {
    chain (id) {
        id -> Int8,
        #[max_length = 255]
        name -> Varchar,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    component_balance (token_id, protocol_component_id, valid_to) {
        token_id -> Int8,
        new_balance -> Bytea,
        previous_value -> Bytea,
        balance_float -> Float8,
        modify_tx -> Int8,
        protocol_component_id -> Int8,
        inserted_ts -> Timestamptz,
        valid_from -> Timestamptz,
        valid_to -> Timestamptz,
    }
}

diesel::table! {
    component_balance_default (token_id, protocol_component_id, valid_to) {
        token_id -> Int8,
        new_balance -> Bytea,
        previous_value -> Bytea,
        balance_float -> Float8,
        modify_tx -> Int8,
        protocol_component_id -> Int8,
        inserted_ts -> Timestamptz,
        valid_from -> Timestamptz,
        valid_to -> Timestamptz,
    }
}

diesel::table! {
    component_tvl (id) {
        id -> Int8,
        protocol_component_id -> Int8,
        tvl -> Float8,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    contract_code (id) {
        id -> Int8,
        code -> Bytea,
        hash -> Bytea,
        account_id -> Int8,
        modify_tx -> Int8,
        valid_from -> Timestamptz,
        valid_to -> Nullable<Timestamptz>,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    contract_storage (account_id, slot, valid_to) {
        slot -> Bytea,
        value -> Nullable<Bytea>,
        previous_value -> Nullable<Bytea>,
        account_id -> Int8,
        modify_tx -> Int8,
        ordinal -> Int8,
        valid_from -> Timestamptz,
        valid_to -> Timestamptz,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    contract_storage_default (account_id, slot, valid_to) {
        slot -> Bytea,
        value -> Nullable<Bytea>,
        previous_value -> Nullable<Bytea>,
        account_id -> Int8,
        modify_tx -> Int8,
        ordinal -> Int8,
        valid_from -> Timestamptz,
        valid_to -> Timestamptz,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    extraction_state (id) {
        id -> Int8,
        #[max_length = 255]
        name -> Varchar,
        #[max_length = 255]
        version -> Varchar,
        cursor -> Nullable<Bytea>,
        chain_id -> Int8,
        attributes -> Nullable<Jsonb>,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
        block_id -> Int8,
    }
}

diesel::table! {
    protocol_component (id) {
        id -> Int8,
        chain_id -> Int8,
        #[max_length = 255]
        external_id -> Varchar,
        attributes -> Nullable<Jsonb>,
        created_at -> Timestamptz,
        creation_tx -> Int8,
        deleted_at -> Nullable<Timestamptz>,
        deletion_tx -> Nullable<Int8>,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
        protocol_type_id -> Int8,
        protocol_system_id -> Int8,
    }
}

diesel::table! {
    protocol_component_holds_contract (protocol_component_id, contract_code_id) {
        protocol_component_id -> Int8,
        contract_code_id -> Int8,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    protocol_component_holds_token (protocol_component_id, token_id) {
        protocol_component_id -> Int8,
        token_id -> Int8,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    protocol_state (protocol_component_id, attribute_name, valid_to) {
        attribute_name -> Varchar,
        attribute_value -> Bytea,
        previous_value -> Nullable<Bytea>,
        modify_tx -> Int8,
        valid_from -> Timestamptz,
        valid_to -> Timestamptz,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
        protocol_component_id -> Int8,
    }
}

diesel::table! {
    protocol_state_default (protocol_component_id, attribute_name, valid_to) {
        attribute_name -> Varchar,
        attribute_value -> Bytea,
        previous_value -> Nullable<Bytea>,
        modify_tx -> Int8,
        valid_from -> Timestamptz,
        valid_to -> Timestamptz,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
        protocol_component_id -> Int8,
    }
}

diesel::table! {
    protocol_system (id) {
        id -> Int8,
        #[max_length = 255]
        name -> Varchar,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::FinancialType;
    use super::sql_types::ImplementationType;

    protocol_type (id) {
        id -> Int8,
        #[max_length = 255]
        name -> Varchar,
        financial_type -> FinancialType,
        attribute_schema -> Nullable<Jsonb>,
        implementation -> ImplementationType,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    token (id) {
        id -> Int8,
        account_id -> Int8,
        #[max_length = 255]
        symbol -> Varchar,
        decimals -> Int4,
        tax -> Int8,
        gas -> Array<Nullable<Int8>>,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
        quality -> Int4,
    }
}

diesel::table! {
    token_price (id) {
        id -> Int8,
        token_id -> Int8,
        price -> Float8,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    transaction (id) {
        id -> Int8,
        hash -> Bytea,
        from -> Bytea,
        to -> Bytea,
        index -> Int8,
        block_id -> Int8,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::joinable!(account -> chain (chain_id));
diesel::joinable!(account_balance -> account (account_id));
diesel::joinable!(account_balance -> token (token_id));
diesel::joinable!(account_balance -> transaction (modify_tx));
diesel::joinable!(block -> chain (chain_id));
diesel::joinable!(component_balance -> protocol_component (protocol_component_id));
diesel::joinable!(component_balance -> token (token_id));
diesel::joinable!(component_balance -> transaction (modify_tx));
diesel::joinable!(component_balance_default -> protocol_component (protocol_component_id));
diesel::joinable!(component_balance_default -> token (token_id));
diesel::joinable!(component_balance_default -> transaction (modify_tx));
diesel::joinable!(component_tvl -> protocol_component (protocol_component_id));
diesel::joinable!(contract_code -> account (account_id));
diesel::joinable!(contract_code -> transaction (modify_tx));
diesel::joinable!(contract_storage -> account (account_id));
diesel::joinable!(contract_storage -> transaction (modify_tx));
diesel::joinable!(contract_storage_default -> account (account_id));
diesel::joinable!(contract_storage_default -> transaction (modify_tx));
diesel::joinable!(extraction_state -> block (block_id));
diesel::joinable!(extraction_state -> chain (chain_id));
diesel::joinable!(protocol_component -> chain (chain_id));
diesel::joinable!(protocol_component -> protocol_system (protocol_system_id));
diesel::joinable!(protocol_component -> protocol_type (protocol_type_id));
diesel::joinable!(protocol_component_holds_contract -> contract_code (contract_code_id));
diesel::joinable!(protocol_component_holds_contract -> protocol_component (protocol_component_id));
diesel::joinable!(protocol_component_holds_token -> protocol_component (protocol_component_id));
diesel::joinable!(protocol_component_holds_token -> token (token_id));
diesel::joinable!(protocol_state -> protocol_component (protocol_component_id));
diesel::joinable!(protocol_state -> transaction (modify_tx));
diesel::joinable!(protocol_state_default -> protocol_component (protocol_component_id));
diesel::joinable!(protocol_state_default -> transaction (modify_tx));
diesel::joinable!(token -> account (account_id));
diesel::joinable!(token_price -> token (token_id));
diesel::joinable!(transaction -> block (block_id));

diesel::allow_tables_to_appear_in_same_query!(
    account,
    account_balance,
    block,
    chain,
    component_balance,
    component_balance_default,
    component_tvl,
    contract_code,
    contract_storage,
    contract_storage_default,
    extraction_state,
    protocol_component,
    protocol_component_holds_contract,
    protocol_component_holds_token,
    protocol_state,
    protocol_state_default,
    protocol_system,
    protocol_type,
    token,
    token_price,
    transaction,
);
