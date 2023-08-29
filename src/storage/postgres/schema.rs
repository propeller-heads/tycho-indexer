// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "financial_protocol_type"))]
    pub struct FinancialProtocolType;

    #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "hstore"))]
    pub struct Hstore;

    #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "protocol_implementation_type"))]
    pub struct ProtocolImplementationType;
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
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    account_balance (id) {
        id -> Int8,
        balance -> Bytea,
        account_id -> Int8,
        modify_tx -> Nullable<Int8>,
        valid_from -> Timestamptz,
        valid_to -> Nullable<Timestamptz>,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::Hstore;

    audit_log (id) {
        id -> Int8,
        #[max_length = 1]
        operation -> Bpchar,
        ts -> Timestamptz,
        userid -> Text,
        original_data -> Nullable<Hstore>,
        new_data -> Nullable<Hstore>,
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
    contract_storage (id) {
        id -> Int8,
        slot -> Bytea,
        value -> Nullable<Bytea>,
        previous_value -> Nullable<Bytea>,
        account_id -> Int8,
        modify_tx -> Int8,
        ordinal -> Int8,
        valid_from -> Timestamptz,
        valid_to -> Nullable<Timestamptz>,
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
    }
}

diesel::table! {
    protocol_calls_contract (id) {
        id -> Int8,
        protocol_component_id -> Int8,
        account_id -> Int8,
        valid_from -> Timestamptz,
        valid_to -> Nullable<Timestamptz>,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
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
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
        protocol_type_id -> Int8,
        protocol_system_id -> Int8,
    }
}

diesel::table! {
    protocol_holds_token (protocol_component_id, token_id) {
        protocol_component_id -> Int8,
        token_id -> Int8,
        inserted_ts -> Timestamptz,
        modified_ts -> Timestamptz,
    }
}

diesel::table! {
    protocol_state (id) {
        id -> Int8,
        tvl -> Nullable<Int8>,
        inertias -> Nullable<Array<Nullable<Int8>>>,
        state -> Nullable<Jsonb>,
        modify_tx -> Int8,
        valid_from -> Timestamptz,
        valid_to -> Nullable<Timestamptz>,
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
    use super::sql_types::FinancialProtocolType;
    use super::sql_types::ProtocolImplementationType;

    protocol_type (id) {
        id -> Int8,
        #[max_length = 255]
        name -> Varchar,
        financial_type -> FinancialProtocolType,
        attribute_schema -> Nullable<Jsonb>,
        implementation -> ProtocolImplementationType,
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
diesel::joinable!(account -> transaction (creation_tx));
diesel::joinable!(account_balance -> account (account_id));
diesel::joinable!(account_balance -> transaction (modify_tx));
diesel::joinable!(block -> chain (chain_id));
diesel::joinable!(contract_code -> account (account_id));
diesel::joinable!(contract_code -> transaction (modify_tx));
diesel::joinable!(contract_storage -> account (account_id));
diesel::joinable!(contract_storage -> transaction (modify_tx));
diesel::joinable!(extraction_state -> chain (chain_id));
diesel::joinable!(protocol_calls_contract -> account (account_id));
diesel::joinable!(protocol_calls_contract -> protocol_component (protocol_component_id));
diesel::joinable!(protocol_component -> chain (chain_id));
diesel::joinable!(protocol_component -> protocol_system (protocol_system_id));
diesel::joinable!(protocol_component -> protocol_type (protocol_type_id));
diesel::joinable!(protocol_component -> transaction (creation_tx));
diesel::joinable!(protocol_holds_token -> protocol_component (protocol_component_id));
diesel::joinable!(protocol_holds_token -> token (token_id));
diesel::joinable!(protocol_state -> protocol_component (protocol_component_id));
diesel::joinable!(protocol_state -> transaction (modify_tx));
diesel::joinable!(token -> account (account_id));
diesel::joinable!(transaction -> block (block_id));

diesel::allow_tables_to_appear_in_same_query!(
    account,
    account_balance,
    audit_log,
    block,
    chain,
    contract_code,
    contract_storage,
    extraction_state,
    protocol_calls_contract,
    protocol_component,
    protocol_holds_token,
    protocol_state,
    protocol_system,
    protocol_type,
    token,
    transaction,
);
