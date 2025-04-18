CREATE TABLE IF NOT EXISTS component_balance_old(
    token_id int8 NOT NULL,
    new_balance bytea NOT NULL,
    previous_value bytea NOT NULL,
    balance_float float8 NOT NULL,
    modify_tx int8 NOT NULL,
    protocol_component_id int8 NOT NULL,
    inserted_ts timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_from timestamptz NOT NULL,
    valid_to timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS contract_storage_old(
    slot bytea NOT NULL,
    value bytea NULL,
    previous_value bytea NULL,
    account_id int8 NOT NULL,
    modify_tx int8 NOT NULL,
    ordinal int8 NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_to timestamptz NOT NULL,
    inserted_ts timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified_ts timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS protocol_state_old(
    attribute_name varchar NOT NULL,
    attribute_value bytea NOT NULL,
    previous_value bytea NULL,
    modify_tx int8 NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_to timestamptz NOT NULL,
    inserted_ts timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified_ts timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    protocol_component_id int8 NOT NULL
);
