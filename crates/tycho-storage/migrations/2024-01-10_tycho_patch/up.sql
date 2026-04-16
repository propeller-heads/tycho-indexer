-- Make the "name" column of the protocol type unique
ALTER TABLE protocol_type
    ADD CONSTRAINT unique_name_constraint UNIQUE (name);

ALTER TABLE protocol_component
    DROP CONSTRAINT protocol_component_chain_id_protocol_system_id_external_id_key;

ALTER TABLE protocol_component
    ADD CONSTRAINT protocol_component_chain_id_external_id_key UNIQUE (chain_id, external_id);

DROP INDEX IF EXISTS idx_protocol_identity;

-- Change the name of the financial and implementation type enums
CREATE TYPE financial_type AS ENUM(
    'swap',
    'psm',
    'debt',
    'leverage'
);

ALTER TABLE protocol_type
    ALTER COLUMN financial_type TYPE financial_type
    USING protocol_type::text::financial_type;

DROP TYPE financial_protocol_type;

CREATE TYPE implementation_type AS ENUM(
    'custom',
    'vm'
);

ALTER TABLE protocol_type
    ALTER COLUMN "implementation" TYPE implementation_type
    USING protocol_type::text::implementation_type;

DROP TYPE protocol_implementation_type;

ALTER TABLE protocol_state
    DROP COLUMN state,
    DROP COLUMN tvl,
    DROP COLUMN inertias,
    ADD COLUMN attribute_name VARCHAR NOT NULL,
    ADD COLUMN attribute_value BYTEA NOT NULL,
    ADD COLUMN previous_value BYTEA NULL;

ALTER TABLE protocol_system
    ADD CONSTRAINT name_unique UNIQUE (name);

-- Make the "account_id" column of the token unique
ALTER TABLE token
    ADD CONSTRAINT unique_account_id_constraint UNIQUE (account_id);

DROP TRIGGER invalidate_previous_protocol_state ON protocol_state;

DROP FUNCTION invalidate_previous_entry_protocol_state();

DROP TRIGGER invalidate_previous_contract_storage ON contract_storage;

DROP FUNCTION invalidate_previous_entry_contract_storage();

DROP TRIGGER invalidate_previous_account_balance ON account_balance;

DROP FUNCTION invalidate_previous_entry_account_balance();

DROP TRIGGER invalidate_previous_contract_code ON contract_code;

DROP FUNCTION invalidate_previous_entry_contract_code();

CREATE TABLE IF NOT EXISTS protocol_component_holds_contract(
    "protocol_component_id" bigint REFERENCES protocol_component(id) ON DELETE CASCADE NOT NULL,
    -- we don't allow a contract to be deleted unless the protocol component was removed
    "contract_code_id" bigint REFERENCES "contract_code"(id) NOT NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY ("protocol_component_id", "contract_code_id")
);

CREATE INDEX IF NOT EXISTS idx_protocol_component_holds_contract_protocol_component_id
    ON protocol_component_holds_contract(protocol_component_id);

CREATE INDEX IF NOT EXISTS idx_protocol_component_holds_contract_contract_code_id ON
    protocol_component_holds_contract(contract_code_id);

--  Saves the component balance of a protocol component.
CREATE TABLE IF NOT EXISTS component_balance(
    "id" bigserial PRIMARY KEY,
    -- id of the token whose balance changed
    "token_id" bigint REFERENCES "token"(id) NOT NULL,
    -- new balance of the token for this component
    "new_balance" bytea NOT NULL,
    -- new balance of the token for this component
    "previous_value" bytea NOT NULL,
    -- new balance as a floating point number
    "balance_float" float NOT NULL,
    -- the transaction that modified the tvl of this component
    "modify_tx" bigint REFERENCES "transaction"(id) ON DELETE CASCADE NOT NULL,
    -- Reference to static attributes of the protocol.
    "protocol_component_id" bigint REFERENCES protocol_component(id) NOT NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- The ts at which this state became valid at.
    "valid_from" timestamptz NOT NULL,
    -- The ts at which this state stopped being valid at. Null if this
    --	state is the currently valid entry.
    "valid_to" timestamptz
);

-- Rename the protocol_holds_token table to protocol_component_holds_token
DROP TRIGGER update_modtime_protocol_holds_token ON protocol_holds_token;

DROP TRIGGER audit_table_protocol_holds_token ON protocol_holds_token;

ALTER TABLE protocol_holds_token RENAME TO protocol_component_holds_token;

CREATE TRIGGER update_modtime_protocol_component_holds_token
    BEFORE UPDATE ON protocol_component_holds_token
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER audit_table_protocol_component_holds_token
    BEFORE UPDATE ON protocol_component_holds_token
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TABLE IF NOT EXISTS token_price(
    "id" bigserial PRIMARY KEY,
    -- Id of the token whose price we record here.
    "token_id" bigint REFERENCES "token"(id) NOT NULL UNIQUE,
    -- Price in native token denomination.
    "price" double precision NOT NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was last modified in this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER update_modtime_token_price
    BEFORE UPDATE ON token_price
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER audit_table_token_price
    BEFORE UPDATE ON protocol_component_holds_token
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TABLE IF NOT EXISTS component_tvl(
    "id" bigserial PRIMARY KEY,
    -- Id of the component whose tvl we record here.
    "protocol_component_id" bigint REFERENCES protocol_component(id) NOT NULL UNIQUE,
    -- Tvl in native token denomination.
    "tvl" double precision NOT NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was last modified in this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_component_tvl_tvl ON component_tvl(tvl);

CREATE TRIGGER update_modtime_component_tvl
    BEFORE UPDATE ON component_tvl
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER audit_table_component_tvl
    BEFORE UPDATE ON component_tvl
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

ALTER TABLE token
    ADD COLUMN quality int NOT NULL DEFAULT 0;
