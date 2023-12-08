-- Your SQL goes here
CREATE EXTENSION IF NOT EXISTS hstore;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TYPE financial_protocol_type AS ENUM(
    'swap',
    'psm',
    'debt',
    'leverage'
);

CREATE TYPE protocol_implementation_type AS ENUM(
    'custom',
    'vm'
);

-- Enumeration of supported blockchains
CREATE TABLE IF NOT EXISTS "chain"(
    "id" bigserial PRIMARY KEY,
    -- The name of the blockchain
    "name" varchar(255) UNIQUE NOT NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- This table stores block at which relevant changes occured.
CREATE TABLE IF NOT EXISTS "block"(
    "id" bigserial PRIMARY KEY,
    -- The unique hash of this block.
    "hash" bytea UNIQUE NOT NULL,
    -- The ancestor hash of this block. Used to trace forked blocks.
    "parent_hash" bytea NOT NULL,
    -- Whether this block is part of the canonical chain.
    "main" bool NOT NULL DEFAULT TRUE,
    -- The block number, table might contain forks so the number is not
    --	necessarily unique - not even withing a single chains scope.
    "number" bigint NOT NULL,
    -- Timestamp this block was validated/mined/created.
    "ts" timestamptz NOT NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- The chain this block belongs to.
    "chain_id" bigint REFERENCES "chain"(id) NOT NULL,
    UNIQUE (chain_id, "hash")
);

CREATE INDEX IF NOT EXISTS idx_block_number_identity ON block("number", "chain_id");

CREATE INDEX IF NOT EXISTS idx_block_hash_identity ON block("hash", "chain_id");

CREATE TABLE IF NOT EXISTS "transaction"(
    "id" bigserial PRIMARY KEY,
    -- The unique hash of this transaction.
    "hash" bytea UNIQUE NOT NULL,
    -- sender of the transaction.
    "from" bytea NOT NULL,
    -- receiver of the transaction,
    "to" bytea NOT NULL,
    -- sequential index of the transaction in the block.
    "index" bigint NOT NULL,
    -- transactions are block scoped and thus also chain scoped.
    "block_id" bigint REFERENCES block(id) ON DELETE CASCADE NOT NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE ("index", block_id),
    UNIQUE ("hash", block_id)
);

CREATE INDEX IF NOT EXISTS idx_transaction_block_id ON TRANSACTION (block_id);

-- ProtocolSystem table group functional components (protocols) that
--	belong to the same logical system.
CREATE TABLE IF NOT EXISTS protocol_system(
    "id" bigserial PRIMARY KEY,
    -- The name of the procotol system, e.g. uniswap-v2, ambient, etc.
    "name" varchar(255) NOT NULL UNIQUE,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Table describing the different protocol types available in the system.
CREATE TABLE IF NOT EXISTS protocol_type(
    "id" bigserial PRIMARY KEY,
    -- The name of the type e.g. uniswap-v2:pool
    "name" varchar(255) NOT NULL UNIQUE,
    -- The actual type of the protocol.
    "financial_type" financial_protocol_type NOT NULL,
    -- The jsonschema to evaluate the attribute json for pools of this type.
    "attribute_schema" jsonb,
    -- What kind of implementation this protocol type uses.
    "implementation" protocol_implementation_type NOT NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Saves the state of an extractor, note that static extration parameters
-- 	are usually defined through infrastructure configuration tools e.g.
--	terraform. So this table only maintains dynamic state that changes during
--	runtime and has to be persisted between restarts.
CREATE TABLE IF NOT EXISTS extraction_state(
    "id" bigserial PRIMARY KEY,
    -- name of the extractor
    "name" varchar(255) NOT NULL,
    -- version of this extractor
    "version" varchar(255) NOT NULL,
    -- last fully extracted cursor for the corresponding substream
    "cursor" bytea NULL,
    -- Extractor instances are scoped to a specific chain.
    "chain_id" bigint REFERENCES "chain"(id) NOT NULL,
    -- additional attributes that the extractor needs to persist
    "attributes" jsonb,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- only allow a single extractor state instance per chain.
    UNIQUE (chain_id, "name")
);

-- Describes the static attributes of a protocol (component). A protocol is usually
--	a single component of a protocol system. E.g. uniswap-v2 is the system
--	that creates and operates swap components (aka pools).
CREATE TABLE IF NOT EXISTS protocol_component(
    "id" bigserial PRIMARY KEY,
    -- Protocols are scoped to a specific chain.
    "chain_id" bigint REFERENCES "chain"(id) NOT NULL,
    -- External id to identify protocol within a chain and system scope.
    --  We can't safely assume a protocol maps 1:1 to a contract address nor
    --	vice versa.
    "external_id" varchar(255) NOT NULL,
    -- All static attributes of the protocol, e.g. precision.
    "attributes" jsonb,
    -- The ts at which this protocol was created. Somewhat redundant as
    --	it could be inferred from related contracts but it might not be clear
    --	in case the protocol relates or more than one contract.
    "created_at" timestamptz NOT NULL,
    -- This is reference makes it easy to revert to a previous state by
    --	simply deleting the corresponding blocks. Once again somewhat
    --	redundant but makes bookkeeping much easier.
    "creation_tx" bigint REFERENCES "transaction"(id) ON DELETE CASCADE NOT NULL,
    -- The ts at which this protocol ceased to exist.
    "deleted_at" timestamptz,
    -- The transaction at which the protocol was destructed.
    "deletion_tx" bigint REFERENCES "transaction"(id) ON DELETE SET NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- The financial type of this protocol.
    "protocol_type_id" bigint REFERENCES protocol_type(id) NOT NULL,
    -- The system that this protocol belongs to e.g. uniswap-v2.
    "protocol_system_id" bigint REFERENCES protocol_system(id) NOT NULL,
    UNIQUE ("chain_id", "protocol_system_id", "external_id")
);

CREATE INDEX IF NOT EXISTS idx_protocol_identity ON protocol_component(external_id, protocol_system_id, chain_id);

-- Describes the mutable state of a component. Versioned by blocks.
CREATE TABLE IF NOT EXISTS protocol_state(
    "id" bigserial PRIMARY KEY,
    -- Remove balances here, cause we need to multiply the balance by
    -- price to calculate tvl. we can't really do this because the
    -- array does not contain the information about the token, directly.
    -- "balances" double precision[],
    -- Same for inertias, note that application side we view inertias and
    -- tvl as part of the state though.
    -- "inertias" double precision[],
    -- --------------------------------------------------
    -- The actual state of the protocols attributes. This is only relevant
    --	for fully implemented protocols. For protocols using vm simulation
    --	use the contract tables instead.
    "state" jsonb,
    -- the transaction that modified the state to this entry.
    "modify_tx" bigint REFERENCES "transaction"(id) ON DELETE CASCADE NOT NULL,
    -- The ts at which this state became valid at.
    "valid_from" timestamptz NOT NULL,
    -- The ts at which this state stopped being valid at. Null if this
    --	state is the currently valid entry.
    "valid_to" timestamptz,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Reference to static attributes of the protocol.
    "protocol_component_id" bigint REFERENCES protocol_component(id) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_protocol_state_tx ON protocol_state(modify_tx);

CREATE INDEX IF NOT EXISTS idx_protocol_state_valid_to ON protocol_state(valid_to);

CREATE INDEX IF NOT EXISTS idx_protocol_state_valid_protocol_component_id ON protocol_state(protocol_component_id);

-- Describes a single account.
CREATE TABLE IF NOT EXISTS "account"(
    "id" bigserial PRIMARY KEY,
    -- Accounts are scoped to a single chain.
    "chain_id" bigint REFERENCES "chain"(id) NOT NULL,
    -- Succinct title of this account e.g. "maker psm"
    "title" varchar(255) NOT NULL,
    -- The address of this account.
    "address" bytea NOT NULL,
    -- transaction that created this contract.
    "creation_tx" bigint REFERENCES TRANSACTION (id) ON DELETE CASCADE,
    -- The ts this contract was created. While inserting tokens
    --	we might not know who created it, so it is nullable.
    "created_at" timestamptz,
    -- The tx this contract was destroyed. Null in case it is active.
    "deleted_at" timestamptz,
    -- transaction that destructed this contract.
    "deletion_tx" bigint REFERENCES "transaction"(id) ON DELETE SET NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- The address is required to be unique per chain.
    UNIQUE ("chain_id", "address")
);

CREATE INDEX IF NOT EXISTS idx_account_chain_id ON account(chain_id);

-- Describes tokens e.g. ERC20 on evm chains.
CREATE TABLE IF NOT EXISTS "token"(
    "id" bigserial PRIMARY KEY,
    -- The account that implements this token.
    "account_id" bigint REFERENCES account(id) ON DELETE CASCADE NOT NULL,
    -- The symbol/ticker for this token.
    "symbol" varchar(255) NOT NULL,
    -- Decimal precision the token stores balances with.
    "decimals" int NOT NULL,
    -- Normal tokens have a quality of 0.
    "quality" int NOT NULL DEFAULT 0,
    -- Chain specific token attributes
    "attributes" jsonb,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_token_symbol ON "token" USING gin("symbol" gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_token_account_id ON token(account_id);

-- M2M relationship between tokens and protocol
CREATE TABLE IF NOT EXISTS protocol_holds_token(
    "protocol_component_id" bigint REFERENCES protocol_component(id) ON DELETE CASCADE NOT NULL,
    -- we don't allow a token to be deleted unless the protocol component was removed
    "token_id" bigint REFERENCES "token"(id) NOT NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY ("protocol_component_id", "token_id")
);

-- TODO: add a trigger similar to contract storage for this table
CREATE TABLE IF NOT EXISTS protocol_tvl(
    "protocol_component_id" bigint REFERENCES protocol_component(id) ON DELETE CASCADE NOT NULL,
    -- we don't allow a token to be deleted unless the protocol component was removed
    "token_id" bigint REFERENCES "token"(id) NOT NULL,
    -- previous balance
    "previous_balance" double precision NOT NULL,
    -- current balance
    "balance" double precision NOT NULL,
    -- The ts at which this state became valid at.
    "valid_from" timestamptz NOT NULL,
    -- The ts at which this state stopped being valid at. Null if this
    --	state is the currently valid entry.
    "valid_to" timestamptz,
    -- transaction that produced this new value
    "modify_tx" bigint REFERENCES "transaction"(id) ON DELETE CASCADE NOT NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- not sure if this pk is great, consider introducing a increasing one
    --  the triplet below should be unique though
    PRIMARY KEY ("protocol_component_id", "token_id", "valid_to")
);

CREATE TABLE IF NOT EXISTS token_prices(
    -- we don't allow a token to be deleted unless the protocol component was removed
    "token_id" bigint REFERENCES "token"(id) NOT NULL,
    "price" double precision NOT NULL,
);
-- Versioned account balance.
CREATE TABLE account_balance(
    "id" bigserial PRIMARY KEY,
    -- The balance of the account.
    "balance" bytea NOT NULL,
    -- the account this entry refers to.
    "account_id" bigint REFERENCES account(id) ON DELETE CASCADE NOT NULL,
    -- the transaction that modified the state to this entry.
    "modify_tx" bigint REFERENCES "transaction"(id) ON DELETE CASCADE NOT NULL,
    -- The ts at which this state became valid at.
    "valid_from" timestamptz NOT NULL,
    -- The ts at which this state stopped being valid at. Null if this
    --	state is the currently valid entry.
    "valid_to" timestamptz NOT NULL,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE ("account_id", "modify_tx")
);

CREATE INDEX IF NOT EXISTS idx_account_balance_account_id ON account_balance(account_id);

CREATE INDEX IF NOT EXISTS idx_account_balance_valid_to ON account_balance(valid_to);

-- Versioned contract code.
CREATE TABLE contract_code(
    "id" bigserial PRIMARY KEY,
    -- The code of this contract optimised for the system using it, e.g. revm.
    "code" bytea NOT NULL,
    -- The hash of the code, allows to easily detect changes.
    "hash" bytea NOT NULL,
    -- the contract this entry refers to.
    "account_id" bigint REFERENCES account(id) ON DELETE CASCADE NOT NULL,
    -- the transaction that modified the code to this entry.
    "modify_tx" bigint REFERENCES "transaction"(id) ON DELETE CASCADE NOT NULL,
    -- The ts at which this copde became valid at.
    "valid_from" timestamptz NOT NULL,
    -- The ts at which this code stopped being valid at. Null if this
    --	state is the currently valid entry.
    "valid_to" timestamptz,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE ("account_id", "modify_tx")
);

CREATE INDEX IF NOT EXISTS idx_contract_code_account_id ON contract_code(account_id);

CREATE INDEX IF NOT EXISTS idx_contract_code_valid_to ON contract_code(valid_to);

-- Versioned contract storage.
CREATE TABLE IF NOT EXISTS contract_storage(
    "id" bigserial PRIMARY KEY,
    -- the preimage/slot for this entry.
    "slot" bytea NOT NULL,
    -- the value of the storage slot at this verion.
    "value" bytea,
    -- the previous versions value, null if first insertion.
    "previous_value" bytea,
    -- the contract this entry refers to.
    "account_id" bigint REFERENCES account(id) ON DELETE CASCADE NOT NULL,
    -- the transaction that modified the slot to this entry.
    "modify_tx" bigint REFERENCES "transaction"(id) ON DELETE CASCADE NOT NULL,
    -- this is redundant with transaction.index, but included
    --	for performance reasons. Orders entries that are valid
    --	within the same version.
    "ordinal" bigint NOT NULL,
    -- The ts at which this slot became valid at.
    "valid_from" timestamptz NOT NULL,
    -- The ts at which this slot stopped being valid at. Null if this
    --	state is the currently valid entry.
    "valid_to" timestamptz,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_contract_storage_account_id ON contract_storage(account_id);

CREATE INDEX IF NOT EXISTS idx_contract_storage_account_id ON contract_storage(account_id, slot);

CREATE INDEX IF NOT EXISTS idx_contract_storage_valid_to ON contract_storage(modify_tx);

CREATE INDEX IF NOT EXISTS idx_contract_storage_valid_to ON contract_storage(valid_from);

CREATE INDEX IF NOT EXISTS idx_contract_storage_valid_to ON contract_storage(valid_to);

-- Relationship between protocols and contract(s).
CREATE TABLE IF NOT EXISTS protocol_calls_contract(
    "id" bigserial PRIMARY KEY,
    "protocol_component_id" bigint REFERENCES protocol_component(id) ON DELETE CASCADE NOT NULL,
    "account_id" bigint REFERENCES account(id) ON DELETE CASCADE NOT NULL,
    -- Tx this assocuation became valud, versioned association between contracts,
    -- allows to track updates of e.g. price feeds.
    "valid_from" timestamptz NOT NULL,
    -- The tx at which this association stopped being valid. Null if this
    --	state is the currently valid entry.
    "valid_to" timestamptz,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE ("protocol_component_id", "account_id", "valid_from"),
    UNIQUE ("protocol_component_id", "account_id", "valid_to")
);

CREATE INDEX IF NOT EXISTS idx_protocol_calls_contract_protocol_component_id ON protocol_calls_contract(protocol_component_id);

CREATE INDEX IF NOT EXISTS idx_protocol_calls_contract_account_id ON protocol_calls_contract(account_id);

CREATE INDEX IF NOT EXISTS idx_protocol_calls_contract_valid_to ON protocol_calls_contract(valid_to);

-- keeps track of what we did.
CREATE TABLE IF NOT EXISTS audit_log(
    "id" bigserial PRIMARY KEY,
    operation char(1) NOT NULL,
    ts timestamptz NOT NULL,
    userid text NOT NULL,
    original_data hstore,
    new_data hstore
);


/*
 * TRIGGERS
 * 
 * Below follows trigger logic for all versioned tables. The trigger will automatically 
 * identify the previous version of an entry, set the valid_to field to the 
 * valid_from of the new version.
 */
CREATE OR REPLACE FUNCTION invalidate_previous_entry_protocol_state()
    RETURNS TRIGGER
    AS $$
BEGIN
    -- Update the 'valid_to' field of the last valid entry when a new one is inserted.
    UPDATE
        protocol_state
    SET
        valid_to = NEW.valid_from
    WHERE
        valid_to IS NULL
        AND protocol_component_id = NEW.protocol_component_id;
    RETURN NEW;
END;
$$
LANGUAGE plpgsql;

CREATE TRIGGER invalidate_previous_protocol_state
    BEFORE INSERT ON protocol_state
    FOR EACH ROW
    EXECUTE PROCEDURE invalidate_previous_entry_protocol_state();

CREATE OR REPLACE FUNCTION invalidate_previous_entry_account_balance()
    RETURNS TRIGGER
    AS $$
BEGIN
    -- Update the 'valid_to' field of the last valid entry when a new one is inserted.
    UPDATE
        account_balance
    SET
        valid_to = NEW.valid_from
    WHERE
        valid_to IS NULL
        AND account_id = NEW.account_id
        -- running this after inserts allows us to use upserts,
        -- currently the application does not use that though
        AND id != NEW.id;
    RETURN NEW;
END;
$$
LANGUAGE plpgsql;

CREATE TRIGGER invalidate_previous_account_balance
    AFTER INSERT ON account_balance
    FOR EACH ROW
    EXECUTE PROCEDURE invalidate_previous_entry_account_balance();

CREATE OR REPLACE FUNCTION invalidate_previous_entry_contract_code()
    RETURNS TRIGGER
    AS $$
BEGIN
    -- Update the 'valid_to' field of the last valid entry when a new one is inserted.
    UPDATE
        contract_code
    SET
        valid_to = NEW.valid_from
    WHERE
        valid_to IS NULL
        AND account_id = NEW.account_id
        -- running this after inserts allows us to use upserts,
        -- currently the application does not use that though
        AND id != NEW.id;
    RETURN NEW;
END;
$$
LANGUAGE plpgsql;

CREATE TRIGGER invalidate_previous_contract_code
    AFTER INSERT ON contract_code
    FOR EACH ROW
    EXECUTE PROCEDURE invalidate_previous_entry_contract_code();

CREATE OR REPLACE FUNCTION invalidate_previous_entry_contract_storage()
    RETURNS TRIGGER
    AS $$
BEGIN
    -- Update the 'valid_to' field of the last valid entry when a new one is inserted.
    UPDATE
        contract_storage
    SET
        valid_to = NEW.valid_from
    WHERE
        valid_to IS NULL
        AND account_id = NEW.account_id
        AND slot = NEW.slot;
    NEW.previous_value =(
        SELECT
            value
        FROM
            contract_storage
        WHERE
            account_id = NEW.account_id
            AND slot = NEW.slot
        LIMIT 1);
    RETURN NEW;
END;
$$
LANGUAGE plpgsql;

CREATE TRIGGER invalidate_previous_contract_storage
    BEFORE INSERT ON contract_storage
    FOR EACH ROW
    EXECUTE PROCEDURE invalidate_previous_entry_contract_storage();

CREATE OR REPLACE FUNCTION invalidate_previous_entry_protocol_calls_contract()
    RETURNS TRIGGER
    AS $$
BEGIN
    -- Update the 'valid_to' field of the last valid entry when a new one is inserted.
    UPDATE
        protocol_calls_contract
    SET
        valid_to = NEW.valid_from
    WHERE
        valid_to IS NULL
        AND protocol_component_id = NEW.protocol_component_id
        AND account_id = NEW.account_id;
    RETURN NEW;
END;
$$
LANGUAGE plpgsql;

-- Bind the function to 'protocol_state' table, to be called on each row insert event.
CREATE TRIGGER invalidate_previous_entry_protocol_calls_contract
    BEFORE INSERT ON protocol_calls_contract
    FOR EACH ROW
    EXECUTE PROCEDURE invalidate_previous_entry_protocol_calls_contract();

-- trigger to handle modified_ts columns
CREATE OR REPLACE FUNCTION update_modified_column()
    RETURNS TRIGGER
    AS $$
BEGIN
    NEW.modified_ts = now();
    RETURN NEW;
END;
$$
LANGUAGE 'plpgsql';

CREATE TRIGGER update_modtime_chain
    BEFORE UPDATE ON "chain"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_block
    BEFORE UPDATE ON "block"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_transaction
    BEFORE UPDATE ON "transaction"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_protocol_system
    BEFORE UPDATE ON "protocol_system"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_protocol_type
    BEFORE UPDATE ON "protocol_type"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_protocol_state
    BEFORE UPDATE ON "protocol_state"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_protocol_component
    BEFORE UPDATE ON "protocol_component"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_account
    BEFORE UPDATE ON "account"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_token
    BEFORE UPDATE ON "token"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_protocol_holds_token
    BEFORE UPDATE ON "protocol_holds_token"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_contract_storage
    BEFORE UPDATE ON "contract_storage"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_account_balance
    BEFORE UPDATE ON "account_balance"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_contract_code
    BEFORE UPDATE ON "contract_code"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_protocol_calls_contract
    BEFORE UPDATE ON "protocol_calls_contract"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER update_modtime_extraction_state
    BEFORE UPDATE ON "extraction_state"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

-- audit trigger keeps a log of modifications
CREATE OR REPLACE FUNCTION audit_trigger()
    RETURNS TRIGGER
    AS $audit_trigger$
BEGIN
    IF(TG_OP = 'DELETE') THEN
        INSERT INTO audit_log(operation, ts, userid, original_data)
        SELECT
            'D',
            now(),
            USER,
            hstore(OLD.*);
        RETURN OLD;
    ELSIF(TG_OP = 'UPDATE') THEN
        INSERT INTO audit_log(operation, ts, userid, original_data, new_data)
        SELECT
            'U',
            now(),
            USER,
            hstore(OLD.*),
            hstore(NEW.*);
        RETURN NEW;
    ELSIF(TG_OP = 'INSERT') THEN
        INSERT INTO audit_log(operation, ts, userid, new_data)
        SELECT
            'I',
            now(),
            USER,
            hstore(NEW.*);
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$audit_trigger$
LANGUAGE plpgsql;

CREATE TRIGGER audit_table_chain
    BEFORE UPDATE ON "chain"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_block
    BEFORE UPDATE ON "block"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_transaction
    BEFORE UPDATE ON "transaction"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_protocol_system
    BEFORE UPDATE ON "protocol_system"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_protocol_type
    BEFORE UPDATE ON "protocol_type"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_protocol_state
    BEFORE UPDATE ON "protocol_state"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_protocol_component
    BEFORE UPDATE ON "protocol_component"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_account
    BEFORE UPDATE ON "account"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_token
    BEFORE UPDATE ON "token"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_protocol_holds_token
    BEFORE UPDATE ON "protocol_holds_token"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_contract_storage
    BEFORE UPDATE ON "contract_storage"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_account_balance
    BEFORE UPDATE ON "account_balance"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_contract_code
    BEFORE UPDATE ON "contract_code"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_protocol_calls_contract
    BEFORE UPDATE ON "protocol_calls_contract"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

CREATE TRIGGER audit_table_extraction_state
    BEFORE UPDATE ON "extraction_state"
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

