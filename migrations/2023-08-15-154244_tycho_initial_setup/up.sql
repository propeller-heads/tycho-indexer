-- Your SQL goes here
CREATE EXTENSION IF NOT EXISTS hstore;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE TYPE financial_protocol_type AS ENUM ('swap', 'psm', 'debt', 'leverage');
CREATE TYPE protocol_implementation_type AS ENUM ('custom', 'vm');

-- Enumeration of supported blockchains
create table if not exists "chain" (
	"id" BIGSERIAL PRIMARY KEY,
	
	-- The name of the blockchain
	"name" varchar(255) unique not null,
	
	-- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp
);

-- This table stores block at which relevant changes occured.
create table if not exists "block" (
	"id" BIGSERIAL PRIMARY KEY,
	
	-- The unique hash of this block.
	"hash" bytea unique not null,
	
	-- The ancestor hash of this block. Used to trace forked blocks.
	"parent_hash" bytea not null,
	
	-- Whether this block is part of the canonical chain.
	"main" bool not null default true,
	
	-- The block number, table might contain forks so the number is not 
	--	necessarily unique - not even withing a single chains scope.
	"number" bigint not null,
	
	-- Timestamp this block was validated/mined/created.
	"ts" timestamptz not null,
	
	-- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp,
	
	-- The chain this block belongs to.
	"chain_id" bigint references "chain"(id) not null,
	
	unique(chain_id, "hash")
);

create index if not exists idx_block_number_identity on block("number", "chain_id");
create index if not exists idx_block_hash_identity on block("hash", "chain_id");


create table if not exists "transaction" (
	"id" BIGSERIAL PRIMARY KEY,
	
	-- The unique hash of this transaction.
	"hash" bytea unique not null,
	
	-- sender of the transaction.
	"from" bytea not null,
	
	-- receiver of the transaction,
	"to" bytea not null,
	
	-- sequential index of the transaction in the block.
	"index" bigint not null,
		
	-- transactions are block scoped and thus also chain scoped.
	"block_id" bigint references block(id) on delete cascade not null,
	
	-- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp,
	
	unique("index", block_id),
	unique("hash", block_id)
);

create index if not exists idx_transaction_block_id on transaction(block_id);


-- ProtocolSystem table group functional components (protocols) that 
--	belong to the same logical system.
create table if not exists protocol_system (
	"id" BIGSERIAL PRIMARY KEY,
	
	-- The name of the procotol system, e.g. uniswap-v2, ambient, etc.
	"name" VARCHAR(255) not null,
	
	-- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp
);

-- Table describing the different protocol types available in the system.
CREATE TABLE if not exists protocol_type (
    "id" BIGSERIAL PRIMARY KEY,
    
    -- The name of the type e.g. uniswap-v2:pool
    "name" VARCHAR(255) not null,
    
    -- The actual type of the protocol.
    "financial_type" financial_protocol_type not null,
    
    -- The jsonschema to evaluate the attribute json for pools of this type.
    "attribute_schema" JSONB,
    
    -- What kind of implementation this protocol type uses.
    "implementation" protocol_implementation_type not null,
    
    -- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp
);


-- Saves the state of an extractor, note that static extration parameters 
-- 	are usually defined through infrastructure configuration tools e.g. 
--	terraform. So this table only maintains dynamic state that changes during
--	runtime and has to be persisted between restarts.
CREATE TABLE if not exists extraction_state (
	"id" BIGSERIAL PRIMARY KEY,
	-- name of the extractor
	"name" varchar(255) not null,

	-- version of this extractor
	"version" varchar(255) not null,

	-- last fully extracted cursor for the corresponding substream
	"cursor" bytea null,

	-- Extractor instances are scoped to a specific chain.
    "chain_id" bigint references "chain"(id) not null,

	-- additional attributes that the extractor needs to persist
	"attributes" jsonb,

	-- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,

	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp,

	-- only allow a single extractor state instance per chain.
	unique(chain_id, "name")
);

-- Describes the static attributes of a protocol (component). A protocol is usually
--	a single component of a protocol system. E.g. uniswap-v2 is the system
--	that creates and operates swap components (aka pools).
create table if not exists protocol_component (
    "id" BIGSERIAL PRIMARY KEY,
    
    -- Protocols are scoped to a specific chain.
    "chain_id" bigint references "chain"(id) not null,
    
    -- External id to identify protocol within a chain and system scope. 
    --  We can't safely assume a protocol maps 1:1 to a contract address nor 
    --	vice versa.
    "external_id" VARCHAR(255) not null,
    
    -- All static attributes of the protocol, e.g. precision.
    "attributes" JSONB,
    
    -- The ts at which this protocol was created. Somewhat redundant as
    --	it could be inferred from related contracts but it might not be clear
    --	in case the protocol relates or more than one contract.
    "created_at" timestamptz not null,

	-- This is reference makes it easy to revert to a previous state by 
	--	simply deleting the corresponding blocks. Once again somewhat 
	--	redundant but makes bookkeeping much easier.
	"creation_tx" bigint references "transaction"(id) on delete cascade not null,
    
    -- The ts at which this protocol ceased to exist.
    "deleted_at" timestamptz,
    
    -- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp,
    
    -- The financial type of this protocol.
    "protocol_type_id" BIGINT REFERENCES protocol_type(id) not null,
    
    -- The system that this protocol belongs to e.g. uniswap-v2.
    "protocol_system_id" BIGINT REFERENCES protocol_system(id) not null,
    
    unique("chain_id", "protocol_system_id", "external_id")
);

create index if not exists idx_protocol_identity on protocol_component(external_id, protocol_system_id, chain_id);

-- Describes the mutable state of a component. Versioned by blocks.
create table if not exists protocol_state (
	"id" BIGSERIAL PRIMARY KEY,
	
	-- The total value locked within the protocol. Might not always apply.
	"tvl" bigint,
	
	-- the inertias per token of the protocol (in increasing order sorted 
	--	by token contract address). Might not always apply. 
	"inertias" bigint[],
	
	-- The actual state of the protocols attributes. This is only relevant 
	--	for fully implemented protocols. For protocols using vm simulation 
	--	use the contract tables instead. 
	"state" JSONB,
		
	-- the transaction that modified the state to this entry.
	"modify_tx" bigint references "transaction"(id) on delete cascade not null,
	
	-- The ts at which this state became valid at.
	"valid_from" timestamptz not null,
	
	-- The ts at which this state stopped being valid at. Null if this 
	--	state is the currently valid entry.
    "valid_to" timestamptz,
    
    -- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp,
    
    -- Reference to static attributes of the protocol.
    "protocol_component_id" BIGINT REFERENCES protocol_component(id) not null
    
);

create index if not exists idx_protocol_state_tx on protocol_state(modify_tx);
create index if not exists idx_protocol_state_valid_to on protocol_state(valid_to);
create index if not exists idx_protocol_state_valid_protocol_component_id on protocol_state(protocol_component_id);


-- Describes a single account.
create table if not exists "account" (
    "id" BIGSERIAL PRIMARY KEY,
    
    -- Accounts are scoped to a single chain.
    "chain_id" bigint references "chain"(id) not null,
    
    -- Succinct title of this account e.g. "maker psm"
    "title" varchar(255) not null,
    
    -- The address of this account.
	"address" bytea not null,
	
	-- transaction that created this contract.
	"creation_tx" bigint references transaction(id) on delete cascade,
	
	-- The ts this contract was created. While inserting tokens 
	--	we might not know who created it, so it is nullable.
	"created_at" timestamptz,
	
	-- The tx this contract was destroyed. Null in case it is active.
    "deleted_at" timestamptz,
    
    -- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp,
    
    -- The address is required to be unique per chain.
    UNIQUE ("chain_id", "address")
);

create index if not exists idx_account_chain_id on account(chain_id);

-- Describes tokens e.g. ERC20 on evm chains.
create table if not exists "token" (
	"id" BIGSERIAL PRIMARY KEY,
	
	-- The account that implements this token.
	"account_id" bigint references account(id) on delete cascade not null,
	
	-- The symbol/ticker for this token.
	"symbol" VARCHAR(255) not null,
	
	-- Decimal precision the token stores balances with.
	"decimals" int not null,
	
	-- The tax this token charges on transfer.
	"tax" bigint not null default 0,
	
	-- The estimated amount of gas used per transfer.
	"gas" bigint[] not null,
	
	-- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp
);

CREATE INDEX if not exists idx_token_symbol ON "token" USING gin("symbol" gin_trgm_ops);
CREATE INDEX if not exists idx_token_account_id ON token(account_id);


-- M2M relationship between tokens and protocol 
CREATE TABLE if not exists protocol_holds_token (
    "protocol_component_id" BIGINT REFERENCES protocol_component(id) on delete cascade not null,
	
	-- we don't allow a token to be deleted unless the protocol component was removed
    "token_id" BIGINT REFERENCES "token"(id) not null,
    
	-- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp,
	
    PRIMARY KEY("protocol_component_id", "token_id")
);

-- Versioned account balance.
create table account_balance(
	"id" BIGSERIAL PRIMARY KEY,
	
	-- The balance of the account.
	"balance" bytea not null,
	
	-- the account this entry refers to.
	"account_id" bigint references account(id) on delete cascade not null,
	
	-- the transaction that modified the state to this entry.
	"modify_tx" bigint references "transaction"(id) on delete cascade,
	
	-- The ts at which this state became valid at.
	"valid_from" timestamptz not null,
	
	-- The ts at which this state stopped being valid at. Null if this 
	--	state is the currently valid entry.
    "valid_to" timestamptz,
    
    -- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp
);

CREATE INDEX if not exists idx_account_balance_account_id ON account_balance (account_id);
CREATE INDEX if not exists idx_account_balance_valid_to ON account_balance (valid_to);

-- Versioned contract code.
create table contract_code(
	"id" BIGSERIAL PRIMARY KEY,
	
	-- The code of this contract optimised for the system using it, e.g. revm.
	"code" bytea not null,
	
	-- The hash of the code, allows to easily detect changes.
	"hash" bytea not null,
	
	-- the contract this entry refers to.
	"account_id" bigint references account(id) on delete cascade not null,
	
	-- the transaction that modified the code to this entry.
	"modify_tx" bigint references "transaction"(id) on delete cascade not null,
	
	-- The ts at which this copde became valid at.
	"valid_from" timestamptz not null,
	
	-- The ts at which this code stopped being valid at. Null if this 
	--	state is the currently valid entry.
    "valid_to" timestamptz,
    
    -- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp
);

CREATE INDEX if not exists idx_contract_code_account_id ON contract_code (account_id);
CREATE INDEX if not exists idx_contract_code_valid_to ON contract_code (valid_to);

-- Versioned contract storage.
create table if not exists contract_storage (
	"id" BIGSERIAL PRIMARY KEY,
	
	-- the preimage/slot for this entry. 
	"slot" bytea not null,

	-- the value of the storage slot at this verion.
	"value" bytea,

	-- the previous versions value, null if first insertion.
	"previous_value" bytea,
	
	-- the contract this entry refers to.
	"account_id" bigint references account(id) on delete cascade not null,
	
	-- the transaction that modified the slot to this entry.
	"modify_tx" bigint references "transaction"(id) on delete cascade not null,

	-- this is redundant with transaction.index, but included 
	--	for performance reasons. Orders entries that are valid 
	--	within the same version.
	"ordinal" bigint not null,
	
	-- The ts at which this slot became valid at.
	"valid_from" timestamptz not null,
	
	-- The ts at which this slot stopped being valid at. Null if this 
	--	state is the currently valid entry.
    "valid_to" timestamptz,
    
    -- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp
);

CREATE INDEX if not exists idx_contract_storage_account_id ON contract_storage (account_id);
CREATE INDEX if not exists idx_contract_storage_account_id ON contract_storage (account_id, slot);
CREATE INDEX if not exists idx_contract_storage_valid_to ON contract_storage (modify_tx);
CREATE INDEX if not exists idx_contract_storage_valid_to ON contract_storage (valid_from);
CREATE INDEX if not exists idx_contract_storage_valid_to ON contract_storage (valid_to);

-- Relationship between protocols and contract(s).
CREATE TABLE if not exists protocol_calls_contract (
	"id" BIGSERIAL PRIMARY KEY,

    "protocol_component_id" BIGINT REFERENCES protocol_component(id) on delete cascade not null,
    
    "account_id" BIGINT REFERENCES account(id) on delete cascade not null,
    
    -- Tx this assocuation became valud, versioned association between contracts, 
    -- allows to track updates of e.g. price feeds. 
	"valid_from" timestamptz not null,
	
	-- The tx at which this association stopped being valid. Null if this 
	--	state is the currently valid entry.
    "valid_to" timestamptz,
    
    -- Timestamp this entry was inserted into this table.
	"inserted_ts" timestamptz not null default current_timestamp,
	
	-- Timestamp this entry was inserted into this table.
	"modified_ts" timestamptz not null default current_timestamp,
    
    UNIQUE("protocol_component_id", "account_id", "valid_from"),
    UNIQUE("protocol_component_id", "account_id", "valid_to")
);

CREATE INDEX if not exists idx_protocol_calls_contract_protocol_component_id ON protocol_calls_contract(protocol_component_id);
CREATE INDEX if not exists idx_protocol_calls_contract_account_id ON protocol_calls_contract(account_id);
CREATE INDEX if not exists idx_protocol_calls_contract_valid_to ON protocol_calls_contract(valid_to);

-- keeps track of what we did.
CREATE TABLE if not exists audit_log (
    "id" BIGSERIAL PRIMARY KEY,
    operation         CHAR(1)   	NOT NULL,
    ts             	  TIMESTAMPTZ 	NOT NULL,
    userid            TEXT      	NOT NULL,
    original_data     hstore,
    new_data          hstore
);

/*
 * TRIGGERS
 * 
 * Below follows trigger logic for all versioned tables. The trigger will automatically 
 * identify the previous version of an entry, set the valid_to field to the 
 * valid_from of the new version.
 */


-- invalidate previous entry automatically through an identity column
CREATE OR REPLACE FUNCTION invalidate_previous_entry() 
RETURNS TRIGGER AS $$

DECLARE
    _tbl_name text;
    _identity_col text;
    _query text;

BEGIN
    IF TG_NARGS <> 2 THEN
        RAISE EXCEPTION 'This trigger requires exactly two parameters: table name and identity column';
    END IF;
    
    _tbl_name := TG_ARGV[0];
    _identity_col := TG_ARGV[1];

    _query := format('
       UPDATE %I 
       SET valid_to = $1.valid_from 
       WHERE id = (
           SELECT id FROM %I 
           WHERE valid_to IS NULL AND %I = ($1).%I 
       );', _tbl_name, _tbl_name, _identity_col, _identity_col);

    EXECUTE _query USING NEW;

    RETURN NEW;

END;
$$ LANGUAGE plpgsql;


CREATE TRIGGER invalidate_previous_protocol_state
BEFORE INSERT ON protocol_state 
FOR EACH ROW EXECUTE PROCEDURE invalidate_previous_entry('protocol_state', 'protocol_component_id');

CREATE TRIGGER invalidate_previous_account_balance
BEFORE INSERT ON account_balance 
FOR EACH ROW EXECUTE PROCEDURE invalidate_previous_entry('account_balance', 'account_id');

CREATE TRIGGER invalidate_previous_contract_code
BEFORE INSERT ON contract_code
FOR EACH ROW EXECUTE PROCEDURE invalidate_previous_entry('contract_code', 'account_id');


CREATE OR REPLACE FUNCTION invalidate_previous_entry_contract_storage() RETURNS TRIGGER AS $$
BEGIN
-- Update the 'valid_to' field of the last valid entry when a new one is inserted.
    UPDATE contract_storage 
    SET valid_to = NEW.valid_from 
    WHERE valid_to IS NULL AND account_id = NEW.account_id and slot = NEW.slot;
	NEW.previous_value = (SELECT value FROM contract_storage WHERE account_id = NEW.account_id and slot = NEW.slot LIMIT 1);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


CREATE TRIGGER invalidate_previous_contract_storage
BEFORE INSERT ON contract_storage
FOR EACH ROW EXECUTE PROCEDURE invalidate_previous_entry_contract_storage();


CREATE OR REPLACE FUNCTION invalidate_previous_entry_protocol_calls_contract() RETURNS TRIGGER AS $$
BEGIN
-- Update the 'valid_to' field of the last valid entry when a new one is inserted.
    UPDATE protocol_calls_contract 
    SET valid_to = NEW.valid_from 
    WHERE valid_to IS NULL AND protocol_component_id = NEW.protocol_component_id and account_id = NEW.account_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Bind the function to 'protocol_state' table, to be called on each row insert event.
CREATE TRIGGER invalidate_previous_entry_protocol_calls_contract
BEFORE INSERT ON protocol_calls_contract 
FOR EACH ROW EXECUTE PROCEDURE invalidate_previous_entry_protocol_calls_contract();

-- trigger to handle modified_ts columns
CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.modified_ts = now();
   RETURN NEW; 
END;
$$ language 'plpgsql';


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
CREATE OR REPLACE FUNCTION audit_trigger() RETURNS TRIGGER AS $audit_trigger$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        INSERT INTO audit_log(operation, ts, userid, original_data) SELECT 'D', now(), user, hstore(OLD.*);
        RETURN OLD;
    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO audit_log(operation, ts, userid, original_data, new_data) SELECT 'U', now(), user, hstore(OLD.*), hstore(NEW.*);
        RETURN NEW;
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO audit_log(operation, ts, userid, new_data) SELECT 'I', now(), user, hstore(NEW.*);
        RETURN NEW;
    END IF;
RETURN NULL;
END;
$audit_trigger$ LANGUAGE plpgsql;


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