-- https://github.com/pgpartman/pg_partman/blob/master/doc/pg_partman.md
CREATE SCHEMA partman;

CREATE EXTENSION pg_partman WITH SCHEMA partman;

-- remove audit table to speed up inserts
DROP TABLE IF EXISTS audit_log;

DROP TRIGGER IF EXISTS audit_table_account ON account;

DROP TRIGGER IF EXISTS audit_table_account_balance ON account_balance;

DROP TRIGGER IF EXISTS audit_table_block ON block;

DROP TRIGGER IF EXISTS audit_table_chain ON chain;

DROP TRIGGER IF EXISTS audit_table_component_balance ON component_balance;

DROP TRIGGER IF EXISTS audit_table_component_tvl ON component_tvl;

DROP TRIGGER IF EXISTS audit_table_contract_code ON contract_code;

DROP TRIGGER IF EXISTS audit_table_contract_storage ON contract_storage;

DROP TRIGGER IF EXISTS audit_table_extraction_state ON extraction_state;

DROP TRIGGER IF EXISTS audit_table_protocol_calls_contract ON protocol_calls_contract;

DROP TRIGGER IF EXISTS audit_table_protocol_component_holds_contract ON
    protocol_component_holds_contract;

DROP TRIGGER IF EXISTS audit_table_protocol_component_holds_token ON
    protocol_component_holds_token;

DROP TRIGGER IF EXISTS audit_table_protocol_state ON protocol_state;

DROP TRIGGER IF EXISTS audit_table_protocol_system ON protocol_system;

DROP TRIGGER IF EXISTS audit_table_protocol_type ON protocol_type;

DROP TRIGGER IF EXISTS audit_table_token ON token;

DROP TRIGGER IF EXISTS audit_table_token_price ON token_price;

DROP TRIGGER IF EXISTS audit_table_transaction ON TRANSACTION;

DROP TRIGGER IF EXISTS audit_table_protocol_component ON protocol_component;

DROP TRIGGER IF EXISTS invalidate_previous_entry_protocol_calls_contract ON
    protocol_calls_contract;

-- PROTOCOL STATE
ALTER TABLE protocol_state RENAME TO protocol_state_old;

UPDATE
    protocol_state_old
SET
    valid_to = '262142-12-31T23:59:59.9999Z'
WHERE
    valid_to IS NULL;

ALTER TABLE protocol_state_old
    ALTER COLUMN valid_to SET NOT NULL;

ALTER INDEX idx_protocol_state_component_id_attribute_name_valid_to RENAME TO
    idx_protocol_state_component_id_attribute_name_valid_to_old;

ALTER INDEX idx_protocol_state_valid_protocol_component_id RENAME TO
    idx_protocol_state_valid_protocol_component_id_old;

ALTER INDEX idx_protocol_state_valid_to RENAME TO idx_protocol_state_valid_to_old;

CREATE TABLE protocol_state(
    attribute_name varchar NOT NULL,
    attribute_value bytea NOT NULL,
    previous_value bytea NULL,
    modify_tx int8 NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_to timestamptz NOT NULL,
    inserted_ts timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified_ts timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    protocol_component_id int8 NOT NULL
)
PARTITION BY RANGE (valid_to);

CREATE INDEX idx_protocol_state_component_id_attribute_name_valid_to ON
    public.protocol_state USING btree(protocol_component_id, attribute_name, valid_to);

CREATE INDEX idx_protocol_state_valid_protocol_component_id ON public.protocol_state
    USING btree(protocol_component_id);

CREATE INDEX idx_protocol_state_valid_to ON public.protocol_state USING btree(valid_to);

ALTER TABLE public.protocol_state
    ADD CONSTRAINT protocol_state_modify_tx_fkey FOREIGN KEY (modify_tx) REFERENCES
	"transaction"(id) ON DELETE CASCADE;

ALTER TABLE public.protocol_state
    ADD CONSTRAINT protocol_state_protocol_component_id_fkey FOREIGN KEY
	(protocol_component_id) REFERENCES protocol_component(id);

SELECT
    partman.create_parent(p_parent_table := 'public.protocol_state', p_control := 'valid_to',
	p_interval := '1 day', p_type := 'range', p_premake := 7,
	p_default_table := TRUE, p_automatic_maintenance := 'on');

-- Move latest values directly into the parent table - they should end up in default
-- without this statement we would create a 262142 partition when moving data with
-- `partition_data_proc` later.
WITH latest_protocol_state AS (
    DELETE FROM protocol_state_old
    WHERE valid_to = '262142-12-31T23:59:59.9999Z'
    RETURNING
        *)
INSERT INTO protocol_state
SELECT
    attribute_name,
    attribute_value,
    previous_value,
    modify_tx,
    valid_from,
    valid_to,
    inserted_ts,
    modified_ts,
    protocol_component_id
FROM
    latest_protocol_state;

--- Create historical partitions, maybe this should not be done as part of the migration since it is quite slow....
--- Unfortunately columns need to match to can't keep id column in old table to migrate data...
ALTER TABLE protocol_state_old
    DROP COLUMN id;

-- this constraint allows us to to upserts into this table.
ALTER TABLE protocol_state_default
    ADD CONSTRAINT protocol_state_default_unique_pk UNIQUE (protocol_component_id, attribute_name);

-- CONTRACT STATE
ALTER TABLE contract_storage RENAME TO contract_storage_old;

ALTER INDEX idx_contract_storage_account_id RENAME TO idx_contract_storage_account_id_old;

ALTER INDEX idx_contract_storage_account_id_slot_valid_to RENAME TO
    idx_contract_storage_account_id_slot_valid_to_old;

ALTER INDEX idx_contract_storage_valid_to RENAME TO idx_contract_storage_valid_to_old;

UPDATE
    contract_storage_old
SET
    valid_to = '262142-12-31T23:59:59.9999Z'
WHERE
    valid_to IS NULL;

ALTER TABLE contract_storage_old
    ALTER COLUMN valid_to SET NOT NULL;

CREATE TABLE contract_storage(
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
)
PARTITION BY RANGE (valid_to);

CREATE INDEX idx_contract_storage_account_id ON public.contract_storage USING btree(account_id);

CREATE INDEX idx_contract_storage_account_id_slot_valid_to ON public.contract_storage
    USING btree(account_id, slot, valid_to);

CREATE INDEX idx_contract_storage_valid_to ON public.contract_storage USING btree(modify_tx);

ALTER TABLE public.contract_storage
    ADD CONSTRAINT contract_storage_account_id_fkey FOREIGN KEY (account_id) REFERENCES
	account(id) ON DELETE CASCADE;

ALTER TABLE public.contract_storage
    ADD CONSTRAINT contract_storage_modify_tx_fkey FOREIGN KEY (modify_tx) REFERENCES
	"transaction"(id) ON DELETE CASCADE;

SELECT
    partman.create_parent(p_parent_table := 'public.contract_storage', p_control :=
	'valid_to', p_interval := '1 day', p_type := 'range',
	p_premake := 7, p_default_table := TRUE, p_automatic_maintenance :=
	'on');

WITH latest_contract_storage AS (
    DELETE FROM contract_storage_old
    WHERE valid_to = '262142-12-31T23:59:59.9999Z'
    RETURNING
        *)
INSERT INTO contract_storage
SELECT
    slot,
    value,
    previous_value,
    account_id,
    modify_tx,
    ordinal,
    valid_from,
    valid_to,
    inserted_ts,
    modified_ts
FROM
    latest_contract_storage;

ALTER TABLE contract_storage_old
    DROP COLUMN id;

ALTER TABLE contract_storage_default
    ADD CONSTRAINT contract_storage_default_unique_pk UNIQUE (account_id, slot);

-- COMPONENT BALANCE
ALTER TABLE component_balance RENAME TO component_balance_old;

UPDATE
    component_balance_old
SET
    valid_to = '262142-12-31T23:59:59.9999Z'
WHERE
    valid_to IS NULL;

ALTER TABLE component_balance_old
    ALTER COLUMN valid_to SET NOT NULL;

ALTER INDEX idx_component_balance_component_id_token_id_valid_to RENAME TO
    idx_component_balance_component_id_token_id_valid_to_old;

ALTER INDEX idx_component_balance_valid_to RENAME TO idx_component_balance_valid_to_old;

CREATE TABLE component_balance(
    token_id int8 NOT NULL,
    new_balance bytea NOT NULL,
    previous_value bytea NOT NULL,
    balance_float float8 NOT NULL,
    modify_tx int8 NOT NULL,
    protocol_component_id int8 NOT NULL,
    inserted_ts timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_from timestamptz NOT NULL,
    valid_to timestamptz NOT NULL
)
PARTITION BY RANGE (valid_to);

CREATE INDEX idx_component_balance_component_id_token_id_valid_to ON
    public.component_balance USING btree(protocol_component_id, token_id, valid_to);

CREATE INDEX idx_component_balance_valid_to ON public.component_balance USING btree(valid_to);

ALTER TABLE public.component_balance
    ADD CONSTRAINT component_balance_modify_tx_fkey FOREIGN KEY (modify_tx) REFERENCES
	"transaction"(id) ON DELETE CASCADE;

ALTER TABLE public.component_balance
    ADD CONSTRAINT component_balance_protocol_component_id_fkey FOREIGN KEY
	(protocol_component_id) REFERENCES protocol_component(id);

ALTER TABLE public.component_balance
    ADD CONSTRAINT component_balance_token_id_fkey FOREIGN KEY (token_id) REFERENCES "token"(id);

SELECT
    partman.create_parent(p_parent_table := 'public.component_balance', p_control :=
	'valid_to', p_interval := '1 day', p_type := 'range',
	p_premake := 7, p_default_table := TRUE, p_automatic_maintenance :=
	'on');

WITH latest_component_balance AS (
    DELETE FROM component_balance_old
    WHERE valid_to = '262142-12-31T23:59:59.9999Z'
    RETURNING
        *)
INSERT INTO component_balance
SELECT
    token_id,
    new_balance,
    previous_value,
    balance_float,
    modify_tx,
    protocol_component_id,
    inserted_ts,
    valid_from,
    valid_to
FROM
    latest_component_balance;

ALTER TABLE component_balance_old
    DROP COLUMN id;

ALTER TABLE component_balance_default
    ADD CONSTRAINT component_balance_default_unique_pk UNIQUE (protocol_component_id, token_id);
