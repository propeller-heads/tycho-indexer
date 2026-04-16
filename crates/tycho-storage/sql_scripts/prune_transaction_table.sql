-- Prune transaction table
--
-- This script will copy all entries in the transaction table currently referenced by
-- another row in any other table to a temporary new transaction table, then drop the old
-- existing transaction table and change all foreign keys and reference to the new
-- transaction table. This is useful if your transaction table has become very bloated
-- and there are more orphaned transactions entries than currently used ones.
--
-- Note
-- This script will lock all tables that reference transaction to avoid updates while
-- it is running.
BEGIN;
LOCK TABLE "transaction" IN access exclusive mode;
LOCK TABLE "protocol_component" IN access exclusive mode;
LOCK TABLE "account" IN access exclusive mode;
LOCK TABLE "account_balance" IN access exclusive mode;
LOCK TABLE "component_balance" IN access exclusive mode;
LOCK TABLE "protocol_state" IN access exclusive mode;
LOCK TABLE "contract_storage" IN access exclusive mode;

CREATE TEMP TABLE temp_transaction_ids(
    id bigint PRIMARY KEY
);

INSERT INTO temp_transaction_ids(id)
SELECT DISTINCT
    cc.modify_tx
FROM
    contract_code cc;

INSERT INTO temp_transaction_ids(id)
SELECT DISTINCT
    pc.creation_tx
FROM
    protocol_component pc
ON CONFLICT (id)
    DO NOTHING;

INSERT INTO temp_transaction_ids(id)
SELECT DISTINCT
    pc.deletion_tx
FROM
    protocol_component pc
WHERE
    pc.deletion_tx IS NOT NULL
ON CONFLICT (id)
    DO NOTHING;

INSERT INTO temp_transaction_ids(id)
SELECT DISTINCT
    a.creation_tx
FROM
    account a
WHERE
    a.creation_tx IS NOT NULL
ON CONFLICT (id)
    DO NOTHING;

INSERT INTO temp_transaction_ids(id)
SELECT DISTINCT
    a.deletion_tx
FROM
    account a
WHERE
    a.deletion_tx IS NOT NULL
ON CONFLICT (id)
    DO NOTHING;

INSERT INTO temp_transaction_ids(id)
SELECT DISTINCT
    t.modify_tx
FROM
    account_balance t
ON CONFLICT (id)
    DO NOTHING;

INSERT INTO temp_transaction_ids(id)
SELECT DISTINCT
    t.modify_tx
FROM
    component_balance t
ON CONFLICT (id)
    DO NOTHING;

INSERT INTO temp_transaction_ids(id)
SELECT DISTINCT
    t.modify_tx
FROM
    protocol_state t
ON CONFLICT (id)
    DO NOTHING;

INSERT INTO temp_transaction_ids(id)
SELECT DISTINCT
    t.modify_tx
FROM
    contract_storage t
ON CONFLICT (id)
    DO NOTHING;

CREATE TABLE "transaction_new" AS
SELECT
    t.*
FROM
    TRANSACTION t
WHERE
    EXISTS (
        SELECT
            1
        FROM
            temp_transaction_ids tti
        WHERE
            t.id = tti.id);


ALTER TABLE "transaction" RENAME TO "transaction_old";
-- Step 1: Attach the sequence to the "id" column and make it NOT NULL with default
ALTER TABLE transaction_old
    ALTER COLUMN id DROP DEFAULT;
ALTER SEQUENCE transaction_id_seq OWNED BY transaction_new.id;
ALTER TABLE transaction_new
    ALTER COLUMN id SET NOT NULL,
    ALTER COLUMN id SET DEFAULT nextval('transaction_id_seq'::regclass);

-- Step 2: Set NOT NULL constraints for the other columns
ALTER TABLE transaction_new
    ALTER COLUMN hash SET NOT NULL,
    ALTER COLUMN "from" SET NOT NULL,
    ALTER COLUMN "to" SET NOT NULL,
    ALTER COLUMN "index" SET NOT NULL,
    ALTER COLUMN block_id SET NOT NULL,
    ALTER COLUMN inserted_ts SET NOT NULL,
    ALTER COLUMN modified_ts SET NOT NULL;

-- Step 3: Set default values for "inserted_ts" and "modified_ts"
ALTER TABLE transaction_new
    ALTER COLUMN inserted_ts SET DEFAULT CURRENT_TIMESTAMP,
    ALTER COLUMN modified_ts SET DEFAULT CURRENT_TIMESTAMP;

-- Step 4: Add the UNIQUE constraints
ALTER TABLE transaction_old RENAME CONSTRAINT transaction_hash_key TO transaction_old_hash_key;
ALTER TABLE transaction_old RENAME CONSTRAINT transaction_index_block_id_key TO
    transaction_old_index_block_id_key;
ALTER TABLE transaction_new
    ADD CONSTRAINT transaction_hash_key UNIQUE (hash),
    ADD CONSTRAINT transaction_index_block_id_key UNIQUE ("index", block_id);

-- Step 5: Add the PRIMARY KEY constraint
ALTER TABLE transaction_old RENAME CONSTRAINT transaction_pkey TO transaction_old_pkey;
ALTER TABLE transaction_new
    ADD CONSTRAINT transaction_pkey PRIMARY KEY (id);

-- Step 6: Indices
ALTER INDEX idx_transaction_block_id RENAME TO idx_transaction_old_block_id;
CREATE INDEX idx_transaction_block_id ON public."transaction_new" USING btree(block_id);

-- Step 7: Table Triggers
ALTER TRIGGER update_modtime_transaction ON transaction_old RENAME TO
    update_modtime_transaction_old;
CREATE TRIGGER update_modtime_transaction
    BEFORE UPDATE ON public."transaction_new"
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

-- Step 8: Foreign Keys
ALTER TABLE transaction_old RENAME CONSTRAINT transaction_block_id_fkey TO
    transaction_old_block_id_fkey;
ALTER TABLE public."transaction_new"
    ADD CONSTRAINT transaction_block_id_fkey FOREIGN KEY (block_id) REFERENCES block(id)
	ON DELETE CASCADE;
ALTER TABLE account
    DROP CONSTRAINT account_creation_tx_fkey;
ALTER TABLE account
    DROP CONSTRAINT account_deletion_tx_fkey;
ALTER TABLE account_balance
    DROP CONSTRAINT account_balance_modify_tx_fkey;
ALTER TABLE component_balance
    DROP CONSTRAINT component_balance_modify_tx_fkey;
ALTER TABLE contract_code
    DROP CONSTRAINT contract_code_modify_tx_fkey;
ALTER TABLE contract_storage
    DROP CONSTRAINT contract_storage_modify_tx_fkey;
ALTER TABLE protocol_component
    DROP CONSTRAINT protocol_component_creation_tx_fkey;
ALTER TABLE protocol_component
    DROP CONSTRAINT protocol_component_deletion_tx_fkey;
ALTER TABLE protocol_state
    DROP CONSTRAINT protocol_state_modify_tx_fkey;
ALTER TABLE account
    ADD CONSTRAINT account_creation_tx_fkey FOREIGN KEY (creation_tx) REFERENCES transaction_new(id);
ALTER TABLE account
    ADD CONSTRAINT account_deletion_tx_fkey FOREIGN KEY (deletion_tx) REFERENCES transaction_new(id);
ALTER TABLE account_balance
    ADD CONSTRAINT account_balance_modify_tx_fkey FOREIGN KEY (modify_tx) REFERENCES
	transaction_new(id);
ALTER TABLE component_balance
    ADD CONSTRAINT component_balance_modify_tx_fkey FOREIGN KEY (modify_tx) REFERENCES
	transaction_new(id);
ALTER TABLE contract_code
    ADD CONSTRAINT contract_code_modify_tx_fkey FOREIGN KEY (modify_tx) REFERENCES
	transaction_new(id);
ALTER TABLE contract_storage
    ADD CONSTRAINT contract_storage_modify_tx_fkey FOREIGN KEY (modify_tx) REFERENCES
	transaction_new(id);
ALTER TABLE protocol_component
    ADD CONSTRAINT protocol_component_creation_tx_fkey FOREIGN KEY (creation_tx)
	REFERENCES transaction_new(id);
ALTER TABLE protocol_component
    ADD CONSTRAINT protocol_component_deletion_tx_fkey FOREIGN KEY (deletion_tx)
	REFERENCES transaction_new(id);
ALTER TABLE protocol_state
    ADD CONSTRAINT protocol_state_modify_tx_fkey FOREIGN KEY (modify_tx) REFERENCES
	transaction_new(id);

-- Finish by renaming tables and dropping interim tables
ALTER TABLE "transaction_new" RENAME TO "transaction";
DROP TABLE "transaction_old";
DROP TABLE "temp_transaction_ids";

COMMIT;
