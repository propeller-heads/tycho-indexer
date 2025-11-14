-- =====================================================================
-- PROTOCOL SYSTEM DELETION SCRIPT
-- =====================================================================
-- This script safely deletes a protocol system and all its associated data
-- while preserving data integrity and foreign key relationships.
-- 
-- Usage: Replace ${protocol_system_to_delete} with the actual protocol name
-- =====================================================================

BEGIN;

-- Acquire exclusive locks on all tables that will be modified
LOCK TABLE protocol_system IN EXCLUSIVE MODE;
LOCK TABLE protocol_component IN EXCLUSIVE MODE;
LOCK TABLE protocol_component_holds_token IN EXCLUSIVE MODE;
LOCK TABLE protocol_component_holds_contract IN EXCLUSIVE MODE;
LOCK TABLE component_balance IN EXCLUSIVE MODE;
LOCK TABLE protocol_state IN EXCLUSIVE MODE;
LOCK TABLE token IN EXCLUSIVE MODE;
LOCK TABLE account IN EXCLUSIVE MODE;
LOCK TABLE account_balance IN EXCLUSIVE MODE;
LOCK TABLE contract_code IN EXCLUSIVE MODE;
LOCK TABLE contract_storage IN EXCLUSIVE MODE;
LOCK TABLE entry_point_tracing_params_calls_account IN EXCLUSIVE MODE;
LOCK TABLE token_price IN EXCLUSIVE MODE;
LOCK TABLE extraction_state IN EXCLUSIVE MODE;

-- =====================================================================
-- STEP 1: IDENTIFY DATA TO DELETE
-- =====================================================================

-- Find all protocol components belonging to the system we want to delete
CREATE TABLE IF NOT EXISTS protocol_components_to_delete AS
SELECT pc.id AS component_id
FROM protocol_component pc
JOIN protocol_system ps ON pc.protocol_system_id = ps.id
WHERE ps.name = '${protocol_system_to_delete}';

CREATE INDEX idx_temp_component_id ON protocol_components_to_delete(component_id);

-- Identify tokens that can be safely deleted
-- Only delete tokens that:
-- 1. Are not held by the zero address
-- 2. Are not used by any other protocol system
CREATE TABLE IF NOT EXISTS tokens_to_delete AS
SELECT DISTINCT t.id AS token_id, t.account_id
FROM token t
JOIN protocol_component_holds_token pcht ON t.id = pcht.token_id
JOIN protocol_component pc ON pcht.protocol_component_id = pc.id
JOIN protocol_system ps ON pc.protocol_system_id = ps.id
JOIN account a ON t.account_id = a.id
WHERE ps.name = '${protocol_system_to_delete}'
  AND a.address != '\x0000000000000000000000000000000000000000'
  AND NOT EXISTS (
    -- Ensure token is not used by any other protocol system
    SELECT 1
    FROM protocol_component_holds_token pcht2
    JOIN protocol_component pc2 ON pcht2.protocol_component_id = pc2.id
    JOIN protocol_system ps2 ON pc2.protocol_system_id = ps2.id
    WHERE pcht2.token_id = t.id
      AND ps2.name != '${protocol_system_to_delete}'
  );

CREATE INDEX idx_temp_token_id ON tokens_to_delete(token_id);
CREATE INDEX idx_temp_token_account_id ON tokens_to_delete(account_id);


-- =====================================================================
-- STEP 2: DELETE RELATIONSHIP RECORDS
-- =====================================================================

-- Remove protocol component to token relationships
DELETE FROM protocol_component_holds_token
WHERE protocol_component_id IN (SELECT component_id FROM protocol_components_to_delete);

-- Remove protocol component to contract relationships
DELETE FROM protocol_component_holds_contract
WHERE protocol_component_id IN (SELECT component_id FROM protocol_components_to_delete);


-- =====================================================================
-- STEP 3: REBUILD COMPONENT BALANCE TABLE
-- =====================================================================

-- Create new component_balance_default table without deleted components
CREATE TABLE component_balance_default_new (LIKE component_balance_default INCLUDING ALL);

INSERT INTO component_balance_default_new
SELECT cb.*
FROM component_balance_default cb
WHERE NOT EXISTS (
    SELECT 1 
    FROM protocol_components_to_delete pctd
    WHERE pctd.component_id = cb.protocol_component_id
);

-- Detach and rename old partition
ALTER TABLE component_balance DETACH PARTITION component_balance_default;
ALTER TABLE component_balance_default RENAME TO component_balance_default_old;

-- Rename constraints
ALTER TABLE component_balance_default_old 
  RENAME CONSTRAINT component_balance_default_unique_pk 
  TO component_balance_default_unique_pk_old;

ALTER TABLE component_balance_default_new 
  RENAME CONSTRAINT component_balance_default_new_protocol_component_id_token_i_key 
  TO component_balance_default_unique_pk;

-- Rename old indexes
ALTER INDEX component_balance_default_modify_tx_idx 
  RENAME TO component_balance_default_modify_tx_idx_old;
ALTER INDEX component_balance_default_protocol_component_id_token_id_va_idx 
  RENAME TO component_balance_default_old_protocol_component_id_token_id_va_idx;
ALTER INDEX component_balance_default_valid_to_idx 
  RENAME TO component_balance_default_valid_to_idx_old;
ALTER INDEX idx_component_balance_default_valid_from 
  RENAME TO idx_component_balance_default_valid_from_old;

-- Rename new indexes to standard names
ALTER INDEX component_balance_default_new_modify_tx_idx 
  RENAME TO component_balance_default_modify_tx_idx;
ALTER INDEX component_balance_default_new_protocol_component_id_token_i_idx 
  RENAME TO component_balance_default_protocol_component_id_token_id_va_idx;
ALTER INDEX component_balance_default_new_valid_from_idx 
  RENAME TO idx_component_balance_default_valid_from;
ALTER INDEX component_balance_default_new_valid_to_idx 
  RENAME TO component_balance_default_valid_to_idx;

-- Add foreign key constraint
ALTER TABLE component_balance_default_new 
  ADD CONSTRAINT component_balance_modify_tx_fkey 
  FOREIGN KEY (modify_tx) REFERENCES transaction(id);

-- Attach new partition
ALTER TABLE component_balance_default_new RENAME TO component_balance_default;
ALTER TABLE component_balance ATTACH PARTITION component_balance_default DEFAULT;


-- =====================================================================
-- STEP 4: REBUILD PROTOCOL STATE TABLE
-- =====================================================================

-- Create new protocol_state_default table without deleted components
CREATE TABLE protocol_state_default_new (LIKE protocol_state_default INCLUDING ALL);

INSERT INTO protocol_state_default_new
SELECT ps.*
FROM protocol_state_default ps
WHERE NOT EXISTS (
    SELECT 1 
    FROM protocol_components_to_delete pctd
    WHERE pctd.component_id = ps.protocol_component_id
);

-- Detach and rename old partition
ALTER TABLE protocol_state DETACH PARTITION protocol_state_default;
ALTER TABLE protocol_state_default RENAME TO protocol_state_default_old;

-- Rename constraints
ALTER TABLE protocol_state_default_old 
  RENAME CONSTRAINT protocol_state_default_unique_pk 
  TO protocol_state_default_unique_pk_old;

ALTER TABLE protocol_state_default_new 
  RENAME CONSTRAINT protocol_state_default_new_protocol_component_id_attribute__key 
  TO protocol_state_default_unique_pk;

-- Rename old indexes
ALTER INDEX protocol_state_default_modify_tx_idx 
  RENAME TO protocol_state_default_modify_tx_idx_old;
ALTER INDEX protocol_state_default_protocol_component_id_attribute_name_idx 
  RENAME TO protocol_state_default_old_protocol_component_id_attribute_name_idx;
ALTER INDEX protocol_state_default_protocol_component_id_idx 
  RENAME TO protocol_state_default_protocol_component_id_idx_old;
ALTER INDEX protocol_state_default_valid_to_idx 
  RENAME TO protocol_state_default_valid_to_idx_old;

-- Rename new indexes to standard names
ALTER INDEX protocol_state_default_new_modify_tx_idx 
  RENAME TO protocol_state_default_modify_tx_idx;
ALTER INDEX protocol_state_default_new_protocol_component_id_attribute__idx 
  RENAME TO protocol_state_default_protocol_component_id_attribute_name_idx;
ALTER INDEX protocol_state_default_new_protocol_component_id_idx 
  RENAME TO protocol_state_default_protocol_component_id_idx;
ALTER INDEX protocol_state_default_new_valid_to_idx 
  RENAME TO protocol_state_default_valid_to_idx;

-- Add foreign key constraint
ALTER TABLE protocol_state_default_new 
  ADD CONSTRAINT protocol_state_modify_tx_fkey 
  FOREIGN KEY (modify_tx) REFERENCES transaction(id);

-- Attach new partition
ALTER TABLE protocol_state_default_new RENAME TO protocol_state_default;
ALTER TABLE protocol_state ATTACH PARTITION protocol_state_default DEFAULT;


-- =====================================================================
-- STEP 5: REBUILD TOKEN AND ACCOUNT TABLES
-- =====================================================================

-- Create new token table without deleted tokens
CREATE TABLE token_new (LIKE token INCLUDING ALL);

INSERT INTO token_new
SELECT t.*
FROM token t
WHERE NOT EXISTS (
    SELECT 1 FROM tokens_to_delete ttd
    WHERE ttd.token_id = t.id
);

-- Create new account table without accounts that only held deleted tokens
CREATE TABLE account_new (LIKE account INCLUDING ALL);

INSERT INTO account_new
SELECT a.*
FROM account a
WHERE NOT EXISTS (
    SELECT 1 FROM tokens_to_delete ttd
    WHERE ttd.account_id = a.id
);

-- Rename old tables
ALTER TABLE account RENAME TO account_old;
ALTER TABLE token RENAME TO token_old;

-- Clean up token prices for deleted tokens
DELETE FROM token_price tp 
WHERE tp.token_id NOT IN (SELECT id FROM token_new);


-- =====================================================================
-- STEP 6: RESTORE ACCOUNT TABLE WITH NEW DATA
-- =====================================================================

-- Transfer sequence ownership
ALTER SEQUENCE account_id_seq OWNED BY account_new.id;

-- Rename old constraints
ALTER TABLE account_old 
  RENAME CONSTRAINT account_chain_id_address_key 
  TO account_old_chain_id_address_key;
ALTER TABLE account_old 
  RENAME CONSTRAINT account_pkey 
  TO account_old_pkey;

-- Rename new constraints to standard names
ALTER TABLE account_new 
  RENAME CONSTRAINT account_new_chain_id_address_key 
  TO account_chain_id_address_key;
ALTER TABLE account_new 
  RENAME CONSTRAINT account_new_pkey 
  TO account_pkey;

-- Rename old indexes
ALTER INDEX idx_account_address RENAME TO idx_account_old_address;
ALTER INDEX idx_account_chain_id RENAME TO idx_account_old_chain_id;
ALTER INDEX idx_account_creation_tx RENAME TO idx_account_old_creation_tx;
ALTER INDEX idx_account_deletion_tx RENAME TO idx_account_old_deletion_tx;

-- Rename new indexes to standard names
ALTER INDEX account_new_address_idx RENAME TO idx_account_address;
ALTER INDEX account_new_chain_id_idx RENAME TO idx_account_chain_id;
ALTER INDEX account_new_creation_tx_idx RENAME TO idx_account_creation_tx;
ALTER INDEX account_new_deletion_tx_idx RENAME TO idx_account_deletion_tx;

-- Add foreign key constraints
ALTER TABLE account_new 
  ADD CONSTRAINT account_chain_id_fkey 
  FOREIGN KEY (chain_id) REFERENCES chain(id);
ALTER TABLE account_new 
  ADD CONSTRAINT account_creation_tx_fkey 
  FOREIGN KEY (creation_tx) REFERENCES transaction(id);
ALTER TABLE account_new 
  ADD CONSTRAINT account_deletion_tx_fkey 
  FOREIGN KEY (deletion_tx) REFERENCES transaction(id);

-- Add update trigger
CREATE TRIGGER update_modtime_account
  BEFORE UPDATE ON account_new
  FOR EACH ROW
  EXECUTE FUNCTION update_modified_column();

-- Update foreign key references in dependent tables
ALTER TABLE account_balance DROP CONSTRAINT account_balance_account_id_fkey;
ALTER TABLE account_balance 
  ADD CONSTRAINT account_balance_account_id_fkey 
  FOREIGN KEY (account_id) REFERENCES account_new(id) ON DELETE CASCADE;

ALTER TABLE contract_code DROP CONSTRAINT contract_code_account_id_fkey;
ALTER TABLE contract_code 
  ADD CONSTRAINT contract_code_account_id_fkey 
  FOREIGN KEY (account_id) REFERENCES account_new(id) ON DELETE CASCADE;

ALTER TABLE contract_storage DROP CONSTRAINT contract_storage_account_id_fkey;
ALTER TABLE contract_storage 
  ADD CONSTRAINT contract_storage_account_id_fkey 
  FOREIGN KEY (account_id) REFERENCES account_new(id) ON DELETE CASCADE;

ALTER TABLE entry_point_tracing_params_calls_account 
  DROP CONSTRAINT entry_point_tracing_params_calls_account_account_id_fkey;
ALTER TABLE entry_point_tracing_params_calls_account 
  ADD CONSTRAINT entry_point_tracing_params_calls_account_account_id_fkey 
  FOREIGN KEY (account_id) REFERENCES account_new(id) ON DELETE CASCADE;


-- =====================================================================
-- STEP 7: RESTORE TOKEN TABLE WITH NEW DATA
-- =====================================================================

-- Transfer sequence ownership
ALTER SEQUENCE token_id_seq OWNED BY token_new.id;

-- Rename old constraints
ALTER TABLE token_old 
  RENAME CONSTRAINT token_pkey 
  TO token_pkey_old;
ALTER TABLE token_old 
  RENAME CONSTRAINT unique_account_id_constraint 
  TO unique_account_id_constraint_old;

-- Rename new constraints to standard names
ALTER TABLE token_new 
  RENAME CONSTRAINT token_new_pkey 
  TO token_pkey;
ALTER TABLE token_new 
  RENAME CONSTRAINT token_new_account_id_key 
  TO unique_account_id_constraint;

-- Drop old foreign key and add new one
ALTER TABLE token_old DROP CONSTRAINT token_account_id_fkey;
ALTER TABLE token_new 
  ADD CONSTRAINT token_account_id_fkey 
  FOREIGN KEY (account_id) REFERENCES account_new(id) ON DELETE CASCADE;

-- Rename old indexes
ALTER INDEX idx_token_account_id RENAME TO idx_token_account_id_old;
ALTER INDEX idx_token_quality RENAME TO idx_token_quality_old;
ALTER INDEX idx_token_symbol RENAME TO idx_token_symbol_old;

-- Rename new indexes to standard names
ALTER INDEX token_new_account_id_idx RENAME TO idx_token_account_id;
ALTER INDEX token_new_quality_idx RENAME TO idx_token_quality;
ALTER INDEX token_new_symbol_idx RENAME TO idx_token_symbol;

-- Add update trigger
CREATE TRIGGER update_modtime_account
  BEFORE UPDATE ON token_new
  FOR EACH ROW
  EXECUTE FUNCTION update_modified_column();

-- Update foreign key references in dependent tables
ALTER TABLE account_balance DROP CONSTRAINT account_balance_token_id_fkey;
ALTER TABLE account_balance 
  ADD CONSTRAINT account_balance_token_id_fkey 
  FOREIGN KEY (token_id) REFERENCES token_new(id);

ALTER TABLE component_balance DROP CONSTRAINT component_balance_token_id_fkey;
ALTER TABLE component_balance 
  ADD CONSTRAINT component_balance_token_id_fkey 
  FOREIGN KEY (token_id) REFERENCES token_new(id) ON DELETE CASCADE;

ALTER TABLE protocol_component_holds_token 
  DROP CONSTRAINT protocol_holds_token_token_id_fkey;
ALTER TABLE protocol_component_holds_token 
  ADD CONSTRAINT protocol_holds_token_token_id_fkey 
  FOREIGN KEY (token_id) REFERENCES token_new(id) ON DELETE CASCADE;

ALTER TABLE token_price DROP CONSTRAINT token_price_token_id_fkey;
ALTER TABLE token_price 
  ADD CONSTRAINT token_price_token_id_fkey 
  FOREIGN KEY (token_id) REFERENCES token_new(id) ON DELETE CASCADE;


-- =====================================================================
-- STEP 8: DELETE PROTOCOL SYSTEM AND EXTRACTION STATE
-- =====================================================================

DELETE FROM protocol_system
WHERE name = '${protocol_system_to_delete}';

DELETE FROM extraction_state
WHERE name = '${protocol_system_to_delete}';


-- =====================================================================
-- STEP 9: FINALIZE TABLE RENAMES
-- =====================================================================

ALTER TABLE account_new RENAME TO account;
ALTER TABLE token_new RENAME TO token;


-- =====================================================================
-- STEP 10: CLEANUP OLD TABLES AND TEMP TABLES
-- =====================================================================

DROP TABLE IF EXISTS component_balance_default_old CASCADE;
DROP TABLE IF EXISTS protocol_state_default_old CASCADE;
DROP TABLE IF EXISTS token_old CASCADE;
DROP TABLE IF EXISTS account_old CASCADE;

DROP TABLE IF EXISTS protocol_components_to_delete;
DROP TABLE IF EXISTS tokens_to_delete;

COMMIT;

-- =====================================================================
-- END OF SCRIPT
-- =====================================================================