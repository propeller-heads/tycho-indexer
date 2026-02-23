-- First add the column without any constraints
ALTER TABLE protocol_component_holds_token ADD COLUMN token_index SMALLINT DEFAULT NULL;

-- The audit_log table was dropped, but the triggers weren't removed!
-- We need to remove these to update existing rows during this migration.
DROP TRIGGER IF EXISTS audit_table_chain ON "chain";
DROP TRIGGER IF EXISTS audit_table_block ON "block";
DROP TRIGGER IF EXISTS audit_table_transaction ON "transaction";
DROP TRIGGER IF EXISTS audit_table_protocol_system ON "protocol_system";
DROP TRIGGER IF EXISTS audit_table_protocol_type ON "protocol_type";
DROP TRIGGER IF EXISTS audit_table_protocol_state ON "protocol_state";
DROP TRIGGER IF EXISTS audit_table_protocol_component ON "protocol_component";
DROP TRIGGER IF EXISTS audit_table_account ON "account";
DROP TRIGGER IF EXISTS audit_table_token ON "token";
DROP TRIGGER IF EXISTS audit_table_contract_storage ON "contract_storage";
DROP TRIGGER IF EXISTS audit_table_account_balance ON "account_balance";
DROP TRIGGER IF EXISTS audit_table_contract_code ON "contract_code";
DROP TRIGGER IF EXISTS audit_table_extraction_state ON "extraction_state";
DROP TRIGGER IF EXISTS audit_table_protocol_component_holds_token ON "protocol_component_holds_token";
DROP TRIGGER IF EXISTS audit_table_token_price ON "protocol_component_holds_token";
DROP TRIGGER IF EXISTS audit_table_component_tvl ON "component_tvl";
DROP FUNCTION IF EXISTS audit_trigger();

-- Migrate existing rows to use lexicographical ordering and negative indexes
UPDATE protocol_component_holds_token
SET token_index = row_num - total_count - 1
FROM (SELECT pcht.protocol_component_id,
             pcht.token_id,
             ROW_NUMBER() OVER (PARTITION BY pcht.protocol_component_id ORDER BY a.address) as row_num,
             COUNT(*) OVER (PARTITION BY pcht.protocol_component_id)                        as total_count
      FROM protocol_component_holds_token pcht
               JOIN token t ON pcht.token_id = t.id
               JOIN account a ON t.account_id = a.id) AS ranked
WHERE protocol_component_holds_token.protocol_component_id = ranked.protocol_component_id
  AND protocol_component_holds_token.token_id = ranked.token_id;

-- Add the NOT NULL constraint to the column
ALTER TABLE protocol_component_holds_token ALTER COLUMN token_index SET NOT NULL;

-- Create a UNIQUE constraint on the combination of protocol_component_id and token_index
ALTER TABLE protocol_component_holds_token ADD CONSTRAINT protocol_holds_token_token_index_unique
    UNIQUE (protocol_component_id, token_index);
