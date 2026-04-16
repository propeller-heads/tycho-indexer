--- Drop special composite indices for in-app versioning queries
DROP INDEX IF EXISTS idx_contract_storage_account_id_slot_valid_to;

DROP INDEX IF EXISTS idx_protocol_state_component_id_attribute_name_valid_to;

DROP INDEX IF EXISTS idx_component_balance_component_id_token_id_valid_to;

DROP INDEX IF EXISTS idx_account_address;

DROP INDEX idx_component_balance_valid_to;

CREATE INDEX IF NOT EXISTS idx_block_number_identity ON block("number", "chain_id");

ALTER TABLE block
    ADD CONSTRAINT block_chain_id_hash_key UNIQUE (chain_id, hash);

ALTER TABLE TRANSACTION
    ADD CONSTRAINT transaction_hash_block_id_key UNIQUE (hash, block_id);
