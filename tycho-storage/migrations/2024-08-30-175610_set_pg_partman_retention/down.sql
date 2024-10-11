-- Reset retention to infinity and retention_keep_table to true for protocol_state
UPDATE partman.part_config
SET retention = 'infinity',
    retention_keep_table = true
WHERE parent_table = 'public.protocol_state';

-- Reset retention to infinity and retention_keep_table to true for contract_storage
UPDATE partman.part_config
SET retention = 'infinity',
    retention_keep_table = true
WHERE parent_table = 'public.contract_storage';

-- Reset retention to infinity and retention_keep_table to true for component_balance
UPDATE partman.part_config
SET retention = 'infinity',
    retention_keep_table = true
WHERE parent_table = 'public.component_balance';
