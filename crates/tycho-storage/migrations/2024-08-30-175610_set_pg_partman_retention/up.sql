-- Update retention settings for protocol_state to keep only the last 3 months
UPDATE partman.part_config
SET retention = '3 months',
    retention_keep_table = false
WHERE parent_table = 'public.protocol_state';

-- Update retention settings for contract_storage to keep only the last 3 months
UPDATE partman.part_config
SET retention = '3 months',
    retention_keep_table = false
WHERE parent_table = 'public.contract_storage';

-- Update retention settings for component_balance to keep only the last 3 months
UPDATE partman.part_config
SET retention = '3 months',
    retention_keep_table = false
WHERE parent_table = 'public.component_balance';
