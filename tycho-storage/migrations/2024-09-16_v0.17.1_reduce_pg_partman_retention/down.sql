-- Reset retention to 3 months for protocol_state
UPDATE partman.part_config
SET retention = '3 months'
WHERE parent_table = 'public.protocol_state';

-- Reset retention to 3 months for contract_storage
UPDATE partman.part_config
SET retention = '3 months'
WHERE parent_table = 'public.contract_storage';

-- Reset retention to 3 months for component_balance
UPDATE partman.part_config
SET retention = '3 months'
WHERE parent_table = 'public.component_balance';
