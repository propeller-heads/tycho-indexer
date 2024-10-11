-- Update retention to 1 months for protocol_state
UPDATE partman.part_config
SET retention = '1 month'
WHERE parent_table = 'public.protocol_state';

-- Update retention to 1 months for contract_storage
UPDATE partman.part_config
SET retention = '1 month'
WHERE parent_table = 'public.contract_storage';

-- Update retention to 1 months for component_balance
UPDATE partman.part_config
SET retention = '1 month'
WHERE parent_table = 'public.component_balance';
