-- Drop the new constraint
ALTER TABLE entry_point DROP CONSTRAINT IF EXISTS entry_point_external_id_target_signature_key;

-- Drop the indexes
DROP INDEX IF EXISTS idx_entry_point_target_signature;
DROP INDEX IF EXISTS idx_entry_point_external_id;

-- Re-add the old constraints (Note: this may fail if there are duplicate entries)
-- You may need to clean up duplicate data first
ALTER TABLE entry_point ADD CONSTRAINT entry_point_external_id_key UNIQUE (external_id);