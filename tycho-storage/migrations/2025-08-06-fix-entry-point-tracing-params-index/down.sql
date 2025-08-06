-- Rollback the hash-based approach and restore the original constraint
-- WARNING: This may fail if there are entries with large data fields that exceed btree limits

-- Drop the trigger and function
DROP TRIGGER IF EXISTS update_entry_point_tracing_params_data_hash_trigger ON entry_point_tracing_params;
DROP FUNCTION IF EXISTS update_entry_point_tracing_params_data_hash();
DROP FUNCTION IF EXISTS compute_data_hash(JSONB);

-- Drop the new hash-based constraint
ALTER TABLE entry_point_tracing_params 
DROP CONSTRAINT IF EXISTS entry_point_tracing_params_entry_point_id_tracing_type_data_hash_key;

-- Remove the data_hash column
ALTER TABLE entry_point_tracing_params 
DROP COLUMN IF EXISTS data_hash;

-- Restore the original constraint (this may fail if large data entries exist)
ALTER TABLE entry_point_tracing_params 
ADD CONSTRAINT entry_point_tracing_params_entry_point_id_tracing_type_data_key 
UNIQUE (entry_point_id, tracing_type, data);