-- Drop any existing constraints that might conflict
ALTER TABLE entry_point DROP CONSTRAINT IF EXISTS entry_point_target_signature_key;
ALTER TABLE entry_point DROP CONSTRAINT IF EXISTS entry_point_external_id_key;

-- Add the correct unique constraint on (external_id, target, signature)
-- This ensures complete uniqueness while allowing multiple hooks to point to the same target+signature
-- as long as they have different external_ids
ALTER TABLE entry_point ADD CONSTRAINT entry_point_external_id_target_signature_key 
    UNIQUE (external_id, target, signature);

-- Add an index on (target, signature) for query performance
CREATE INDEX IF NOT EXISTS idx_entry_point_target_signature ON entry_point(target, signature);

-- Add an index on external_id for query performance
CREATE INDEX IF NOT EXISTS idx_entry_point_external_id ON entry_point(external_id);