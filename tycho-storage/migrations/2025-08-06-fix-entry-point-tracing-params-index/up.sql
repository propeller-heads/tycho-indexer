-- Fix the btree index size issue by using a hash-based approach for the data field
-- The original constraint caused PostgreSQL to create a btree index that failed 
-- when the data field (containing large calldata) exceeded ~2704 bytes

-- Enable the pgcrypto extension for digest functions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Add a new column to store the hash of the data field
ALTER TABLE entry_point_tracing_params 
ADD COLUMN data_hash bytea;

-- Create a function to compute SHA-256 hash of JSONB data
CREATE OR REPLACE FUNCTION compute_data_hash(data_field JSONB) 
RETURNS bytea AS $$
BEGIN
    RETURN digest(data_field::text, 'sha256');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Update existing rows to populate the data_hash column
UPDATE entry_point_tracing_params 
SET data_hash = compute_data_hash(data) 
WHERE data IS NOT NULL;

-- Drop the existing unique constraint that includes the large data field
ALTER TABLE entry_point_tracing_params 
DROP CONSTRAINT entry_point_tracing_params_entry_point_id_tracing_type_data_key;

-- Add a new unique constraint using the hash instead of the full data
ALTER TABLE entry_point_tracing_params 
ADD CONSTRAINT entry_point_tracing_params_entry_point_id_tracing_type_data_hash_key 
UNIQUE (entry_point_id, tracing_type, data_hash);

-- Create a trigger to automatically update data_hash when data is modified
CREATE OR REPLACE FUNCTION update_entry_point_tracing_params_data_hash()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.data IS DISTINCT FROM OLD.data THEN
        NEW.data_hash = compute_data_hash(NEW.data);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_entry_point_tracing_params_data_hash_trigger
    BEFORE INSERT OR UPDATE ON entry_point_tracing_params
    FOR EACH ROW
    EXECUTE FUNCTION update_entry_point_tracing_params_data_hash();