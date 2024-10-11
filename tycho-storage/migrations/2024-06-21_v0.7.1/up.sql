--- Add block_id to extraction_state (without NOT NULL constraint)
ALTER TABLE extraction_state
ADD COLUMN "block_id" bigint REFERENCES "block"(id);

-- Populate existing extraction_state with the oldest block_id for its chain
WITH oldest_blocks AS (
    SELECT b.chain_id, MIN(b.id) AS oldest_block_id
    FROM "block" b
    GROUP BY b.chain_id
)
UPDATE extraction_state es
SET block_id = (
    SELECT ob.oldest_block_id
    FROM oldest_blocks ob
    WHERE es.chain_id = ob.chain_id
);

-- add NOT NULL constraint
ALTER TABLE extraction_state ALTER COLUMN block_id SET NOT NULL;
