--- Fix faulty protocol_state values due to a bug in versioning
--- This script should properly repair the current attribute values
--- but will not keep history in-tact. The "wrong active" version will
--- be lost and the "correct current" version will be duplicated.
--- temporary table with corrected attributes but potentially duplicated pc, attribute name pairs
CREATE TABLE protocol_state_correction_step_1
(
    id                    int8        NULL,
    modify_tx             int8        NULL,
    valid_from            timestamptz NULL,
    valid_to              timestamptz NULL,
    inserted_ts           timestamptz NULL,
    modified_ts           timestamptz NULL,
    protocol_component_id int8        NULL,
    attribute_name        varchar     NULL,
    attribute_value       bytea       NULL,
    previous_value        bytea       NULL,
    tx_index              int8        NOT NULL
);

--- Identify bad states in current table using a self join
--- If we had a previous state at the same block, that is
--- now outdated but had a higher tx index we save the previous
--- outdated state into our temporary table.
WITH latest_state AS (SELECT *
                      FROM protocol_state ps
                               JOIN "transaction" t ON t.id = ps.modify_tx
                      WHERE valid_to IS NULL),
     same_block_change AS (SELECT ps.id,
                                  ps.modify_tx,
                                  ps.valid_from,
                                  ps.valid_to,
                                  ps.inserted_ts,
                                  ps.modified_ts,
                                  ps.protocol_component_id,
                                  ps.attribute_name,
                                  ps.attribute_value,
                                  ps.previous_value,
                                  t."index"
                           FROM protocol_state ps
                                    JOIN "transaction" t ON t.id = ps.modify_tx
                           WHERE valid_to = valid_from)
INSERT
INTO protocol_state_correction_step_1
SELECT sbc.id,
       sbc.modify_tx,
       sbc.valid_from,
       sbc.valid_to,
       sbc.inserted_ts,
       sbc.modified_ts,
       sbc.protocol_component_id,
       sbc.attribute_name,
       sbc.attribute_value,
       sbc.previous_value,
       sbc."index"
FROM latest_state ls
         JOIN same_block_change sbc ON (ls.protocol_component_id = sbc.protocol_component_id
    AND ls.attribute_name = sbc.attribute_name
    AND ls.valid_from = sbc.valid_from)
WHERE ls."index" < sbc."index";

--- Next we look for old state that has a wrong attribute set
--- Cutoff date for archive is: 2024-04-04 15:41:23.000 +0000
--- select MAX(valid_to) from protocol_state_archive_3;
--- Extract previous state from archive tables, very slow takes around 2000s
--- We query all active state that is active for longer than the
--- cutoff date, we then join this subquery with the archive table
--- and compare transaction indicices. Last but not least we insert affected
---- rows into the temporary table.
WITH latest_state AS (SELECT ps.protocol_component_id,
                             ps.attribute_name,
                             ps.valid_from,
                             tx."index"
                      FROM protocol_state ps
                               JOIN "transaction" tx ON tx.id = ps.modify_tx
                      WHERE valid_from <= '2024-04-04 15:41:23.000 +0000'
                        AND valid_to IS NULL)
INSERT
INTO protocol_state_correction_step_1
SELECT ps.id,
       ps.modify_tx,
       ps.valid_from,
       ps.valid_to,
       ps.inserted_ts,
       ps.modified_ts,
       ps.protocol_component_id,
       ps.attribute_name,
       ps.attribute_value,
       ps.previous_value,
       tx."index"
FROM
--- Tried all archive tables, only archive_3 (the biggest) has relevant data
protocol_state_archive_3 ps
    JOIN "transaction" tx ON tx.id = ps.modify_tx
    JOIN latest_state ls ON ls.protocol_component_id = ps.protocol_component_id
    AND ls.attribute_name = ps.attribute_name
    AND ls.valid_from = ps.valid_from
WHERE ls."index" < tx."index";

--- Create a table that will contain the final correct state version
--- there will be no duplicated protocol_component, attribute_name
--- rows in here anymore.
CREATE TABLE protocol_state_correction_step_2
(
    id                    int8        NULL,
    modify_tx             int8        NULL,
    valid_from            timestamptz NULL,
    valid_to              timestamptz NULL,
    inserted_ts           timestamptz NULL,
    modified_ts           timestamptz NULL,
    protocol_component_id int8        NULL,
    attribute_name        varchar     NULL,
    attribute_value       bytea       NULL,
    previous_value        bytea       NULL
);

--- aggregation to select latest entry in case there were multiple:
INSERT INTO protocol_state_correction_step_2
SELECT id,
       modify_tx,
       valid_from,
       valid_to,
       inserted_ts,
       modified_ts,
       protocol_component_id,
       attribute_name,
       attribute_value,
       previous_value
FROM (SELECT *,
             ROW_NUMBER() OVER (PARTITION BY protocol_component_id, attribute_name ORDER BY
                 valid_from DESC, tx_index DESC) AS rn
      FROM protocol_state_correction_step_1) sub
WHERE rn = 1;

--- Preview planned changes
SELECT ps.protocol_component_id,
       ps.attribute_name,
       ps.attribute_value  AS wrong_value,
       psc.attribute_value AS new_value
FROM protocol_state ps
         JOIN protocol_state_correction_step_2 psc ON ps.protocol_component_id = psc.protocol_component_id
    AND ps.attribute_name = psc.attribute_name
WHERE ps.valid_to IS NULL;

-- Execute the update
update
    protocol_state ps
set attribute_value = psc.attribute_value,
    previous_value  = ps.attribute_value,
    modify_tx       = psc.modify_tx
FROM protocol_state_correction_step_2 psc
WHERE ps.protocol_component_id = psc.protocol_component_id
  AND ps.attribute_name = psc.attribute_name
  AND ps.valid_to IS NULL;

-- cleanup
DROP TABLE protocol_state_correction_step_2;

DROP TABLE protocol_state_correction_step_1;
