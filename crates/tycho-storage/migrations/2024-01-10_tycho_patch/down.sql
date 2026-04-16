CREATE TYPE protocol_implementation_type AS ENUM(
    'custom',
    'vm'
);

ALTER TABLE protocol_type
    ALTER COLUMN "implementation" TYPE protocol_implementation_type
    USING protocol_type::text::protocol_implementation_type;

DROP TYPE implementation_type;

CREATE TYPE financial_protocol_type AS ENUM(
    'swap',
    'psm',
    'debt',
    'leverage'
);

ALTER TABLE protocol_type
    ALTER COLUMN financial_type TYPE financial_protocol_type
    USING protocol_type::text::financial_protocol_type;

DROP TYPE financial_type;

ALTER TABLE protocol_type
    DROP CONSTRAINT unique_name_constraint;

CREATE OR REPLACE FUNCTION invalidate_previous_entry_protocol_state()
    RETURNS TRIGGER
    AS $$
BEGIN
    -- Update the 'valid_to' field of the last valid entry when a new one is inserted.
    UPDATE
        protocol_state
    SET
        valid_to = NEW.valid_from
    WHERE
        valid_to IS NULL
        AND protocol_component_id = NEW.protocol_component_id;
    RETURN NEW;
END;
$$
LANGUAGE plpgsql;

ALTER TABLE protocol_state
    DROP COLUMN attribute_name,
    DROP COLUMN attribute_value,
    DROP COLUMN previous_value,
    ADD COLUMN state jsonb NULL,
    ADD COLUMN tvl bigint NULL,
    ADD COLUMN inertias bigint[] NULL;

CREATE TRIGGER invalidate_previous_protocol_state
    BEFORE INSERT ON protocol_state
    FOR EACH ROW
    EXECUTE PROCEDURE invalidate_previous_entry_protocol_state();

ALTER TABLE protocol_system
    DROP CONSTRAINT name_unique;

ALTER TABLE token
    DROP CONSTRAINT unique_account_id_constraint;

CREATE OR REPLACE FUNCTION invalidate_previous_entry_contract_storage()
    RETURNS TRIGGER
    AS $$
BEGIN
    -- Get previous value from latest storage entry.
    NEW.previous_value =(
        SELECT
            value
        FROM
            contract_storage
        WHERE
            valid_to IS NULL
            AND account_id = NEW.account_id
            AND slot = NEW.slot
        LIMIT 1);
    -- Update the 'valid_to' field of the last valid entry when a new one is inserted.
    UPDATE
        contract_storage
    SET
        valid_to = NEW.valid_from
    WHERE
        valid_to IS NULL
        AND account_id = NEW.account_id
        AND slot = NEW.slot;
    RETURN NEW;
END;
$$
LANGUAGE plpgsql;

CREATE TRIGGER invalidate_previous_contract_storage
    BEFORE INSERT ON contract_storage
    FOR EACH ROW
    EXECUTE PROCEDURE invalidate_previous_entry_contract_storage();

CREATE OR REPLACE FUNCTION invalidate_previous_entry_account_balance()
    RETURNS TRIGGER
    AS $$
BEGIN
    -- Update the 'valid_to' field of the last valid entry when a new one is inserted.
    UPDATE
        account_balance
    SET
        valid_to = NEW.valid_from
    WHERE
        valid_to IS NULL
        AND account_id = NEW.account_id
        -- running this after inserts allows us to use upserts,
        -- currently the application does not use that though
        AND id != NEW.id;
    RETURN NEW;
END;
$$
LANGUAGE plpgsql;

CREATE TRIGGER invalidate_previous_account_balance
    AFTER INSERT ON account_balance
    FOR EACH ROW
    EXECUTE PROCEDURE invalidate_previous_entry_account_balance();

CREATE OR REPLACE FUNCTION invalidate_previous_entry_contract_code()
    RETURNS TRIGGER
    AS $$
BEGIN
    -- Update the 'valid_to' field of the last valid entry when a new one is inserted.
    UPDATE
        contract_code
    SET
        valid_to = NEW.valid_from
    WHERE
        valid_to IS NULL
        AND account_id = NEW.account_id
        -- running this after inserts allows us to use upserts,
        -- currently the application does not use that though
        AND id != NEW.id;
    RETURN NEW;
END;
$$
LANGUAGE plpgsql;

CREATE TRIGGER invalidate_previous_contract_code
    AFTER INSERT ON contract_code
    FOR EACH ROW
    EXECUTE PROCEDURE invalidate_previous_entry_contract_code();

DROP TABLE component_balance;

-- remove token_price table
DROP TRIGGER IF EXISTS update_modtime_token_price ON token_price;

DROP TRIGGER IF EXISTS audit_table_token_price ON protocol_component_holds_token;

DROP TABLE IF EXISTS token_price;

-- Drop the triggers from the renamed table
DROP TRIGGER IF EXISTS update_modtime_protocol_component_holds_token ON
    protocol_component_holds_token;

DROP TRIGGER IF EXISTS audit_table_protocol_component_holds_token ON
    protocol_component_holds_token;

-- Rename the table back to its original name
ALTER TABLE protocol_component_holds_token RENAME TO protocol_holds_token;

-- Recreate any triggers that were originally on protocol_holds_token, if needed
CREATE TRIGGER update_modtime_protocol_holds_token
    BEFORE UPDATE ON protocol_holds_token
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();

CREATE TRIGGER audit_table_protocol_holds_token
    BEFORE UPDATE ON protocol_holds_token
    FOR EACH ROW
    EXECUTE PROCEDURE audit_trigger();

-- add back index to protocol component
CREATE INDEX IF NOT EXISTS idx_protocol_identity ON protocol_component(external_id,
    protocol_system_id, chain_id);

-- add back old unique constraint
ALTER TABLE protocol_component
    ADD CONSTRAINT protocol_component_chain_id_protocol_system_id_external_id_key UNIQUE
	(chain_id, protocol_system_id, external_id);

ALTER TABLE protocol_component
    DROP CONSTRAINT protocol_component_chain_id_external_id_key;

-- remove component_tvl table
DROP TRIGGER IF EXISTS update_modtime_component_tvl ON component_tvl;

DROP TRIGGER IF EXISTS audit_table_component_tvl ON component_tvl;

DROP INDEX IF EXISTS idx_component_tvl_tvl;

DROP TABLE IF EXISTS component_tvl;

ALTER TABLE token
    DROP COLUMN quality;
