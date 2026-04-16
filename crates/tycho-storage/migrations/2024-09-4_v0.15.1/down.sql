-- Remove the cascading deletes
ALTER TABLE public.protocol_component
    DROP CONSTRAINT IF EXISTS protocol_component_protocol_system_id_fkey,
    ADD CONSTRAINT protocol_component_protocol_system_id_fkey
    FOREIGN KEY (protocol_system_id)
    REFERENCES protocol_system(id);

ALTER TABLE public.protocol_component_holds_token
    DROP CONSTRAINT IF EXISTS protocol_holds_token_protocol_component_id_fkey,
    ADD CONSTRAINT protocol_holds_token_protocol_component_id_fkey
    FOREIGN KEY (protocol_component_id)
    REFERENCES protocol_component(id);

ALTER TABLE public.protocol_component_holds_contract
    DROP CONSTRAINT IF EXISTS protocol_component_holds_contract_protocol_component_id_fkey,
    ADD CONSTRAINT protocol_component_holds_contract_protocol_component_id_fkey
    FOREIGN KEY (protocol_component_id)
    REFERENCES protocol_component(id);

ALTER TABLE public.protocol_state
    DROP CONSTRAINT IF EXISTS protocol_state_protocol_component_id_fkey,
    ADD CONSTRAINT protocol_state_protocol_component_id_fkey
    FOREIGN KEY (protocol_component_id)
    REFERENCES protocol_component(id);

ALTER TABLE public.component_balance
    DROP CONSTRAINT IF EXISTS component_balance_protocol_component_id_fkey,
    ADD CONSTRAINT component_balance_protocol_component_id_fkey
    FOREIGN KEY (protocol_component_id)
    REFERENCES protocol_component(id);

ALTER TABLE public.component_tvl
    DROP CONSTRAINT IF EXISTS component_tvl_protocol_component_id_fkey,
    ADD CONSTRAINT component_tvl_protocol_component_id_fkey
    FOREIGN KEY (protocol_component_id)
    REFERENCES protocol_component(id);

ALTER TABLE public.protocol_component_holds_contract
    DROP CONSTRAINT IF EXISTS protocol_component_holds_contract_contract_code_id_fkey,
    ADD CONSTRAINT protocol_component_holds_contract_contract_code_id_fkey
    FOREIGN KEY (contract_code_id)
    REFERENCES contract_code(id);

ALTER TABLE public.protocol_component_holds_token
    DROP CONSTRAINT IF EXISTS protocol_holds_token_token_id_fkey,
    ADD CONSTRAINT protocol_holds_token_token_id_fkey
    FOREIGN KEY (token_id)
    REFERENCES token(id);

ALTER TABLE public.token_price
    DROP CONSTRAINT IF EXISTS token_price_token_id_fkey,
    ADD CONSTRAINT token_price_token_id_fkey
    FOREIGN KEY (token_id)
    REFERENCES token(id);

ALTER TABLE public.component_balance
    DROP CONSTRAINT IF EXISTS component_balance_token_id_fkey,
    ADD CONSTRAINT component_balance_token_id_fkey
    FOREIGN KEY (token_id)
    REFERENCES token(id);


-- Add protocol_calls_contract table

-- Relationship between protocols and contract(s).
CREATE TABLE IF NOT EXISTS protocol_calls_contract(
    "id" bigserial PRIMARY KEY,
    "protocol_component_id" bigint REFERENCES protocol_component(id) ON DELETE CASCADE NOT NULL,
    "account_id" bigint REFERENCES account(id) ON DELETE CASCADE NOT NULL,
    -- Tx this association became valid, versioned association between contracts,
    -- allows to track updates of e.g. price feeds.
    "valid_from" timestamptz NOT NULL,
    -- The tx at which this association stopped being valid. Null if this
    --	state is the currently valid entry.
    "valid_to" timestamptz,
    -- Timestamp this entry was inserted into this table.
    "inserted_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Timestamp this entry was inserted into this table.
    "modified_ts" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE ("protocol_component_id", "account_id", "valid_from"),
    UNIQUE ("protocol_component_id", "account_id", "valid_to")
);

CREATE INDEX IF NOT EXISTS idx_protocol_calls_contract_protocol_component_id ON
    protocol_calls_contract(protocol_component_id);

CREATE INDEX IF NOT EXISTS idx_protocol_calls_contract_account_id ON
    protocol_calls_contract(account_id);

CREATE INDEX IF NOT EXISTS idx_protocol_calls_contract_valid_to ON
    protocol_calls_contract(valid_to);


CREATE TRIGGER update_modtime_protocol_calls_contract
    BEFORE UPDATE ON "protocol_calls_contract"
    FOR EACH ROW
    EXECUTE PROCEDURE update_modified_column();
