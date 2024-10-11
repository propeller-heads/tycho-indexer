-- Add cascade deletes for protocol system related tables
ALTER TABLE public.protocol_component
    DROP CONSTRAINT IF EXISTS protocol_component_protocol_system_id_fkey,
    ADD CONSTRAINT protocol_component_protocol_system_id_fkey
    FOREIGN KEY (protocol_system_id)
    REFERENCES protocol_system(id)
    ON DELETE CASCADE;

ALTER TABLE public.protocol_component_holds_token
    DROP CONSTRAINT IF EXISTS protocol_holds_token_protocol_component_id_fkey,
    ADD CONSTRAINT protocol_holds_token_protocol_component_id_fkey
    FOREIGN KEY (protocol_component_id)
    REFERENCES protocol_component(id)
    ON DELETE CASCADE;

ALTER TABLE public.protocol_component_holds_contract
    DROP CONSTRAINT IF EXISTS protocol_component_holds_contract_protocol_component_id_fkey,
    ADD CONSTRAINT protocol_component_holds_contract_protocol_component_id_fkey
    FOREIGN KEY (protocol_component_id)
    REFERENCES protocol_component(id)
    ON DELETE CASCADE;

ALTER TABLE public.protocol_state
    DROP CONSTRAINT IF EXISTS protocol_state_protocol_component_id_fkey,
    ADD CONSTRAINT protocol_state_protocol_component_id_fkey
    FOREIGN KEY (protocol_component_id)
    REFERENCES protocol_component(id)
    ON DELETE CASCADE;

ALTER TABLE public.component_balance
    DROP CONSTRAINT IF EXISTS component_balance_protocol_component_id_fkey,
    ADD CONSTRAINT component_balance_protocol_component_id_fkey
    FOREIGN KEY (protocol_component_id)
    REFERENCES protocol_component(id)
    ON DELETE CASCADE;

ALTER TABLE public.component_tvl
    DROP CONSTRAINT IF EXISTS component_tvl_protocol_component_id_fkey,
    ADD CONSTRAINT component_tvl_protocol_component_id_fkey
    FOREIGN KEY (protocol_component_id)
    REFERENCES protocol_component(id)
    ON DELETE CASCADE;


-- Add cascade delete for account related tables
ALTER TABLE public.protocol_component_holds_contract
    DROP CONSTRAINT IF EXISTS protocol_component_holds_contract_contract_code_id_fkey,
    ADD CONSTRAINT protocol_component_holds_contract_contract_code_id_fkey
    FOREIGN KEY (contract_code_id)
    REFERENCES contract_code(id)
    ON DELETE CASCADE;

-- Add cascade delete for token related tables
ALTER TABLE public.protocol_component_holds_token
    DROP CONSTRAINT IF EXISTS protocol_holds_token_token_id_fkey,
    ADD CONSTRAINT protocol_holds_token_token_id_fkey
    FOREIGN KEY (token_id)
    REFERENCES token(id)
    ON DELETE CASCADE;

ALTER TABLE public.token_price
    DROP CONSTRAINT IF EXISTS token_price_token_id_fkey,
    ADD CONSTRAINT token_price_token_id_fkey
    FOREIGN KEY (token_id)
    REFERENCES token(id)
    ON DELETE CASCADE;

ALTER TABLE public.component_balance
    DROP CONSTRAINT IF EXISTS component_balance_token_id_fkey,
    ADD CONSTRAINT component_balance_token_id_fkey
    FOREIGN KEY (token_id)
    REFERENCES token(id)
    ON DELETE CASCADE;

-- drop unused table (we use protocol_component_holds_contract instead)
DROP TABLE IF EXISTS protocol_calls_contract;
