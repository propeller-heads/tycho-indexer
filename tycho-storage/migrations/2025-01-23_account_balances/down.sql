-- REMOVE token_id from account_balance table
-- Step 1: Drop the new unique constraint
ALTER TABLE account_balance
DROP CONSTRAINT account_balance_account_id_token_id_modify_tx_key;

-- Step 2: Restore the old constraint
ALTER TABLE account_balance
ADD CONSTRAINT account_balance_account_id_modify_tx_key UNIQUE (account_id, modify_tx);

-- Step 3: Drop the index on account and token_id
DROP INDEX IF EXISTS account_balance_account_token_id_idx;

-- Step 4: Drop the foreign key constraint
ALTER TABLE account_balance
DROP CONSTRAINT IF EXISTS account_balance_token_id_fkey;

-- Step 5: Remove the token_id column from the account_balance table
ALTER TABLE account_balance DROP COLUMN IF EXISTS token_id;

-- Step 6: Conditionally remove the ETH native token from the token table if not referenced elsewhere
DELETE FROM token 
WHERE account_id = (
    SELECT id FROM account WHERE address = '\x0000000000000000000000000000000000000000'
)
AND NOT EXISTS (
    SELECT 1 FROM protocol_component_holds_token 
    WHERE protocol_component_holds_token.token_id = token.id
);

-- Step 7: Conditionally remove the zero address account if it has no linked tokens
DELETE FROM account 
WHERE address = '\x0000000000000000000000000000000000000000'
AND NOT EXISTS (
    SELECT 1 FROM token WHERE token.account_id = account.id
);
