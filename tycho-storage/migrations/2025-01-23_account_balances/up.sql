-- ADD token_id to account_balance table.

-- Step 1: add zero address account (to link to ETH token)
-- Assumes each db only has 1 chain
INSERT INTO account (chain_id, title, address)
VALUES (
    (SELECT id FROM chain LIMIT 1),
    'ETH_0x0000000000000000000000000000000000000000',
    '\x0000000000000000000000000000000000000000'
)
ON CONFLICT (chain_id, address) DO NOTHING;

-- Step 2: add ETH native token (currently only ethereum and base chains are used in our dbs 
-- so we can assume ETH is the native token)
INSERT INTO token (account_id, symbol, decimals, tax, gas, quality)
VALUES (
    (SELECT id FROM account WHERE address = '\x0000000000000000000000000000000000000000'),
    'ETH',
    18,
    0,
    ARRAY[0]::BIGINT[],
    100
)
ON CONFLICT (account_id) DO NOTHING;

-- Step 3.1: Add the token_id column to the account_balance table
ALTER TABLE account_balance
ADD COLUMN "token_id" BIGINT;

-- Step 3.2: Populate the token_id column with the the native token id
UPDATE account_balance
SET token_id = (
    SELECT t.id 
    FROM token t 
    JOIN account a ON t.account_id = a.id 
    WHERE a.address = '\x0000000000000000000000000000000000000000'
);

-- Step 3.3: Alter the column to be NOT NULL once all values are set
ALTER TABLE account_balance
ALTER COLUMN "token_id" SET NOT NULL;

-- Step 4: Add the foreign key constraint
ALTER TABLE account_balance
ADD CONSTRAINT account_balance_token_id_fkey
FOREIGN KEY (token_id)
REFERENCES token(id);

-- Step 5: index on token_id and account
CREATE INDEX account_balance_account_token_id_idx ON account_balance (account_id, token_id);


-- ADD balance_float to account_balance table

-- Step 1: Add balance_float column
ALTER TABLE account_balance ADD COLUMN balance_float FLOAT8;

-- Step 2: Update the new column by converting 'balance' bytea to float8
UPDATE account_balance
SET balance_float = ('x' || encode(balance, 'hex'))::bit(64)::bigint::float8;

-- Step 3: After populating the new column, set it to NOT NULL
ALTER TABLE account_balance ALTER COLUMN balance_float SET NOT NULL;