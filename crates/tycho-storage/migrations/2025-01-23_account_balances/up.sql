-- ADD token_id to account_balance table.

-- Step 1: add zero address account (to link to ETH token) if the DB has only 1 chain and 
-- it is either ethereum or base
DO $$
BEGIN
    IF (
        SELECT COUNT(*) 
        FROM chain 
        WHERE name IN ('ethereum', 'base', 'arbitrum')
    ) = 1 THEN
        INSERT INTO account (chain_id, title, address)
        VALUES (
            (SELECT id FROM chain WHERE name IN ('ethereum', 'base') LIMIT 1),
            'ETH_0x0000000000000000000000000000000000000000',
            '\x0000000000000000000000000000000000000000'
        )
        ON CONFLICT (chain_id, address) DO NOTHING;
    END IF;
END $$;

-- Step 2: add ETH native token if the DB has only 1 chain and it is either ethereum or base
DO $$
BEGIN
    IF (
        SELECT COUNT(*) 
        FROM chain 
        WHERE name IN ('ethereum', 'base')
    ) = 1 THEN
        INSERT INTO token (account_id, symbol, decimals, tax, gas, quality)
        VALUES (
            (SELECT id FROM account WHERE address = '\x0000000000000000000000000000000000000000'),
            'ETH',
            18,
            0,
            ARRAY[2300, 2300, 2300, 2300]::BIGINT[],
            100
        )
        ON CONFLICT (account_id) DO NOTHING;
    END IF;
END $$;

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

-- Step 6: remove old contraints
ALTER TABLE account_balance
DROP CONSTRAINT account_balance_account_id_modify_tx_key;

-- Step 7: add new contraint
ALTER TABLE account_balance
ADD CONSTRAINT account_balance_account_id_token_id_modify_tx_key
UNIQUE (account_id, token_id, modify_tx);
