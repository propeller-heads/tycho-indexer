#!/bin/bash

#  Removes a protocol system and all related entries from the database.
#  This includes all protocol components, protocol states, accounts and their histories.
#  Note - linked blocks, transactions and accounts shared with other systems will not be removed.
#  TO USE: run the following cli command: './remove_protocol_system.sh <database_name> <protocol_system_to_delete> [<port_number>]'

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 <database_name> <protocol_system_to_delete> [<port_number>]"
    exit 1
fi

# Set the database, protocol system, and optional port number
db_name=$1
protocol_system_to_delete=$2
port_number=${3:-5432} # Default port is 5432 if not provided

# Warning message
echo ""
echo 'RECOMMENDATION: As a precaution, please take a db snapshot before proceeding.'
read -p 'Are you ready to proceed? (y/n) ' -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Exiting..."
    exit 1
fi

echo ""
echo "Connecting to $db_name..."

# Prompt user for username and password
read -p "Enter PostgreSQL username: " db_user
read -s -p "Enter PostgreSQL password: " db_password
echo

# Create an audit file to log what will be deleted
audit_file="audit_${protocol_system_to_delete}_deletion.log"
current_date=$(date '+%Y-%m-%d %H:%M:%S')
echo "Audit log for deletion of protocol system: $protocol_system_to_delete" > "$audit_file"
echo "Date: $current_date" >> "$audit_file"
echo "-----------------------------------------" >> "$audit_file"
echo "" >> "$audit_file"

echo ""
echo "Analysing $db_name..."


# Export password to PGPASSWORD environment variable so psql doesn't prompt for it again
export PGPASSWORD="$db_password"

# Collect the list of component IDs and contract IDs that will be deleted
psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" <<EOF >> "$audit_file"
\set protocol_system_name '$protocol_system_to_delete'

--- List of protocol components to be deleted
SELECT external_id AS "Protocol components to delete" FROM protocol_component
WHERE protocol_system_id = (SELECT id FROM protocol_system WHERE name = :'protocol_system_name');

--- List of accounts to be deleted
SELECT DISTINCT '0x' || encode(a.address::bytea, 'hex') AS "Contracts to delete"
FROM account a
JOIN contract_code cc ON a.id = cc.account_id
JOIN protocol_component_holds_contract pchc ON pchc.contract_code_id = cc.id
JOIN protocol_component pc ON pchc.protocol_component_id = pc.id
JOIN protocol_system ps ON pc.protocol_system_id = ps.id
WHERE ps.name = :'protocol_system_name'
AND NOT EXISTS (
    SELECT 1
    FROM protocol_component_holds_contract pchc2
    JOIN protocol_component pc2 ON pchc2.protocol_component_id = pc2.id
    JOIN protocol_system ps2 ON pc2.protocol_system_id = ps2.id
    WHERE pchc2.contract_code_id = cc.id
    AND ps2.name <> :'protocol_system_name'
)
AND NOT EXISTS (
    SELECT 1
    FROM protocol_component_holds_token pcht
    JOIN token t ON pcht.token_id = t.id 
    JOIN protocol_component pc2 ON pcht.protocol_component_id = pc2.id
    JOIN protocol_system ps2 ON pc2.protocol_system_id = ps2.id
    WHERE t.account_id = a.id
    AND ps2.name <> :'protocol_system_name'
);

--- List of tokens to be deleted
SELECT t.symbol AS "Token Symbol", '0x' || encode(a.address::bytea, 'hex') AS "Token Address", t.id AS "Token ID"
FROM token t
JOIN account a ON t.account_id = a.id
JOIN protocol_component_holds_token pcht ON t.id = pcht.token_id
JOIN protocol_component pc ON pcht.protocol_component_id = pc.id
JOIN protocol_system ps ON pc.protocol_system_id = ps.id
GROUP BY t.symbol, a.address, t.id
HAVING COUNT(DISTINCT CASE WHEN ps.name <> :'protocol_system_name' THEN ps.id END) = 0;
EOF

echo "Audit log written to $audit_file."
echo "View the log if you want to verify what will be deleted."

# Prompt user to confirm deletion
read -p "Do you want to proceed with the deletion? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Exiting..."
    exit 1
fi

echo "Deleting all db entries related to $protocol_system_to_delete..."

# Execute deletion
psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" <<EOF
\set protocol_system_name '$protocol_system_to_delete'

BEGIN;

--- Find and remove all token tokens exclusively linked to the protocol components of the system being deleted. Accounts
--- linked to these tokens will also be deleted.
WITH tokens_to_delete AS (
    --- Select the tokens that should be deleted
    SELECT t.id, a.id AS account_id
    FROM token t
    JOIN account a ON t.account_id = a.id
    JOIN protocol_component_holds_token pcht ON t.id = pcht.token_id
    JOIN protocol_component pc ON pcht.protocol_component_id = pc.id
    JOIN protocol_system ps ON pc.protocol_system_id = ps.id
    GROUP BY t.id, a.id
    HAVING COUNT(DISTINCT CASE WHEN ps.name <> :'protocol_system_name' THEN ps.id END) = 0
)
--- Delete the linked accounts (tokens will be cascade deleted)
DELETE FROM account
WHERE id IN (SELECT account_id FROM tokens_to_delete);

--- Find and remove all linked accounts (accounts are not cascade deleted). Note, this will cascade delete the linked contract
--- code entries too.
DELETE FROM account
WHERE id IN (
    SELECT DISTINCT cc.account_id
    FROM contract_code cc
    JOIN protocol_component_holds_contract pchc ON pchc.contract_code_id = cc.id
    JOIN protocol_component pc ON pchc.protocol_component_id = pc.id
    JOIN protocol_system ps ON pc.protocol_system_id = ps.id
    WHERE ps.name = :'protocol_system_name'
    AND NOT EXISTS (
        SELECT 1
        FROM protocol_component_holds_contract pchc2
        JOIN protocol_component pc2 ON pchc2.protocol_component_id = pc2.id
        JOIN protocol_system ps2 ON pc2.protocol_system_id = ps2.id
        WHERE pchc2.contract_code_id = cc.id
        AND ps2.name <> :'protocol_system_name'
    )
    AND NOT EXISTS (
        SELECT 1
        FROM protocol_component_holds_token pcht
        JOIN token t ON pcht.token_id = t.id 
        JOIN protocol_component pc2 ON pcht.protocol_component_id = pc2.id
        JOIN protocol_system ps2 ON pc2.protocol_system_id = ps2.id
        WHERE t.account_id = cc.account_id
        AND ps2.name <> :'protocol_system_name'
    )
);

-- Cascade delete protocol system and all related entries
DELETE FROM protocol_system
WHERE name = :'protocol_system_name';

-- Delete substreams cursor
DELETE FROM extraction_state
WHERE name = :'protocol_system_name';

COMMIT;
EOF
