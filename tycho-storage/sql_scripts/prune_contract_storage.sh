#!/bin/bash

#  Prunes contract_storage for a given address by removing entries whose slots were not detected by DCI (i.e. are not 
#  present in any entry_point_tracing_result's accessed_slots).
#  This is intended to be used if fully indexing a contract is not desire (millions of slots to index) and you only added
#  the contract to the DCI blacklist after it was already indexed.
#  TO USE: run the following cli command: './prune_contract_storage.sh <database_name> <contract_address> [<port_number>]'

# Exit on any error
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 <database_name> <contract_address> [<port_number>]"
    exit 1
fi

# Set the database, contract address, and optional port number
db_name=$1
contract_address=$2
port_number=${3:-5432} # Default port is 5432 if not provided

# Normalize address (remove 0x prefix for consistency in display)
display_address=${contract_address#0x}

echo ""
echo "=========================================="
echo "  CONTRACT STORAGE CLEANUP"
echo "=========================================="
echo ""
echo "Database:        $db_name"
echo "Contract:        0x$display_address"
echo "Port:            $port_number"
echo ""
echo "⚠️  WARNING: This operation will:"
echo "   - Delete contract_storage entries for 0x$display_address"
echo "   - Only keep slots that exist in entry_point_tracing_result's accessed_slots"
echo "   - This operation cannot be undone"
echo ""
echo "RECOMMENDATION: Take a database snapshot before proceeding."
echo ""
read -p "Are you ready to proceed? (y/n) " -n 1 -r
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

# Export password to PGPASSWORD environment variable
export PGPASSWORD="$db_password"

# Test connection
echo ""
echo "Testing database connection..."
if ! psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" -c "SELECT 1;" > /dev/null 2>&1; then
    echo "❌ Error: Failed to connect to database."
    exit 1
fi
echo "✓ Connection successful."

echo ""
echo "Analyzing $db_name..."
echo ""

# Collect and display information about what will be affected
echo "Account Information:"
echo "--------------------"
if ! account_info=$(psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" -t -A 2>&1 <<EOF
\set address '0x$display_address'
SELECT 
    id || '|' ||
    '0x' || encode(address::bytea, 'hex') || '|' ||
    COALESCE(title, 'N/A') || '|' ||
    chain_id
FROM account
WHERE address = decode(
    CASE 
        WHEN :'address' LIKE '0x%' THEN substring(:'address' from 3)
        ELSE :'address'
    END,
    'hex'
)
LIMIT 1;
EOF
); then
    echo "❌ Error querying account information:"
    echo "$account_info"
    exit 1
fi

if [ -z "$account_info" ]; then
    echo "  ❌ Account not found for address: 0x$display_address"
    echo ""
    echo "Exiting..."
    exit 1
fi

IFS='|' read -r account_id account_hex account_title chain_id <<< "$account_info"
echo "  Account ID: $account_id"
echo "  Address:   $account_hex"
echo "  Title:     $account_title"
echo "  Chain ID:  $chain_id"
echo ""

echo "Current Contract Storage:"
echo "------------------------"
if ! total_storage=$(psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" -t -A 2>&1 <<EOF
\set address '0x$display_address'
SELECT COUNT(*)::text
FROM contract_storage cs
JOIN account a ON cs.account_id = a.id
WHERE a.address = decode(
    CASE 
        WHEN :'address' LIKE '0x%' THEN substring(:'address' from 3)
        ELSE :'address'
    END,
    'hex'
);
EOF
); then
    echo "❌ Error querying contract storage:"
    echo "$total_storage"
    exit 1
fi
echo "  Total storage entries: $total_storage"
echo ""

echo "Detected Slots from Tracing Results:"
echo "--------------------------------"
if ! valid_slots=$(psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" -t -A 2>&1 <<EOF
\set address '0x$display_address'
SELECT COUNT(slot_bytea)::text
FROM (
    SELECT DISTINCT
        decode(
            CASE 
                WHEN slot_hex LIKE '0x%' THEN substring(slot_hex from 3)
                ELSE slot_hex
            END,
            'hex'
        ) AS slot_bytea
    FROM entry_point_tracing_result,
    LATERAL jsonb_each_text(detection_data->'accessed_slots') AS contract_slots(contract_address, slots_array),
    LATERAL jsonb_array_elements_text(slots_array::jsonb) AS slot_hex
    WHERE contract_address = :'address'
       OR contract_address = '0x' || encode(decode(
           CASE 
               WHEN :'address' LIKE '0x%' THEN substring(:'address' from 3)
               ELSE :'address'
           END,
           'hex'
       ), 'hex')
) valid_slots;
EOF
); then
    echo "❌ Error querying valid slots:"
    echo "$valid_slots"
    exit 1
fi
echo "  Distinct slots found: $valid_slots"
echo ""

echo "Estimated Deletions:"
echo "-------------------"
if ! deletion_info=$(psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" -t -A 2>&1 <<EOF
\set address '0x$display_address'
WITH account_info AS (
    SELECT id AS account_id
    FROM account
    WHERE address = decode(
        CASE 
            WHEN :'address' LIKE '0x%' THEN substring(:'address' from 3)
            ELSE :'address'
        END,
        'hex'
    )
    LIMIT 1
),
valid_slots AS (
    SELECT DISTINCT
        decode(
            CASE 
                WHEN slot_hex LIKE '0x%' THEN substring(slot_hex from 3)
                ELSE slot_hex
            END,
            'hex'
        ) AS slot_bytea
    FROM entry_point_tracing_result,
    LATERAL jsonb_each_text(detection_data->'accessed_slots') AS contract_slots(contract_address, slots_array),
    LATERAL jsonb_array_elements_text(slots_array::jsonb) AS slot_hex
    WHERE contract_address = :'address'
       OR contract_address = '0x' || encode(decode(
           CASE 
               WHEN :'address' LIKE '0x%' THEN substring(:'address' from 3)
               ELSE :'address'
           END,
           'hex'
       ), 'hex')
)
SELECT 
    COALESCE((SELECT COUNT(*)::text FROM contract_storage cs, account_info ai WHERE cs.account_id = ai.account_id), '0') || '|' ||
    COALESCE((SELECT COUNT(*)::text FROM contract_storage cs, account_info ai, valid_slots vs 
     WHERE cs.account_id = ai.account_id AND cs.slot = vs.slot_bytea), '0') || '|' ||
    COALESCE((SELECT COUNT(*)::text FROM contract_storage cs, account_info ai 
     WHERE cs.account_id = ai.account_id 
     AND NOT EXISTS (SELECT 1 FROM valid_slots vs WHERE vs.slot_bytea = cs.slot)), '0');
EOF
); then
    echo "❌ Error estimating deletions:"
    echo "$deletion_info"
    exit 1
fi

IFS='|' read -r total_entries entries_to_keep entries_to_delete <<< "$deletion_info"
echo "  Total entries:    $total_entries"
echo "  Entries to keep: $entries_to_keep"
echo "  Entries to delete: $entries_to_delete"
echo ""

echo "✓ Analysis complete."
echo ""

# Prompt user to confirm deletion
read -p "Do you want to proceed with the cleanup? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Exiting..."
    exit 1
fi

echo ""
echo "=========================================="
echo "  STARTING CLEANUP PROCESS"
echo "=========================================="
echo ""
echo "⏳ Executing cleanup script..."
echo "   This may take several minutes depending on data size."
echo ""

# Execute cleanup
start_time=$(date +%s)
if psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" <<SQL_SCRIPT
BEGIN;

DO \$\$
DECLARE
    target_address_hex TEXT := '$contract_address';  -- Get from variable substitution
    target_address_bytea BYTEA;
    target_account_id BIGINT;
    deleted_count INTEGER := 0;
    valid_slots_count INTEGER := 0;
    total_storage_count INTEGER := 0;
BEGIN
    -- Remove 0x prefix if present and convert to bytea
    IF target_address_hex LIKE '0x%' THEN
        target_address_bytea := decode(substring(target_address_hex from 3), 'hex');
    ELSE
        target_address_bytea := decode(target_address_hex, 'hex');
    END IF;

    -- Get account_id for the given address
    SELECT id INTO target_account_id
    FROM account
    WHERE address = target_address_bytea
    LIMIT 1;

    IF target_account_id IS NULL THEN
        RAISE EXCEPTION 'Account not found for address: %', target_address_hex;
    END IF;

    RAISE NOTICE 'Found account_id: % for address: %', target_account_id, target_address_hex;

    -- Count total contract_storage entries for this account
    SELECT COUNT(*) INTO total_storage_count
    FROM contract_storage
    WHERE account_id = target_account_id;

    RAISE NOTICE 'Total contract_storage entries for this account: %', total_storage_count;

    -- Count valid slots from entry_point_tracing_result
    SELECT COUNT(DISTINCT slot_bytea) INTO valid_slots_count
    FROM (
        SELECT DISTINCT
            decode(
                CASE 
                    WHEN slot_hex LIKE '0x%' THEN substring(slot_hex from 3)
                    ELSE slot_hex
                END,
                'hex'
            ) AS slot_bytea
        FROM entry_point_tracing_result,
        LATERAL jsonb_each_text(detection_data->'accessed_slots') AS contract_slots(contract_address, slots_array),
        LATERAL jsonb_array_elements_text(slots_array::jsonb) AS slot_hex
        WHERE contract_address = target_address_hex
           OR contract_address = '0x' || encode(target_address_bytea, 'hex')
    ) valid_slots;

    RAISE NOTICE 'Found % valid slots in entry_point_tracing_result for address: %', valid_slots_count, target_address_hex;

    -- Delete contract_storage entries where slot is not in any accessed_slots
    -- for this contract address in entry_point_tracing_result
    WITH valid_slots AS (
        -- Extract all slots from accessed_slots where the target address is a key
        SELECT DISTINCT
            decode(
                CASE 
                    WHEN slot_hex LIKE '0x%' THEN substring(slot_hex from 3)
                    ELSE slot_hex
                END,
                'hex'
            ) AS slot_bytea
        FROM entry_point_tracing_result,
        LATERAL jsonb_each_text(detection_data->'accessed_slots') AS contract_slots(contract_address, slots_array),
        LATERAL jsonb_array_elements_text(slots_array::jsonb) AS slot_hex
        WHERE contract_address = target_address_hex
           OR contract_address = '0x' || encode(target_address_bytea, 'hex')
    )
    DELETE FROM contract_storage cs
    WHERE cs.account_id = target_account_id
      AND NOT EXISTS (
          SELECT 1
          FROM valid_slots vs
          WHERE vs.slot_bytea = cs.slot
      );

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RAISE NOTICE 'Deleted % contract_storage entries for address: %', deleted_count, target_address_hex;
    RAISE NOTICE 'Remaining contract_storage entries: %', total_storage_count - deleted_count;
END \$\$;

COMMIT;
SQL_SCRIPT
then
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    echo ""
    echo "=========================================="
    echo "  ✓ CLEANUP COMPLETED SUCCESSFULLY"
    echo "=========================================="
    echo ""
    echo "Duration: ${duration} seconds"
    echo "Contract storage cleanup for '0x$display_address' has been completed."
else
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    echo ""
    echo "=========================================="
    echo "  ❌ CLEANUP FAILED"
    echo "=========================================="
    echo ""
    echo "Duration: ${duration} seconds"
    echo "An error occurred during cleanup."
    echo ""
    echo "⚠️  Note: All changes have been rolled back due to transaction failure."
    exit 1
fi

echo ""
echo "Done! 🎉"

