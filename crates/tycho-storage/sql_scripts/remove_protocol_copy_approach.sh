#!/bin/bash

#  Removes a protocol system and all related entries from the database.
#  This script uses the table copy approach for safe deletion.
#  Note - linked blocks, transactions and accounts shared with other systems will not be removed.
#  TO USE: run the following cli command: './remove_protocol_copy_approach.sh <database_name> <protocol_system_to_delete> [<port_number>]'

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 <database_name> <protocol_system_to_delete> [<port_number>]"
    exit 1
fi

# Set the database, protocol system, and optional port number
db_name=$1
protocol_system_to_delete=$2
port_number=${3:-5432} # Default port is 5432 if not provided

# Check if SQL script exists
sql_script="remove_protocol_copy_approach.sql"
if [ ! -f "$sql_script" ]; then
    echo "Error: SQL script '$sql_script' not found in current directory."
    exit 1
fi

# Warning message
echo ""
echo "=========================================="
echo "  PROTOCOL SYSTEM DELETION (COPY METHOD)"
echo "=========================================="
echo ""
echo "Database:        $db_name"
echo "Protocol System: $protocol_system_to_delete"
echo "Port:            $port_number"
echo ""
echo "⚠️  WARNING: This operation will:"
echo "   - Create new copies of affected tables"
echo "   - Delete all data related to '$protocol_system_to_delete'"
echo "   - Require exclusive table locks during execution"
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

# Create an audit file to log what will be deleted
audit_file="audit_${protocol_system_to_delete}_deletion_$(date '+%Y%m%d_%H%M%S').log"
current_date=$(date '+%Y-%m-%d %H:%M:%S')
echo "Audit log for deletion of protocol system: $protocol_system_to_delete" > "$audit_file"
echo "Date: $current_date" >> "$audit_file"
echo "Database: $db_name" >> "$audit_file"
echo "Method: Table copy approach" >> "$audit_file"
echo "-----------------------------------------" >> "$audit_file"
echo "" >> "$audit_file"

echo ""
echo "Analyzing $db_name..."

# Collect the list of components, contracts, and tokens that will be deleted
psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" <<EOF >> "$audit_file"
\set protocol_system_name '$protocol_system_to_delete'

-- Protocol components to be deleted
SELECT '' AS section;
SELECT 'PROTOCOL COMPONENTS TO DELETE' AS section;
SELECT COUNT(*) AS component_count FROM protocol_component
WHERE protocol_system_id = (SELECT id FROM protocol_system WHERE name = :'protocol_system_name');

SELECT external_id AS component_external_id FROM protocol_component
WHERE protocol_system_id = (SELECT id FROM protocol_system WHERE name = :'protocol_system_name')
ORDER BY external_id;

-- Tokens to be deleted
SELECT '' AS section;
SELECT 'TOKENS TO DELETE' AS section;
SELECT DISTINCT t.id, t.symbol, '0x' || encode(a.address::bytea, 'hex') AS token_address
FROM token t
JOIN protocol_component_holds_token pcht ON t.id = pcht.token_id
JOIN protocol_component pc ON pcht.protocol_component_id = pc.id
JOIN protocol_system ps ON pc.protocol_system_id = ps.id
JOIN account a ON t.account_id = a.id
WHERE ps.name = :'protocol_system_name'
  AND a.address != '\x0000000000000000000000000000000000000000'
  AND NOT EXISTS (
    SELECT 1
    FROM protocol_component_holds_token pcht2
    JOIN protocol_component pc2 ON pcht2.protocol_component_id = pc2.id
    JOIN protocol_system ps2 ON pc2.protocol_system_id = ps2.id
    WHERE pcht2.token_id = t.id
      AND ps2.name != :'protocol_system_name'
  )
ORDER BY t.symbol;

SELECT '' AS section;
SELECT 'SUMMARY' AS section;
SELECT 
    (SELECT COUNT(*) FROM protocol_component 
     WHERE protocol_system_id = (SELECT id FROM protocol_system WHERE name = :'protocol_system_name')) 
    AS total_components,
    (SELECT COUNT(DISTINCT t.id)
     FROM token t
     JOIN protocol_component_holds_token pcht ON t.id = pcht.token_id
     JOIN protocol_component pc ON pcht.protocol_component_id = pc.id
     JOIN protocol_system ps ON pc.protocol_system_id = ps.id
     JOIN account a ON t.account_id = a.id
     WHERE ps.name = :'protocol_system_name'
       AND a.address != '\x0000000000000000000000000000000000000000'
       AND NOT EXISTS (
         SELECT 1
         FROM protocol_component_holds_token pcht2
         JOIN protocol_component pc2 ON pcht2.protocol_component_id = pc2.id
         JOIN protocol_system ps2 ON pc2.protocol_system_id = ps2.id
         WHERE pcht2.token_id = t.id
           AND ps2.name != :'protocol_system_name'
       )) AS total_tokens;
EOF

echo ""
echo "✓ Analysis complete."
echo "📄 Audit log written to: $audit_file"
echo ""
echo "Please review the audit log to verify what will be deleted."
echo ""

# Prompt user to confirm deletion
read -p "Do you want to proceed with the deletion? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Exiting..."
    exit 1
fi

echo ""
echo "=========================================="
echo "  STARTING DELETION PROCESS"
echo "=========================================="
echo ""
echo "⏳ Executing deletion script..."
echo "   This may take several minutes depending on data size."
echo ""

# Execute deletion using the SQL file with variable substitution
# Create a temporary file with the variable substituted
temp_sql=$(mktemp)
sed "s/\${protocol_system_to_delete}/$protocol_system_to_delete/g" "$sql_script" > "$temp_sql"

# Execute the SQL script and capture output
start_time=$(date +%s)
if psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" -f "$temp_sql" 2>&1 | tee -a "$audit_file"; then
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    echo "" | tee -a "$audit_file"
    echo "=========================================="
    echo "  ✓ DELETION COMPLETED SUCCESSFULLY"
    echo "=========================================="
    echo ""
    echo "Duration: ${duration} seconds"
    echo "Protocol system '$protocol_system_to_delete' has been removed."
    echo ""
    echo "Full execution log saved to: $audit_file"
else
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    echo "" | tee -a "$audit_file"
    echo "=========================================="
    echo "  ❌ DELETION FAILED"
    echo "=========================================="
    echo ""
    echo "Duration: ${duration} seconds"
    echo "An error occurred during deletion."
    echo "Check the audit log for details: $audit_file"
    echo ""
    echo "⚠️  Note: All changes have been rolled back due to transaction failure."
    
    # Clean up temp file
    rm -f "$temp_sql"
    exit 1
fi

# Clean up temp file
rm -f "$temp_sql"

echo ""
echo "Done! 🎉"