#!/bin/bash

#  Enables or disables the transaction cleanup cronjob in the database.
#  TO USE: run the following cli command: './toggle_transaction_cleanup_cronjob.sh <database_name> <enable|disable> [<port_number>]'

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 <database_name> <enable|disable> [<port_number>]"
    exit 1
fi

# Set the database, action, and optional port number
db_name=$1
action=$2
port_number=${3:-5432} # Default port is 5432 if not provided

# Validate action parameter
if [ "$action" != "enable" ] && [ "$action" != "disable" ]; then
    echo "Error: action must be either 'enable' or 'disable'"
    exit 1
fi

# Convert action to boolean for SQL
if [ "$action" == "enable" ]; then
    active_value="TRUE"
    action_verb="enabling"
else
    active_value="FALSE"
    action_verb="disabling"
fi

echo ""
echo "Connecting to $db_name..."

# Prompt user for username and password
read -p "Enter PostgreSQL username: " db_user
read -s -p "Enter PostgreSQL password: " db_password
echo

# Export password to PGPASSWORD environment variable so psql doesn't prompt for it again
export PGPASSWORD="$db_password"

echo ""
echo "Checking current status of clean_transaction_table cronjob..."

# Check current status
current_status=$(psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" -t -A <<EOF
SELECT active FROM cron.job WHERE jobname = 'clean_transaction_table';
EOF
)

if [ -z "$current_status" ]; then
    echo "Error: cronjob 'clean_transaction_table' not found in the database."
    exit 1
fi

# Trim whitespace
current_status=$(echo "$current_status" | xargs)

if [ "$current_status" == "t" ] || [ "$current_status" == "true" ]; then
    current_status_display="enabled"
else
    current_status_display="disabled"
fi

echo "Current status: $current_status_display"

# Check if already in desired state
if [ "$action" == "enable" ] && [ "$current_status" == "t" ]; then
    echo "Cronjob is already enabled. No changes needed."
    exit 0
elif [ "$action" == "disable" ] && [ "$current_status" == "f" ]; then
    echo "Cronjob is already disabled. No changes needed."
    exit 0
fi

echo ""
echo "This will $action the clean_transaction_table cronjob."
read -p "Are you ready to proceed? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Exiting..."
    exit 1
fi

echo ""
echo "$action_verb clean_transaction_table cronjob..."

# Execute the update
psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" <<EOF
BEGIN;

UPDATE cron.job 
SET active = $active_value 
WHERE jobname = 'clean_transaction_table';

COMMIT;
EOF

if [ $? -eq 0 ]; then
    echo ""
    echo "Successfully $action the clean_transaction_table cronjob."
    
    # Verify the change
    new_status=$(psql -d "$db_name" -h localhost -p "$port_number" -U "$db_user" -t -A <<EOF
SELECT active FROM cron.job WHERE jobname = 'clean_transaction_table';
EOF
)
    new_status=$(echo "$new_status" | xargs)
    
    if [ "$new_status" == "t" ] || [ "$new_status" == "true" ]; then
        new_status_display="enabled"
    else
        new_status_display="disabled"
    fi
    
    echo "New status: $new_status_display"
else
    echo ""
    echo "Error: Failed to update the cronjob status."
    exit 1
fi

