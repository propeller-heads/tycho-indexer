#!/bin/bash
set -e

usage() {
    cat << EOF
Usage: $0 [--db-url URL]

Optional:
  --db-url URL     PostgreSQL connection URL 
                   (default: postgresql://postgres:mypassword@localhost:5431/tycho_indexer_0)

Example:
  $0
  $0 --db-url postgresql://user:pass@host:5432/dbname
EOF
    exit 1
}

# Defaults
DB_URL="postgresql://postgres:mypassword@localhost:5431/tycho_indexer_0"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --db-url) DB_URL="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1"; usage ;;
    esac
done

# Update component_tvl table
echo "Aggregating component TVL..."

TVL_RESULT=$(psql "$DB_URL" -t -c "
INSERT INTO component_tvl (protocol_component_id, tvl)
SELECT
    bal.protocol_component_id as protocol_component_id,
    SUM(bal.balance_float / token_price.price) as tvl
FROM
    component_balance AS bal
INNER JOIN
    token_price ON bal.token_id = token_price.token_id
WHERE
    bal.valid_to = '262143-01-01 00:59:59.999999+01'
GROUP BY
    bal.protocol_component_id
ON CONFLICT (protocol_component_id)
DO UPDATE SET
    tvl = EXCLUDED.tvl
RETURNING protocol_component_id;
")

TVL_ROWS=$(echo "$TVL_RESULT" | grep -v '^$' | wc -l)

echo "Done! Updated $TVL_ROWS component TVL entries"