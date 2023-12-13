#!/bin/bash

BLOCK_NUMBER=$1

if [ -z "$BLOCK_NUMBER" ]; then
    echo "Usage: ./download_blocks.sh BLOCK_NUMBER"
    exit 1
fi

OUTPUT=$(substreams run -e mainnet.eth.streamingfast.io:443 ../substreams-explorers/ethereum-explorer/substreams.yaml map_block_full --start-block $BLOCK_NUMBER --stop-block +1)

# Remove log lines
CLEAN_JSON=$(echo "$OUTPUT" | perl -0777 -pe 's/^.*?({.*}).*$/$1/s')

# Extract the data from "@data" key using jq
DATA=$(echo "$CLEAN_JSON" | jq -r '.["@data"]')

echo "$DATA" | aws s3 cp - s3://defibot-data/test-assets/tycho/block_$BLOCK_NUMBER.json

