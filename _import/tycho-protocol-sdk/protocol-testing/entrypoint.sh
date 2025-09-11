#!/bin/bash
set -e

if [ "$#" -lt 1 ]; then
	echo "Usage: $0 protocol1[=filter] [protocol2 ...] or \"$0 'protocol1[=filter] protocol2'\""
	exit 1
fi

if [ "$#" -eq 1 ] && [[ "$1" == *" "* ]]; then
	IFS=' ' read -r -a args <<< "$1"
else
	args=("$@")
fi

for test in "${args[@]}"; do
	protocol="${test%%=*}"
	filter="${test#*=}"
	if [[ "$test" == *"="* ]]; then
		tycho-protocol-sdk --package "$protocol" --db-url "$DATABASE_URL" --match-test "$filter"
	else
	  tycho-protocol-sdk --package "$protocol" --db-url "$DATABASE_URL"
	fi
done
