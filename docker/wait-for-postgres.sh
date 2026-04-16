#!/bin/bash

set -e

host="$1"
shift
cmd="$@"

until echo > /dev/tcp/"$host"/5432; do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 1
done

>&2 echo "Postgres is up - executing command"
exec $cmd
