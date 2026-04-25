#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 <command>"
    exit 1
fi

TIME_OUT=$(mktemp)

/usr/bin/time -f "%e %M %P %U %S" -o "$TIME_OUT" "$@"

STATS=$(awk '$1 ~ /^[0-9.]+$/ && NF >= 5 {print $0; exit}' "$TIME_OUT")

read -r ELAPSED_SEC MAX_RSS_KB CPU_PER USER_SEC SYS_SEC <<< "$STATS"
rm "$TIME_OUT"

ELAPSED_INT=$(awk "BEGIN {print int($ELAPSED_SEC)}")
MAX_RSS_MB=$(awk "BEGIN {print int($MAX_RSS_KB / 1024)}")

printf "Elapsed (wall clock) time: %d s\n" "$ELAPSED_SEC"
printf "Maximum resident set size: %d MB\n" "$MAX_RSS_MB"