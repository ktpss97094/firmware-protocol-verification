#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Use sudo to run this script"
    exit 1
fi

if [ $# -eq 0 ]; then
    echo "Usage: $0 <command>"
    exit 1
fi

cleanup() {
    sysctl -w kernel.randomize_va_space=2 > /dev/null
}

trap cleanup EXIT

TIME_OUT=$(mktemp)

sysctl -w kernel.randomize_va_space=0 > /dev/null
sync; echo 3 > /proc/sys/vm/drop_caches

/usr/bin/time -f "%e %M %P %U %S" -o "$TIME_OUT" "$@"

STATS=$(awk '$1 ~ /^[0-9.]+$/ && NF >= 5 {print $0; exit}' "$TIME_OUT")
read -r ELAPSED_SEC MAX_RSS_KB CPU_PER USER_SEC SYS_SEC <<< "$STATS"
rm "$TIME_OUT"

ELAPSED_SEC=$(awk "BEGIN {print int($ELAPSED_SEC)}")
MAX_RSS_MB=$(awk "BEGIN {print int($MAX_RSS_KB / 1024)}")

printf "Elapsed (wall clock) time: %d s\n" "$ELAPSED_SEC"
printf "Maximum resident set size: %d MB\n" "$MAX_RSS_MB"