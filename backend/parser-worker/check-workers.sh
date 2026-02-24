#!/bin/bash

echo "Checking for parser-worker processes..."
echo ""

# Find all node processes running dist/index.js
WORKERS=$(ps aux | grep "node.*dist/index.js" | grep -v grep)

if [ -z "$WORKERS" ]; then
    echo "✓ No parser-worker processes found."
else
    echo "⚠ Found parser-worker process(es):"
    echo "$WORKERS" | while read line; do
        PID=$(echo "$line" | awk '{print $2}')
        CMD=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
        echo "  PID: $PID"
        echo "  Command: $CMD"
        echo ""
    done
fi

echo ""
echo "All Node.js processes:"
ps aux | grep node | grep -v grep | awk '{printf "PID: %-8s %s\n", $2, substr($0, index($0,$11))}'
