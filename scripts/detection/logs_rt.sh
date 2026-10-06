#!/bin/bash

# Security Monitor - Real-time Logs
# This script tails the logs from the local directory mapped to the container

LOG_DIR="./logs"

if [ ! -d "$LOG_DIR" ]; then
    echo "Error: Logs directory $LOG_DIR not found. Is the container running?"
    exit 1
fi

echo "--- Tailing Security Monitor Logs (Ctrl+C to stop) ---"
tail -f "$LOG_DIR"/monitor.log "$LOG_DIR"/threats.log "$LOG_DIR"/audit.log 2>/dev/null
