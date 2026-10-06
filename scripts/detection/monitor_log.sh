#!/bin/bash

# Security Monitor - Status and Startup Logs
# Shows the current container status and the last few lines of the container's output

CONTAINER_NAME="security-monitor"

echo "=== Container Status ==="
docker ps -a --filter "name=$CONTAINER_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.RunningFor}}"

echo ""
echo "=== Last 20 Startup Log Lines ==="
docker logs --tail 20 "$CONTAINER_NAME"

echo ""
echo "=== Health Status ==="
docker inspect --format='{{json .State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "Health check not initialized or container not found."
