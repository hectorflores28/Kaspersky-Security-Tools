#!/bin/bash

# Threat Detection Script
TIMESTAMP="$(date +'%Y-%m-%d %H:%M:%S')"
THREAT_SCORE=0
ALERTS=()

echo "[${TIMESTAMP}] ========== THREAT DETECTION SCAN ==========="

# 1. Check for suspicious processes
echo "[${TIMESTAMP}] Checking for suspicious processes..."
SUSPICIOUS_PROCS=$(ps aux | grep -E '(nc|ncat|netcat|bash|sh|python|perl|ruby)' | grep -v grep | wc -l)
if [ "${SUSPICIOUS_PROCS}" -gt 5 ]; then
    THREAT_SCORE=$((THREAT_SCORE + 20))
    ALERTS+=("HIGH: Suspicious process count: ${SUSPICIOUS_PROCS}")
fi

# 2. Check for unauthorized SSH keys
echo "[${TIMESTAMP}] Checking SSH keys..."
if [ -f /root/.ssh/authorized_keys ]; then
    SSH_KEYS=$(wc -l < /root/.ssh/authorized_keys)
    if [ "${SSH_KEYS}" -gt 5 ]; then
        THREAT_SCORE=$((THREAT_SCORE + 15))
        ALERTS+=("MEDIUM: Multiple SSH keys detected: ${SSH_KEYS}")
    fi
fi

# 3. Check for recently modified critical files
echo "[${TIMESTAMP}] Checking file modifications..."
for FILE in /etc/passwd /etc/shadow /etc/sudoers /root/.bashrc /root/.bash_history; do
    if [ -f "${FILE}" ]; then
        MTIME=$(find "${FILE}" -mmin -30 2>/dev/null)
        if [ -n "${MTIME}" ]; then
            THREAT_SCORE=$((THREAT_SCORE + 25))
            ALERTS+=("HIGH: Recently modified critical file: ${FILE}")
        fi
    fi
done

# 4. Check for unusual network connections
echo "[${TIMESTAMP}] Checking network connections..."
ESTABLISHED=$(netstat -an 2>/dev/null | grep ESTABLISHED | wc -l || ss -an | grep ESTABLISHED | wc -l)
if [ "${ESTABLISHED}" -gt 50 ]; then
    THREAT_SCORE=$((THREAT_SCORE + 10))
    ALERTS+=("MEDIUM: High number of established connections: ${ESTABLISHED}")
fi

# 5. Check for rootkits
if command -v chkrootkit &> /dev/null; then
    echo "[${TIMESTAMP}] Running rootkit detection..."
    ROOTKIT_RESULTS=$(chkrootkit 2>/dev/null | grep -i "INFECTED" | wc -l)
    if [ "${ROOTKIT_RESULTS}" -gt 0 ]; then
        THREAT_SCORE=$((THREAT_SCORE + 50))
        ALERTS+=("CRITICAL: Rootkit indicators detected!")
    fi
fi

# 6. Check for hidden processes
echo "[${TIMESTAMP}] Checking for hidden processes..."
PS_COUNT=$(ps aux | wc -l)
PROC_COUNT=$(ls -la /proc | grep "^d" | wc -l)
if [ "${PROC_COUNT}" -gt $((PS_COUNT + 10)) ]; then
    THREAT_SCORE=$((THREAT_SCORE + 40))
    ALERTS+=("CRITICAL: Hidden processes detected (process discrepancy)!")
fi

# 7. Check for suspicious cron jobs
echo "[${TIMESTAMP}] Checking cron jobs..."
if [ -d /etc/cron.d ]; then
    CRON_COUNT=$(find /etc/cron.d -type f | wc -l)
    if [ "${CRON_COUNT}" -gt 10 ]; then
        THREAT_SCORE=$((THREAT_SCORE + 15))
        ALERTS+=("MEDIUM: Unusual number of cron jobs: ${CRON_COUNT}")
    fi
fi

# 8. Check disk space
echo "[${TIMESTAMP}] Checking disk space..."
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "${DISK_USAGE}" -gt 90 ]; then
    THREAT_SCORE=$((THREAT_SCORE + 5))
    ALERTS+=("LOW: High disk usage: ${DISK_USAGE}%")
fi

# 9. Check for suspicious environment variables
echo "[${TIMESTAMP}] Checking environment..."
if env | grep -E 'LD_PRELOAD|LD_LIBRARY_PATH' | grep -v "^#"; then
    THREAT_SCORE=$((THREAT_SCORE + 30))
    ALERTS+=("HIGH: Suspicious LD_* environment variables detected!")
fi

# 10. Check system load
echo "[${TIMESTAMP}] Checking system load..."
LOAD=$(uptime | awk '{print $(NF-2)}' | sed 's/,//')
if (( $(echo "$LOAD > 5.0" | bc -l) )); then
    THREAT_SCORE=$((THREAT_SCORE + 5))
    ALERTS+=("LOW: High system load: ${LOAD}")
fi

# Output results
echo ""
echo "[${TIMESTAMP}] ========== SCAN RESULTS ==========="
echo "Threat Score: ${THREAT_SCORE}/100"

if [ ${#ALERTS[@]} -gt 0 ]; then
    echo "Alerts:"
    for alert in "${ALERTS[@]}"; do
        echo "  * ${alert}"
    done
else
    echo "No threats detected."
fi

# Risk assessment
if [ "${THREAT_SCORE}" -gt 70 ]; then
    echo "[${TIMESTAMP}] RISK LEVEL: CRITICAL - Immediate action required!"
    exit 1
elif [ "${THREAT_SCORE}" -gt 40 ]; then
    echo "[${TIMESTAMP}] RISK LEVEL: HIGH - Investigation recommended."
    exit 1
elif [ "${THREAT_SCORE}" -gt 20 ]; then
    echo "[${TIMESTAMP}] RISK LEVEL: MEDIUM - Monitor closely."
    exit 0
else
    echo "[${TIMESTAMP}] RISK LEVEL: LOW - System appears normal."
    exit 0
fi
