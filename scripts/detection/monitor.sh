#!/bin/bash

# Security Monitoring Container Startup Script
set -e

LOG_DIR="/var/log/security-monitor"
AUDIT_LOG="${LOG_DIR}/audit.log"
CMD_LOG="${LOG_DIR}/commands.log"
FILE_LOG="${LOG_DIR}/file-changes.log"
THREAT_LOG="${LOG_DIR}/threats.log"
USER_LOG="${LOG_DIR}/users.log"

echo "[$(date +'%Y-%m-%d %H:%M:%S')] Security Monitor Starting..." | tee -a "${LOG_DIR}/monitor.log"

# Initialize AIDE database if not present
if [ ! -f /var/lib/aide/aide.db ]; then
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Initializing AIDE database..." | tee -a "${LOG_DIR}/monitor.log"
    aideinit >/dev/null 2>&1 || echo "AIDE initialization skipped - may run as unprivileged user"
fi

# Initialize auditd
if command -v auditctl &> /dev/null; then
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Loading audit rules..." | tee -a "${LOG_DIR}/monitor.log"
    auditctl -R /etc/audit/rules.d/security-monitor.rules 2>/dev/null || true
    auditctl -l >> "${LOG_DIR}/audit-rules.log" 2>&1 || true
fi

# Start rsyslog for centralized logging
if command -v rsyslogd &> /dev/null; then
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Starting rsyslog..." | tee -a "${LOG_DIR}/monitor.log"
    rm -f /var/run/rsyslogd.pid
    rsyslogd
fi

# Start osqueryd
if command -v osqueryd &> /dev/null; then
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Starting osqueryd..." | tee -a "${LOG_DIR}/monitor.log"
    osqueryd --config_path=/etc/osquery/osquery.conf --pidfile=/var/run/osqueryd.pid --daemonize
fi

# Start fail2ban
if command -v fail2ban-server &> /dev/null; then
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Starting fail2ban..." | tee -a "${LOG_DIR}/monitor.log"
    mkdir -p /var/run/fail2ban
    fail2ban-server >/dev/null 2>&1 || true
fi

# Create initial snapshot
echo "[$(date +'%Y-%m-%d %H:%M:%S')] Taking initial system snapshot..." | tee -a "${LOG_DIR}/monitor.log"
{
    echo "=== SYSTEM SNAPSHOT ==="
    echo "Time: $(date)"
    echo ""
    echo "=== USERS ==="
    w || echo "w command failed - possibly missing utmp"
    echo ""
    echo "=== LOGIN HISTORY ==="
    lastlog 2>/dev/null | head -20 || echo "lastlog not available"
    echo ""
    echo "=== PROCESSES ==="
    ps aux
    echo ""
    echo "=== NETWORK CONNECTIONS ==="
    netstat -tulnp 2>/dev/null || ss -tulnp
} > "${LOG_DIR}/initial-snapshot.txt" 2>&1

# Monitor audit logs (Start once outside the loop)
if [ -f /var/log/audit/audit.log ]; then
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Starting audit log monitoring..." | tee -a "${LOG_DIR}/monitor.log"
    tail -f /var/log/audit/audit.log >> "${AUDIT_LOG}" 2>&1 &
elif [ -f /host/var/log/audit/audit.log ]; then
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Starting host audit log monitoring..." | tee -a "${LOG_DIR}/monitor.log"
    tail -f /host/var/log/audit/audit.log >> "${AUDIT_LOG}" 2>&1 &
fi

# Monitoring loop
COUNTER=0
while true; do
    COUNTER=$((COUNTER + 1))
    TIMESTAMP="$(date +'%Y-%m-%d %H:%M:%S')"
    
    # Check for new user logins
    w >> "${USER_LOG}" 2>&1 || true
    
    # Check for file integrity changes every 5 minutes
    if [ $((COUNTER % 5)) -eq 0 ]; then
        echo "[${TIMESTAMP}] Running periodic security checks..." >> "${LOG_DIR}/monitor.log"
        if command -v aide &> /dev/null; then
            aide --check >> "${FILE_LOG}" 2>&1 || true
        fi
        
        # Check for suspicious processes
        /usr/local/bin/security-scripts/threat-detector.sh >> "${THREAT_LOG}" 2>&1 || true
    fi
    
    # Log current connections and processes
    {
        echo "[${TIMESTAMP}] Active Connections:"
        netstat -tulnp 2>/dev/null || ss -tulnp
        echo ""
        echo "[${TIMESTAMP}] Recent Process Activity:"
        ps aux --sort=-etime | head -20
    } >> "${LOG_DIR}/system-activity.log" 2>&1
    
    # Check for kernel security warnings
    dmesg | tail -20 >> "${LOG_DIR}/kernel-events.log" 2>&1 || true
    
    sleep 60
done
