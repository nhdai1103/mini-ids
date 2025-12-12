#!/bin/bash
# Script để test SSH brute-force trên Ubuntu

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         🔐 SSH BRUTE-FORCE TEST 🔐                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo

echo "📋 Script này sẽ thực hiện SSH failed login attempts"
echo "   để test Mini IDS"
echo

# Target
TARGET=${1:-localhost}
echo "🎯 Target: $TARGET"
echo

# Test 1: Brute-force với các username phổ biến
echo "1️⃣ Testing brute-force (10 attempts)..."
USERS=("admin" "root" "test" "user" "guest" "oracle" "mysql" "postgres" "admin" "root")

for i in {0..9}; do
    user=${USERS[$i]}
    echo "   [$((i+1))/10] Trying: $user@$TARGET"
    
    # Sử dụng timeout để tự động fail sau 2 giây
    timeout 2 ssh -o ConnectTimeout=2 \
                   -o StrictHostKeyChecking=no \
                   -o UserKnownHostsFile=/dev/null \
                   -o PreferredAuthentications=password \
                   ${user}@${TARGET} \
                   2>/dev/null || true
    
    sleep 0.5
done

echo "   ✅ Completed 10 failed attempts"
echo

# Test 2: SQL Injection payloads
echo "2️⃣ Testing SQL Injection payloads..."
SQL_PAYLOADS=(
    "admin' OR '1'='1"
    "root'--"
    "test' UNION SELECT"
)

for payload in "${SQL_PAYLOADS[@]}"; do
    echo "   Testing: $payload"
    timeout 2 ssh -o ConnectTimeout=2 \
                   -o StrictHostKeyChecking=no \
                   -o UserKnownHostsFile=/dev/null \
                   "${payload}@${TARGET}" \
                   2>/dev/null || true
    sleep 0.3
done

echo "   ✅ Completed SQL Injection tests"
echo

# Test 3: Command Injection
echo "3️⃣ Testing Command Injection..."
CMD_PAYLOADS=(
    "admin; cat /etc/passwd"
    "root | whoami"
    "test && ls"
)

for payload in "${CMD_PAYLOADS[@]}"; do
    echo "   Testing: $payload"
    timeout 2 ssh -o ConnectTimeout=2 \
                   -o StrictHostKeyChecking=no \
                   -o UserKnownHostsFile=/dev/null \
                   "${payload}@${TARGET}" \
                   2>/dev/null || true
    sleep 0.3
done

echo "   ✅ Completed Command Injection tests"
echo

# Test 4: Path Traversal
echo "4️⃣ Testing Path Traversal..."
PATH_PAYLOADS=(
    "../../../root"
    "..\\..\\..\\admin"
)

for payload in "${PATH_PAYLOADS[@]}"; do
    echo "   Testing: $payload"
    timeout 2 ssh -o ConnectTimeout=2 \
                   -o StrictHostKeyChecking=no \
                   -o UserKnownHostsFile=/dev/null \
                   "${payload}@${TARGET}" \
                   2>/dev/null || true
    sleep 0.3
done

echo "   ✅ Completed Path Traversal tests"
echo

# Summary
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ✅ HOÀN THÀNH! Đã tạo SSH logs                           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo
echo "📊 Tổng cộng:"
echo "   • 10 brute-force attempts"
echo "   • 3 SQL injection attempts"
echo "   • 3 command injection attempts"
echo "   • 2 path traversal attempts"
echo
echo "🔍 Kiểm tra kết quả:"
echo "   1. Monitor sẽ hiển thị cảnh báo trong console"
echo "   2. Xem logs: sudo tail -20 /var/log/auth.log | grep sshd"
echo "   3. Xem alerts: sqlite3 alerts.db 'SELECT * FROM alerts;'"
echo "   4. Dashboard: python3 app.py (http://localhost:5000)"
echo
