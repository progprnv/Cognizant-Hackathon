#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# test_scenarios.sh  —  Demonstrate all fraud detection scenarios
# Run: bash test_scenarios.sh
# Requires: API running on localhost:8000
# ═══════════════════════════════════════════════════════════════

BASE="http://localhost:8000/api"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'

echo -e "\n${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  FraudShield AI — Scenario Test Suite${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}\n"

# ── 1. Register a user ────────────────────────────────────────
echo -e "${BOLD}1. Register Test User${NC}"
REGISTER=$(curl -s -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@bank.com","password":"SecurePass123!"}')
echo "$REGISTER" | python3 -m json.tool 2>/dev/null || echo "$REGISTER"
USER_ID=$(echo "$REGISTER" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
echo -e "User ID: $USER_ID\n"
sleep 0.5

# ── 2. Normal Login (LOW risk) ────────────────────────────────
echo -e "${GREEN}2. Normal Login → Expect ALLOW (LOW risk)${NC}"
curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "SecurePass123!",
    "behavioral": {
      "login_duration_ms": 5200,
      "keystroke_intervals": [110, 95, 130, 105, 120, 88, 115, 102, 97, 108, 125, 90],
      "mouse_event_count": 14,
      "typing_speed_wpm": 42
    },
    "device": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0",
      "screen_res": "1920x1080",
      "device_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
    },
    "ip_address": "192.168.1.100"
  }' | python3 -m json.tool 2>/dev/null
echo ""
sleep 0.5

# ── 3. Autofill Attack (HIGH risk) ───────────────────────────
echo -e "${RED}3. Autofill Attack → Expect BLOCK (HIGH risk)${NC}"
curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "SecurePass123!",
    "behavioral": {
      "login_duration_ms": 120,
      "keystroke_intervals": [],
      "mouse_event_count": 0,
      "autofill_suspected": true,
      "typing_speed_wpm": 0
    },
    "device": {
      "user_agent": "Mozilla/5.0 (Linux; Android 13) Chrome/125.0.0.0",
      "screen_res": "1080x2400",
      "device_id": "deadbeef12345678deadbeef12345678"
    },
    "ip_address": "45.33.99.101"
  }' | python3 -m json.tool 2>/dev/null
echo ""
sleep 0.5

# ── 4. Same-Device Behaviour Deviation (MEDIUM-HIGH risk) ────
echo -e "${YELLOW}4. Same Device, Anomalous Behaviour → Expect OTP or BLOCK${NC}"
curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "SecurePass123!",
    "behavioral": {
      "login_duration_ms": 180,
      "keystroke_intervals": [15, 12, 18, 10, 14],
      "mouse_event_count": 1,
      "typing_speed_wpm": 180
    },
    "device": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0",
      "screen_res": "1920x1080",
      "device_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
    },
    "ip_address": "192.168.1.100"
  }' | python3 -m json.tool 2>/dev/null
echo ""
sleep 0.5

# ── 5. New Device + New IP + Unusual Hour ────────────────────
echo -e "${RED}5. Credential Stuffing Pattern → Expect BLOCK${NC}"
curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "WrongPassword",
    "behavioral": {
      "login_duration_ms": 350,
      "keystroke_intervals": [25, 30, 22, 28],
      "mouse_event_count": 0,
      "typing_speed_wpm": 15
    },
    "device": {
      "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0",
      "screen_res": "1366x768",
      "device_id": "ffffffff00000000aaaaaaaa11111111"
    },
    "ip_address": "103.45.67.89"
  }' | python3 -m json.tool 2>/dev/null
echo ""
sleep 0.5

# ── 6. Direct Risk Scoring ───────────────────────────────────
echo -e "${BOLD}6. Direct ML Risk Score (worst case features)${NC}"
curl -s -X POST "$BASE/risk/score" \
  -H "Content-Type: application/json" \
  -d '{
    "login_duration_ms": 100,
    "keystroke_avg_interval": 0,
    "mouse_event_count": 0,
    "typing_speed_wpm": 0,
    "is_new_device": true,
    "is_new_ip": true,
    "is_unusual_hour": true,
    "geo_distance_km": 8000,
    "autofill_detected": true
  }' | python3 -m json.tool 2>/dev/null
echo ""
sleep 0.5

# ── 7. Transaction Check ─────────────────────────────────────
if [ -n "$USER_ID" ]; then
  echo -e "${YELLOW}7. Large Transaction → Expect OTP or BLOCK${NC}"
  curl -s -X POST "$BASE/tx/check" \
    -H "Content-Type: application/json" \
    -d "{
      \"user_id\": \"$USER_ID\",
      \"session_id\": \"sess_test_001\",
      \"amount\": 25000,
      \"currency\": \"USD\",
      \"recipient_id\": \"unknown_recipient\",
      \"transaction_type\": \"TRANSFER\",
      \"device\": {
        \"user_agent\": \"Mozilla/5.0 (Windows NT 10.0) Chrome/125.0.0.0\",
        \"screen_res\": \"1920x1080\",
        \"device_id\": \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\"
      }
    }" | python3 -m json.tool 2>/dev/null
  echo ""
fi

# ── 8. Dashboard Stats ───────────────────────────────────────
echo -e "${BOLD}8. Dashboard Stats${NC}"
curl -s "$BASE/admin/stats" | python3 -m json.tool 2>/dev/null
echo ""

echo -e "${BOLD}9. Health Check${NC}"
curl -s "$BASE/health" | python3 -m json.tool 2>/dev/null
echo ""

echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  All scenarios complete!${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
