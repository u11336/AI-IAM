#!/bin/bash
echo "=== STATISTICAL ANOMALY DETECTION TEST ==="
BASE_URL="http://localhost:8080/api"

# Setup: Create user and establish baseline
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "anomalyuser",
    "email": "anomaly@test.com",
    "password": "AnomalyPass123!"
  }' > /dev/null

echo "1. Establishing Normal Behavior Baseline (10 normal logins):"
for i in {1..10}; do
  NORMAL_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 192.168.1.100" \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    -d '{
      "username": "anomalyuser",
      "password": "AnomalyPass123!"
    }')
  
  RISK_SCORE=$(echo "$NORMAL_LOGIN" | jq -r '.risk_score // "N/A"')
  echo "  Normal login $i - Risk Score: $RISK_SCORE"
  sleep 1
done

echo -e "\n2. Test IP Address Anomaly:"
IP_ANOMALY=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 203.0.113.42" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -d '{
    "username": "anomalyuser",
    "password": "AnomalyPass123!"
  }')

echo "$IP_ANOMALY" | jq '.'
IP_RISK=$(echo "$IP_ANOMALY" | jq -r '.risk_score // "N/A"')
echo "IP Anomaly Risk Score: $IP_RISK"

echo -e "\n3. Test User Agent Anomaly (Desktop � Mobile):"
UA_ANOMALY=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 192.168.1.100" \
  -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)" \
  -d '{
    "username": "anomalyuser",
    "password": "AnomalyPass123!"
  }')

echo "$UA_ANOMALY" | jq '.'
UA_RISK=$(echo "$UA_ANOMALY" | jq -r '.risk_score // "N/A"')
echo "User Agent Anomaly Risk Score: $UA_RISK"

echo -e "\n4. Test Bot Detection:"
BOT_ANOMALY=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 192.168.1.100" \
  -H "User-Agent: curl/7.68.0" \
  -d '{
    "username": "anomalyuser",
    "password": "AnomalyPass123!"
  }')

echo "$BOT_ANOMALY" | jq '.'
BOT_RISK=$(echo "$BOT_ANOMALY" | jq -r '.risk_score // "N/A"')
echo "Bot Detection Risk Score: $BOT_RISK"

echo -e "\n5. Test Combined Anomalies (High Risk):"
COMBINED_ANOMALY=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 8.8.8.8" \
  -H "User-Agent: SuspiciousBot/1.0" \
  -d '{
    "username": "anomalyuser",
    "password": "AnomalyPass123!"
  }')

echo "$COMBINED_ANOMALY" | jq '.'
COMBINED_RISK=$(echo "$COMBINED_ANOMALY" | jq -r '.risk_score // "N/A"')
echo "Combined Anomaly Risk Score: $COMBINED_RISK"