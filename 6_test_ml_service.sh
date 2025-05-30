#!/bin/bash
echo "=== ML SERVICE TESTING ==="
BASE_URL="http://localhost:8080/api"
ML_URL="http://localhost:8001"

echo "1. ML Service Health Check:"
curl -s "$ML_URL/health" | jq '.'

echo -e "\n2. ML Models Status:"
curl -s "$ML_URL/models/status" | jq '.'

echo -e "\n3. Direct ML Prediction Test:"
CURRENT_TIME=$(date -Iseconds)
ML_PREDICTION=$(curl -s -X POST "$ML_URL/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "ip_address": "203.0.113.42",
    "user_agent": "SuspiciousBot/1.0",
    "resource": "sensitive_data",
    "action": "download",
    "timestamp": "'$CURRENT_TIME'",
    "success": true
  }')

echo "$ML_PREDICTION" | jq '.'

echo -e "\n4. ML Training Endpoint Test:"
TRAINING_DATA=$(curl -s -X POST "$ML_URL/train" \
  -H "Content-Type: application/json" \
  -d '{
    "access_logs": [
      {
        "user_id": 1,
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "resource": "dashboard",
        "action": "view",
        "timestamp": "'$CURRENT_TIME'",
        "success": true
      }
    ]
  }')

echo "$TRAINING_DATA" | jq '.'

echo -e "\n5. Test ML Integration via Auth Endpoint:"
# Setup user first
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mluser",
    "email": "ml@test.com",
    "password": "MlPass123!"
  }' > /dev/null

ML_AUTH_TEST=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 203.0.113.42" \
  -H "User-Agent: SuspiciousBot/1.0" \
  -d '{
    "username": "mluser",
    "password": "MlPass123!"
  }')

echo "$ML_AUTH_TEST" | jq '.'
ML_AUTH_RISK=$(echo "$ML_AUTH_TEST" | jq -r '.risk_score // "N/A"')
echo "ML-Enhanced Auth Risk Score: $ML_AUTH_RISK"