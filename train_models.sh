#!/bin/bash
echo "=== TRAINING ML MODELS ==="

ML_URL="http://localhost:8001"

echo "1. Check ML service status:"
curl -s "$ML_URL/health" | jq '.'

echo -e "\n2. Check models status before training:"
curl -s "$ML_URL/models/status" | jq '.'

echo -e "\n3. Generate training data and train models:"

# Generate synthetic training data
CURRENT_TIME=$(date -Iseconds)

TRAINING_DATA='{
  "access_logs": [
    {
      "user_id": 1,
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "resource": "dashboard",
      "action": "view",
      "timestamp": "'$CURRENT_TIME'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 1,
      "ip_address": "192.168.1.100", 
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "resource": "profile",
      "action": "edit",
      "timestamp": "'$CURRENT_TIME'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 1,
      "ip_address": "203.0.113.42",
      "user_agent": "SuspiciousBot/1.0",
      "resource": "sensitive_data",
      "action": "download",
      "timestamp": "'$CURRENT_TIME'",
      "success": true,
      "is_anomaly": 1
    },
    {
      "user_id": 2,
      "ip_address": "192.168.1.101",
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      "resource": "reports",
      "action": "view",
      "timestamp": "'$CURRENT_TIME'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 2,
      "ip_address": "8.8.8.8",
      "user_agent": "curl/7.68.0",
      "resource": "admin_panel",
      "action": "access",
      "timestamp": "'$CURRENT_TIME'",
      "success": true,
      "is_anomaly": 1
    }
  ]
}'

echo "Training data prepared, sending to ML service..."

TRAINING_RESPONSE=$(curl -s -X POST "$ML_URL/train" \
  -H "Content-Type: application/json" \
  -d "$TRAINING_DATA")

echo "Training Response: $TRAINING_RESPONSE"

echo -e "\n4. Wait for training to complete (10 seconds):"
sleep 10

echo -e "\n5. Check models status after training:"
curl -s "$ML_URL/models/status" | jq '.'

echo -e "\n6. Test ML prediction:"
TEST_PREDICTION=$(curl -s -X POST "$ML_URL/predict" \
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

echo "Test Prediction: $TEST_PREDICTION"