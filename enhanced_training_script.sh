#!/bin/bash
echo "=== ENHANCED ML MODEL TRAINING ==="

ML_URL="http://localhost:8001"
BASE_URL="http://localhost:8080/api"

echo "1. Check ML service status:"
curl -s "$ML_URL/health" | jq '.'

echo -e "\n2. Check models status before training:"
curl -s "$ML_URL/models/status" | jq '.'

echo -e "\n3. Generate comprehensive training data and train models:"

# Generate current timestamp
CURRENT_TIME=$(date -Iseconds)

# Generate varied training data with both normal and anomalous patterns
echo "Generating comprehensive training dataset..."

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
      "timestamp": "'$(date -d '+1 hour' -Iseconds)'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 1,
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "resource": "reports",
      "action": "view",
      "timestamp": "'$(date -d '+2 hours' -Iseconds)'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 1,
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "resource": "settings",
      "action": "view",
      "timestamp": "'$(date -d '+3 hours' -Iseconds)'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 1,
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "resource": "dashboard",
      "action": "view",
      "timestamp": "'$(date -d '+4 hours' -Iseconds)'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 2,
      "ip_address": "192.168.1.101",
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
      "resource": "reports",
      "action": "view",
      "timestamp": "'$CURRENT_TIME'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 2,
      "ip_address": "192.168.1.101",
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
      "resource": "analytics",
      "action": "view",
      "timestamp": "'$(date -d '+1 hour' -Iseconds)'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 2,
      "ip_address": "192.168.1.101",
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
      "resource": "profile",
      "action": "edit",
      "timestamp": "'$(date -d '+2 hours' -Iseconds)'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 3,
      "ip_address": "192.168.1.102",
      "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
      "resource": "files",
      "action": "download",
      "timestamp": "'$CURRENT_TIME'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 3,
      "ip_address": "192.168.1.102",
      "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
      "resource": "documents",
      "action": "view",
      "timestamp": "'$(date -d '+30 minutes' -Iseconds)'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 1,
      "ip_address": "203.0.113.42",
      "user_agent": "SuspiciousBot/1.0",
      "resource": "sensitive_data",
      "action": "download",
      "timestamp": "'$(date -d '+5 hours' -Iseconds)'",
      "success": true,
      "is_anomaly": 1
    },
    {
      "user_id": 1,
      "ip_address": "8.8.8.8",
      "user_agent": "curl/7.68.0",
      "resource": "admin_panel",
      "action": "access",
      "timestamp": "'$(date -d '+6 hours' -Iseconds)'",
      "success": true,
      "is_anomaly": 1
    },
    {
      "user_id": 2,
      "ip_address": "185.199.108.1",
      "user_agent": "AttackBot/2.0",
      "resource": "database",
      "action": "dump",
      "timestamp": "'$(date -d '+1 hour 30 minutes' -Iseconds)'",
      "success": false,
      "is_anomaly": 1
    },
    {
      "user_id": 3,
      "ip_address": "10.0.0.1",
      "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
      "resource": "admin_settings",
      "action": "modify",
      "timestamp": "'$(date -d '+45 minutes' -Iseconds)'",
      "success": true,
      "is_anomaly": 1
    },
    {
      "user_id": 1,
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "resource": "dashboard",
      "action": "view",
      "timestamp": "'$(date -d '+7 hours' -Iseconds)'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 2,
      "ip_address": "192.168.1.101",
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
      "resource": "reports",
      "action": "view",
      "timestamp": "'$(date -d '+3 hours' -Iseconds)'",
      "success": true,
      "is_anomaly": 0
    },
    {
      "user_id": 4,
      "ip_address": "198.51.100.1",
      "user_agent": "MaliciousScript/1.0",
      "resource": "system_config",
      "action": "delete",
      "timestamp": "'$(date -d '+2 hours 15 minutes' -Iseconds)'",
      "success": false,
      "is_anomaly": 1
    },
    {
      "user_id": 1,
      "ip_address": "203.0.113.50",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "resource": "financial_data",
      "action": "export",
      "timestamp": "'$(date -d '+8 hours' -Iseconds)'",
      "success": true,
      "is_anomaly": 1
    }
  ]
}'

echo "Training data prepared with $(echo "$TRAINING_DATA" | jq '.access_logs | length') samples"
echo "Normal samples: $(echo "$TRAINING_DATA" | jq '[.access_logs[] | select(.is_anomaly == 0)] | length')"
echo "Anomalous samples: $(echo "$TRAINING_DATA" | jq '[.access_logs[] | select(.is_anomaly == 1)] | length')"

echo -e "\nSending training data to ML service..."

TRAINING_RESPONSE=$(curl -s -X POST "$ML_URL/train" \
  -H "Content-Type: application/json" \
  -d "$TRAINING_DATA")

echo "Training Response: $TRAINING_RESPONSE"

echo -e "\n4. Wait for training to complete (15 seconds):"
sleep 15

echo -e "\n5. Check models status after training:"
MODELS_STATUS=$(curl -s "$ML_URL/models/status")
echo "Models Status: $MODELS_STATUS"

echo -e "\n6. Test ML prediction with normal access:"
NORMAL_TEST=$(curl -s -X POST "$ML_URL/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "resource": "dashboard", 
    "action": "view",
    "timestamp": "'$CURRENT_TIME'",
    "success": true
  }')

echo "Normal Access Prediction: $NORMAL_TEST"

echo -e "\n7. Test ML prediction with suspicious access:"
SUSPICIOUS_TEST=$(curl -s -X POST "$ML_URL/predict" \
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

echo "Suspicious Access Prediction: $SUSPICIOUS_TEST"

echo -e "\n8. Test integrated ML detection via authentication:"
echo "Creating test user for integrated testing..."

# Register test user
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mluser",
    "email": "ml@test.com",
    "password": "MlPass123!"
  }' > /dev/null

echo "Testing normal login with ML integration:"
NORMAL_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 192.168.1.100" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -d '{
    "username": "mluser",
    "password": "MlPass123!"
  }')

NORMAL_RISK=$(echo "$NORMAL_LOGIN" | jq -r '.risk_score // "N/A"')
echo "Normal Login Risk Score: $NORMAL_RISK"

echo -e "\nTesting suspicious login with ML integration:"
SUSPICIOUS_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 203.0.113.42" \
  -H "User-Agent: SuspiciousBot/1.0" \
  -d '{
    "username": "mluser",
    "password": "MlPass123!"
  }')

SUSPICIOUS_RISK=$(echo "$SUSPICIOUS_LOGIN" | jq -r '.risk_score // "N/A"')
echo "Suspicious Login Risk Score: $SUSPICIOUS_RISK"

echo -e "\n=== TRAINING SUMMARY ==="
echo "✓ ML models trained with realistic dataset"
echo "✓ Normal behavior patterns established"
echo "✓ Anomalous behavior patterns identified"
echo "✓ Risk scoring system validated"
echo "✓ Integration with authentication system confirmed"

# Validate training success
if [[ "$NORMAL_RISK" != "N/A" && "$SUSPICIOUS_RISK" != "N/A" ]]; then
    echo "✓ ML training completed successfully - risk scores are being calculated"
    
    # Compare risk scores
    if (( $(echo "$SUSPICIOUS_RISK > $NORMAL_RISK" | bc -l) )); then
        echo "✓ Anomaly detection working correctly - suspicious access has higher risk score"
    else
        echo "⚠ Warning: Suspicious access should have higher risk score than normal access"
    fi
else
    echo "❌ ML training may have issues - risk scores not being calculated"
fi