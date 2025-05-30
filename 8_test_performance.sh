#!/bin/bash
echo "=== PERFORMANCE TESTING ==="
BASE_URL="http://localhost:8080/api"
ML_URL="http://localhost:8001"

# Setup test user
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "perfuser",
    "email": "perf@test.com",
    "password": "PerfPass123!"
  }' > /dev/null

echo "1. Single Authentication Performance:"
start_time=$(date +%s.%N)

AUTH_PERF=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "perfuser",
    "password": "PerfPass123!"
  }')

end_time=$(date +%s.%N)
auth_duration=$(echo "$end_time - $start_time" | bc)

echo "Authentication completed in: ${auth_duration}s"
echo "Response: $(echo "$AUTH_PERF" | jq -c '.')"

echo -e "\n2. ML Service Performance:"
ml_start=$(date +%s.%N)

ML_PERF=$(curl -s -X POST "$ML_URL/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "resource": "test",
    "action": "access",
    "timestamp": "'$(date -Iseconds)'",
    "success": true
  }')

ml_end=$(date +%s.%N)
ml_duration=$(echo "$ml_end - $ml_start" | bc)

echo "ML prediction completed in: ${ml_duration}s"
echo "ML Response: $(echo "$ML_PERF" | jq -c '.')"

echo -e "\n3. Concurrent Authentication Test (10 parallel requests):"
concurrent_start=$(date +%s.%N)

for i in {1..10}; do
  curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 192.168.1.$((100 + i))" \
    -d '{
      "username": "perfuser",
      "password": "PerfPass123!"
    }' > /dev/null &
done

wait  # Wait for all background processes

concurrent_end=$(date +%s.%N)
concurrent_duration=$(echo "$concurrent_end - $concurrent_start" | bc)

echo "10 concurrent authentications completed in: ${concurrent_duration}s"
avg_time=$(echo "scale=3; $concurrent_duration / 10" | bc)
echo "Average time per authentication: ${avg_time}s"

echo -e "\n4. Load Test (50 sequential requests):"
load_start=$(date +%s.%N)

for i in {1..50}; do
  curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
      "username": "perfuser",
      "password": "PerfPass123!"
    }' > /dev/null
  
  if [[ $((i % 10)) -eq 0 ]]; then
    echo "  Completed $i/50 requests..."
  fi
done

load_end=$(date +%s.%N)
load_duration=$(echo "$load_end - $load_start" | bc)

echo "50 sequential authentications completed in: ${load_duration}s"
throughput=$(echo "scale=2; 50 / $load_duration" | bc)
echo "Throughput: ${throughput} requests/second"