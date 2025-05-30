#!/bin/bash
echo "=== BASIC FUNCTIONALITY TEST ==="
BASE_URL="http://localhost:8080/api"

echo "1. Health Check:"
curl -s "$BASE_URL/health" | jq '.'

echo -e "\n2. User Registration:"
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "TestPass123!"
  }' | jq '.'

echo -e "\n3. User Login:"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "TestPass123!"
  }')

echo "$LOGIN_RESPONSE" | jq '.'
TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')

echo -e "\n4. Get Current User (with token):"
curl -s -X GET "$BASE_URL/auth/me" \
  -H "Authorization: Bearer $TOKEN" | jq '.'