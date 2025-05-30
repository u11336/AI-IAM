#!/bin/bash
echo "=== MULTI-FACTOR AUTHENTICATION TEST ==="
BASE_URL="http://localhost:8080/api"

# Setup: Create and login user
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mfauser",
    "email": "mfa@test.com",
    "password": "MfaPass123!"
  }' > /dev/null

LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mfauser",
    "password": "MfaPass123!"
  }')

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')

echo "1. Enable MFA:"
MFA_SETUP=$(curl -s -X POST "$BASE_URL/auth/mfa/enable" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json")

echo "$MFA_SETUP" | jq '.'
MFA_SECRET=$(echo "$MFA_SETUP" | jq -r '.secret')
MFA_URL=$(echo "$MFA_SETUP" | jq -r '.url')

echo -e "\nMFA Secret: $MFA_SECRET"
echo "QR Code URL: $MFA_URL"

echo -e "\n2. Test MFA Verification (Invalid Code):"
curl -s -X POST "$BASE_URL/auth/mfa/verify" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "123456"
  }' | jq '.'

echo -e "\n3. Test MFA Verification (Empty Code):"
curl -s -X POST "$BASE_URL/auth/mfa/verify" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "code": ""
  }' | jq '.'

echo -e "\n4. Test Disable MFA:"
curl -s -X POST "$BASE_URL/auth/mfa/disable" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "MfaPass123!"
  }' | jq '.'

echo -e "\n5. Test Disable MFA (Invalid Password):"
curl -s -X POST "$BASE_URL/auth/mfa/disable" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "WrongPassword"
  }' | jq '.'