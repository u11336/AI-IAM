#!/bin/bash
echo "=== AUTHENTICATION SECURITY TEST ==="
BASE_URL="http://localhost:8080/api"

# Setup: Create test user
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "securitytest",
    "email": "security@test.com",
    "password": "SecurityPass123!"
  }' > /dev/null

echo "1. Test Invalid Password:"
curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "securitytest",
    "password": "WrongPassword"
  }' | jq '.'

echo -e "\n2. Test Invalid Username:"
curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "nonexistent",
    "password": "AnyPassword123!"
  }' | jq '.'

echo -e "\n3. Test Multiple Failed Attempts (Account Lockout):"
for i in {1..6}; do
  echo "Failed attempt $i:"
  curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
      "username": "securitytest",
      "password": "WrongPassword'$i'"
    }' | jq '.error'
  sleep 1
done

echo -e "\n4. Test Login After Lockout:"
curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "securitytest",
    "password": "SecurityPass123!"
  }' | jq '.'

echo -e "\n5. Test Invalid Token:"
curl -s -X GET "$BASE_URL/auth/me" \
  -H "Authorization: Bearer invalid.token.here" | jq '.'

echo -e "\n6. Test Expired Token (simulation):"
curl -s -X GET "$BASE_URL/auth/me" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.expired.token" | jq '.'
