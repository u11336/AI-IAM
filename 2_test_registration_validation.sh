#!/bin/bash
echo "=== REGISTRATION VALIDATION TEST ==="
BASE_URL="http://localhost:8080/api"

echo "1. Test Weak Password:"
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "weakuser",
    "email": "weak@test.com", 
    "password": "123"
  }' | jq '.'

echo -e "\n2. Test Invalid Email:"
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "invaliduser",
    "email": "not-an-email",
    "password": "ValidPass123!"
  }' | jq '.'

echo -e "\n3. Test Missing Fields:"
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "incomplete"
  }' | jq '.'

echo -e "\n4. Test Duplicate Username:"
# First register a user
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "duplicate",
    "email": "first@test.com",
    "password": "FirstPass123!"
  }' > /dev/null

# Try to register with same username
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "duplicate",
    "email": "second@test.com",
    "password": "SecondPass123!"
  }' | jq '.'