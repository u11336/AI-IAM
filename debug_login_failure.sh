#!/bin/bash
echo "=== DEBUG LOGIN FAILURE ==="

echo "1. Check user details in database:"
sqlite3 iam.db "SELECT id, username, email, length(password_hash), is_active, is_locked, failed_login_count FROM users WHERE username='fulltest';"

echo -e "\n2. Check password hash format:"
sqlite3 iam.db "SELECT substr(password_hash, 1, 15) as hash_prefix FROM users WHERE username='fulltest';"

echo -e "\n3. Check all users and their password hashes:"
sqlite3 iam.db "SELECT id, username, substr(password_hash, 1, 10) as hash_start, length(password_hash) as hash_len FROM users;"

echo -e "\n4. Create fresh test user and try login immediately:"
echo "Creating fresh user..."
FRESH_REG=$(curl -s -X POST "http://localhost:8080/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "freshtest",
    "email": "fresh@test.com",
    "password": "Fresh123!"
  }')
echo "Registration: $FRESH_REG"

echo -e "\n5. Check fresh user in database:"
sqlite3 iam.db "SELECT id, username, length(password_hash), substr(password_hash, 1, 10) FROM users WHERE username='freshtest';"

echo -e "\n6. Try login with fresh user:"
FRESH_LOGIN=$(curl -s -X POST "http://localhost:8080/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "freshtest",
    "password": "Fresh123!"
  }')
echo "Fresh login: $FRESH_LOGIN"

echo -e "\n7. Try login with wrong password to see difference:"
WRONG_LOGIN=$(curl -s -X POST "http://localhost:8080/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "freshtest",
    "password": "WrongPassword"
  }')
echo "Wrong password: $WRONG_LOGIN"

echo -e "\n8. Check Go service logs for any errors during login attempts"
echo "   Look for bcrypt errors, database errors, or authentication details"