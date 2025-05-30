#!/bin/bash
echo "=== ATTACK SIMULATION TEST ==="
BASE_URL="http://localhost:8080/api"

# Setup: Create target user
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "targetuser",
    "email": "target@test.com",
    "password": "TargetPass123!"
  }' > /dev/null

echo "1. Brute Force Attack Simulation:"
PASSWORDS=("password" "123456" "admin" "target" "password123" "qwerty")

for pass in "${PASSWORDS[@]}"; do
  echo "Trying password: $pass"
  BRUTE_FORCE=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 203.0.113.100" \
    -H "User-Agent: BruteForceBot/1.0" \
    -d '{
      "username": "targetuser",
      "password": "'$pass'"
    }')
  
  ERROR=$(echo "$BRUTE_FORCE" | jq -r '.error // "none"')
  echo "  Result: $ERROR"
  sleep 1
done

echo -e "\n2. Distributed Attack (Multiple IPs):"
ATTACKER_IPS=("203.0.113.1" "203.0.113.2" "203.0.113.3" "203.0.113.4" "203.0.113.5")

for ip in "${ATTACKER_IPS[@]}"; do
  echo "Attack from IP: $ip"
  DISTRIBUTED_ATTACK=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $ip" \
    -H "User-Agent: AttackBot/1.0" \
    -d '{
      "username": "targetuser",
      "password": "guessed_password"
    }')
  
  RISK_SCORE=$(echo "$DISTRIBUTED_ATTACK" | jq -r '.risk_score // "N/A"')
  ERROR=$(echo "$DISTRIBUTED_ATTACK" | jq -r '.error // "none"')
  echo "  Risk Score: $RISK_SCORE, Error: $ERROR"
  sleep 0.5
done

echo -e "\n3. Credential Stuffing Simulation:"
CREDENTIALS=(
  "admin:admin123"
  "user:password"
  "test:test123"
  "root:toor"
  "guest:guest"
)

for cred in "${CREDENTIALS[@]}"; do
  IFS=':' read -r username password <<< "$cred"
  echo "Trying $username:$password"
  
  STUFFING_ATTACK=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 198.51.100.100" \
    -H "User-Agent: CredentialStuffingBot/1.0" \
    -d '{
      "username": "'$username'",
      "password": "'$password'"
    }')
  
  ERROR=$(echo "$STUFFING_ATTACK" | jq -r '.error // "none"')
  echo "  Result: $ERROR"
  sleep 1
done

echo -e "\n4. High-Frequency Attack Detection:"
echo "Rapid successive login attempts..."
for i in {1..20}; do
  RAPID_ATTACK=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 185.199.108.100" \
    -H "User-Agent: RapidAttackBot/1.0" \
    -d '{
      "username": "targetuser",
      "password": "rapid_attack_'$i'"
    }')
  
  if [[ $((i % 5)) -eq 0 ]]; then
    RISK_SCORE=$(echo "$RAPID_ATTACK" | jq -r '.risk_score // "N/A"')
    ERROR=$(echo "$RAPID_ATTACK" | jq -r '.error // "none"')
    echo "  Attempt $i - Risk Score: $RISK_SCORE, Error: $ERROR"
  fi
done
