#!/bin/bash
echo "=== CHECK AUTHENTICATION CODE ==="

echo "1. Check UserRepository GetByUsername method:"
grep -A 10 "GetByUsername" internal/data/repository/user_repo.go 2>/dev/null || echo "❌ GetByUsername not found"

echo -e "\n2. Check password comparison in auth service:"
grep -A 5 -B 5 "CompareHashAndPassword" internal/core/auth/auth.go 2>/dev/null || echo "❌ Password comparison not found"

echo -e "\n3. Check password hashing in register:"
grep -A 5 -B 5 "GenerateFromPassword" internal/core/auth/auth.go 2>/dev/null || echo "❌ Password hashing not found"

echo -e "\n4. Check Register method in auth service:"
grep -A 15 "func.*Register" internal/core/auth/auth.go | head -20

echo -e "\n5. Check Login method in auth service:"
grep -A 15 "func.*Login" internal/core/auth/auth.go | head -20

echo -e "\n6. Check if bcrypt import exists:"
grep -n "bcrypt" internal/core/auth/auth.go || echo "❌ bcrypt import not found"

echo -e "\n7. Look for any hardcoded issues in password validation:"
grep -E "password|hash" internal/api/auth.go | head -10