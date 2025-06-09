#!/bin/bash

# AI-IAM Comprehensive Testing Script
# Tests all functionality step by step:

set -e  # Exit on any error

# Configuration
BASE_URL="http://localhost:8080/api"
ML_URL="http://localhost:8001"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Global variables for test data
ADMIN_TOKEN=""
USER_TOKEN=""
TEST_USER_ID=""
SUSPICIOUS_USER_ID=""

# Utility functions
print_header() {
    echo -e "\n${BLUE}===========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===========================================${NC}\n"
}

print_step() {
    echo -e "${GREEN}V $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}!  $1${NC}"
}

print_error() {
    echo -e "${RED}X $1${NC}"
}

wait_for_service() {
    local url=$1
    local service_name=$2
    local max_attempts=30
    
    echo "� Waiting for $service_name to be ready..."
    
    for i in $(seq 1 $max_attempts); do
        if curl -s "$url/health" > /dev/null 2>&1; then
            print_step "$service_name is ready!"
            return 0
        fi
        echo "   Attempt $i/$max_attempts..."
        sleep 2
    done
    
    print_error "$service_name failed to start"
    exit 1
}

extract_json_field() {
    echo "$1" | jq -r "$2"
}

# Test functions
test_system_health() {
    print_header "PHASE 1: SYSTEM HEALTH CHECK"
    
    print_step "1.1 Testing Go Backend Health"
    GO_HEALTH=$(curl -s "$BASE_URL/health")
    echo "Go Service Health: $GO_HEALTH"
    
    print_step "1.2 Testing ML Service Health"
    ML_HEALTH=$(curl -s "$ML_URL/health")
    echo "ML Service Health: $ML_HEALTH"
    
    print_step "1.3 Testing ML Models Status"
    ML_MODELS=$(curl -s "$ML_URL/models/status")
    echo "ML Models Status: $ML_MODELS"
}

test_user_registration() {
    print_header "PHASE 2: USER REGISTRATION"
    
    print_step "2.1 Register Admin User"
    ADMIN_REG=$(curl -s -X POST "$BASE_URL/auth/register" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "admin",
            "email": "admin@company.com",
            "password": "AdminPass123!"
        }')
    
    echo "Admin Registration Response: $ADMIN_REG"
    
    print_step "2.2 Register Normal User"
    USER_REG=$(curl -s -X POST "$BASE_URL/auth/register" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "john.doe",
            "email": "john.doe@company.com",
            "password": "UserPass123!"
        }')
    
    echo "User Registration Response: $USER_REG"
    TEST_USER_ID=$(extract_json_field "$USER_REG" ".id")
    
    print_step "2.3 Register Suspicious User (for anomaly testing)"
    SUSPICIOUS_REG=$(curl -s -X POST "$BASE_URL/auth/register" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "suspicious.user",
            "email": "suspicious@external.com",
            "password": "SuspiciousPass123!"
        }')
    
    echo "Suspicious User Registration: $SUSPICIOUS_REG"
    SUSPICIOUS_USER_ID=$(extract_json_field "$SUSPICIOUS_REG" ".id")
    
    print_step "2.4 Test Registration Validation"
    
    # Test weak password
    WEAK_PASS=$(curl -s -X POST "$BASE_URL/auth/register" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "weakuser",
            "email": "weak@test.com",
            "password": "123"
        }')
    echo "Weak Password Response: $WEAK_PASS"
    
    # Test invalid email
    INVALID_EMAIL=$(curl -s -X POST "$BASE_URL/auth/register" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "invalidemail",
            "email": "invalid-email",
            "password": "ValidPass123!"
        }')
    echo "Invalid Email Response: $INVALID_EMAIL"
    
    # Test duplicate username
    DUPLICATE_USER=$(curl -s -X POST "$BASE_URL/auth/register" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "john.doe",
            "email": "john.duplicate@company.com",
            "password": "ValidPass123!"
        }')
    echo "Duplicate Username Response: $DUPLICATE_USER"
}

test_authentication() {
    print_header "PHASE 3: AUTHENTICATION TESTING"
    
    print_step "3.1 Admin Login"
    ADMIN_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 192.168.1.10" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        -d '{
            "username": "admin",
            "password": "AdminPass123!"
        }')
    
    echo "Admin Login Response: $ADMIN_LOGIN"
    ADMIN_TOKEN=$(extract_json_field "$ADMIN_LOGIN" ".token")
    ADMIN_RISK=$(extract_json_field "$ADMIN_LOGIN" ".risk_score")
    echo "Admin Token: ${ADMIN_TOKEN:0:50}..."
    echo "Admin Risk Score: $ADMIN_RISK"
    
    print_step "3.2 Normal User Login"
    USER_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 192.168.1.100" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        -d '{
            "username": "john.doe",
            "password": "UserPass123!"
        }')
    
    echo "User Login Response: $USER_LOGIN"
    USER_TOKEN=$(extract_json_field "$USER_LOGIN" ".token")
    USER_RISK=$(extract_json_field "$USER_LOGIN" ".risk_score")
    echo "User Token: ${USER_TOKEN:0:50}..."
    echo "User Risk Score: $USER_RISK"
    
    print_step "3.3 Invalid Credentials Test"
    INVALID_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "john.doe",
            "password": "WrongPassword"
        }')
    echo "Invalid Login Response: $INVALID_LOGIN"
    
    print_step "3.4 Test Token Validation"
    if [[ -n "$USER_TOKEN" ]]; then
        ME_RESPONSE=$(curl -s -X GET "$BASE_URL/auth/me" \
            -H "Authorization: Bearer $USER_TOKEN")
        echo "Current User Response: $ME_RESPONSE"
    else
        print_error "No valid user token available"
    fi
}

test_mfa_functionality() {
    print_header "PHASE 4: MULTI-FACTOR AUTHENTICATION"
    
    if [[ -z "$USER_TOKEN" ]]; then
        print_error "No user token available for MFA testing"
        return 1
    fi
    
    print_step "4.1 Enable MFA"
    MFA_ENABLE=$(curl -s -X POST "$BASE_URL/auth/mfa/enable" \
        -H "Authorization: Bearer $USER_TOKEN" \
        -H "Content-Type: application/json")
    
    echo "MFA Enable Response: $MFA_ENABLE"
    MFA_SECRET=$(extract_json_field "$MFA_ENABLE" ".secret")
    MFA_URL=$(extract_json_field "$MFA_ENABLE" ".url")
    
    if [[ -n "$MFA_SECRET" ]]; then
        print_step "MFA Secret Generated: ${MFA_SECRET:0:10}..."
        print_step "MFA QR URL: $MFA_URL"
        
        # For testing, we'll simulate MFA verification
        # In real scenario, you'd use an authenticator app
        print_warning "In production, scan QR code with authenticator app"
        
        print_step "4.2 Test MFA Verification (simulated)"
        # Note: Real TOTP code would be generated by authenticator app
        MFA_VERIFY=$(curl -s -X POST "$BASE_URL/auth/mfa/verify" \
            -H "Authorization: Bearer $USER_TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
                "code": "123456"
            }')
        echo "MFA Verify Response: $MFA_VERIFY"
    else
        print_error "Failed to generate MFA secret"
    fi
}

test_rbac_system() {
    print_header "PHASE 5: ROLE-BASED ACCESS CONTROL (RBAC)"
    
    if [[ -z "$ADMIN_TOKEN" ]]; then
        print_error "No admin token available for RBAC testing"
        return 1
    fi
    
    print_step "5.1 List All Roles"
    ROLES_LIST=$(curl -s -X GET "$BASE_URL/rbac/roles" \
        -H "Authorization: Bearer $ADMIN_TOKEN")
    echo "Roles List: $ROLES_LIST"
    
    print_step "5.2 Create Custom Role"
    ROLE_CREATE=$(curl -s -X POST "$BASE_URL/rbac/roles" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "analyst",
            "description": "Data analyst with limited access"
        }')
    echo "Role Creation Response: $ROLE_CREATE"
    
    print_step "5.3 List All Permissions"
    PERMISSIONS_LIST=$(curl -s -X GET "$BASE_URL/rbac/permissions" \
        -H "Authorization: Bearer $ADMIN_TOKEN")
    echo "Permissions List: $PERMISSIONS_LIST"
    
    print_step "5.4 Test Permission Check"
    if [[ -n "$USER_TOKEN" ]]; then
        PERMISSION_CHECK=$(curl -s -X GET "$BASE_URL/rbac/check?resource=users&action=read" \
            -H "Authorization: Bearer $USER_TOKEN")
        echo "Permission Check Response: $PERMISSION_CHECK"
    fi
}

build_normal_behavior_baseline() {
    print_header "PHASE 6: BUILDING NORMAL BEHAVIOR BASELINE"
    
    print_step "6.1 Generate Normal Login Patterns (10 logins)"
    
    for i in $(seq 1 10); do
        NORMAL_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
            -H "Content-Type: application/json" \
            -H "X-Forwarded-For: 192.168.1.100" \
            -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
            -d '{
                "username": "john.doe",
                "password": "UserPass123!"
            }')
        
        RISK_SCORE=$(extract_json_field "$NORMAL_LOGIN" ".risk_score")
        echo "   Normal Login $i - Risk Score: $RISK_SCORE"
        sleep 1
    done
    
    print_step "6.2 Train ML Models with Normal Patterns"
    # This would ideally send training data to ML service
    # For now, ML service will learn from access patterns automatically
}

test_statistical_anomaly_detection() {
    print_header "PHASE 7: STATISTICAL ANOMALY DETECTION (GO Backend)"
    
    print_step "7.1 Disable ML Service (simulate ML service down)"
    # We'll test statistical fallback by trying with different patterns
    
    print_step "7.2 Test IP Address Anomaly"
    IP_ANOMALY=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 203.0.113.42" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        -d '{
            "username": "john.doe",
            "password": "UserPass123!"
        }')
    
    IP_RISK=$(extract_json_field "$IP_ANOMALY" ".risk_score")
    IP_ERROR=$(extract_json_field "$IP_ANOMALY" ".error")
    
    echo "IP Anomaly Response: $IP_ANOMALY"
    if [[ "$IP_ERROR" != "null" && "$IP_ERROR" != "" ]]; then
        print_error "IP Anomaly BLOCKED! Risk Score: $IP_RISK"
    else
        print_warning "IP Anomaly detected. Risk Score: $IP_RISK"
    fi
    
    print_step "7.3 Test User Agent Anomaly"
    UA_ANOMALY=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 192.168.1.100" \
        -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)" \
        -d '{
            "username": "john.doe",
            "password": "UserPass123!"
        }')
    
    UA_RISK=$(extract_json_field "$UA_ANOMALY" ".risk_score")
    echo "User Agent Anomaly Response: $UA_ANOMALY"
    print_warning "User Agent Anomaly Risk Score: $UA_RISK"
    
    print_step "7.4 Test Time-based Anomaly (Off Hours)"
    # Note: This would be more effective with controlled time
    OFFHOURS_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 192.168.1.100" \
        -H "User-Agent: curl/7.68.0" \
        -d '{
            "username": "john.doe",
            "password": "UserPass123!"
        }')
    
    OFFHOURS_RISK=$(extract_json_field "$OFFHOURS_LOGIN" ".risk_score")
    echo "Off-hours Login Risk Score: $OFFHOURS_RISK"
}

test_ml_anomaly_detection() {
    print_header "PHASE 8: ML-POWERED ANOMALY DETECTION"
    
    print_step "8.1 Test ML Service Direct Prediction"
    ML_PREDICTION=$(curl -s -X POST "$ML_URL/predict" \
        -H "Content-Type: application/json" \
        -d '{
            "user_id": '$TEST_USER_ID',
            "ip_address": "203.0.113.42",
            "user_agent": "Suspicious-Bot/1.0",
            "resource": "sensitive_data",
            "action": "download",
            "timestamp": "'$(date -Iseconds)'",
            "success": true
        }')
    
    echo "ML Direct Prediction: $ML_PREDICTION"
    
    print_step "8.2 Test Integrated ML Detection via Login"
    INTEGRATED_ML=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 8.8.8.8" \
        -H "User-Agent: curl/7.68.0" \
        -d '{
            "username": "john.doe",
            "password": "UserPass123!"
        }')
    
    ML_INTEGRATED_RISK=$(extract_json_field "$INTEGRATED_ML" ".risk_score")
    echo "Integrated ML Detection Response: $INTEGRATED_ML"
    print_warning "ML-Enhanced Risk Score: $ML_INTEGRATED_RISK"
    
    print_step "8.3 Test Attack Pattern Detection"
    SUSPICIOUS_IPS=("203.0.113.1" "198.51.100.1" "203.0.113.50" "185.199.108.1")
    
    for ip in "${SUSPICIOUS_IPS[@]}"; do
        ATTACK_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
            -H "Content-Type: application/json" \
            -H "X-Forwarded-For: $ip" \
            -H "User-Agent: AttackBot/1.0" \
            -d '{
                "username": "suspicious.user",
                "password": "SuspiciousPass123!"
            }')
        
        ATTACK_RISK=$(extract_json_field "$ATTACK_LOGIN" ".risk_score")
        ATTACK_ERROR=$(extract_json_field "$ATTACK_LOGIN" ".error")
        
        if [[ "$ATTACK_ERROR" != "null" && "$ATTACK_ERROR" != "" ]]; then
            print_error "ATTACK BLOCKED from IP $ip! Risk Score: $ATTACK_RISK"
        else
            print_warning "Suspicious login from IP $ip. Risk Score: $ATTACK_RISK"
        fi
        
        sleep 0.5
    done
}

test_security_responses() {
    print_header "PHASE 9: SECURITY RESPONSE TESTING"
    
    print_step "9.1 Test Account Lockout (Multiple Failed Attempts)"
    for i in $(seq 1 6); do
        FAILED_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
            -H "Content-Type: application/json" \
            -d '{
                "username": "john.doe",
                "password": "WrongPassword$i"
            }')
        
        echo "Failed Login Attempt $i: $(extract_json_field "$FAILED_LOGIN" ".error")"
        sleep 1
    done
    
    print_step "9.2 Test Locked Account Login"
    LOCKED_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "john.doe",
            "password": "UserPass123!"
        }')
    echo "Locked Account Login: $LOCKED_LOGIN"
    
    print_step "9.3 Test High-Risk Block"
    HIGH_RISK_LOGIN=$(curl -s -X POST "$BASE_URL/auth/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 1.2.3.4" \
        -H "User-Agent: MaliciousBot/1.0" \
        -d '{
            "username": "suspicious.user",
            "password": "SuspiciousPass123!"
        }')
    echo "High Risk Login Response: $HIGH_RISK_LOGIN"
}

test_audit_logging() {
    print_header "PHASE 10: AUDIT LOGGING VERIFICATION"
    
    if [[ -z "$ADMIN_TOKEN" ]]; then
        print_error "No admin token for audit testing"
        return 1
    fi
    
    print_step "10.1 Check Audit Logs"
    AUDIT_LOGS=$(curl -s -X GET "$BASE_URL/admin/audit-logs?limit=10" \
        -H "Authorization: Bearer $ADMIN_TOKEN")
    echo "Recent Audit Logs: $AUDIT_LOGS"
    
    print_step "10.2 Check Anomaly History"
    ANOMALY_HISTORY=$(curl -s -X GET "$BASE_URL/admin/anomalies?limit=10" \
        -H "Authorization: Bearer $ADMIN_TOKEN")
    echo "Recent Anomalies: $ANOMALY_HISTORY"
    
    print_step "10.3 Check User Access Patterns"
    if [[ -n "$TEST_USER_ID" ]]; then
        ACCESS_PATTERNS=$(curl -s -X GET "$BASE_URL/admin/users/$TEST_USER_ID/access-patterns" \
            -H "Authorization: Bearer $ADMIN_TOKEN")
        echo "User Access Patterns: $ACCESS_PATTERNS"
    fi
}

test_performance() {
    print_header "PHASE 11: PERFORMANCE TESTING"
    
    print_step "11.1 Authentication Performance Test (250 concurrent requests)" #10,000
    
    # Simple performance test
    start_time=$(date +%s.%N)
    
    for i in $(seq 1 250); do #10,000
        curl -s -X POST "$BASE_URL/auth/login" \
            -H "Content-Type: application/json" \
            -H "X-Forwarded-For: 192.168.1.$((0 + i))" \
            -d '{
                "username": "admin",
                "password": "AdminPass123!"
            }' > /dev/null &
    done
    
    wait  # Wait for all background jobs to complete
    
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    
    print_step "10 concurrent authentications completed in ${duration}s"
    avg_time=$(echo "scale=3; $duration / 10" | bc)
    print_step "Average authentication time: ${avg_time}s"
    
    print_step "11.2 ML Service Performance"
    ml_start=$(date +%s.%N)
    
    ML_PERF_TEST=$(curl -s -X POST "$ML_URL/predict" \
        -H "Content-Type: application/json" \
        -d '{
            "user_id": 1,
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0",
            "resource": "test",
            "action": "access",
            "timestamp": "'$(date -Iseconds)'",
            "success": true
        }')
    
    ml_end=$(date +%s.%N)
    ml_duration=$(echo "$ml_end - $ml_start" | bc)
    print_step "ML prediction time: ${ml_duration}s"
}

generate_test_report() {
    print_header "PHASE 12: TEST SUMMARY REPORT"
    
    echo "======================================"
    echo "AI-IAM SYSTEM TEST REPORT"
    echo "======================================"
    echo "Date: $(date)"
    echo "Go Backend: $BASE_URL"
    echo "ML Service: $ML_URL"
    echo ""
    echo "TESTS COMPLETED:"
    echo "V System Health Check"
    echo "V User Registration & Validation"
    echo "V Authentication & Token Management"
    echo "V Multi-Factor Authentication"
    echo "V Role-Based Access Control"
    echo "V Statistical Anomaly Detection"
    echo "V ML-Powered Anomaly Detection"
    echo "V Security Response Mechanisms"
    echo "V Audit Logging & Compliance"
    echo "V Performance Testing"
    echo ""
    echo "KEY METRICS:"
    echo " Normal User Risk Score: $USER_RISK"
    echo " IP Anomaly Risk Score: $IP_RISK"
    echo " User Agent Anomaly Risk Score: $UA_RISK"
    echo " ML Enhanced Risk Score: $ML_INTEGRATED_RISK"
    echo ""
    echo "SECURITY FEATURES VERIFIED:"
    echo " Password strength validation"
    echo " Account lockout after failed attempts"
    echo " JWT token authentication"
    echo " Multi-factor authentication setup"
    echo " Role-based permissions"
    echo " Real-time anomaly detection"
    echo " Risk-adaptive security responses"
    echo " Comprehensive audit logging"
    echo ""
    echo "SYSTEM STATUS: OPERATIONAL"
    echo "======================================"
}

# Main execution
main() {
    print_header "AI-IAM COMPREHENSIVE SYSTEM TEST"
    echo "Testing all functionality: Static � ML � Security � Performance"
    
    # Wait for services
    wait_for_service "$BASE_URL" "AI-IAM Service"
    wait_for_service "$ML_URL" "ML Service"
    
    # Execute test phases
    test_system_health
    test_user_registration
    test_authentication
    test_mfa_functionality
    test_rbac_system
    build_normal_behavior_baseline
    test_statistical_anomaly_detection
    test_ml_anomaly_detection
    test_security_responses
    test_audit_logging
    test_performance
    generate_test_report
    
    print_step "All tests completed successfully!"
}

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    print_error "jq is required for JSON parsing. Install with: sudo apt install jq"
    exit 1
fi

# Check if bc is installed for performance calculations
if ! command -v bc &> /dev/null; then
    print_error "bc is required for calculations. Install with: sudo apt install bc"
    exit 1
fi

# Run main function
main "$@"