#!/bin/bash

# Define colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Running AI-IAM system tests...${NC}"
echo "======================="

# Track if any tests fail
FAILED=0

# Run utility tests
echo -e "${YELLOW}Running utility tests...${NC}"
go test -v github.com/u11336/ai-iam/internal/utils
if [ $? -ne 0 ]; then
    FAILED=1
    echo -e "${RED}Utility tests failed!${NC}"
else
    echo -e "${GREEN}Utility tests passed!${NC}"
fi
echo ""

# Run data repository tests
echo -e "${YELLOW}Running repository tests...${NC}"
go test -v github.com/u11336/ai-iam/internal/data/repository
if [ $? -ne 0 ]; then
    FAILED=1
    echo -e "${RED}Repository tests failed!${NC}"
else
    echo -e "${GREEN}Repository tests passed!${NC}"
fi
echo ""

# Run authentication service tests
echo -e "${YELLOW}Running authentication service tests...${NC}"
go test -v github.com/u11336/ai-iam/internal/core/auth
if [ $? -ne 0 ]; then
    FAILED=1
    echo -e "${RED}Authentication service tests failed!${NC}"
else
    echo -e "${GREEN}Authentication service tests passed!${NC}"
fi
echo ""

# Run API handler tests
echo -e "${YELLOW}Running API handler tests...${NC}"
go test -v github.com/u11336/ai-iam/internal/api
if [ $? -ne 0 ]; then
    FAILED=1
    echo -e "${RED}API handler tests failed!${NC}"
else
    echo -e "${GREEN}API handler tests passed!${NC}"
fi
echo ""

# Run all tests with coverage
echo -e "${YELLOW}Running all tests with coverage...${NC}"
go test -cover ./...
echo ""

# Check if any tests failed
if [ $FAILED -eq 1 ]; then
    echo -e "${RED}Some tests failed! Please check the output above.${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed successfully!${NC}"
    exit 0
fi