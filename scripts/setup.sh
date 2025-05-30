#!/bin/bash

# Check if Go is installed
if ! command -v go &> /dev/null
then
    echo "Error: Go is not installed or not in PATH"
    exit 1
fi

# Create module
echo "Initializing Go module..."
go mod init github.com/u11336/ai-iam

# Install dependencies
echo "Installing dependencies..."
go get github.com/dgrijalva/jwt-go@v3.2.0+incompatible
go get github.com/go-chi/chi/v5@v5.0.8
go get github.com/mattn/go-sqlite3@v1.14.16
go get github.com/pquerna/otp@v1.4.0
go get golang.org/x/crypto@v0.11.0

# Create database directory if it doesn't exist
mkdir -p data

# Create a basic config.json file
cat > config.json << EOF
{
  "port": 8080,
  "database_path": "./data/iam.db",
  "jwt_secret": "change-me-in-production",
  "jwt_expiration_hours": 24,
  "mfa_enabled": true,
  "anomaly_detection_on": true,
  "risk_threshold_low": 0.3,
  "risk_threshold_medium": 0.6,
  "risk_threshold_high": 0.9
}
EOF

echo "Setup complete!"
echo "You can now run the application with: go run cmd/server/main.go"