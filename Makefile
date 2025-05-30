# AI-IAM System Makefile

# Variables
BINARY_NAME=ai-iam
GO=go
GO_BUILD=$(GO) build
GO_TEST=$(GO) test
GO_CLEAN=$(GO) clean
GO_GET=$(GO) get
GO_MOD=$(GO) mod
GO_VET=$(GO) vet
GO_FMT=$(GO) fmt
MAIN_PATH=cmd/server/main.go

# Build flags
BUILD_FLAGS=-v

# Default target executed when no arguments are provided to make
all: test build

# Builds the binary
build:
	@echo "Building binary..."
	$(GO_BUILD) $(BUILD_FLAGS) -o bin/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Build complete!"

# Runs the application
run: build
	@echo "Running application..."
	./bin/$(BINARY_NAME)

# Installs dependencies
deps:
	@echo "Installing dependencies..."
	$(GO_MOD) tidy
	@echo "Dependencies installed!"

# Tests the application
test:
	@echo "Running tests..."
	$(GO_TEST) -v ./...
	@echo "Tests complete!"

# Run test coverage
cover:
	@echo "Running test coverage..."
	$(GO_TEST) -cover ./...
	@echo "Test coverage complete!"

# Generate test coverage report
cover-html:
	@echo "Generating test coverage report..."
	$(GO_TEST) -coverprofile=coverage.txt ./...
	$(GO) tool cover -html=coverage.txt -o cover.html
	@echo "Test coverage report generated: cover.html"

# Format code
fmt:
	@echo "Formatting code..."
	$(GO_FMT) ./...
	@echo "Formatting complete!"

# Vet code
vet:
	@echo "Vetting code..."
	$(GO_VET) ./...
	@echo "Vetting complete!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(GO_CLEAN)
	rm -f bin/$(BINARY_NAME)
	@echo "Clean complete!"

# Setup project
setup:
	@echo "Setting up project..."
	chmod +x scripts/setup.sh
	./scripts/setup.sh
	@echo "Setup complete!"

# Clean and rebuild
rebuild: clean build

# Help menu
help:
	@echo "AI-IAM System Makefile Commands:"
	@echo "  make all         - Run tests and build the application"
	@echo "  make build       - Build the application"
	@echo "  make run         - Build and run the application"
	@echo "  make deps        - Install dependencies"
	@echo "  make test        - Run tests"
	@echo "  make cover       - Run test coverage"
	@echo "  make cover-html  - Generate test coverage report"
	@echo "  make fmt         - Format code"
	@echo "  make vet         - Vet code"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make setup       - Setup project"
	@echo "  make rebuild     - Clean and rebuild"
	@echo "  make help        - Show this help menu"

.PHONY: all build run deps test cover cover-html fmt vet clean setup rebuild help