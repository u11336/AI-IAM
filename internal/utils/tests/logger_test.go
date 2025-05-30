package utils_test

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/u11336/ai-iam/internal/utils"
)

func TestLogger(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer
	testLogger := log.New(&buf, "", 0)

	// Create a logger with our test logger
	logger := &utils.Logger{}

	// Use reflection to set the internal logger to our test logger
	// Note: This is a bit of a hack for testing; in a real application,
	// we might want to make the logger field exported or provide a constructor
	// that accepts a custom logger for testing.
	logger.SetLogger(testLogger)

	// Disable caller information for testing
	logger.SetShowCaller(false)

	// Test different log levels
	logger.Info("Test info message")
	if !strings.Contains(buf.String(), "INFO") || !strings.Contains(buf.String(), "Test info message") {
		t.Errorf("Expected INFO message in log, got: %s", buf.String())
	}

	// Reset buffer
	buf.Reset()

	// Test with key-value pairs
	logger.Error("Test error message", "key1", "value1", "key2", 42)
	output := buf.String()
	if !strings.Contains(output, "ERROR") ||
		!strings.Contains(output, "Test error message") ||
		!strings.Contains(output, "key1=value1") ||
		!strings.Contains(output, "key2=42") {
		t.Errorf("Expected ERROR message with key-value pairs in log, got: %s", output)
	}

	// Reset buffer
	buf.Reset()

	// Test odd number of key-value pairs
	logger.Warn("Test warning message", "odd_key")
	output = buf.String()
	if !strings.Contains(output, "WARN") ||
		!strings.Contains(output, "Test warning message") ||
		!strings.Contains(output, "odd_key=MISSING") {
		t.Errorf("Expected WARN message with odd key-value pair in log, got: %s", output)
	}
}

func TestLogLevels(t *testing.T) {
	// Create a buffer to capture log output
	var buf bytes.Buffer
	testLogger := log.New(&buf, "", 0)

	// Create a logger with our test logger
	logger := &utils.Logger{}
	logger.SetLogger(testLogger)
	logger.SetShowCaller(false)

	// Set log level to WARN
	logger.SetLevel(utils.WARN)

	// Debug and Info should not be logged
	logger.Debug("Test debug message")
	if buf.String() != "" {
		t.Errorf("Expected no DEBUG message in log, got: %s", buf.String())
	}

	logger.Info("Test info message")
	if buf.String() != "" {
		t.Errorf("Expected no INFO message in log, got: %s", buf.String())
	}

	// Warn, Error, Fatal should be logged
	logger.Warn("Test warn message")
	if !strings.Contains(buf.String(), "WARN") || !strings.Contains(buf.String(), "Test warn message") {
		t.Errorf("Expected WARN message in log, got: %s", buf.String())
	}

	// Reset buffer
	buf.Reset()

	logger.Error("Test error message")
	if !strings.Contains(buf.String(), "ERROR") || !strings.Contains(buf.String(), "Test error message") {
		t.Errorf("Expected ERROR message in log, got: %s", buf.String())
	}

	// Note: We can't easily test Fatal since it calls os.Exit(1)
}
