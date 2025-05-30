package auth_test

import (
	"testing"
	"time"

	"github.com/u11336/ai-iam/internal/core/auth"
	"github.com/u11336/ai-iam/internal/data/models"
	"github.com/u11336/ai-iam/internal/tests/mocks"
)

func TestAnomalyDetection(t *testing.T) {
	// Create mock repository
	auditRepo := mocks.NewMockAuditRepository()

	// Create anomaly detector
	detector := auth.NewAnomalyDetector(auditRepo)

	// Create a test user
	userID := int64(1)

	// Add normal access pattern data
	auditRepo.AddTestAccessLogs(userID, 20, "192.168.1.1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "users", "read")

	// Test cases for anomaly detection
	tests := []struct {
		name           string
		accessLog      *models.AccessLog
		expectHighRisk bool
	}{
		{
			name: "Normal access pattern",
			accessLog: &models.AccessLog{
				UserID:     userID,
				IPAddress:  "192.168.1.1",
				UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				Resource:   "users",
				Action:     "read",
				AccessTime: time.Now().Hour()*60 + time.Now().Minute(),
				DayOfWeek:  int(time.Now().Weekday()),
			},
			expectHighRisk: false,
		},
		{
			name: "Different IP address",
			accessLog: &models.AccessLog{
				UserID:     userID,
				IPAddress:  "10.0.0.1", // Different IP
				UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				Resource:   "users",
				Action:     "read",
				AccessTime: time.Now().Hour()*60 + time.Now().Minute(),
				DayOfWeek:  int(time.Now().Weekday()),
			},
			expectHighRisk: true,
		},
		{
			name: "Different user agent",
			accessLog: &models.AccessLog{
				UserID:     userID,
				IPAddress:  "192.168.1.1",
				UserAgent:  "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)", // Different user agent
				Resource:   "users",
				Action:     "read",
				AccessTime: time.Now().Hour()*60 + time.Now().Minute(),
				DayOfWeek:  int(time.Now().Weekday()),
			},
			expectHighRisk: true,
		},
		{
			name: "Different resource",
			accessLog: &models.AccessLog{
				UserID:     userID,
				IPAddress:  "192.168.1.1",
				UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				Resource:   "admin", // Different resource
				Action:     "write",
				AccessTime: time.Now().Hour()*60 + time.Now().Minute(),
				DayOfWeek:  int(time.Now().Weekday()),
			},
			expectHighRisk: true,
		},
		{
			name: "Unusual time",
			accessLog: &models.AccessLog{
				UserID:     userID,
				IPAddress:  "192.168.1.1",
				UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				Resource:   "users",
				Action:     "read",
				AccessTime: (time.Now().Hour()+12)%24*60 + time.Now().Minute(), // 12 hours offset
				DayOfWeek:  int(time.Now().Weekday()),
			},
			expectHighRisk: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			riskScore, anomalyType := detector.CalculateRiskScore(tc.accessLog)

			t.Logf("Risk score: %f, Anomaly type: %s", riskScore, anomalyType)

			if tc.expectHighRisk && riskScore < 0.7 {
				t.Errorf("Expected high risk score (≥0.7) but got %f", riskScore)
			}

			if !tc.expectHighRisk && riskScore >= 0.7 {
				t.Errorf("Expected low risk score (<0.7) but got %f", riskScore)
			}

			if riskScore >= 0.7 && anomalyType == "none" {
				t.Errorf("Expected anomaly type to be set for high risk score")
			}
		})
	}
}

func TestAnomalyClassification(t *testing.T) {
	// Create mock repository
	auditRepo := mocks.NewMockAuditRepository()

	// Create anomaly detector
	detector := auth.NewAnomalyDetector(auditRepo)

	// Test user agent classification
	userAgents := []struct {
		name     string
		agent    string
		expected string
	}{
		{"Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "windows"},
		{"macOS", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36", "mac"},
		{"Linux", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", "linux"},
		{"Android", "Mozilla/5.0 (Linux; Android 10; SM-A505F) AppleWebKit/537.36", "android"},
		{"iOS", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15", "ios"},
		{"Mobile", "Mozilla/5.0 (Mobile; Windows Phone 8.1; Android 4.0; ARM; Trident/7.0)", "mobile"},
		{"Bot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "bot"},
		{"Unknown", "Unknown User Agent", "other"},
	}

	for _, tc := range userAgents {
		t.Run(tc.name, func(t *testing.T) {
			// We need to access the private method, so we'll test it indirectly
			// Create an access log with this user agent
			accessLog := &models.AccessLog{
				UserID:     1,
				IPAddress:  "127.0.0.1",
				UserAgent:  tc.agent,
				Resource:   "test",
				Action:     "test",
				AccessTime: 720, // Noon
				DayOfWeek:  1,   // Monday
			}

			// Calculate risk score - this will use the classifyUserAgent method
			score, anomalyType := detector.CalculateRiskScore(accessLog)

			// Log the results for debugging
			t.Logf("Agent: %s, Score: %f, Type: %s", tc.agent, score, anomalyType)
		})
	}
}
