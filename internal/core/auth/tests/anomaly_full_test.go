package auth_test

import (
	"testing"
	"time"

	"github.com/u11336/ai-iam/internal/core/auth"
	"github.com/u11336/ai-iam/internal/data/models"
	"github.com/u11336/ai-iam/internal/tests/mocks"
)

func setupAnomalyDetector() (*auth.AnomalyDetector, *mocks.MockAuditRepository, int64) {
	// Create mock repository
	auditRepo := mocks.NewMockAuditRepository()

	// Create anomaly detector
	detector := auth.NewAnomalyDetector(auditRepo)

	// Create a test user
	userID := int64(1)

	// Add normal access pattern data
	auditRepo.AddTestAccessLogs(
		userID,
		20,
		"192.168.1.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
		"users",
		"read",
	)

	return detector, auditRepo, userID
}

func TestTimeBasedAnomalies(t *testing.T) {
	detector, _, userID := setupAnomalyDetector()

	// Get current time
	now := time.Now()
	dayMinutes := now.Hour()*60 + now.Minute()
	dayOfWeek := int(now.Weekday())

	// Test cases for different times
	tests := []struct {
		name         string
		accessTime   int
		dayOfWeek    int
		expectHigher bool
	}{
		{
			name:         "Normal time",
			accessTime:   dayMinutes,
			dayOfWeek:    dayOfWeek,
			expectHigher: false,
		},
		{
			name:         "Off-hours (middle of night)",
			accessTime:   3 * 60, // 3:00 AM
			dayOfWeek:    dayOfWeek,
			expectHigher: true,
		},
		{
			name:         "Weekend (if today is weekday)",
			accessTime:   dayMinutes,
			dayOfWeek:    (dayOfWeek + 3) % 7, // Shift to weekend if currently weekday
			expectHigher: true,
		},
	}

	// Reference log for normal time
	normalLog := &models.AccessLog{
		UserID:     userID,
		IPAddress:  "192.168.1.1",
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
		Resource:   "users",
		Action:     "read",
		AccessTime: dayMinutes,
		DayOfWeek:  dayOfWeek,
	}
	normalRiskScore, _ := detector.CalculateRiskScore(normalLog)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create access log with test time
			accessLog := &models.AccessLog{
				UserID:     userID,
				IPAddress:  "192.168.1.1",
				UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
				Resource:   "users",
				Action:     "read",
				AccessTime: tc.accessTime,
				DayOfWeek:  tc.dayOfWeek,
			}

			// Calculate risk score
			riskScore, anomalyType := detector.CalculateRiskScore(accessLog)

			// Log for debugging
			t.Logf("Time: %d, Day: %d, Risk: %f, Type: %s", tc.accessTime, tc.dayOfWeek, riskScore, anomalyType)

			// Compare with normal score
			if tc.expectHigher && riskScore <= normalRiskScore {
				t.Errorf("Expected higher risk score for %s but got %f (normal: %f)", tc.name, riskScore, normalRiskScore)
			}

			if !tc.expectHigher && riskScore > normalRiskScore*1.5 {
				t.Errorf("Expected similar risk score for %s but got %f (normal: %f)", tc.name, riskScore, normalRiskScore)
			}
		})
	}
}

func TestLocationBasedAnomalies(t *testing.T) {
	detector, _, userID := setupAnomalyDetector()

	// Test cases for different IP addresses
	tests := []struct {
		name       string
		ipAddress  string
		expectRisk bool
	}{
		{
			name:       "Normal IP",
			ipAddress:  "192.168.1.1",
			expectRisk: false,
		},
		{
			name:       "Different subnet",
			ipAddress:  "192.168.2.1",
			expectRisk: true,
		},
		{
			name:       "Different class",
			ipAddress:  "10.0.0.1",
			expectRisk: true,
		},
	}

	// Get current time
	now := time.Now()
	dayMinutes := now.Hour()*60 + now.Minute()
	dayOfWeek := int(now.Weekday())

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create access log with test IP
			accessLog := &models.AccessLog{
				UserID:     userID,
				IPAddress:  tc.ipAddress,
				UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
				Resource:   "users",
				Action:     "read",
				AccessTime: dayMinutes,
				DayOfWeek:  dayOfWeek,
			}

			// Calculate risk score
			riskScore, anomalyType := detector.CalculateRiskScore(accessLog)

			// Log for debugging
			t.Logf("IP: %s, Risk: %f, Type: %s", tc.ipAddress, riskScore, anomalyType)

			// Check if risk is as expected
			isHighRisk := riskScore >= 0.7
			if tc.expectRisk && !isHighRisk {
				t.Errorf("Expected high risk for %s but got %f", tc.name, riskScore)
			}

			if !tc.expectRisk && isHighRisk {
				t.Errorf("Expected low risk for %s but got %f", tc.name, riskScore)
			}

			// If high risk, check if type is location
			if isHighRisk && tc.expectRisk && anomalyType != "location" {
				t.Errorf("Expected location anomaly type but got %s", anomalyType)
			}
		})
	}
}

func TestResourceBasedAnomalies(t *testing.T) {
	detector, _, userID := setupAnomalyDetector()

	// Test cases for different resources
	tests := []struct {
		name       string
		resource   string
		action     string
		expectRisk bool
	}{
		{
			name:       "Normal resource",
			resource:   "users",
			action:     "read",
			expectRisk: false,
		},
		{
			name:       "Sensitive resource",
			resource:   "admin",
			action:     "write",
			expectRisk: true,
		},
		{
			name:       "Normal resource, unusual action",
			resource:   "users",
			action:     "delete",
			expectRisk: true,
		},
	}

	// Get current time
	now := time.Now()
	dayMinutes := now.Hour()*60 + now.Minute()
	dayOfWeek := int(now.Weekday())

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create access log with test resource
			accessLog := &models.AccessLog{
				UserID:     userID,
				IPAddress:  "192.168.1.1",
				UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
				Resource:   tc.resource,
				Action:     tc.action,
				AccessTime: dayMinutes,
				DayOfWeek:  dayOfWeek,
			}

			// Calculate risk score
			riskScore, anomalyType := detector.CalculateRiskScore(accessLog)

			// Log for debugging
			t.Logf("Resource: %s, Action: %s, Risk: %f, Type: %s",
				tc.resource, tc.action, riskScore, anomalyType)

			// Check if risk is as expected
			isHighRisk := riskScore >= 0.7
			if tc.expectRisk && !isHighRisk {
				t.Errorf("Expected high risk for %s but got %f", tc.name, riskScore)
			}

			if !tc.expectRisk && isHighRisk {
				t.Errorf("Expected low risk for %s but got %f", tc.name, riskScore)
			}

			// If high risk, check if type is resource
			if isHighRisk && tc.expectRisk && anomalyType != "resource" {
				t.Errorf("Expected resource anomaly type but got %s", anomalyType)
			}
		})
	}
}

func TestBehaviorBasedAnomalies(t *testing.T) {
	detector, auditRepo, userID := setupAnomalyDetector()

	// Add some normal access logs
	auditRepo.AddTestAccessLogs(
		userID,
		20,
		"192.168.1.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
		"users",
		"read",
	)

	// Test cases for different user agents
	tests := []struct {
		name       string
		userAgent  string
		expectRisk bool
	}{
		{
			name:       "Normal browser",
			userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
			expectRisk: false,
		},
		{
			name:       "Different browser",
			userAgent:  "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
			expectRisk: true,
		},
		{
			name:       "Bot user agent",
			userAgent:  "Googlebot/2.1 (+http://www.google.com/bot.html)",
			expectRisk: true,
		},
	}

	// Get current time
	now := time.Now()
	dayMinutes := now.Hour()*60 + now.Minute()
	dayOfWeek := int(now.Weekday())

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create access log with test user agent
			accessLog := &models.AccessLog{
				UserID:     userID,
				IPAddress:  "192.168.1.1",
				UserAgent:  tc.userAgent,
				Resource:   "users",
				Action:     "read",
				AccessTime: dayMinutes,
				DayOfWeek:  dayOfWeek,
			}

			// Calculate risk score
			riskScore, anomalyType := detector.CalculateRiskScore(accessLog)

			// Log for debugging
			t.Logf("UserAgent: %s, Risk: %f, Type: %s", tc.userAgent, riskScore, anomalyType)

			// Check if risk is as expected
			isHighRisk := riskScore >= 0.7
			if tc.expectRisk && !isHighRisk {
				t.Errorf("Expected high risk for %s but got %f", tc.name, riskScore)
			}

			if !tc.expectRisk && isHighRisk {
				t.Errorf("Expected low risk for %s but got %f", tc.name, riskScore)
			}

			// If high risk, check if type is behavior
			if isHighRisk && tc.expectRisk && anomalyType != "behavior" {
				t.Errorf("Expected behavior anomaly type but got %s", anomalyType)
			}
		})
	}
}

func TestFrequencyBasedAnomalies(t *testing.T) {
	detector, auditRepo, userID := setupAnomalyDetector()

	// Add access logs with specific spacing
	// These logs will be spaced 1 hour apart
	baseTime := time.Now().Add(-24 * time.Hour)
	for i := 0; i < 10; i++ {
		accessTime := baseTime.Add(time.Duration(i) * time.Hour)
		log := models.AccessLog{
			ID:         int64(i + 1),
			UserID:     userID,
			IPAddress:  "192.168.1.1",
			UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
			Resource:   "users",
			Action:     "read",
			Timestamp:  accessTime,
			AccessTime: accessTime.Hour()*60 + accessTime.Minute(),
			DayOfWeek:  int(accessTime.Weekday()),
			Success:    true,
		}
		auditRepo.AddCustomAccessLog(log)
	}

	// Test cases for frequency anomalies
	tests := []struct {
		name       string
		timeDelta  time.Duration
		expectRisk bool
	}{
		{
			name:       "Normal frequency",
			timeDelta:  time.Hour, // 1 hour since last access (matches pattern)
			expectRisk: false,
		},
		{
			name:       "Rapid access",
			timeDelta:  time.Minute, // 1 minute since last access (too fast)
			expectRisk: true,
		},
		{
			name:       "Very long gap",
			timeDelta:  48 * time.Hour, // 48 hours since last access (too slow)
			expectRisk: true,
		},
	}

	// Reference time (most recent log)
	lastLog := auditRepo.GetLatestAccessLog(userID)
	lastLog.Timestamp.Add(time.Hour) // Normal would be 1 hour after last log

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Calculate access time based on the time delta
			accessTime := lastLog.Timestamp.Add(tc.timeDelta)

			// Create access log with test timestamp
			accessLog := &models.AccessLog{
				UserID:     userID,
				IPAddress:  "192.168.1.1",
				UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
				Resource:   "users",
				Action:     "read",
				Timestamp:  accessTime,
				AccessTime: accessTime.Hour()*60 + accessTime.Minute(),
				DayOfWeek:  int(accessTime.Weekday()),
			}

			// Calculate risk score
			riskScore, anomalyType := detector.CalculateRiskScore(accessLog)

			// Log for debugging
			t.Logf("Time delta: %v, Risk: %f, Type: %s", tc.timeDelta, riskScore, anomalyType)

			// Check if risk is as expected
			isHighRisk := riskScore >= 0.6 // Lower threshold for frequency-based risks
			if tc.expectRisk && !isHighRisk {
				t.Errorf("Expected high risk for %s but got %f", tc.name, riskScore)
			}

			if !tc.expectRisk && isHighRisk {
				t.Errorf("Expected low risk for %s but got %f", tc.name, riskScore)
			}
		})
	}
}

func TestMultiFactorRiskScoring(t *testing.T) {
	detector, _, userID := setupAnomalyDetector()

	// Get current time
	now := time.Now()
	dayMinutes := now.Hour()*60 + now.Minute()
	dayOfWeek := int(now.Weekday())

	// Test cases combining multiple risk factors
	tests := []struct {
		name       string
		ipAddress  string
		userAgent  string
		resource   string
		action     string
		accessTime int
		dayOfWeek  int
		expectRisk float64 // Expected approximate risk level
	}{
		{
			name:       "No risk factors",
			ipAddress:  "192.168.1.1",
			userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
			resource:   "users",
			action:     "read",
			accessTime: dayMinutes,
			dayOfWeek:  dayOfWeek,
			expectRisk: 0.1, // Low risk
		},
		{
			name:       "One risk factor (IP)",
			ipAddress:  "10.0.0.1", // Different IP class
			userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
			resource:   "users",
			action:     "read",
			accessTime: dayMinutes,
			dayOfWeek:  dayOfWeek,
			expectRisk: 0.7, // Medium-high risk
		},
		{
			name:       "Two risk factors (IP and resource)",
			ipAddress:  "10.0.0.1", // Different IP class
			userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
			resource:   "admin", // Sensitive resource
			action:     "read",
			accessTime: dayMinutes,
			dayOfWeek:  dayOfWeek,
			expectRisk: 0.8, // High risk
		},
		{
			name:       "Three risk factors (IP, resource, and time)",
			ipAddress:  "10.0.0.1", // Different IP class
			userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
			resource:   "admin", // Sensitive resource
			action:     "write", // Sensitive action
			accessTime: 3 * 60,  // 3:00 AM (unusual time)
			dayOfWeek:  dayOfWeek,
			expectRisk: 0.9, // Very high risk
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create access log with test factors
			accessLog := &models.AccessLog{
				UserID:     userID,
				IPAddress:  tc.ipAddress,
				UserAgent:  tc.userAgent,
				Resource:   tc.resource,
				Action:     tc.action,
				AccessTime: tc.accessTime,
				DayOfWeek:  tc.dayOfWeek,
			}

			// Calculate risk score
			riskScore, anomalyType := detector.CalculateRiskScore(accessLog)

			// Log for debugging
			t.Logf("Scenario: %s, Risk: %f, Type: %s", tc.name, riskScore, anomalyType)

			// Check if risk is approximately as expected (±0.2)
			if riskScore < tc.expectRisk-0.2 || riskScore > tc.expectRisk+0.2 {
				t.Errorf("Expected risk score around %f for %s but got %f",
					tc.expectRisk, tc.name, riskScore)
			}
		})
	}
}
