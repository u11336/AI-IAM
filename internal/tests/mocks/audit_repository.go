package mocks

import (
	"time"

	"github.com/u11336/ai-iam/internal/data/models"
)

// MockAuditRepository is a mock implementation of AuditRepository for testing
type MockAuditRepository struct {
	auditLogs     []models.AuditLog
	accessLogs    []models.AccessLog
	anomalies     []models.AnomalyDetection
	nextAuditID   int64
	nextAccessID  int64
	nextAnomalyID int64
}

// NewMockAuditRepository creates a new mock audit repository
func NewMockAuditRepository() *MockAuditRepository {
	return &MockAuditRepository{
		auditLogs:     []models.AuditLog{},
		accessLogs:    []models.AccessLog{},
		anomalies:     []models.AnomalyDetection{},
		nextAuditID:   1,
		nextAccessID:  1,
		nextAnomalyID: 1,
	}
}

// CreateAuditLog creates a new audit log entry
func (r *MockAuditRepository) CreateAuditLog(log *models.AuditLog) error {
	log.ID = r.nextAuditID
	r.nextAuditID++
	log.Timestamp = time.Now()

	r.auditLogs = append(r.auditLogs, *log)
	return nil
}

// GetAuditLogs retrieves audit logs with pagination and filtering
func (r *MockAuditRepository) GetAuditLogs(userID int64, eventType, status string, limit, offset int) ([]*models.AuditLog, error) {
	var filtered []*models.AuditLog

	// Apply filters
	for i, log := range r.auditLogs {
		if userID > 0 && log.UserID != userID {
			continue
		}

		if eventType != "" && log.EventType != eventType {
			continue
		}

		if status != "" && log.Status != status {
			continue
		}

		// Apply pagination
		if len(filtered) >= offset && len(filtered) < offset+limit {
			// Create a copy to avoid modifying the original
			logCopy := r.auditLogs[i]
			filtered = append(filtered, &logCopy)
		}

		if len(filtered) >= offset+limit {
			break
		}
	}

	return filtered, nil
}

// CreateAccessLog creates a new access log entry for anomaly detection
func (r *MockAuditRepository) CreateAccessLog(log *models.AccessLog) error {
	log.ID = r.nextAccessID
	r.nextAccessID++
	log.Timestamp = time.Now()

	r.accessLogs = append(r.accessLogs, *log)
	return nil
}

// GetUserAccessLogs retrieves access logs for a specific user
func (r *MockAuditRepository) GetUserAccessLogs(userID int64, limit int) ([]*models.AccessLog, error) {
	var filtered []*models.AccessLog

	// Filter by user ID and apply limit
	for i, log := range r.accessLogs {
		if log.UserID == userID {
			// Create a copy to avoid modifying the original
			logCopy := r.accessLogs[i]
			filtered = append(filtered, &logCopy)

			if len(filtered) >= limit {
				break
			}
		}
	}

	return filtered, nil
}

// GetUserAccessPattern retrieves access patterns for anomaly detection
func (r *MockAuditRepository) GetUserAccessPattern(userID int64, lookbackDays int) ([]*models.AccessLog, error) {
	var filtered []*models.AccessLog
	cutoff := time.Now().AddDate(0, 0, -lookbackDays)

	// Filter by user ID and lookback period
	for i, log := range r.accessLogs {
		if log.UserID == userID && log.Timestamp.After(cutoff) {
			// Create a copy to avoid modifying the original
			logCopy := r.accessLogs[i]
			filtered = append(filtered, &logCopy)
		}
	}

	return filtered, nil
}

// RecordAnomaly records a detected anomaly
func (r *MockAuditRepository) RecordAnomaly(anomaly *models.AnomalyDetection) error {
	anomaly.ID = r.nextAnomalyID
	r.nextAnomalyID++
	anomaly.Timestamp = time.Now()

	r.anomalies = append(r.anomalies, *anomaly)
	return nil
}

// GetUserAnomalies retrieves anomalies for a specific user
func (r *MockAuditRepository) GetUserAnomalies(userID int64, limit int) ([]*models.AnomalyDetection, error) {
	var filtered []*models.AnomalyDetection

	// Filter by user ID and apply limit
	for i, anomaly := range r.anomalies {
		if anomaly.UserID == userID {
			// Create a copy to avoid modifying the original
			anomalyCopy := r.anomalies[i]
			filtered = append(filtered, &anomalyCopy)

			if len(filtered) >= limit {
				break
			}
		}
	}

	return filtered, nil
}

// GetAuditLogsForTests returns all audit logs for testing purposes
func (r *MockAuditRepository) GetAuditLogsForTests() []models.AuditLog {
	return r.auditLogs
}

// GetAccessLogsForTests returns all access logs for testing purposes
func (r *MockAuditRepository) GetAccessLogsForTests() []models.AccessLog {
	return r.accessLogs
}

// GetAnomaliesForTests returns all anomalies for testing purposes
func (r *MockAuditRepository) GetAnomaliesForTests() []models.AnomalyDetection {
	return r.anomalies
}

// AddTestAccessLogs adds test access logs for anomaly detection testing
func (r *MockAuditRepository) AddTestAccessLogs(userID int64, count int, ipAddress, userAgent, resource, action string) {
	// Add some normal access logs
	now := time.Now()
	dayMinutes := now.Hour()*60 + now.Minute()
	dayOfWeek := int(now.Weekday())

	for i := 0; i < count; i++ {
		log := models.AccessLog{
			ID:         r.nextAccessID,
			UserID:     userID,
			IPAddress:  ipAddress,
			UserAgent:  userAgent,
			Resource:   resource,
			Action:     action,
			Timestamp:  now.Add(time.Duration(-i) * time.Hour), // Spaced one hour apart
			AccessTime: dayMinutes,
			DayOfWeek:  dayOfWeek,
			Success:    true,
		}
		r.nextAccessID++
		r.accessLogs = append(r.accessLogs, log)
	}
}

// AddCustomAccessLog adds a customized access log (used for testing frequency patterns)
func (r *MockAuditRepository) AddCustomAccessLog(log models.AccessLog) {
	// Set ID if not provided
	if log.ID == 0 {
		log.ID = r.nextAccessID
		r.nextAccessID++
	} else if log.ID >= r.nextAccessID {
		// Update nextAccessID if the provided ID is higher
		r.nextAccessID = log.ID + 1
	}

	r.accessLogs = append(r.accessLogs, log)
}

// GetLatestAccessLog gets the most recent access log for a user
func (r *MockAuditRepository) GetLatestAccessLog(userID int64) *models.AccessLog {
	var latest *models.AccessLog
	var latestTime time.Time

	for i, log := range r.accessLogs {
		if log.UserID == userID && (latest == nil || log.Timestamp.After(latestTime)) {
			latest = &r.accessLogs[i]
			latestTime = log.Timestamp
		}
	}

	return latest
}
