package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/u11336/ai-iam/internal/data/models"
	"github.com/u11336/ai-iam/internal/data/repository"
	"github.com/u11336/ai-iam/internal/utils"
)

type AdminHandler struct {
	userRepo  *repository.UserRepository
	roleRepo  *repository.RoleRepository
	auditRepo *repository.AuditRepository
	logger    *utils.Logger
}

// NewAdminHandler creates a new AdminHandler
func NewAdminHandler(userRepo *repository.UserRepository, roleRepo *repository.RoleRepository, auditRepo *repository.AuditRepository, logger *utils.Logger) *AdminHandler {
	return &AdminHandler{
		userRepo:  userRepo,
		roleRepo:  roleRepo,
		auditRepo: auditRepo,
		logger:    logger,
	}
}

// GetAuditLogs retrieves audit logs with pagination and filtering
func (h *AdminHandler) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	userIDStr := r.URL.Query().Get("user_id")
	eventType := r.URL.Query().Get("event_type")
	status := r.URL.Query().Get("status")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	// Set default values
	limit := 100
	offset := 0
	var userID int64 = 0

	// Parse user ID if provided
	if userIDStr != "" {
		id, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			errorResponse(w, "Invalid user ID", http.StatusBadRequest)
			return
		}
		userID = id
	}

	// Parse limit if provided
	if limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil {
			errorResponse(w, "Invalid limit", http.StatusBadRequest)
			return
		}
		if l > 0 && l <= 1000 {
			limit = l
		}
	}

	// Parse offset if provided
	if offsetStr != "" {
		o, err := strconv.Atoi(offsetStr)
		if err != nil {
			errorResponse(w, "Invalid offset", http.StatusBadRequest)
			return
		}
		if o >= 0 {
			offset = o
		}
	}

	// Get audit logs
	logs, err := h.auditRepo.GetAuditLogs(userID, eventType, status, limit, offset)
	if err != nil {
		h.logger.Error("Error getting audit logs", "error", err)
		errorResponse(w, "Failed to get audit logs", http.StatusInternalServerError)
		return
	}

	writeJSON(w, logs, http.StatusOK)
}

// GetAnomalies retrieves detected anomalies
func (h *AdminHandler) GetAnomalies(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	thresholdStr := r.URL.Query().Get("threshold")

	// Set default values
	limit := 100
	offset := 0
	threshold := 0.7 // Default risk threshold

	// Parse limit if provided
	if limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil {
			errorResponse(w, "Invalid limit", http.StatusBadRequest)
			return
		}
		if l > 0 && l <= 1000 {
			limit = l
		}
	}

	// Parse offset if provided
	if offsetStr != "" {
		o, err := strconv.Atoi(offsetStr)
		if err != nil {
			errorResponse(w, "Invalid offset", http.StatusBadRequest)
			return
		}
		if o >= 0 {
			offset = o
		}
	}

	// Parse threshold if provided
	if thresholdStr != "" {
		t, err := strconv.ParseFloat(thresholdStr, 64)
		if err != nil {
			errorResponse(w, "Invalid threshold", http.StatusBadRequest)
			return
		}
		if t >= 0 && t <= 1 {
			threshold = t
		}
	}

	allAnomalies := []*models.AnomalyDetection{
		{
			ID:          1,
			UserID:      1,
			AccessLogID: 1,
			AnomalyType: "time",
			RiskScore:   0.85,
			ActionTaken: "alert",
			Timestamp:   time.Now().Add(-24 * time.Hour),
		},
		{
			ID:          2,
			UserID:      2,
			AccessLogID: 2,
			AnomalyType: "location",
			RiskScore:   0.92,
			ActionTaken: "block",
			Timestamp:   time.Now().Add(-12 * time.Hour),
		},
		{
			ID:          3,
			UserID:      3,
			AccessLogID: 3,
			AnomalyType: "resource",
			RiskScore:   0.65,
			ActionTaken: "alert",
			Timestamp:   time.Now().Add(-6 * time.Hour),
		},
		{
			ID:          4,
			UserID:      1,
			AccessLogID: 4,
			AnomalyType: "behavior",
			RiskScore:   0.78,
			ActionTaken: "mfa",
			Timestamp:   time.Now().Add(-3 * time.Hour),
		},
	}

	// filtering by treshold
	filteredAnomalies := []*models.AnomalyDetection{}
	for _, anomaly := range allAnomalies {
		if anomaly.RiskScore >= threshold {
			filteredAnomalies = append(filteredAnomalies, anomaly)
		}
	}

	// pagination
	startIndex := offset
	endIndex := offset + limit

	if startIndex >= len(filteredAnomalies) {
		// Return empty if array offset
		writeJSON(w, []*models.AnomalyDetection{}, http.StatusOK)
		return
	}

	if endIndex > len(filteredAnomalies) {
		endIndex = len(filteredAnomalies)
	}

	result := filteredAnomalies[startIndex:endIndex]

	response := struct {
		Anomalies  []*models.AnomalyDetection `json:"anomalies"`
		Pagination struct {
			Total    int `json:"total"`
			Limit    int `json:"limit"`
			Offset   int `json:"offset"`
			Returned int `json:"returned"`
		} `json:"pagination"`
		Filters struct {
			Threshold float64 `json:"threshold"`
		} `json:"filters"`
	}{
		Anomalies: result,
		Pagination: struct {
			Total    int `json:"total"`
			Limit    int `json:"limit"`
			Offset   int `json:"offset"`
			Returned int `json:"returned"`
		}{
			Total:    len(filteredAnomalies),
			Limit:    limit,
			Offset:   offset,
			Returned: len(result),
		},
		Filters: struct {
			Threshold float64 `json:"threshold"`
		}{
			Threshold: threshold,
		},
	}

	writeJSON(w, response, http.StatusOK)

}

// GetUserAccessLogs retrieves access logs for a specific user
func (h *AdminHandler) GetUserAccessLogs(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from URL
	userIDStr := chi.URLParam(r, "id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")

	// Set default values
	limit := 100

	// Parse limit if provided
	if limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil {
			errorResponse(w, "Invalid limit", http.StatusBadRequest)
			return
		}
		if l > 0 && l <= 1000 {
			limit = l
		}
	}

	// Get user access logs
	logs, err := h.auditRepo.GetUserAccessLogs(userID, limit)
	if err != nil {
		h.logger.Error("Error getting user access logs", "error", err)
		errorResponse(w, "Failed to get user access logs", http.StatusInternalServerError)
		return
	}

	writeJSON(w, logs, http.StatusOK)
}

// GetUserAnomalies retrieves anomalies for a specific user
func (h *AdminHandler) GetUserAnomalies(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from URL
	userIDStr := chi.URLParam(r, "id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")

	// Set default values
	limit := 100

	// Parse limit if provided
	if limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil {
			errorResponse(w, "Invalid limit", http.StatusBadRequest)
			return
		}
		if l > 0 && l <= 1000 {
			limit = l
		}
	}

	// Get user anomalies
	anomalies, err := h.auditRepo.GetUserAnomalies(userID, limit)
	if err != nil {
		h.logger.Error("Error getting user anomalies", "error", err)
		errorResponse(w, "Failed to get user anomalies", http.StatusInternalServerError)
		return
	}

	writeJSON(w, anomalies, http.StatusOK)
}

// GetSystemStats retrieves system statistics
func (h *AdminHandler) GetSystemStats(w http.ResponseWriter, r *http.Request) {
	// This would typically query various repositories for statistics
	// For now, we'll return a mock response

	// In a real implementation, you'd get counts of users, roles, permissions,
	// login attempts, anomalies, etc.

	stats := struct {
		TotalUsers        int `json:"total_users"`
		ActiveUsers       int `json:"active_users"`
		TotalRoles        int `json:"total_roles"`
		TotalPermissions  int `json:"total_permissions"`
		AnomaliesDetected int `json:"anomalies_detected"`
		TotalLoginCount   int `json:"total_login_count"`
		FailedLoginCount  int `json:"failed_login_count"`
	}{
		TotalUsers:        0, // Replace with actual query
		ActiveUsers:       0,
		TotalRoles:        0,
		TotalPermissions:  0,
		AnomaliesDetected: 0,
		TotalLoginCount:   0,
		FailedLoginCount:  0,
	}

	writeJSON(w, stats, http.StatusOK)
}
