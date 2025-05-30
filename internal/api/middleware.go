package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/u11336/ai-iam/internal/core/auth"
	"github.com/u11336/ai-iam/internal/data/models"
	"github.com/u11336/ai-iam/internal/data/repository"
	"github.com/u11336/ai-iam/internal/utils"
)

// contextKey is a custom type for context keys
type contextKey string

// context keys
const (
	userIDKey contextKey = "userID"
	ipKey     contextKey = "ip"
	startKey  contextKey = "start"
)

// Middleware holds middleware dependencies
type Middleware struct {
	authService *auth.AuthService
	auditRepo   *repository.AuditRepository
	logger      *utils.Logger
}

// NewMiddleware creates a new middleware
func NewMiddleware(authService *auth.AuthService, auditRepo *repository.AuditRepository, logger *utils.Logger) *Middleware {
	return &Middleware{
		authService: authService,
		auditRepo:   auditRepo,
		logger:      logger,
	}
}

// LogRequest logs each request
func (m *Middleware) LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := context.WithValue(r.Context(), startKey, start)

		m.logger.Info("Request started",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", getClientIP(r),
			"user_agent", r.UserAgent(),
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Authenticate verifies JWT token and adds user ID to context
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			errorResponse(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Check if the header has the correct format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			errorResponse(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// Verify token
		userID, err := m.authService.VerifyToken(token)
		if err != nil {
			errorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Add user ID to context
		ctx := context.WithValue(r.Context(), userIDKey, userID)

		// Add client IP to context for logging
		ctx = context.WithValue(ctx, ipKey, getClientIP(r))

		// Continue to the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthorizeResource checks if the user has the required permission for a resource
func (m *Middleware) AuthorizeResource(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user ID from context
			userID, ok := r.Context().Value(userIDKey).(int64)
			if !ok {
				errorResponse(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if user has permission
			hasPermission, err := m.authService.HasPermission(userID, resource, action)
			if err != nil {
				m.logger.Error("Error checking permission", "error", err)
				errorResponse(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !hasPermission {
				// Audit the unauthorized access attempt
				clientIP := getClientIP(r)
				m.auditAccessAttempt(userID, resource, action, clientIP, r.UserAgent(), "denied")

				errorResponse(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			// Continue to the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// AuditTrail logs access to resources for auditing and anomaly detection
func (m *Middleware) AuditTrail(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user ID from context
			userID, ok := r.Context().Value(userIDKey).(int64)
			if !ok {
				// If no user ID in context, skip auditing
				next.ServeHTTP(w, r)
				return
			}

			// Get client IP
			clientIP := getClientIP(r)

			// Log the access attempt for auditing
			m.auditAccessAttempt(userID, resource, action, clientIP, r.UserAgent(), "success")

			// Continue to the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// CORS adds Cross-Origin Resource Sharing headers
func (m *Middleware) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Continue to the next handler
		next.ServeHTTP(w, r)
	})
}

// RecoverPanic recovers from panics and logs the error
func (m *Middleware) RecoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				m.logger.Error("Panic recovered", "error", err, "path", r.URL.Path)
				errorResponse(w, "Internal server error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// auditAccessAttempt logs access attempts for both auditing and anomaly detection
func (m *Middleware) auditAccessAttempt(userID int64, resource, action, ipAddress, userAgent, status string) {
	// Create audit log
	auditLog := &models.AuditLog{
		UserID:    userID,
		EventType: "access",
		Resource:  resource,
		Action:    action,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Status:    status,
	}

	// Save audit log
	if err := m.auditRepo.CreateAuditLog(auditLog); err != nil {
		m.logger.Error("Error creating audit log", "error", err)
	}

	// Create access log for anomaly detection
	accessLog := &models.AccessLog{
		UserID:     userID,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		Resource:   resource,
		Action:     action,
		AccessTime: timeOfDayInMinutes(time.Now()),
		DayOfWeek:  int(time.Now().Weekday()),
		Success:    status == "success",
	}

	// Save access log
	if err := m.auditRepo.CreateAccessLog(accessLog); err != nil {
		m.logger.Error("Error creating access log", "error", err)
	}
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header first
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs, use the first one
		ips := strings.Split(forwardedFor, ",")
		return strings.TrimSpace(ips[0])
	}

	// Otherwise use RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}

// timeOfDayInMinutes converts the current time to minutes from midnight
func timeOfDayInMinutes(t time.Time) int {
	return t.Hour()*60 + t.Minute()
}

// errorResponse sends a JSON error response
func errorResponse(w http.ResponseWriter, message string, statusCode int) {
	response := map[string]string{"error": message}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
