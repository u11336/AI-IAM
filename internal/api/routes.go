package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/u11336/ai-iam/internal/config"
	"github.com/u11336/ai-iam/internal/core/auth"
	"github.com/u11336/ai-iam/internal/data/repository"
	"github.com/u11336/ai-iam/internal/utils"
)

// NewRouter creates a new router with all routes configured
func NewRouter(db *sql.DB, logger *utils.Logger, cfg *config.Config) http.Handler {
	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	roleRepo := repository.NewRoleRepository(db)
	auditRepo := repository.NewAuditRepository(db)

	// Initialize services
	authConfig := auth.AuthConfig{
		JWTSecret:        cfg.JWTSecret,
		JWTExpiration:    time.Duration(cfg.JWTExpirationHours) * time.Hour,
		MFAEnabled:       cfg.MFAEnabled,
		MFAIssuer:        "AI-IAM",
		AnomalyEnabled:   cfg.AnomalyDetectionOn,
		MLServiceURL:     "http://localhost:8001", // Default ML service URL 		cfg.MLServiceURL
		MLServiceEnabled: true,                    // Enable ML service by default 	cfg.MLServiceEnabled
	}
	authService := auth.NewAuthService(userRepo, auditRepo, authConfig)

	// Initialize middleware
	mw := NewMiddleware(authService, auditRepo, logger)

	// Initialize handlers
	authHandler := NewAuthHandler(authService, userRepo, logger)
	adminHandler := NewAdminHandler(userRepo, roleRepo, auditRepo, logger)

	// Create router
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(mw.CORS)

	// Root endpoints (no prefix)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{
			"message": "AI-Powered IAM API",
			"version": "1.0.0",
			"status":  "operational",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		// Get ML service status
		mlStatus := authService.GetMLServiceStatus()

		response := map[string]interface{}{
			"status":     "healthy",
			"service":    "AI-IAM Service",
			"version":    "1.0.0",
			"timestamp":  time.Now().Format(time.RFC3339),
			"ml_service": mlStatus,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})

	// ALL API ROUTES UNDER /api PREFIX
	r.Route("/api", func(r chi.Router) {
		// API Health endpoint
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			mlStatus := authService.GetMLServiceStatus()

			response := map[string]interface{}{
				"status":     "healthy",
				"service":    "AI-IAM API",
				"version":    "1.0.0",
				"timestamp":  time.Now().Format(time.RFC3339),
				"ml_service": mlStatus,
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		})

		// Auth routes (NO authentication required)
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", authHandler.Register)
			r.Post("/login", authHandler.Login)

			// Protected auth routes (authentication required)
			r.Group(func(r chi.Router) {
				r.Use(mw.Authenticate)
				r.Get("/me", authHandler.GetCurrentUser)
				r.Post("/mfa/enable", authHandler.EnableMFA)
				r.Post("/mfa/verify", authHandler.VerifyMFA)
				r.Post("/mfa/disable", authHandler.DisableMFA)
			})
		})

		// RBAC routes
		r.Route("/rbac", func(r chi.Router) {
			r.Use(mw.Authenticate)

			// Get roles and permissions
			r.Get("/roles", func(w http.ResponseWriter, r *http.Request) {
				rows, err := db.Query("SELECT id, name, description FROM roles")
				if err != nil {
					logger.Error("Database error getting roles", "error", err)
					http.Error(w, "Database error", http.StatusInternalServerError)
					return
				}
				defer rows.Close()

				type Role struct {
					ID          int64  `json:"id"`
					Name        string `json:"name"`
					Description string `json:"description"`
				}

				var roles []Role
				for rows.Next() {
					var role Role
					if err := rows.Scan(&role.ID, &role.Name, &role.Description); err != nil {
						continue
					}
					roles = append(roles, role)
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(roles)
			})

			r.Get("/permissions", func(w http.ResponseWriter, r *http.Request) {
				rows, err := db.Query("SELECT id, name, description, resource, action FROM permissions")
				if err != nil {
					logger.Error("Database error getting permissions", "error", err)
					http.Error(w, "Database error", http.StatusInternalServerError)
					return
				}
				defer rows.Close()

				type Permission struct {
					ID          int64  `json:"id"`
					Name        string `json:"name"`
					Description string `json:"description"`
					Resource    string `json:"resource"`
					Action      string `json:"action"`
				}

				var permissions []Permission
				for rows.Next() {
					var perm Permission
					if err := rows.Scan(&perm.ID, &perm.Name, &perm.Description, &perm.Resource, &perm.Action); err != nil {
						continue
					}
					permissions = append(permissions, perm)
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(permissions)
			})

			// Permission check endpoint
			r.Get("/check", func(w http.ResponseWriter, r *http.Request) {
				resource := r.URL.Query().Get("resource")
				action := r.URL.Query().Get("action")

				if resource == "" || action == "" {
					http.Error(w, "Resource and action parameters required", http.StatusBadRequest)
					return
				}

				// Get user ID from context
				userID, ok := r.Context().Value(userIDKey).(int64)
				if !ok {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}

				// Check permission
				hasPermission, err := authService.HasPermission(userID, resource, action)
				if err != nil {
					logger.Error("Error checking permission", "error", err)
					http.Error(w, "Internal server error", http.StatusInternalServerError)
					return
				}

				response := map[string]interface{}{
					"user_id":        userID,
					"resource":       resource,
					"action":         action,
					"has_permission": hasPermission,
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			})
		})

		// Admin routes with WORKING implementations
		r.Route("/admin", func(r chi.Router) {
			r.Use(mw.Authenticate)

			// User management
			r.Get("/users", func(w http.ResponseWriter, r *http.Request) {
				users, err := userRepo.GetAllUsers(100, 0)
				if err != nil {
					logger.Error("Database error getting users", "error", err)
					http.Error(w, "Database error", http.StatusInternalServerError)
					return
				}

				// Sanitize user data
				type SafeUser struct {
					ID       int64  `json:"id"`
					Username string `json:"username"`
					Email    string `json:"email"`
					IsActive bool   `json:"is_active"`
					IsLocked bool   `json:"is_locked"`
				}

				var safeUsers []SafeUser
				for _, user := range users {
					safeUsers = append(safeUsers, SafeUser{
						ID:       user.ID,
						Username: user.Username,
						Email:    user.Email,
						IsActive: user.IsActive,
						IsLocked: user.IsLocked,
					})
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(safeUsers)
			})

			// Audit logs - now working
			r.Get("/audit-logs", adminHandler.GetAuditLogs)

			// Anomalies - now working
			r.Get("/anomalies", adminHandler.GetAnomalies)

			// User-specific routes
			r.Route("/users/{id}", func(r chi.Router) {
				r.Get("/access-logs", adminHandler.GetUserAccessLogs)
				r.Get("/anomalies", adminHandler.GetUserAnomalies)

				// Access patterns endpoint
				r.Get("/access-patterns", func(w http.ResponseWriter, r *http.Request) {
					userIDStr := chi.URLParam(r, "id")
					userID, err := strconv.ParseInt(userIDStr, 10, 64)
					if err != nil {
						http.Error(w, "Invalid user ID", http.StatusBadRequest)
						return
					}

					// Get user access patterns
					accessLogs, err := auditRepo.GetUserAccessLogs(userID, 100)
					if err != nil {
						logger.Error("Error getting user access patterns", "error", err)
						http.Error(w, "Failed to get access patterns", http.StatusInternalServerError)
						return
					}

					// Analyze patterns
					patterns := struct {
						UserID         int64          `json:"user_id"`
						TotalAccess    int            `json:"total_access"`
						UniqueIPs      int            `json:"unique_ips"`
						Resources      map[string]int `json:"resources"`
						HourlyActivity map[int]int    `json:"hourly_activity"`
					}{
						UserID:         userID,
						TotalAccess:    len(accessLogs),
						Resources:      make(map[string]int),
						HourlyActivity: make(map[int]int),
					}

					uniqueIPs := make(map[string]bool)
					for _, log := range accessLogs {
						// Count resources
						patterns.Resources[log.Resource]++

						// Count unique IPs
						uniqueIPs[log.IPAddress] = true

						// Count hourly activity
						hour := log.AccessTime / 60 // Convert minutes to hour
						patterns.HourlyActivity[hour]++
					}

					patterns.UniqueIPs = len(uniqueIPs)

					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(patterns)
				})
			})

			// System statistics
			r.Get("/stats", adminHandler.GetSystemStats)
		})
	})

	logger.Info("Router configured successfully")
	logger.Info("Available endpoints:")
	logger.Info("  GET  /health")
	logger.Info("  GET  /api/health")
	logger.Info("  POST /api/auth/register")
	logger.Info("  POST /api/auth/login")
	logger.Info("  GET  /api/auth/me")
	logger.Info("  GET  /api/rbac/roles")
	logger.Info("  GET  /api/rbac/permissions")
	logger.Info("  GET  /api/rbac/check")
	logger.Info("  GET  /api/admin/users")
	logger.Info("  GET  /api/admin/audit-logs")
	logger.Info("  GET  /api/admin/anomalies")
	logger.Info("  GET  /api/admin/users/{id}/access-logs")
	logger.Info("  GET  /api/admin/users/{id}/anomalies")
	logger.Info("  GET  /api/admin/users/{id}/access-patterns")
	logger.Info("  GET  /api/admin/stats")

	return r
}
