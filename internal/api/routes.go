// internal/api/routes.go - МИНИМАЛЬНАЯ РАБОЧАЯ ВЕРСИЯ
package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
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
	//roleRepo := repository.NewRoleRepository(db)
	auditRepo := repository.NewAuditRepository(db)

	// Initialize services
	authConfig := auth.AuthConfig{
		JWTSecret:      cfg.JWTSecret,
		JWTExpiration:  time.Duration(cfg.JWTExpirationHours) * time.Hour,
		MFAEnabled:     cfg.MFAEnabled,
		MFAIssuer:      "AI-IAM",
		AnomalyEnabled: cfg.AnomalyDetectionOn,
		//MLServiceURL:     cfg.MLServiceURL,
		//MLServiceEnabled: cfg.MLServiceEnabled,
	}
	authService := auth.NewAuthService(userRepo, auditRepo, authConfig)
	//rbacService := rbac.NewRBACService(userRepo, roleRepo)

	// Initialize middleware
	mw := NewMiddleware(authService, auditRepo, logger)

	// Initialize handlers
	authHandler := NewAuthHandler(authService, userRepo, logger)
	// rbacHandler := NewRBACHandler(rbacService, logger)  // Временно отключено
	// adminHandler := NewAdminHandler(userRepo, roleRepo, auditRepo, logger)  // Временно отключено

	// Create router
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Root endpoints (no prefix)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("AI-Powered IAM API"))
	})

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]string{
			"status":  "healthy",
			"service": "AI-IAM Service",
			"version": "1.0.0",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	})

	// ALL API ROUTES UNDER /api PREFIX
	r.Route("/api", func(r chi.Router) {
		// API Health endpoint
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			response := map[string]string{
				"status":  "healthy",
				"service": "AI-IAM API",
				"version": "1.0.0",
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

		// RBAC routes (ВРЕМЕННО ОТКЛЮЧЕНЫ - будем добавлять по одному)
		r.Route("/rbac", func(r chi.Router) {
			r.Use(mw.Authenticate)

			// Простые заглушки для тестирования
			r.Get("/roles", func(w http.ResponseWriter, r *http.Request) {
				// Прямой запрос к базе данных
				rows, err := db.Query("SELECT id, name, description FROM roles")
				if err != nil {
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
				// Прямой запрос к базе данных
				rows, err := db.Query("SELECT id, name, description, resource, action FROM permissions")
				if err != nil {
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

			// Остальные методы - заглушки
			r.Get("/check", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"status": "not implemented"})
			})
		})

		// Admin routes (ВРЕМЕННО ОТКЛЮЧЕНЫ)
		r.Route("/admin", func(r chi.Router) {
			r.Use(mw.Authenticate)
			// r.Use(mw.AuthorizeResource("admin", "access"))  // Временно отключено

			r.Get("/users", func(w http.ResponseWriter, r *http.Request) {
				// Прямой запрос к базе данных
				rows, err := db.Query("SELECT id, username, email, is_active, is_locked FROM users LIMIT 10")
				if err != nil {
					http.Error(w, "Database error", http.StatusInternalServerError)
					return
				}
				defer rows.Close()

				type User struct {
					ID       int64  `json:"id"`
					Username string `json:"username"`
					Email    string `json:"email"`
					IsActive bool   `json:"is_active"`
					IsLocked bool   `json:"is_locked"`
				}

				var users []User
				for rows.Next() {
					var user User
					if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.IsActive, &user.IsLocked); err != nil {
						continue
					}
					users = append(users, user)
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(users)
			})

			// Заглушки для остальных методов
			r.Get("/audit-logs", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"status": "not implemented"})
			})

			r.Get("/anomalies", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"status": "not implemented"})
			})
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
	logger.Info("  GET  /api/admin/users")

	return r
}
