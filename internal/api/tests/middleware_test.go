package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/u11336/ai-iam/internal/api"
	"github.com/u11336/ai-iam/internal/core/auth"
	"github.com/u11336/ai-iam/internal/data/models"
	"github.com/u11336/ai-iam/internal/tests/mocks"
	"github.com/u11336/ai-iam/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

func setupTestMiddleware() (*api.Middleware, *mocks.MockUserRepository, *mocks.MockAuditRepository, *auth.AuthService) {
	// Create mock repositories
	userRepo := mocks.NewMockUserRepository()
	auditRepo := mocks.NewMockAuditRepository()

	// Create auth service
	authConfig := auth.AuthConfig{
		JWTSecret:      "test-secret",
		JWTExpiration:  time.Hour,
		MFAEnabled:     false,
		MFAIssuer:      "test-issuer",
		AnomalyEnabled: false,
	}
	authService := auth.NewAuthService(userRepo, auditRepo, authConfig)

	// Create logger
	logger := utils.NewLogger()

	// Create middleware
	middleware := api.NewMiddleware(authService, auditRepo, logger)

	return middleware, userRepo, auditRepo, authService
}

func TestAuthenticateMiddleware(t *testing.T) {
	mw, userRepo, _, authService := setupTestMiddleware()

	// Create a test user
	password := "TestPassword123!"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user := userRepo.AddTestUser("testuser", "test@example.com", string(hashedPassword), false)

	// Login to get a token
	loginRequest := models.LoginRequest{
		Username: "testuser",
		Password: password,
	}

	response, err := authService.Login(loginRequest, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Error logging in: %v", err)
	}

	token := response.Token

	// Test cases
	tests := []struct {
		name       string
		headerAuth string
		expectCode int
	}{
		{
			name:       "Valid token",
			headerAuth: "Bearer " + token,
			expectCode: http.StatusOK,
		},
		{
			name:       "Missing Authorization header",
			headerAuth: "",
			expectCode: http.StatusUnauthorized,
		},
		{
			name:       "Invalid Authorization format",
			headerAuth: "Basic " + token,
			expectCode: http.StatusUnauthorized,
		},
		{
			name:       "Invalid token",
			headerAuth: "Bearer invalid.token.string",
			expectCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test handler that will be wrapped by the middleware
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// If we reach here, authentication was successful
				// Check if user ID was added to context
				userID, ok := r.Context().Value(api.ContextUserIDKey).(int64)
				if !ok {
					t.Errorf("Expected user ID in context but got none")
				} else if userID != user.ID {
					t.Errorf("Expected user ID %d but got %d", user.ID, userID)
				}

				w.WriteHeader(http.StatusOK)
			})

			// Wrap the test handler with the authenticate middleware
			handler := mw.Authenticate(nextHandler)

			// Create a test request
			req := httptest.NewRequest("GET", "/", nil)
			if tc.headerAuth != "" {
				req.Header.Set("Authorization", tc.headerAuth)
			}

			// Create a test response recorder
			rr := httptest.NewRecorder()

			// Serve the request
			handler.ServeHTTP(rr, req)

			// Check the status code
			if rr.Code != tc.expectCode {
				t.Errorf("Expected status code %d but got %d", tc.expectCode, rr.Code)
			}
		})
	}
}

func TestAuthorizeResourceMiddleware(t *testing.T) {
	mw, userRepo, _, _ := setupTestMiddleware()

	// Create a test admin user and a regular user
	adminUser := userRepo.AddTestUser("admin", "admin@example.com", "hashedPassword", true)
	regularUser := userRepo.AddTestUser("user", "user@example.com", "hashedPassword", false)

	// Define resources and actions
	resource := "test_resource"
	action := "read"

	// Test cases
	tests := []struct {
		name       string
		userID     int64
		expectCode int
	}{
		{
			name:       "Admin user with permission",
			userID:     adminUser.ID,
			expectCode: http.StatusOK,
		},
		{
			name:       "Regular user with permission",
			userID:     regularUser.ID,
			expectCode: http.StatusOK, // For this test, we assume everyone has 'read' permission on 'test_resource'
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test handler that will be wrapped by the middleware
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// If we reach here, authorization was successful
				w.WriteHeader(http.StatusOK)
			})

			// Wrap the test handler with the authorize middleware
			handler := mw.AuthorizeResource(resource, action)(nextHandler)

			// Create a test request with user ID in context
			req := httptest.NewRequest("GET", "/", nil)
			ctx := context.WithValue(req.Context(), api.ContextUserIDKey, tc.userID)
			req = req.WithContext(ctx)

			// Create a test response recorder
			rr := httptest.NewRecorder()

			// Serve the request
			handler.ServeHTTP(rr, req)

			// Check the status code
			if rr.Code != tc.expectCode {
				t.Errorf("Expected status code %d but got %d", tc.expectCode, rr.Code)
			}
		})
	}
}

func TestAuditTrailMiddleware(t *testing.T) {
	mw, _, auditRepo, _ := setupTestMiddleware()

	// Define user, resource, and action for the test
	userID := int64(1)
	resource := "test_resource"
	action := "read"

	// Create a test handler that will be wrapped by the middleware
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap the test handler with the audit trail middleware
	handler := mw.AuditTrail(resource, action)(nextHandler)

	// Create a test request with user ID in context
	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), api.ContextUserIDKey, userID)
	req = req.WithContext(ctx)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("User-Agent", "test-agent")

	// Create a test response recorder
	rr := httptest.NewRecorder()

	// Get initial count of logs
	initialAuditCount := len(auditRepo.GetAuditLogsForTests())
	initialAccessCount := len(auditRepo.GetAccessLogsForTests())

	// Serve the request
	handler.ServeHTTP(rr, req)

	// Check if audit and access logs were created
	if len(auditRepo.GetAuditLogsForTests()) != initialAuditCount+1 {
		t.Errorf("Expected audit log to be created")
	}

	if len(auditRepo.GetAccessLogsForTests()) != initialAccessCount+1 {
		t.Errorf("Expected access log to be created")
	}

	// Check the latest audit log
	auditLogs := auditRepo.GetAuditLogsForTests()
	if len(auditLogs) > 0 {
		latestLog := auditLogs[len(auditLogs)-1]

		if latestLog.UserID != userID {
			t.Errorf("Expected user ID %d but got %d", userID, latestLog.UserID)
		}

		if latestLog.Resource != resource {
			t.Errorf("Expected resource %s but got %s", resource, latestLog.Resource)
		}

		if latestLog.Action != action {
			t.Errorf("Expected action %s but got %s", action, latestLog.Action)
		}

		if latestLog.IPAddress != "127.0.0.1" {
			t.Errorf("Expected IP 127.0.0.1 but got %s", latestLog.IPAddress)
		}

		if latestLog.Status != "success" {
			t.Errorf("Expected status 'success' but got %s", latestLog.Status)
		}
	}
}

func TestCORSMiddleware(t *testing.T) {
	mw, _, _, _ := setupTestMiddleware()

	// Create a test handler that will be wrapped by the middleware
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap the test handler with the CORS middleware
	handler := mw.CORS(nextHandler)

	// Test normal request
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Check CORS headers
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("Expected 'Access-Control-Allow-Origin: *' header")
	}

	if rr.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Errorf("Expected 'Access-Control-Allow-Methods' header")
	}

	if rr.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Errorf("Expected 'Access-Control-Allow-Headers' header")
	}

	// Test preflight OPTIONS request
	req = httptest.NewRequest("OPTIONS", "/", nil)
	rr = httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Check status code for OPTIONS request
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS request but got %d", rr.Code)
	}
}

func TestRecoverPanicMiddleware(t *testing.T) {
	mw, _, _, _ := setupTestMiddleware()

	// Create a test handler that will panic
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	// Wrap the test handler with the recover panic middleware
	handler := mw.RecoverPanic(nextHandler)

	// Create a test request
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	// Serve the request - this should not crash the test
	handler.ServeHTTP(rr, req)

	// Check that we got a 500 response
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500 but got %d", rr.Code)
	}

	// Check the response body
	var errorResponse struct {
		Error string `json:"error"`
	}

	err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
	if err != nil {
		t.Errorf("Error parsing response body: %v", err)
	}

	if errorResponse.Error != "Internal server error" {
		t.Errorf("Expected error message 'Internal server error' but got '%s'", errorResponse.Error)
	}
}
