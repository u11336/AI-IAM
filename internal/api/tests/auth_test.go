package api_test

import (
	"bytes"
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

func setupAuthHandler() (*api.AuthHandler, *mocks.MockUserRepository, *mocks.MockAuditRepository, *auth.AuthService) {
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

	// Create auth handler
	authHandler := api.NewAuthHandler(authService, userRepo, logger)

	return authHandler, userRepo, auditRepo, authService
}

func TestLoginHandler(t *testing.T) {
	handler, userRepo, _, _ := setupAuthHandler()

	// Create a test user
	password := "TestPassword123!"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	userRepo.AddTestUser("testuser", "test@example.com", string(hashedPassword), false)

	// Test cases
	tests := []struct {
		name       string
		username   string
		password   string
		expectCode int
	}{
		{
			name:       "Valid credentials",
			username:   "testuser",
			password:   password,
			expectCode: http.StatusOK,
		},
		{
			name:       "Invalid username",
			username:   "wronguser",
			password:   password,
			expectCode: http.StatusUnauthorized,
		},
		{
			name:       "Invalid password",
			username:   "testuser",
			password:   "wrongpassword",
			expectCode: http.StatusUnauthorized,
		},
		{
			name:       "Empty username",
			username:   "",
			password:   password,
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Empty password",
			username:   "testuser",
			password:   "",
			expectCode: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create login request
			loginRequest := models.LoginRequest{
				Username: tc.username,
				Password: tc.password,
			}

			// Convert to JSON
			body, _ := json.Marshal(loginRequest)

			// Create test request
			req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", "127.0.0.1")
			req.Header.Set("User-Agent", "test-agent")

			// Create test response recorder
			rr := httptest.NewRecorder()

			// Call the login handler
			handler.Login(rr, req)

			// Check the status code
			if rr.Code != tc.expectCode {
				t.Errorf("Expected status code %d but got %d", tc.expectCode, rr.Code)
			}

			// If success, check the response body
			if tc.expectCode == http.StatusOK {
				var response models.LoginResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Errorf("Error parsing response body: %v", err)
				}

				if response.Token == "" {
					t.Errorf("Expected non-empty token")
				}

				if response.User == nil {
					t.Errorf("Expected user object in response")
				}
			}
		})
	}
}

func TestRegisterHandler(t *testing.T) {
	handler, userRepo, _, _ := setupAuthHandler()

	// Test cases
	tests := []struct {
		name       string
		username   string
		email      string
		password   string
		expectCode int
	}{
		{
			name:       "Valid registration",
			username:   "newuser",
			email:      "new@example.com",
			password:   "SecurePassword123!",
			expectCode: http.StatusCreated,
		},
		{
			name:       "Empty username",
			username:   "",
			email:      "new@example.com",
			password:   "SecurePassword123!",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Empty email",
			username:   "newuser",
			email:      "",
			password:   "SecurePassword123!",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Empty password",
			username:   "newuser",
			email:      "new@example.com",
			password:   "",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Invalid email format",
			username:   "newuser",
			email:      "not-an-email",
			password:   "SecurePassword123!",
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "Weak password",
			username:   "newuser",
			email:      "new@example.com",
			password:   "password", // Too weak
			expectCode: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mock repository for each test
			if tc.name == "Valid registration" {
				userRepo = mocks.NewMockUserRepository()
				handler.SetUserRepo(userRepo)
			}

			// Create register request
			registerRequest := struct {
				Username string `json:"username"`
				Email    string `json:"email"`
				Password string `json:"password"`
			}{
				Username: tc.username,
				Email:    tc.email,
				Password: tc.password,
			}

			// Convert to JSON
			body, _ := json.Marshal(registerRequest)

			// Create test request
			req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			// Create test response recorder
			rr := httptest.NewRecorder()

			// Call the register handler
			handler.Register(rr, req)

			// Check the status code
			if rr.Code != tc.expectCode {
				t.Errorf("Expected status code %d but got %d", tc.expectCode, rr.Code)
			}

			// If success, check the response body
			if tc.expectCode == http.StatusCreated {
				var response struct {
					ID       int64  `json:"id"`
					Username string `json:"username"`
					Email    string `json:"email"`
				}

				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Errorf("Error parsing response body: %v", err)
				}

				if response.ID <= 0 {
					t.Errorf("Expected valid user ID")
				}

				if response.Username != tc.username {
					t.Errorf("Expected username %s but got %s", tc.username, response.Username)
				}

				if response.Email != tc.email {
					t.Errorf("Expected email %s but got %s", tc.email, response.Email)
				}

				// Try to register same user again - should fail
				req = httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
				rr = httptest.NewRecorder()
				handler.Register(rr, req)

				if rr.Code != http.StatusConflict {
					t.Errorf("Expected conflict status code for duplicate username but got %d", rr.Code)
				}
			}
		})
	}
}

func TestMFAHandlers(t *testing.T) {
	handler, userRepo, _, authService := setupAuthHandler()

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

	// Test enable MFA
	t.Run("Enable MFA", func(t *testing.T) {
		// Create test request
		req := httptest.NewRequest("POST", "/api/auth/mfa/enable", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		// Create test response recorder
		rr := httptest.NewRecorder()

		// Add user ID to context
		ctx := req.Context()
		ctx = context.WithValue(ctx, api.ContextUserIDKey, user.ID)
		req = req.WithContext(ctx)

		// Call the enable MFA handler
		handler.EnableMFA(rr, req)

		// Check the status code
		if rr.Code != http.StatusOK {
			t.Errorf("Expected status code 200 but got %d", rr.Code)
		}

		// Check the response body
		var mfaResponse struct {
			Secret string `json:"secret"`
			URL    string `json:"url"`
		}

		if err := json.Unmarshal(rr.Body.Bytes(), &mfaResponse); err != nil {
			t.Errorf("Error parsing response body: %v", err)
		}

		if mfaResponse.Secret == "" {
			t.Errorf("Expected non-empty MFA secret")
		}

		if mfaResponse.URL == "" {
			t.Errorf("Expected non-empty MFA URL")
		}

		// MFA should be configured but not enabled yet
		if user.MFAEnabled {
			t.Errorf("MFA should not be enabled before verification")
		}
	})

	// Test verify MFA
	t.Run("Verify MFA", func(t *testing.T) {
		// Create verify request
		verifyRequest := struct {
			Code string `json:"code"`
		}{
			Code: "123456", // Mock will accept any code
		}

		// Convert to JSON
		body, _ := json.Marshal(verifyRequest)

		// Create test request
		req := httptest.NewRequest("POST", "/api/auth/mfa/verify", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		// Create test response recorder
		rr := httptest.NewRecorder()

		// Add user ID to context
		ctx := req.Context()
		ctx = context.WithValue(ctx, api.ContextUserIDKey, user.ID)
		req = req.WithContext(ctx)

		// Call the verify MFA handler
		handler.VerifyMFA(rr, req)

		// Check the status code
		if rr.Code != http.StatusOK {
			t.Errorf("Expected status code 200 but got %d", rr.Code)
		}

		// MFA should now be enabled
		if !user.MFAEnabled {
			t.Errorf("MFA should be enabled after verification")
		}
	})

	// Test disable MFA
	t.Run("Disable MFA", func(t *testing.T) {
		// Create disable request
		disableRequest := struct {
			Password string `json:"password"`
		}{
			Password: password,
		}

		// Convert to JSON
		body, _ := json.Marshal(disableRequest)

		// Create test request
		req := httptest.NewRequest("POST", "/api/auth/mfa/disable", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		// Create test response recorder
		rr := httptest.NewRecorder()

		// Add user ID to context
		ctx := req.Context()
		ctx = context.WithValue(ctx, api.ContextUserIDKey, user.ID)
		req = req.WithContext(ctx)

		// Call the disable MFA handler
		handler.DisableMFA(rr, req)

		// Check the status code
		if rr.Code != http.StatusOK {
			t.Errorf("Expected status code 200 but got %d", rr.Code)
		}

		// MFA should now be disabled
		if user.MFAEnabled {
			t.Errorf("MFA should be disabled")
		}

		if user.MFASecret != "" {
			t.Errorf("MFA secret should be cleared")
		}
	})
}
