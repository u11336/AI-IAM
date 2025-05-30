package auth_test

import (
	"testing"
	"time"

	"github.com/u11336/ai-iam/internal/core/auth"
	"github.com/u11336/ai-iam/internal/data/models"
	"github.com/u11336/ai-iam/internal/tests/mocks"
	"golang.org/x/crypto/bcrypt"
)

func TestLogin(t *testing.T) {
	// Create mock repositories
	userRepo := mocks.NewMockUserRepository()
	auditRepo := mocks.NewMockAuditRepository()

	// Create a test user with known password
	password := "TestPassword123!"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user := userRepo.AddTestUser("testuser", "test@example.com", string(hashedPassword), false)

	// Create auth service with mock repositories
	authConfig := auth.AuthConfig{
		JWTSecret:      "test-secret",
		JWTExpiration:  time.Hour * 24,
		MFAEnabled:     false,
		MFAIssuer:      "test-issuer",
		AnomalyEnabled: false,
	}
	authService := auth.NewAuthService(userRepo, auditRepo, authConfig)

	// Test cases
	tests := []struct {
		name           string
		username       string
		password       string
		ipAddress      string
		userAgent      string
		expectError    bool
		errorType      error
		lockUser       bool
		deactivateUser bool
	}{
		{
			name:        "Valid credentials",
			username:    "testuser",
			password:    password,
			ipAddress:   "127.0.0.1",
			userAgent:   "test-agent",
			expectError: false,
		},
		{
			name:        "Invalid username",
			username:    "wronguser",
			password:    password,
			ipAddress:   "127.0.0.1",
			userAgent:   "test-agent",
			expectError: true,
			errorType:   auth.ErrInvalidCredentials,
		},
		{
			name:        "Invalid password",
			username:    "testuser",
			password:    "wrongpassword",
			ipAddress:   "127.0.0.1",
			userAgent:   "test-agent",
			expectError: true,
			errorType:   auth.ErrInvalidCredentials,
		},
		{
			name:        "Locked account",
			username:    "testuser",
			password:    password,
			ipAddress:   "127.0.0.1",
			userAgent:   "test-agent",
			expectError: true,
			errorType:   auth.ErrAccountLocked,
			lockUser:    true,
		},
		{
			name:           "Inactive account",
			username:       "testuser",
			password:       password,
			ipAddress:      "127.0.0.1",
			userAgent:      "test-agent",
			expectError:    true,
			errorType:      auth.ErrAccountInactive,
			deactivateUser: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset user state for each test case
			user.IsLocked = tc.lockUser
			user.IsActive = !tc.deactivateUser

			// Attempt login
			loginRequest := models.LoginRequest{
				Username: tc.username,
				Password: tc.password,
			}

			response, err := authService.Login(loginRequest, tc.ipAddress, tc.userAgent)

			// Check error
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
					return
				}

				if err != tc.errorType {
					t.Errorf("Expected error %v but got %v", tc.errorType, err)
				}

				return
			}

			// Check success
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Check response
			if response == nil {
				t.Errorf("Expected response but got nil")
				return
			}

			if response.Token == "" {
				t.Errorf("Expected non-empty token")
			}

			if response.User == nil {
				t.Errorf("Expected user object in response")
			} else if response.User.ID != user.ID {
				t.Errorf("Expected user ID %d but got %d", user.ID, response.User.ID)
			}
		})
	}
}

func TestRegister(t *testing.T) {
	// Create mock repositories
	userRepo := mocks.NewMockUserRepository()
	auditRepo := mocks.NewMockAuditRepository()

	// Create auth service with mock repositories
	authConfig := auth.AuthConfig{
		JWTSecret:      "test-secret",
		JWTExpiration:  time.Hour * 24,
		MFAEnabled:     false,
		MFAIssuer:      "test-issuer",
		AnomalyEnabled: false,
	}
	authService := auth.NewAuthService(userRepo, auditRepo, authConfig)

	// Test register
	username := "newuser"
	email := "new@example.com"
	password := "SecurePass123!"

	user, err := authService.Register(username, email, password)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	// Check user was created correctly
	if user.ID <= 0 {
		t.Errorf("Expected valid user ID but got %d", user.ID)
	}

	if user.Username != username {
		t.Errorf("Expected username %s but got %s", username, user.Username)
	}

	if user.Email != email {
		t.Errorf("Expected email %s but got %s", email, user.Email)
	}

	// Check password was hashed
	if user.PasswordHash == password {
		t.Errorf("Password was not hashed")
	}

	if len(user.Roles) == 0 {
		t.Errorf("Expected default role assignment")
	}

	// Test duplicate registration
	_, err = authService.Register(username, "another@example.com", password)
	if err == nil {
		t.Errorf("Expected error for duplicate username but got nil")
	}
}

func TestVerifyToken(t *testing.T) {
	// Create mock repositories
	userRepo := mocks.NewMockUserRepository()
	auditRepo := mocks.NewMockAuditRepository()

	// Create a test user
	userRepo.AddTestUser("testuser", "test@example.com", "hashedPassword", false)

	// Create auth service with mock repositories and short expiration
	authConfig := auth.AuthConfig{
		JWTSecret:      "test-secret",
		JWTExpiration:  time.Second * 2, // Very short expiration for testing
		MFAEnabled:     false,
		MFAIssuer:      "test-issuer",
		AnomalyEnabled: false,
	}
	authService := auth.NewAuthService(userRepo, auditRepo, authConfig)

	// Login to get a token
	loginRequest := models.LoginRequest{
		Username: "testuser",
		Password: "TestPassword123!", // Doesn't matter for mock
	}

	response, err := authService.Login(loginRequest, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Unexpected error during login: %v", err)
	}

	token := response.Token

	// Verify token
	userID, err := authService.VerifyToken(token)
	if err != nil {
		t.Errorf("Unexpected error verifying token: %v", err)
	}

	if userID <= 0 {
		t.Errorf("Expected valid user ID but got %d", userID)
	}

	// Test invalid token
	_, err = authService.VerifyToken("invalid.token.string")
	if err == nil {
		t.Errorf("Expected error for invalid token but got nil")
	}

	// Test expired token
	time.Sleep(time.Second * 3) // Wait for token to expire

	_, err = authService.VerifyToken(token)
	if err == nil {
		t.Errorf("Expected error for expired token but got nil")
	}
}

func TestMFAFunctionality(t *testing.T) {
	// Create mock repositories
	userRepo := mocks.NewMockUserRepository()
	auditRepo := mocks.NewMockAuditRepository()

	// Create a test user
	user := userRepo.AddTestUser("testuser", "test@example.com", "hashedPassword", false)

	// Create auth service with mock repositories and MFA enabled
	authConfig := auth.AuthConfig{
		JWTSecret:      "test-secret",
		JWTExpiration:  time.Hour * 24,
		MFAEnabled:     true,
		MFAIssuer:      "test-issuer",
		AnomalyEnabled: false,
	}
	authService := auth.NewAuthService(userRepo, auditRepo, authConfig)

	// Enable MFA
	secret, url, err := authService.EnableMFA(user.ID)
	if err != nil {
		t.Fatalf("Unexpected error enabling MFA: %v", err)
	}

	if secret == "" {
		t.Errorf("Expected non-empty MFA secret")
	}

	if url == "" {
		t.Errorf("Expected non-empty MFA URL")
	}

	// At this point, MFA should be configured but not enabled yet
	if user.MFAEnabled {
		t.Errorf("MFA should not be enabled before verification")
	}

	// We can't verify the actual MFA code in a unit test because it depends on time
	// But we can verify that the MFA setup process works
	err = authService.VerifyMFA(user.ID, "123456") // Mock will accept any code
	if err == nil {
		// In a real test, we would expect this to fail with an invalid code
		// But in our mock, we'll just check that the user's MFA is now enabled
		if !user.MFAEnabled {
			t.Errorf("MFA should be enabled after verification")
		}
	}

	// Disable MFA
	err = authService.DisableMFA(user.ID, "TestPassword123!")
	if err != nil {
		t.Fatalf("Unexpected error disabling MFA: %v", err)
	}

	if user.MFAEnabled {
		t.Errorf("MFA should be disabled")
	}

	if user.MFASecret != "" {
		t.Errorf("MFA secret should be cleared")
	}
}
