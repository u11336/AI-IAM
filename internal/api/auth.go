package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/u11336/ai-iam/internal/core/auth"
	"github.com/u11336/ai-iam/internal/data/models"
	"github.com/u11336/ai-iam/internal/data/repository"
	"github.com/u11336/ai-iam/internal/utils"
)

// AuthHandler handles authentication-related requests
type AuthHandler struct {
	authService *auth.AuthService
	userRepo    *repository.UserRepository
	logger      *utils.Logger
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(authService *auth.AuthService, userRepo *repository.UserRepository, logger *utils.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		userRepo:    userRepo,
		logger:      logger,
	}
}

// SetUserRepo sets the user repository (used for testing)
func (h *AuthHandler) SetUserRepo(userRepo *repository.UserRepository) {
	h.userRepo = userRepo
}

// RegisterRoutes registers the routes for the auth handler
func (h *AuthHandler) RegisterRoutes(r chi.Router, mw *Middleware) {
	r.Post("/login", h.Login)
	r.Post("/register", h.Register)
	r.With(mw.Authenticate).Post("/mfa/enable", h.EnableMFA)
	r.With(mw.Authenticate).Post("/mfa/verify", h.VerifyMFA)
	r.With(mw.Authenticate).Post("/mfa/disable", h.DisableMFA)
	r.With(mw.Authenticate).Get("/me", h.GetCurrentUser)
}

// Login authenticates a user and returns a JWT token
// @Summary Login a user
// @Description Authenticates a user and returns a JWT token
// @Tags auth
// @Accept json
// @Produce json
// @Param loginRequest body models.LoginRequest true "Login credentials"
// @Success 200 {object} models.LoginResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest models.LoginRequest

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		h.logger.Error("Error parsing login request", "error", err)
		errorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate request
	if loginRequest.Username == "" || loginRequest.Password == "" {
		errorResponse(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Attempt to authenticate
	response, err := h.authService.Login(loginRequest, getClientIP(r), r.UserAgent())
	if err != nil {
		// Handle different types of authentication errors
		switch err {
		case auth.ErrInvalidCredentials:
			errorResponse(w, "Invalid username or password", http.StatusUnauthorized)
		case auth.ErrAccountLocked:
			errorResponse(w, "Account is locked", http.StatusForbidden)
		case auth.ErrAccountInactive:
			errorResponse(w, "Account is inactive", http.StatusForbidden)
		case auth.ErrMFARequired:
			// Return response with MFA required flag
			writeJSON(w, response, http.StatusOK)
		case auth.ErrInvalidMFACode:
			errorResponse(w, "Invalid MFA code", http.StatusUnauthorized)
		case auth.ErrHighRiskDetected:
			errorResponse(w, "High risk access attempt detected", http.StatusForbidden)
		default:
			h.logger.Error("Error during login", "error", err)
			errorResponse(w, "Authentication failed", http.StatusInternalServerError)
		}
		return
	}

	// Return JWT token
	writeJSON(w, response, http.StatusOK)
}

// Register creates a new user account
// @Summary Register a new user
// @Description Creates a new user account
// @Tags auth
// @Accept json
// @Produce json
// @Param registerRequest body RegisterRequest true "User registration details"
// @Success 201 {object} UserResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var registerRequest struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&registerRequest); err != nil {
		h.logger.Error("Error parsing register request", "error", err)
		errorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate request
	if registerRequest.Username == "" || registerRequest.Email == "" || registerRequest.Password == "" {
		errorResponse(w, "Username, email, and password are required", http.StatusBadRequest)
		return
	}

	// Validate email format
	if !utils.IsValidEmail(registerRequest.Email) {
		errorResponse(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Validate password strength
	if !utils.IsStrongPassword(registerRequest.Password) {
		errorResponse(w, "Password must be at least 8 characters and include a mix of letters, numbers, and symbols", http.StatusBadRequest)
		return
	}

	// Create user
	user, err := h.authService.Register(registerRequest.Username, registerRequest.Email, registerRequest.Password)
	if err != nil {
		h.logger.Error("Error registering user", "error", err)

		// Handle duplicate username/email
		if err.Error() == "UNIQUE constraint failed: users.username" {
			errorResponse(w, "Username already exists", http.StatusConflict)
			return
		}
		if err.Error() == "UNIQUE constraint failed: users.email" {
			errorResponse(w, "Email already exists", http.StatusConflict)
			return
		}

		errorResponse(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Sanitize user object for response
	userResponse := struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
	}{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
	}

	// Return created user
	writeJSON(w, userResponse, http.StatusCreated)
}

// EnableMFA generates a new MFA secret for a user
// @Summary Enable MFA
// @Description Generates a new MFA secret for a user
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} MFAResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/mfa/enable [post]
func (h *AuthHandler) EnableMFA(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := r.Context().Value(userIDKey).(int64)
	if !ok {
		errorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Generate MFA secret
	secret, url, err := h.authService.EnableMFA(userID)
	if err != nil {
		h.logger.Error("Error enabling MFA", "error", err)
		errorResponse(w, "Failed to enable MFA", http.StatusInternalServerError)
		return
	}

	// Return MFA secret and URL
	response := struct {
		Secret string `json:"secret"`
		URL    string `json:"url"`
	}{
		Secret: secret,
		URL:    url,
	}

	writeJSON(w, response, http.StatusOK)
}

// VerifyMFA verifies the MFA code and enables MFA for the user
// @Summary Verify MFA
// @Description Verifies the MFA code and enables MFA for the user
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param verifyRequest body VerifyMFARequest true "MFA verification details"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/mfa/verify [post]
func (h *AuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	var verifyRequest struct {
		Code string `json:"code"`
	}

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&verifyRequest); err != nil {
		h.logger.Error("Error parsing verify MFA request", "error", err)
		errorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate request
	if verifyRequest.Code == "" {
		errorResponse(w, "MFA code is required", http.StatusBadRequest)
		return
	}

	// Get user ID from context
	userID, ok := r.Context().Value(userIDKey).(int64)
	if !ok {
		errorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Verify MFA
	if err := h.authService.VerifyMFA(userID, verifyRequest.Code); err != nil {
		if err == auth.ErrInvalidMFACode {
			errorResponse(w, "Invalid MFA code", http.StatusBadRequest)
		} else {
			h.logger.Error("Error verifying MFA", "error", err)
			errorResponse(w, "Failed to verify MFA", http.StatusInternalServerError)
		}
		return
	}

	// Return success response
	response := struct {
		Success bool `json:"success"`
	}{
		Success: true,
	}

	writeJSON(w, response, http.StatusOK)
}

// DisableMFA disables MFA for a user
// @Summary Disable MFA
// @Description Disables MFA for a user
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param disableRequest body DisableMFARequest true "MFA disable details"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/mfa/disable [post]
func (h *AuthHandler) DisableMFA(w http.ResponseWriter, r *http.Request) {
	var disableRequest struct {
		Password string `json:"password"`
	}

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&disableRequest); err != nil {
		h.logger.Error("Error parsing disable MFA request", "error", err)
		errorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate request
	if disableRequest.Password == "" {
		errorResponse(w, "Password is required", http.StatusBadRequest)
		return
	}

	// Get user ID from context
	userID, ok := r.Context().Value(userIDKey).(int64)
	if !ok {
		errorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Disable MFA
	if err := h.authService.DisableMFA(userID, disableRequest.Password); err != nil {
		if err == auth.ErrInvalidCredentials {
			errorResponse(w, "Invalid password", http.StatusUnauthorized)
		} else {
			h.logger.Error("Error disabling MFA", "error", err)
			errorResponse(w, "Failed to disable MFA", http.StatusInternalServerError)
		}
		return
	}

	// Return success response
	response := struct {
		Success bool `json:"success"`
	}{
		Success: true,
	}

	writeJSON(w, response, http.StatusOK)
}

// GetCurrentUser returns the current user
// @Summary Get current user
// @Description Returns the current authenticated user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} UserResponse
// @Failure 401 {object} ErrorResponse
// @Router /auth/me [get]
func (h *AuthHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context
	userID, ok := r.Context().Value(userIDKey).(int64)
	if !ok {
		errorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user from database
	user, err := h.userRepo.GetByID(userID)
	if err != nil {
		h.logger.Error("Error getting current user", "error", err)
		errorResponse(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	// Sanitize user object for response
	userResponse := struct {
		ID         int64         `json:"id"`
		Username   string        `json:"username"`
		Email      string        `json:"email"`
		MFAEnabled bool          `json:"mfa_enabled"`
		Roles      []models.Role `json:"roles"`
	}{
		ID:         user.ID,
		Username:   user.Username,
		Email:      user.Email,
		MFAEnabled: user.MFAEnabled,
		Roles:      user.Roles,
	}

	// Return user
	writeJSON(w, userResponse, http.StatusOK)
}
