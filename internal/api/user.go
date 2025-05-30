package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/u11336/ai-iam/internal/core/rbac"
	"github.com/u11336/ai-iam/internal/data/models"
	"github.com/u11336/ai-iam/internal/data/repository"
	"github.com/u11336/ai-iam/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

// UserHandler handles user management requests
type UserHandler struct {
	userRepo    *repository.UserRepository
	rbacService *rbac.RBACService
	logger      *utils.Logger
}

// NewUserHandler creates a new UserHandler
func NewUserHandler(userRepo *repository.UserRepository, rbacService *rbac.RBACService, logger *utils.Logger) *UserHandler {
	return &UserHandler{
		userRepo:    userRepo,
		rbacService: rbacService,
		logger:      logger,
	}
}

// GetAllUsers retrieves all users
func (h *UserHandler) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	// Default pagination
	limit := 100
	offset := 0

	// Get users from repository
	users, err := h.userRepo.GetAllUsers(limit, offset)
	if err != nil {
		h.logger.Error("Error getting users", "error", err)
		errorResponse(w, "Failed to get users", http.StatusInternalServerError)
		return
	}

	// Sanitize user objects for response
	sanitizedUsers := make([]interface{}, 0, len(users))
	for _, user := range users {
		sanitizedUser := struct {
			ID         int64         `json:"id"`
			Username   string        `json:"username"`
			Email      string        `json:"email"`
			MFAEnabled bool          `json:"mfa_enabled"`
			IsActive   bool          `json:"is_active"`
			IsLocked   bool          `json:"is_locked"`
			LastLogin  time.Time     `json:"last_login_at,omitempty"`
			Roles      []models.Role `json:"roles"`
		}{
			ID:         user.ID,
			Username:   user.Username,
			Email:      user.Email,
			MFAEnabled: user.MFAEnabled,
			IsActive:   user.IsActive,
			IsLocked:   user.IsLocked,
			LastLogin:  user.LastLoginAt,
			Roles:      user.Roles,
		}

		sanitizedUsers = append(sanitizedUsers, sanitizedUser)
	}

	writeJSON(w, sanitizedUsers, http.StatusOK)
}

// GetUser retrieves a user by ID
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Get user from repository
	user, err := h.userRepo.GetByID(id)
	if err != nil {
		h.logger.Error("Error getting user", "error", err)
		errorResponse(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	// Sanitize user object for response
	sanitizedUser := struct {
		ID         int64         `json:"id"`
		Username   string        `json:"username"`
		Email      string        `json:"email"`
		MFAEnabled bool          `json:"mfa_enabled"`
		IsActive   bool          `json:"is_active"`
		IsLocked   bool          `json:"is_locked"`
		LastLogin  time.Time     `json:"last_login_at,omitempty"`
		Roles      []models.Role `json:"roles"`
	}{
		ID:         user.ID,
		Username:   user.Username,
		Email:      user.Email,
		MFAEnabled: user.MFAEnabled,
		IsActive:   user.IsActive,
		IsLocked:   user.IsLocked,
		LastLogin:  user.LastLoginAt,
		Roles:      user.Roles,
	}

	writeJSON(w, sanitizedUser, http.StatusOK)
}

// CreateUser creates a new user
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var createRequest struct {
		Username string   `json:"username"`
		Email    string   `json:"email"`
		Password string   `json:"password"`
		Roles    []string `json:"roles,omitempty"`
		IsActive bool     `json:"is_active"`
	}

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&createRequest); err != nil {
		h.logger.Error("Error parsing create user request", "error", err)
		errorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate request
	if createRequest.Username == "" || createRequest.Email == "" || createRequest.Password == "" {
		errorResponse(w, "Username, email, and password are required", http.StatusBadRequest)
		return
	}

	// Validate email format
	if !utils.IsValidEmail(createRequest.Email) {
		errorResponse(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Validate password strength
	if !utils.IsStrongPassword(createRequest.Password) {
		errorResponse(w, "Password must be at least 8 characters and include a mix of letters, numbers, and symbols", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(createRequest.Password), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("Error hashing password", "error", err)
		errorResponse(w, "Failed to process password", http.StatusInternalServerError)
		return
	}

	// Create user object
	user := &models.User{
		Username:     createRequest.Username,
		Email:        createRequest.Email,
		PasswordHash: string(hashedPassword),
		IsActive:     createRequest.IsActive,
	}

	// Create user in database
	if err := h.userRepo.Create(user); err != nil {
		h.logger.Error("Error creating user", "error", err)

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

	// Assign roles if provided
	if len(createRequest.Roles) > 0 {
		for _, roleName := range createRequest.Roles {
			// Get role by name
			role, err := h.rbacService.GetRoleByName(roleName)
			if err != nil || role == nil {
				h.logger.Warn("Role not found", "role", roleName)
				continue
			}

			// Assign role to user
			if err := h.rbacService.AssignRoleToUser(user.ID, role.ID); err != nil {
				h.logger.Error("Error assigning role to user", "error", err)
			}
		}
	} else {
		// Assign default 'user' role
		defaultRole, err := h.rbacService.GetRoleByName("user")
		if err == nil && defaultRole != nil {
			if err := h.rbacService.AssignRoleToUser(user.ID, defaultRole.ID); err != nil {
				h.logger.Error("Error assigning default role to user", "error", err)
			}
		}
	}

	// Return created user
	sanitizedUser := struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		IsActive bool   `json:"is_active"`
	}{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		IsActive: user.IsActive,
	}

	writeJSON(w, sanitizedUser, http.StatusCreated)
}

// UpdateUser updates a user
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var updateRequest struct {
		Email    string `json:"email,omitempty"`
		Password string `json:"password,omitempty"`
		IsActive bool   `json:"is_active,omitempty"`
		IsLocked bool   `json:"is_locked,omitempty"`
	}

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&updateRequest); err != nil {
		h.logger.Error("Error parsing update user request", "error", err)
		errorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Get user from repository
	user, err := h.userRepo.GetByID(id)
	if err != nil {
		h.logger.Error("Error getting user", "error", err)
		errorResponse(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	// Update fields if provided
	if updateRequest.Email != "" {
		// Validate email format
		if !utils.IsValidEmail(updateRequest.Email) {
			errorResponse(w, "Invalid email format", http.StatusBadRequest)
			return
		}
		user.Email = updateRequest.Email
	}

	if updateRequest.Password != "" {
		// Validate password strength
		if !utils.IsStrongPassword(updateRequest.Password) {
			errorResponse(w, "Password must be at least 8 characters and include a mix of letters, numbers, and symbols", http.StatusBadRequest)
			return
		}

		// Hash password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updateRequest.Password), bcrypt.DefaultCost)
		if err != nil {
			h.logger.Error("Error hashing password", "error", err)
			errorResponse(w, "Failed to process password", http.StatusInternalServerError)
			return
		}

		user.PasswordHash = string(hashedPassword)
	}

	// Update active/locked status
	user.IsActive = updateRequest.IsActive
	user.IsLocked = updateRequest.IsLocked

	// Update user in database
	if err := h.userRepo.Update(user); err != nil {
		h.logger.Error("Error updating user", "error", err)
		errorResponse(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	// Return updated user
	sanitizedUser := struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		IsActive bool   `json:"is_active"`
		IsLocked bool   `json:"is_locked"`
	}{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		IsActive: user.IsActive,
		IsLocked: user.IsLocked,
	}

	writeJSON(w, sanitizedUser, http.StatusOK)
}

// DeleteUser deletes a user
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Delete user from database
	if err := h.userRepo.Delete(id); err != nil {
		h.logger.Error("Error deleting user", "error", err)
		errorResponse(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	// Return success response
	response := struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{
		Success: true,
		Message: "User deleted successfully",
	}

	writeJSON(w, response, http.StatusOK)
}
