package mocks

import (
	"errors"
	"time"

	"github.com/u11336/ai-iam/internal/data/models"
)

// MockUserRepository is a mock implementation of UserRepository for testing
type MockUserRepository struct {
	users           map[int64]*models.User
	usersByUsername map[string]*models.User
	nextID          int64
	roles           map[int64][]int64 // userID -> roleIDs
}

// NewMockUserRepository creates a new mock user repository
func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users:           make(map[int64]*models.User),
		usersByUsername: make(map[string]*models.User),
		nextID:          1,
		roles:           make(map[int64][]int64),
	}
}

// GetByID retrieves a user by ID
func (r *MockUserRepository) GetByID(id int64) (*models.User, error) {
	user, exists := r.users[id]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// GetByUsername retrieves a user by username
func (r *MockUserRepository) GetByUsername(username string) (*models.User, error) {
	user, exists := r.usersByUsername[username]
	if !exists {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// Create creates a new user
func (r *MockUserRepository) Create(user *models.User) error {
	// Check for duplicate username
	if _, exists := r.usersByUsername[user.Username]; exists {
		return errors.New("UNIQUE constraint failed: users.username")
	}

	// Set ID and timestamps
	user.ID = r.nextID
	r.nextID++
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	// Add to maps
	r.users[user.ID] = user
	r.usersByUsername[user.Username] = user

	return nil
}

// Update updates an existing user
func (r *MockUserRepository) Update(user *models.User) error {
	if _, exists := r.users[user.ID]; !exists {
		return errors.New("user not found")
	}

	// Update username map if username changed
	existingUser := r.users[user.ID]
	if existingUser.Username != user.Username {
		delete(r.usersByUsername, existingUser.Username)
		r.usersByUsername[user.Username] = user
	}

	user.UpdatedAt = time.Now()
	r.users[user.ID] = user

	return nil
}

// UpdateLastLogin updates the last login time for a user
func (r *MockUserRepository) UpdateLastLogin(userID int64) error {
	user, exists := r.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	user.LastLoginAt = time.Now()
	user.FailedLoginAttempts = 0

	return nil
}

// IncrementFailedLogin increments the failed login counter for a user
func (r *MockUserRepository) IncrementFailedLogin(username string) error {
	user, exists := r.usersByUsername[username]
	if !exists {
		return errors.New("user not found")
	}

	user.FailedLoginAttempts++
	if user.FailedLoginAttempts >= 5 {
		user.IsLocked = true
	}

	return nil
}

// Delete deletes a user
func (r *MockUserRepository) Delete(id int64) error {
	user, exists := r.users[id]
	if !exists {
		return errors.New("user not found")
	}

	delete(r.usersByUsername, user.Username)
	delete(r.users, id)
	delete(r.roles, id)

	return nil
}

// AssignRole assigns a role to a user
func (r *MockUserRepository) AssignRole(userID, roleID int64) error {
	if _, exists := r.users[userID]; !exists {
		return errors.New("user not found")
	}

	// Check if role is already assigned
	userRoles, exists := r.roles[userID]
	if !exists {
		userRoles = []int64{}
	}

	for _, id := range userRoles {
		if id == roleID {
			return nil // Role already assigned
		}
	}

	r.roles[userID] = append(userRoles, roleID)

	// Update user's roles slice
	user := r.users[userID]
	user.Roles = append(user.Roles, models.Role{ID: roleID})

	return nil
}

// RemoveRole removes a role from a user
func (r *MockUserRepository) RemoveRole(userID, roleID int64) error {
	if _, exists := r.users[userID]; !exists {
		return errors.New("user not found")
	}

	userRoles, exists := r.roles[userID]
	if !exists {
		return nil // No roles to remove
	}

	// Filter out the role
	var newRoles []int64
	for _, id := range userRoles {
		if id != roleID {
			newRoles = append(newRoles, id)
		}
	}

	r.roles[userID] = newRoles

	// Update user's roles slice
	user := r.users[userID]
	var updatedRoles []models.Role
	for _, role := range user.Roles {
		if role.ID != roleID {
			updatedRoles = append(updatedRoles, role)
		}
	}
	user.Roles = updatedRoles

	return nil
}

// HasPermission checks if a user has a specific permission
func (r *MockUserRepository) HasPermission(userID int64, resource, action string) (bool, error) {
	// In a real system, this would check the database
	// For testing, we'll just return true for user ID 1 (admin)
	if userID == 1 {
		return true, nil
	}

	// For simplicity in testing
	if resource == "test_resource" && action == "read" {
		return true, nil
	}

	return false, nil
}

// GetAllUsers retrieves all users with pagination
func (r *MockUserRepository) GetAllUsers(limit, offset int) ([]*models.User, error) {
	users := make([]*models.User, 0, len(r.users))

	count := 0
	skip := offset

	// Collect users with pagination
	for _, user := range r.users {
		if skip > 0 {
			skip--
			continue
		}

		users = append(users, user)
		count++

		if count >= limit {
			break
		}
	}

	return users, nil
}

// AddTestUser adds a test user to the mock repository
func (r *MockUserRepository) AddTestUser(username, email, passwordHash string, isAdmin bool) *models.User {
	user := &models.User{
		ID:           r.nextID,
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	r.nextID++
	r.users[user.ID] = user
	r.usersByUsername[user.Username] = user

	if isAdmin {
		adminRole := models.Role{
			ID:   1,
			Name: "admin",
		}
		user.Roles = append(user.Roles, adminRole)
		r.roles[user.ID] = []int64{1}
	} else {
		userRole := models.Role{
			ID:   2,
			Name: "user",
		}
		user.Roles = append(user.Roles, userRole)
		r.roles[user.ID] = []int64{2}
	}

	return user
}
