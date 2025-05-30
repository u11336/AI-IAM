package rbac

import (
	"errors"
	"fmt"

	"github.com/u11336/ai-iam/internal/data/models"
	"github.com/u11336/ai-iam/internal/data/repository"
)

var (
	ErrRoleNotFound            = errors.New("role not found")
	ErrPermissionNotFound      = errors.New("permission not found")
	ErrRoleAlreadyExists       = errors.New("role already exists")
	ErrPermissionAlreadyExists = errors.New("permission already exists")
	ErrRoleInUse               = errors.New("role is in use and cannot be deleted")
)

// RBACService handles role-based access control
type RBACService struct {
	userRepo *repository.UserRepository
	db       *repository.RoleRepository
}

// NewRBACService creates a new RBAC service
func NewRBACService(userRepo *repository.UserRepository, roleRepo *repository.RoleRepository) *RBACService {
	return &RBACService{
		userRepo: userRepo,
		db:       roleRepo,
	}
}

// GetRoles retrieves all roles
func (s *RBACService) GetRoles() ([]models.Role, error) {
	return s.db.GetAllRoles()
}

// GetRole retrieves a role by ID
func (s *RBACService) GetRole(id int64) (*models.Role, error) {
	role, err := s.db.GetRoleByID(id)
	if err != nil {
		return nil, fmt.Errorf("error getting role: %w", err)
	}

	if role == nil {
		return nil, ErrRoleNotFound
	}

	return role, nil
}

// CreateRole creates a new role
func (s *RBACService) CreateRole(name, description string) (*models.Role, error) {
	// Check if role already exists
	existing, _ := s.db.GetRoleByName(name)
	if existing != nil {
		return nil, ErrRoleAlreadyExists
	}

	role := &models.Role{
		Name:        name,
		Description: description,
	}

	if err := s.db.CreateRole(role); err != nil {
		return nil, fmt.Errorf("error creating role: %w", err)
	}

	return role, nil
}

// UpdateRole updates a role
func (s *RBACService) UpdateRole(id int64, name, description string) (*models.Role, error) {
	role, err := s.db.GetRoleByID(id)
	if err != nil {
		return nil, fmt.Errorf("error getting role: %w", err)
	}

	if role == nil {
		return nil, ErrRoleNotFound
	}

	// If name is changing, check for duplicates
	if name != role.Name {
		existing, _ := s.db.GetRoleByName(name)
		if existing != nil {
			return nil, ErrRoleAlreadyExists
		}
	}

	role.Name = name
	role.Description = description

	if err := s.db.UpdateRole(role); err != nil {
		return nil, fmt.Errorf("error updating role: %w", err)
	}

	return role, nil
}

// DeleteRole deletes a role
func (s *RBACService) DeleteRole(id int64) error {
	role, err := s.db.GetRoleByID(id)
	if err != nil {
		return fmt.Errorf("error getting role: %w", err)
	}

	if role == nil {
		return ErrRoleNotFound
	}

	// Check if role is in use
	inUse, err := s.db.IsRoleInUse(id)
	if err != nil {
		return fmt.Errorf("error checking if role is in use: %w", err)
	}

	if inUse {
		return ErrRoleInUse
	}

	if err := s.db.DeleteRole(id); err != nil {
		return fmt.Errorf("error deleting role: %w", err)
	}

	return nil
}

// GetPermissions retrieves all permissions
func (s *RBACService) GetPermissions() ([]models.Permission, error) {
	return s.db.GetAllPermissions()
}

// GetPermission retrieves a permission by ID
func (s *RBACService) GetPermission(id int64) (*models.Permission, error) {
	perm, err := s.db.GetPermissionByID(id)
	if err != nil {
		return nil, fmt.Errorf("error getting permission: %w", err)
	}

	if perm == nil {
		return nil, ErrPermissionNotFound
	}

	return perm, nil
}

// CreatePermission creates a new permission
func (s *RBACService) CreatePermission(name, description, resource, action string) (*models.Permission, error) {
	// Check if permission already exists
	existing, _ := s.db.GetPermissionByResourceAction(resource, action)
	if existing != nil {
		return nil, ErrPermissionAlreadyExists
	}

	perm := &models.Permission{
		Name:        name,
		Description: description,
		Resource:    resource,
		Action:      action,
	}

	if err := s.db.CreatePermission(perm); err != nil {
		return nil, fmt.Errorf("error creating permission: %w", err)
	}

	return perm, nil
}

// UpdatePermission updates a permission
func (s *RBACService) UpdatePermission(id int64, name, description, resource, action string) (*models.Permission, error) {
	perm, err := s.db.GetPermissionByID(id)
	if err != nil {
		return nil, fmt.Errorf("error getting permission: %w", err)
	}

	if perm == nil {
		return nil, ErrPermissionNotFound
	}

	// If resource/action is changing, check for duplicates
	if resource != perm.Resource || action != perm.Action {
		existing, _ := s.db.GetPermissionByResourceAction(resource, action)
		if existing != nil && existing.ID != id {
			return nil, ErrPermissionAlreadyExists
		}
	}

	perm.Name = name
	perm.Description = description
	perm.Resource = resource
	perm.Action = action

	if err := s.db.UpdatePermission(perm); err != nil {
		return nil, fmt.Errorf("error updating permission: %w", err)
	}

	return perm, nil
}

// DeletePermission deletes a permission
func (s *RBACService) DeletePermission(id int64) error {
	perm, err := s.db.GetPermissionByID(id)
	if err != nil {
		return fmt.Errorf("error getting permission: %w", err)
	}

	if perm == nil {
		return ErrPermissionNotFound
	}

	if err := s.db.DeletePermission(id); err != nil {
		return fmt.Errorf("error deleting permission: %w", err)
	}

	return nil
}

// AssignPermissionToRole assigns a permission to a role
func (s *RBACService) AssignPermissionToRole(roleID, permID int64) error {
	// Check if role exists
	role, err := s.db.GetRoleByID(roleID)
	if err != nil {
		return fmt.Errorf("error getting role: %w", err)
	}

	if role == nil {
		return ErrRoleNotFound
	}

	// Check if permission exists
	perm, err := s.db.GetPermissionByID(permID)
	if err != nil {
		return fmt.Errorf("error getting permission: %w", err)
	}

	if perm == nil {
		return ErrPermissionNotFound
	}

	// Assign permission to role
	if err := s.db.AssignPermissionToRole(roleID, permID); err != nil {
		return fmt.Errorf("error assigning permission to role: %w", err)
	}

	return nil
}

// RemovePermissionFromRole removes a permission from a role
func (s *RBACService) RemovePermissionFromRole(roleID, permID int64) error {
	// Check if role exists
	role, err := s.db.GetRoleByID(roleID)
	if err != nil {
		return fmt.Errorf("error getting role: %w", err)
	}

	if role == nil {
		return ErrRoleNotFound
	}

	// Check if permission exists
	perm, err := s.db.GetPermissionByID(permID)
	if err != nil {
		return fmt.Errorf("error getting permission: %w", err)
	}

	if perm == nil {
		return ErrPermissionNotFound
	}

	// Remove permission from role
	if err := s.db.RemovePermissionFromRole(roleID, permID); err != nil {
		return fmt.Errorf("error removing permission from role: %w", err)
	}

	return nil
}

// AssignRoleToUser assigns a role to a user
func (s *RBACService) AssignRoleToUser(userID, roleID int64) error {
	// Check if user exists
	_, err := s.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("error getting user: %w", err)
	}

	// Check if role exists
	role, err := s.db.GetRoleByID(roleID)
	if err != nil {
		return fmt.Errorf("error getting role: %w", err)
	}

	if role == nil {
		return ErrRoleNotFound
	}

	// Assign role to user
	if err := s.userRepo.AssignRole(userID, roleID); err != nil {
		return fmt.Errorf("error assigning role to user: %w", err)
	}

	return nil
}

// RemoveRoleFromUser removes a role from a user
func (s *RBACService) RemoveRoleFromUser(userID, roleID int64) error {
	// Check if user exists
	_, err := s.userRepo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("error getting user: %w", err)
	}

	// Check if role exists
	role, err := s.db.GetRoleByID(roleID)
	if err != nil {
		return fmt.Errorf("error getting role: %w", err)
	}

	if role == nil {
		return ErrRoleNotFound
	}

	// Remove role from user
	if err := s.userRepo.RemoveRole(userID, roleID); err != nil {
		return fmt.Errorf("error removing role from user: %w", err)
	}

	return nil
}

// HasPermission checks if a user has a specific permission
func (s *RBACService) HasPermission(userID int64, resource, action string) (bool, error) {
	return s.userRepo.HasPermission(userID, resource, action)
}

// GetRolesByUser retrieves all roles assigned to a user
func (s *RBACService) GetRolesByUser(userID int64) ([]models.Role, error) {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("error getting user: %w", err)
	}

	return user.Roles, nil
}

// GetPermissionsByRole retrieves all permissions assigned to a role
func (s *RBACService) GetPermissionsByRole(roleID int64) ([]models.Permission, error) {
	role, err := s.db.GetRoleByID(roleID)
	if err != nil {
		return nil, fmt.Errorf("error getting role: %w", err)
	}

	if role == nil {
		return nil, ErrRoleNotFound
	}

	return role.Permissions, nil
}

func (s *RBACService) GetRoleByName(name string) (*models.Role, error) {
	role, err := s.db.GetRoleByName(name)
	if err != nil {
		return nil, fmt.Errorf("error getting role by name: %w", err)
	}

	if role == nil {
		return nil, ErrRoleNotFound
	}

	return role, nil
}
