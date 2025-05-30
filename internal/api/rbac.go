package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/u11336/ai-iam/internal/core/rbac"
	"github.com/u11336/ai-iam/internal/utils"
)

// RBACHandler handles role and permission related requests
type RBACHandler struct {
	rbacService *rbac.RBACService
	logger      *utils.Logger
}

// NewRBACHandler creates a new RBACHandler
func NewRBACHandler(rbacService *rbac.RBACService, logger *utils.Logger) *RBACHandler {
	return &RBACHandler{
		rbacService: rbacService,
		logger:      logger,
	}
}

// GetAllRoles returns all roles
func (h *RBACHandler) GetAllRoles(w http.ResponseWriter, r *http.Request) {
	// Get roles from service
	roles, err := h.rbacService.GetRoles()
	if err != nil {
		h.logger.Error("Error getting roles", "error", err)
		errorResponse(w, "Failed to get roles", http.StatusInternalServerError)
		return
	}

	// Return roles
	writeJSON(w, roles, http.StatusOK)
}

// GetRole returns a specific role
func (h *RBACHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	// Get role ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	// Get role from service
	role, err := h.rbacService.GetRole(id)
	if err != nil {
		if err == rbac.ErrRoleNotFound {
			errorResponse(w, "Role not found", http.StatusNotFound)
			return
		}

		h.logger.Error("Error getting role", "error", err)
		errorResponse(w, "Failed to get role", http.StatusInternalServerError)
		return
	}

	// Return role
	writeJSON(w, role, http.StatusOK)
}

// CreateRole creates a new role
func (h *RBACHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		errorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate request
	if request.Name == "" {
		errorResponse(w, "Role name is required", http.StatusBadRequest)
		return
	}

	// Create role
	role, err := h.rbacService.CreateRole(request.Name, request.Description)
	if err != nil {
		if err == rbac.ErrRoleAlreadyExists {
			errorResponse(w, "Role already exists", http.StatusConflict)
			return
		}

		h.logger.Error("Error creating role", "error", err)
		errorResponse(w, "Failed to create role", http.StatusInternalServerError)
		return
	}

	// Return created role
	writeJSON(w, role, http.StatusCreated)
}

// UpdateRole updates a role
func (h *RBACHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	// Get role ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	var request struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		errorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate request
	if request.Name == "" {
		errorResponse(w, "Role name is required", http.StatusBadRequest)
		return
	}

	// Update role
	role, err := h.rbacService.UpdateRole(id, request.Name, request.Description)
	if err != nil {
		if err == rbac.ErrRoleNotFound {
			errorResponse(w, "Role not found", http.StatusNotFound)
			return
		}

		if err == rbac.ErrRoleAlreadyExists {
			errorResponse(w, "Role name already exists", http.StatusConflict)
			return
		}

		h.logger.Error("Error updating role", "error", err)
		errorResponse(w, "Failed to update role", http.StatusInternalServerError)
		return
	}

	// Return updated role
	writeJSON(w, role, http.StatusOK)
}

// DeleteRole deletes a role
func (h *RBACHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	// Get role ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	// Delete role
	err = h.rbacService.DeleteRole(id)
	if err != nil {
		if err == rbac.ErrRoleNotFound {
			errorResponse(w, "Role not found", http.StatusNotFound)
			return
		}

		if err == rbac.ErrRoleInUse {
			errorResponse(w, "Cannot delete role because it is in use", http.StatusConflict)
			return
		}

		h.logger.Error("Error deleting role", "error", err)
		errorResponse(w, "Failed to delete role", http.StatusInternalServerError)
		return
	}

	// Return success
	writeJSON(w, map[string]bool{"success": true}, http.StatusOK)
}

// GetAllPermissions returns all permissions
func (h *RBACHandler) GetAllPermissions(w http.ResponseWriter, r *http.Request) {
	// Get permissions from service
	permissions, err := h.rbacService.GetPermissions()
	if err != nil {
		h.logger.Error("Error getting permissions", "error", err)
		errorResponse(w, "Failed to get permissions", http.StatusInternalServerError)
		return
	}

	// Return permissions
	writeJSON(w, permissions, http.StatusOK)
}

// GetPermission returns a specific permission
func (h *RBACHandler) GetPermission(w http.ResponseWriter, r *http.Request) {
	// Get permission ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid permission ID", http.StatusBadRequest)
		return
	}

	// Get permission from service
	permission, err := h.rbacService.GetPermission(id)
	if err != nil {
		if err == rbac.ErrPermissionNotFound {
			errorResponse(w, "Permission not found", http.StatusNotFound)
			return
		}

		h.logger.Error("Error getting permission", "error", err)
		errorResponse(w, "Failed to get permission", http.StatusInternalServerError)
		return
	}

	// Return permission
	writeJSON(w, permission, http.StatusOK)
}

// CreatePermission creates a new permission
func (h *RBACHandler) CreatePermission(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Resource    string `json:"resource"`
		Action      string `json:"action"`
	}

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		errorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate request
	if request.Name == "" || request.Resource == "" || request.Action == "" {
		errorResponse(w, "Name, resource, and action are required", http.StatusBadRequest)
		return
	}

	// Create permission
	permission, err := h.rbacService.CreatePermission(request.Name, request.Description, request.Resource, request.Action)
	if err != nil {
		if err == rbac.ErrPermissionAlreadyExists {
			errorResponse(w, "Permission already exists", http.StatusConflict)
			return
		}

		h.logger.Error("Error creating permission", "error", err)
		errorResponse(w, "Failed to create permission", http.StatusInternalServerError)
		return
	}

	// Return created permission
	writeJSON(w, permission, http.StatusCreated)
}

// UpdatePermission updates a permission
func (h *RBACHandler) UpdatePermission(w http.ResponseWriter, r *http.Request) {
	// Get permission ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid permission ID", http.StatusBadRequest)
		return
	}

	var request struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Resource    string `json:"resource"`
		Action      string `json:"action"`
	}

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		errorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate request
	if request.Name == "" || request.Resource == "" || request.Action == "" {
		errorResponse(w, "Name, resource, and action are required", http.StatusBadRequest)
		return
	}

	// Update permission
	permission, err := h.rbacService.UpdatePermission(id, request.Name, request.Description, request.Resource, request.Action)
	if err != nil {
		if err == rbac.ErrPermissionNotFound {
			errorResponse(w, "Permission not found", http.StatusNotFound)
			return
		}

		if err == rbac.ErrPermissionAlreadyExists {
			errorResponse(w, "Permission already exists", http.StatusConflict)
			return
		}

		h.logger.Error("Error updating permission", "error", err)
		errorResponse(w, "Failed to update permission", http.StatusInternalServerError)
		return
	}

	// Return updated permission
	writeJSON(w, permission, http.StatusOK)
}

// DeletePermission deletes a permission
func (h *RBACHandler) DeletePermission(w http.ResponseWriter, r *http.Request) {
	// Get permission ID from URL
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid permission ID", http.StatusBadRequest)
		return
	}

	// Delete permission
	err = h.rbacService.DeletePermission(id)
	if err != nil {
		if err == rbac.ErrPermissionNotFound {
			errorResponse(w, "Permission not found", http.StatusNotFound)
			return
		}

		h.logger.Error("Error deleting permission", "error", err)
		errorResponse(w, "Failed to delete permission", http.StatusInternalServerError)
		return
	}

	// Return success
	writeJSON(w, map[string]bool{"success": true}, http.StatusOK)
}

// AssignPermissionToRole assigns a permission to a role
func (h *RBACHandler) AssignPermissionToRole(w http.ResponseWriter, r *http.Request) {
	// Get role ID from URL
	roleIDStr := chi.URLParam(r, "id")
	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	var request struct {
		PermissionID int64 `json:"permission_id"`
	}

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		errorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Assign permission to role
	err = h.rbacService.AssignPermissionToRole(roleID, request.PermissionID)
	if err != nil {
		if err == rbac.ErrRoleNotFound {
			errorResponse(w, "Role not found", http.StatusNotFound)
			return
		}

		if err == rbac.ErrPermissionNotFound {
			errorResponse(w, "Permission not found", http.StatusNotFound)
			return
		}

		h.logger.Error("Error assigning permission to role", "error", err)
		errorResponse(w, "Failed to assign permission to role", http.StatusInternalServerError)
		return
	}

	// Return success
	writeJSON(w, map[string]bool{"success": true}, http.StatusOK)
}

// RemovePermissionFromRole removes a permission from a role
func (h *RBACHandler) RemovePermissionFromRole(w http.ResponseWriter, r *http.Request) {
	// Get role ID and permission ID from URL
	roleIDStr := chi.URLParam(r, "id")
	permIDStr := chi.URLParam(r, "permId")

	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	permID, err := strconv.ParseInt(permIDStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid permission ID", http.StatusBadRequest)
		return
	}

	// Remove permission from role
	err = h.rbacService.RemovePermissionFromRole(roleID, permID)
	if err != nil {
		if err == rbac.ErrRoleNotFound {
			errorResponse(w, "Role not found", http.StatusNotFound)
			return
		}

		if err == rbac.ErrPermissionNotFound {
			errorResponse(w, "Permission not found", http.StatusNotFound)
			return
		}

		h.logger.Error("Error removing permission from role", "error", err)
		errorResponse(w, "Failed to remove permission from role", http.StatusInternalServerError)
		return
	}

	// Return success
	writeJSON(w, map[string]bool{"success": true}, http.StatusOK)
}

// AssignRoleToUser assigns a role to a user
func (h *RBACHandler) AssignRoleToUser(w http.ResponseWriter, r *http.Request) {
	// Get user ID from URL
	userIDStr := chi.URLParam(r, "id")
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var request struct {
		RoleID int64 `json:"role_id"`
	}

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		errorResponse(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Assign role to user
	err = h.rbacService.AssignRoleToUser(userID, request.RoleID)
	if err != nil {
		if err == rbac.ErrRoleNotFound {
			errorResponse(w, "Role not found", http.StatusNotFound)
			return
		}

		h.logger.Error("Error assigning role to user", "error", err)
		errorResponse(w, "Failed to assign role to user", http.StatusInternalServerError)
		return
	}

	// Return success
	writeJSON(w, map[string]bool{"success": true}, http.StatusOK)
}

// RemoveRoleFromUser removes a role from a user
func (h *RBACHandler) RemoveRoleFromUser(w http.ResponseWriter, r *http.Request) {
	// Get user ID and role ID from URL
	userIDStr := chi.URLParam(r, "id")
	roleIDStr := chi.URLParam(r, "roleId")

	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	roleID, err := strconv.ParseInt(roleIDStr, 10, 64)
	if err != nil {
		errorResponse(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	// Remove role from user
	err = h.rbacService.RemoveRoleFromUser(userID, roleID)
	if err != nil {
		if err == rbac.ErrRoleNotFound {
			errorResponse(w, "Role not found", http.StatusNotFound)
			return
		}

		h.logger.Error("Error removing role from user", "error", err)
		errorResponse(w, "Failed to remove role from user", http.StatusInternalServerError)
		return
	}

	// Return success
	writeJSON(w, map[string]bool{"success": true}, http.StatusOK)
}
