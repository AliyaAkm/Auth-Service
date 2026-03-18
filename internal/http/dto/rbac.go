package dto

import (
	"time"

	"github.com/google/uuid"
)

type AssignRoleRequest struct {
	Role string `json:"role"`
}

type RoleResponse struct {
	ID           uuid.UUID `json:"id"`
	Code         string    `json:"code"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	IsDefault    bool      `json:"is_default"`
	IsPrivileged bool      `json:"is_privileged"`
	IsSupport    bool      `json:"is_support"`
	CreatedAt    time.Time `json:"created_at"`
}

type UserResponse struct {
	ID        uuid.UUID      `json:"id"`
	Email     string         `json:"email"`
	Roles     []RoleResponse `json:"roles"`
	IsActive  bool           `json:"is_active"`
	CreatedAt time.Time      `json:"created_at"`
}

type UserRolesResponse struct {
	UserID uuid.UUID      `json:"user_id"`
	Roles  []RoleResponse `json:"roles"`
}
