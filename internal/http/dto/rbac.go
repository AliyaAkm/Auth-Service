package dto

import (
	"time"

	"github.com/google/uuid"
)

type ReplaceUserRolesRequest struct {
	UserID  uuid.UUID   `json:"user_id"`
	RoleIDs []uuid.UUID `json:"role_ids"`
	RolesID []uuid.UUID `json:"roles_id"`
}

func (r ReplaceUserRolesRequest) EffectiveRoleIDs() []uuid.UUID {
	if len(r.RoleIDs) > 0 {
		return r.RoleIDs
	}
	return r.RolesID
}

type RevokeUserRoleRequest struct {
	UserID uuid.UUID `json:"user_id"`
	RoleID uuid.UUID `json:"role_id"`
}

type UpdateUserStatusRequest struct {
	UserID   uuid.UUID `json:"user_id"`
	IsActive *bool     `json:"is_active"`
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
