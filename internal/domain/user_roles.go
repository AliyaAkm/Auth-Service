package domain

import (
	"github.com/google/uuid"
	"time"
)

type UserRoles struct {
	UserID     uuid.UUID
	RoleID     uuid.UUID
	AssignedBy uuid.UUID
	AssignedAt time.Time
}
