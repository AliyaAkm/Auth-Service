package domain

import (
	"github.com/google/uuid"
	"time"
)

type PasswordResetCode struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	CodeHash  string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}
