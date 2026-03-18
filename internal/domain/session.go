package domain

import (
	"github.com/google/uuid"
	"time"
)

type RefreshSession struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	RefreshTokenHash string
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	CreatedAt        time.Time
}
