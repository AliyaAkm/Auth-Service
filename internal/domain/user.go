package domain

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	Roles        []Role
	IsActive     bool
	CreatedAt    time.Time
}
