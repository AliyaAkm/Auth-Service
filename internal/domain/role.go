package domain

import (
	"github.com/google/uuid"
	"time"
)

type Role struct {
	ID           uuid.UUID
	Code         string
	Name         string
	Description  string
	IsDefault    bool
	IsPrivileged bool
	IsSupport    bool
	CreatedAt    time.Time
}
