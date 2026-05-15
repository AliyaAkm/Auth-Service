package domain

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID              uuid.UUID
	Email           string
	Login           string
	Bio             string
	PhotoURL        string
	Streak          int
	MaxStreak       int
	Level           int
	XP              int64
	PasswordHash    *string  // nullable for OAuth-only users
	OAuthProvider   *string  // "google" or "github"
	OAuthProviderID *string  // ID from OAuth provider
	Roles           []Role
	IsActive        bool
	CreatedAt       time.Time
}

type UserProfileUpdate struct {
	Email    *string
	Login    *string
	Bio      *string
	PhotoURL *string
}
