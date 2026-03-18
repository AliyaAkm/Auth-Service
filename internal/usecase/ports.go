package usecase

import (
	"auth-service/internal/domain"
	"auth-service/internal/service/jwt"
	"context"
	"github.com/google/uuid"
	"time"
)

type UserRepository interface {
	Create(ctx context.Context, u domain.User) error
	FindByEmail(ctx context.Context, email string) (domain.User, bool)
	FindByID(ctx context.Context, id uuid.UUID) (domain.User, bool)
	FindUserRoles(ctx context.Context, id uuid.UUID) (*domain.Role, bool)
}

type RefreshRepository interface {
	Create(ctx context.Context, s domain.RefreshSession) error
	GetByHash(ctx context.Context, hash string) (domain.RefreshSession, bool)
	RevokeByHash(ctx context.Context, hash string, when time.Time) error
}

type TokenIssuer interface {
	NewAccessToken(userID uuid.UUID, role string, isActive bool) (string, error)
	VerifyAccessToken(tokenStr string) (*jwt.Claims, error)
}

type PasswordHasher interface {
	Hash(plain string) (string, error)
	Compare(hash, plain string) bool
}
