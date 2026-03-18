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
	CreateWithRoles(ctx context.Context, u domain.User, roleCodes []string, assignedBy *uuid.UUID) error
	FindByEmail(ctx context.Context, email string) (domain.User, bool)
	FindByID(ctx context.Context, id uuid.UUID) (domain.User, bool)
	ListUsers(ctx context.Context) ([]domain.User, error)
	ListRoles(ctx context.Context) ([]domain.Role, error)
	GetRoleByCode(ctx context.Context, code string) (domain.Role, bool, error)
	GetRoleByID(ctx context.Context, id uuid.UUID) (domain.Role, bool, error)
	ReplaceUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error
	RevokeRole(ctx context.Context, userID uuid.UUID, roleID uuid.UUID) error
	CountUsersByRole(ctx context.Context, roleCode string) (int, error)
}

type RefreshRepository interface {
	Create(ctx context.Context, s domain.RefreshSession) error
	GetByHash(ctx context.Context, hash string) (domain.RefreshSession, bool)
	RevokeByHash(ctx context.Context, hash string, when time.Time) error
}

type TokenIssuer interface {
	NewAccessToken(userID uuid.UUID, primaryRole string, roles []string, isActive bool) (string, error)
	VerifyAccessToken(tokenStr string) (*jwt.Claims, error)
}

type PasswordHasher interface {
	Hash(plain string) (string, error)
	Compare(hash, plain string) bool
}
