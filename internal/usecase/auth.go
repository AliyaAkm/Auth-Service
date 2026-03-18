package usecase

import (
	"auth-service/internal/domain"
	"auth-service/internal/service/security"
	"context"
	"time"

	"github.com/google/uuid"
)

type Tokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type Auth struct {
	users   UserRepository
	refresh RefreshRepository
	hasher  PasswordHasher
	issuer  TokenIssuer

	refreshTTL time.Duration
	now        func() time.Time
	uuidNew    func() uuid.UUID
}

func NewAuth(users UserRepository, refresh RefreshRepository, hasher PasswordHasher, issuer TokenIssuer, refreshTTL time.Duration, uuidNew func() uuid.UUID, now func() time.Time) *Auth {
	return &Auth{
		users:      users,
		refresh:    refresh,
		hasher:     hasher,
		issuer:     issuer,
		refreshTTL: refreshTTL,
		uuidNew:    uuidNew,
		now:        now,
	}
}

func (a *Auth) Register(ctx context.Context, email, password string) (Tokens, error) {
	if _, ok := a.users.FindByEmail(ctx, email); ok {
		return Tokens{}, domain.ErrEmailTaken
	}

	pwHash, err := a.hasher.Hash(password)
	if err != nil {
		return Tokens{}, err
	}

	u := domain.User{
		ID:           a.uuidNew(),
		Email:        email,
		PasswordHash: pwHash,
		Roles: []domain.Role{
			{Code: domain.RoleStudent},
		},
		IsActive:  true,
		CreatedAt: a.now(),
	}
	if err := a.users.Create(ctx, u); err != nil {
		return Tokens{}, err
	}

	return a.IssueTokens(ctx, u)
}

func (a *Auth) Login(ctx context.Context, email, password string) (Tokens, error) {
	u, ok := a.users.FindByEmail(ctx, email)
	if !ok {
		return Tokens{}, domain.ErrInvalidCredentials
	}
	if !u.IsActive {
		return Tokens{}, domain.ErrInactiveUser
	}
	if !a.hasher.Compare(u.PasswordHash, password) {
		return Tokens{}, domain.ErrInvalidCredentials
	}

	return a.IssueTokens(ctx, u)
}

func (a *Auth) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	if refreshToken == "" {
		return Tokens{}, domain.ErrInvalidToken
	}

	hash := security.HashToken(refreshToken)
	sess, ok := a.refresh.GetByHash(ctx, hash)
	if !ok {
		return Tokens{}, domain.ErrInvalidToken
	}
	if sess.RevokedAt != nil {
		return Tokens{}, domain.ErrSessionRevoked
	}

	now := a.now()
	if now.After(sess.ExpiresAt) {
		if err := a.refresh.RevokeByHash(ctx, hash, now); err != nil {
			return Tokens{}, err
		}
		return Tokens{}, domain.ErrInvalidToken
	}

	u, ok := a.users.FindByID(ctx, sess.UserID)
	if !ok {
		return Tokens{}, domain.ErrInvalidToken
	}
	if !u.IsActive {
		return Tokens{}, domain.ErrInactiveUser
	}

	if err := a.refresh.RevokeByHash(ctx, hash, now); err != nil {
		return Tokens{}, err
	}

	return a.IssueTokens(ctx, u)
}

func (a *Auth) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return domain.ErrInvalidToken
	}

	hash := security.HashToken(refreshToken)
	if _, ok := a.refresh.GetByHash(ctx, hash); !ok {
		return domain.ErrInvalidToken
	}

	a.refresh.RevokeByHash(ctx, hash, a.now())
	return nil
}

func (a *Auth) GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	user, ok := a.users.FindByID(ctx, userID)
	if !ok {
		return nil, domain.ErrNotFound
	}

	return &user, nil
}

func (a *Auth) IssueTokens(ctx context.Context, u domain.User) (Tokens, error) {
	roles := domain.RoleCodesFromRoles(u.Roles)
	primaryRole := domain.PrimaryRoleCode(u.Roles)
	if primaryRole == "" {
		return Tokens{}, domain.ErrRoleNotFound
	}

	access, err := a.issuer.NewAccessToken(u.ID, primaryRole, roles, u.IsActive)
	if err != nil {
		return Tokens{}, err
	}

	rt, err := security.NewRefreshToken()
	if err != nil {
		return Tokens{}, err
	}

	now := a.now()
	sess := domain.RefreshSession{
		ID:               a.uuidNew(),
		UserID:           u.ID,
		RefreshTokenHash: security.HashToken(rt),
		ExpiresAt:        now.Add(a.refreshTTL),
		CreatedAt:        now,
	}
	if err := a.refresh.Create(ctx, sess); err != nil {
		return Tokens{}, err
	}

	return Tokens{AccessToken: access, RefreshToken: rt}, nil
}
