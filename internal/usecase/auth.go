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
	users       UserRepository
	refresh     RefreshRepository
	resets      PasswordResetRepository
	hasher      PasswordHasher
	issuer      TokenIssuer
	resetSender PasswordResetCodeSender

	refreshTTL   time.Duration
	resetCodeTTL time.Duration
	resetCodeNew func() (string, error)
	now          func() time.Time
	uuidNew      func() uuid.UUID
}

func NewAuth(
	users UserRepository,
	refresh RefreshRepository,
	resets PasswordResetRepository,
	hasher PasswordHasher,
	issuer TokenIssuer,
	resetSender PasswordResetCodeSender,
	refreshTTL time.Duration,
	resetCodeTTL time.Duration,
	resetCodeNew func() (string, error),
	uuidNew func() uuid.UUID,
	now func() time.Time,
) *Auth {
	return &Auth{
		users:        users,
		refresh:      refresh,
		resets:       resets,
		hasher:       hasher,
		issuer:       issuer,
		resetSender:  resetSender,
		refreshTTL:   refreshTTL,
		resetCodeTTL: resetCodeTTL,
		resetCodeNew: resetCodeNew,
		uuidNew:      uuidNew,
		now:          now,
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

func (a *Auth) ForgotPassword(ctx context.Context, email string) error {
	user, ok := a.users.FindByEmail(ctx, email)
	if !ok || !user.IsActive {
		return nil
	}

	code, err := a.resetCodeNew()
	if err != nil {
		return err
	}

	now := a.now()
	if err := a.resets.InvalidateActiveByUserID(ctx, user.ID, now); err != nil {
		return err
	}

	reset := domain.PasswordResetCode{
		ID:        a.uuidNew(),
		UserID:    user.ID,
		CodeHash:  security.HashToken(code),
		ExpiresAt: now.Add(a.resetCodeTTL),
		CreatedAt: now,
	}
	if err := a.resets.Create(ctx, reset); err != nil {
		return err
	}

	if err := a.resetSender.SendPasswordResetCode(ctx, user.Email, code); err != nil {
		_ = a.resets.InvalidateActiveByUserID(ctx, user.ID, now)
		return err
	}

	// The endpoint intentionally returns the same response for existing and
	// non-existing emails to avoid account enumeration.
	return nil
}

func (a *Auth) ResetPassword(ctx context.Context, email, code, newPassword string) error {
	user, ok := a.users.FindByEmail(ctx, email)
	if !ok || !user.IsActive {
		return domain.ErrInvalidResetCode
	}

	reset, ok, err := a.resets.GetActiveByUserIDAndCodeHash(ctx, user.ID, security.HashToken(code), a.now())
	if err != nil {
		return err
	}
	if !ok {
		return domain.ErrInvalidResetCode
	}

	pwHash, err := a.hasher.Hash(newPassword)
	if err != nil {
		return err
	}

	if err := a.users.UpdatePassword(ctx, user.ID, pwHash); err != nil {
		return err
	}

	now := a.now()
	if err := a.resets.MarkUsed(ctx, reset.ID, now); err != nil {
		return err
	}
	if err := a.refresh.RevokeAllByUserID(ctx, user.ID, now); err != nil {
		return err
	}

	return nil
}

func (a *Auth) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	user, ok := a.users.FindByID(ctx, userID)
	if !ok {
		return domain.ErrNotFound
	}
	if !user.IsActive {
		return domain.ErrInactiveUser
	}
	if !a.hasher.Compare(user.PasswordHash, currentPassword) {
		return domain.ErrCurrentPassword
	}

	pwHash, err := a.hasher.Hash(newPassword)
	if err != nil {
		return err
	}

	if err := a.users.UpdatePassword(ctx, user.ID, pwHash); err != nil {
		return err
	}

	now := a.now()
	if err := a.resets.InvalidateActiveByUserID(ctx, user.ID, now); err != nil {
		return err
	}
	if err := a.refresh.RevokeAllByUserID(ctx, user.ID, now); err != nil {
		return err
	}

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
