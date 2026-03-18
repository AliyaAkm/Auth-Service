package usecase

import (
	"auth-service/internal/domain"
	"auth-service/internal/service/jwt"
	"auth-service/internal/service/security"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

type authUserRepoStub struct {
	usersByID    map[uuid.UUID]domain.User
	usersByEmail map[string]uuid.UUID
}

func newAuthUserRepoStub(users ...domain.User) *authUserRepoStub {
	repo := &authUserRepoStub{
		usersByID:    make(map[uuid.UUID]domain.User, len(users)),
		usersByEmail: make(map[string]uuid.UUID, len(users)),
	}
	for _, user := range users {
		repo.usersByID[user.ID] = user
		repo.usersByEmail[user.Email] = user.ID
	}
	return repo
}

func (r *authUserRepoStub) Create(_ context.Context, u domain.User) error {
	r.usersByID[u.ID] = u
	r.usersByEmail[u.Email] = u.ID
	return nil
}

func (r *authUserRepoStub) CreateWithRoles(_ context.Context, u domain.User, _ []string, _ *uuid.UUID) error {
	r.usersByID[u.ID] = u
	r.usersByEmail[u.Email] = u.ID
	return nil
}

func (r *authUserRepoStub) FindByEmail(_ context.Context, email string) (domain.User, bool) {
	userID, ok := r.usersByEmail[email]
	if !ok {
		return domain.User{}, false
	}
	user, ok := r.usersByID[userID]
	return user, ok
}

func (r *authUserRepoStub) FindByID(_ context.Context, id uuid.UUID) (domain.User, bool) {
	user, ok := r.usersByID[id]
	return user, ok
}

func (r *authUserRepoStub) UpdatePassword(_ context.Context, userID uuid.UUID, passwordHash string) error {
	user, ok := r.usersByID[userID]
	if !ok {
		return domain.ErrNotFound
	}
	user.PasswordHash = passwordHash
	r.usersByID[userID] = user
	return nil
}

func (r *authUserRepoStub) UpdateStatus(_ context.Context, userID uuid.UUID, isActive bool) error {
	user, ok := r.usersByID[userID]
	if !ok {
		return domain.ErrNotFound
	}
	user.IsActive = isActive
	r.usersByID[userID] = user
	return nil
}

func (r *authUserRepoStub) ListUsers(context.Context) ([]domain.User, error) {
	return nil, nil
}

func (r *authUserRepoStub) ListRoles(context.Context) ([]domain.Role, error) {
	return nil, nil
}

func (r *authUserRepoStub) GetRoleByCode(context.Context, string) (domain.Role, bool, error) {
	return domain.Role{}, false, nil
}

func (r *authUserRepoStub) GetRoleByID(context.Context, uuid.UUID) (domain.Role, bool, error) {
	return domain.Role{}, false, nil
}

func (r *authUserRepoStub) ReplaceUserRoles(context.Context, uuid.UUID, []uuid.UUID, *uuid.UUID) error {
	return nil
}

func (r *authUserRepoStub) RevokeRole(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}

func (r *authUserRepoStub) CountUsersByRole(context.Context, string) (int, error) {
	return 0, nil
}

func (r *authUserRepoStub) CountActiveUsersByRole(context.Context, string) (int, error) {
	return 0, nil
}

type authRefreshRepoStub struct {
	revokedAllFor []uuid.UUID
}

func (r *authRefreshRepoStub) Create(context.Context, domain.RefreshSession) error {
	return nil
}

func (r *authRefreshRepoStub) GetByHash(context.Context, string) (domain.RefreshSession, bool) {
	return domain.RefreshSession{}, false
}

func (r *authRefreshRepoStub) RevokeByHash(context.Context, string, time.Time) error {
	return nil
}

func (r *authRefreshRepoStub) RevokeAllByUserID(_ context.Context, userID uuid.UUID, _ time.Time) error {
	r.revokedAllFor = append(r.revokedAllFor, userID)
	return nil
}

type authResetRepoStub struct {
	resets []domain.PasswordResetCode
}

func (r *authResetRepoStub) Create(_ context.Context, reset domain.PasswordResetCode) error {
	r.resets = append(r.resets, reset)
	return nil
}

func (r *authResetRepoStub) GetActiveByUserIDAndCodeHash(_ context.Context, userID uuid.UUID, codeHash string, now time.Time) (domain.PasswordResetCode, bool, error) {
	for _, reset := range r.resets {
		if reset.UserID != userID {
			continue
		}
		if reset.CodeHash != codeHash {
			continue
		}
		if reset.UsedAt != nil || !reset.ExpiresAt.After(now) {
			continue
		}
		return reset, true, nil
	}
	return domain.PasswordResetCode{}, false, nil
}

func (r *authResetRepoStub) InvalidateActiveByUserID(_ context.Context, userID uuid.UUID, when time.Time) error {
	for i := range r.resets {
		if r.resets[i].UserID != userID {
			continue
		}
		if r.resets[i].UsedAt != nil || !r.resets[i].ExpiresAt.After(when) {
			continue
		}
		r.resets[i].UsedAt = &when
	}
	return nil
}

func (r *authResetRepoStub) MarkUsed(_ context.Context, resetID uuid.UUID, when time.Time) error {
	for i := range r.resets {
		if r.resets[i].ID != resetID {
			continue
		}
		if r.resets[i].UsedAt != nil {
			return domain.ErrInvalidResetCode
		}
		r.resets[i].UsedAt = &when
		return nil
	}
	return domain.ErrInvalidResetCode
}

type authTokenIssuerStub struct{}

func (authTokenIssuerStub) NewAccessToken(uuid.UUID, string, []string, bool) (string, error) {
	return "access-token", nil
}

func (authTokenIssuerStub) VerifyAccessToken(string) (*jwt.Claims, error) {
	return nil, nil
}

type authResetSenderStub struct {
	email string
	code  string
	calls int
}

func (s *authResetSenderStub) SendPasswordResetCode(_ context.Context, email, code string) error {
	s.email = email
	s.code = code
	s.calls++
	return nil
}

func TestForgotPasswordCreatesResetCodeAndSendsIt(t *testing.T) {
	user := domain.User{
		ID:       uuid.New(),
		Email:    "student@example.com",
		IsActive: true,
		Roles:    []domain.Role{{Code: domain.RoleStudent}},
	}

	userRepo := newAuthUserRepoStub(user)
	refreshRepo := &authRefreshRepoStub{}
	resetRepo := &authResetRepoStub{}
	resetSender := &authResetSenderStub{}
	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)

	uc := NewAuth(
		userRepo,
		refreshRepo,
		resetRepo,
		security.PasswordHasher{},
		authTokenIssuerStub{},
		resetSender,
		24*time.Hour,
		15*time.Minute,
		func() (string, error) { return "123456", nil },
		uuid.New,
		func() time.Time { return now },
	)

	if err := uc.ForgotPassword(context.Background(), user.Email); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(resetRepo.resets) != 1 {
		t.Fatalf("expected 1 reset code, got %d", len(resetRepo.resets))
	}
	if resetRepo.resets[0].CodeHash != security.HashToken("123456") {
		t.Fatalf("unexpected code hash: %s", resetRepo.resets[0].CodeHash)
	}
	if resetSender.calls != 1 || resetSender.email != user.Email || resetSender.code != "123456" {
		t.Fatal("expected reset code to be sent once")
	}
}

func TestForgotPasswordUnknownEmailReturnsNil(t *testing.T) {
	uc := NewAuth(
		newAuthUserRepoStub(),
		&authRefreshRepoStub{},
		&authResetRepoStub{},
		security.PasswordHasher{},
		authTokenIssuerStub{},
		&authResetSenderStub{},
		24*time.Hour,
		15*time.Minute,
		func() (string, error) { return "123456", nil },
		uuid.New,
		time.Now,
	)

	if err := uc.ForgotPassword(context.Background(), "missing@example.com"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestResetPasswordUpdatesPasswordAndRevokesSessions(t *testing.T) {
	user := domain.User{
		ID:       uuid.New(),
		Email:    "student@example.com",
		IsActive: true,
		Roles:    []domain.Role{{Code: domain.RoleStudent}},
	}

	now := time.Date(2026, 3, 18, 10, 0, 0, 0, time.UTC)
	resetID := uuid.New()
	userRepo := newAuthUserRepoStub(user)
	refreshRepo := &authRefreshRepoStub{}
	resetRepo := &authResetRepoStub{
		resets: []domain.PasswordResetCode{
			{
				ID:        resetID,
				UserID:    user.ID,
				CodeHash:  security.HashToken("654321"),
				ExpiresAt: now.Add(10 * time.Minute),
				CreatedAt: now,
			},
		},
	}

	uc := NewAuth(
		userRepo,
		refreshRepo,
		resetRepo,
		security.PasswordHasher{},
		authTokenIssuerStub{},
		&authResetSenderStub{},
		24*time.Hour,
		15*time.Minute,
		func() (string, error) { return "123456", nil },
		uuid.New,
		func() time.Time { return now },
	)

	if err := uc.ResetPassword(context.Background(), user.Email, "654321", "newpassword"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	updatedUser, ok := userRepo.FindByID(context.Background(), user.ID)
	if !ok {
		t.Fatal("expected updated user to exist")
	}
	if updatedUser.PasswordHash == "" || updatedUser.PasswordHash == user.PasswordHash {
		t.Fatal("expected password hash to be updated")
	}
	if !(security.PasswordHasher{}).Compare(updatedUser.PasswordHash, "newpassword") {
		t.Fatal("expected new password hash to match")
	}
	if len(refreshRepo.revokedAllFor) != 1 || refreshRepo.revokedAllFor[0] != user.ID {
		t.Fatal("expected all refresh sessions to be revoked")
	}
	if resetRepo.resets[0].UsedAt == nil {
		t.Fatal("expected reset code to be marked as used")
	}
}

func TestChangePasswordUpdatesPasswordAndRevokesSessions(t *testing.T) {
	oldHash, err := security.PasswordHasher{}.Hash("oldpassword")
	if err != nil {
		t.Fatalf("unexpected hash error: %v", err)
	}

	user := domain.User{
		ID:           uuid.New(),
		Email:        "student@example.com",
		PasswordHash: oldHash,
		IsActive:     true,
		Roles:        []domain.Role{{Code: domain.RoleStudent}},
	}

	now := time.Date(2026, 3, 18, 11, 0, 0, 0, time.UTC)
	userRepo := newAuthUserRepoStub(user)
	refreshRepo := &authRefreshRepoStub{}
	resetRepo := &authResetRepoStub{}

	uc := NewAuth(
		userRepo,
		refreshRepo,
		resetRepo,
		security.PasswordHasher{},
		authTokenIssuerStub{},
		&authResetSenderStub{},
		24*time.Hour,
		15*time.Minute,
		func() (string, error) { return "123456", nil },
		uuid.New,
		func() time.Time { return now },
	)

	if err := uc.ChangePassword(context.Background(), user.ID, "oldpassword", "newpassword"); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	updatedUser, ok := userRepo.FindByID(context.Background(), user.ID)
	if !ok {
		t.Fatal("expected updated user to exist")
	}
	if !(security.PasswordHasher{}).Compare(updatedUser.PasswordHash, "newpassword") {
		t.Fatal("expected updated password hash to match new password")
	}
	if len(refreshRepo.revokedAllFor) != 1 || refreshRepo.revokedAllFor[0] != user.ID {
		t.Fatal("expected all refresh sessions to be revoked")
	}
}
