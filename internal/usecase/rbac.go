package usecase

import (
	"auth-service/internal/domain"
	"context"
	"time"

	"github.com/google/uuid"
)

type RBAC struct {
	users   UserRepository
	hasher  PasswordHasher
	uuidNew func() uuid.UUID
	now     func() time.Time
}

func NewRBAC(users UserRepository, hasher PasswordHasher, uuidNew func() uuid.UUID, now func() time.Time) *RBAC {
	return &RBAC{
		users:   users,
		hasher:  hasher,
		uuidNew: uuidNew,
		now:     now,
	}
}

func (r *RBAC) ListUsers(ctx context.Context, actorUserID uuid.UUID) ([]domain.User, error) {
	actor, err := r.requireActor(ctx, actorUserID)
	if err != nil {
		return nil, err
	}
	if !domain.CanViewOtherUsersRoles(actor.Roles) {
		return nil, domain.ErrForbidden
	}

	return r.users.ListUsers(ctx)
}

func (r *RBAC) CreateAdminUser(ctx context.Context, actorUserID uuid.UUID, email, password string) (*domain.User, error) {
	actor, err := r.requireActor(ctx, actorUserID)
	if err != nil {
		return nil, err
	}
	if !domain.HasRole(actor.Roles, domain.RoleAdmin) {
		return nil, domain.ErrForbidden
	}

	if _, ok := r.users.FindByEmail(ctx, email); ok {
		return nil, domain.ErrEmailTaken
	}

	pwHash, err := r.hasher.Hash(password)
	if err != nil {
		return nil, err
	}

	user := domain.User{
		ID:           r.uuidNew(),
		Email:        email,
		PasswordHash: pwHash,
		Roles: []domain.Role{
			{Code: domain.RoleAdmin},
		},
		IsActive:  true,
		CreatedAt: r.now(),
	}

	assignedBy := actor.ID
	if err := r.users.CreateWithRoles(ctx, user, []string{domain.RoleAdmin}, &assignedBy); err != nil {
		return nil, err
	}

	created, ok := r.users.FindByID(ctx, user.ID)
	if !ok {
		return nil, domain.ErrNotFound
	}

	return &created, nil
}

func (r *RBAC) ListRoles(ctx context.Context) ([]domain.Role, error) {
	return r.users.ListRoles(ctx)
}

func (r *RBAC) GetUserRoles(ctx context.Context, actorUserID, targetUserID uuid.UUID) ([]domain.Role, error) {
	actor, err := r.requireActor(ctx, actorUserID)
	if err != nil {
		return nil, err
	}

	if actorUserID != targetUserID && !domain.CanViewOtherUsersRoles(actor.Roles) {
		return nil, domain.ErrForbidden
	}

	target, ok := r.users.FindByID(ctx, targetUserID)
	if !ok {
		return nil, domain.ErrNotFound
	}

	return target.Roles, nil
}

func (r *RBAC) AssignRole(ctx context.Context, actorUserID, targetUserID uuid.UUID, roleCode string) ([]domain.Role, error) {
	actor, target, normalizedRole, err := r.loadUsersAndRole(ctx, actorUserID, targetUserID, roleCode)
	if err != nil {
		return nil, err
	}

	if !domain.CanManageRole(actor.Roles, normalizedRole) {
		return nil, domain.ErrForbidden
	}

	assignedBy := actor.ID
	if err := r.users.AssignRole(ctx, target.ID, normalizedRole, &assignedBy); err != nil {
		return nil, err
	}

	updated, ok := r.users.FindByID(ctx, target.ID)
	if !ok {
		return nil, domain.ErrNotFound
	}

	return updated.Roles, nil
}

func (r *RBAC) RevokeRole(ctx context.Context, actorUserID, targetUserID uuid.UUID, roleCode string) ([]domain.Role, error) {
	actor, target, normalizedRole, err := r.loadUsersAndRole(ctx, actorUserID, targetUserID, roleCode)
	if err != nil {
		return nil, err
	}

	if !domain.CanManageRole(actor.Roles, normalizedRole) {
		return nil, domain.ErrForbidden
	}

	if !domain.HasRole(target.Roles, normalizedRole) {
		return nil, domain.ErrRoleNotAssigned
	}

	if len(target.Roles) == 1 {
		return nil, domain.ErrUserMustHaveRole
	}

	if normalizedRole == domain.RoleAdmin {
		adminsCount, err := r.users.CountUsersByRole(ctx, domain.RoleAdmin)
		if err != nil {
			return nil, err
		}
		if adminsCount <= 1 {
			return nil, domain.ErrLastAdminRemoval
		}
	}

	if err := r.users.RevokeRole(ctx, target.ID, normalizedRole); err != nil {
		return nil, err
	}

	updated, ok := r.users.FindByID(ctx, target.ID)
	if !ok {
		return nil, domain.ErrNotFound
	}

	return updated.Roles, nil
}

func (r *RBAC) loadUsersAndRole(ctx context.Context, actorUserID, targetUserID uuid.UUID, roleCode string) (domain.User, domain.User, string, error) {
	normalizedRole := domain.NormalizeRoleCode(roleCode)
	if !domain.IsValidRoleCode(normalizedRole) {
		return domain.User{}, domain.User{}, "", domain.ErrValidation
	}

	actor, err := r.requireActor(ctx, actorUserID)
	if err != nil {
		return domain.User{}, domain.User{}, "", err
	}

	target, ok := r.users.FindByID(ctx, targetUserID)
	if !ok {
		return domain.User{}, domain.User{}, "", domain.ErrNotFound
	}

	return actor, target, normalizedRole, nil
}

func (r *RBAC) requireActor(ctx context.Context, actorUserID uuid.UUID) (domain.User, error) {
	actor, ok := r.users.FindByID(ctx, actorUserID)
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	if !actor.IsActive {
		return domain.User{}, domain.ErrInactiveUser
	}

	return actor, nil
}
