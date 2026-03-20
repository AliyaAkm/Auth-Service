package usecase

import (
	"auth-service/internal/domain"
	"context"

	"github.com/google/uuid"
)

type RBAC struct {
	users UserRepository
}

func NewRBAC(users UserRepository) *RBAC {
	return &RBAC{users: users}
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

func (r *RBAC) ReplaceUserRoles(ctx context.Context, actorUserID, targetUserID uuid.UUID, roleIDs []uuid.UUID) ([]domain.Role, error) {
	actor, err := r.requireAdminActor(ctx, actorUserID)
	if err != nil {
		return nil, err
	}

	target, ok := r.users.FindByID(ctx, targetUserID)
	if !ok {
		return nil, domain.ErrNotFound
	}

	normalizedRoleIDs := uniqueRoleIDs(roleIDs)
	if len(normalizedRoleIDs) == 0 {
		return nil, domain.ErrUserMustHaveRole
	}

	desiredRoles, err := r.loadRolesByIDs(ctx, normalizedRoleIDs)
	if err != nil {
		return nil, err
	}

	if domain.HasRole(target.Roles, domain.RoleAdmin) && !domain.HasRole(desiredRoles, domain.RoleAdmin) {
		adminsCount, err := r.users.CountUsersByRole(ctx, domain.RoleAdmin)
		if err != nil {
			return nil, err
		}
		if adminsCount <= 1 {
			return nil, domain.ErrLastAdminRemoval
		}
	}

	assignedBy := actor.ID
	if err := r.users.ReplaceUserRoles(ctx, target.ID, normalizedRoleIDs, &assignedBy); err != nil {
		return nil, err
	}

	updated, ok := r.users.FindByID(ctx, target.ID)
	if !ok {
		return nil, domain.ErrNotFound
	}

	return updated.Roles, nil
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

func (r *RBAC) RevokeRole(ctx context.Context, actorUserID, targetUserID, roleID uuid.UUID) ([]domain.Role, error) {
	_, err := r.requireAdminActor(ctx, actorUserID)
	if err != nil {
		return nil, err
	}

	target, ok := r.users.FindByID(ctx, targetUserID)
	if !ok {
		return nil, domain.ErrNotFound
	}

	role, ok, err := r.users.GetRoleByID(ctx, roleID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, domain.ErrRoleNotFound
	}

	if !domain.HasRole(target.Roles, role.Code) {
		return nil, domain.ErrRoleNotAssigned
	}
	if len(target.Roles) == 1 {
		return nil, domain.ErrUserMustHaveRole
	}

	if role.Code == domain.RoleAdmin {
		adminsCount, err := r.users.CountUsersByRole(ctx, domain.RoleAdmin)
		if err != nil {
			return nil, err
		}
		if adminsCount <= 1 {
			return nil, domain.ErrLastAdminRemoval
		}
	}

	if err := r.users.RevokeRole(ctx, target.ID, role.ID); err != nil {
		return nil, err
	}

	updated, ok := r.users.FindByID(ctx, target.ID)
	if !ok {
		return nil, domain.ErrNotFound
	}

	return updated.Roles, nil
}

func (r *RBAC) UpdateUserStatus(ctx context.Context, actorUserID, targetUserID uuid.UUID, isActive bool) (domain.User, error) {
	actor, err := r.requireActor(ctx, actorUserID)
	if err != nil {
		return domain.User{}, err
	}
	if !domain.CanViewOtherUsersRoles(actor.Roles) {
		return domain.User{}, domain.ErrForbidden
	}

	target, ok := r.users.FindByID(ctx, targetUserID)
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}

	if !domain.CanManageUserStatus(actor.Roles, target.Roles) {
		return domain.User{}, domain.ErrForbidden
	}

	if target.IsActive == isActive {
		return target, nil
	}

	if !isActive && domain.HasRole(target.Roles, domain.RoleAdmin) {
		adminsCount, err := r.users.CountActiveUsersByRole(ctx, domain.RoleAdmin)
		if err != nil {
			return domain.User{}, err
		}
		if adminsCount <= 1 {
			return domain.User{}, domain.ErrLastAdminDeactivation
		}
	}

	if err := r.users.UpdateStatus(ctx, target.ID, isActive); err != nil {
		return domain.User{}, err
	}

	updated, ok := r.users.FindByID(ctx, target.ID)
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}

	return updated, nil
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

func (r *RBAC) requireAdminActor(ctx context.Context, actorUserID uuid.UUID) (domain.User, error) {
	actor, err := r.requireActor(ctx, actorUserID)
	if err != nil {
		return domain.User{}, err
	}
	if !domain.HasRole(actor.Roles, domain.RoleAdmin) {
		return domain.User{}, domain.ErrForbidden
	}

	return actor, nil
}

func (r *RBAC) loadRolesByIDs(ctx context.Context, roleIDs []uuid.UUID) ([]domain.Role, error) {
	roles := make([]domain.Role, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		if roleID == uuid.Nil {
			return nil, domain.ErrValidation
		}

		role, ok, err := r.users.GetRoleByID(ctx, roleID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, domain.ErrRoleNotFound
		}

		roles = append(roles, role)
	}

	return roles, nil
}

func uniqueRoleIDs(roleIDs []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(roleIDs))
	result := make([]uuid.UUID, 0, len(roleIDs))

	for _, roleID := range roleIDs {
		if roleID == uuid.Nil {
			continue
		}
		if _, exists := seen[roleID]; exists {
			continue
		}
		seen[roleID] = struct{}{}
		result = append(result, roleID)
	}

	return result
}
