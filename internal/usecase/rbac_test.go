package usecase

import (
	"auth-service/internal/domain"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

type rbacRepoStub struct {
	users map[uuid.UUID]domain.User
	roles map[string]domain.Role
}

func newRBACRepoStub(users ...domain.User) *rbacRepoStub {
	repo := &rbacRepoStub{
		users: make(map[uuid.UUID]domain.User),
		roles: map[string]domain.Role{
			domain.RoleStudent: {ID: uuid.New(), Code: domain.RoleStudent},
			domain.RoleTeacher: {ID: uuid.New(), Code: domain.RoleTeacher},
			domain.RoleManager: {ID: uuid.New(), Code: domain.RoleManager},
			domain.RoleAdmin:   {ID: uuid.New(), Code: domain.RoleAdmin},
		},
	}

	for _, user := range users {
		repo.users[user.ID] = user
	}

	return repo
}

func (r *rbacRepoStub) Create(context.Context, domain.User) error {
	return nil
}

func (r *rbacRepoStub) FindByEmail(context.Context, string) (domain.User, bool) {
	return domain.User{}, false
}

func (r *rbacRepoStub) FindByID(_ context.Context, id uuid.UUID) (domain.User, bool) {
	user, ok := r.users[id]
	return user, ok
}

func (r *rbacRepoStub) ListRoles(context.Context) ([]domain.Role, error) {
	return []domain.Role{
		r.roles[domain.RoleStudent],
		r.roles[domain.RoleTeacher],
		r.roles[domain.RoleManager],
		r.roles[domain.RoleAdmin],
	}, nil
}

func (r *rbacRepoStub) GetRoleByCode(_ context.Context, code string) (domain.Role, bool, error) {
	role, ok := r.roles[domain.NormalizeRoleCode(code)]
	return role, ok, nil
}

func (r *rbacRepoStub) AssignRole(_ context.Context, userID uuid.UUID, roleCode string, assignedBy *uuid.UUID) error {
	user := r.users[userID]
	role, ok, _ := r.GetRoleByCode(context.Background(), roleCode)
	if !ok {
		return domain.ErrRoleNotFound
	}
	if domain.HasRole(user.Roles, role.Code) {
		return domain.ErrRoleAlreadyAssigned
	}

	user.Roles = append(user.Roles, domain.Role{
		ID:        role.ID,
		Code:      role.Code,
		CreatedAt: time.Now(),
	})
	r.users[userID] = user
	_ = assignedBy
	return nil
}

func (r *rbacRepoStub) RevokeRole(_ context.Context, userID uuid.UUID, roleCode string) error {
	user := r.users[userID]
	filtered := make([]domain.Role, 0, len(user.Roles))
	removed := false
	for _, role := range user.Roles {
		if domain.NormalizeRoleCode(role.Code) == domain.NormalizeRoleCode(roleCode) {
			removed = true
			continue
		}
		filtered = append(filtered, role)
	}
	if !removed {
		return domain.ErrRoleNotAssigned
	}
	user.Roles = filtered
	r.users[userID] = user
	return nil
}

func (r *rbacRepoStub) CountUsersByRole(_ context.Context, roleCode string) (int, error) {
	count := 0
	for _, user := range r.users {
		if domain.HasRole(user.Roles, roleCode) {
			count++
		}
	}
	return count, nil
}

func TestAssignRoleRejectsManagerToAdmin(t *testing.T) {
	managerID := uuid.New()
	targetID := uuid.New()

	repo := newRBACRepoStub(
		domain.User{ID: managerID, IsActive: true, Roles: []domain.Role{{Code: domain.RoleManager}}},
		domain.User{ID: targetID, IsActive: true, Roles: []domain.Role{{Code: domain.RoleStudent}}},
	)

	uc := NewRBAC(repo)
	_, err := uc.AssignRole(context.Background(), managerID, targetID, domain.RoleAdmin)
	if err != domain.ErrForbidden {
		t.Fatalf("expected forbidden, got %v", err)
	}
}

func TestRevokeRoleRejectsLastAdminRemoval(t *testing.T) {
	adminID := uuid.New()

	repo := newRBACRepoStub(
		domain.User{
			ID:       adminID,
			IsActive: true,
			Roles: []domain.Role{
				{Code: domain.RoleAdmin},
				{Code: domain.RoleStudent},
			},
		},
	)

	uc := NewRBAC(repo)
	_, err := uc.RevokeRole(context.Background(), adminID, adminID, domain.RoleAdmin)
	if err != domain.ErrLastAdminRemoval {
		t.Fatalf("expected last admin removal, got %v", err)
	}
}
