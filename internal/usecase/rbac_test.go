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
	roles map[uuid.UUID]domain.Role
}

func newRBACRepoStub(users ...domain.User) *rbacRepoStub {
	adminRoleID := uuid.New()
	managerRoleID := uuid.New()
	teacherRoleID := uuid.New()
	studentRoleID := uuid.New()

	repo := &rbacRepoStub{
		users: make(map[uuid.UUID]domain.User),
		roles: map[uuid.UUID]domain.Role{
			studentRoleID: {ID: studentRoleID, Code: domain.RoleStudent},
			teacherRoleID: {ID: teacherRoleID, Code: domain.RoleTeacher},
			managerRoleID: {ID: managerRoleID, Code: domain.RoleManager},
			adminRoleID:   {ID: adminRoleID, Code: domain.RoleAdmin},
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

func (r *rbacRepoStub) CreateWithRoles(_ context.Context, user domain.User, roleCodes []string, assignedBy *uuid.UUID) error {
	user.Roles = user.Roles[:0]
	for _, roleCode := range roleCodes {
		role, ok, _ := r.GetRoleByCode(context.Background(), roleCode)
		if !ok {
			return domain.ErrRoleNotFound
		}
		user.Roles = append(user.Roles, role)
	}
	r.users[user.ID] = user
	_ = assignedBy
	return nil
}

func (r *rbacRepoStub) FindByEmail(_ context.Context, email string) (domain.User, bool) {
	for _, user := range r.users {
		if user.Email == email {
			return user, true
		}
	}
	return domain.User{}, false
}

func (r *rbacRepoStub) FindByID(_ context.Context, id uuid.UUID) (domain.User, bool) {
	user, ok := r.users[id]
	return user, ok
}

func (r *rbacRepoStub) ListUsers(context.Context) ([]domain.User, error) {
	users := make([]domain.User, 0, len(r.users))
	for _, user := range r.users {
		users = append(users, user)
	}
	return users, nil
}

func (r *rbacRepoStub) ListRoles(context.Context) ([]domain.Role, error) {
	roles := make([]domain.Role, 0, len(r.roles))
	for _, role := range r.roles {
		roles = append(roles, role)
	}
	return roles, nil
}

func (r *rbacRepoStub) GetRoleByCode(_ context.Context, code string) (domain.Role, bool, error) {
	for _, role := range r.roles {
		if domain.NormalizeRoleCode(role.Code) == domain.NormalizeRoleCode(code) {
			return role, true, nil
		}
	}
	return domain.Role{}, false, nil
}

func (r *rbacRepoStub) GetRoleByID(_ context.Context, id uuid.UUID) (domain.Role, bool, error) {
	role, ok := r.roles[id]
	return role, ok, nil
}

func (r *rbacRepoStub) ReplaceUserRoles(_ context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	user := r.users[userID]
	user.Roles = user.Roles[:0]
	for _, roleID := range roleIDs {
		role, ok := r.roles[roleID]
		if !ok {
			return domain.ErrRoleNotFound
		}
		user.Roles = append(user.Roles, domain.Role{
			ID:        role.ID,
			Code:      role.Code,
			CreatedAt: time.Now(),
		})
	}
	r.users[userID] = user
	_ = assignedBy
	return nil
}

func (r *rbacRepoStub) RevokeRole(_ context.Context, userID uuid.UUID, roleID uuid.UUID) error {
	user := r.users[userID]
	filtered := make([]domain.Role, 0, len(user.Roles))
	removed := false
	for _, role := range user.Roles {
		if role.ID == roleID {
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

func newRBACUseCase(repo *rbacRepoStub) *RBAC {
	return NewRBAC(repo)
}

func roleIDByCode(t *testing.T, repo *rbacRepoStub, code string) uuid.UUID {
	t.Helper()

	role, ok, err := repo.GetRoleByCode(context.Background(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("role %s not found", code)
	}

	return role.ID
}

func TestReplaceUserRolesRequiresAdmin(t *testing.T) {
	managerID := uuid.New()
	targetID := uuid.New()

	repo := newRBACRepoStub(
		domain.User{ID: managerID, IsActive: true, Roles: []domain.Role{{Code: domain.RoleManager}}},
		domain.User{ID: targetID, IsActive: true, Roles: []domain.Role{{Code: domain.RoleStudent}}},
	)

	uc := newRBACUseCase(repo)
	_, err := uc.ReplaceUserRoles(context.Background(), managerID, targetID, []uuid.UUID{roleIDByCode(t, repo, domain.RoleAdmin)})
	if err != domain.ErrForbidden {
		t.Fatalf("expected forbidden, got %v", err)
	}
}

func TestReplaceUserRolesSupportsMultipleRoles(t *testing.T) {
	adminID := uuid.New()
	targetID := uuid.New()

	adminRole := domain.Role{ID: uuid.New(), Code: domain.RoleAdmin}
	managerRole := domain.Role{ID: uuid.New(), Code: domain.RoleManager}
	teacherRole := domain.Role{ID: uuid.New(), Code: domain.RoleTeacher}
	studentRole := domain.Role{ID: uuid.New(), Code: domain.RoleStudent}

	repo := &rbacRepoStub{
		users: map[uuid.UUID]domain.User{
			adminID:  {ID: adminID, IsActive: true, Roles: []domain.Role{adminRole}},
			targetID: {ID: targetID, IsActive: true, Roles: []domain.Role{studentRole}},
		},
		roles: map[uuid.UUID]domain.Role{
			adminRole.ID:   adminRole,
			managerRole.ID: managerRole,
			teacherRole.ID: teacherRole,
			studentRole.ID: studentRole,
		},
	}

	uc := newRBACUseCase(repo)
	roles, err := uc.ReplaceUserRoles(context.Background(), adminID, targetID, []uuid.UUID{adminRole.ID, managerRole.ID, teacherRole.ID})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if !domain.HasRole(roles, domain.RoleAdmin) || !domain.HasRole(roles, domain.RoleManager) || !domain.HasRole(roles, domain.RoleTeacher) {
		t.Fatal("expected target user to receive admin, manager and teacher roles")
	}
}

func TestRevokeRoleRejectsLastAdminRemoval(t *testing.T) {
	adminRole := domain.Role{ID: uuid.New(), Code: domain.RoleAdmin}
	studentRole := domain.Role{ID: uuid.New(), Code: domain.RoleStudent}
	adminID := uuid.New()

	repo := &rbacRepoStub{
		users: map[uuid.UUID]domain.User{
			adminID: {
				ID:       adminID,
				IsActive: true,
				Roles:    []domain.Role{adminRole, studentRole},
			},
		},
		roles: map[uuid.UUID]domain.Role{
			adminRole.ID:   adminRole,
			studentRole.ID: studentRole,
		},
	}

	uc := newRBACUseCase(repo)
	_, err := uc.RevokeRole(context.Background(), adminID, adminID, adminRole.ID)
	if err != domain.ErrLastAdminRemoval {
		t.Fatalf("expected last admin removal, got %v", err)
	}
}
