package domain

import "testing"

func TestPrimaryRoleCode(t *testing.T) {
	roles := []Role{
		{Code: RoleStudent},
		{Code: RoleTeacher},
		{Code: RoleAdmin},
	}

	got := PrimaryRoleCode(roles)
	if got != RoleAdmin {
		t.Fatalf("expected %q, got %q", RoleAdmin, got)
	}
}

func TestCanManageRole(t *testing.T) {
	managerRoles := []Role{{Code: RoleManager}}
	adminRoles := []Role{{Code: RoleAdmin}}

	if !CanManageRole(managerRoles, RoleTeacher) {
		t.Fatal("manager should be able to manage teacher role")
	}
	if CanManageRole(managerRoles, RoleAdmin) {
		t.Fatal("manager must not be able to manage admin role")
	}
	if !CanManageRole(adminRoles, RoleAdmin) {
		t.Fatal("admin should be able to manage admin role")
	}
}
