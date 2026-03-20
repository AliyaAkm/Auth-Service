package domain

import (
	"github.com/google/uuid"
	"slices"
	"time"
)

const (
	RoleStudent = "student"
	RoleTeacher = "teacher"
	RoleManager = "manager"
	RoleAdmin   = "admin"
)

var rolePriority = map[string]int{
	RoleStudent: 1,
	RoleTeacher: 2,
	RoleManager: 3,
	RoleAdmin:   4,
}

type Role struct {
	ID           uuid.UUID
	Code         string
	Name         string
	Description  string
	IsDefault    bool
	IsPrivileged bool
	IsSupport    bool
	CreatedAt    time.Time
}

func IsValidRoleCode(code string) bool {
	_, ok := rolePriority[code]
	return ok
}

func RoleCodesFromRoles(roles []Role) []string {
	codes := make([]string, 0, len(roles))
	for _, role := range roles {
		code := role.Code
		if code == "" || slices.Contains(codes, code) {
			continue
		}
		codes = append(codes, code)
	}
	return codes
}

func HasRole(roles []Role, want string) bool {
	for _, role := range roles {
		if role.Code == want {
			return true
		}
	}
	return false
}

func PrimaryRoleCode(roles []Role) string {
	var primary string
	maxPriority := -1

	for _, role := range roles {
		code := role.Code
		priority, ok := rolePriority[code]
		if !ok {
			continue
		}
		if priority > maxPriority {
			maxPriority = priority
			primary = code
		}
	}

	return primary
}

func CanViewOtherUsersRoles(roles []Role) bool {
	return HasRole(roles, RoleManager) || HasRole(roles, RoleAdmin)
}

func CanManageRole(roles []Role, targetRole string) bool {
	switch {
	case HasRole(roles, RoleAdmin):
		return IsValidRoleCode(targetRole)
	case HasRole(roles, RoleManager):
		return targetRole == RoleStudent || targetRole == RoleTeacher
	default:
		return false
	}
}

func CanManageUserStatus(actorRoles, targetRoles []Role) bool {
	if len(targetRoles) == 0 {
		return false
	}

	for _, role := range targetRoles {
		if !CanManageRole(actorRoles, role.Code) {
			return false
		}
	}

	return true
}
