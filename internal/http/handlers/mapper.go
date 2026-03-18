package handlers

import (
	"auth-service/internal/domain"
	"auth-service/internal/http/dto"

	"github.com/google/uuid"
)

func toUserResponse(user *domain.User) dto.UserResponse {
	return dto.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Roles:     toRoleResponses(user.Roles),
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
	}
}

func toUserResponses(users []domain.User) []dto.UserResponse {
	result := make([]dto.UserResponse, 0, len(users))
	for i := range users {
		result = append(result, toUserResponse(&users[i]))
	}
	return result
}

func toUserRolesResponse(userID uuid.UUID, roles []domain.Role) dto.UserRolesResponse {
	return dto.UserRolesResponse{
		UserID: userID,
		Roles:  toRoleResponses(roles),
	}
}

func toRoleResponses(roles []domain.Role) []dto.RoleResponse {
	result := make([]dto.RoleResponse, 0, len(roles))
	for _, role := range roles {
		result = append(result, dto.RoleResponse{
			ID:           role.ID,
			Code:         role.Code,
			Name:         role.Name,
			Description:  role.Description,
			IsDefault:    role.IsDefault,
			IsPrivileged: role.IsPrivileged,
			IsSupport:    role.IsSupport,
			CreatedAt:    role.CreatedAt,
		})
	}
	return result
}
