package handlers

import (
	"auth-service/internal/domain"
	"auth-service/internal/http/dto"
	"auth-service/internal/http/middleware"
	"auth-service/internal/http/respond"
	"auth-service/internal/usecase"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type RBACHandler struct {
	uc *usecase.RBAC
}

func NewRBACHandler(uc *usecase.RBAC) *RBACHandler {
	return &RBACHandler{uc: uc}
}

func (h *RBACHandler) ListUsers(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	users, err := h.uc.ListUsers(c, actorUserID)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toUserResponses(users))
}

func (h *RBACHandler) UpdateUserRoles(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	var req dto.ReplaceUserRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}
	if req.UserID == uuid.Nil {
		respond.Error(c, http.StatusBadRequest, "validation", "user_id required")
		return
	}

	roleIDs := req.EffectiveRoleIDs()
	if len(roleIDs) == 0 {
		respond.Error(c, http.StatusBadRequest, "validation", "role_ids required")
		return
	}

	roles, err := h.uc.ReplaceUserRoles(c, actorUserID, req.UserID, roleIDs)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toUserRolesResponse(req.UserID, roles))
}

func (h *RBACHandler) ListRoles(c *gin.Context) {
	roles, err := h.uc.ListRoles(c)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toRoleResponses(roles))
}

func (h *RBACHandler) GetUserProfile(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	user, err := h.uc.GetUserProfile(c, actorUserID, actorUserID)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toProfileResponse(&user))
}

func (h *RBACHandler) GetUserProfileByID(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	targetUserID, err := uuid.Parse(c.Param("userID"))
	if err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid user id")
		return
	}

	user, err := h.uc.GetUserProfileByID(c, actorUserID, targetUserID)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toProfileResponse(&user))
}

func (h *RBACHandler) UpdateUserProfile(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	var req dto.UpdateUserProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}

	update := domain.UserProfileUpdate{
		Email:    cleanOptional(req.Email),
		Login:    firstOptional(cleanOptional(req.Login), cleanOptional(req.Name)),
		Bio:      cleanOptional(req.Bio),
		PhotoURL: firstOptional(cleanOptional(req.PhotoURL), cleanOptional(req.AvatarURL), cleanOptional(req.AvatarBase64)),
	}
	if update.Email != nil {
		normalized := normalizeEmail(*update.Email)
		if err := domain.ValidateEmail(normalized); err != nil {
			respond.Error(c, http.StatusBadRequest, "validation", "invalid email")
			return
		}
		update.Email = &normalized
	}

	user, err := h.uc.UpdateUserProfile(c, actorUserID, actorUserID, update)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toProfileResponse(&user))
}

func (h *RBACHandler) GetUserRoles(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	targetUserID, err := uuid.Parse(c.Param("userID"))
	if err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid user id")
		return
	}

	roles, err := h.uc.GetUserRoles(c, actorUserID, targetUserID)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toUserRolesResponse(targetUserID, roles))
}

func (h *RBACHandler) RevokeRoles(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	var req dto.RevokeUserRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}
	if req.UserID == uuid.Nil || req.RoleID == uuid.Nil {
		respond.Error(c, http.StatusBadRequest, "validation", "user_id and role_id required")
		return
	}

	roles, err := h.uc.RevokeRole(c, actorUserID, req.UserID, req.RoleID)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toUserRolesResponse(req.UserID, roles))
}

func (h *RBACHandler) UpdateUserStatus(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	var req dto.UpdateUserStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}
	if req.UserID == uuid.Nil {
		respond.Error(c, http.StatusBadRequest, "validation", "user_id required")
		return
	}
	if req.IsActive == nil {
		respond.Error(c, http.StatusBadRequest, "validation", "is_active required")
		return
	}

	user, err := h.uc.UpdateUserStatus(c, actorUserID, req.UserID, *req.IsActive)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			respond.Error(c, http.StatusNotFound, "not_found", domain.ErrNotFound.Error())
			return
		}
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toUserResponse(&user))
}

func cleanOptional(value *string) *string {
	if value == nil {
		return nil
	}
	cleaned := strings.TrimSpace(*value)
	return &cleaned
}

func firstOptional(values ...*string) *string {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
