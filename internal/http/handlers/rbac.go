package handlers

import (
	"auth-service/internal/http/dto"
	"auth-service/internal/http/middleware"
	"auth-service/internal/http/respond"
	"auth-service/internal/usecase"
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

func (h *RBACHandler) ListRoles(c *gin.Context) {
	roles, err := h.uc.ListRoles(c)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toRoleResponses(roles))
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

func (h *RBACHandler) AssignRole(c *gin.Context) {
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

	var req dto.AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}

	roles, err := h.uc.AssignRole(c, actorUserID, targetUserID, strings.TrimSpace(req.Role))
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toUserRolesResponse(targetUserID, roles))
}

func (h *RBACHandler) RevokeRole(c *gin.Context) {
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

	roles, err := h.uc.RevokeRole(c, actorUserID, targetUserID, strings.TrimSpace(c.Param("roleCode")))
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toUserRolesResponse(targetUserID, roles))
}
