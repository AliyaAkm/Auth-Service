package handlers

import (
	"errors"
	"github.com/google/uuid"
	"net/http"
	"strings"

	"auth-service/internal/domain"
	"auth-service/internal/http/dto"
	"auth-service/internal/http/respond"
	jwtlib "auth-service/internal/service/jwt"
	"auth-service/internal/usecase"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	uc     *usecase.Auth
	jwtMgr *jwtlib.Manager
}

// todo: interface for uc (port.go)
func NewAuthHandler(uc *usecase.Auth, jwtMgr *jwtlib.Manager) *AuthHandler {
	return &AuthHandler{uc: uc, jwtMgr: jwtMgr}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req dto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}
	email := normalizeEmail(req.Email)
	if err := domain.ValidateEmail(email); err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid email")
		return
	}
	if err := domain.ValidatePassword(req.Password); err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid password")
		return
	}

	tokens, err := h.uc.Register(c, req.Email, req.Password)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusCreated, tokens)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req dto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}

	email := normalizeEmail(req.Email)
	if err := domain.ValidateEmail(email); err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid email")
		return
	}
	if err := domain.ValidatePassword(req.Password); err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid password")
		return
	}

	tokens, err := h.uc.Login(c, req.Email, req.Password)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, tokens)
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req dto.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}
	if req.RefreshToken == "" {
		respond.Error(c, http.StatusBadRequest, "validation", "refresh_token required")
		return
	}

	tokens, err := h.uc.Refresh(c, req.RefreshToken)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, tokens)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req dto.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}
	if req.RefreshToken == "" {
		respond.Error(c, http.StatusBadRequest, "validation", "refresh_token required")
		return
	}

	if err := h.uc.Logout(c, req.RefreshToken); err != nil {
		writeDomainError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) Me(c *gin.Context) {
	tokenStr := bearerToken(c)
	if tokenStr == "" {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing bearer token")
		return
	}

	claims, err := h.jwtMgr.VerifyAccessToken(tokenStr)
	if err != nil {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "invalid token")
		return
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid user id")
	}
	user, err := h.uc.GetUserByID(c, userID)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, user)

}

func bearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, prefix))
}

// todo: все коды перенести в константы, объявлять тут
// todo: вниз пробросить respond.Error и вызывать его просто сверху , использовать структуру error
func writeDomainError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrValidation):
		respond.Error(c, http.StatusBadRequest, "validation", domain.ErrValidation.Error())
	case errors.Is(err, domain.ErrEmailTaken):
		respond.Error(c, http.StatusConflict, "email_taken", domain.ErrEmailTaken.Error())
	case errors.Is(err, domain.ErrInvalidCredentials):
		respond.Error(c, http.StatusUnauthorized, "invalid_credentials", domain.ErrInvalidCredentials.Error())
	case errors.Is(err, domain.ErrInactiveUser):
		respond.Error(c, http.StatusForbidden, "inactive_user", domain.ErrInactiveUser.Error())
	case errors.Is(err, domain.ErrInvalidToken), errors.Is(err, domain.ErrSessionRevoked):
		respond.Error(c, http.StatusUnauthorized, "invalid_token", domain.ErrInvalidToken.Error())
	default:
		c.Error(err)
		respond.Error(c, http.StatusInternalServerError, "internal", domain.ErrInternal.Error())
	}
}

func normalizeEmail(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}
