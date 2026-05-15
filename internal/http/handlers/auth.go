package handlers

import (
	"auth-service/internal/domain"
	"auth-service/internal/http/dto"
	"auth-service/internal/http/middleware"
	"auth-service/internal/http/respond"
	"auth-service/internal/service"
	jwtlib "auth-service/internal/service/jwt"
	"auth-service/internal/usecase"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthHandler struct {
	uc           *usecase.Auth
	jwtMgr       *jwtlib.Manager
	googleOAuth  interface{}
	gitHubOAuth  interface{}
}

func NewAuthHandler(uc *usecase.Auth, jwtMgr *jwtlib.Manager) *AuthHandler {
	return &AuthHandler{uc: uc, jwtMgr: jwtMgr}
}

func NewAuthHandlerWithOAuth(
	uc *usecase.Auth,
	jwtMgr *jwtlib.Manager,
	googleOAuth interface{},
	gitHubOAuth interface{},
) *AuthHandler {
	return &AuthHandler{
		uc:          uc,
		jwtMgr:      jwtMgr,
		googleOAuth: googleOAuth,
		gitHubOAuth: gitHubOAuth,
	}
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

	tokens, err := h.uc.Register(c, email, req.Password)
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

	tokens, err := h.uc.Login(c, email, req.Password)
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

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req dto.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}

	email := normalizeEmail(req.Email)
	if err := domain.ValidateEmail(email); err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid email")
		return
	}

	if err := h.uc.ForgotPassword(c, email); err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusAccepted, gin.H{
		"message": "If the account exists, password reset instructions will be sent.",
	})
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req dto.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}

	email := normalizeEmail(req.Email)
	if err := domain.ValidateEmail(email); err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid email")
		return
	}

	code := strings.TrimSpace(req.Code)
	if code == "" {
		respond.Error(c, http.StatusBadRequest, "validation", "code required")
		return
	}

	if err := domain.ValidatePassword(req.NewPassword); err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid password")
		return
	}

	if err := h.uc.ResetPassword(c, email, code, req.NewPassword); err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, gin.H{
		"message": "Password has been reset successfully.",
	})
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	var req dto.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}

	if strings.TrimSpace(req.CurrentPassword) == "" {
		respond.Error(c, http.StatusBadRequest, "validation", "current_password required")
		return
	}
	if err := domain.ValidatePassword(req.NewPassword); err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid password")
		return
	}

	if err := h.uc.ChangePassword(c, userID, req.CurrentPassword, req.NewPassword); err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, gin.H{
		"message": "Password has been changed successfully.",
	})
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
		return
	}

	user, err := h.uc.GetUserByID(c, userID)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toUserResponse(user))
}

func bearerToken(c *gin.Context) string {
	header := c.GetHeader("Authorization")
	if header == "" {
		return ""
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}

	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func writeDomainError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrValidation):
		respond.Error(c, http.StatusBadRequest, "validation", domain.ErrValidation.Error())
	case errors.Is(err, domain.ErrEmailTaken):
		respond.Error(c, http.StatusConflict, "email_taken", domain.ErrEmailTaken.Error())
	case errors.Is(err, domain.ErrInvalidCredentials):
		respond.Error(c, http.StatusUnauthorized, "invalid_credentials", domain.ErrInvalidCredentials.Error())
	case errors.Is(err, domain.ErrCurrentPassword):
		respond.Error(c, http.StatusUnauthorized, "current_password_invalid", domain.ErrCurrentPassword.Error())
	case errors.Is(err, domain.ErrInvalidResetCode):
		respond.Error(c, http.StatusBadRequest, "invalid_reset_code", domain.ErrInvalidResetCode.Error())
	case errors.Is(err, domain.ErrInactiveUser):
		respond.Error(c, http.StatusForbidden, "inactive_user", domain.ErrInactiveUser.Error())
	case errors.Is(err, domain.ErrForbidden):
		respond.Error(c, http.StatusForbidden, "forbidden", domain.ErrForbidden.Error())
	case errors.Is(err, domain.ErrNotFound):
		respond.Error(c, http.StatusNotFound, "not_found", domain.ErrNotFound.Error())
	case errors.Is(err, domain.ErrInvalidToken), errors.Is(err, domain.ErrSessionRevoked):
		respond.Error(c, http.StatusUnauthorized, "invalid_token", domain.ErrInvalidToken.Error())
	case errors.Is(err, domain.ErrRoleNotFound):
		respond.Error(c, http.StatusNotFound, "role_not_found", domain.ErrRoleNotFound.Error())
	case errors.Is(err, domain.ErrRoleAlreadyAssigned):
		respond.Error(c, http.StatusConflict, "role_already_assigned", domain.ErrRoleAlreadyAssigned.Error())
	case errors.Is(err, domain.ErrRoleNotAssigned):
		respond.Error(c, http.StatusNotFound, "role_not_assigned", domain.ErrRoleNotAssigned.Error())
	case errors.Is(err, domain.ErrUserMustHaveRole):
		respond.Error(c, http.StatusConflict, "user_must_have_role", domain.ErrUserMustHaveRole.Error())
	case errors.Is(err, domain.ErrLastAdminRemoval):
		respond.Error(c, http.StatusConflict, "last_admin_removal", domain.ErrLastAdminRemoval.Error())
	case errors.Is(err, domain.ErrLastAdminDeactivation):
		respond.Error(c, http.StatusConflict, "last_admin_deactivation", domain.ErrLastAdminDeactivation.Error())
	default:
		c.Error(err)
		respond.Error(c, http.StatusInternalServerError, "internal", domain.ErrInternal.Error())
	}
}

func normalizeEmail(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

// GoogleAuthURL returns URL to redirect user to Google login
// GET /auth/oauth/google/url
func (h *AuthHandler) GoogleAuthURL(c *gin.Context) {
	if h.googleOAuth == nil {
		respond.Error(c, http.StatusNotImplemented, "not_implemented", "Google OAuth is not configured")
		return
	}

	// Generate random state for CSRF protection
	state := uuid.New().String()
	
	// Store state in session (in production, use proper session management)
	c.SetCookie("oauth_state", state, 3600, "/", "", false, true)

	provider := h.googleOAuth.(*service.GoogleProvider)
	url := provider.GetAuthURL(state)

	respond.PureJSON(c, http.StatusOK, gin.H{
		"auth_url": url,
	})
}

// GoogleCallback handles Google OAuth callback
// POST /auth/oauth/google/callback
// Body: {"code": "authorization_code"}
func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	if h.googleOAuth == nil {
		respond.Error(c, http.StatusNotImplemented, "not_implemented", "Google OAuth is not configured")
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "invalid_request", "code required")
		return
	}

	// Exchange code for user info
	provider := h.googleOAuth.(*service.GoogleProvider)
	email, googleID, err := provider.ExchangeCode(c, req.Code)
	if err != nil {
		respond.Error(c, http.StatusUnauthorized, "oauth_error", "failed to verify code")
		return
	}

	// Handle OAuth callback (find or create user)
	tokens, err := h.uc.HandleOAuthCallback(c, email, "google", googleID)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, tokens)
}

// GitHubAuthURL returns URL to redirect user to GitHub login
// GET /auth/oauth/github/url
func (h *AuthHandler) GitHubAuthURL(c *gin.Context) {
	if h.gitHubOAuth == nil {
		respond.Error(c, http.StatusNotImplemented, "not_implemented", "GitHub OAuth is not configured")
		return
	}

	state := uuid.New().String()
	c.SetCookie("oauth_state", state, 3600, "/", "", false, true)

	provider := h.gitHubOAuth.(*service.GitHubProvider)
	url := provider.GetAuthURL(state)

	respond.PureJSON(c, http.StatusOK, gin.H{
		"auth_url": url,
	})
}

// GitHubCallback handles GitHub OAuth callback
// POST /auth/oauth/github/callback
// Body: {"code": "authorization_code"}
func (h *AuthHandler) GitHubCallback(c *gin.Context) {
	if h.gitHubOAuth == nil {
		respond.Error(c, http.StatusNotImplemented, "not_implemented", "GitHub OAuth is not configured")
		return
	}

	var req struct {
		Code string `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "invalid_request", "code required")
		return
	}

	// Exchange code for user info
	provider := h.gitHubOAuth.(*service.GitHubProvider)
	email, githubID, err := provider.ExchangeCode(c, req.Code)
	if err != nil {
		respond.Error(c, http.StatusUnauthorized, "oauth_error", "failed to verify code")
		return
	}

	// Handle OAuth callback
	tokens, err := h.uc.HandleOAuthCallback(c, email, "github", githubID)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, tokens)
}
