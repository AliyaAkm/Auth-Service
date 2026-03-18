package middleware

import (
	"auth-service/internal/domain"
	"auth-service/internal/http/respond"
	jwtlib "auth-service/internal/service/jwt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	contextUserIDKey = "auth.user_id"
	contextRolesKey  = "auth.roles"
)

func Authenticate(jwtMgr *jwtlib.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := bearerToken(c.GetHeader("Authorization"))
		if tokenStr == "" {
			respond.Error(c, 401, "unauthorized", "missing bearer token")
			c.Abort()
			return
		}

		claims, err := jwtMgr.VerifyAccessToken(tokenStr)
		if err != nil {
			respond.Error(c, 401, "unauthorized", "invalid token")
			c.Abort()
			return
		}
		if !claims.IsActive {
			respond.Error(c, 403, "inactive_user", domain.ErrInactiveUser.Error())
			c.Abort()
			return
		}

		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			respond.Error(c, 400, "validation", "invalid user id")
			c.Abort()
			return
		}

		c.Set(contextUserIDKey, userID)
		c.Set(contextRolesKey, claims.Roles)
		c.Next()
	}
}

func RequireRole(requiredRoles ...string) gin.HandlerFunc {
	normalizedAllowed := make([]string, 0, len(requiredRoles))
	for _, role := range requiredRoles {
		role = domain.NormalizeRoleCode(role)
		if role != "" {
			normalizedAllowed = append(normalizedAllowed, role)
		}
	}

	return func(c *gin.Context) {
		currentRoles := CurrentRoles(c)
		for _, currentRole := range currentRoles {
			for _, allowedRole := range normalizedAllowed {
				if currentRole == allowedRole {
					c.Next()
					return
				}
			}
		}

		respond.Error(c, 403, "forbidden", domain.ErrForbidden.Error())
		c.Abort()
	}
}

func CurrentUserID(c *gin.Context) (uuid.UUID, bool) {
	value, ok := c.Get(contextUserIDKey)
	if !ok {
		return uuid.UUID{}, false
	}

	userID, ok := value.(uuid.UUID)
	return userID, ok
}

func CurrentRoles(c *gin.Context) []string {
	value, ok := c.Get(contextRolesKey)
	if !ok {
		return nil
	}

	roles, ok := value.([]string)
	if !ok {
		return nil
	}

	return roles
}

func bearerToken(header string) string {
	if header == "" {
		return ""
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}

	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}
