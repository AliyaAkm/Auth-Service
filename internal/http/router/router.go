package router

import (
	"auth-service/internal/http/handlers"
	"auth-service/internal/http/middleware"
	jwtlib "auth-service/internal/service/jwt"
	"github.com/gin-gonic/gin"
)

func New(authH *handlers.AuthHandler, rbacH *handlers.RBACHandler, jwtMgr *jwtlib.Manager) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	r.GET("/health", health)

	auth := r.Group("/auth")
	{
		auth.POST("/register", authH.Register)
		auth.POST("/login", authH.Login)
		auth.POST("/refresh", authH.Refresh)
		auth.POST("/logout", authH.Logout)
		auth.GET("/me", authH.Me)
	}

	rbac := r.Group("/rbac")
	rbac.Use(middleware.Authenticate(jwtMgr))
	{
		rbac.GET("/roles", rbacH.ListRoles)
		rbac.GET("/users/:userID/roles", rbacH.GetUserRoles)
		rbac.POST("/users/:userID/roles", rbacH.AssignRole)
		rbac.DELETE("/users/:userID/roles/:roleCode", rbacH.RevokeRole)
	}
	return r
}
