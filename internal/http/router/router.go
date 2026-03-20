package router

import (
	"auth-service/internal/http/handlers"
	"auth-service/internal/http/middleware"
	jwtlib "auth-service/internal/service/jwt"

	"github.com/gin-gonic/gin"
)

const (
	RoleStudent = "student"
	RoleTeacher = "teacher"
	RoleManager = "manager"
	RoleAdmin   = "admin"
)

func New(authH *handlers.AuthHandler, rbacH *handlers.RBACHandler, jwtMgr *jwtlib.Manager) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	r.GET("/health", health)

	auth := r.Group("/auth")
	{
		auth.POST("/register", authH.Register)
		auth.POST("/login", authH.Login)
		auth.POST("/forgot-password", authH.ForgotPassword)
		auth.POST("/reset-password", authH.ResetPassword)
		auth.POST("/change-password", middleware.Authenticate(jwtMgr), authH.ChangePassword)
		auth.POST("/refresh", authH.Refresh)
		auth.POST("/logout", authH.Logout)
		auth.GET("/me", authH.Me)
	}

	usersGroup := r.Group("/users")
	usersGroup.Use(middleware.Authenticate(jwtMgr), middleware.RequireRole(RoleAdmin, RoleManager))
	{
		usersGroup.GET("/", rbacH.ListUsers)

		usersGroup.PATCH("/status", rbacH.UpdateUserStatus)
	}

	rolesGroup := r.Group("/roles")
	rolesGroup.Use(middleware.Authenticate(jwtMgr), middleware.RequireRole(RoleAdmin, RoleManager))
	{
		rolesGroup.GET("/", rbacH.ListRoles)
	}

	userRolesGroup := r.Group("/user_roles")
	userRolesGroup.Use(middleware.Authenticate(jwtMgr))
	{
		userRolesGroup.GET("/:userID", middleware.RequireRole(RoleAdmin, RoleManager), rbacH.GetUserRoles)
		userRolesGroup.PATCH("/", middleware.RequireRole(RoleAdmin), rbacH.UpdateUserRoles)
		userRolesGroup.POST("/revoke", middleware.RequireRole(RoleAdmin), rbacH.RevokeRoles)
	}

	return r
}
