package main

import (
	jwtlib "auth-service/internal/service/jwt"
	"auth-service/internal/service/notification"
	"context"
	"errors"
	"github.com/google/uuid"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth-service/internal/config"
	"auth-service/internal/http/handlers"
	"auth-service/internal/http/router"
	"auth-service/internal/repo/postgres"
	"auth-service/internal/service/security"
	"auth-service/internal/usecase"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load(".env")

	cfg, err := config.ReadEnv()
	if err != nil {
		log.Fatal("configuration error:", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL())
	if err != nil {
		log.Fatal("error connecting to the database:", err)
	}
	defer pool.Close()

	userRepo := postgres.NewUserRepo(pool)
	refreshRepo := postgres.NewRefreshRepo(pool)
	resetRepo := postgres.NewPasswordResetRepo(pool)

	hasher := security.PasswordHasher{}
	resetSender, err := notification.NewSMTPPasswordResetCodeSender(
		cfg.SMTP.Host,
		cfg.SMTP.Port,
		cfg.SMTP.Username,
		cfg.SMTP.Password,
		cfg.SMTP.FromEmail,
		cfg.SMTP.FromName,
		cfg.SMTP.PasswordResetSubject,
	)
	if err != nil {
		log.Fatal("smtp configuration error:", err)
	}

	jwtMgr := jwtlib.New(
		[]byte(cfg.JWT.Secret),
		cfg.JWT.Issuer,
		cfg.JWT.Audience,
		cfg.JWT.AccessTTL,
	)

	authUC := usecase.NewAuth(
		userRepo,
		refreshRepo,
		resetRepo,
		hasher,
		jwtMgr,
		resetSender,
		cfg.JWT.RefreshTTL,
		15*time.Minute,
		security.NewPasswordResetCode,
		uuid.New,
		time.Now,
	)
	rbacUC := usecase.NewRBAC(userRepo)

	authH := handlers.NewAuthHandler(authUC, jwtMgr)
	rbacH := handlers.NewRBACHandler(rbacUC)

	engine := router.New(authH, rbacH, jwtMgr)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           engine,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Println("auth-service started on", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && errors.Is(http.ErrServerClosed, err) {
			log.Println("server error:", err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Println("shutdown error:", err)
	}

	log.Println("auth-service stopped")
}
