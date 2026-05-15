package main

import (
	jwtlib "auth-service/internal/service/jwt"
	"auth-service/internal/service"
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
	"go.uber.org/zap"
)

func main() {
	_ = godotenv.Load(".env")

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal("logger initialization error:", err)
	}
	defer logger.Sync()

	cfg, err := config.ReadEnv()
	if err != nil {
		logger.Fatal("configuration error", zap.Error(err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL())
	if err != nil {
		logger.Fatal("error connecting to the database", zap.Error(err))
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
		logger.Fatal("smtp configuration error", zap.Error(err))
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

	// Initialize OAuth providers
	googleOAuth := service.NewGoogleProvider(
		cfg.Google.ClientID,
		cfg.Google.ClientSecret,
		cfg.Google.RedirectURL,
	)
	gitHubOAuth := service.NewGitHubProvider(
		cfg.GitHub.ClientID,
		cfg.GitHub.ClientSecret,
		cfg.GitHub.RedirectURL,
	)

	authH := handlers.NewAuthHandlerWithOAuth(authUC, jwtMgr, googleOAuth, gitHubOAuth)
	rbacH := handlers.NewRBACHandler(rbacUC)

	engine := router.New(authH, rbacH, jwtMgr, logger)

	srv := &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           engine,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("auth-service started", zap.String("addr", cfg.ListenAddr()))
		if err := srv.ListenAndServe(); err != nil && errors.Is(http.ErrServerClosed, err) {
			logger.Error("server error", zap.Error(err))
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", zap.Error(err))
	}

	logger.Info("auth-service stopped")
}
