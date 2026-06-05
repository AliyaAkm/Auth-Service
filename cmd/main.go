package main

import (
	jwtlib "auth-service/internal/service/jwt"
	"auth-service/internal/service/notification"
	"auth-service/internal/service/storage"
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
	storageClient, err := storage.NewClient(storage.ClientConfig{
		BaseURL: cfg.Storage.URL,
		Timeout: cfg.Storage.Timeout,
	})
	if err != nil {
		logger.Fatal("error configuring storage service client", zap.Error(err))
	}

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

	var eventSender usecase.NotificationSender
	if cfg.Notification.InternalAPIKey != "" {
		eventSender, err = notification.NewEventClient(notification.EventClientConfig{
			BaseURL:        cfg.Notification.URL,
			Timeout:        cfg.Notification.Timeout,
			InternalAPIKey: cfg.Notification.InternalAPIKey,
		})
		if err != nil {
			logger.Fatal("notification client configuration error", zap.Error(err))
		}
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
		eventSender,
	)
	rbacUC := usecase.NewRBAC(userRepo)

	authH := handlers.NewAuthHandler(authUC, jwtMgr)
	rbacH := handlers.NewRBACHandler(rbacUC, storageClient)

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
